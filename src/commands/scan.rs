use std::io::{self, Write};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use colored::Colorize;
use serde::Deserialize;

use crate::client::MlabClient;
use crate::commands::{fetch, parse_or_exit, print_json};
use crate::error::{ApiError, ErrorKind};
use crate::util::urlencode;

/// Upper bound on how long `scan domain` follows a scan before handing the user
/// back their shell. The API has no terminal "failed" answer on this route, so
/// without a ceiling a dead scan would poll forever.
const MAX_WAIT: Duration = Duration::from_secs(15 * 60);

enum Poll {
    Status(String),
    /// The call will keep failing the same way — stop.
    Fatal(ApiError),
    /// A blip worth retrying (network, 5xx, malformed body).
    Transient(String),
}

fn poll_domain_status(client: &MlabClient, domain: &str) -> Poll {
    let raw = crate::commands::body(client.get(&format!(
        "/scan/domain/status?domain={}",
        urlencode(domain)
    )));

    let raw = match raw {
        Ok(b) => b,
        // A classified error already knows whether retrying can help: only a
        // plain transport/5xx blip is worth another round.
        Err(e) => {
            return match e.kind {
                ErrorKind::Other => Poll::Transient(e.message),
                _ => Poll::Fatal(e),
            }
        }
    };

    match serde_json::from_str::<serde_json::Value>(&raw)
        .ok()
        .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(str::to_string))
    {
        Some(s) => Poll::Status(s),
        None => Poll::Transient("malformed status response".to_string()),
    }
}

fn abort_polling(error: ApiError, domain: &str) -> ! {
    clear_spinner();
    eprintln!(
        "  Check again later with: {}",
        format!("mlab results domain {domain}").dimmed()
    );
    error.report()
}

fn clear_spinner() {
    print!("\r{}\r", " ".repeat(60));
    io::stdout().flush().ok();
}

pub fn domain(client: &MlabClient, domain: &str, no_follow: bool, json: bool) {
    // 1. Launch the scan
    let payload = serde_json::json!({ "domain": domain });
    fetch(client.post_json("/scan/domain", &payload));

    if no_follow {
        println!(
            "{} Scan launched for {}. Check status with: {}",
            "ok:".green().bold(),
            domain.cyan(),
            format!("mlab status domain {domain}").dimmed(),
        );
        return;
    }

    // 2. Poll status with spinner
    println!(
        "  {} Scanning {}...",
        "🌐",
        domain.cyan().bold()
    );
    println!();

    let spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let mut frame_idx = 0;
    let start = Instant::now();
    let poll_interval = Duration::from_secs(3);
    let mut last_status = String::from("pending");
    let mut consecutive_errors = 0u32;

    loop {
        let elapsed = start.elapsed();
        let secs = elapsed.as_secs();
        let spinner = spinner_frames[frame_idx % spinner_frames.len()];
        frame_idx += 1;

        let status_display = match last_status.as_str() {
            "pending" => "queued".yellow(),
            "scanning" => "scanning".cyan(),
            "success" => "done".green(),
            other => other.normal(),
        };

        print!(
            "\r  {} {}  {} elapsed    ",
            spinner.cyan(),
            status_display,
            format!("{secs}s").dimmed(),
        );
        io::stdout().flush().ok();

        if last_status == "success" {
            break;
        }

        if elapsed >= MAX_WAIT {
            abort_polling(
                ApiError::new(
                    None,
                    format!(
                        "gave up after {}s (last status: {last_status})",
                        elapsed.as_secs()
                    ),
                ),
                domain,
            );
        }

        thread::sleep(poll_interval);

        match poll_domain_status(client, domain) {
            Poll::Status(s) => {
                consecutive_errors = 0;
                // A terminal failure must not be mistaken for progress: without
                // this the loop would spin until the timeout on a dead scan.
                if matches!(s.as_str(), "failed" | "fail" | "error") {
                    abort_polling(ApiError::new(None, format!("scan {s}")), domain);
                }
                last_status = s;
            }
            // 4xx means the request itself is wrong (bad key, unknown domain);
            // retrying cannot fix it, so stop rather than loop silently.
            Poll::Fatal(e) => abort_polling(e, domain),
            Poll::Transient(msg) => {
                consecutive_errors += 1;
                if consecutive_errors >= 5 {
                    abort_polling(
                        ApiError::new(None, format!("{msg} (5 consecutive failures)")),
                        domain,
                    );
                }
            }
        }
    }

    clear_spinner();

    println!(
        "  {} Scan completed in {}s",
        "✔".green().bold(),
        start.elapsed().as_secs()
    );
    println!();

    // 3. Fetch and display results
    crate::commands::results::domain(client, domain, json);
}

// ═══════════════════════════════════════════════════════════════════
//  IP Lookup
// ═══════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct IpResult {
    ip: String,
    #[serde(default)]
    reserved: bool,
    // Public IP fields
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    r#as: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    continent: Option<String>,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    zip: Option<String>,
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
    #[serde(default)]
    currency: Option<String>,
    // Reserved IP fields
    #[serde(default, rename = "type")]
    ip_type: Option<String>,
    #[serde(default)]
    range: Option<String>,
    #[serde(default)]
    rfc: Option<String>,
}

pub fn ip(client: &MlabClient, ip: &str, json: bool) {
    let body = fetch(client.get(&format!("/scan/ip?ip={}", urlencode(ip))));

    if json {
        print_json(&body);
        return;
    }

    let r: IpResult = parse_or_exit(&body, "IP");
    print_ip_ui(&r);
}

fn print_ip_ui(r: &IpResult) {
    let div = format!("  {}", "─".repeat(60));

    println!();
    println!("  {} IP Lookup  {}", "🔍", r.ip.cyan().bold());
    println!("{}", div.dimmed());

    if r.reserved {
        // ── Reserved IP ──
        println!(
            "  {:<14} {}",
            "Status:".dimmed(),
            "Reserved / Private".yellow().bold()
        );
        if let Some(t) = &r.ip_type {
            println!("  {:<14} {}", "Type:".dimmed(), t);
        }
        if let Some(range) = &r.range {
            println!("  {:<14} {}", "Range:".dimmed(), range);
        }
        if let Some(rfc) = &r.rfc {
            println!("  {:<14} {}", "RFC:".dimmed(), rfc);
        }
        println!("{}", div.dimmed());
        println!();
        return;
    }

    // ── Network ──
    println!("  {}", "Network".bold().underline());
    print_field("ISP", &r.isp);
    print_field("Org", &r.org);
    print_field("AS", &r.r#as);
    println!();

    // ── Location ──
    println!("  {}", "Location".bold().underline());

    // Build location line: City, Region, Country (CC)
    let mut loc_parts: Vec<String> = Vec::new();
    if let Some(city) = &r.city {
        if !city.is_empty() {
            loc_parts.push(city.clone());
        }
    }
    if let Some(region) = &r.region {
        if !region.is_empty() {
            loc_parts.push(region.clone());
        }
    }
    if let Some(country) = &r.country {
        let cc = r.country_code.as_deref().unwrap_or("");
        if !cc.is_empty() {
            loc_parts.push(format!("{country} ({cc})"));
        } else if !country.is_empty() {
            loc_parts.push(country.clone());
        }
    }

    if !loc_parts.is_empty() {
        let flag = r
            .country_code
            .as_deref()
            .map(country_flag)
            .unwrap_or_default();
        println!(
            "  {:<14} {} {}",
            "Location:".dimmed(),
            flag,
            loc_parts.join(", ")
        );
    }

    if let Some(continent) = &r.continent {
        if !continent.is_empty() {
            println!("  {:<14} {}", "Continent:".dimmed(), continent);
        }
    }

    if let (Some(lat), Some(lon)) = (&r.lat, &r.lon) {
        println!(
            "  {:<14} {}, {}",
            "Coordinates:".dimmed(),
            lat,
            lon
        );
    }

    if let Some(tz) = &r.timezone {
        if !tz.is_empty() {
            println!("  {:<14} {}", "Timezone:".dimmed(), tz);
        }
    }
    if let Some(zip) = &r.zip {
        if !zip.is_empty() {
            println!("  {:<14} {}", "ZIP:".dimmed(), zip);
        }
    }
    if let Some(currency) = &r.currency {
        if !currency.is_empty() {
            println!("  {:<14} {}", "Currency:".dimmed(), currency);
        }
    }

    println!("{}", div.dimmed());
    println!();
}

fn print_field(label: &str, value: &Option<String>) {
    let padded = format!("{}:", label);
    match value {
        Some(v) if !v.is_empty() => println!("  {:<14} {}", padded.dimmed(), v),
        _ => {}
    }
}

fn country_flag(cc: &str) -> String {
    if cc.len() != 2 {
        return String::new();
    }
    let chars: Vec<char> = cc
        .to_uppercase()
        .chars()
        .filter_map(|c| {
            if c.is_ascii_uppercase() {
                char::from_u32(0x1F1E6 + (c as u32 - 'A' as u32))
            } else {
                None
            }
        })
        .collect();
    chars.iter().collect()
}

// ═══════════════════════════════════════════════════════════════════
//  Crypto lookup
// ═══════════════════════════════════════════════════════════════════

pub fn crypto(client: &MlabClient, addresses: &[String], chain: Option<&str>, json: bool) {
    if addresses.len() > 1 {
        return crate::commands::lookup::bulk_crypto(client, addresses, chain, json);
    }
    let address = addresses[0].as_str();

    // An explicit `chain` short-circuits the API's address classification, so
    // only send one when the user actually named it — otherwise a BTC address
    // would be looked up on whatever default we hardcoded.
    let mut path = format!("/scan/crypto?address={}", urlencode(address));
    if let Some(c) = chain {
        path.push_str(&format!("&chain={}", urlencode(c)));
    }
    let body = fetch(client.get(&path));

    if json {
        print_json(&body);
        return;
    }

    let v: serde_json::Value = parse_or_exit(&body, "crypto");

    let div = format!("  {}", "─".repeat(60));
    println!();
    println!("  {} Crypto Lookup  {}", "🪙", address.cyan().bold());
    println!("{}", div.dimmed());
    let resolved_chain = v
        .get("chain")
        .and_then(|c| c.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| chain.unwrap_or("unknown").to_uppercase());
    let source = match v.get("chain_source").and_then(|c| c.as_str()) {
        Some("detected") => "  (detected from address)",
        Some("default") => "  (default — pass --chain to override)",
        _ => "",
    };
    println!(
        "  {:<14} {}{}",
        "Chain:".dimmed(),
        resolved_chain.to_uppercase(),
        source.dimmed()
    );

    if let Some(obj) = v.as_object() {
        for (k, val) in obj {
            if k == "address" || k == "chain" || k == "chain_source" {
                continue;
            }
            let label = format!("{}:", k);
            let rendered = match val {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => "—".to_string(),
                other => serde_json::to_string(other).unwrap_or_default(),
            };
            println!("  {:<14} {}", label.dimmed(), rendered);
        }
    }

    println!("{}", div.dimmed());
    println!();
}

// ═══════════════════════════════════════════════════════════════════
//  File upload
// ═══════════════════════════════════════════════════════════════════

pub fn file(client: &MlabClient, path: &str, follow: bool, json: bool) {
    let file_path = Path::new(path);
    if !file_path.exists() {
        ApiError {
            status: None,
            message: format!("file not found: {path}"),
            kind: ErrorKind::Input,
        }
        .report();
    }

    let body = fetch(client.upload_file(file_path));

    if json {
        print_json(&body);
        return;
    }

    let v: serde_json::Value = parse_or_exit(&body, "upload");
    let sha256 = v
        .get("sha256")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();

    println!();
    println!("  {} {}", "✔".green().bold(), "File uploaded".bold());
    if let Some(name) = v.get("filename").and_then(|f| f.as_str()) {
        println!("  {:<10} {}", "Stored:".dimmed(), name);
    }
    if !sha256.is_empty() {
        println!("  {:<10} {}", "SHA256:".dimmed(), sha256.cyan());
    }
    println!();

    if !follow {
        if !sha256.is_empty() {
            println!(
                "  {}",
                format!("Results: mlab results file {sha256}").dimmed()
            );
            println!();
        }
        return;
    }

    if sha256.is_empty() {
        ApiError::new(None, "the upload returned no hash to follow.").report();
    }

    follow_file(client, &sha256, json);
}

/// Poll the analysis to completion, the way `scan domain` does. `partial` and
/// `failed` are terminal too — waiting past them would never end.
fn follow_file(client: &MlabClient, sha256: &str, json: bool) {
    let spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let mut frame_idx = 0;
    let start = Instant::now();
    let mut consecutive_errors = 0u32;

    loop {
        let spinner = spinner_frames[frame_idx % spinner_frames.len()];
        frame_idx += 1;

        let raw = crate::commands::body(client.get(&format!(
            "/scan/file/results?sha256={}",
            urlencode(sha256)
        )));

        let status = match raw {
            Ok(b) => {
                consecutive_errors = 0;
                serde_json::from_str::<serde_json::Value>(&b)
                    .ok()
                    .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(str::to_string))
                    .unwrap_or_else(|| "pending".to_string())
            }
            // 404 simply means the analysis has not produced a record yet.
            Err(e) if e.kind == ErrorKind::NotFound => "pending".to_string(),
            Err(e) if e.kind == ErrorKind::Other => {
                consecutive_errors += 1;
                if consecutive_errors >= 5 {
                    clear_spinner();
                    e.report();
                }
                "pending".to_string()
            }
            Err(e) => {
                clear_spinner();
                e.report();
            }
        };

        if matches!(status.as_str(), "completed" | "partial" | "failed") {
            clear_spinner();
            break;
        }

        if start.elapsed() >= MAX_WAIT {
            clear_spinner();
            ApiError::new(
                None,
                format!("gave up after {}s (last status: {status})", start.elapsed().as_secs()),
            )
            .report();
        }

        print!(
            "\r  {} {}  {} elapsed    ",
            spinner.cyan(),
            status.cyan(),
            format!("{}s", start.elapsed().as_secs()).dimmed()
        );
        io::stdout().flush().ok();
        thread::sleep(Duration::from_secs(3));
    }

    crate::commands::results::file(client, sha256, None, json);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_flag_maps_iso_codes_to_regional_indicators() {
        assert_eq!(country_flag("FR"), "\u{1F1EB}\u{1F1F7}");
        assert_eq!(country_flag("fr"), "\u{1F1EB}\u{1F1F7}");
    }

    #[test]
    fn country_flag_is_empty_for_anything_that_is_not_a_pair_of_letters() {
        assert_eq!(country_flag(""), "");
        assert_eq!(country_flag("FRA"), "");
        assert_eq!(country_flag("12"), "");
    }
}
