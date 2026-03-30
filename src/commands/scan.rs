use std::io::{self, Write};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use colored::Colorize;
use serde::Deserialize;

use crate::client::MlabClient;

pub fn domain(client: &MlabClient, domain: &str, no_follow: bool, json: bool) {
    // 1. Launch the scan
    let body = serde_json::json!({ "domain": domain });
    let resp = match client.post_json("/scan/domain", &body) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Request failed: {e}");
            std::process::exit(1);
        }
    };

    let status = resp.status();
    let resp_body = resp.text().unwrap_or_default();

    if !status.is_success() {
        eprintln!("{} HTTP {status}", "error:".red().bold());
        match serde_json::from_str::<serde_json::Value>(&resp_body) {
            Ok(v) => eprintln!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(_) => eprintln!("{resp_body}"),
        }
        std::process::exit(1);
    }

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

        thread::sleep(poll_interval);

        // Poll
        match client.get(&format!("/scan/domain/status?domain={}", domain)) {
            Ok(resp) => {
                let body = resp.text().unwrap_or_default();
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(s) = v.get("status").and_then(|s| s.as_str()) {
                        last_status = s.to_string();
                    }
                }
            }
            Err(_) => {}
        }
    }

    // Clear spinner line
    print!("\r{}\r", " ".repeat(60));
    io::stdout().flush().ok();

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
    let resp = match client.get(&format!("/scan/ip?ip={}", ip)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Request failed: {e}");
            std::process::exit(1);
        }
    };

    let status = resp.status();
    let body = resp.text().unwrap_or_default();

    if !status.is_success() {
        eprintln!("{} HTTP {status}", "error:".red().bold());
        eprintln!("{body}");
        std::process::exit(1);
    }

    if json {
        match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(_) => println!("{body}"),
        }
        return;
    }

    let r: IpResult = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("{} Failed to parse IP result.", "error:".red().bold());
            eprintln!("{body}");
            std::process::exit(1);
        }
    };

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
//  File upload
// ═══════════════════════════════════════════════════════════════════

pub fn file(client: &MlabClient, path: &str) {
    let file_path = Path::new(path);
    if !file_path.exists() {
        eprintln!("File not found: {path}");
        std::process::exit(1);
    }

    match client.upload_file(file_path) {
        Ok(resp) => crate::commands::print_response(resp),
        Err(e) => {
            eprintln!("Request failed: {e}");
            std::process::exit(1);
        }
    }
}
