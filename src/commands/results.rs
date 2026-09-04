use colored::Colorize;
use serde::Deserialize;

use crate::client::MlabClient;
use crate::commands::{fetch, parse_or_exit, print_json};
use crate::commands::ssl::{render_table, SslCert};
use crate::util::urlencode;

// ═══════════════════════════════════════════════════════════════════
//  Domain results
// ═══════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct DomainResults {
    #[serde(default)]
    domain: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    scan_date: String,
    #[serde(default)]
    results: DomainData,
}

#[derive(Deserialize, Default)]
struct DomainData {
    #[serde(default)]
    subdomains: Vec<String>,
    #[serde(default)]
    subdomains_suspicious: Vec<SuspiciousSub>,
    #[serde(default)]
    dns: DnsData,
    #[serde(default)]
    ssl: Vec<SslCert>,
    #[serde(default)]
    files: FilesData,
}

#[derive(Deserialize, Default)]
struct SuspiciousSub {
    #[serde(default)]
    keyword: String,
    #[serde(default)]
    subdomain: String,
}

#[derive(Deserialize, Default)]
struct DnsData {
    #[serde(default)]
    resolve: Vec<DnsResolve>,
    #[serde(default)]
    txt: TxtRecords,
}

#[derive(Deserialize, Default)]
struct DnsResolve {
    #[serde(default)]
    domain: String,
    #[serde(default)]
    a: Option<Vec<String>>,
    #[serde(default)]
    aaaa: Option<Vec<String>>,
    #[serde(default)]
    cname: Option<String>,
}

#[derive(Deserialize, Default)]
struct TxtRecords {
    #[serde(default)]
    raw: Vec<String>,
    #[serde(default)]
    spf: Option<String>,
    #[serde(default)]
    dmarc: Option<String>,
    #[serde(default)]
    dkim: Vec<String>,
}

#[derive(Deserialize, Default)]
struct FilesData {
    #[serde(default)]
    security_txt: String,
    #[serde(default)]
    robots_txt: String,
}

pub fn domain(client: &MlabClient, domain: &str, json: bool) {
    let body = fetch(client.get(&format!(
        "/scan/domain/results?domain={}",
        urlencode(domain)
    )));

    if json {
        print_json(&body);
        return;
    }

    let r: DomainResults = parse_or_exit(&body, "domain results");

    // The status route answers "success" for any non-pending scan, failures
    // included, so an empty report is the only signal the CLI gets that nothing
    // was actually produced.
    let empty = r.results.subdomains.is_empty()
        && r.results.subdomains_suspicious.is_empty()
        && r.results.dns.resolve.is_empty()
        && r.results.dns.txt.raw.is_empty()
        && r.results.ssl.is_empty()
        && r.results.files.robots_txt.is_empty()
        && r.results.files.security_txt.is_empty();

    print_domain_ui(&r);

    if empty {
        eprintln!(
            "  {} Empty report — the scan may have failed or is still running.",
            "warning:".yellow().bold()
        );
        eprintln!(
            "  Relaunch with: {}",
            format!("mlab scan domain {}", r.domain).dimmed()
        );
        eprintln!();
    }
}

fn print_domain_ui(r: &DomainResults) {
    let div = format!("  {}", "─".repeat(80));

    // ── Header ──
    let status_badge = match r.status.as_str() {
        "completed" => "✔ completed".green().bold(),
        "in_progress" => "⏳ in progress".yellow().bold(),
        "pending" => "⏳ pending".yellow().bold(),
        other => other.normal(),
    };

    println!();
    println!("  {} Domain Scan Results  [{}]", "🌐", status_badge);
    println!("{}", div.dimmed());
    println!("  {:<12} {}", "Domain:".dimmed(), r.domain.cyan().bold());
    if !r.scan_date.is_empty() {
        println!("  {:<12} {}", "Scanned:".dimmed(), r.scan_date);
    }
    println!();

    // ── Subdomains ──
    println!("  {}", "Subdomains".bold().underline());
    if r.results.subdomains.is_empty() {
        println!("  {}", "No subdomains discovered.".dimmed());
    } else {
        println!(
            "  Found {} subdomain(s):",
            r.results.subdomains.len().to_string().bold()
        );
        for sub in &r.results.subdomains {
            println!("    {} {}", "•".dimmed(), sub);
        }
    }
    println!();

    // ── Suspicious subdomains ──
    if !r.results.subdomains_suspicious.is_empty() {
        println!(
            "  {} {}",
            "⚠".yellow(),
            "Suspicious Subdomains".bold().underline().yellow()
        );
        for s in &r.results.subdomains_suspicious {
            println!(
                "    {} {}  (keyword: {})",
                "⚠".yellow(),
                s.subdomain.yellow(),
                s.keyword.red().bold(),
            );
        }
        println!();
    }

    // ── DNS ──
    println!("  {}", "DNS Records".bold().underline());

    for rec in &r.results.dns.resolve {
        let label = if rec.domain.is_empty() {
            r.domain.clone()
        } else {
            rec.domain.clone()
        };
        println!("  {}", label.cyan());

        if let Some(a) = &rec.a {
            if !a.is_empty() {
                println!("    {:<8} {}", "A".bold(), a.join(", "));
            }
        }
        if let Some(aaaa) = &rec.aaaa {
            if !aaaa.is_empty() {
                println!("    {:<8} {}", "AAAA".bold(), aaaa.join(", "));
            }
        }
        if let Some(cname) = &rec.cname {
            println!("    {:<8} {}", "CNAME".bold(), cname);
        }
    }
    println!();

    // ── TXT / SPF / DMARC / DKIM ──
    println!("  {}", "Email Security".bold().underline());
    let txt = &r.results.dns.txt;

    // SPF
    match &txt.spf {
        Some(spf) if !spf.is_empty() => {
            println!("    {:<8} {} {}", "SPF".bold(), "✔".green(), spf);
        }
        _ => {
            println!("    {:<8} {} {}", "SPF".bold(), "✘".red(), "Not configured".red());
        }
    }

    // DMARC
    match &txt.dmarc {
        Some(dmarc) if !dmarc.is_empty() => {
            println!("    {:<8} {} {}", "DMARC".bold(), "✔".green(), dmarc);
        }
        _ => {
            println!(
                "    {:<8} {} {}",
                "DMARC".bold(),
                "✘".red(),
                "Not configured".red()
            );
        }
    }

    // DKIM
    if txt.dkim.is_empty() {
        println!(
            "    {:<8} {} {}",
            "DKIM".bold(),
            "✘".red(),
            "No records found".red()
        );
    } else {
        for (i, dk) in txt.dkim.iter().enumerate() {
            if i == 0 {
                println!("    {:<8} {} {}", "DKIM".bold(), "✔".green(), dk);
            } else {
                println!("    {:<8}   {}", "", dk);
            }
        }
    }

    // Raw TXT
    if !txt.raw.is_empty() {
        println!();
        println!("  {}", "TXT Records".bold().underline());
        for entry in &txt.raw {
            println!("    {}", entry.dimmed());
        }
    }
    println!();

    // ── Files ──
    println!("  {}", "Discovered Files".bold().underline());

    print_file_content("security.txt", &r.results.files.security_txt);
    print_file_content("robots.txt", &r.results.files.robots_txt);
    println!();

    // ── SSL ──
    // The certificates ship with this very response; pointing the user at
    // another command for data already on screen was pure waste.
    println!("  {}", "SSL Certificates".bold().underline());
    if r.results.ssl.is_empty() {
        println!("  {}", "None recorded for this domain.".dimmed());
        println!();
    } else {
        const SHOWN: usize = 5;
        let shown = r.results.ssl.len().min(SHOWN);
        println!(
            "  Showing {} of {} certificate(s):",
            shown.to_string().bold(),
            r.results.ssl.len().to_string().bold()
        );
        println!();
        render_table(&r.results.ssl[..shown], false);
        if r.results.ssl.len() > shown {
            println!(
                "  {}",
                format!("Full history: mlab ssl {}", r.domain).dimmed()
            );
            println!();
        }
    }

    println!("{}", div.dimmed());
    println!();
}

fn print_file_content(name: &str, content: &str) {
    let trimmed = content.trim();
    if trimmed.is_empty()
        || trimmed.to_lowercase().contains("error 404")
        || trimmed.to_lowercase().contains("not found")
    {
        println!(
            "    {:<16} {}",
            name.bold(),
            "Not found".dimmed()
        );
    } else {
        println!("    {}", name.bold());
        let lines: Vec<&str> = trimmed.lines().collect();
        let max = 15;
        for line in lines.iter().take(max) {
            println!("      {}", line.dimmed());
        }
        if lines.len() > max {
            println!(
                "      {} ({} more lines, use {} to see full output)",
                "...".dimmed(),
                lines.len() - max,
                "--json".cyan(),
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  File results
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
//  File results
// ═══════════════════════════════════════════════════════════════════

/// Rendered from a `Value` rather than a struct on purpose: this payload has
/// already changed shape once in production (`jobs_total`/`analysis` became
/// `tools_total`/`tools`, and the published OpenAPI example still shows the old
/// one). A typed parse turns that into "unreadable response" and no report at
/// all; reading defensively keeps the command useful across both.
pub fn file(client: &MlabClient, sha256: &str, tool: Option<&str>, json: bool) {
    if let Some(tool) = tool {
        return tool_output(client, sha256, tool, json);
    }

    let body = fetch(client.get(&format!(
        "/scan/file/results?sha256={}",
        urlencode(sha256)
    )));

    if json {
        print_json(&body);
        return;
    }

    let v: serde_json::Value = parse_or_exit(&body, "file results");
    print_file_ui(&v);
}

/// One tool's raw output, fetched on demand — the summary deliberately omits it.
fn tool_output(client: &MlabClient, sha256: &str, tool: &str, json: bool) {
    let body = fetch(client.get(&format!(
        "/scan/file/output?sha256={}&tool={}",
        urlencode(sha256),
        urlencode(tool)
    )));

    if json {
        print_json(&body);
        return;
    }

    let v: serde_json::Value = parse_or_exit(&body, "tool output");
    let output = v.get("output").and_then(|o| o.as_str()).unwrap_or("");

    if v.get("is_json").and_then(|b| b.as_bool()).unwrap_or(false) {
        // Stored as a JSON string; pretty-print it rather than showing one line.
        match serde_json::from_str::<serde_json::Value>(output) {
            Ok(parsed) => println!("{}", serde_json::to_string_pretty(&parsed).unwrap_or_default()),
            Err(_) => println!("{output}"),
        }
    } else {
        println!("{output}");
    }
}

fn print_file_ui(r: &serde_json::Value) {
    let div = format!("  {}", "─".repeat(80));
    let status = r.get("status").and_then(|s| s.as_str()).unwrap_or("unknown");

    let status_badge = match status {
        "completed" => "✔ completed".green().bold(),
        "partial" => "◐ partial".yellow().bold(),
        "failed" => "✖ failed".red().bold(),
        "in_progress" | "running" => "⏳ in progress".yellow().bold(),
        "pending" => "⏳ pending".yellow().bold(),
        other => other.normal(),
    };

    println!();
    println!("  {} File Scan Results  [{}]", "📄", status_badge);
    println!("{}", div.dimmed());

    if let Some(error) = r.get("error") {
        let message = error.get("message").and_then(|m| m.as_str()).unwrap_or("The scan failed.");
        let reason = error.get("reason").and_then(|m| m.as_str()).unwrap_or("");
        println!("  {} {}", "✖".red().bold(), message.red());
        if !reason.is_empty() {
            println!("  {:<12} {}", "Reason:".dimmed(), reason);
        }
        println!();
    }

    // ── File metadata ──
    let file = r.get("file").cloned().unwrap_or(serde_json::Value::Null);
    let name = file
        .get("display_name")
        .or_else(|| file.get("filename"))
        .and_then(|n| n.as_str())
        .unwrap_or("");

    println!("  {}", "File Info".bold().underline());
    if !name.is_empty() {
        println!("  {:<12} {}", "Name:".dimmed(), name);
    }
    if let Some(mime) = file.get("mime_type").and_then(|m| m.as_str()) {
        if !mime.is_empty() {
            println!("  {:<12} {}", "MIME:".dimmed(), mime);
        }
    }
    if let Some(size) = file.get("size").and_then(|s| s.as_u64()) {
        println!("  {:<12} {}", "Size:".dimmed(), format_size(size));
    }
    if let Some(created) = file.get("created_at").and_then(|c| c.as_str()) {
        println!("  {:<12} {}", "Created:".dimmed(), format_date(created));
    }
    println!();

    // ── Hashes ──
    println!("  {}", "Hashes".bold().underline());
    for (label, key) in [("SHA-256:", "sha256"), ("SHA-1:", "sha1"), ("MD5:", "md5"), ("ssdeep:", "ssdeep")] {
        if let Some(value) = file.get(key).and_then(|v| v.as_str()) {
            if !value.is_empty() {
                println!("  {:<12} {}", label.dimmed(), value);
            }
        }
    }
    println!();

    // ── Progress ──
    let done = r.get("tools_done").or_else(|| r.get("jobs_completed")).and_then(|v| v.as_u64()).unwrap_or(0);
    let total = r.get("tools_total").or_else(|| r.get("jobs_total")).and_then(|v| v.as_u64()).unwrap_or(0);
    println!(
        "  {} {}  {}",
        "Tools:".bold(),
        progress_bar(done as u32, total.max(done) as u32, 20),
        format!("{done}/{total}").bold(),
    );
    println!("{}", div.dimmed());

    print_tools(r);
    print_observations(r);
    print_sightings(r);

    if let Some(sha) = file.get("sha256").and_then(|s| s.as_str()) {
        if !sha.is_empty() {
            println!(
                "  {}",
                format!("Raw output of one tool: mlab results file {sha} --tool <name>").dimmed()
            );
            println!();
        }
    }
}

fn print_tools(r: &serde_json::Value) {
    // `tools` is the current shape; `analysis` was the previous one.
    if let Some(tools) = r.get("tools").and_then(|t| t.as_array()) {
        if tools.is_empty() {
            println!("  {}", "No tool has reported yet.".dimmed());
            println!();
            return;
        }
        println!();
        println!(
            "  {:<18} {:<12} {:<10} {:<10} {}",
            "Tool".bold().underline(),
            "Status".bold().underline(),
            "Exit".bold().underline(),
            "Duration".bold().underline(),
            "Output".bold().underline(),
        );
        for t in tools {
            let status = t.get("status").and_then(|s| s.as_str()).unwrap_or("-");
            let coloured = match status {
                "completed" | "ok" | "success" => status.green(),
                "failed" | "error" => status.red(),
                other => other.yellow(),
            };
            println!(
                "  {:<18} {:<12} {:<10} {:<10} {}",
                t.get("tool").and_then(|x| x.as_str()).unwrap_or("-"),
                coloured,
                t.get("exit_code").map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
                t.get("duration_ms").and_then(|d| d.as_u64()).map(|d| format!("{d} ms")).unwrap_or_else(|| "-".into()),
                format_size(t.get("output_bytes").and_then(|b| b.as_u64()).unwrap_or(0)).dimmed(),
            );
            if let Some(note) = t.get("note").and_then(|n| n.as_str()) {
                if !note.is_empty() {
                    println!("  {:<18} {}", "", note.dimmed());
                }
            }
        }
        println!();
        return;
    }

    if let Some(jobs) = r.get("analysis").and_then(|a| a.as_array()) {
        for job in jobs {
            let name = job.get("job_name").and_then(|n| n.as_str()).unwrap_or("job");
            println!();
            println!("  {} {}", "▶".cyan(), format!(" {} ", name.to_uppercase()).on_cyan().white().bold());
            let data = job.get("data").cloned().unwrap_or_default();
            let text = match &data {
                serde_json::Value::String(s) => s.clone(),
                other => serde_json::to_string_pretty(other).unwrap_or_default(),
            };
            for line in text.lines().take(30) {
                println!("      {}", line.dimmed());
            }
        }
        println!();
    }
}

fn print_observations(r: &serde_json::Value) {
    let Some(groups) = r.get("observations").and_then(|o| o.as_object()) else { return };
    if groups.is_empty() {
        return;
    }
    println!("  {}", "Indicators".bold().underline());
    for (kind, entries) in groups {
        let Some(list) = entries.as_array() else { continue };
        println!("    {} ({})", kind.bold(), list.len());
        for entry in list.iter().take(20) {
            let value = entry.get("value").and_then(|v| v.as_str()).unwrap_or("");
            let tool = entry.get("tool").and_then(|t| t.as_str()).unwrap_or("");
            println!("      {} {}  {}", "•".dimmed(), value, tool.dimmed());
        }
        if list.len() > 20 {
            println!("      {}", format!("… {} more", list.len() - 20).dimmed());
        }
    }
    println!();
}

fn print_sightings(r: &serde_json::Value) {
    let Some(list) = r.get("sightings").and_then(|s| s.as_array()) else { return };
    if list.is_empty() {
        return;
    }
    // Distribution URLs and lure names: live malicious values, shown as text and
    // never dressed up as something to click.
    println!("  {}", "Sightings".bold().underline());
    for s in list.iter().take(20) {
        println!(
            "    {:<12} {}",
            s.get("kind").and_then(|k| k.as_str()).unwrap_or("-").dimmed(),
            s.get("value").and_then(|v| v.as_str()).unwrap_or(""),
        );
    }
    println!();
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn format_date(raw: &str) -> String {
    raw.replace('T', " ")
        .replace("+00:00", " UTC")
        .replace("+0000", " UTC")
}

fn progress_bar(done: u32, total: u32, width: usize) -> String {
    if total == 0 {
        return format!("{}", "░".repeat(width).dimmed());
    }
    let ratio = (done as f64 / total as f64).min(1.0);
    let filled = (ratio * width as f64).round() as usize;
    let empty = width - filled;

    let color_bar = if ratio >= 1.0 {
        "█".repeat(filled).green().to_string()
    } else {
        "█".repeat(filled).yellow().to_string()
    };

    format!("{}{}", color_bar, "░".repeat(empty).dimmed())
}

