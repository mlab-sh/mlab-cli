use colored::Colorize;
use serde::Deserialize;

use crate::client::MlabClient;

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
    let resp = match client.get(&format!("/scan/domain/results?domain={}", domain)) {
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
        // Remove ssl from JSON output too? No, keep raw for --json
        match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(_) => println!("{body}"),
        }
        return;
    }

    let r: DomainResults = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("{} Failed to parse domain results.", "error:".red().bold());
            eprintln!("{body}");
            std::process::exit(1);
        }
    };

    print_domain_ui(&r);
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

    // ── SSL hint ──
    println!("{}", div.dimmed());
    println!(
        "  {} SSL certificates are not shown here. Use {} to view them.",
        "ℹ".cyan(),
        format!("mlab ssl {}", r.domain).cyan().bold(),
    );
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

#[derive(Deserialize)]
struct FileResults {
    status: String,
    file: FileInfo,
    jobs_total: u32,
    jobs_completed: u32,
    analysis: Vec<AnalysisJob>,
}

#[derive(Deserialize)]
struct FileInfo {
    sha256: String,
    md5: String,
    #[serde(default)]
    ssdeep: String,
    filename: String,
    size: u64,
    mime_type: String,
    created_at: String,
}

#[derive(Deserialize)]
struct AnalysisJob {
    job_name: String,
    end_date: String,
    data: serde_json::Value,
}

pub fn file(client: &MlabClient, sha256: &str, json: bool) {
    let resp = match client.get(&format!("/scan/file/results?sha256={}", sha256)) {
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

    let results: FileResults = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("{} Failed to parse file results.", "error:".red().bold());
            eprintln!("{body}");
            std::process::exit(1);
        }
    };

    print_file_ui(&results);
}

fn print_file_ui(r: &FileResults) {
    let div = format!("  {}", "─".repeat(80));

    // ── Header ──
    let status_badge = match r.status.as_str() {
        "completed" => "✔ completed".green().bold(),
        "in_progress" => "⏳ in progress".yellow().bold(),
        "pending" => "⏳ pending".yellow().bold(),
        other => other.normal(),
    };
    println!();
    println!("  {} File Scan Results  [{}]", "📄", status_badge);
    println!("{}", div.dimmed());

    // ── File metadata ──
    println!("  {}", "File Info".bold().underline());
    println!("  {:<12} {}", "Filename:".dimmed(), r.file.filename);
    println!("  {:<12} {}", "MIME:".dimmed(), r.file.mime_type);
    println!("  {:<12} {}", "Size:".dimmed(), format_size(r.file.size));
    println!("  {:<12} {}", "Created:".dimmed(), format_date(&r.file.created_at));
    println!();

    // ── Hashes ──
    println!("  {}", "Hashes".bold().underline());
    println!("  {:<12} {}", "SHA-256:".dimmed(), r.file.sha256);
    println!("  {:<12} {}", "MD5:".dimmed(), r.file.md5);
    if !r.file.ssdeep.is_empty() {
        println!("  {:<12} {}", "ssdeep:".dimmed(), r.file.ssdeep);
    }
    println!();

    // ── Jobs progress ──
    let progress = format!("{}/{}", r.jobs_completed, r.jobs_total);
    let bar = progress_bar(r.jobs_completed, r.jobs_total.max(r.jobs_completed), 20);
    println!(
        "  {} {}  {}",
        "Jobs:".bold(),
        bar,
        progress.bold(),
    );
    println!("{}", div.dimmed());

    // ── Analysis results ──
    if r.analysis.is_empty() {
        println!("  {}", "No analysis results yet.".dimmed());
        println!();
        return;
    }

    for (i, job) in r.analysis.iter().enumerate() {
        let job_label = format!(" {} ", job.job_name.to_uppercase());
        let end = format_date(&job.end_date);

        println!();
        println!(
            "  {} {}  {}",
            "▶".cyan(),
            job_label.on_cyan().white().bold(),
            format!("completed {end}").dimmed(),
        );
        println!();

        let data_str = match &job.data {
            serde_json::Value::String(s) => s.clone(),
            other => serde_json::to_string_pretty(other).unwrap_or_default(),
        };

        let lines: Vec<&str> = data_str.lines().collect();
        let max_lines = 30;
        let truncated = lines.len() > max_lines;

        for line in lines.iter().take(max_lines) {
            println!("    {}", line);
        }

        if truncated {
            println!(
                "    {} ({} more lines, use {} to see full output)",
                "...".dimmed(),
                lines.len() - max_lines,
                "--json".cyan(),
            );
        }

        if i < r.analysis.len() - 1 {
            println!("  {}", "· · ·".dimmed());
        }
    }

    println!();
    println!("{}", div.dimmed());
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
