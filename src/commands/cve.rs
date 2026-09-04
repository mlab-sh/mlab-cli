use colored::Colorize;
use serde::Deserialize;

use crate::client::HostClient;
use crate::commands::vuln_body;
use crate::ui;
use crate::util::urlencode;

#[derive(Deserialize)]
struct SearchResponse {
    total_results: u64,
    #[serde(default)]
    results_per_page: u64,
    #[serde(default)]
    start_index: u64,
    cves: Vec<CveSummary>,
}

#[derive(Deserialize)]
struct CveSummary {
    id: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    published: String,
    #[serde(default)]
    cvss_score: Option<f64>,
    #[serde(default)]
    cvss_severity: Option<String>,
    #[serde(default)]
    in_kev: Option<bool>,
}

#[derive(Deserialize)]
struct CveDetail {
    id: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    published: String,
    #[serde(default)]
    last_modified: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    cvss_score: Option<f64>,
    #[serde(default)]
    cvss_severity: Option<String>,
    #[serde(default)]
    cvss_vector: Option<String>,
    #[serde(default)]
    epss_score: Option<f64>,
    #[serde(default)]
    epss_percentile: Option<f64>,
    #[serde(default)]
    in_kev: Option<bool>,
    #[serde(default)]
    kev_date_added: Option<String>,
    #[serde(default)]
    kev_due_date: Option<String>,
    #[serde(default)]
    weaknesses: Vec<serde_json::Value>,
    #[serde(default)]
    references: Vec<Reference>,
}

#[derive(Deserialize)]
struct Reference {
    url: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

fn fetch(client: &HostClient, path: &str) -> String {
    vuln_body(client.get(path))
}

/// Build the filter query these routes share: search, CSV export and the RSS
/// feed all read the same parameters server-side.
fn filter_query(query: &str, opts: &SearchOptions) -> String {
    let mut path = format!("?q={}", urlencode(query));
    let mut push = |key: &str, value: &str| {
        path.push_str(&format!("&{key}={}", urlencode(value)));
    };

    if let Some(v) = opts.severity {
        push("severity", v);
    }
    if let Some(v) = opts.date_start {
        push("dateStart", v);
    }
    if let Some(v) = opts.date_end {
        push("dateEnd", v);
    }
    if let Some(v) = opts.vendor {
        push("vendor", v);
    }
    if let Some(v) = opts.cwe {
        push("cwe", v);
    }
    if let Some(v) = opts.min_cvss {
        push("minCvss", &v.to_string());
    }
    if opts.kev_only {
        push("kevOnly", "1");
    }
    if opts.exact {
        push("exact", "1");
    }
    path
}

fn color_severity(sev: &str) -> colored::ColoredString {
    match sev.to_uppercase().as_str() {
        "CRITICAL" => sev.red().bold(),
        "HIGH" => sev.red(),
        "MEDIUM" => sev.yellow(),
        "LOW" => sev.green(),
        _ => sev.normal(),
    }
}

pub struct SearchOptions<'a> {
    pub severity: Option<&'a str>,
    pub date_start: Option<&'a str>,
    pub date_end: Option<&'a str>,
    pub vendor: Option<&'a str>,
    pub cwe: Option<&'a str>,
    pub min_cvss: Option<f64>,
    pub kev_only: bool,
    pub exact: bool,
    pub page: u32,
    pub limit: Option<u32>,
}

pub fn search(client: &HostClient, query: &str, opts: &SearchOptions, json: bool) {
    let mut path = format!("/api/v1/cve{}", filter_query(query, opts));
    if opts.page > 0 {
        path.push_str(&format!("&page={}", opts.page));
    }
    if let Some(v) = opts.limit {
        path.push_str(&format!("&limit={v}"));
    }

    let body = ui::with_spinner(&format!("Searching CVEs for {query}"), || fetch(client, &path));

    if json {
        crate::commands::print_json(&body);
        return;
    }

    let r: SearchResponse = crate::commands::parse_or_exit(&body, "CVE search");
    print_summary_list(&r.cves, r.total_results, r.start_index, r.results_per_page);
    print_pagination_hint(&r, opts);
}

/// The API pages results but never says so; without this a user reads the first
/// 20 hits and assumes that is everything.
fn print_pagination_hint(r: &SearchResponse, opts: &SearchOptions) {
    if r.results_per_page == 0 || r.total_results <= r.start_index + r.cves.len() as u64 {
        return;
    }
    println!(
        "  {}",
        format!(
            "More results — rerun with --page {}",
            opts.page + 1
        )
        .dimmed()
    );
    println!();
}

pub fn latest(client: &HostClient, json: bool) {
    let body = ui::with_spinner("Fetching the latest CVEs", || {
        fetch(client, "/api/v1/cve/latest")
    });

    if json {
        crate::commands::print_json(&body);
        return;
    }

    let r: SearchResponse = crate::commands::parse_or_exit(&body, "CVE feed");

    println!();
    println!("  {} CVEs published in the last 7 days", "🆕".to_string());
    print_summary_list(&r.cves, r.total_results, r.start_index, r.results_per_page);
}

pub fn detail(client: &HostClient, cve_id: &str, json: bool) {
    let path = format!("/api/v1/cve/{}", urlencode(cve_id));
    let body = ui::with_spinner(&format!("Fetching {cve_id}"), || fetch(client, &path));

    if json {
        crate::commands::print_json(&body);
        return;
    }

    let d: CveDetail = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => {
            println!("{body}");
            return;
        }
    };

    print_detail(&d);
}

fn print_summary_list(cves: &[CveSummary], total: u64, start: u64, per_page: u64) {
    let div = format!("  {}", "─".repeat(72));
    println!("{}", div.dimmed());
    if cves.is_empty() {
        println!("  {}", "No results.".dimmed());
        println!("{}", div.dimmed());
        println!();
        return;
    }

    let shown_end = start + cves.len() as u64;
    println!(
        "  {} {}-{} of {} total (page size {})",
        "Results:".dimmed(),
        start + 1,
        shown_end,
        total,
        per_page,
    );
    println!("{}", div.dimmed());

    for c in cves {
        let sev = c.cvss_severity.as_deref().unwrap_or("");
        let score = c
            .cvss_score
            .map(|s| format!("{:.1}", s))
            .unwrap_or_else(|| "—".to_string());
        let kev = if c.in_kev.unwrap_or(false) {
            " 🚨KEV".red().to_string()
        } else {
            String::new()
        };
        let date = c.published.split('T').next().unwrap_or("");

        println!(
            "  {} {} {} {} {}",
            c.id.cyan().bold(),
            format!("[{}]", color_severity(sev)),
            format!("CVSS {score}").bold(),
            date.dimmed(),
            kev,
        );
        let desc = truncate(&c.description, 200);
        println!("    {}", desc.dimmed());
    }
    println!("{}", div.dimmed());
    println!();
}

fn print_detail(d: &CveDetail) {
    let div = format!("  {}", "─".repeat(72));
    let kev_badge = if d.in_kev.unwrap_or(false) {
        " 🚨 KEV".red().bold().to_string()
    } else {
        String::new()
    };

    println!();
    println!("  {} {}{}", "🛡 ".to_string(), d.id.cyan().bold(), kev_badge);
    println!("{}", div.dimmed());

    if let Some(sev) = &d.cvss_severity {
        let score = d
            .cvss_score
            .map(|s| format!("{:.1}", s))
            .unwrap_or_else(|| "—".to_string());
        println!(
            "  {:<14} {} ({})",
            "CVSS:".dimmed(),
            score.bold(),
            color_severity(sev),
        );
    }
    if let Some(v) = &d.cvss_vector {
        println!("  {:<14} {}", "Vector:".dimmed(), v);
    }
    if let Some(score) = d.epss_score {
        let pct = d.epss_percentile.unwrap_or(0.0) * 100.0;
        println!(
            "  {:<14} {:.4} (percentile {:.1}%)",
            "EPSS:".dimmed(),
            score,
            pct,
        );
    }
    if d.in_kev.unwrap_or(false) {
        if let Some(added) = &d.kev_date_added {
            println!("  {:<14} added {}", "KEV:".dimmed(), added);
        }
        if let Some(due) = &d.kev_due_date {
            println!("  {:<14} {}", "Due:".dimmed(), due);
        }
    }
    if !d.published.is_empty() {
        println!("  {:<14} {}", "Published:".dimmed(), d.published);
    }
    if !d.last_modified.is_empty() {
        println!("  {:<14} {}", "Modified:".dimmed(), d.last_modified);
    }
    if let Some(s) = &d.status {
        println!("  {:<14} {}", "Status:".dimmed(), s);
    }

    if !d.description.is_empty() {
        println!();
        println!("  {}", "Description".bold().underline());
        for line in wrap(&d.description, 70) {
            println!("  {}", line);
        }
    }

    if !d.weaknesses.is_empty() {
        println!();
        println!("  {}", "Weaknesses".bold().underline());
        for w in &d.weaknesses {
            let s = match w {
                serde_json::Value::String(s) => s.clone(),
                other => serde_json::to_string(other).unwrap_or_default(),
            };
            println!("  • {}", s);
        }
    }

    if !d.references.is_empty() {
        println!();
        println!("  {} ({})", "References".bold().underline(), d.references.len());
        for r in d.references.iter().take(15) {
            let tags = if r.tags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", r.tags.join(", ")).dimmed().to_string()
            };
            let src = r
                .source
                .as_deref()
                .map(|s| format!(" — {}", s))
                .unwrap_or_default();
            println!("  • {}{}{}", r.url.blue(), src.dimmed(), tags);
        }
        if d.references.len() > 15 {
            println!(
                "  {}",
                format!("… and {} more", d.references.len() - 15).dimmed()
            );
        }
    }

    println!("{}", div.dimmed());
    println!();
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.replace('\n', " ");
    if s.chars().count() <= max {
        s
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for paragraph in s.split('\n') {
        let mut current = String::new();
        for word in paragraph.split_whitespace() {
            if current.is_empty() {
                current.push_str(word);
            } else if current.len() + 1 + word.len() > width {
                lines.push(std::mem::take(&mut current));
                current.push_str(word);
            } else {
                current.push(' ');
                current.push_str(word);
            }
        }
        if !current.is_empty() {
            lines.push(current);
        }
    }
    lines
}

// ═══════════════════════════════════════════════════════════════════
//  Bulk and reference routes
// ═══════════════════════════════════════════════════════════════════

/// The heaviest anonymous route on the host, and the only one with a per-IP
/// budget: refusals come back as 429 + `Retry-After`, which the client honours.
pub fn dump(
    client: &HostClient,
    date_start: Option<&str>,
    date_end: Option<&str>,
    min_cvss: Option<f64>,
) {
    let mut path = String::from("/api/v1/cve/dump?");
    if let Some(v) = date_start {
        path.push_str(&format!("dateStart={}&", urlencode(v)));
    }
    if let Some(v) = date_end {
        path.push_str(&format!("dateEnd={}&", urlencode(v)));
    }
    if let Some(v) = min_cvss {
        path.push_str(&format!("minCvss={v}&"));
    }

    let body = ui::with_spinner("Downloading the CVE dump", || fetch(client, &path));
    // Always raw: a dump exists to be piped into a file or jq.
    println!("{body}");
}

pub fn stats(client: &HostClient, json: bool) {
    let body = ui::with_spinner("Fetching statistics", || fetch(client, "/api/v1/stats"));
    if json {
        crate::commands::print_json(&body);
        return;
    }
    render_rows(&body, "📊", "CVE Statistics");
}

pub fn sources(client: &HostClient, json: bool) {
    let body = ui::with_spinner("Fetching sources", || fetch(client, "/api/v1/sources"));
    if json {
        crate::commands::print_json(&body);
        return;
    }
    render_rows(&body, "🗂", "Advisory Sources");
}

pub fn advisories(client: &HostClient, cve: Option<&str>, country: Option<&str>, limit: Option<u32>, json: bool) {
    let mut path = String::from("/api/v1/advisories?");
    if let Some(v) = cve {
        path.push_str(&format!("cve={}&", urlencode(v)));
    }
    if let Some(v) = country {
        path.push_str(&format!("country={}&", urlencode(v)));
    }
    if let Some(v) = limit {
        path.push_str(&format!("limit={v}&"));
    }

    let body = ui::with_spinner("Fetching advisories", || fetch(client, &path));
    if json {
        crate::commands::print_json(&body);
        return;
    }

    let v: serde_json::Value = crate::commands::parse_or_exit(&body, "advisories");
    // Two shapes: `?cve=` answers an object, the listing answers an array.
    let rows = v
        .get("advisories")
        .cloned()
        .unwrap_or(v.clone());
    render_value_rows(&rows, "🏛", "Advisories");
}

pub fn vendor_months(client: &HostClient, vendor: &str, year: u32, json: bool) {
    let path = format!("/api/v1/vendor/{}/months?year={year}", urlencode(vendor));
    let body = ui::with_spinner(&format!("Fetching {vendor} {year}"), || fetch(client, &path));

    if json {
        crate::commands::print_json(&body);
        return;
    }

    let v: serde_json::Value = crate::commands::parse_or_exit(&body, "vendor");
    let months = v.get("months").and_then(|m| m.as_array()).cloned().unwrap_or_default();
    let counts: Vec<u64> = months.iter().map(|m| m.as_u64().unwrap_or(0)).collect();
    let peak = counts.iter().copied().max().unwrap_or(0).max(1);

    println!();
    println!("  {} {} — {}", "📈", vendor.cyan().bold(), year.to_string().bold());
    println!("{}", format!("  {}", "─".repeat(56)).dimmed());
    for (i, count) in counts.iter().enumerate() {
        let width = ((*count as f64 / peak as f64) * 30.0).round() as usize;
        println!(
            "  {:<5} {:<32} {}",
            MONTHS.get(i).copied().unwrap_or("?"),
            "█".repeat(width).cyan(),
            count.to_string().bold()
        );
    }
    println!("{}", format!("  {}", "─".repeat(56)).dimmed());
    println!();
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// CSV and RSS live at the site root, NOT under `/api/v1` — the paths the Node
/// SDK documents (`/api/v1/export/csv`, `/api/v1/rss`) do not exist.
pub fn export(client: &HostClient, query: &str, opts: &SearchOptions, format: &str) {
    let path = match format {
        "rss" => format!("/rss{}", filter_query(query, opts)),
        _ => format!("/export/csv{}", filter_query(query, opts)),
    };
    let body = ui::with_spinner(&format!("Exporting as {format}"), || fetch(client, &path));
    println!("{body}");
}

fn render_rows(body: &str, icon: &str, title: &str) {
    let v: serde_json::Value = crate::commands::parse_or_exit(body, title);
    render_value_rows(&v, icon, title);
}

fn render_value_rows(v: &serde_json::Value, icon: &str, title: &str) {
    println!();
    println!("  {icon} {}", title.bold());
    println!("{}", format!("  {}", "─".repeat(72)).dimmed());

    match v {
        serde_json::Value::Array(rows) if !rows.is_empty() => {
            for row in rows {
                match row {
                    serde_json::Value::Object(fields) => {
                        let line: Vec<String> = fields
                            .iter()
                            .filter(|(_, val)| !val.is_null())
                            .map(|(k, val)| {
                                let rendered = match val {
                                    serde_json::Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                };
                                format!("{}: {}", k.dimmed(), rendered)
                            })
                            .collect();
                        println!("  {}", line.join("   "));
                    }
                    other => println!("  {other}"),
                }
            }
        }
        serde_json::Value::Object(fields) => {
            for (k, val) in fields {
                let rendered = match val {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                println!("  {:<22} {}", format!("{k}:").dimmed(), rendered);
            }
        }
        _ => println!("  {}", "No data.".dimmed()),
    }

    println!("{}", format!("  {}", "─".repeat(72)).dimmed());
    println!();
}
