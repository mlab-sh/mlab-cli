use colored::Colorize;
use serde::Deserialize;

use crate::client::{build_http_client, retry_after};
use crate::error::ApiError;
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

fn fetch(hostname: &str, path: &str) -> String {
    let url = format!("{}{}", hostname.trim_end_matches('/'), path);
    let client = build_http_client();

    for attempt in 1..=3u32 {
        let resp = match client.get(&url).send() {
            Ok(r) => r,
            Err(e) if attempt < 3 && (e.is_timeout() || e.is_connect()) => {
                std::thread::sleep(std::time::Duration::from_millis(300 * attempt as u64));
                continue;
            }
            Err(e) => ApiError::transport(e).report(),
        };

        let status = resp.status();

        // The CVE host rate-limits its heaviest route and names the delay.
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let delay = retry_after(&resp);
            if let Some(d) = delay {
                if attempt < 3 && d.as_secs() <= 30 {
                    std::thread::sleep(d);
                    continue;
                }
            }
            let wait = delay.map(|d| format!(" — retry in {}s", d.as_secs())).unwrap_or_default();
            ApiError::new(Some(429), format!("rate limited by the CVE API{wait}")).report();
        }

        let body = resp.text().unwrap_or_default();

        if !status.is_success() {
            ApiError::from_response(status.as_u16(), &body).report();
        }

        // This host reports failures inside a 200 body, so the status code is
        // not enough to know the call succeeded.
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
            if let Some(message) = v.get("error").and_then(|e| e.as_str()) {
                ApiError::new(None, message).report();
            }
        }

        return body;
    }

    ApiError::new(None, "the CVE API did not answer").report()
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

pub fn search(hostname: &str, query: &str, opts: &SearchOptions, json: bool) {
    let mut path = format!("/api/v1/cve?q={}", urlencode(query));

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
    if opts.page > 0 {
        push("page", &opts.page.to_string());
    }
    if let Some(v) = opts.limit {
        push("limit", &v.to_string());
    }

    let body = ui::with_spinner(&format!("Searching CVEs for {query}"), || fetch(hostname, &path));

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

pub fn latest(hostname: &str, json: bool) {
    let body = ui::with_spinner("Fetching the latest CVEs", || {
        fetch(hostname, "/api/v1/cve/latest")
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

pub fn detail(hostname: &str, cve_id: &str, json: bool) {
    let path = format!("/api/v1/cve/{}", urlencode(cve_id));
    let body = ui::with_spinner(&format!("Fetching {cve_id}"), || fetch(hostname, &path));

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
