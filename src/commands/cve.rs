use colored::Colorize;
use reqwest::blocking::Client;
use serde::Deserialize;

const DEFAULT_HOSTNAME: &str = "https://vuln.mlab.sh";

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
    let resp = match Client::new().get(&url).send() {
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
    body
}

pub fn resolve_hostname(override_host: Option<&str>) -> String {
    override_host
        .map(|s| s.to_string())
        .unwrap_or_else(|| DEFAULT_HOSTNAME.to_string())
}

fn urlencode(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
                vec![c]
            } else {
                format!("%{:02X}", c as u32).chars().collect::<Vec<_>>()
            }
        })
        .collect()
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

pub fn search(
    hostname: &str,
    query: &str,
    severity: Option<&str>,
    date_start: Option<&str>,
    exact: bool,
    json: bool,
) {
    let mut path = format!("/api/v1/cve?q={}", urlencode(query));
    if let Some(s) = severity {
        path.push_str(&format!("&severity={}", urlencode(s)));
    }
    if let Some(d) = date_start {
        path.push_str(&format!("&dateStart={}", urlencode(d)));
    }
    if exact {
        path.push_str("&exact=1");
    }

    let body = fetch(hostname, &path);

    if json {
        match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(_) => println!("{body}"),
        }
        return;
    }

    let r: SearchResponse = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            println!("{body}");
            return;
        }
    };

    print_summary_list(&r.cves, r.total_results, r.start_index, r.results_per_page);
}

pub fn latest(hostname: &str, json: bool) {
    let body = fetch(hostname, "/api/v1/cve/latest");

    if json {
        match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(_) => println!("{body}"),
        }
        return;
    }

    let r: SearchResponse = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            println!("{body}");
            return;
        }
    };

    println!();
    println!("  {} CVEs published in the last 7 days", "🆕".to_string());
    print_summary_list(&r.cves, r.total_results, r.start_index, r.results_per_page);
}

pub fn detail(hostname: &str, cve_id: &str, json: bool) {
    let path = format!("/api/v1/cve/{}", urlencode(cve_id));
    let body = fetch(hostname, &path);

    if json {
        match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(_) => println!("{body}"),
        }
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
