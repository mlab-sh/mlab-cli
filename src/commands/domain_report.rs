//! Domain scan report, v2 (`/scan/domain/report`, `schema: "domain-report/2"`).
//!
//! The v2 contract is additive: new fields appear, none are renamed. So the
//! report is read as a `serde_json::Value` and every field is optional here —
//! a section the scan predates prints nothing instead of failing the command.

use colored::Colorize;
use serde_json::Value;

use crate::client::MlabClient;
use crate::commands::lookup::severity_marker;
use crate::commands::ssl::{render_table, SslCert};
use crate::commands::{fetch, parse_or_exit, print_json};
use crate::error::{ApiError, ErrorKind};
use crate::output;
use crate::ui;
use crate::util::urlencode;

/// Findings shown before pointing at `--json` for the rest.
const MAX_FINDINGS: usize = 25;
/// Rows shown in a list (subdomains, technologies, MX…) before "N more".
const MAX_ROWS: usize = 10;

pub fn run(client: &MlabClient, domain: &str, json: bool) {
    let body = ui::with_spinner(&format!("Fetching report for {domain}"), || {
        fetch(client.get(&format!("/scan/domain/report?domain={}", urlencode(domain))))
    });

    let v: Value = parse_or_exit(&body, "domain report");
    if output::wants_json(json) {
        print_json(&body);
    } else {
        print_report(&v);
    }

    match text(&v["status"]).as_deref() {
        Some("failed") => ApiError {
            status: None,
            message: format!("the scan of {domain} failed"),
            kind: ErrorKind::Other,
        }
        .report(),
        Some("partial") => {
            ui::warning("Partial scan — some checks did not finish, the report is incomplete.")
        }
        Some("in_progress") => {
            ui::warning("Scan still running — the report is incomplete and not graded yet.");
            ui::info(&format!("Track it with: mlab status domain {domain}"));
        }
        _ => {}
    }
}

// ── Value helpers ────────────────────────────────────────────────────

/// A non-empty string, or a number / bool rendered as text.
fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn list(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}

fn count(v: &Value) -> usize {
    list(v).len()
}

fn row(label: &str, value: impl std::fmt::Display) {
    println!("    {:<16} {}", format!("{label}:").dimmed(), value);
}

fn row_opt(label: &str, v: &Value) {
    if let Some(s) = text(v) {
        row(label, s);
    }
}

fn yes_no(v: &Value) -> colored::ColoredString {
    match v.as_bool() {
        Some(true) => "✔ yes".green(),
        Some(false) => "✘ no".red(),
        None => "—".dimmed(),
    }
}

fn heading(title: &str) {
    println!();
    println!("  {}", title.bold().underline());
}

fn more(total: usize, shown: usize) {
    if total > shown {
        println!(
            "      {}",
            format!("… {} more (--json for all)", total - shown).dimmed()
        );
    }
}

pub fn severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" | "warning" | "warn" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

/// Findings, worst first. A stable sort keeps the server's order inside a
/// severity, which already groups them by section.
pub fn sorted_findings(v: &Value) -> Vec<&Value> {
    let mut f: Vec<&Value> = list(&v["findings"]).iter().collect();
    f.sort_by_key(|x| severity_rank(x["severity"].as_str().unwrap_or("")));
    f
}

// ── Rendering ────────────────────────────────────────────────────────

fn print_report(v: &Value) {
    let div = format!("  {}", "─".repeat(80));
    let domain = text(&v["domain"]).unwrap_or_default();

    let badge = match text(&v["status"]).as_deref() {
        Some("completed") => "✔ completed".green().bold(),
        Some("partial") => "◐ partial".yellow().bold(),
        Some("failed") => "✘ failed".red().bold(),
        Some("in_progress") => "⏳ in progress".yellow().bold(),
        Some(other) => other.to_string().normal(),
        None => "unknown".normal(),
    };

    println!();
    println!("  🌐 Domain Report  {}  [{}]", domain.cyan().bold(), badge);
    println!("{}", div.dimmed());
    row_opt("Scanned", &v["scan_date"]);
    print_score(&v["score"]);

    print_findings(v);
    print_registration(&v["registration"]);
    print_dns(&v["dns"]);
    print_mail(&v["mail"]);
    print_web(&v["web"]);
    print_certificates(&v["certificates"]);
    print_surface(&v["surface"]);

    println!();
    println!("{}", div.dimmed());
    println!();
}

fn print_score(score: &Value) {
    let (Some(value), Some(grade)) = (text(&score["value"]), text(&score["grade"])) else {
        row("Score", "not graded".dimmed());
        return;
    };
    let grade = match grade.chars().next() {
        Some('A') => grade.green().bold(),
        Some('B') => grade.cyan().bold(),
        Some('C') => grade.yellow().bold(),
        _ => grade.red().bold(),
    };
    row("Score", format!("{value}/100  grade {grade}"));
}

fn print_findings(v: &Value) {
    let findings = sorted_findings(v);
    heading(&format!("Findings ({})", findings.len()));
    if findings.is_empty() {
        println!("    {}", "No findings.".dimmed());
        return;
    }

    let mut tally: Vec<(String, usize)> = Vec::new();
    for f in &findings {
        let s = f["severity"]
            .as_str()
            .unwrap_or("unknown")
            .to_ascii_lowercase();
        match tally.iter_mut().find(|(k, _)| *k == s) {
            Some((_, n)) => *n += 1,
            None => tally.push((s, 1)),
        }
    }
    let summary: Vec<String> = tally.iter().map(|(s, n)| format!("{n} {s}")).collect();
    println!("    {}", summary.join(" · ").dimmed());

    for f in findings.iter().take(MAX_FINDINGS) {
        let section = text(&f["section"])
            .map(|s| format!("  [{s}]"))
            .unwrap_or_default();
        println!(
            "    {:<11} {}{}",
            severity_marker(f["severity"].as_str().unwrap_or("")),
            text(&f["title"]).unwrap_or_default(),
            section.dimmed()
        );
    }
    more(findings.len(), MAX_FINDINGS);
}

fn print_registration(r: &Value) {
    if r.is_null() {
        return;
    }
    heading("Registration");
    if r["found"].as_bool() == Some(false) {
        println!("    {}", "No WHOIS record found.".dimmed());
        return;
    }
    row_opt("Registrar", &r["registrar"]);
    if let Some(created) = text(&r["created"]) {
        let age = text(&r["age_days"])
            .map(|d| format!("  ({d} days ago)"))
            .unwrap_or_default();
        row("Created", format!("{created}{}", age.dimmed()));
    }
    if let Some(expires) = text(&r["expires"]) {
        let left = match r["expires_in_days"].as_i64() {
            Some(d) if d < 30 => format!("  (in {d} days)").red().to_string(),
            Some(d) => format!("  (in {d} days)").dimmed().to_string(),
            None => String::new(),
        };
        row("Expires", format!("{expires}{left}"));
    }
    let ns: Vec<String> = list(&r["nameservers"]).iter().filter_map(text).collect();
    if !ns.is_empty() {
        row("Nameservers", ns.join(", "));
    }
}

fn print_dns(d: &Value) {
    if d.is_null() {
        return;
    }
    heading("DNS");
    let rec = &d["records"];
    let ns: Vec<String> = list(&rec["ns"]).iter().filter_map(text).collect();
    if !ns.is_empty() {
        row("NS", ns.join(", "));
    }
    let mx = list(&rec["mx"]);
    for (i, m) in mx.iter().take(MAX_ROWS).enumerate() {
        let line = format!(
            "{} {}",
            text(&m["priority"]).unwrap_or_default(),
            text(&m["exchange"]).unwrap_or_default()
        );
        if i == 0 {
            row("MX", line);
        } else {
            println!("    {:<16} {}", "", line);
        }
    }
    more(mx.len(), MAX_ROWS);
    row_opt("DNSSEC", &d["dnssec"]["status"]);
    if d["caa"].is_null() {
        row("CAA", "not audited".dimmed());
    } else {
        row("CAA", format!("{} record(s)", count(&rec["caa"])));
    }
    let saas: Vec<String> = list(&d["txt"]["saas"])
        .iter()
        .filter_map(|s| text(&s["service"]))
        .collect();
    if !saas.is_empty() {
        row("SaaS (TXT)", saas.join(", "));
    }
}

fn print_mail(m: &Value) {
    if m.is_null() {
        return;
    }
    heading("Mail");
    row_opt("Grade", &m["grade"]);

    let spf = &m["spf"];
    match text(&spf["record"]) {
        Some(r) if spf["present"].as_bool() != Some(false) => {
            row("SPF", format!("{} {r}", "✔".green()))
        }
        _ => row("SPF", format!("{} {}", "✘".red(), "not configured".red())),
    }
    let dmarc = &m["dmarc"];
    if dmarc["present"].as_bool() == Some(true) {
        let policy = text(&dmarc["policy"]).unwrap_or_else(|| "?".into());
        row("DMARC", format!("{} p={policy}", "✔".green()));
    } else {
        row("DMARC", format!("{} {}", "✘".red(), "not configured".red()));
    }
    let dkim: Vec<String> = list(&m["dkim"])
        .iter()
        .filter(|k| k["present"].as_bool() != Some(false))
        .filter_map(|k| text(&k["selector"]))
        .collect();
    if dkim.is_empty() {
        row(
            "DKIM",
            format!("{} {}", "✘".red(), "no selector found".red()),
        );
    } else {
        row("DKIM", format!("{} {}", "✔".green(), dkim.join(", ")));
    }
    row("BIMI", yes_no(&m["bimi"]["present"]));
    row("TLS-RPT", yes_no(&m["tls_rpt"]["present"]));
}

fn print_web(w: &Value) {
    if w.is_null() {
        return;
    }
    heading("Web");
    let http = &w["http"];
    if http["reachable"].as_bool() == Some(false) {
        row("HTTP", "unreachable".dimmed());
    } else {
        let status = text(&http["status"]).unwrap_or_default();
        let url = text(&http["final_url"]).unwrap_or_default();
        row("HTTP", format!("{status} {url}").trim().to_string());
        row_opt("Server", &http["server"]);
        row("HTTPS upgrade", yes_no(&http["https_upgrade"]));
        let missing: Vec<String> = list(&http["missing_security_headers"])
            .iter()
            .filter_map(text)
            .collect();
        if !missing.is_empty() {
            row("Missing headers", missing.join(", ").yellow());
        }
    }

    let tls = &w["tls"];
    if tls["reachable"].as_bool() == Some(true) {
        row_opt("TLS", &tls["protocol"]);
        row_opt("Issuer", &tls["cert"]["issuer"]);
        if let Some(to) = text(&tls["cert"]["valid_to"]) {
            let left = text(&tls["days_remaining"])
                .map(|d| format!("  ({d} days left)"))
                .unwrap_or_default();
            row("Valid until", format!("{to}{}", left.dimmed()));
        }
    }

    let cve = &w["cve"];
    if let Some(total) = cve["total_cves"].as_i64().filter(|n| *n > 0) {
        let kev = cve["kev_count"].as_i64().unwrap_or(0);
        let max = text(&cve["max_cvss"])
            .map(|c| format!(", max CVSS {c}"))
            .unwrap_or_default();
        let line = format!("{total} CVE(s), {kev} known exploited{max}");
        row(
            "CVEs",
            if kev > 0 {
                line.red().bold()
            } else {
                line.yellow()
            },
        );
    }
}

fn print_certificates(c: &Value) {
    if c.is_null() {
        return;
    }
    heading("Certificates");
    let h = &c["history"];
    row_opt("Seen in CT", &h["cert_count"]);
    row_opt("Valid now", &h["currently_valid_count"]);
    row_opt("Expired", &h["expired_count"]);
    row_opt("CAs used", &h["ca_count"]);
    row_opt("First seen", &h["first_seen"]);

    // Same rows as `mlab ssl`, so the table is the one users already know.
    let certs: Vec<SslCert> = serde_json::from_value(c["list"].clone()).unwrap_or_default();
    if !certs.is_empty() {
        const SHOWN: usize = 5;
        println!();
        render_table(&certs[..certs.len().min(SHOWN)], false);
        if certs.len() > SHOWN {
            println!("    {}", "Full history: mlab ssl <domain>".dimmed());
        }
    }
}

fn print_surface(s: &Value) {
    if s.is_null() {
        return;
    }
    heading("Attack surface");

    let subs = list(&s["subdomains"]);
    row("Subdomains", subs.len());
    for sub in subs.iter().filter_map(text).take(MAX_ROWS) {
        println!("      {} {}", "•".dimmed(), sub);
    }
    more(subs.len(), MAX_ROWS);

    for sus in list(&s["suspicious"]) {
        println!(
            "      {} {}  (keyword: {})",
            "⚠".yellow(),
            text(&sus["subdomain"]).unwrap_or_default().yellow(),
            text(&sus["keyword"]).unwrap_or_default().red().bold()
        );
    }

    let web = &s["web"];
    if let (Some(checked), Some(reachable)) = (text(&web["checked"]), text(&web["reachable"])) {
        row(
            "Hosts visited",
            format!("{reachable} reachable of {checked} checked"),
        );
    }
    let tech: Vec<String> = list(&web["technologies"])
        .iter()
        .filter_map(|t| {
            let name = text(&t["name"])?;
            Some(match text(&t["version"]) {
                Some(v) => format!("{name} {v}"),
                None => name,
            })
        })
        .collect();
    if !tech.is_empty() {
        let shown: Vec<String> = tech.iter().take(MAX_ROWS).cloned().collect();
        row("Technologies", shown.join(", "));
        more(tech.len(), MAX_ROWS);
    }

    let takeover: Vec<String> = list(&s["takeover"]["candidates"])
        .iter()
        .filter(|c| c["vulnerable"].as_bool() == Some(true))
        .filter_map(|c| text(&c["subdomain"]))
        .collect();
    if !takeover.is_empty() {
        row("Takeover", takeover.join(", ").red().bold());
    }
    let typo = count(&s["typosquat"]["registered"]);
    if typo > 0 {
        row("Lookalikes", format!("{typo} registered").yellow());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn findings_come_out_worst_first_and_keep_their_order_within_a_severity() {
        let v = json!({"findings": [
            {"severity": "low", "title": "a"},
            {"severity": "critical", "title": "b"},
            {"severity": "medium", "title": "c"},
            {"severity": "critical", "title": "d"},
            {"severity": "bogus", "title": "e"},
        ]});
        let titles: Vec<&str> = sorted_findings(&v)
            .iter()
            .map(|f| f["title"].as_str().unwrap())
            .collect();
        assert_eq!(titles, ["b", "d", "c", "a", "e"]);
    }

    #[test]
    fn missing_fields_render_as_nothing_rather_than_failing() {
        assert_eq!(text(&Value::Null), None);
        assert_eq!(text(&json!("  ")), None);
        assert_eq!(text(&json!(42)), Some("42".into()));
        assert!(list(&json!({})["x"]).is_empty());
        assert!(sorted_findings(&json!({})).is_empty());
    }
}
