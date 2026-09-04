//! The single-value lookups: URL, hash, email, phone, MAC — plus IOC
//! extraction, shell-script analysis and network capture.
//!
//! These endpoints answer with flat JSON objects that differ in their fields but
//! agree on their shape: scalars, a few nested groups, and a `findings` array of
//! `{severity, title, detail}`. One renderer covers all of them, which is what
//! keeps adding the next lookup cheap.

use std::io::Read;

use base64::Engine;
use colored::Colorize;
use serde_json::Value;

use crate::client::MlabClient;
use crate::commands::{fetch, parse_or_exit, print_json};
use crate::error::{ApiError, ErrorKind};
use crate::util::urlencode;

pub struct Panel<'a> {
    pub icon: &'a str,
    pub title: &'a str,
    pub subject: &'a str,
    /// Keys promoted to the top, in this order. Everything else follows.
    pub highlights: &'a [&'a str],
}

// ═══════════════════════════════════════════════════════════════════
//  Commands
// ═══════════════════════════════════════════════════════════════════

pub fn url(client: &MlabClient, target: &str, resolve: bool, json: bool) {
    let mut path = format!("/scan/url?url={}", urlencode(target));
    if resolve {
        // Off by default server-side: following an attacker-chosen link is
        // opt-in, so the flag is the user saying "yes, fetch it".
        path.push_str("&resolve=1");
    }
    let body = fetch(client.get(&path));
    show(
        &body,
        json,
        &Panel {
            icon: "🔗",
            title: "URL Analysis",
            subject: target,
            highlights: &["url", "scheme", "host", "host_unicode", "port", "path"],
        },
    );
}

pub fn hash(client: &MlabClient, digests: &[String], json: bool) {
    if digests.len() > 1 {
        return bulk_hash(client, digests, json);
    }
    let digest = &digests[0];
    let body = fetch(client.get(&format!("/scan/hash?hash={}", urlencode(digest))));
    show(
        &body,
        json,
        &Panel {
            icon: "🧬",
            title: "Hash Lookup",
            subject: digest,
            highlights: &["hash", "algorithm", "found", "verdict", "enrichment_source"],
        },
    );
}

pub fn bulk_crypto(client: &MlabClient, addresses: &[String], chain: Option<&str>, json: bool) {
    let mut payload = serde_json::json!({ "addresses": addresses });
    if let Some(c) = chain {
        payload["chain"] = Value::String(c.to_string());
    }
    let body = fetch(client.post_json("/scan/crypto", &payload));
    if json {
        print_json(&body);
        return;
    }
    let v: Value = parse_or_exit(&body, "crypto");
    render_bulk("Crypto Lookup", "🪙", &v, "results", "address");
}

fn bulk_hash(client: &MlabClient, digests: &[String], json: bool) {
    let payload = serde_json::json!({ "hashes": digests });
    let body = fetch(client.post_json("/scan/hash", &payload));
    if json {
        print_json(&body);
        return;
    }
    let v: Value = parse_or_exit(&body, "hash");
    render_bulk("Hash Lookup", "🧬", &v, "results", "hash");
}

pub fn email(client: &MlabClient, address: &str, json: bool) {
    let body = fetch(client.get(&format!("/scan/email?email={}", urlencode(address))));
    show(
        &body,
        json,
        &Panel {
            icon: "📧",
            title: "Email Lookup",
            subject: address,
            highlights: &["email", "domain", "mailbox_type", "is_role", "is_free_provider", "is_disposable"],
        },
    );
}

pub fn phone(client: &MlabClient, number: &str, json: bool) {
    let body = fetch(client.get(&format!("/scan/phone?number={}", urlencode(number))));
    show(
        &body,
        json,
        &Panel {
            icon: "📞",
            title: "Phone Lookup",
            subject: number,
            highlights: &["input", "verdict", "valid", "country_code", "region", "line_type", "allocated_operator"],
        },
    );
}

pub fn mac(client: &MlabClient, address: &str, json: bool) {
    let body = fetch(client.get(&format!("/scan/mac?mac={}", urlencode(address))));
    show(
        &body,
        json,
        &Panel {
            icon: "🖧",
            title: "MAC Lookup",
            subject: address,
            highlights: &["mac", "verdict", "vendor", "oui", "cast", "administration", "randomized"],
        },
    );
}

/// Pull indicators out of whatever the analyst pasted — a report, an email, a
/// log. Reads a file, or stdin when the path is `-`, which is the point: it
/// belongs at the end of a pipe.
pub fn ioc(client: &MlabClient, source: &str, country: Option<&str>, risk: Option<&str>, json: bool) {
    let text = read_input(source);
    let text = String::from_utf8_lossy(&text).to_string();

    if text.trim().is_empty() {
        ApiError {
            status: None,
            message: "nothing to analyse — the input is empty.".to_string(),
            kind: ErrorKind::Input,
        }
        .report();
    }

    let mut path = String::from("/scan/ioc");
    let mut sep = '?';
    if let Some(c) = country {
        path.push_str(&format!("{sep}country={}", urlencode(c)));
        sep = '&';
    }
    if let Some(r) = risk {
        path.push_str(&format!("{sep}risk={}", urlencode(r)));
    }

    let payload = serde_json::json!({ "text": text });
    let body = fetch(client.post_json(&path, &payload));

    if json {
        print_json(&body);
        return;
    }

    let v: Value = parse_or_exit(&body, "IOC");
    let label = if source == "-" { "stdin" } else { source };
    render_iocs(&v, "IOC Extraction", label);
}

/// Analyse a shell script: upload it, then read back the stored report.
pub fn bash(client: &MlabClient, source: &str, json: bool) {
    let bytes = read_input(source);
    if bytes.is_empty() {
        ApiError {
            status: None,
            message: "the script is empty.".to_string(),
            kind: ErrorKind::Input,
        }
        .report();
    }

    let filename = std::path::Path::new(source)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("script.sh");

    let payload = serde_json::json!({
        "content_b64": base64::engine::general_purpose::STANDARD.encode(&bytes),
        "filename": filename,
    });
    let posted = fetch(client.post_json("/scan/file/bash", &payload));
    let posted: Value = parse_or_exit(&posted, "bash analysis");
    let sha256 = posted.get("sha256").and_then(|s| s.as_str()).unwrap_or_default();

    if sha256.is_empty() {
        ApiError::new(None, "the API accepted the script but returned no hash.").report();
    }

    // The POST only stores the report; the GET is what returns it.
    let body = fetch(client.get(&format!("/scan/file/bash?sha256={}", urlencode(sha256))));

    if json {
        print_json(&body);
        return;
    }

    let v: Value = parse_or_exit(&body, "bash analysis");
    render_bash(&v);
}

pub fn network(client: &MlabClient, target: &str, json: bool) {
    let body = fetch(client.get(&format!(
        "/scan/domain/loadnetworkrequest?url={}",
        urlencode(target)
    )));

    if json {
        print_json(&body);
        return;
    }

    let v: Value = parse_or_exit(&body, "network capture");
    render_network(&v, target);
}

// ═══════════════════════════════════════════════════════════════════
//  Rendering
// ═══════════════════════════════════════════════════════════════════

fn show(body: &str, json: bool, panel: &Panel) {
    if json {
        print_json(body);
        return;
    }
    let v: Value = parse_or_exit(body, panel.title);
    render_panel(panel, &v);
}

pub fn render_panel(panel: &Panel, v: &Value) {
    let div = format!("  {}", "─".repeat(72));

    println!();
    println!("  {} {}  {}", panel.icon, panel.title, panel.subject.cyan().bold());
    println!("{}", div.dimmed());

    let Some(obj) = v.as_object() else {
        println!("  {}", v);
        return;
    };

    let mut printed: Vec<&str> = Vec::new();

    for key in panel.highlights {
        if let Some(val) = obj.get(*key) {
            if print_scalar(key, val, 2) {
                printed.push(key);
            }
        }
    }

    for (key, val) in obj {
        if printed.contains(&key.as_str()) || key == "findings" || !is_scalar(val) {
            continue;
        }
        print_scalar(key, val, 2);
    }

    // Nested groups (score, formats, domain_scan, host_context, resolution…)
    for (key, val) in obj {
        let Some(inner) = val.as_object() else { continue };
        if inner.is_empty() {
            continue;
        }
        println!();
        println!("  {}", humanize(key).bold().underline());
        for (k, v) in inner {
            if is_scalar(v) {
                print_scalar(k, v, 4);
            } else if let Some(a) = v.as_array() {
                if !a.is_empty() {
                    print_scalar(k, &Value::String(summarize_array(a)), 4);
                }
            }
        }
    }

    print_findings(obj.get("findings"));
    println!("{}", div.dimmed());
    println!();
}

fn print_findings(findings: Option<&Value>) {
    let Some(list) = findings.and_then(|f| f.as_array()) else { return };
    if list.is_empty() {
        return;
    }

    println!();
    println!("  {}", "Findings".bold().underline());
    for f in list {
        let severity = f.get("severity").and_then(|s| s.as_str()).unwrap_or("info");
        let title = f.get("title").and_then(|s| s.as_str()).unwrap_or("");
        let detail = f.get("detail").and_then(|s| s.as_str()).unwrap_or("");

        println!("    {} {}", severity_marker(severity), title.bold());
        if !detail.is_empty() {
            println!("      {}", detail.dimmed());
        }
    }
}

pub fn severity_marker(severity: &str) -> colored::ColoredString {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => "▲ critical".red().bold(),
        "high" => "▲ high".red(),
        "medium" | "warning" | "warn" => "▲ medium".yellow(),
        "low" => "▪ low".cyan(),
        other => format!("▪ {other}").normal(),
    }
}

fn render_iocs(v: &Value, title: &str, subject: &str) {
    let div = format!("  {}", "─".repeat(72));
    let total = v.get("ioc_total").and_then(|t| t.as_u64()).unwrap_or(0);

    println!();
    println!("  {} {}  {}", "🧾", title, subject.cyan().bold());
    println!("{}", div.dimmed());
    println!("  {:<14} {}", "Indicators:".dimmed(), total.to_string().bold());
    if v.get("truncated").and_then(|t| t.as_bool()).unwrap_or(false) {
        println!(
            "  {}",
            "Output truncated — the input exceeded the extraction cap.".yellow()
        );
    }

    if let Some(groups) = v.get("iocs").and_then(|i| i.as_object()) {
        for (kind, entries) in groups {
            let Some(list) = entries.as_array() else { continue };
            println!();
            println!(
                "  {} ({})",
                humanize(kind).bold().underline(),
                list.len().to_string().bold()
            );
            for entry in list {
                let value = entry.get("value").and_then(|x| x.as_str()).unwrap_or("");
                println!("    {} {}", "•".dimmed(), value);
            }
        }
    }

    if let Some(risk) = v.get("risk") {
        if risk.is_object() {
            println!();
            println!("  {}", "Risk".bold().underline());
            for (k, val) in risk.as_object().unwrap() {
                if is_scalar(val) {
                    print_scalar(k, val, 4);
                }
            }
        }
    }

    println!("{}", div.dimmed());
    println!();
}

fn render_bash(v: &Value) {
    let div = format!("  {}", "─".repeat(72));
    let file = v.get("file").cloned().unwrap_or(Value::Null);
    let name = file.get("filename").and_then(|f| f.as_str()).unwrap_or("script");

    println!();
    println!("  {} {}  {}", "📜", "Shell Script Analysis", name.cyan().bold());
    println!("{}", div.dimmed());
    if let Some(obj) = file.as_object() {
        for (k, val) in obj {
            if is_scalar(val) {
                print_scalar(k, val, 2);
            }
        }
    }

    if let Some(list) = v.get("suspicious").and_then(|s| s.as_array()) {
        println!();
        println!("  {} ({})", "Suspicious Patterns".bold().underline(), list.len());
        if list.is_empty() {
            println!("    {}", "Nothing flagged.".dimmed());
        }
        for item in list {
            match item {
                Value::String(s) => println!("    {} {}", "▲".yellow(), s),
                other => {
                    let severity = other.get("severity").and_then(|s| s.as_str()).unwrap_or("medium");
                    let title = other
                        .get("title")
                        .or_else(|| other.get("label"))
                        .or_else(|| other.get("pattern"))
                        .and_then(|s| s.as_str())
                        .unwrap_or("");
                    println!("    {} {}", severity_marker(severity), title);
                    if let Some(detail) = other.get("detail").and_then(|s| s.as_str()) {
                        println!("      {}", detail.dimmed());
                    }
                }
            }
        }
    }

    if let Some(groups) = v.get("iocs").and_then(|i| i.as_object()) {
        let total = v.get("ioc_total").and_then(|t| t.as_u64()).unwrap_or(0);
        if total > 0 {
            println!();
            println!("  {} ({})", "Indicators".bold().underline(), total);
            for (kind, entries) in groups {
                let Some(list) = entries.as_array() else { continue };
                for entry in list {
                    let value = entry
                        .get("value")
                        .and_then(|x| x.as_str())
                        .unwrap_or_default();
                    println!("    {:<12} {}", humanize(kind).dimmed(), value);
                }
            }
        }
    }

    println!("{}", div.dimmed());
    println!();
}

fn render_network(v: &Value, subject: &str) {
    let div = format!("  {}", "─".repeat(100));
    let requests = v.get("requests").and_then(|r| r.as_array());

    println!();
    println!("  {} {}  {}", "🌐", "Network Capture", subject.cyan().bold());
    println!("{}", div.dimmed());

    let Some(list) = requests else {
        // The payload comes from a capture service, not from this API; if it
        // ever changes shape, showing it beats pretending we understood it.
        println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
        return;
    };

    let failed = list.iter().filter(|r| r.get("failed").and_then(|f| f.as_bool()).unwrap_or(false)).count();
    println!(
        "  {:<14} {}   {:<10} {}   {:<8} {}",
        "Requests:".dimmed(),
        list.len().to_string().bold(),
        "Failed:".dimmed(),
        if failed > 0 { failed.to_string().red().bold() } else { failed.to_string().normal() },
        "Bytes:".dimmed(),
        v.get("totalBytes").and_then(|b| b.as_u64()).unwrap_or(0),
    );
    println!();
    println!(
        "  {:<7} {:<7} {:<14} {:<10} {}",
        "Method".bold().underline(),
        "Status".bold().underline(),
        "Type".bold().underline(),
        "Bytes".bold().underline(),
        "URL".bold().underline(),
    );

    for r in list {
        let method = r.get("method").and_then(|m| m.as_str()).unwrap_or("-");
        let failed = r.get("failed").and_then(|f| f.as_bool()).unwrap_or(false);
        let status = match r.get("status").and_then(|s| s.as_u64()) {
            Some(c) if c >= 400 => c.to_string().red().to_string(),
            Some(c) => c.to_string().green().to_string(),
            None if failed => "fail".red().to_string(),
            None => "-".to_string(),
        };
        println!(
            "  {:<7} {:<7} {:<14} {:<10} {}",
            method,
            status,
            r.get("resourceType").and_then(|t| t.as_str()).unwrap_or("-"),
            r.get("encodedBytes").and_then(|b| b.as_u64()).unwrap_or(0),
            r.get("url").and_then(|u| u.as_str()).unwrap_or("").dimmed(),
        );
        if let Some(err) = r.get("errorText").and_then(|e| e.as_str()) {
            if !err.is_empty() {
                println!("  {:<7} {}", "", err.red());
            }
        }
    }

    println!("{}", div.dimmed());
    println!();
}

/// Bulk answers carry results plus the rows the API could not use; showing only
/// the successes would quietly drop half of what the analyst pasted.
fn render_bulk(title: &str, icon: &str, v: &Value, results_key: &str, value_key: &str) {
    let div = format!("  {}", "─".repeat(72));
    println!();
    println!("  {} {} {}", icon, title, "(bulk)".dimmed());
    println!("{}", div.dimmed());

    if let Some(list) = v.get(results_key).and_then(|r| r.as_array()) {
        for entry in list {
            let subject = entry
                .get(value_key)
                .or_else(|| entry.get("address"))
                .and_then(|s| s.as_str())
                .unwrap_or("");
            let verdict = entry
                .get("verdict")
                .or_else(|| entry.get("risk_score"))
                .map(render_value)
                .unwrap_or_default();
            println!("  {:<70} {}", subject, verdict.bold());
        }
    }

    for key in ["not_queryable", "invalid", "deferred", "errors"] {
        if let Some(list) = v.get(key).and_then(|r| r.as_array()) {
            if list.is_empty() {
                continue;
            }
            println!();
            println!("  {} ({})", humanize(key).bold().underline(), list.len());
            for entry in list {
                let text = match entry {
                    Value::String(s) => s.clone(),
                    other => other
                        .get("value")
                        .or_else(|| other.get("hash"))
                        .or_else(|| other.get("address"))
                        .map(render_value)
                        .unwrap_or_else(|| other.to_string()),
                };
                println!("    {} {}", "•".dimmed(), text.dimmed());
            }
        }
    }

    println!("{}", div.dimmed());
    println!();
}

// ═══════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════

fn read_input(source: &str) -> Vec<u8> {
    if source == "-" {
        let mut buf = Vec::new();
        if std::io::stdin().read_to_end(&mut buf).is_err() {
            ApiError::new(None, "could not read stdin.").report();
        }
        return buf;
    }

    match std::fs::read(source) {
        Ok(b) => b,
        Err(e) => ApiError {
            status: None,
            message: format!("cannot read {source}: {e}"),
            kind: ErrorKind::Input,
        }
        .report(),
    }
}

fn is_scalar(v: &Value) -> bool {
    matches!(v, Value::String(_) | Value::Number(_) | Value::Bool(_))
}

fn render_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => if *b { "yes".to_string() } else { "no".to_string() },
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

fn summarize_array(a: &[Value]) -> String {
    let rendered: Vec<String> = a.iter().take(4).map(render_value).collect();
    if a.len() > 4 {
        format!("{} … (+{})", rendered.join(", "), a.len() - 4)
    } else {
        rendered.join(", ")
    }
}

/// Print one `key: value` line; returns false for values not worth a line
/// (null, empty string) so the caller knows nothing was shown.
fn print_scalar(key: &str, value: &Value, indent: usize) -> bool {
    let rendered = match value {
        Value::Null => return false,
        Value::String(s) if s.is_empty() => return false,
        other => render_value(other),
    };
    let label = format!("{}:", humanize(key));
    println!("{}{:<22} {}", " ".repeat(indent), label.dimmed(), rendered);
    true
}

fn humanize(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for (i, c) in key.replace('_', " ").chars().enumerate() {
        if i == 0 {
            out.extend(c.to_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_are_rendered_as_readable_labels() {
        assert_eq!(humanize("country_code"), "Country code");
        assert_eq!(humanize("mac"), "Mac");
        assert_eq!(humanize(""), "");
    }

    #[test]
    fn booleans_read_as_yes_and_no_rather_than_true_and_false() {
        assert_eq!(render_value(&json!(true)), "yes");
        assert_eq!(render_value(&json!(false)), "no");
        assert_eq!(render_value(&json!(42)), "42");
        assert_eq!(render_value(&json!("x")), "x");
    }

    #[test]
    fn empty_and_null_values_do_not_get_a_line() {
        assert!(!print_scalar("k", &Value::Null, 0));
        assert!(!print_scalar("k", &json!(""), 0));
        assert!(print_scalar("k", &json!("v"), 0));
        assert!(print_scalar("k", &json!(false), 0));
    }

    #[test]
    fn long_arrays_are_summarized_rather_than_dumped() {
        let a = vec![json!("a"), json!("b"), json!("c"), json!("d"), json!("e"), json!("f")];
        assert_eq!(summarize_array(&a), "a, b, c, d … (+2)");
        assert_eq!(summarize_array(&a[..2]), "a, b");
    }

    #[test]
    fn only_scalars_are_treated_as_single_line_fields() {
        assert!(is_scalar(&json!("s")));
        assert!(is_scalar(&json!(1)));
        assert!(is_scalar(&json!(true)));
        assert!(!is_scalar(&json!(null)));
        assert!(!is_scalar(&json!({"a": 1})));
        assert!(!is_scalar(&json!([1])));
    }
}
