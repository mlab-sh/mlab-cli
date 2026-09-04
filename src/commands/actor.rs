//! Threat-actor intelligence from `actors.mlab.sh`.
//!
//! A public read-only host: no credential, and every route answers `200` even
//! when it failed — `{"error":"not_found"}` arrives with a success status, so
//! the body is what decides, not the status line.

use colored::Colorize;
use serde_json::Value;

use crate::client::HostClient;
use crate::commands::{parse_or_exit, print_json, vuln_body};
use crate::error::{ApiError, ErrorKind};
use crate::ui;
use crate::util::urlencode;

/// The dataset is ETDA Threat Group Cards + MITRE ATT&CK under CC BY-NC-SA 4.0.
/// Redistributing it without saying so would breach the licence, so every
/// rendered view carries the attribution.
const ATTRIBUTION: &str = "Data: ETDA Threat Group Cards + MITRE ATT&CK — CC BY-NC-SA 4.0";

pub struct ListFilters<'a> {
    pub origin: Option<&'a str>,
    pub motivation: Option<&'a str>,
    pub sector: Option<&'a str>,
    pub updated_since: Option<&'a str>,
    pub limit: Option<u32>,
    pub offset: u32,
}

pub fn list(client: &HostClient, filters: &ListFilters, json: bool) {
    let mut path = String::from("/api/v1/actors?");
    let mut push = |key: &str, value: &str| {
        path.push_str(&format!("{key}={}&", urlencode(value)));
    };

    // The API calls this `origin`, not `country` — a country filter would be
    // silently ignored.
    if let Some(v) = filters.origin {
        push("origin", v);
    }
    if let Some(v) = filters.motivation {
        push("motivation", v);
    }
    if let Some(v) = filters.sector {
        push("sector", v);
    }
    if let Some(v) = filters.updated_since {
        push("updated_since", v);
    }
    if let Some(v) = filters.limit {
        push("limit", &v.to_string());
    }
    if filters.offset > 0 {
        push("offset", &filters.offset.to_string());
    }

    let body = ui::with_spinner("Listing threat actors", || vuln_body(client.get(&path)));

    if json {
        print_json(&body);
        return;
    }

    let v: Value = parse_or_exit(&body, "actors");
    let items = v.get("items").and_then(|i| i.as_array()).cloned().unwrap_or_default();
    let total = v.get("total").and_then(|t| t.as_u64()).unwrap_or(0);
    let offset = v.get("offset").and_then(|o| o.as_u64()).unwrap_or(0);
    let limit = v.get("limit").and_then(|l| l.as_u64()).unwrap_or(0);

    println!();
    println!("  {} {}", "🎭", "Threat Actors".bold());
    println!("{}", divider(96));
    println!(
        "  {:<14} {} of {}",
        "Showing:".dimmed(),
        items.len().to_string().bold(),
        total.to_string().bold()
    );
    println!();

    if items.is_empty() {
        println!("  {}", "No actors match those filters.".dimmed());
        println!();
        return;
    }

    println!(
        "  {:<26} {:<20} {:<16} {}",
        "Name".bold().underline(),
        "Slug".bold().underline(),
        "Origin".bold().underline(),
        "Motivation".bold().underline(),
    );

    for actor in &items {
        println!(
            "  {:<26} {:<20} {:<16} {}",
            truncate(text(actor, "primary_name"), 26),
            truncate(text(actor, "slug"), 20).cyan(),
            truncate(&origin_of(actor), 16),
            truncate(&join(actor, "motivation"), 34).dimmed(),
        );
    }

    println!("{}", divider(96));
    // Without this a reader takes the first page for the whole dataset.
    if offset + (items.len() as u64) < total {
        println!(
            "  {}",
            format!("More actors — rerun with --offset {}", offset + limit.max(items.len() as u64)).dimmed()
        );
    }
    println!("  {}", ATTRIBUTION.dimmed());
    println!();
}

pub fn get(client: &HostClient, slug: &str, json: bool) {
    let body = ui::with_spinner(&format!("Fetching {slug}"), || {
        vuln_body(client.get(&format!("/api/v1/actors/{}", urlencode(slug))))
    });

    if json {
        print_json(&body);
        return;
    }

    let v: Value = parse_or_exit(&body, "actor");
    let actor = v.get("actor").cloned().unwrap_or(Value::Null);

    println!();
    println!(
        "  {} {}  {}",
        "🎭",
        text(&actor, "primary_name").bold(),
        text(&actor, "slug").cyan()
    );
    println!("{}", divider(84));

    for (label, key) in [("Origin", "suspected_origin"), ("First seen", "first_seen"), ("TLP", "tlp")] {
        let value = text(&actor, key);
        if !value.is_empty() {
            println!("  {:<16} {}", format!("{label}:").dimmed(), value);
        }
    }
    for (label, key) in [("Motivation", "motivation"), ("Sectors", "targets_sectors"), ("Countries", "targets_countries")] {
        let value = join(&actor, key);
        if !value.is_empty() {
            println!("  {:<16} {}", format!("{label}:").dimmed(), value);
        }
    }

    let description = text(&actor, "description");
    if !description.is_empty() {
        println!();
        for line in wrap(&description, 78) {
            println!("  {line}");
        }
    }

    section_list(&v, "aliases", "Aliases", |a| text(a, "alias").to_string());
    section_list(&v, "cves", "Exploited CVEs", |c| match c {
        Value::String(s) => s.clone(),
        other => text(other, "cve_id").to_string(),
    });
    section_rows(&v, "tools", "Tools & Malware", |t| {
        (text(t, "mitre_id").to_string(), format!("{}  {}", text(t, "name"), text(t, "kind").dimmed()))
    });
    section_rows(&v, "techniques", "Techniques", |t| {
        (text(t, "mitre_id").to_string(), format!("{}  {}", text(t, "name"), text(t, "tactic").dimmed()))
    });
    section_rows(&v, "references", "References", |r| {
        (String::new(), format!("{}  {}", text(r, "title"), text(r, "url").dimmed()))
    });

    println!("{}", divider(84));
    println!("  {}", ATTRIBUTION.dimmed());
    println!();
}

pub fn by_cve(client: &HostClient, cve: &str, json: bool) {
    let cve = cve.to_uppercase();
    let body = ui::with_spinner(&format!("Finding actors exploiting {cve}"), || {
        vuln_body(client.get(&format!("/api/v1/cves/{}/actors", urlencode(&cve))))
    });

    if json {
        print_json(&body);
        return;
    }

    let v: Value = parse_or_exit(&body, "actors");
    let actors = v.get("actors").and_then(|a| a.as_array()).cloned().unwrap_or_default();

    println!();
    println!("  {} Actors exploiting {}", "🎭", cve.cyan().bold());
    println!("{}", divider(84));

    if actors.is_empty() {
        // Nobody documented is not the same as nobody exploiting it.
        println!("  {}", "No actor is documented exploiting this CVE.".dimmed());
    } else {
        for actor in &actors {
            println!(
                "  {:<26} {:<20} {}",
                truncate(text(actor, "primary_name"), 26).bold(),
                truncate(text(actor, "slug"), 20).cyan(),
                truncate(&origin_of(actor), 24).dimmed(),
            );
        }
    }

    if let Some(url) = v.get("vuln_url").and_then(|u| u.as_str()) {
        println!();
        println!("  {:<14} {}", "Advisory:".dimmed(), url);
    }
    println!("{}", divider(84));
    println!("  {}", ATTRIBUTION.dimmed());
    println!();
}

/// STIX 2.1 bundle for one actor — raw, because it exists to be fed to another
/// tool rather than read.
pub fn stix(client: &HostClient, slug: &str) {
    let body = ui::with_spinner(&format!("Exporting {slug}"), || {
        vuln_body(client.get(&format!("/actors/{}.stix.json", urlencode(slug))))
    });
    println!("{body}");
}

pub fn export(client: &HostClient, format: &str) {
    let path = match format {
        "jsonl" => "/export/actors.jsonl",
        _ => "/export/actors.csv",
    };
    let body = ui::with_spinner(&format!("Exporting all actors as {format}"), || {
        crate::commands::fetch(client.get(path))
    });
    println!("{body}");
}

// ═══════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════

fn divider(width: usize) -> String {
    format!("  {}", "─".repeat(width)).dimmed().to_string()
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("")
}

fn join(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

fn origin_of(actor: &Value) -> String {
    let origin = text(actor, "suspected_origin");
    if origin.is_empty() {
        "unknown".to_string()
    } else {
        origin.to_string()
    }
}

fn section_list(v: &Value, key: &str, title: &str, render: impl Fn(&Value) -> String) {
    let Some(items) = v.get(key).and_then(|x| x.as_array()) else { return };
    let values: Vec<String> = items.iter().map(&render).filter(|s| !s.is_empty()).collect();
    if values.is_empty() {
        return;
    }
    println!();
    println!("  {} ({})", title.bold().underline(), values.len());
    for chunk in values.chunks(4) {
        println!("    {}", chunk.join("   "));
    }
}

fn section_rows(v: &Value, key: &str, title: &str, render: impl Fn(&Value) -> (String, String)) {
    let Some(items) = v.get(key).and_then(|x| x.as_array()) else { return };
    if items.is_empty() {
        return;
    }
    println!();
    println!("  {} ({})", title.bold().underline(), items.len());
    for item in items.iter().take(40) {
        let (id, rest) = render(item);
        if id.is_empty() {
            println!("    {rest}");
        } else {
            println!("    {:<12} {}", id.dimmed(), rest);
        }
    }
    if items.len() > 40 {
        println!("    {}", format!("… {} more", items.len() - 40).dimmed());
    }
}

fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(width.saturating_sub(1)).collect::<String>())
    }
}

/// Wrap on word boundaries so a description stays readable in a terminal.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// Reject a malformed identifier before spending a request on it.
pub fn validate_cve(id: &str) -> String {
    let upper = id.trim().to_uppercase();
    let rest = upper.strip_prefix("CVE-").unwrap_or("");
    let mut parts = rest.split('-');
    let year_ok = parts.next().map(|y| y.len() == 4 && y.chars().all(|c| c.is_ascii_digit()));
    let seq_ok = parts
        .next()
        .map(|n| (4..=7).contains(&n.len()) && n.chars().all(|c| c.is_ascii_digit()));

    if year_ok != Some(true) || seq_ok != Some(true) || parts.next().is_some() {
        ApiError {
            status: None,
            message: format!("'{id}' is not a CVE identifier — expected CVE-YYYY-NNNN."),
            kind: ErrorKind::Input,
        }
        .report();
    }
    upper
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn list_fields_read_through_missing_keys() {
        let actor = json!({"primary_name": "APT28", "motivation": ["Espionage", "Sabotage"]});
        assert_eq!(text(&actor, "primary_name"), "APT28");
        assert_eq!(text(&actor, "slug"), "");
        assert_eq!(join(&actor, "motivation"), "Espionage, Sabotage");
        assert_eq!(join(&actor, "targets_sectors"), "");
    }

    #[test]
    fn an_unknown_origin_is_labelled_rather_than_left_blank() {
        assert_eq!(origin_of(&json!({"suspected_origin": "Russia"})), "Russia");
        assert_eq!(origin_of(&json!({})), "unknown");
        assert_eq!(origin_of(&json!({"suspected_origin": ""})), "unknown");
    }

    #[test]
    fn descriptions_wrap_on_word_boundaries() {
        let lines = wrap("the quick brown fox jumps over the lazy dog", 12);
        assert!(lines.iter().all(|l| l.chars().count() <= 12), "{lines:?}");
        assert_eq!(lines.join(" "), "the quick brown fox jumps over the lazy dog");
    }

    #[test]
    fn wrapping_handles_empty_and_oversized_words() {
        assert!(wrap("", 10).is_empty());
        assert_eq!(wrap("supercalifragilistic", 5), vec!["supercalifragilistic"]);
    }

    #[test]
    fn long_cells_are_truncated_with_an_ellipsis() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("abcdefghij", 5), "abcd…");
    }
}
