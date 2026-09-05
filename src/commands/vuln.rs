//! Dependency scanning against `vuln.mlab.sh`: whole-manifest scans and
//! single-coordinate OSV queries.
//!
//! This is the CI-facing part of the CLI, so the failure semantics matter more
//! than the rendering. The API is explicit that `ok:false` means "this
//! coordinate could not be scanned", never "no vulnerabilities", and that a 502
//! or 503 is an outage. A gate that reads either as "clean" is worse than no
//! gate at all, so an incomplete scan can never satisfy `--fail-on`.

use std::io::Read;
use std::path::Path;

use colored::Colorize;
use serde_json::Value;

use crate::client::HostClient;
use crate::commands::{print_json, vuln_body};
use crate::cvss::{band, score_of, Severity};
use crate::error::{ApiError, ErrorKind, EXIT_FINDINGS};
use crate::output;
use crate::ui;
use crate::util::urlencode;

/// One advisory, flattened against the package it affects.
struct Finding {
    package: String,
    version: String,
    ecosystem: String,
    advisory: String,
    cve: String,
    score: Option<f64>,
    severity: Severity,
    fixed: String,
    summary: String,
}

pub struct ScanOptions<'a> {
    pub source: Option<&'a str>,
    pub url: Option<&'a str>,
    pub format: Option<&'a str>,
    pub fail_on: Option<&'a str>,
    pub json: bool,
}

pub fn scan(client: &HostClient, opts: &ScanOptions) {
    let threshold = match opts.fail_on {
        Some(raw) => match Severity::parse(raw) {
            Some(s) => Some(s),
            None => ApiError {
                status: None,
                message: format!("unknown severity '{raw}' — use critical, high, medium or low."),
                kind: ErrorKind::Input,
            }
            .report(),
        },
        None => None,
    };

    let (body, label) = match (opts.url, opts.source) {
        (Some(url), _) => {
            // URL mode: the server fetches and parses the lockfile itself.
            let mut path = format!("/api/v2/scan?url={}", urlencode(url));
            if let Some(f) = opts.format {
                path.push_str(&format!("&format={}", urlencode(f)));
            }
            let raw = ui::with_spinner(&format!("Scanning {url}"), || vuln_body(client.get(&path)));
            (raw, url.to_string())
        }
        (None, Some(source)) => {
            let content = read_input(source);
            let name = Path::new(source)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("manifest");
            // The raw lockfile goes up as the body: the scanner detects npm,
            // cargo, pip and the rest server-side, so the CLI never has to learn
            // a lockfile format.
            let mut path = format!("/api/v2/scan?filename={}", urlencode(name));
            if let Some(f) = opts.format {
                path.push_str(&format!("&format={}", urlencode(f)));
            }
            let raw = ui::with_spinner(&format!("Scanning {name}"), || {
                vuln_body(client.post_raw(&path, content))
            });
            (raw, name.to_string())
        }
        (None, None) => ApiError {
            status: None,
            message: "provide a lockfile path, `-` for stdin, or --url.".to_string(),
            kind: ErrorKind::Input,
        }
        .report(),
    };

    if opts.json {
        print_json(&body);
        // Even in JSON mode the gate still has to fire, or a CI job that asked
        // for machine-readable output would silently stop failing.
        let v: Value = serde_json::from_str(&body).unwrap_or_default();
        gate(&collect(&v), &v, threshold, opts.json);
        return;
    }

    let v: Value = crate::commands::parse_or_exit(&body, "scan");
    let findings = collect(&v);

    if output::wants_csv() {
        // Same columns, in the same order, as the web scan page's CSV export.
        let rows: Vec<Vec<String>> = findings
            .iter()
            .map(|f| {
                vec![
                    f.package.clone(),
                    f.version.clone(),
                    f.ecosystem.clone(),
                    f.advisory.clone(),
                    f.cve.clone(),
                    f.score.map(|s| format!("{s:.1}")).unwrap_or_default(),
                    f.severity.label().to_string(),
                    f.fixed.clone(),
                    f.summary.replace('\n', " "),
                ]
            })
            .collect();
        output::csv_table(
            &[
                "package",
                "version",
                "ecosystem",
                "advisory",
                "cve",
                "cvss",
                "severity",
                "fixed",
                "summary",
            ],
            &rows,
        );
    } else {
        render(&v, &findings, &label);
    }

    gate(&findings, &v, threshold, opts.json);
}

pub fn query(client: &HostClient, coordinate: &str, version: Option<&str>, json: bool) {
    let package = if coordinate.starts_with("pkg:") {
        serde_json::json!({ "purl": coordinate })
    } else {
        match coordinate.split_once('/') {
            Some((ecosystem, name)) if !ecosystem.is_empty() && !name.is_empty() => {
                serde_json::json!({ "ecosystem": ecosystem, "name": name })
            }
            _ => ApiError {
                status: None,
                message: format!(
                    "'{coordinate}' is not a package coordinate — use a purl (pkg:cargo/time) or ecosystem/name (crates.io/time)."
                ),
                kind: ErrorKind::Input,
            }
            .report(),
        }
    };

    let mut payload = serde_json::json!({ "package": package });
    if let Some(v) = version {
        payload["version"] = Value::String(v.to_string());
    }

    let body = ui::with_spinner(&format!("Querying {coordinate}"), || {
        vuln_body(client.post_json("/api/v2/query", &payload))
    });

    if output::wants_json(json) {
        print_json(&body);
        return;
    }

    let v: Value = crate::commands::parse_or_exit(&body, "query");
    let vulns = v
        .get("vulns")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();

    let findings: Vec<Finding> = vulns
        .iter()
        .map(|vuln| finding_from(vuln, coordinate, version.unwrap_or(""), ""))
        .collect();

    println!();
    println!(
        "  📦 Package Query  {}",
        format!(
            "{coordinate}{}",
            version.map(|v| format!("@{v}")).unwrap_or_default()
        )
        .cyan()
        .bold()
    );
    println!("{}", format!("  {}", "─".repeat(88)).dimmed());
    if findings.is_empty() {
        // An empty list is a real answer here, not an absence of one.
        println!("  {} No known vulnerabilities.", "✔".green().bold());
        println!();
        return;
    }
    print_table(&findings);
}

// ═══════════════════════════════════════════════════════════════════
//  Findings
// ═══════════════════════════════════════════════════════════════════

fn collect(v: &Value) -> Vec<Finding> {
    let results = v
        .get("results")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();
    let packages = v
        .get("packages")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();

    let mut findings = Vec::new();
    for (i, result) in results.iter().enumerate() {
        let Some(vulns) = result.get("vulns").and_then(|x| x.as_array()) else {
            continue;
        };
        // `results[i]` lines up with the coordinates the server echoed back.
        let coord = packages.get(i);
        let name = coord
            .and_then(|c| c.get("name").or_else(|| c.get("purl")))
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        let version = coord
            .and_then(|c| c.get("version"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let ecosystem = coord
            .and_then(|c| c.get("ecosystem"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();

        for vuln in vulns {
            findings.push(finding_from(vuln, &name, &version, &ecosystem));
        }
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.score.unwrap_or(0.0).total_cmp(&a.score.unwrap_or(0.0)))
            .then(a.package.cmp(&b.package))
    });
    findings
}

fn finding_from(vuln: &Value, package: &str, version: &str, ecosystem: &str) -> Finding {
    let advisory = vuln
        .get("id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let cve = if advisory.to_ascii_uppercase().starts_with("CVE-") {
        advisory.clone()
    } else {
        vuln.get("aliases")
            .and_then(|a| a.as_array())
            .into_iter()
            .flatten()
            .filter_map(|a| a.as_str())
            .find(|a| a.to_ascii_uppercase().starts_with("CVE-"))
            .unwrap_or_default()
            .to_string()
    };
    let summary = vuln
        .get("summary")
        .or_else(|| vuln.get("details"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .lines()
        .next()
        .unwrap_or("")
        .to_string();

    let score = score_of(vuln);

    Finding {
        package: package.to_string(),
        version: version.to_string(),
        ecosystem: ecosystem.to_string(),
        advisory,
        cve,
        score,
        severity: band(score),
        fixed: fixed_version(vuln, package),
        summary,
    }
}

/// The version that resolves the advisory, when the range says so.
fn fixed_version(vuln: &Value, package: &str) -> String {
    let affected = vuln
        .get("affected")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    for entry in &affected {
        // An advisory can cover several packages; only this one's ranges apply.
        if !package.is_empty() {
            if let Some(name) = entry.pointer("/package/name").and_then(|n| n.as_str()) {
                if !name.eq_ignore_ascii_case(package) {
                    continue;
                }
            }
        }
        for range in entry
            .get("ranges")
            .and_then(|r| r.as_array())
            .into_iter()
            .flatten()
        {
            for event in range
                .get("events")
                .and_then(|e| e.as_array())
                .into_iter()
                .flatten()
            {
                if let Some(fixed) = event.get("fixed").and_then(|f| f.as_str()) {
                    return fixed.to_string();
                }
            }
        }
    }
    String::new()
}

// ═══════════════════════════════════════════════════════════════════
//  Output
// ═══════════════════════════════════════════════════════════════════

fn render(v: &Value, findings: &[Finding], label: &str) {
    let scanned = v.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
    let cached = v.get("cached").and_then(|c| c.as_bool()).unwrap_or(false);

    println!();
    println!("  📦 Dependency Scan  {}", label.cyan().bold());
    println!("{}", format!("  {}", "─".repeat(88)).dimmed());
    println!(
        "  {:<14} {}{}",
        "Packages:".dimmed(),
        scanned.to_string().bold(),
        if cached {
            "  (cached)".dimmed().to_string()
        } else {
            String::new()
        },
    );

    if v.get("truncated")
        .and_then(|t| t.as_bool())
        .unwrap_or(false)
    {
        println!(
            "  {}",
            "Manifest truncated — not every package was scanned.".yellow()
        );
    }

    let counts = tally(findings);
    if findings.is_empty() {
        println!("  {:<14} {}", "Findings:".dimmed(), "none".green().bold());
    } else {
        println!(
            "  {:<14} {}",
            "Findings:".dimmed(),
            counts
                .iter()
                .map(|(sev, n)| colour(*sev, &format!("{n} {}", sev.label())).to_string())
                .collect::<Vec<_>>()
                .join("  "),
        );
    }
    println!();

    if !findings.is_empty() {
        print_table(findings);
    }

    for warning in incomplete(v) {
        ui::warning(&warning);
    }
}

/// Pad to `width` counting characters, not bytes — `{:<n}` measures the ANSI
/// escapes too, which knocks every colored column out of alignment.
fn pad(text: &str, width: usize) -> String {
    " ".repeat(width.saturating_sub(text.chars().count()))
}

fn print_table(findings: &[Finding]) {
    println!(
        "  {:<28} {:<14} {:<24} {:<10} {}",
        "Package".bold().underline(),
        "Severity".bold().underline(),
        "Advisory".bold().underline(),
        "Fixed in".bold().underline(),
        "Summary".bold().underline(),
    );

    for f in findings {
        // The ecosystem disambiguates a name that exists in several registries.
        let package = match (f.ecosystem.is_empty(), f.version.is_empty()) {
            (true, true) => f.package.clone(),
            (true, false) => format!("{}@{}", f.package, f.version),
            (false, true) => format!("{}:{}", f.ecosystem, f.package),
            (false, false) => format!("{}:{}@{}", f.ecosystem, f.package, f.version),
        };
        let severity = match f.score {
            Some(s) => format!("{} {:.1}", f.severity.label(), s),
            None => f.severity.label().to_string(),
        };
        let advisory = if f.cve.is_empty() || f.cve == f.advisory {
            f.advisory.clone()
        } else {
            format!("{} ({})", f.advisory, f.cve)
        };

        let advisory = truncate(&advisory, 24);
        let fixed = if f.fixed.is_empty() {
            "—".to_string()
        } else {
            f.fixed.clone()
        };

        println!(
            "  {:<28} {}{} {}{} {}{} {}",
            truncate(&package, 28),
            colour(f.severity, &severity),
            pad(&severity, 14),
            advisory,
            pad(&advisory, 24),
            if f.fixed.is_empty() {
                fixed.dimmed().to_string()
            } else {
                fixed.green().to_string()
            },
            pad(&fixed, 10),
            truncate(&f.summary, 58).dimmed(),
        );
    }
    println!();
}

fn tally(findings: &[Finding]) -> Vec<(Severity, usize)> {
    let mut out = Vec::new();
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::None,
    ] {
        let n = findings.iter().filter(|f| f.severity == sev).count();
        if n > 0 {
            out.push((sev, n));
        }
    }
    out
}

fn colour(sev: Severity, text: &str) -> colored::ColoredString {
    match sev {
        Severity::Critical => text.red().bold(),
        Severity::High => text.red(),
        Severity::Medium => text.yellow(),
        Severity::Low => text.cyan(),
        Severity::None => text.dimmed(),
    }
}

/// Reasons this scan cannot be called complete.
fn incomplete(v: &Value) -> Vec<String> {
    let mut reasons = Vec::new();

    if v.get("outage").and_then(|o| o.as_bool()).unwrap_or(false) {
        reasons.push("The vulnerability source had an outage during this scan.".to_string());
    }

    let unscanned = v
        .get("results")
        .and_then(|r| r.as_array())
        .map(|rs| {
            rs.iter()
                .filter(|r| r.get("ok").and_then(|o| o.as_bool()) == Some(false))
                .count()
        })
        .unwrap_or(0);
    if unscanned > 0 {
        // The API is explicit that this is not the same as "no vulnerabilities".
        reasons.push(format!(
            "{unscanned} package(s) could not be scanned — that is not the same as finding nothing."
        ));
    }

    if v.get("truncated")
        .and_then(|t| t.as_bool())
        .unwrap_or(false)
    {
        reasons.push("The manifest was truncated before scanning.".to_string());
    }

    reasons
}

/// Apply `--fail-on`. An incomplete scan never passes the gate: "we did not
/// look" must not be reported as "nothing to find".
fn gate(findings: &[Finding], payload: &Value, threshold: Option<Severity>, json: bool) {
    let Some(threshold) = threshold else { return };

    let reasons = incomplete(payload);
    if !reasons.is_empty() {
        if output::wants_json(json) {
            for reason in &reasons {
                ui::warning(reason);
            }
        }
        ApiError::new(
            None,
            format!(
                "scan incomplete, so --fail-on {} cannot be evaluated: {}",
                threshold.label(),
                reasons.join(" ")
            ),
        )
        .report();
    }

    let matched: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity >= threshold)
        .collect();
    if matched.is_empty() {
        return;
    }

    ui::restore();
    eprintln!(
        "{} {} finding(s) at or above {}",
        "error:".red().bold(),
        matched.len(),
        threshold.label()
    );
    for f in matched.iter().take(10) {
        eprintln!(
            "  {} {}@{}  {}",
            colour(f.severity, f.severity.label()),
            f.package,
            f.version,
            f.advisory.dimmed()
        );
    }
    std::process::exit(EXIT_FINDINGS);
}

fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_string()
    } else {
        format!(
            "{}…",
            s.chars().take(width.saturating_sub(1)).collect::<String>()
        )
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn payload_with(results: Value, packages: Value) -> Value {
        json!({ "count": 2, "cached": false, "truncated": false, "outage": false,
                "results": results, "packages": packages })
    }

    #[test]
    fn findings_are_flattened_against_the_package_at_the_same_index() {
        let v = payload_with(
            json!([
                {"ok": true, "vulns": []},
                {"ok": true, "vulns": [{"id":"GHSA-x","aliases":["CVE-2026-1"],
                    "severity":[{"score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                    "summary":"bad","affected":[{"package":{"name":"left-pad"},
                    "ranges":[{"events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}]}
            ]),
            json!([{"name":"ok-pkg","version":"1.0.0"},{"name":"left-pad","version":"1.0.0","ecosystem":"npm"}]),
        );

        let findings = collect(&v);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].package, "left-pad");
        assert_eq!(findings[0].version, "1.0.0");
        assert_eq!(findings[0].cve, "CVE-2026-1");
        assert_eq!(findings[0].fixed, "1.2.3");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn findings_are_ordered_worst_first() {
        let vuln = |id: &str, vector: &str| json!({"id": id, "severity":[{"score": vector}]});
        let v = payload_with(
            json!([{"ok": true, "vulns": [
                vuln("LOW", "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"),
                vuln("CRIT", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
            ]}]),
            json!([{"name":"p","version":"1"}]),
        );
        let findings = collect(&v);
        assert_eq!(findings[0].advisory, "CRIT");
        assert_eq!(findings[1].advisory, "LOW");
    }

    #[test]
    fn a_fix_from_another_package_in_the_same_advisory_is_not_borrowed() {
        let vuln = json!({"id":"GHSA-y","affected":[
            {"package":{"name":"other"},"ranges":[{"events":[{"fixed":"9.9.9"}]}]},
            {"package":{"name":"mine"},"ranges":[{"events":[{"fixed":"2.0.0"}]}]}]});
        assert_eq!(fixed_version(&vuln, "mine"), "2.0.0");
        assert_eq!(fixed_version(&vuln, "other"), "9.9.9");
    }

    #[test]
    fn an_outage_makes_a_scan_incomplete() {
        let mut v = payload_with(json!([{"ok": true, "vulns": []}]), json!([{"name":"p"}]));
        assert!(incomplete(&v).is_empty());

        v["outage"] = json!(true);
        assert_eq!(incomplete(&v).len(), 1);
    }

    #[test]
    fn a_package_that_could_not_be_scanned_makes_it_incomplete_too() {
        // `ok:false` means "not scanned", never "clean".
        let v = payload_with(
            json!([{"ok": false, "unqueryable": true}, {"ok": true, "vulns": []}]),
            json!([{"name":"a"},{"name":"b"}]),
        );
        let reasons = incomplete(&v);
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("1 package"));
    }

    #[test]
    fn a_truncated_manifest_is_flagged() {
        let mut v = payload_with(json!([]), json!([]));
        v["truncated"] = json!(true);
        assert_eq!(incomplete(&v).len(), 1);
    }

    #[test]
    fn the_tally_counts_each_band_and_drops_the_empty_ones() {
        let v = payload_with(
            json!([{"ok": true, "vulns": [
                {"id":"a","severity":[{"score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
                {"id":"b","severity":[{"score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}
            ]}]),
            json!([{"name":"p","version":"1"}]),
        );
        let counts = tally(&collect(&v));
        assert_eq!(counts, vec![(Severity::Critical, 1), (Severity::High, 1)]);
    }

    #[test]
    fn padding_counts_characters_not_escape_sequences() {
        assert_eq!(pad("abc", 6).len(), 3);
        assert_eq!(pad("abcdef", 6).len(), 0);
        assert_eq!(pad("toolongvalue", 6).len(), 0);
        // Multi-byte input pads by what the terminal shows, not by byte count.
        assert_eq!(pad("é", 3).len(), 2);
    }

    #[test]
    fn long_cells_are_truncated_with_an_ellipsis() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("abcdefghij", 5), "abcd…");
    }
}
