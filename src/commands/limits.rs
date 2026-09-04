use colored::Colorize;
use serde::Deserialize;

use crate::client::MlabClient;
use crate::commands::body;
use crate::error::ApiError;
use crate::ui::Spinner;

struct LimitInfo {
    label: &'static str,
    icon: &'static str,
    path: &'static str,
}

const LIMITS: &[LimitInfo] = &[
    LimitInfo { label: "Domain scans",   icon: "🌐", path: "/limit/domain" },
    LimitInfo { label: "IP lookups",     icon: "🔍", path: "/limit/ip" },
    LimitInfo { label: "File scans",     icon: "📄", path: "/limit/file" },
    LimitInfo { label: "Crypto lookups", icon: "🪙", path: "/limit/crypto" },
];

/// The API answers with a JSON object, not a bare number:
/// `{"scan_type":"domain","remaining":98,"total":100}`.
#[derive(Deserialize)]
struct LimitResponse {
    #[serde(default)]
    remaining: u64,
    #[serde(default)]
    total: u64,
}

fn fetch_limit(client: &MlabClient, path: &str) -> Result<LimitResponse, ApiError> {
    let raw = body(client.get(path))?;
    serde_json::from_str(&raw)
        .map_err(|e| ApiError::new(None, format!("unreadable limit response: {e}")))
}

const BAR_WIDTH: usize = 20;

/// How many cells of a `width`-wide bar to fill. Split out from the rendering so
/// the arithmetic (including the total == 0 case) is testable without colors.
fn bar_fill(remaining: u64, total: u64, width: usize) -> usize {
    if total == 0 {
        return 0;
    }
    let ratio = remaining.min(total) as f64 / total as f64;
    ((ratio * width as f64).round() as usize).min(width)
}

/// A quota at or below a fifth of the allowance is worth flagging.
fn is_low(remaining: u64, total: u64) -> bool {
    total > 0 && remaining * 5 <= total
}

fn print_bar(remaining: u64, total: u64) -> String {
    let fill = bar_fill(remaining, total, BAR_WIDTH);
    let filled = "█".repeat(fill);
    format!(
        "{}{}",
        if is_low(remaining, total) { filled.red() } else { filled.green() },
        "░".repeat(BAR_WIDTH - fill).dimmed(),
    )
}

pub fn run(client: &MlabClient, scan_type: Option<&str>, raw: bool) {
    let targets: Vec<&LimitInfo> = match scan_type {
        Some(t) => {
            let info = LIMITS.iter().find(|l| l.path.ends_with(t));
            match info {
                Some(l) => vec![l],
                None => {
                    eprintln!("Unknown limit type: {t}. Use: domain, ip, file, or crypto.");
                    std::process::exit(1);
                }
            }
        }
        None => LIMITS.iter().collect(),
    };

    let mut failure: Option<ApiError> = None;
    // One request per scan type: a plain spinner would look stuck, so it counts.
    let spinner = Spinner::with_steps("Checking quotas", targets.len() as u64);
    let mut rows: Vec<(usize, String)> = Vec::new();
    let mut values: Vec<Option<LimitResponse>> = Vec::new();

    for (i, limit) in targets.iter().enumerate() {
        let outcome = fetch_limit(client, limit.path);
        spinner.advance();
        match outcome {
            Ok(l) => {
                values.push(Some(LimitResponse { remaining: l.remaining, total: l.total }));
                rows.push((
                    i,
                    if raw {
                        l.remaining.to_string()
                    } else {
                        format!(
                            "  {} {:<14} {} {}",
                            limit.icon,
                            limit.label,
                            print_bar(l.remaining, l.total),
                            format!("{} / {} remaining", l.remaining, l.total).bold(),
                        )
                    },
                ));
            }
            Err(e) => {
                values.push(None);
                rows.push((
                    i,
                    if raw {
                        "error".to_string()
                    } else {
                        format!("  {} {:<14} {}", limit.icon, limit.label, e.message.red())
                    },
                ));
                failure = Some(e);
            }
        }
    }

    // Printed only once every request is in, so the spinner never interleaves
    // with the table it is waiting for.
    spinner.clear();

    if crate::output::wants_csv() {
        let table: Vec<Vec<String>> = targets
            .iter()
            .zip(values.iter())
            .map(|(limit, value)| {
                let scan_type = limit.path.trim_start_matches("/limit/").to_string();
                match value {
                    Some(l) => vec![scan_type, l.remaining.to_string(), l.total.to_string()],
                    None => vec![scan_type, "error".to_string(), "error".to_string()],
                }
            })
            .collect();
        crate::output::csv_table(&["scan_type", "remaining", "total"], &table);
    } else {
        for (_, row) in &rows {
            println!("{row}");
        }
    }

    // Exit with the reason for the failure (auth, quota, …), not a flat 1.
    if let Some(e) = failure {
        e.report();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bar_fill_is_proportional_to_the_total() {
        assert_eq!(bar_fill(100, 100, 20), 20);
        assert_eq!(bar_fill(50, 100, 20), 10);
        assert_eq!(bar_fill(0, 100, 20), 0);
    }

    #[test]
    fn bar_fill_survives_a_zero_or_inconsistent_total() {
        // An unknown allowance must not divide by zero...
        assert_eq!(bar_fill(0, 0, 20), 0);
        assert_eq!(bar_fill(9, 0, 20), 0);
        // ...and remaining > total must not overflow the bar.
        assert_eq!(bar_fill(150, 100, 20), 20);
    }

    #[test]
    fn low_quota_is_a_fifth_or_less() {
        assert!(is_low(20, 100));
        assert!(is_low(0, 100));
        assert!(!is_low(21, 100));
        assert!(!is_low(5, 0));
    }

    #[test]
    fn limit_response_reads_the_documented_json_shape() {
        // The API answers with an object, never a bare integer: parsing this as
        // a number is exactly the bug this test exists to prevent.
        let body = r#"{"scan_type":"domain","remaining":98,"total":100}"#;
        let l: LimitResponse = serde_json::from_str(body).expect("parses");
        assert_eq!(l.remaining, 98);
        assert_eq!(l.total, 100);
        assert!(body.parse::<u64>().is_err());
    }

    #[test]
    fn limit_response_tolerates_missing_fields() {
        let l: LimitResponse = serde_json::from_str(r#"{"scan_type":"ip"}"#).expect("parses");
        assert_eq!(l.remaining, 0);
        assert_eq!(l.total, 0);
    }
}
