use colored::Colorize;
use serde::Deserialize;

use crate::client::MlabClient;
use crate::commands::{fetch, parse_or_exit, print_json};
use crate::util::{days_until, urlencode};

/// Certificates expiring within this many days are flagged as needing attention.
const EXPIRY_WARNING_DAYS: i64 = 30;

#[derive(Deserialize, Default)]
pub struct SslCert {
    #[serde(default)]
    pub common_name: String,
    #[serde(default)]
    pub issuer_name: String,
    #[serde(default)]
    pub not_before: String,
    #[serde(default)]
    pub not_after: String,
    #[serde(default)]
    pub name_value: String,
    #[serde(default)]
    pub serial_number: String,
}

pub fn run(client: &MlabClient, domain: &str, json: bool) {
    let body = fetch(client.get(&format!("/domain/ssl?domain={}", urlencode(domain))));

    if json {
        print_json(&body);
        return;
    }

    let certs: Vec<SslCert> = parse_or_exit(&body, "SSL");

    if certs.is_empty() {
        println!("  No SSL certificates on record for {}.", domain.cyan());
        // The endpoint only reads what a scan already collected, so an empty
        // answer usually means "never scanned", not "no certificates".
        println!(
            "  {}",
            format!("Run `mlab scan domain {domain}` first — this endpoint returns cached scan data.")
                .dimmed()
        );
        return;
    }

    println!();
    println!(
        "  {} Found {} certificate(s) for {}",
        "🔒",
        certs.len().to_string().bold(),
        domain.cyan()
    );
    println!();
    render_table(&certs, true);
}

/// Shared with the domain report so both surfaces render certificates the same way.
pub fn render_table(certs: &[SslCert], show_sans: bool) {
    let divider = format!("  {}", "─".repeat(100));

    println!(
        "  {:<30} {:<14} {:<14} {:<40}",
        "Common Name".bold().underline(),
        "Valid From".bold().underline(),
        "Expires".bold().underline(),
        "Issuer".bold().underline(),
    );
    println!("{}", divider.dimmed());

    for cert in certs {
        let not_before = date_only(&cert.not_before);
        let not_after = date_only(&cert.not_after);

        let expiry = match expiry_state(&cert.not_after) {
            Expiry::Expired => format!("{} (expired)", not_after).red().to_string(),
            Expiry::Soon(days) => format!("{} ({}d left)", not_after, days).yellow().to_string(),
            Expiry::Valid => not_after.green().to_string(),
            Expiry::Unknown => not_after.normal().to_string(),
        };

        println!(
            "  {:<30} {:<14} {:<25} {}",
            cert.common_name,
            not_before,
            expiry,
            shorten_issuer(&cert.issuer_name).dimmed(),
        );

        if show_sans {
            let sans: Vec<&str> = cert
                .name_value
                .split('\n')
                .filter(|s| !s.is_empty() && *s != cert.common_name)
                .collect();
            if !sans.is_empty() {
                println!("  {} {}", "  SANs:".dimmed(), sans.join(", ").dimmed());
            }
            if !cert.serial_number.is_empty() {
                println!("  {} {}", "  Serial:".dimmed(), cert.serial_number.dimmed());
            }
        }
    }

    println!("{}", divider.dimmed());
    println!();
    println!(
        "  {} = valid   {} = expires within {EXPIRY_WARNING_DAYS} days   {} = expired",
        "●".green(),
        "●".yellow(),
        "●".red(),
    );
    println!();
}

#[derive(Debug, PartialEq, Eq)]
enum Expiry {
    Valid,
    Soon(i64),
    Expired,
    Unknown,
}

/// Expiry measured against the clock, not against a date baked in at authoring
/// time — a hardcoded "today" silently rots into wrong answers.
fn expiry_state(not_after: &str) -> Expiry {
    match days_until(not_after) {
        None => Expiry::Unknown,
        Some(d) if d < 0 => Expiry::Expired,
        Some(d) if d <= EXPIRY_WARNING_DAYS => Expiry::Soon(d),
        Some(_) => Expiry::Valid,
    }
}

fn date_only(timestamp: &str) -> &str {
    timestamp.split('T').next().unwrap_or(timestamp)
}

fn shorten_issuer(issuer: &str) -> String {
    for part in issuer.split(", ") {
        if let Some(cn) = part.strip_prefix("CN=") {
            return cn.to_string();
        }
    }
    for part in issuer.split(", ") {
        if let Some(org) = part.strip_prefix("O=") {
            return org.to_string();
        }
    }
    issuer.chars().take(40).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::today_epoch_days;

    fn iso(days_from_today: i64) -> String {
        // Build a date by walking the same conversion the helper uses, so the
        // test cannot drift with the calendar.
        let target = today_epoch_days() + days_from_today;
        let mut y = 1970;
        let mut remaining = target;
        loop {
            let len = if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 366 } else { 365 };
            if remaining < len {
                break;
            }
            remaining -= len;
            y += 1;
        }
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let months = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let mut m = 0;
        while remaining >= months[m] {
            remaining -= months[m];
            m += 1;
        }
        format!("{:04}-{:02}-{:02}", y, m + 1, remaining + 1)
    }

    #[test]
    fn expiry_is_measured_against_today_not_a_baked_in_date() {
        assert_eq!(expiry_state(&iso(-1)), Expiry::Expired);
        assert_eq!(expiry_state(&iso(400)), Expiry::Valid);
    }

    #[test]
    fn a_certificate_expiring_within_the_month_is_flagged() {
        assert!(matches!(expiry_state(&iso(10)), Expiry::Soon(_)));
        assert_eq!(expiry_state(&iso(EXPIRY_WARNING_DAYS + 5)), Expiry::Valid);
    }

    #[test]
    fn an_unparsable_date_is_reported_as_unknown_rather_than_guessed() {
        assert_eq!(expiry_state(""), Expiry::Unknown);
        assert_eq!(expiry_state("n/a"), Expiry::Unknown);
    }

    #[test]
    fn issuer_is_shortened_to_the_common_name_then_the_organization() {
        assert_eq!(shorten_issuer("C=US, O=DigiCert Inc, CN=DigiCert Global CA G2"), "DigiCert Global CA G2");
        assert_eq!(shorten_issuer("C=US, O=Let's Encrypt"), "Let's Encrypt");
        assert_eq!(shorten_issuer("weird"), "weird");
    }

    #[test]
    fn timestamps_are_trimmed_to_their_date() {
        assert_eq!(date_only("2027-01-15T23:59:59"), "2027-01-15");
        assert_eq!(date_only("2027-01-15"), "2027-01-15");
    }
}
