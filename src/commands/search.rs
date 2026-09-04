//! One entry point that works out what you pasted and routes it.
//!
//! Detection is local and ordered most-specific-first: an IPv4 literal must not
//! be read as a domain, and a 32-character hex string is a digest, not a name.
//! Nothing here launches a domain scan — that spends quota and takes minutes, so
//! it stays an explicit `mlab scan domain`.

use colored::Colorize;

use crate::client::{HostClient, MlabClient};
use crate::error::{ApiError, ErrorKind};
use crate::ui;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Cve,
    Ip,
    Mac,
    Email,
    Hash,
    Crypto,
    Url,
    Phone,
    Domain,
    Unknown,
}

impl Target {
    pub fn label(self) -> &'static str {
        match self {
            Target::Cve => "CVE identifier",
            Target::Ip => "IP address",
            Target::Mac => "MAC address",
            Target::Email => "email address",
            Target::Hash => "file hash",
            Target::Crypto => "crypto address",
            Target::Url => "URL",
            Target::Phone => "phone number",
            Target::Domain => "domain",
            Target::Unknown => "unrecognised input",
        }
    }
}

pub fn detect(raw: &str) -> Target {
    let input = raw.trim();
    if input.is_empty() {
        return Target::Unknown;
    }

    if is_cve(input) {
        return Target::Cve;
    }
    if is_ip(input) {
        return Target::Ip;
    }
    if is_mac(input) {
        return Target::Mac;
    }
    if is_email(input) {
        return Target::Email;
    }
    if is_hash(input) {
        return Target::Hash;
    }
    if is_crypto(input) {
        return Target::Crypto;
    }
    // A scheme or a path means the whole string is a URL, not a bare host.
    if input.contains("://") || input.contains('/') {
        return Target::Url;
    }
    if is_phone(input) {
        return Target::Phone;
    }
    if is_domain(input) {
        return Target::Domain;
    }
    Target::Unknown
}

pub fn run(client: &MlabClient, vuln: &HostClient, query: &str, json: bool) {
    let target = detect(query);
    let value = query.trim();

    if target == Target::Unknown {
        ApiError {
            status: None,
            message: format!("could not tell what '{value}' is."),
            kind: ErrorKind::Input,
        }
        .report();
    }

    ui::info(&format!("Detected {} — routing to it", target.label()));

    match target {
        Target::Cve => crate::commands::cve::detail(vuln, value, json),
        Target::Ip => crate::commands::scan::ip(client, value, json),
        Target::Mac => crate::commands::lookup::mac(client, value, json),
        Target::Email => crate::commands::lookup::email(client, value, json),
        Target::Hash => crate::commands::lookup::hash(client, &[value.to_string()], json),
        Target::Crypto => crate::commands::scan::crypto(client, &[value.to_string()], None, json),
        Target::Url => crate::commands::lookup::url(client, value, false, json),
        Target::Phone => crate::commands::lookup::phone(client, value, json),
        // Deliberately the read side: searching must never start a scan.
        Target::Domain => {
            crate::commands::results::domain(client, value, json);
        }
        Target::Unknown => unreachable!("handled above"),
    }
}

/// The web page for a target, on whichever host owns it.
pub fn web_url(target: Target, value: &str, main_host: &str, cve_host: &str) -> Option<String> {
    let main = main_host.trim_end_matches('/');
    let encoded = crate::util::urlencode(value);
    match target {
        Target::Domain => Some(format!("{main}/domain/{encoded}")),
        Target::Ip => Some(format!("{main}/ip/{encoded}")),
        Target::Hash => Some(format!("{main}/hash/{encoded}")),
        Target::Mac => Some(format!("{main}/mac/{encoded}")),
        Target::Email => Some(format!("{main}/email/{encoded}")),
        Target::Phone => Some(format!("{main}/phone/{encoded}")),
        Target::Crypto => Some(format!("{main}/crypto/{encoded}")),
        Target::Url => Some(format!("{main}/url?q={encoded}")),
        Target::Cve => Some(format!("{}/cve/{}", cve_host.trim_end_matches('/'), value.to_uppercase())),
        Target::Unknown => None,
    }
}

/// Open the matching report in a browser. The URL is built from a fixed
/// template plus the user's own argument — never from anything a server said.
pub fn open(value: &str, main_host: &str, cve_host: &str, print_only: bool) {
    let target = detect(value);
    let Some(url) = web_url(target, value.trim(), main_host, cve_host) else {
        ApiError {
            status: None,
            message: format!("could not tell what '{value}' is, so there is no page to open."),
            kind: ErrorKind::Input,
        }
        .report();
    };

    if print_only {
        println!("{url}");
        return;
    }

    match launch(&url) {
        Ok(()) => ui::success(&format!("Opened {}", url.cyan())),
        Err(e) => {
            // Not being able to launch a browser is not a reason to withhold the
            // address — a headless box still wants to see it.
            ui::warning(&format!("Could not open a browser ({e})"));
            println!("{url}");
        }
    }
}

#[cfg(target_os = "macos")]
fn launch(url: &str) -> std::io::Result<()> {
    std::process::Command::new("open").arg(url).status().map(|_| ())
}

#[cfg(target_os = "windows")]
fn launch(url: &str) -> std::io::Result<()> {
    std::process::Command::new("cmd").args(["/C", "start", "", url]).status().map(|_| ())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn launch(url: &str) -> std::io::Result<()> {
    std::process::Command::new("xdg-open").arg(url).status().map(|_| ())
}

// ═══════════════════════════════════════════════════════════════════
//  Detection
// ═══════════════════════════════════════════════════════════════════

fn is_cve(s: &str) -> bool {
    let upper = s.to_uppercase();
    let Some(rest) = upper.strip_prefix("CVE-") else { return false };
    let mut parts = rest.split('-');
    let year = parts.next().unwrap_or("");
    let seq = parts.next().unwrap_or("");
    parts.next().is_none()
        && year.len() == 4
        && year.chars().all(|c| c.is_ascii_digit())
        && (4..=7).contains(&seq.len())
        && seq.chars().all(|c| c.is_ascii_digit())
}

fn is_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

fn is_mac(s: &str) -> bool {
    let separators = [':', '-'];
    let parts: Vec<&str> = s.split(separators).collect();
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_email(s: &str) -> bool {
    let mut parts = s.split('@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    parts.next().is_none() && !local.is_empty() && is_domain(domain)
}

/// MD5, SHA-1 and SHA-256 by length. SHA-512 is deliberately included: the API
/// answers "describable but not queryable" rather than nothing.
fn is_hash(s: &str) -> bool {
    matches!(s.len(), 32 | 40 | 64 | 128) && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_crypto(s: &str) -> bool {
    // EVM: 0x + 40 hex.
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return rest.len() == 40 && rest.chars().all(|c| c.is_ascii_hexdigit());
    }
    // Bech32 (bitcoin, and the same shape for several chains).
    if (s.starts_with("bc1") || s.starts_with("tb1")) && (14..=74).contains(&s.len()) {
        return s.chars().all(|c| c.is_ascii_alphanumeric());
    }
    // Base58 legacy addresses: no 0, O, I or l, and no dots to confuse with hosts.
    if matches!(s.chars().next(), Some('1') | Some('3')) && (26..=35).contains(&s.len()) {
        return s.chars().all(|c| c.is_ascii_alphanumeric() && !"0OIl".contains(c));
    }
    false
}

fn is_phone(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('+') else { return false };
    let digits: String = rest.chars().filter(|c| !c.is_whitespace() && *c != '-' && *c != '.').collect();
    (6..=15).contains(&digits.len()) && digits.chars().all(|c| c.is_ascii_digit())
}

fn is_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 || !s.contains('.') || s.starts_with('.') || s.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    let tld = labels.last().copied().unwrap_or("");
    // A numeric TLD is never a real domain; that shape is a malformed IP.
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_supported_shape_is_recognised() {
        let cases = [
            ("CVE-2024-3094", Target::Cve),
            ("cve-2024-3094", Target::Cve),
            ("8.8.8.8", Target::Ip),
            ("2606:4700::1111", Target::Ip),
            ("00:11:22:33:44:55", Target::Mac),
            ("00-11-22-33-44-55", Target::Mac),
            ("abuse@example.com", Target::Email),
            ("d41d8cd98f00b204e9800998ecf8427e", Target::Hash),
            ("da39a3ee5e6b4b0d3255bfef95601890afd80709", Target::Hash),
            ("0x742d35Cc6634C0532925a3b844Bc454e4438f44e", Target::Crypto),
            ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Target::Crypto),
            ("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", Target::Crypto),
            ("https://example.com/path", Target::Url),
            ("example.com/path", Target::Url),
            ("+33612345678", Target::Phone),
            ("example.com", Target::Domain),
            ("sub.example.co.uk", Target::Domain),
        ];
        for (input, expected) in cases {
            assert_eq!(detect(input), expected, "for {input:?}");
        }
    }

    #[test]
    fn an_ip_is_never_mistaken_for_a_domain() {
        assert_eq!(detect("1.2.3.4"), Target::Ip);
        // Four numeric labels that are not a valid IP are not a domain either.
        assert_eq!(detect("999.999.999.999"), Target::Unknown);
    }

    #[test]
    fn a_digest_is_never_mistaken_for_a_name() {
        // 32 hex characters have no dot, so nothing else could claim them.
        assert_eq!(detect("d41d8cd98f00b204e9800998ecf8427e"), Target::Hash);
        assert_eq!(detect("deadbeef"), Target::Unknown);
    }

    #[test]
    fn junk_is_reported_rather_than_guessed() {
        for input in ["", "   ", "hello world", "...", "-", "not a thing"] {
            assert_eq!(detect(input), Target::Unknown, "for {input:?}");
        }
    }

    #[test]
    fn a_trailing_or_leading_dot_is_not_a_domain() {
        assert_eq!(detect(".example.com"), Target::Unknown);
        assert_eq!(detect("example.com."), Target::Unknown);
        assert_eq!(detect("example..com"), Target::Unknown);
    }

    #[test]
    fn a_numeric_tld_is_refused() {
        assert_eq!(detect("1.2.3.400"), Target::Unknown);
    }

    #[test]
    fn base58_addresses_reject_the_ambiguous_characters() {
        // '0', 'O', 'I' and 'l' are not in the base58 alphabet.
        assert_eq!(detect("10OIl1eP5QGefi2DMPTfTL5SLmv7Div"), Target::Unknown);
    }

    #[test]
    fn web_urls_point_at_the_host_that_owns_the_page() {
        let main = "https://mlab.sh";
        let cve = "https://vuln.mlab.sh";
        assert_eq!(
            web_url(Target::Domain, "example.com", main, cve).unwrap(),
            "https://mlab.sh/domain/example.com"
        );
        assert_eq!(
            web_url(Target::Cve, "cve-2024-3094", main, cve).unwrap(),
            "https://vuln.mlab.sh/cve/CVE-2024-3094"
        );
        assert_eq!(
            web_url(Target::Url, "https://x.test/a b", main, cve).unwrap(),
            "https://mlab.sh/url?q=https%3A%2F%2Fx.test%2Fa%20b"
        );
        assert!(web_url(Target::Unknown, "?", main, cve).is_none());
    }

    #[test]
    fn a_trailing_slash_on_the_host_is_not_doubled() {
        assert_eq!(
            web_url(Target::Ip, "8.8.8.8", "https://mlab.sh/", "https://vuln.mlab.sh/").unwrap(),
            "https://mlab.sh/ip/8.8.8.8"
        );
    }
}
