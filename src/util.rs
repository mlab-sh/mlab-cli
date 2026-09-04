//! Small shared helpers: query-string escaping and just enough calendar
//! arithmetic to say whether a certificate has expired.

/// Percent-encode everything outside the RFC 3986 unreserved set.
///
/// Every value interpolated into a query string goes through this — a domain or
/// hash carrying an `&` would otherwise smuggle a second parameter into the URL.
pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.as_bytes() {
        let c = *byte as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse the leading `YYYY-MM-DD` of a timestamp into days since the epoch.
/// Returns `None` for anything that is not a date, which the callers render as
/// "unknown" rather than guessing.
pub fn epoch_days(timestamp: &str) -> Option<i64> {
    let date = timestamp.get(..10)?;
    let mut parts = date.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

pub fn today_epoch_days() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    secs / 86_400
}

/// Days from today until `timestamp`; negative once it is in the past.
pub fn days_until(timestamp: &str) -> Option<i64> {
    Some(epoch_days(timestamp)? - today_epoch_days())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_leaves_the_unreserved_set_alone() {
        assert_eq!(urlencode("example.com"), "example.com");
        assert_eq!(urlencode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(urlencode("CVE-2024-3094"), "CVE-2024-3094");
    }

    #[test]
    fn urlencode_neutralizes_query_injection() {
        let encoded = urlencode("evil.com&domain=other.com");
        assert!(!encoded.contains('&'));
        assert!(!encoded.contains('='));
        assert_eq!(urlencode("a b"), "a%20b");
    }

    #[test]
    fn urlencode_escapes_multibyte_input_per_utf8_byte() {
        // Percent-encoding is defined over bytes; encoding the char's code point
        // would produce something no server can decode.
        assert_eq!(urlencode("é"), "%C3%A9");
    }

    #[test]
    fn epoch_days_matches_known_dates() {
        assert_eq!(epoch_days("1970-01-01"), Some(0));
        assert_eq!(epoch_days("1970-01-02T00:00:00"), Some(1));
        assert_eq!(epoch_days("2000-03-01"), Some(11017));
        assert_eq!(epoch_days("2026-01-01"), Some(20454));
    }

    #[test]
    fn epoch_days_rejects_anything_that_is_not_a_date() {
        assert_eq!(epoch_days(""), None);
        assert_eq!(epoch_days("not-a-date"), None);
        assert_eq!(epoch_days("2026-13-01"), None);
        assert_eq!(epoch_days("2026-01-99"), None);
    }

    #[test]
    fn days_until_is_signed_around_today() {
        let today = today_epoch_days();
        assert_eq!(days_until("1970-01-01"), Some(-today));
        assert!(days_until("2999-01-01").unwrap() > 0);
    }
}
