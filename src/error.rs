//! One place that turns an HTTP answer into a message a human can act on and an
//! exit code a script can branch on.
//!
//! The API answers 400 for almost everything — quota exhausted, maintenance,
//! malformed input — with the reason in `{"error": "..."}`. Printing `HTTP 400`
//! and the raw JSON pushes that classification onto every caller, so it happens
//! here once instead.

use std::fmt::Display;

use colored::Colorize;

pub const EXIT_ERROR: i32 = 1;
pub const EXIT_AUTH: i32 = 2;
pub const EXIT_QUOTA: i32 = 3;
pub const EXIT_INPUT: i32 = 4;
pub const EXIT_MAINTENANCE: i32 = 5;
pub const EXIT_NOT_FOUND: i32 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Auth,
    Quota,
    Input,
    Maintenance,
    NotFound,
    Other,
}

impl ErrorKind {
    pub fn exit_code(self) -> i32 {
        match self {
            ErrorKind::Auth => EXIT_AUTH,
            ErrorKind::Quota => EXIT_QUOTA,
            ErrorKind::Input => EXIT_INPUT,
            ErrorKind::Maintenance => EXIT_MAINTENANCE,
            ErrorKind::NotFound => EXIT_NOT_FOUND,
            ErrorKind::Other => EXIT_ERROR,
        }
    }

    pub fn hint(self) -> Option<&'static str> {
        match self {
            ErrorKind::Auth => Some("Check your key with `mlab whoami`, or set a new one with `mlab login`."),
            ErrorKind::Quota => Some("See what is left with `mlab limits`."),
            ErrorKind::Maintenance => Some("The platform is in maintenance — retry in a few minutes."),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: Option<u16>,
    pub message: String,
    pub kind: ErrorKind,
}

impl ApiError {
    pub fn new(status: Option<u16>, message: impl Into<String>) -> Self {
        let message = message.into();
        let kind = classify(status, &message);
        Self { status, message, kind }
    }

    /// Something went wrong before an HTTP status existed (DNS, TLS, timeout).
    pub fn transport(e: impl Display) -> Self {
        Self { status: None, message: e.to_string(), kind: ErrorKind::Other }
    }

    pub fn from_response(status: u16, body: &str) -> Self {
        Self::new(Some(status), extract_message(status, body))
    }

    pub fn report(&self) -> ! {
        // The status is redundant once the message says what went wrong, so it
        // is only shown when the server gave us nothing better to print.
        match self.status {
            Some(code) if self.kind == ErrorKind::Other && self.message == format!("HTTP {code}") => {
                eprintln!("{} the API answered HTTP {code}", "error:".red().bold())
            }
            _ => eprintln!("{} {}", "error:".red().bold(), self.message),
        }
        if let Some(hint) = self.kind.hint() {
            eprintln!("  {}", hint.dimmed());
        }
        std::process::exit(self.kind.exit_code())
    }
}

/// Pull the human-readable reason out of a response body, falling back to the
/// status line when the body is not the documented `{"error": ...}` shape.
pub fn extract_message(status: u16, body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        for key in ["error", "message"] {
            if let Some(m) = v.get(key).and_then(|m| m.as_str()) {
                if !m.is_empty() {
                    return m.to_string();
                }
            }
        }
    }
    let trimmed = body.trim();
    if !trimmed.is_empty() && trimmed.len() <= 200 && !trimmed.starts_with('{') {
        return trimmed.to_string();
    }
    format!("HTTP {status}")
}

/// Map a status and a message onto something the caller can branch on. The
/// status alone is not enough: production answers 400 for quota, maintenance
/// and bad input alike, so the message is what separates them.
pub fn classify(status: Option<u16>, message: &str) -> ErrorKind {
    match status {
        Some(401) | Some(403) => return ErrorKind::Auth,
        Some(429) => return ErrorKind::Quota,
        _ => {}
    }

    let m = message.to_ascii_lowercase();

    if m.contains("limit reached") || m.contains("quota") || m.contains("too many") {
        ErrorKind::Quota
    } else if m.contains("maintenance") {
        ErrorKind::Maintenance
    } else if m.contains("unauthorized") || m.contains("api key") {
        ErrorKind::Auth
    } else if m.contains("no scan found") || m.contains("not found") || m.contains("no results") {
        ErrorKind::NotFound
    } else if m.contains("invalid")
        || m.contains("please provide")
        || m.contains("not a recognized")
        || m.contains("unsupported")
    {
        ErrorKind::Input
    } else if status == Some(404) {
        ErrorKind::NotFound
    } else {
        ErrorKind::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_refusals_arrive_as_400_and_must_not_look_like_bad_input() {
        let e = ApiError::from_response(400, r#"{"error":"Scan limit reached. Please try again later."}"#);
        assert_eq!(e.kind, ErrorKind::Quota);
        assert_eq!(e.kind.exit_code(), EXIT_QUOTA);
        assert!(e.message.contains("Scan limit reached"));
    }

    #[test]
    fn maintenance_is_its_own_outcome() {
        let e = ApiError::from_response(400, r#"{"error":"Service temporarily unavailable for maintenance. Please try again later."}"#);
        assert_eq!(e.kind, ErrorKind::Maintenance);
        assert_eq!(e.kind.exit_code(), EXIT_MAINTENANCE);
    }

    #[test]
    fn malformed_input_is_distinguished_from_a_missing_record() {
        assert_eq!(
            ApiError::from_response(400, r#"{"error":"Provided domain is invalid."}"#).kind,
            ErrorKind::Input
        );
        assert_eq!(
            ApiError::from_response(400, r#"{"error":"No scan found for the provided domain."}"#).kind,
            ErrorKind::NotFound
        );
    }

    #[test]
    fn transport_and_status_codes_map_to_auth_and_rate_limits() {
        assert_eq!(ApiError::from_response(401, r#"{"error":"Unauthorized"}"#).kind, ErrorKind::Auth);
        assert_eq!(ApiError::from_response(429, "{}").kind, ErrorKind::Quota);
        assert_eq!(ApiError::transport("connection refused").kind, ErrorKind::Other);
    }

    #[test]
    fn a_body_that_is_not_the_documented_shape_still_yields_something_readable() {
        assert_eq!(extract_message(500, ""), "HTTP 500");
        assert_eq!(extract_message(502, "upstream is down"), "upstream is down");
        assert_eq!(extract_message(400, r#"{"detail":"nope"}"#), "HTTP 400");
        assert_eq!(extract_message(400, r#"{"message":"try later"}"#), "try later");
    }

    #[test]
    fn every_kind_has_a_distinct_exit_code() {
        let codes: Vec<i32> = [
            ErrorKind::Auth,
            ErrorKind::Quota,
            ErrorKind::Input,
            ErrorKind::Maintenance,
            ErrorKind::NotFound,
            ErrorKind::Other,
        ]
        .iter()
        .map(|k| k.exit_code())
        .collect();
        let mut unique = codes.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(codes.len(), unique.len(), "exit codes collide: {codes:?}");
        assert!(codes.iter().all(|c| *c > 0));
    }
}
