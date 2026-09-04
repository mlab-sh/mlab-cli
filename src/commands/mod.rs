pub mod login;
pub mod whoami;
pub mod scan;
pub mod status;
pub mod results;
pub mod ssl;
pub mod limits;
pub mod lookup;
pub mod cve;
pub mod vuln;
pub mod actor;

use reqwest::blocking::Response;
use serde::de::DeserializeOwned;

use crate::error::ApiError;

/// Read a response body, or fail with a classified error. Every command funnels
/// through here so `{"error": "..."}` is rendered the same way everywhere.
pub fn body(result: Result<Response, ApiError>) -> Result<String, ApiError> {
    let resp = result?;
    let status = resp.status();
    let text = resp.text().unwrap_or_default();
    if status.is_success() {
        Ok(text)
    } else {
        Err(ApiError::from_response(status.as_u16(), &text))
    }
}

/// `body`, but a failure ends the process with the matching exit code.
pub fn fetch(result: Result<Response, ApiError>) -> String {
    match body(result) {
        Ok(b) => b,
        Err(e) => e.report(),
    }
}

pub fn print_json(body: &str) {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Err(_) => println!("{body}"),
    }
}

pub fn parse_or_exit<T: DeserializeOwned>(body: &str, what: &str) -> T {
    match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => ApiError::new(None, format!("unreadable {what} response: {e}")).report(),
    }
}

/// `body`, plus the quirk of the CVE host: it reports failures inside a 200 by
/// putting an `error` key in the payload, so the status code alone would let
/// them through as success.
pub fn vuln_body(result: Result<Response, ApiError>) -> String {
    let raw = fetch(result);
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
        if let Some(message) = v.get("error").and_then(|e| e.as_str()) {
            ApiError::new(None, message).report();
        }
    }
    raw
}
