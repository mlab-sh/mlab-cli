pub mod login;
pub mod whoami;
pub mod scan;
pub mod status;
pub mod results;
pub mod ssl;
pub mod limits;
pub mod cve;

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
