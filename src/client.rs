use std::path::Path;
use std::thread;
use std::time::Duration;

use reqwest::blocking::{multipart, Client, Response};
use reqwest::StatusCode;

use crate::error::{ApiError, ErrorKind};

/// Attempts for a safe (GET) request, including the first one.
const MAX_ATTEMPTS: u32 = 3;
/// Longest `Retry-After` we will sit through rather than handing the user an error.
const MAX_RETRY_AFTER: u64 = 30;

pub struct MlabClient {
    client: Client,
    /// Site root, e.g. `https://mlab.sh`. A few endpoints (file upload) live
    /// here rather than under the versioned API prefix.
    root_url: String,
    base_url: String,
    api_key: String,
}

impl MlabClient {
    pub fn new(hostname: &str, api_key: &str) -> Self {
        let root_url = hostname.trim_end_matches('/').to_string();
        let base_url = format!("{}/api/v1", root_url);
        Self {
            client: build_http_client(),
            root_url,
            base_url,
            api_key: api_key.to_string(),
        }
    }

    fn auth_header(&self) -> String {
        format!("token {}", self.api_key)
    }

    /// GETs are safe to replay, so transport blips and 5xx are retried with a
    /// short backoff; a 429 is honoured when the server names a sane delay.
    pub fn get(&self, path: &str) -> Result<Response, ApiError> {
        let url = format!("{}{}", self.base_url, path);
        let mut attempt = 1;
        loop {
            let result = self
                .client
                .get(&url)
                .header("Authorization", self.auth_header())
                .send();

            match retry_decision(result, attempt) {
                Attempt::Done(r) => return r,
                Attempt::RetryAfter(delay) => {
                    thread::sleep(delay);
                    attempt += 1;
                }
            }
        }
    }

    /// Not retried: replaying a scan launch would spend the caller's quota twice.
    pub fn post_json(&self, path: &str, body: &serde_json::Value) -> Result<Response, ApiError> {
        self.client
            .post(format!("{}{}", self.base_url, path))
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .map_err(ApiError::transport)
    }

    /// Upload lives at the site root (`/upload/file`), NOT under `/api/v1` —
    /// the API router has no `upload` route, so the prefixed URL 404s.
    pub fn upload_file(&self, file_path: &Path) -> Result<Response, ApiError> {
        let form = multipart::Form::new()
            .file("file", file_path)
            .map_err(|e| {
                ApiError::new(None, format!("cannot read {}: {e}", file_path.display()))
            })?;

        self.client
            .post(format!("{}/upload/file", self.root_url))
            .header("Authorization", self.auth_header())
            .multipart(form)
            .send()
            .map_err(ApiError::transport)
    }
}

pub fn build_http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(concat!("mlab-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_else(|_| Client::new())
}

enum Attempt {
    Done(Result<Response, ApiError>),
    RetryAfter(Duration),
}

/// Shared by both hosts: decide whether a result is final or worth replaying.
fn retry_decision(result: Result<Response, reqwest::Error>, attempt: u32) -> Attempt {
    let last = attempt >= MAX_ATTEMPTS;
    match result {
        Ok(resp) => {
            let status = resp.status();
            if status == StatusCode::TOO_MANY_REQUESTS {
                // The server tells us how long to wait; obey it when the wait is
                // short enough to be worth it, and surface a quota error if not.
                if let Some(delay) = retry_after(&resp) {
                    if !last && delay.as_secs() <= MAX_RETRY_AFTER {
                        return Attempt::RetryAfter(delay);
                    }
                    return Attempt::Done(Err(ApiError {
                        status: Some(429),
                        message: format!(
                            "rate limited — retry in {}s (Retry-After)",
                            delay.as_secs()
                        ),
                        kind: ErrorKind::Quota,
                    }));
                }
            }
            if status.is_server_error() && !last {
                return Attempt::RetryAfter(backoff(attempt));
            }
            Attempt::Done(Ok(resp))
        }
        Err(e) if !last && is_retryable(&e) => Attempt::RetryAfter(backoff(attempt)),
        Err(e) => Attempt::Done(Err(ApiError::transport(e))),
    }
}

fn is_retryable(e: &reqwest::Error) -> bool {
    e.is_timeout() || e.is_connect() || e.is_request()
}

fn backoff(attempt: u32) -> Duration {
    Duration::from_millis(300 * 2u64.pow(attempt.saturating_sub(1)))
}

pub fn retry_after(resp: &Response) -> Option<Duration> {
    resp.headers()
        .get("retry-after")?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_with_each_attempt() {
        assert!(backoff(2) > backoff(1));
        assert!(backoff(3) > backoff(2));
    }

    #[test]
    fn the_api_prefix_is_appended_once_and_the_root_kept_separate() {
        let c = MlabClient::new("https://mlab.sh/", "k");
        assert_eq!(c.root_url, "https://mlab.sh");
        assert_eq!(c.base_url, "https://mlab.sh/api/v1");
    }
}
