use reqwest::blocking::{Client, multipart, Response};
use std::path::Path;

pub struct MlabClient {
    client: Client,
    base_url: String,
    api_key: String,
}

impl MlabClient {
    pub fn new(hostname: &str, api_key: &str) -> Self {
        let base_url = format!("{}/api/v1", hostname.trim_end_matches('/'));
        Self {
            client: Client::new(),
            base_url,
            api_key: api_key.to_string(),
        }
    }

    fn auth_header(&self) -> String {
        format!("token {}", self.api_key)
    }

    pub fn get(&self, path: &str) -> Result<Response, reqwest::Error> {
        self.client
            .get(format!("{}{}", self.base_url, path))
            .header("Authorization", self.auth_header())
            .send()
    }

    pub fn post_json(&self, path: &str, body: &serde_json::Value) -> Result<Response, reqwest::Error> {
        self.client
            .post(format!("{}{}", self.base_url, path))
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json")
            .json(body)
            .send()
    }

    pub fn upload_file(&self, file_path: &Path) -> Result<Response, reqwest::Error> {
        let form = multipart::Form::new()
            .file("file", file_path)
            .expect("Failed to read file for upload");

        // File upload uses /upload/file (not under /api/v1)
        let url = format!(
            "{}/upload/file",
            self.base_url.replace("/api/v1", "")
        );

        self.client
            .post(url)
            .header("Authorization", self.auth_header())
            .multipart(form)
            .send()
    }
}
