use colored::Colorize;
use dialoguer::Input;

use crate::client::MlabClient;
use crate::commands::body;
use crate::config::Config;
use crate::error::{ApiError, ErrorKind};
use crate::ui;

pub fn run(hostname: &str, key: Option<&str>) {
    let api_key = match key {
        Some(k) => k.trim().to_string(),
        None => {
            println!("{}", "mlab.sh — Login".bold());
            println!();
            Input::<String>::new()
                .with_prompt("API Key")
                .interact_text()
                .expect("Failed to read input")
                .trim()
                .to_string()
        }
    };

    if api_key.is_empty() {
        ApiError {
            status: None,
            message: "API key cannot be empty.".to_string(),
            kind: ErrorKind::Input,
        }
        .report();
    }

    // Verify before writing: storing a key that does not work only moves the
    // failure to whatever the user runs next.
    let organization = verify(hostname, &api_key);

    let mut config = Config::load();
    config.hostname = hostname.to_string();
    config.api_key = api_key;
    config.save();

    println!(
        "{} Authenticated as {} — key saved to {}",
        "ok:".green().bold(),
        organization.cyan(),
        Config::path().display()
    );
}

fn verify(hostname: &str, api_key: &str) -> String {
    let client = MlabClient::new(hostname, api_key);
    let raw = match ui::with_spinner("Verifying the key", || body(client.get("/"))) {
        Ok(b) => b,
        Err(e) => e.report(),
    };

    let v: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
    let organization = v.get("organization").and_then(|o| o.as_str()).unwrap_or("");
    let is_api_key = v.get("auth").and_then(|a| a.as_str()) == Some("api_key");

    if organization.is_empty() && !is_api_key {
        ApiError {
            status: None,
            message: "that key was not accepted by the API — nothing was saved.".to_string(),
            kind: ErrorKind::Auth,
        }
        .report();
    }

    if organization.is_empty() {
        "your organization".to_string()
    } else {
        organization.to_string()
    }
}

pub fn logout() {
    let path = Config::path();
    if !path.exists() {
        println!("Not logged in — nothing to do.");
        return;
    }

    let mut config = Config::load();
    if config.api_key.is_empty() {
        println!("Not logged in — nothing to do.");
        return;
    }

    // The hostname is a preference, not a credential: keep it.
    config.api_key = String::new();
    config.save();

    println!(
        "{} API key removed from {}",
        "ok:".green().bold(),
        path.display()
    );
}
