use colored::Colorize;

use crate::client::MlabClient;
use crate::commands::{fetch, parse_or_exit, print_json};
use crate::error::{ApiError, ErrorKind};
use crate::ui;

pub fn run(client: &MlabClient, json: bool) {
    let body = ui::with_spinner("Checking credentials", || fetch(client.get("/")));

    if json {
        print_json(&body);
        return;
    }

    let v: serde_json::Value = parse_or_exit(&body, "identity");
    let organization = v.get("organization").and_then(|o| o.as_str()).unwrap_or("");

    // The API answers 200 with a generic greeting when the key is unknown, so
    // the status code alone cannot tell an authenticated call from a rejected
    // one. An organization (or the explicit api_key marker) is the real signal.
    let authenticated = !organization.is_empty()
        || v.get("auth").and_then(|a| a.as_str()) == Some("api_key");

    if !authenticated {
        ApiError {
            status: None,
            message: "API key not recognized.".to_string(),
            kind: ErrorKind::Auth,
        }
        .report();
    }

    println!();
    println!("  {} {}", "✔".green().bold(), "Authenticated".bold());
    println!("  {:<14} {}", "Organization:".dimmed(), organization.cyan());
    if let Some(plan) = v.get("plan").and_then(|p| p.as_str()) {
        println!("  {:<14} {}", "Plan:".dimmed(), plan);
    }
    println!();
}
