use colored::Colorize;

use crate::client::MlabClient;
use crate::commands::{fetch, parse_or_exit, print_json};
use crate::ui;
use crate::util::urlencode;

pub fn domain(client: &MlabClient, domain: &str, json: bool) {
    let body = ui::with_spinner(&format!("Checking {domain}"), || {
        fetch(client.get(&format!(
            "/scan/domain/status?domain={}",
            urlencode(domain)
        )))
    });

    if json {
        print_json(&body);
        return;
    }

    let v: serde_json::Value = parse_or_exit(&body, "status");
    let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("unknown");
    let message = v.get("message").and_then(|m| m.as_str()).unwrap_or("");

    println!();
    println!("  {} {}  {}", "🌐", domain.cyan().bold(), badge(status));
    if !message.is_empty() {
        println!("  {}", message.dimmed());
    }
    if status == "success" {
        println!(
            "  {}",
            format!("Fetch it with: mlab results domain {domain}").dimmed()
        );
    }
    println!();
}

fn badge(status: &str) -> colored::ColoredString {
    match status {
        "success" => "✔ done".green().bold(),
        "scanning" => "⏳ scanning".cyan().bold(),
        "pending" => "⏳ queued".yellow().bold(),
        "failed" | "fail" | "error" => "✖ failed".red().bold(),
        other => other.normal(),
    }
}
