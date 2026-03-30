use colored::Colorize;
use serde::Deserialize;

use crate::client::MlabClient;

#[derive(Deserialize)]
struct SslCert {
    #[serde(default)]
    common_name: String,
    #[serde(default)]
    issuer_name: String,
    #[serde(default)]
    not_before: String,
    #[serde(default)]
    not_after: String,
    #[serde(default)]
    name_value: String,
    #[serde(default)]
    serial_number: String,
}

pub fn run(client: &MlabClient, domain: &str, json: bool) {
    let resp = match client.get(&format!("/domain/ssl?domain={}", domain)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Request failed: {e}");
            std::process::exit(1);
        }
    };

    let status = resp.status();
    let body = resp.text().unwrap_or_default();

    if !status.is_success() {
        eprintln!("{} HTTP {status}", "error:".red().bold());
        eprintln!("{body}");
        std::process::exit(1);
    }

    if json {
        match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(_) => println!("{body}"),
        }
        return;
    }

    let certs: Vec<SslCert> = match serde_json::from_str(&body) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("{} Failed to parse SSL response.", "error:".red().bold());
            eprintln!("{body}");
            std::process::exit(1);
        }
    };

    if certs.is_empty() {
        println!("No SSL certificates found for {domain}.");
        return;
    }

    println!(
        "{} Found {} certificate(s) for {}",
        "🔒".to_string(),
        certs.len().to_string().bold(),
        domain.cyan()
    );
    println!();

    // Table header
    let divider = format!(
        "  {}", "─".repeat(100)
    );

    println!(
        "  {:<30} {:<14} {:<14} {:<40}",
        "Common Name".bold().underline(),
        "Valid From".bold().underline(),
        "Expires".bold().underline(),
        "Issuer".bold().underline(),
    );
    println!("{}", divider.dimmed());

    for cert in &certs {
        let not_before = cert.not_before.split('T').next().unwrap_or(&cert.not_before);
        let not_after = cert.not_after.split('T').next().unwrap_or(&cert.not_after);

        let expiry_colored = if is_expired(&cert.not_after) {
            not_after.red().to_string()
        } else if is_expiring_soon(&cert.not_after) {
            not_after.yellow().to_string()
        } else {
            not_after.green().to_string()
        };

        // Shorten issuer for display
        let issuer_short = shorten_issuer(&cert.issuer_name);

        println!(
            "  {:<30} {:<14} {:<25} {}",
            cert.common_name,
            not_before,
            expiry_colored,
            issuer_short.dimmed(),
        );

        // Show SANs if different from common_name
        let sans: Vec<&str> = cert
            .name_value
            .split('\n')
            .filter(|s| !s.is_empty() && *s != cert.common_name)
            .collect();
        if !sans.is_empty() {
            println!(
                "  {} {}",
                "  SANs:".dimmed(),
                sans.join(", ").dimmed(),
            );
        }
    }

    println!("{}", divider.dimmed());
    println!();
    println!(
        "  {} = valid   {} = expiring soon   {} = expired",
        "●".green(),
        "●".yellow(),
        "●".red(),
    );
}

fn shorten_issuer(issuer: &str) -> String {
    // Extract CN= value if present
    for part in issuer.split(", ") {
        if let Some(cn) = part.strip_prefix("CN=") {
            return cn.to_string();
        }
    }
    // Fallback: extract O= value
    for part in issuer.split(", ") {
        if let Some(org) = part.strip_prefix("O=") {
            return org.to_string();
        }
    }
    issuer.chars().take(40).collect()
}

fn is_expired(not_after: &str) -> bool {
    not_after < "2026-03-30"
}

fn is_expiring_soon(not_after: &str) -> bool {
    not_after < "2026-04-30"
}
