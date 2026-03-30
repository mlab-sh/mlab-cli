pub mod login;
pub mod whoami;
pub mod scan;
pub mod status;
pub mod results;
pub mod ssl;
pub mod limits;

use colored::Colorize;
use reqwest::blocking::Response;

pub fn print_response(resp: Response) {
    let status = resp.status();
    let body = resp.text().unwrap_or_default();

    if !status.is_success() {
        eprintln!("{} HTTP {status}", "error:".red().bold());
    }

    match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(json) => {
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        Err(_) => {
            println!("{body}");
        }
    }

    if !status.is_success() {
        std::process::exit(1);
    }
}
