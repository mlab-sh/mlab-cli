use colored::Colorize;
use dialoguer::Input;

use crate::config::Config;

pub fn run() {
    println!("{}", "mlab.sh — Login".bold());
    println!();

    let api_key: String = Input::new()
        .with_prompt("API Key")
        .interact_text()
        .expect("Failed to read input");

    if api_key.is_empty() {
        eprintln!("{} API key cannot be empty.", "error:".red().bold());
        std::process::exit(1);
    }

    let mut config = Config::load();
    config.api_key = api_key;
    config.save();

    println!(
        "{} API key saved to {}",
        "ok:".green().bold(),
        Config::path().display()
    );
}
