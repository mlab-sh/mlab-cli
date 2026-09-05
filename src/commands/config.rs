//! `mlab config` — read and edit `~/.mlab/conf.yml` without an editor.
//!
//! Credentials are masked by default. A config dump is the kind of thing people
//! paste into issues and CI logs, and a key that leaks that way is a key that
//! has to be rotated.

use colored::Colorize;

use crate::config::{Config, Profile};
use crate::error::{ApiError, ErrorKind};

const KEYS: &[&str] = &[
    "hostname",
    "cve_hostname",
    "actors_hostname",
    "api_key",
    "vuln_token",
];
const SECRETS: &[&str] = &["api_key", "vuln_token"];

pub fn path() {
    println!("{}", Config::path().display());
}

pub fn list(profile: Option<&str>, reveal: bool) {
    let config = Config::load_with_profile(profile);

    println!();
    println!("  ⚙ {}", Config::path().display().to_string().dimmed());
    if let Some(name) = profile {
        println!("  {:<18} {}", "Profile:".dimmed(), name.cyan());
    }
    println!();
    for key in KEYS {
        println!(
            "  {:<18} {}",
            format!("{key}:").dimmed(),
            display_value(&config, key, reveal)
        );
    }

    if !config.profiles.is_empty() {
        println!();
        println!("  {}", "Profiles".bold().underline());
        for (name, p) in &config.profiles {
            let overrides: Vec<&str> = KEYS
                .iter()
                .copied()
                .filter(|k| !profile_field(p, k).is_empty())
                .collect();
            println!("    {:<16} {}", name.cyan(), overrides.join(", ").dimmed());
        }
    }
    println!();
}

pub fn get(key: &str, profile: Option<&str>, reveal: bool) {
    check_key(key);
    let config = Config::load_with_profile(profile);
    println!("{}", display_value(&config, key, reveal));
}

pub fn set(key: &str, value: &str, profile: Option<&str>) {
    check_key(key);

    let mut config = Config::load();
    match profile {
        Some(name) => {
            let entry = config.profiles.entry(name.to_string()).or_default();
            set_profile_field(entry, key, value);
        }
        None => set_field(&mut config, key, value),
    }
    config.save();

    let shown = if SECRETS.contains(&key) {
        mask(value)
    } else {
        value.to_string()
    };
    println!(
        "{} {} = {}{}",
        "ok:".green().bold(),
        key,
        shown,
        profile
            .map(|p| format!("  (profile {p})"))
            .unwrap_or_default()
            .dimmed()
    );
}

fn check_key(key: &str) {
    if !KEYS.contains(&key) {
        ApiError {
            status: None,
            message: format!("unknown key '{key}' — known keys: {}", KEYS.join(", ")),
            kind: ErrorKind::Input,
        }
        .report();
    }
}

fn field<'a>(config: &'a Config, key: &str) -> &'a str {
    match key {
        "hostname" => &config.hostname,
        "cve_hostname" => &config.cve_hostname,
        "actors_hostname" => &config.actors_hostname,
        "api_key" => &config.api_key,
        "vuln_token" => &config.vuln_token,
        _ => "",
    }
}

fn set_field(config: &mut Config, key: &str, value: &str) {
    let target = match key {
        "hostname" => &mut config.hostname,
        "cve_hostname" => &mut config.cve_hostname,
        "actors_hostname" => &mut config.actors_hostname,
        "api_key" => &mut config.api_key,
        "vuln_token" => &mut config.vuln_token,
        _ => return,
    };
    *target = value.to_string();
}

fn profile_field<'a>(profile: &'a Profile, key: &str) -> &'a str {
    match key {
        "hostname" => &profile.hostname,
        "cve_hostname" => &profile.cve_hostname,
        "actors_hostname" => &profile.actors_hostname,
        "api_key" => &profile.api_key,
        "vuln_token" => &profile.vuln_token,
        _ => "",
    }
}

fn set_profile_field(profile: &mut Profile, key: &str, value: &str) {
    let target = match key {
        "hostname" => &mut profile.hostname,
        "cve_hostname" => &mut profile.cve_hostname,
        "actors_hostname" => &mut profile.actors_hostname,
        "api_key" => &mut profile.api_key,
        "vuln_token" => &mut profile.vuln_token,
        _ => return,
    };
    *target = value.to_string();
}

fn display_value(config: &Config, key: &str, reveal: bool) -> String {
    let value = field(config, key);
    if value.is_empty() {
        return "—".dimmed().to_string();
    }
    if SECRETS.contains(&key) && !reveal {
        return mask(value);
    }
    value.to_string()
}

/// Enough to recognise which credential this is, not enough to use it.
pub fn mask(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 8 {
        return "•".repeat(chars.len().max(1));
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars
        .iter()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masking_keeps_enough_to_recognise_and_too_little_to_use() {
        let masked = mask("mlab_abcdefghijklmnop");
        assert_eq!(masked, "mlab…mnop");
        assert!(!masked.contains("abcdefghij"));
    }

    #[test]
    fn a_short_secret_is_hidden_entirely() {
        assert_eq!(mask("short"), "•••••");
        assert_eq!(mask(""), "•");
    }

    #[test]
    fn secrets_are_masked_unless_explicitly_revealed() {
        let config = Config {
            api_key: "mlab_abcdefghijklmnop".to_string(),
            ..Default::default()
        };

        assert_eq!(display_value(&config, "api_key", false), "mlab…mnop");
        assert_eq!(
            display_value(&config, "api_key", true),
            "mlab_abcdefghijklmnop"
        );
    }

    #[test]
    fn a_hostname_is_never_masked() {
        let config = Config::default();
        assert_eq!(display_value(&config, "hostname", false), "https://mlab.sh");
    }

    #[test]
    fn every_known_key_reads_and_writes_the_same_field() {
        for key in KEYS {
            let mut config = Config::default();
            set_field(&mut config, key, "value");
            assert_eq!(field(&config, key), "value", "for {key}");

            let mut profile = Profile::default();
            set_profile_field(&mut profile, key, "value");
            assert_eq!(profile_field(&profile, key), "value", "for {key}");
        }
    }
}
