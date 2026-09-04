use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ErrorKind};

pub const API_KEY_ENV: &str = "MLAB_API_KEY";
pub const HOSTNAME_ENV: &str = "MLAB_HOSTNAME";
pub const CVE_HOSTNAME_ENV: &str = "MLAB_CVE_HOSTNAME";
pub const VULN_TOKEN_ENV: &str = "MLAB_VULN_TOKEN";
pub const ACTORS_HOSTNAME_ENV: &str = "MLAB_ACTORS_HOSTNAME";
pub const PROFILE_ENV: &str = "MLAB_PROFILE";

pub const DEFAULT_HOSTNAME: &str = "https://mlab.sh";
pub const DEFAULT_CVE_HOSTNAME: &str = "https://vuln.mlab.sh";
pub const DEFAULT_ACTORS_HOSTNAME: &str = "https://actors.mlab.sh";

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default = "default_cve_hostname")]
    pub cve_hostname: String,
    #[serde(default = "default_actors_hostname")]
    pub actors_hostname: String,
    #[serde(default)]
    pub api_key: String,
    /// Personal CI token for vuln.mlab.sh. A separate credential from `api_key`:
    /// different service, different issuer, and it only lifts the scan quota.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vuln_token: String,
    /// Named overlays, for people who work across several organisations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, Profile>,
}

/// A profile overrides only the fields it sets; everything else falls through
/// to the top level.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cve_hostname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub actors_hostname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub api_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vuln_token: String,
}

fn default_hostname() -> String {
    DEFAULT_HOSTNAME.to_string()
}

fn default_cve_hostname() -> String {
    DEFAULT_CVE_HOSTNAME.to_string()
}

fn default_actors_hostname() -> String {
    DEFAULT_ACTORS_HOSTNAME.to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hostname: default_hostname(),
            cve_hostname: default_cve_hostname(),
            actors_hostname: default_actors_hostname(),
            api_key: String::new(),
            vuln_token: String::new(),
            profiles: BTreeMap::new(),
        }
    }
}

/// Precedence, highest first: an explicit flag, the environment, the config
/// file. CI passes an environment variable; a human edits the file; a one-off
/// override wins over both.
fn resolve(flag: Option<&str>, env: Option<String>, file: &str, fallback: &str) -> String {
    let candidates = [
        flag.map(str::to_string),
        env.filter(|v| !v.trim().is_empty()),
        Some(file.to_string()).filter(|v| !v.trim().is_empty()),
    ];
    candidates
        .into_iter()
        .flatten()
        .next()
        .unwrap_or_else(|| fallback.to_string())
}

impl Config {
    pub fn dir() -> PathBuf {
        dirs::home_dir()
            .expect("Cannot determine home directory")
            .join(".mlab")
    }

    pub fn path() -> PathBuf {
        Self::dir().join("conf.yml")
    }

    pub fn load() -> Self {
        let path = Self::path();
        if path.exists() {
            let content = fs::read_to_string(&path).expect("Failed to read config file");
            serde_yaml::from_str(&content).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    /// Load the file, then overlay the selected profile.
    ///
    /// A named profile that does not exist is an error, never a silent
    /// fall-through: quietly using the default credentials for `--profile prod`
    /// is how you scan the wrong organisation.
    pub fn load_with_profile(flag: Option<&str>) -> Self {
        let mut config = Self::load();
        let name = flag
            .map(str::to_string)
            .or_else(|| std::env::var(PROFILE_ENV).ok())
            .filter(|n| !n.trim().is_empty());

        let Some(name) = name else { return config };

        let Some(profile) = config.profiles.get(name.trim()).cloned() else {
            let known: Vec<&str> = config.profiles.keys().map(String::as_str).collect();
            ApiError {
                status: None,
                message: format!(
                    "no profile named '{}' in {}{}",
                    name.trim(),
                    Self::path().display(),
                    if known.is_empty() {
                        String::new()
                    } else {
                        format!(" (known: {})", known.join(", "))
                    }
                ),
                kind: ErrorKind::Input,
            }
            .report();
        };

        overlay(&mut config.hostname, &profile.hostname);
        overlay(&mut config.cve_hostname, &profile.cve_hostname);
        overlay(&mut config.actors_hostname, &profile.actors_hostname);
        overlay(&mut config.api_key, &profile.api_key);
        overlay(&mut config.vuln_token, &profile.vuln_token);
        config
    }

    pub fn save(&self) {
        let dir = Self::dir();
        fs::create_dir_all(&dir).expect("Failed to create ~/.mlab directory");
        let path = Self::path();
        let content = serde_yaml::to_string(self).expect("Failed to serialize config");
        fs::write(&path, content).expect("Failed to write config file");
        restrict_permissions(&path);
    }

    pub fn resolved_hostname(&self, flag: Option<&str>) -> String {
        resolve(flag, std::env::var(HOSTNAME_ENV).ok(), &self.hostname, DEFAULT_HOSTNAME)
    }

    pub fn resolved_cve_hostname(&self, flag: Option<&str>) -> String {
        resolve(
            flag,
            std::env::var(CVE_HOSTNAME_ENV).ok(),
            &self.cve_hostname,
            DEFAULT_CVE_HOSTNAME,
        )
    }

    /// Optional: most of vuln.mlab.sh answers unauthenticated, the token only
    /// raises the scan rate limit. Missing is not an error.
    pub fn resolved_actors_hostname(&self, flag: Option<&str>) -> String {
        resolve(
            flag,
            std::env::var(ACTORS_HOSTNAME_ENV).ok(),
            &self.actors_hostname,
            DEFAULT_ACTORS_HOSTNAME,
        )
    }

    pub fn resolved_vuln_token(&self, flag: Option<&str>) -> Option<String> {
        let token = resolve(flag, std::env::var(VULN_TOKEN_ENV).ok(), &self.vuln_token, "");
        Some(token).filter(|t| !t.is_empty())
    }

    pub fn resolved_api_key(&self, flag: Option<&str>) -> String {
        let key = resolve(flag, std::env::var(API_KEY_ENV).ok(), &self.api_key, "");
        if key.is_empty() {
            ApiError {
                status: None,
                message: format!(
                    "no API key configured — run `mlab login`, pass --api-key, or set {API_KEY_ENV}."
                ),
                kind: ErrorKind::Auth,
            }
            .report();
        }
        key
    }
}

fn overlay(target: &mut String, value: &str) {
    if !value.trim().is_empty() {
        *target = value.to_string();
    }
}

/// The file holds a credential, so it is not world-readable. Best-effort: a
/// filesystem that cannot express the mode is not a reason to refuse to save.
#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_file_is_conf_yml_under_a_dot_mlab_directory() {
        let path = Config::path();
        assert_eq!(path.file_name().unwrap(), "conf.yml");
        assert_eq!(path.parent().unwrap().file_name().unwrap(), ".mlab");
    }

    #[test]
    fn a_config_without_a_hostname_falls_back_to_production() {
        let c: Config = serde_yaml::from_str("api_key: mlab_abc").expect("parses");
        assert_eq!(c.hostname, DEFAULT_HOSTNAME);
        assert_eq!(c.cve_hostname, DEFAULT_CVE_HOSTNAME);
        assert_eq!(c.actors_hostname, DEFAULT_ACTORS_HOSTNAME);
        assert_eq!(c.api_key, "mlab_abc");
    }

    #[test]
    fn a_config_without_an_api_key_parses_with_an_empty_one() {
        let c: Config = serde_yaml::from_str("hostname: http://localhost:8080").expect("parses");
        assert_eq!(c.hostname, "http://localhost:8080");
        assert!(c.api_key.is_empty());
    }

    #[test]
    fn config_survives_a_serialize_parse_round_trip() {
        let c = Config {
            hostname: "https://staging.mlab.sh".to_string(),
            cve_hostname: "https://staging-vuln.mlab.sh".to_string(),
            actors_hostname: "https://staging-actors.mlab.sh".to_string(),
            api_key: "k".to_string(),
            vuln_token: "t".to_string(),
            profiles: BTreeMap::new(),
        };
        let back: Config = serde_yaml::from_str(&serde_yaml::to_string(&c).unwrap()).unwrap();
        assert_eq!(back.hostname, c.hostname);
        assert_eq!(back.cve_hostname, c.cve_hostname);
        assert_eq!(back.api_key, c.api_key);
        assert_eq!(back.vuln_token, c.vuln_token);
    }

    #[test]
    fn a_profile_overrides_only_the_fields_it_sets() {
        let raw = "hostname: https://mlab.sh\napi_key: base\nprofiles:\n  work:\n    api_key: work-key\n";
        let mut config: Config = serde_yaml::from_str(raw).expect("parses");
        let profile = config.profiles.get("work").cloned().expect("profile exists");

        overlay(&mut config.api_key, &profile.api_key);
        overlay(&mut config.hostname, &profile.hostname);

        assert_eq!(config.api_key, "work-key");
        // Untouched by the profile, so the base value survives.
        assert_eq!(config.hostname, "https://mlab.sh");
    }

    #[test]
    fn a_config_without_profiles_still_parses() {
        let c: Config = serde_yaml::from_str("api_key: k").expect("parses");
        assert!(c.profiles.is_empty());
    }

    #[test]
    fn an_empty_profile_field_does_not_erase_the_base_value() {
        let mut value = "keep".to_string();
        overlay(&mut value, "");
        assert_eq!(value, "keep");
        overlay(&mut value, "   ");
        assert_eq!(value, "keep");
        overlay(&mut value, "new");
        assert_eq!(value, "new");
    }

    #[test]
    fn a_missing_vuln_token_is_not_an_error() {
        let c = Config::default();
        assert_eq!(c.resolved_vuln_token(None), None);
        assert_eq!(c.resolved_vuln_token(Some("t")), Some("t".to_string()));
    }

    #[test]
    fn a_flag_beats_the_environment_which_beats_the_file() {
        assert_eq!(resolve(Some("flag"), Some("env".into()), "file", "def"), "flag");
        assert_eq!(resolve(None, Some("env".into()), "file", "def"), "env");
        assert_eq!(resolve(None, None, "file", "def"), "file");
        assert_eq!(resolve(None, None, "", "def"), "def");
    }

    #[test]
    fn a_blank_environment_variable_does_not_shadow_the_file() {
        assert_eq!(resolve(None, Some("   ".into()), "file", "def"), "file");
        assert_eq!(resolve(None, Some(String::new()), "file", "def"), "file");
    }
}
