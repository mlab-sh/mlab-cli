use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ErrorKind};

pub const API_KEY_ENV: &str = "MLAB_API_KEY";
pub const HOSTNAME_ENV: &str = "MLAB_HOSTNAME";
pub const CVE_HOSTNAME_ENV: &str = "MLAB_CVE_HOSTNAME";

pub const DEFAULT_HOSTNAME: &str = "https://mlab.sh";
pub const DEFAULT_CVE_HOSTNAME: &str = "https://vuln.mlab.sh";

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default = "default_cve_hostname")]
    pub cve_hostname: String,
    #[serde(default)]
    pub api_key: String,
}

fn default_hostname() -> String {
    DEFAULT_HOSTNAME.to_string()
}

fn default_cve_hostname() -> String {
    DEFAULT_CVE_HOSTNAME.to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hostname: default_hostname(),
            cve_hostname: default_cve_hostname(),
            api_key: String::new(),
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
            api_key: "k".to_string(),
        };
        let back: Config = serde_yaml::from_str(&serde_yaml::to_string(&c).unwrap()).unwrap();
        assert_eq!(back.hostname, c.hostname);
        assert_eq!(back.cve_hostname, c.cve_hostname);
        assert_eq!(back.api_key, c.api_key);
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
