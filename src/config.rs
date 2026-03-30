use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default)]
    pub api_key: String,
}

fn default_hostname() -> String {
    "https://mlab.sh".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hostname: default_hostname(),
            api_key: String::new(),
        }
    }
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
        let content = serde_yaml::to_string(self).expect("Failed to serialize config");
        fs::write(Self::path(), content).expect("Failed to write config file");
    }

    pub fn require_api_key(&self) -> &str {
        if self.api_key.is_empty() {
            eprintln!("No API key configured. Run `mlab login` first.");
            std::process::exit(1);
        }
        &self.api_key
    }
}
