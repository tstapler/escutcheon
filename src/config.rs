use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub hosts: HashMap<String, HostConfig>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Defaults {
    pub knock_ports: Option<Vec<u16>>,
    pub knock_proto: Option<String>,
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct HostConfig {
    pub knock_ports: Option<Vec<u16>>,
    pub knock_proto: Option<String>,
    pub ttl_secs: Option<u64>,
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)?;
        Ok(toml::from_str(&raw)?)
    }

    pub fn resolve_host(&self, alias: &str) -> Option<&HostConfig> {
        self.hosts.get(alias)
    }
}

fn config_path() -> anyhow::Result<PathBuf> {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("~/.config"));
    Ok(base.join("escutcheon").join("config.toml"))
}
