use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Default)]
pub struct MorphConfig {
    pub server: Option<ServerConfig>,
    pub client: Option<ClientConfig>,
    pub profile: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub bind: String,
    pub private_key: PathBuf,
    pub acl: PathBuf,
    #[serde(default = "default_tun")]
    pub tun: String,
    #[serde(default = "default_tun_ip_server")]
    pub tun_ip: String,
    pub psk: Option<PskConfig>,
    pub cookie: Option<CookieConfig>,
    #[serde(default)]
    pub no_auto_net: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClientConfig {
    pub server: String,
    pub private_key: PathBuf,
    pub server_public_key: String,
    #[serde(default = "default_tun")]
    pub tun: String,
    #[serde(default = "default_tun_ip_client")]
    pub tun_ip: String,
    #[serde(default = "default_gateway")]
    pub gateway: String,
    pub psk: Option<PskConfig>,
    #[serde(default)]
    pub no_auto_net: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PskConfig {
    pub file: Option<PathBuf>,
    pub env: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CookieConfig {
    pub master_key: Option<String>,
    #[serde(default = "default_rotation_secs")]
    pub rotation_secs: u64,
}

fn default_tun() -> String { "tun0".into() }
fn default_tun_ip_server() -> String { "10.8.0.1".into() }
fn default_tun_ip_client() -> String { "10.8.0.2".into() }
fn default_gateway() -> String { "10.8.0.1".into() }
fn default_rotation_secs() -> u64 { 60 }

impl MorphConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config '{}'", path.display()))?;
        let config: Self = toml::from_str(&raw)
            .with_context(|| format!("failed to parse config '{}'", path.display()))?;
        Ok(config)
    }
}
