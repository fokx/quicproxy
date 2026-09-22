use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_server_listen")]
    pub listen: SocketAddr,

    pub auth_key: String,

    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,

    #[serde(default = "default_auto_cert")]
    pub auto_cert: bool,

    #[serde(default = "default_auto_cert_domain")]
    pub auto_cert_domain: String,
}

fn default_server_listen() -> SocketAddr {
    "0.0.0.0:4433".parse().unwrap()
}

fn default_auto_cert() -> bool {
    true
}

fn default_auto_cert_domain() -> String {
    "localhost".to_string()
}

impl ServerConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read server config from {}", path.as_ref().display()))?;
        let config: ServerConfig = toml::from_str(&content)
            .with_context(|| "Failed to parse server config TOML")?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TransportMode {
    #[default]
    Auto,
    Quic,
    Tcp,
}

impl std::str::FromStr for TransportMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(TransportMode::Auto),
            "quic" => Ok(TransportMode::Quic),
            "tcp" => Ok(TransportMode::Tcp),
            other => anyhow::bail!(
                "Unknown transport mode '{}', expected 'auto', 'quic', or 'tcp'",
                other
            ),
        }
    }
}

impl std::fmt::Display for TransportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportMode::Auto => write!(f, "auto"),
            TransportMode::Quic => write!(f, "quic"),
            TransportMode::Tcp => write!(f, "tcp"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    #[serde(default = "default_socks5_listen")]
    pub socks5_listen: SocketAddr,

    pub server_addr: String,

    #[serde(default = "default_server_port")]
    pub server_port: u16,

    pub auth_key: String,

    #[serde(default)]
    pub transport: TransportMode,

    pub server_name: Option<String>,

    #[serde(default)]
    pub insecure: bool,

    pub cert_fingerprint: Option<String>,

    pub ca_cert: Option<PathBuf>,

    pub socks5_user: Option<String>,
    pub socks5_password: Option<String>,
}

fn default_socks5_listen() -> SocketAddr {
    "127.0.0.1:1080".parse().unwrap()
}

fn default_server_port() -> u16 {
    4433
}

impl ClientConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read client config from {}", path.as_ref().display()))?;
        let config: ClientConfig = toml::from_str(&content)
            .with_context(|| "Failed to parse client config TOML")?;
        Ok(config)
    }
}
