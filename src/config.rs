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

    #[serde(default)]
    pub masquerade: Option<crate::server::masquerade::MasqueradeConfig>,

    #[serde(default)]
    pub anti_probe: Option<crate::server::antiprobe::AntiProbeConfig>,

    #[serde(default)]
    pub obfuscation: Option<crate::obfs::ObfuscationConfig>,

    #[serde(default = "default_udp_session_timeout")]
    pub udp_session_timeout_secs: u64,
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

fn default_udp_session_timeout() -> u64 {
    120
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_server_listen(),
            auth_key: String::new(),
            tls_cert: None,
            tls_key: None,
            auto_cert: default_auto_cert(),
            auto_cert_domain: default_auto_cert_domain(),
            masquerade: None,
            anti_probe: None,
            obfuscation: None,
            udp_session_timeout_secs: default_udp_session_timeout(),
        }
    }
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

    #[serde(default)]
    pub obfuscation: Option<crate::obfs::ObfuscationConfig>,

    #[serde(default)]
    pub tls_fingerprint: Option<crate::tls_fingerprint::TlsFingerprintConfig>,
}

fn default_socks5_listen() -> SocketAddr {
    "127.0.0.1:1080".parse().unwrap()
}

fn default_server_port() -> u16 {
    4433
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            socks5_listen: default_socks5_listen(),
            server_addr: "127.0.0.1".to_string(),
            server_port: default_server_port(),
            auth_key: String::new(),
            transport: TransportMode::Auto,
            server_name: None,
            insecure: false,
            cert_fingerprint: None,
            ca_cert: None,
            socks5_user: None,
            socks5_password: None,
            obfuscation: None,
            tls_fingerprint: None,
        }
    }
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
