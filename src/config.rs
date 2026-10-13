use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_server_listen")]
    pub listen: SocketAddr,

    #[serde(default)]
    pub realm_listen: Option<String>,

    pub auth_key: String,

    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,

    #[serde(default = "default_auto_cert")]
    pub auto_cert: bool,

    #[serde(default = "default_auto_cert_domain")]
    pub auto_cert_domain: String,

    #[serde(default)]
    pub auto_cert_dir: Option<PathBuf>,

    #[serde(default)]
    pub masquerade: Option<crate::server::masquerade::MasqueradeConfig>,

    #[serde(default)]
    pub anti_probe: Option<crate::server::antiprobe::AntiProbeConfig>,

    #[serde(default)]
    pub obfuscation: Option<crate::obfs::ObfuscationConfig>,

    #[serde(default = "default_udp_session_timeout")]
    pub udp_session_timeout_secs: u64,

    #[serde(default)]
    pub acl: Option<AclConfig>,

    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,

    #[serde(default)]
    pub realm: Option<crate::realm::RealmConfig>,
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
            realm_listen: None,
            auth_key: String::new(),
            tls_cert: None,
            tls_key: None,
            auto_cert: default_auto_cert(),
            auto_cert_domain: default_auto_cert_domain(),
            auto_cert_dir: None,
            masquerade: None,
            anti_probe: None,
            obfuscation: None,
            udp_session_timeout_secs: default_udp_session_timeout(),
            acl: None,
            outbounds: Vec::new(),
            realm: None,
        }
    }
}

impl ServerConfig {
    pub fn is_realm(&self) -> bool {
        self.realm_listen.is_some()
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref()).with_context(|| {
            format!(
                "Failed to read server config from {}",
                path.as_ref().display()
            )
        })?;

        let mut table: toml::Table =
            toml::from_str(&content).with_context(|| "Failed to parse server config TOML")?;

        let mut realm_from_listen = None;
        if let Some(listen_val) = table.get("listen") {
            if let Some(s) = listen_val.as_str() {
                if crate::realm::is_realm_addr(s) {
                    realm_from_listen = Some(s.to_string());
                    table.insert(
                        "listen".to_string(),
                        toml::Value::String("0.0.0.0:4433".to_string()),
                    );
                }
            }
        }

        let mut config: ServerConfig = table
            .try_into()
            .with_context(|| "Failed to deserialize server config")?;

        if let Some(r) = realm_from_listen {
            config.realm_listen = Some(r);
        }

        if let Some(ref acl) = config.acl {
            acl.validate()?;
        }
        if let Some(ref realm_uri) = config.realm_listen {
            crate::realm::parse_realm_addr(realm_uri)
                .with_context(|| "Invalid realm URI in server config")?;
        }
        Ok(config)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InlineRules(pub Vec<String>);

impl<'de> Deserialize<'de> for InlineRules {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrVec {
            Single(String),
            Multiple(Vec<String>),
        }
        match StringOrVec::deserialize(deserializer)? {
            StringOrVec::Single(s) => {
                let lines: Vec<String> = s.lines().map(|l| l.to_string()).collect();
                Ok(InlineRules(lines))
            }
            StringOrVec::Multiple(v) => Ok(InlineRules(v)),
        }
    }
}

impl InlineRules {
    pub fn to_rules_string(&self) -> String {
        self.0.join("\n")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AclConfig {
    #[serde(default)]
    pub file: Option<PathBuf>,

    #[serde(default)]
    pub inline: Option<InlineRules>,

    #[serde(default)]
    pub geoip: Option<PathBuf>,

    #[serde(default)]
    pub geosite: Option<PathBuf>,

    #[serde(default)]
    pub geo_update_interval: Option<String>,
}

impl AclConfig {
    pub fn validate(&self) -> Result<()> {
        if self.file.is_some() && self.inline.is_some() {
            anyhow::bail!("cannot set both acl.file and acl.inline");
        }
        Ok(())
    }

    pub fn load_rules_string(&self) -> Result<String> {
        self.validate()?;
        if let Some(ref path) = self.file {
            let s = fs::read_to_string(path)
                .with_context(|| format!("Failed to read ACL rules from {}", path.display()))?;
            Ok(s)
        } else if let Some(ref inline) = self.inline {
            Ok(inline.to_rules_string())
        } else {
            Ok(String::new())
        }
    }

    pub fn parse_geo_update_interval(&self) -> Option<std::time::Duration> {
        self.geo_update_interval.as_deref().and_then(parse_duration)
    }
}

pub fn parse_duration(s: &str) -> Option<std::time::Duration> {
    let s = s.trim().to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_suffix('h') {
        let hours: u64 = rest.trim().parse().ok()?;
        return Some(std::time::Duration::from_secs(hours * 3600));
    }
    if let Some(rest) = s.strip_suffix('d') {
        let days: u64 = rest.trim().parse().ok()?;
        return Some(std::time::Duration::from_secs(days * 86400));
    }
    if let Some(rest) = s.strip_suffix('m') {
        let mins: u64 = rest.trim().parse().ok()?;
        return Some(std::time::Duration::from_secs(mins * 60));
    }
    if let Some(rest) = s.strip_suffix('s') {
        let secs: u64 = rest.trim().parse().ok()?;
        return Some(std::time::Duration::from_secs(secs));
    }
    let secs: u64 = s.parse().ok()?;
    Some(std::time::Duration::from_secs(secs))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundType {
    Direct,
    Reject,
    Socks5,
    Http,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DirectOutboundConfig {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub bind_ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    pub bind_ipv6: Option<Ipv6Addr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5OutboundConfig {
    pub addr: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpOutboundConfig {
    pub url: String,
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub outbound_type: OutboundType,
    #[serde(default)]
    pub direct: Option<DirectOutboundConfig>,
    #[serde(default)]
    pub socks5: Option<Socks5OutboundConfig>,
    #[serde(default)]
    pub http: Option<HttpOutboundConfig>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrafficMode {
    #[default]
    Aggregation,
    Resilient,
}

impl std::str::FromStr for TrafficMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aggregation" => Ok(TrafficMode::Aggregation),
            "resilient" => Ok(TrafficMode::Resilient),
            other => anyhow::bail!(
                "Unknown traffic mode '{}', expected 'aggregation' or 'resilient'",
                other
            ),
        }
    }
}

impl std::fmt::Display for TrafficMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrafficMode::Aggregation => write!(f, "aggregation"),
            TrafficMode::Resilient => write!(f, "resilient"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AggregationStrategy {
    #[default]
    RoundRobin,
    Random,
}

impl std::str::FromStr for AggregationStrategy {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "round_robin" | "roundrobin" => Ok(AggregationStrategy::RoundRobin),
            "random" => Ok(AggregationStrategy::Random),
            other => anyhow::bail!(
                "Unknown aggregation strategy '{}', expected 'round_robin' or 'random'",
                other
            ),
        }
    }
}

impl std::fmt::Display for AggregationStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AggregationStrategy::RoundRobin => write!(f, "round_robin"),
            AggregationStrategy::Random => write!(f, "random"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiServerRoutingConfig {
    #[serde(default)]
    pub mode: TrafficMode,

    #[serde(default)]
    pub strategy: AggregationStrategy,

    /// Optional designated outbound server name or address.
    /// When specified, all traffic to the Internet is relayed through this outbound server,
    /// preventing the outbound IP seen by destination servers from changing.
    #[serde(default)]
    pub relay_to_server: Option<String>,

    /// If the designated relay outbound server is temporarily unreachable,
    /// whether to allow intermediate servers to exit directly to the target.
    #[serde(default = "default_true")]
    pub relay_fallback_direct: bool,
}

fn default_true() -> bool {
    true
}

impl Default for MultiServerRoutingConfig {
    fn default() -> Self {
        Self {
            mode: TrafficMode::Aggregation,
            strategy: AggregationStrategy::RoundRobin,
            relay_to_server: None,
            relay_fallback_direct: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerNodeConfig {
    /// Friendly name or label for this server (e.g. "us-west-1", "node-a")
    #[serde(default)]
    pub name: String,

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

    /// Weight for random aggregation load-balancing (default: 1)
    #[serde(default = "default_weight")]
    pub weight: u32,

    /// Priority for resilient failover (lower number = higher priority, default: 1)
    #[serde(default = "default_priority")]
    pub priority: u32,

    #[serde(default)]
    pub obfuscation: Option<crate::obfs::ObfuscationConfig>,

    #[serde(default)]
    pub tls_fingerprint: Option<crate::tls_fingerprint::TlsFingerprintConfig>,

    #[serde(default)]
    pub realm: Option<crate::realm::RealmConfig>,
}

fn default_weight() -> u32 {
    1
}

fn default_priority() -> u32 {
    1
}

impl ServerNodeConfig {
    pub fn is_realm(&self) -> bool {
        crate::realm::is_realm_addr(&self.server_addr)
    }
}

impl Default for ServerNodeConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            server_addr: "127.0.0.1".to_string(),
            server_port: default_server_port(),
            auth_key: String::new(),
            transport: TransportMode::Auto,
            server_name: None,
            insecure: false,
            cert_fingerprint: None,
            ca_cert: None,
            weight: default_weight(),
            priority: default_priority(),
            obfuscation: None,
            tls_fingerprint: None,
            realm: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    #[serde(default = "default_socks5_listen")]
    pub socks5_listen: SocketAddr,

    /// Upstream QuicProxy servers
    #[serde(default)]
    pub servers: Vec<ServerNodeConfig>,

    /// Routing configuration for multi-server traffic
    #[serde(default)]
    pub routing: MultiServerRoutingConfig,

    pub socks5_user: Option<String>,
    pub socks5_password: Option<String>,

    #[serde(default)]
    pub acl: Option<AclConfig>,

    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
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
            servers: vec![ServerNodeConfig::default()],
            routing: MultiServerRoutingConfig::default(),
            socks5_user: None,
            socks5_password: None,
            acl: None,
            outbounds: Vec::new(),
        }
    }
}

impl ClientConfig {
    pub fn new_single_server(socks5_listen: SocketAddr, server_node: ServerNodeConfig) -> Self {
        Self {
            socks5_listen,
            servers: vec![server_node],
            routing: MultiServerRoutingConfig::default(),
            socks5_user: None,
            socks5_password: None,
            acl: None,
            outbounds: Vec::new(),
        }
    }

    pub fn validate_and_normalize(&mut self) -> Result<()> {
        if let Some(ref acl) = self.acl {
            acl.validate()?;
        }
        if self.servers.is_empty() {
            anyhow::bail!("Client configuration must specify at least one server in 'servers'");
        }
        for (idx, server) in self.servers.iter_mut().enumerate() {
            if server.name.is_empty() {
                server.name = format!("node-{}", idx + 1);
            }
            if server.server_addr.is_empty() {
                anyhow::bail!("Server node #{} has empty server_addr", idx + 1);
            }
            if server.is_realm() {
                crate::realm::parse_realm_addr(&server.server_addr).with_context(|| {
                    format!("Server node '{}' has invalid realm URI", server.name)
                })?;
            }
            if server.auth_key.is_empty() {
                anyhow::bail!("Server node '{}' must have an auth_key", server.name);
            }
            if server.cert_fingerprint.is_some() {
                if server.transport == TransportMode::Tcp {
                    anyhow::bail!(
                        "Server node '{}': cert_fingerprint cannot be used with transport = 'tcp' because TCP transport does not use TLS certificates",
                        server.name
                    );
                }
                if server.insecure {
                    tracing::warn!(
                        "Server node '{}': cert_fingerprint is specified, disabling 'insecure = true' to enforce fingerprint verification",
                        server.name
                    );
                    server.insecure = false;
                }
            }
        }
        if let Some(ref relay_target) = self.routing.relay_to_server {
            let exists = self
                .servers
                .iter()
                .any(|s| s.name == *relay_target || s.server_addr == *relay_target);
            if !exists {
                anyhow::bail!(
                    "Configured relay_to_server '{}' was not found among configured servers",
                    relay_target
                );
            }
        }
        Ok(())
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref()).with_context(|| {
            format!(
                "Failed to read client config from {}",
                path.as_ref().display()
            )
        })?;
        let mut config: ClientConfig =
            toml::from_str(&content).with_context(|| "Failed to parse client config TOML")?;
        config.validate_and_normalize()?;
        Ok(config)
    }
}
