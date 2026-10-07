use super::punch::AddrFamily;
use super::stun::DEFAULT_REALM_STUN_SERVERS;
use crate::config::parse_duration;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RealmConfig {
    #[serde(default)]
    pub stun_servers: Vec<String>,
    #[serde(default)]
    pub stun_timeout: Option<String>,
    #[serde(default)]
    pub punch_timeout: Option<String>,
    #[serde(default)]
    pub heartbeat_interval: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub ip_mode: Option<String>,
    #[serde(default)]
    pub port_mapping: Option<PortMappingConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortMappingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default)]
    pub lifetime: Option<String>,
}

impl PortMappingConfig {
    pub fn timeout_duration(&self) -> Duration {
        self.timeout
            .as_deref()
            .and_then(parse_duration)
            .unwrap_or(Duration::from_secs(10))
    }

    pub fn lifetime_duration(&self) -> Duration {
        self.lifetime
            .as_deref()
            .and_then(parse_duration)
            .unwrap_or(Duration::from_secs(600))
    }
}

impl RealmConfig {
    pub fn stun_timeout_duration(&self) -> Duration {
        self.stun_timeout
            .as_deref()
            .and_then(parse_duration)
            .unwrap_or(Duration::from_secs(4))
    }

    pub fn punch_timeout_duration(&self) -> Duration {
        self.punch_timeout
            .as_deref()
            .and_then(parse_duration)
            .unwrap_or(Duration::from_secs(10))
    }

    pub fn heartbeat_interval_duration(&self, default_interval: Duration) -> Duration {
        self.heartbeat_interval
            .as_deref()
            .and_then(parse_duration)
            .unwrap_or(default_interval)
    }

    pub fn ip_mode_family(&self) -> AddrFamily {
        match self
            .ip_mode
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("v4") => AddrFamily::IPv4,
            Some("v6") => AddrFamily::IPv6,
            _ => AddrFamily::Any,
        }
    }

    pub fn effective_stun_servers(&self, addr_stuns: &[String]) -> Vec<String> {
        if !addr_stuns.is_empty() {
            return addr_stuns.to_vec();
        }
        if !self.stun_servers.is_empty() {
            return self.stun_servers.clone();
        }
        DEFAULT_REALM_STUN_SERVERS
            .iter()
            .map(|s| s.to_string())
            .collect()
    }
}
