pub mod cache;
pub mod geo;
pub mod matcher;
pub mod rule;

use anyhow::{Result, bail};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

pub use cache::{MatchCache, MatchResult, MatchResultCacheKey};
pub use geo::{DefaultGeoLoader, GeoLoader};
pub use matcher::{HostInfo, HostMatcher, compile_host_matcher};
pub use rule::{Protocol, TextRule, parse_proto_port, parse_text_rules};

use crate::outbound::{Outbound, build_outbound_map};
use crate::protocol::TargetAddr;

pub const DEFAULT_ACL_CACHE_SIZE: usize = 1024;

pub struct CompiledRule<O> {
    pub outbound: O,
    pub host_matcher: Box<dyn HostMatcher>,
    pub protocol: Protocol,
    pub start_port: u16,
    pub end_port: u16,
    pub hijack_address: Option<IpAddr>,
}

impl<O> CompiledRule<O> {
    pub fn matches(&self, host: &HostInfo, proto: Protocol, port: u16) -> bool {
        if self.protocol != Protocol::Both && self.protocol != proto {
            return false;
        }
        if self.start_port != 0 && (port < self.start_port || port > self.end_port) {
            return false;
        }
        self.host_matcher.matches(host)
    }
}

pub struct CompiledRuleSet<O: Clone> {
    pub rules: Vec<CompiledRule<O>>,
    pub cache: MatchCache<O>,
}

impl<O: Clone> CompiledRuleSet<O> {
    pub fn match_target(
        &self,
        mut host: HostInfo,
        proto: Protocol,
        port: u16,
    ) -> (Option<O>, Option<IpAddr>) {
        host.name = host.name.trim_end_matches('.').to_ascii_lowercase();
        let key = MatchResultCacheKey {
            host: host.cache_string(),
            proto,
            port,
        };

        if let Some(res) = self.cache.get(&key) {
            return (res.outbound, res.hijack_address);
        }

        for rule in &self.rules {
            if rule.matches(&host, proto, port) {
                let outbound = Some(rule.outbound.clone());
                let hijack = rule.hijack_address;
                self.cache.put(
                    key,
                    MatchResult {
                        outbound: outbound.clone(),
                        hijack_address: hijack,
                    },
                );
                return (outbound, hijack);
            }
        }

        // Cache no-match
        self.cache.put(
            key,
            MatchResult {
                outbound: None,
                hijack_address: None,
            },
        );
        (None, None)
    }
}

pub async fn compile<O: Clone>(
    rules: &[TextRule],
    outbounds: &HashMap<String, O>,
    cache_size: usize,
    geo_loader: &dyn GeoLoader,
) -> Result<CompiledRuleSet<O>> {
    let mut compiled_rules = Vec::with_capacity(rules.len());

    for rule in rules {
        let outbound = match outbounds.get(&rule.outbound.to_ascii_lowercase()) {
            Some(ob) => ob.clone(),
            None => bail!(
                "error at line {}: outbound {} not found",
                rule.line_num,
                rule.outbound
            ),
        };

        let host_matcher = compile_host_matcher(&rule.address, geo_loader)
            .await
            .map_err(|e| anyhow::anyhow!("error at line {}: {:#}", rule.line_num, e))?;

        let (proto, start_port, end_port) = parse_proto_port(&rule.proto_port)
            .map_err(|e| anyhow::anyhow!("error at line {}: {:#}", rule.line_num, e))?;

        let hijack_address = if !rule.hijack_address.is_empty() {
            let ip = rule.hijack_address.parse::<IpAddr>().map_err(|_| {
                anyhow::anyhow!(
                    "error at line {}: invalid hijack address (must be an IP address): {}",
                    rule.line_num,
                    rule.hijack_address
                )
            })?;
            Some(ip)
        } else {
            None
        };

        compiled_rules.push(CompiledRule {
            outbound,
            host_matcher,
            protocol: proto,
            start_port,
            end_port,
            hijack_address,
        });
    }

    Ok(CompiledRuleSet {
        rules: compiled_rules,
        cache: MatchCache::new(cache_size),
    })
}

pub struct ACLEngine {
    pub rule_set: CompiledRuleSet<Arc<dyn Outbound>>,
    pub default_outbound: Arc<dyn Outbound>,
}

impl ACLEngine {
    pub async fn new_from_string(
        rules_str: &str,
        outbounds_cfg: &[crate::config::OutboundConfig],
        geo_loader: &dyn GeoLoader,
    ) -> Result<Self> {
        let text_rules = parse_text_rules(rules_str)?;
        let (ob_map, default_ob) = build_outbound_map(outbounds_cfg)?;
        let rule_set = compile(&text_rules, &ob_map, DEFAULT_ACL_CACHE_SIZE, geo_loader).await?;
        Ok(Self {
            rule_set,
            default_outbound: default_ob,
        })
    }

    pub async fn resolve_host_info(target: &TargetAddr) -> HostInfo {
        match target {
            TargetAddr::Ip(addr) => match addr.ip() {
                IpAddr::V4(v4) => HostInfo {
                    name: v4.to_string(),
                    ipv4: Some(v4),
                    ipv6: None,
                },
                IpAddr::V6(v6) => HostInfo {
                    name: v6.to_string(),
                    ipv4: None,
                    ipv6: Some(v6),
                },
            },
            TargetAddr::Domain(host, port) => {
                let mut v4_opt = None;
                let mut v6_opt = None;
                if let Ok(addrs) = tokio::net::lookup_host((host.as_str(), *port)).await {
                    for addr in addrs {
                        match addr.ip() {
                            IpAddr::V4(v4) if v4_opt.is_none() => v4_opt = Some(v4),
                            IpAddr::V6(v6) if v6_opt.is_none() => v6_opt = Some(v6),
                            _ => {}
                        }
                    }
                }
                HostInfo {
                    name: host.clone(),
                    ipv4: v4_opt,
                    ipv6: v6_opt,
                }
            }
        }
    }

    pub async fn handle(
        &self,
        target: &TargetAddr,
        proto: Protocol,
    ) -> (Arc<dyn Outbound>, TargetAddr) {
        let host_info = Self::resolve_host_info(target).await;
        let port = target.port();
        let (ob_opt, hijack_opt) = self.rule_set.match_target(host_info, proto, port);

        let outbound = ob_opt.unwrap_or_else(|| Arc::clone(&self.default_outbound));

        let final_target = if let Some(hijack_ip) = hijack_opt {
            TargetAddr::Ip(std::net::SocketAddr::new(hijack_ip, port))
        } else {
            target.clone()
        };

        (outbound, final_target)
    }
}

impl Default for ACLEngine {
    fn default() -> Self {
        let default_ob = Arc::new(crate::outbound::direct::DirectOutbound::default());
        Self {
            rule_set: CompiledRuleSet {
                rules: Vec::new(),
                cache: MatchCache::new(DEFAULT_ACL_CACHE_SIZE),
            },
            default_outbound: default_ob,
        }
    }
}
