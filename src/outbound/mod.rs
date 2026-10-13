pub mod direct;
pub mod http;
pub mod reject;
pub mod socks5;

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::{OutboundConfig, OutboundType};
use crate::protocol::TargetAddr;
pub use direct::{DirectMode, DirectOutbound};
pub use http::HttpOutbound;
pub use reject::RejectOutbound;
pub use socks5::Socks5Outbound;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncReadWrite for T {}

use std::future::Future;
use std::pin::Pin;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Outbound: Send + Sync {
    fn name(&self) -> &str;
    fn is_reject(&self) -> bool {
        false
    }
    fn tcp_connect<'a>(
        &'a self,
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncReadWrite>>>;
}

/// Default outbound for client-side routing representing the upstream proxy tunnel.
#[derive(Debug, Default, Clone)]
pub struct DefaultOutbound;

impl Outbound for DefaultOutbound {
    fn name(&self) -> &str {
        "default"
    }

    fn tcp_connect<'a>(
        &'a self,
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncReadWrite>>> {
        Box::pin(async move {
            anyhow::bail!(
                "Default outbound represents proxy tunnel to upstream server for {}",
                target
            );
        })
    }
}

pub fn build_outbound_map(
    configs: &[OutboundConfig],
) -> Result<(HashMap<String, Arc<dyn Outbound>>, Arc<dyn Outbound>)> {
    let mut map: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
    let mut first_custom: Option<Arc<dyn Outbound>> = None;

    for cfg in configs {
        let ob: Arc<dyn Outbound> = match cfg.outbound_type {
            OutboundType::Direct => {
                let direct_cfg = cfg.direct.as_ref();
                let mode = direct_cfg
                    .and_then(|d| d.mode.as_deref())
                    .map(DirectMode::parse)
                    .unwrap_or(DirectMode::Auto);
                let bind_v4 = direct_cfg.and_then(|d| d.bind_ipv4);
                let bind_v6 = direct_cfg.and_then(|d| d.bind_ipv6);
                Arc::new(DirectOutbound::new(&cfg.name, mode, bind_v4, bind_v6))
            }
            OutboundType::Reject => Arc::new(RejectOutbound::new(&cfg.name)),
            OutboundType::Socks5 => {
                let s5 = cfg.socks5.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Missing socks5 block for outbound {}", cfg.name)
                })?;
                Arc::new(Socks5Outbound::new(
                    &cfg.name,
                    &s5.addr,
                    s5.username.clone(),
                    s5.password.clone(),
                ))
            }
            OutboundType::Http => {
                let h = cfg.http.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Missing http block for outbound {}", cfg.name)
                })?;
                Arc::new(HttpOutbound::new(&cfg.name, &h.url, h.insecure)?)
            }
        };

        if first_custom.is_none() {
            first_custom = Some(Arc::clone(&ob));
        }

        map.insert(cfg.name.to_ascii_lowercase(), ob);
    }

    // Built-in outbounds if not explicitly overridden
    if !map.contains_key("direct") {
        map.insert(
            "direct".to_string(),
            Arc::new(DirectOutbound::new("direct", DirectMode::Auto, None, None)),
        );
    }

    if !map.contains_key("reject") {
        map.insert(
            "reject".to_string(),
            Arc::new(RejectOutbound::new("reject")),
        );
    }

    let default_ob = if let Some(custom) = map.get("default") {
        Arc::clone(custom)
    } else if let Some(first) = first_custom {
        first
    } else {
        Arc::clone(map.get("direct").unwrap())
    };

    map.insert("default".to_string(), Arc::clone(&default_ob));

    Ok((map, default_ob))
}

pub fn build_client_outbound_map(
    configs: &[OutboundConfig],
) -> Result<(HashMap<String, Arc<dyn Outbound>>, Arc<dyn Outbound>)> {
    let mut map: HashMap<String, Arc<dyn Outbound>> = HashMap::new();

    for cfg in configs {
        let ob: Arc<dyn Outbound> = match cfg.outbound_type {
            OutboundType::Direct => {
                let direct_cfg = cfg.direct.as_ref();
                let mode = direct_cfg
                    .and_then(|d| d.mode.as_deref())
                    .map(DirectMode::parse)
                    .unwrap_or(DirectMode::Auto);
                let bind_v4 = direct_cfg.and_then(|d| d.bind_ipv4);
                let bind_v6 = direct_cfg.and_then(|d| d.bind_ipv6);
                Arc::new(DirectOutbound::new(&cfg.name, mode, bind_v4, bind_v6))
            }
            OutboundType::Reject => Arc::new(RejectOutbound::new(&cfg.name)),
            OutboundType::Socks5 => {
                let s5 = cfg.socks5.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Missing socks5 block for outbound {}", cfg.name)
                })?;
                Arc::new(Socks5Outbound::new(
                    &cfg.name,
                    &s5.addr,
                    s5.username.clone(),
                    s5.password.clone(),
                ))
            }
            OutboundType::Http => {
                let h = cfg.http.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Missing http block for outbound {}", cfg.name)
                })?;
                Arc::new(HttpOutbound::new(&cfg.name, &h.url, h.insecure)?)
            }
        };

        map.insert(cfg.name.to_ascii_lowercase(), ob);
    }

    // Built-in outbounds if not explicitly overridden
    if !map.contains_key("direct") {
        map.insert(
            "direct".to_string(),
            Arc::new(DirectOutbound::new("direct", DirectMode::Auto, None, None)),
        );
    }

    if !map.contains_key("reject") {
        map.insert(
            "reject".to_string(),
            Arc::new(RejectOutbound::new("reject")),
        );
    }

    let default_ob = if let Some(custom) = map.get("default") {
        Arc::clone(custom)
    } else {
        Arc::new(DefaultOutbound)
    };

    map.insert("default".to_string(), Arc::clone(&default_ob));

    Ok((map, default_ob))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DirectOutboundConfig, OutboundConfig, OutboundType};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_default_outbounds() {
        let (map, default_ob) = build_outbound_map(&[]).unwrap();
        assert!(map.contains_key("direct"));
        assert!(map.contains_key("reject"));
        assert!(map.contains_key("default"));
        assert_eq!(default_ob.name(), "direct");

        let reject = map.get("reject").unwrap();
        assert!(reject.is_reject());
        assert!(
            reject
                .tcp_connect(&TargetAddr::Ip("127.0.0.1:80".parse().unwrap()))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_custom_outbounds_and_default_precedence() {
        let configs = vec![
            OutboundConfig {
                name: "my-reject".to_string(),
                outbound_type: OutboundType::Reject,
                direct: None,
                socks5: None,
                http: None,
            },
            OutboundConfig {
                name: "my-direct".to_string(),
                outbound_type: OutboundType::Direct,
                direct: Some(DirectOutboundConfig {
                    mode: Some("4".to_string()),
                    bind_ipv4: None,
                    bind_ipv6: None,
                }),
                socks5: None,
                http: None,
            },
        ];

        let (map, default_ob) = build_outbound_map(&configs).unwrap();
        assert!(map.contains_key("my-reject"));
        assert!(map.contains_key("my-direct"));
        // First custom outbound becomes default if none named "default"
        assert_eq!(default_ob.name(), "my-reject");
    }

    #[tokio::test]
    async fn test_direct_outbound_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let direct = DirectOutbound::new("direct", DirectMode::Auto, None, None);
        let target = TargetAddr::Ip(addr);
        let stream = direct.tcp_connect(&target).await;
        assert!(stream.is_ok());
    }
}
