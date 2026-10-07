use anyhow::{bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

use crate::protocol::TargetAddr;
use super::{AsyncReadWrite, Outbound};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DirectMode {
    #[default]
    Auto,
    V4Only,
    V6Only,
    V4Prefer,
    V6Prefer,
}

impl DirectMode {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "4" | "v4" | "ipv4" => DirectMode::V4Only,
            "6" | "v6" | "ipv6" => DirectMode::V6Only,
            "46" | "v46" => DirectMode::V4Prefer,
            "64" | "v64" => DirectMode::V6Prefer,
            _ => DirectMode::Auto,
        }
    }
}

pub struct DirectOutbound {
    name: String,
    mode: DirectMode,
    bind_ipv4: Option<Ipv4Addr>,
    bind_ipv6: Option<Ipv6Addr>,
}

impl DirectOutbound {
    pub fn new(
        name: impl Into<String>,
        mode: DirectMode,
        bind_ipv4: Option<Ipv4Addr>,
        bind_ipv6: Option<Ipv6Addr>,
    ) -> Self {
        Self {
            name: name.into(),
            mode,
            bind_ipv4,
            bind_ipv6,
        }
    }

    async fn resolve_addrs(&self, target: &TargetAddr) -> Result<Vec<SocketAddr>> {
        match target {
            TargetAddr::Ip(addr) => {
                match (addr.ip(), self.mode) {
                    (IpAddr::V4(_), DirectMode::V6Only) => {
                        bail!("Target {} is IPv4 but mode is IPv6 only", target);
                    }
                    (IpAddr::V6(_), DirectMode::V4Only) => {
                        bail!("Target {} is IPv6 but mode is IPv4 only", target);
                    }
                    _ => Ok(vec![*addr]),
                }
            }
            TargetAddr::Domain(host, port) => {
                let host_port = format!("{}:{}", host, port);
                let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&host_port)
                    .await
                    .with_context(|| format!("Failed to resolve target domain {}", host))?
                    .collect();

                if addrs.is_empty() {
                    bail!("No IP addresses found for target domain {}", host);
                }

                let mut v4s = Vec::new();
                let mut v6s = Vec::new();
                for addr in addrs {
                    if addr.is_ipv4() {
                        v4s.push(addr);
                    } else {
                        v6s.push(addr);
                    }
                }

                match self.mode {
                    DirectMode::V4Only => {
                        if v4s.is_empty() {
                            bail!("No IPv4 address resolved for domain {}", host);
                        }
                        Ok(v4s)
                    }
                    DirectMode::V6Only => {
                        if v6s.is_empty() {
                            bail!("No IPv6 address resolved for domain {}", host);
                        }
                        Ok(v6s)
                    }
                    DirectMode::V4Prefer => {
                        v4s.extend(v6s);
                        Ok(v4s)
                    }
                    DirectMode::V6Prefer => {
                        v6s.extend(v4s);
                        Ok(v6s)
                    }
                    DirectMode::Auto => {
                        v4s.extend(v6s);
                        Ok(v4s)
                    }
                }
            }
        }
    }

    async fn connect_to_addr(&self, addr: SocketAddr) -> Result<TcpStream> {
        let stream = match addr {
            SocketAddr::V4(_) => {
                let socket = TcpSocket::new_v4().context("Failed to create TCP socket")?;
                let _ = socket.set_nodelay(true);
                if let Some(bind_v4) = self.bind_ipv4 {
                    socket
                        .bind(SocketAddr::new(IpAddr::V4(bind_v4), 0))
                        .with_context(|| format!("Failed to bind TCP socket to IPv4 {}", bind_v4))?;
                }
                timeout(CONNECT_TIMEOUT, socket.connect(addr))
                    .await
                    .with_context(|| format!("Timeout connecting to {}", addr))?
                    .with_context(|| format!("Failed to connect to {}", addr))?
            }
            SocketAddr::V6(_) => {
                let socket = TcpSocket::new_v6().context("Failed to create TCP socket")?;
                let _ = socket.set_nodelay(true);
                if let Some(bind_v6) = self.bind_ipv6 {
                    socket
                        .bind(SocketAddr::new(IpAddr::V6(bind_v6), 0))
                        .with_context(|| format!("Failed to bind TCP socket to IPv6 {}", bind_v6))?;
                }
                timeout(CONNECT_TIMEOUT, socket.connect(addr))
                    .await
                    .with_context(|| format!("Timeout connecting to {}", addr))?
                    .with_context(|| format!("Failed to connect to {}", addr))?
            }
        };
        Ok(stream)
    }
}

impl Outbound for DirectOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn tcp_connect<'a>(&'a self, target: &'a TargetAddr) -> super::BoxFuture<'a, Result<Box<dyn AsyncReadWrite>>> {
        Box::pin(async move {
            let addrs = self.resolve_addrs(target).await?;
            let mut last_err = None;

            for addr in addrs {
                match self.connect_to_addr(addr).await {
                    Ok(stream) => return Ok(Box::new(stream) as Box<dyn AsyncReadWrite>),
                    Err(e) => {
                        last_err = Some(e);
                    }
                }
            }

            Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Failed to connect to {}", target)))
        })
    }
}

impl Default for DirectOutbound {
    fn default() -> Self {
        Self::new("direct", DirectMode::Auto, None, None)
    }
}

