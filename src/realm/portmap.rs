use anyhow::{Context, Result, bail};
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

pub const PORTMAP_PROTOCOL: &str = "UDP";
pub const PORTMAP_DESCRIPTION: &str = "quicproxy-realm";

pub struct PortMapper {
    internal_port: u16,
    lifetime: Duration,
    external_addr: Mutex<Option<SocketAddr>>,
    gateway: Option<igd_next::Gateway>,
}

impl PortMapper {
    /// Attempts UPnP discovery and UDP port mapping on the local gateway.
    /// Non-fatal: if gateway is not found or mapping fails, returns an error.
    pub async fn new(
        internal_port: u16,
        timeout_dur: Duration,
        lifetime: Duration,
    ) -> Result<Self> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        // igd-next search_gateway is synchronous / blocking network IO, run on blocking thread
        tokio::task::spawn_blocking(move || {
            let res = igd_next::search_gateway(Default::default());
            let _ = tx.send(res);
        });

        let gateway = match tokio::time::timeout(timeout_dur, rx).await {
            Ok(Ok(Ok(gw))) => gw,
            Ok(Ok(Err(e))) => bail!("gateway discovery failed: {}", e),
            Ok(Err(_)) => bail!("gateway discovery cancelled"),
            Err(_) => bail!("gateway discovery timed out"),
        };

        let mapper = Self {
            internal_port,
            lifetime,
            external_addr: Mutex::new(None),
            gateway: Some(gateway),
        };

        mapper.renew(timeout_dur).await?;
        Ok(mapper)
    }

    /// (Re-)requests the port mapping and updates the external address.
    /// Returns true if the external address changed.
    pub async fn renew(&self, timeout_dur: Duration) -> Result<bool> {
        let Some(gw) = self.gateway.clone() else {
            bail!("no active gateway");
        };

        let internal_port = self.internal_port;
        let lease_secs = self.lifetime.as_secs() as u32;

        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::task::spawn_blocking(move || {
            // Add port mapping
            let local_ip = match local_ip_address() {
                Ok(ip) => ip,
                Err(e) => {
                    let _ = tx.send(Err(e));
                    return;
                }
            };

            let local_sock = SocketAddr::new(IpAddr::V4(local_ip), internal_port);
            let res = gw
                .add_port(
                    igd_next::PortMappingProtocol::UDP,
                    internal_port,
                    local_sock,
                    lease_secs,
                    PORTMAP_DESCRIPTION,
                )
                .map_err(|e| anyhow::anyhow!("add_port failed: {}", e))
                .and_then(|_| {
                    gw.get_external_ip()
                        .map_err(|e| anyhow::anyhow!("get_external_ip failed: {}", e))
                })
                .map(|ext_ip| SocketAddr::new(ext_ip, internal_port));

            let _ = tx.send(res);
        });

        let new_ext_addr = match tokio::time::timeout(timeout_dur, rx).await {
            Ok(Ok(Ok(addr))) => addr,
            Ok(Ok(Err(e))) => bail!("{}", e),
            Ok(Err(_)) => bail!("renew cancelled"),
            Err(_) => bail!("renew timed out"),
        };

        let mut guard = self.external_addr.lock().unwrap();
        let changed = *guard != Some(new_ext_addr);
        *guard = Some(new_ext_addr);
        Ok(changed)
    }

    pub fn external_addr(&self) -> Option<SocketAddr> {
        *self.external_addr.lock().unwrap()
    }

    pub fn internal_port(&self) -> u16 {
        self.internal_port
    }

    pub fn lifetime(&self) -> Duration {
        self.lifetime
    }

    /// Removes port mapping on gateway (best-effort).
    pub fn close(&self) {
        if let Some(gw) = self.gateway.clone() {
            let port = self.internal_port;
            drop(tokio::task::spawn_blocking(move || {
                let _ = gw.remove_port(igd_next::PortMappingProtocol::UDP, port);
            }));
        }
    }
}

fn local_ip_address() -> Result<std::net::Ipv4Addr> {
    // Determine routeable local IPv4 by connecting a UDP socket to a public address
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .context("failed to bind UDP socket for local IP detection")?;
    socket
        .connect("1.1.1.1:80")
        .context("failed to connect UDP socket for local IP detection")?;
    let local = socket.local_addr()?;
    match local.ip() {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => bail!("detected non-IPv4 address"),
    }
}
