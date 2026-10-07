use anyhow::{Context, Result, bail};
use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::protocol::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, TargetAddr, UdpDatagram};
use crate::transport::ActiveTransport;

pub fn parse_socks5_udp_header(data: &[u8]) -> Result<(TargetAddr, &[u8])> {
    if data.len() < 4 {
        bail!("SOCKS5 UDP header too short");
    }

    // RSV
    if data[0] != 0 || data[1] != 0 {
        bail!("Invalid RSV in SOCKS5 UDP header");
    }

    // FRAG
    if data[2] != 0 {
        warn!("SOCKS5 UDP fragmentation not supported (FRAG={})", data[2]);
        bail!("SOCKS5 UDP fragmentation not supported");
    }

    let atyp = data[3];
    let mut pos = 4;

    let target = match atyp {
        ATYP_IPV4 => {
            if data.len() < pos + 6 {
                bail!("Incomplete IPv4 address in UDP header");
            }
            let mut ip_bytes = [0u8; 4];
            ip_bytes.copy_from_slice(&data[pos..pos + 4]);
            pos += 4;
            let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
            pos += 2;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip_bytes)), port))
        }
        ATYP_DOMAIN => {
            if data.len() < pos + 1 {
                bail!("Incomplete domain length in UDP header");
            }
            let len = data[pos] as usize;
            pos += 1;
            if data.len() < pos + len + 2 {
                bail!("Incomplete domain in UDP header");
            }
            let domain = String::from_utf8(data[pos..pos + len].to_vec())
                .context("Invalid UTF-8 in domain name")?;
            pos += len;
            let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
            pos += 2;
            TargetAddr::Domain(domain, port)
        }
        ATYP_IPV6 => {
            if data.len() < pos + 18 {
                bail!("Incomplete IPv6 address in UDP header");
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[pos..pos + 16]);
            pos += 16;
            let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
            pos += 2;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port))
        }
        _ => bail!("Unknown ATYP: {}", atyp),
    };

    Ok((target, &data[pos..]))
}

pub fn build_socks5_udp_header(target: &TargetAddr, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256 + payload.len());

    // RSV
    buf.push(0x00);
    buf.push(0x00);
    // FRAG
    buf.push(0x00);

    match target {
        TargetAddr::Ip(SocketAddr::V4(addr)) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Ip(SocketAddr::V6(addr)) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Domain(domain, port) => {
            buf.push(ATYP_DOMAIN);
            let bytes = domain.as_bytes();
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }

    buf.extend_from_slice(payload);
    buf
}

pub struct UdpRelay {
    session_id: u32,
    relay_socket: Arc<UdpSocket>,
    client_addr: tokio::sync::Mutex<Option<SocketAddr>>,
    incoming_rx: tokio::sync::Mutex<mpsc::Receiver<UdpDatagram>>,
}

impl UdpRelay {
    pub async fn new(
        session_id: u32,
        bind_addr: SocketAddr,
        incoming_rx: mpsc::Receiver<UdpDatagram>,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .context("Failed to bind UDP socket")?;
        Ok(Self {
            session_id,
            relay_socket: Arc::new(socket),
            client_addr: tokio::sync::Mutex::new(None),
            incoming_rx: tokio::sync::Mutex::new(incoming_rx),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.relay_socket
            .local_addr()
            .context("Failed to get local address of UDP socket")
    }

    pub async fn run_client_to_server(
        &self,
        transport: Arc<ActiveTransport>,
        acl_engine: Arc<crate::acl::ACLEngine>,
    ) -> Result<()> {
        let mut buf = [0u8; 2048];
        loop {
            let (len, src_addr) = self.relay_socket.recv_from(&mut buf).await?;
            let data = &buf[..len];

            // Record client address on first packet
            {
                let mut client_addr_guard = self.client_addr.lock().await;
                if client_addr_guard.is_none() {
                    *client_addr_guard = Some(src_addr);
                } else if let Some(addr) = *client_addr_guard {
                    if addr != src_addr {
                        warn!(
                            "Received UDP packet from unknown address {} (expected {})",
                            src_addr, addr
                        );
                        continue;
                    }
                }
            }

            match parse_socks5_udp_header(data) {
                Ok((target, payload)) => {
                    let (outbound, final_target) =
                        acl_engine.handle(&target, crate::acl::Protocol::Udp).await;
                    if outbound.name() == "reject" {
                        debug!(
                            "Dropped outgoing UDP datagram to {} due to ACL reject rule",
                            target
                        );
                        continue;
                    }
                    let dgram = UdpDatagram {
                        session_id: self.session_id,
                        target: final_target,
                        payload: payload.to_vec(),
                    };
                    let encoded = dgram.encode();
                    if let Err(e) = transport.send_datagram(&encoded) {
                        warn!("Failed to send UDP datagram: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Failed to parse SOCKS5 UDP header: {}", e);
                }
            }
        }
    }

    pub async fn run_server_to_client(&self) -> Result<()> {
        let mut rx = self.incoming_rx.lock().await;
        while let Some(dgram) = rx.recv().await {
            let addr = {
                let guard = self.client_addr.lock().await;
                *guard
            };
            if let Some(client_addr) = addr {
                let packet = build_socks5_udp_header(&dgram.target, &dgram.payload);
                if let Err(e) = self.relay_socket.send_to(&packet, client_addr).await {
                    warn!("Failed to send UDP packet to client: {}", e);
                }
            } else {
                debug!("Dropped incoming UDP packet because client address is unknown");
            }
        }
        Ok(())
    }
}

pub struct DatagramRouter {
    routers: DashMap<u32, mpsc::Sender<UdpDatagram>>,
}

impl Default for DatagramRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl DatagramRouter {
    pub fn new() -> Self {
        Self {
            routers: DashMap::new(),
        }
    }

    pub fn register(&self, session_id: u32) -> mpsc::Receiver<UdpDatagram> {
        let (tx, rx) = mpsc::channel(1024);
        self.routers.insert(session_id, tx);
        rx
    }

    pub fn deregister(&self, session_id: u32) {
        self.routers.remove(&session_id);
    }

    pub async fn route(&self, dgram: UdpDatagram) {
        let tx = self
            .routers
            .get(&dgram.session_id)
            .map(|r| r.value().clone());

        if let Some(tx) = tx {
            if let Err(e) = tx.send(dgram).await {
                debug!("Failed to route datagram: channel closed ({})", e);
            }
        } else {
            debug!("Dropped datagram: session {} not found", dgram.session_id);
        }
    }

    pub async fn recv_and_route_loop(self: Arc<Self>, transport: Arc<ActiveTransport>) {
        loop {
            match transport.recv_datagram().await {
                Ok(data) => match UdpDatagram::decode(&data) {
                    Ok(dgram) => {
                        self.route(dgram).await;
                    }
                    Err(e) => {
                        warn!("Failed to decode UdpDatagram: {}", e);
                    }
                },
                Err(e) => {
                    error!("Error receiving datagram from transport: {}", e);
                    break;
                }
            }
        }
    }
}
