use anyhow::{Context, Result, bail};
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::{AsyncReadWrite, Outbound};
use crate::protocol::TargetAddr;

const SOCKS5_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Socks5Outbound {
    name: String,
    addr: String,
    username: Option<String>,
    password: Option<String>,
}

impl Socks5Outbound {
    pub fn new(
        name: impl Into<String>,
        addr: impl Into<String>,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            addr: addr.into(),
            username,
            password,
        }
    }
}

impl Outbound for Socks5Outbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn tcp_connect<'a>(
        &'a self,
        target: &'a TargetAddr,
    ) -> super::BoxFuture<'a, Result<Box<dyn AsyncReadWrite>>> {
        Box::pin(async move {
            let stream = timeout(SOCKS5_TIMEOUT, TcpStream::connect(&self.addr))
                .await
                .with_context(|| format!("Timeout connecting to upstream SOCKS5 {}", self.addr))?
                .with_context(|| format!("Failed to connect to upstream SOCKS5 {}", self.addr))?;
            let _ = stream.set_nodelay(true);

            let mut stream = stream;

            // 1. Negotiation
            if let (Some(user), Some(pass)) = (&self.username, &self.password) {
                // Offer username/password auth (0x02)
                stream.write_all(&[0x05, 0x01, 0x02]).await?;
                let mut resp = [0u8; 2];
                stream.read_exact(&mut resp).await?;
                if resp[0] != 0x05 || resp[1] != 0x02 {
                    bail!(
                        "Upstream SOCKS5 server rejected username/password method (method: 0x{:02x})",
                        resp[1]
                    );
                }

                // Subnegotiation RFC 1929
                let mut auth_pkt = vec![0x01, user.len() as u8];
                auth_pkt.extend_from_slice(user.as_bytes());
                auth_pkt.push(pass.len() as u8);
                auth_pkt.extend_from_slice(pass.as_bytes());
                stream.write_all(&auth_pkt).await?;

                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await?;
                if auth_resp[1] != 0x00 {
                    bail!("Upstream SOCKS5 authentication failed");
                }
            } else {
                // Offer NO AUTH (0x00)
                stream.write_all(&[0x05, 0x01, 0x00]).await?;
                let mut resp = [0u8; 2];
                stream.read_exact(&mut resp).await?;
                if resp[0] != 0x05 || resp[1] != 0x00 {
                    bail!(
                        "Upstream SOCKS5 server rejected NO AUTH method (method: 0x{:02x})",
                        resp[1]
                    );
                }
            }

            // 2. Send CONNECT request
            let mut req = vec![0x05, 0x01, 0x00];
            match target {
                TargetAddr::Ip(addr) => match addr.ip() {
                    IpAddr::V4(v4) => {
                        req.push(0x01); // IPv4
                        req.extend_from_slice(&v4.octets());
                        req.extend_from_slice(&addr.port().to_be_bytes());
                    }
                    IpAddr::V6(v6) => {
                        req.push(0x04); // IPv6
                        req.extend_from_slice(&v6.octets());
                        req.extend_from_slice(&addr.port().to_be_bytes());
                    }
                },
                TargetAddr::Domain(domain, port) => {
                    req.push(0x03); // Domain
                    req.push(domain.len() as u8);
                    req.extend_from_slice(domain.as_bytes());
                    req.extend_from_slice(&port.to_be_bytes());
                }
            }
            stream.write_all(&req).await?;

            // 3. Read CONNECT response
            let mut header = [0u8; 4];
            stream.read_exact(&mut header).await?;
            if header[0] != 0x05 {
                bail!("Invalid SOCKS5 response version: 0x{:02x}", header[0]);
            }
            if header[1] != 0x00 {
                bail!("Upstream SOCKS5 server returned error 0x{:02x}", header[1]);
            }

            // Drain BND.ADDR and BND.PORT
            match header[3] {
                0x01 => {
                    let mut buf = [0u8; 4 + 2];
                    stream.read_exact(&mut buf).await?;
                }
                0x03 => {
                    let len = stream.read_u8().await? as usize;
                    let mut buf = vec![0u8; len + 2];
                    stream.read_exact(&mut buf).await?;
                }
                0x04 => {
                    let mut buf = [0u8; 16 + 2];
                    stream.read_exact(&mut buf).await?;
                }
                other => bail!("Invalid SOCKS5 ATYP 0x{:02x} in response", other),
            }

            Ok(Box::new(stream) as Box<dyn AsyncReadWrite>)
        })
    }
}
