use anyhow::{bail, Context, Result};
use rand::RngExt;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u8 = 0x01;
pub const AUTH_TYPE_PSK: u8 = 0x01;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const STATUS_SUCCESS: u8 = 0x00;
pub const STATUS_AUTH_FAILED: u8 = 0x01;
pub const STATUS_CONNECT_FAILED: u8 = 0x02;
pub const STATUS_UNSUPPORTED: u8 = 0x03;
pub const STATUS_GENERAL_ERROR: u8 = 0x04;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(addr) => addr.port(),
            TargetAddr::Domain(_, port) => *port,
        }
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::Ip(addr) => write!(f, "{}", addr),
            TargetAddr::Domain(host, port) => write!(f, "{}:{}", host, port),
        }
    }
}

/// Generate random padding bytes between min_len and max_len inclusive.
pub fn generate_padding(min_len: usize, max_len: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let span = if max_len > min_len { max_len - min_len + 1 } else { 1 };
    let len = min_len + (rng.random::<u32>() as usize % span);
    let mut pad = vec![0u8; len];
    rng.fill(&mut pad[..]);
    pad
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub version: u8,
    pub auth_type: u8,
    pub token: [u8; 32],
    pub padding: Vec<u8>,
}

impl AuthRequest {
    pub fn new(token: [u8; 32]) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            auth_type: AUTH_TYPE_PSK,
            token,
            padding: generate_padding(16, 64),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    pub version: u8,
    pub status: u8,
    pub padding: Vec<u8>,
}

impl AuthResponse {
    pub fn new(status: u8) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            status,
            padding: generate_padding(16, 64),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRequest {
    pub cmd: u8,
    pub target: TargetAddr,
    pub padding: Vec<u8>,
}

impl ProxyRequest {
    pub fn connect(target: TargetAddr) -> Self {
        Self {
            cmd: CMD_CONNECT,
            target,
            padding: generate_padding(16, 64),
        }
    }

    pub fn udp_associate(target: TargetAddr) -> Self {
        Self {
            cmd: CMD_UDP_ASSOCIATE,
            target,
            padding: generate_padding(16, 64),
        }
    }
}

/// A UDP datagram frame for transport over QUIC unreliable datagrams or TCP stream encapsulation.
///
/// Wire format:
///   
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    pub session_id: u32,
    pub target: TargetAddr,
    pub payload: Vec<u8>,
}

impl UdpDatagram {
    /// Encode this datagram into a byte vector (synchronous, for atomic datagram delivery).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + self.payload.len());
        buf.extend_from_slice(&self.session_id.to_be_bytes());
        // Encode target address inline
        match &self.target {
            TargetAddr::Ip(std::net::SocketAddr::V4(v4)) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&v4.ip().octets());
                buf.extend_from_slice(&v4.port().to_be_bytes());
            }
            TargetAddr::Ip(std::net::SocketAddr::V6(v6)) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&v6.ip().octets());
                buf.extend_from_slice(&v6.port().to_be_bytes());
            }
            TargetAddr::Domain(domain, port) => {
                buf.push(ATYP_DOMAIN);
                let domain_bytes = domain.as_bytes();
                buf.push(domain_bytes.len() as u8);
                buf.extend_from_slice(domain_bytes);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode a datagram from raw bytes (synchronous).
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            bail!("UDP datagram too short: {} bytes", data.len());
        }
        let session_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let atyp = data[4];
        let (target, payload_offset) = match atyp {
            ATYP_IPV4 => {
                if data.len() < 4 + 1 + 4 + 2 {
                    bail!("UDP datagram IPv4 too short");
                }
                let ip = Ipv4Addr::new(data[5], data[6], data[7], data[8]);
                let port = u16::from_be_bytes([data[9], data[10]]);
                (TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port)), 11)
            }
            ATYP_IPV6 => {
                if data.len() < 4 + 1 + 16 + 2 {
                    bail!("UDP datagram IPv6 too short");
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&data[5..21]);
                let port = u16::from_be_bytes([data[21], data[22]]);
                (
                    TargetAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port)),
                    23,
                )
            }
            ATYP_DOMAIN => {
                if data.len() < 4 + 1 + 1 {
                    bail!("UDP datagram domain too short");
                }
                let domain_len = data[5] as usize;
                if data.len() < 4 + 1 + 1 + domain_len + 2 {
                    bail!("UDP datagram domain data too short");
                }
                let domain = String::from_utf8(data[6..6 + domain_len].to_vec())
                    .context("Invalid domain UTF-8 in UDP datagram")?;
                let port_offset = 6 + domain_len;
                let port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);
                (TargetAddr::Domain(domain, port), port_offset + 2)
            }
            _ => bail!("Unsupported address type in UDP datagram: 0x{:02x}", atyp),
        };
        let payload = data[payload_offset..].to_vec();
        Ok(Self {
            session_id,
            target,
            payload,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyResponse {
    pub status: u8,
    pub padding: Vec<u8>,
}

impl ProxyResponse {
    pub fn new(status: u8) -> Self {
        Self {
            status,
            padding: generate_padding(16, 64),
        }
    }
}

// ================= Async Codecs =================

pub async fn write_auth_request<W: AsyncWrite + Unpin>(w: &mut W, req: &AuthRequest) -> Result<()> {
    w.write_u8(req.version).await?;
    w.write_u8(req.auth_type).await?;
    w.write_all(&req.token).await?;
    let pad_len = u8::try_from(req.padding.len().min(255)).unwrap_or(255);
    w.write_u8(pad_len).await?;
    if pad_len > 0 {
        w.write_all(&req.padding[..pad_len as usize]).await?;
    }
    w.flush().await?;
    Ok(())
}

pub async fn read_auth_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<AuthRequest> {
    let version = r.read_u8().await.context("Failed to read auth version")?;
    if version != PROTOCOL_VERSION {
        bail!("Unsupported protocol version: {}", version);
    }
    let auth_type = r.read_u8().await.context("Failed to read auth type")?;
    let mut token = [0u8; 32];
    r.read_exact(&mut token).await.context("Failed to read auth token")?;
    let pad_len = r.read_u8().await.context("Failed to read auth padding len")? as usize;
    let mut padding = vec![0u8; pad_len];
    if pad_len > 0 {
        r.read_exact(&mut padding).await.context("Failed to read auth padding")?;
    }
    Ok(AuthRequest {
        version,
        auth_type,
        token,
        padding,
    })
}

pub async fn write_auth_response<W: AsyncWrite + Unpin>(w: &mut W, resp: &AuthResponse) -> Result<()> {
    w.write_u8(resp.version).await?;
    w.write_u8(resp.status).await?;
    let pad_len = u8::try_from(resp.padding.len().min(255)).unwrap_or(255);
    w.write_u8(pad_len).await?;
    if pad_len > 0 {
        w.write_all(&resp.padding[..pad_len as usize]).await?;
    }
    w.flush().await?;
    Ok(())
}

pub async fn read_auth_response<R: AsyncRead + Unpin>(r: &mut R) -> Result<AuthResponse> {
    let version = r.read_u8().await.context("Failed to read auth response version")?;
    let status = r.read_u8().await.context("Failed to read auth status")?;
    let pad_len = r.read_u8().await.context("Failed to read auth response padding len")? as usize;
    let mut padding = vec![0u8; pad_len];
    if pad_len > 0 {
        r.read_exact(&mut padding).await.context("Failed to read auth response padding")?;
    }
    Ok(AuthResponse {
        version,
        status,
        padding,
    })
}

pub async fn write_target_addr<W: AsyncWrite + Unpin>(w: &mut W, target: &TargetAddr) -> Result<()> {
    match target {
        TargetAddr::Ip(SocketAddr::V4(v4)) => {
            w.write_u8(ATYP_IPV4).await?;
            w.write_all(&v4.ip().octets()).await?;
            w.write_u16(v4.port()).await?;
        }
        TargetAddr::Ip(SocketAddr::V6(v6)) => {
            w.write_u8(ATYP_IPV6).await?;
            w.write_all(&v6.ip().octets()).await?;
            w.write_u16(v6.port()).await?;
        }
        TargetAddr::Domain(domain, port) => {
            w.write_u8(ATYP_DOMAIN).await?;
            let domain_bytes = domain.as_bytes();
            if domain_bytes.len() > 255 {
                bail!("Domain name exceeds 255 bytes limit");
            }
            w.write_u8(domain_bytes.len() as u8).await?;
            w.write_all(domain_bytes).await?;
            w.write_u16(*port).await?;
        }
    }
    Ok(())
}

pub async fn read_target_addr<R: AsyncRead + Unpin>(r: &mut R) -> Result<TargetAddr> {
    let atyp = r.read_u8().await.context("Failed to read address type")?;
    match atyp {
        ATYP_IPV4 => {
            let mut ip_bytes = [0u8; 4];
            r.read_exact(&mut ip_bytes).await.context("Failed to read IPv4 octets")?;
            let port = r.read_u16().await.context("Failed to read port")?;
            Ok(TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip_bytes)), port)))
        }
        ATYP_IPV6 => {
            let mut ip_bytes = [0u8; 16];
            r.read_exact(&mut ip_bytes).await.context("Failed to read IPv6 octets")?;
            let port = r.read_u16().await.context("Failed to read port")?;
            Ok(TargetAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port)))
        }
        ATYP_DOMAIN => {
            let len = r.read_u8().await.context("Failed to read domain length")? as usize;
            let mut domain_bytes = vec![0u8; len];
            r.read_exact(&mut domain_bytes).await.context("Failed to read domain string")?;
            let domain = String::from_utf8(domain_bytes).context("Domain is not valid UTF-8")?;
            let port = r.read_u16().await.context("Failed to read port")?;
            Ok(TargetAddr::Domain(domain, port))
        }
        _ => bail!("Unsupported address type: 0x{:02x}", atyp),
    }
}

pub async fn write_proxy_request<W: AsyncWrite + Unpin>(w: &mut W, req: &ProxyRequest) -> Result<()> {
    w.write_u8(req.cmd).await?;
    write_target_addr(w, &req.target).await?;
    let pad_len = u8::try_from(req.padding.len().min(255)).unwrap_or(255);
    w.write_u8(pad_len).await?;
    if pad_len > 0 {
        w.write_all(&req.padding[..pad_len as usize]).await?;
    }
    w.flush().await?;
    Ok(())
}

pub async fn read_proxy_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<ProxyRequest> {
    let cmd = r.read_u8().await.context("Failed to read proxy cmd")?;
    let target = read_target_addr(r).await?;
    let pad_len = r.read_u8().await.context("Failed to read proxy req padding len")? as usize;
    let mut padding = vec![0u8; pad_len];
    if pad_len > 0 {
        r.read_exact(&mut padding).await.context("Failed to read proxy req padding")?;
    }
    Ok(ProxyRequest {
        cmd,
        target,
        padding,
    })
}

pub async fn write_proxy_response<W: AsyncWrite + Unpin>(w: &mut W, resp: &ProxyResponse) -> Result<()> {
    w.write_u8(resp.status).await?;
    let pad_len = u8::try_from(resp.padding.len().min(255)).unwrap_or(255);
    w.write_u8(pad_len).await?;
    if pad_len > 0 {
        w.write_all(&resp.padding[..pad_len as usize]).await?;
    }
    w.flush().await?;
    Ok(())
}

pub async fn read_proxy_response<R: AsyncRead + Unpin>(r: &mut R) -> Result<ProxyResponse> {
    let status = r.read_u8().await.context("Failed to read proxy status")?;
    let pad_len = r.read_u8().await.context("Failed to read proxy resp padding len")? as usize;
    let mut padding = vec![0u8; pad_len];
    if pad_len > 0 {
        r.read_exact(&mut padding).await.context("Failed to read proxy resp padding")?;
    }
    Ok(ProxyResponse { status, padding })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_auth_codec() {
        let req = AuthRequest::new([42u8; 32]);
        let mut buf = Vec::new();
        write_auth_request(&mut buf, &req).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = read_auth_request(&mut cursor).await.unwrap();
        assert_eq!(req.version, decoded.version);
        assert_eq!(req.auth_type, decoded.auth_type);
        assert_eq!(req.token, decoded.token);
        assert_eq!(req.padding, decoded.padding);

        let resp = AuthResponse::new(STATUS_SUCCESS);
        let mut resp_buf = Vec::new();
        write_auth_response(&mut resp_buf, &resp).await.unwrap();

        let mut resp_cursor = Cursor::new(resp_buf);
        let decoded_resp = read_auth_response(&mut resp_cursor).await.unwrap();
        assert_eq!(resp.version, decoded_resp.version);
        assert_eq!(resp.status, decoded_resp.status);
        assert_eq!(resp.padding, decoded_resp.padding);
    }

    #[tokio::test]
    async fn test_proxy_codec_domain() {
        let target = TargetAddr::Domain("example.com".to_string(), 443);
        let req = ProxyRequest::connect(target.clone());
        let mut buf = Vec::new();
        write_proxy_request(&mut buf, &req).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = read_proxy_request(&mut cursor).await.unwrap();
        assert_eq!(req.cmd, decoded.cmd);
        assert_eq!(req.target, decoded.target);
        assert_eq!(req.padding, decoded.padding);

        let resp = ProxyResponse::new(STATUS_SUCCESS);
        let mut resp_buf = Vec::new();
        write_proxy_response(&mut resp_buf, &resp).await.unwrap();

        let mut resp_cursor = Cursor::new(resp_buf);
        let decoded_resp = read_proxy_response(&mut resp_cursor).await.unwrap();
        assert_eq!(resp.status, decoded_resp.status);
        assert_eq!(resp.padding, decoded_resp.padding);
    }

    #[tokio::test]
    async fn test_proxy_codec_ipv4() {
        let addr: SocketAddr = "1.2.3.4:8080".parse().unwrap();
        let target = TargetAddr::Ip(addr);
        let req = ProxyRequest::connect(target);
        let mut buf = Vec::new();
        write_proxy_request(&mut buf, &req).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = read_proxy_request(&mut cursor).await.unwrap();
        assert_eq!(req.cmd, decoded.cmd);
        assert_eq!(req.target, decoded.target);
    }
}
