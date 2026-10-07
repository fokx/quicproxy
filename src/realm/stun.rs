use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::time::{Instant, timeout};

pub const DEFAULT_REALM_STUN_SERVERS: &[&str] = &[
    "stun.nextcloud.com:3478",
    "stun.sip.us:3478",
    "global.stun.twilio.com:3478",
];

pub const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
pub const STUN_HEADER_LEN: usize = 20;
pub const STUN_TRANSACTION_ID_LEN: usize = 12;

pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_SUCCESS: u16 = 0x0101;

pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

pub const DEFAULT_STUN_TIMEOUT: Duration = Duration::from_secs(4);

pub type TransactionId = [u8; STUN_TRANSACTION_ID_LEN];

/// Checks if a UDP datagram conforms to the RFC 5389 STUN message header.
pub fn is_stun_message(packet: &[u8]) -> bool {
    if packet.len() < STUN_HEADER_LEN {
        return false;
    }
    // Most significant 2 bits must be 0
    if (packet[0] & 0xC0) != 0 {
        return false;
    }
    // Magic cookie check
    packet[4..8] == STUN_MAGIC_COOKIE
}

/// Builds an RFC 5389 Binding Request datagram (20 bytes).
pub fn build_binding_request(tx_id: TransactionId) -> [u8; STUN_HEADER_LEN] {
    let mut msg = [0u8; STUN_HEADER_LEN];
    msg[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    msg[2..4].copy_from_slice(&0u16.to_be_bytes()); // 0 attributes length
    msg[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
    msg[8..20].copy_from_slice(&tx_id);
    msg
}

/// Parses an RFC 5389 Binding Success Response, returning the transaction ID and mapped socket address.
pub fn parse_binding_response(packet: &[u8]) -> Result<(TransactionId, SocketAddr)> {
    if packet.len() < STUN_HEADER_LEN {
        bail!("STUN message too short");
    }
    if !is_stun_message(packet) {
        bail!("not a valid STUN message");
    }

    let msg_type = u16::from_be_bytes([packet[0], packet[1]]);
    if msg_type != BINDING_SUCCESS {
        bail!(
            "not a STUN binding success response (type: 0x{:04x})",
            msg_type
        );
    }

    let msg_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if STUN_HEADER_LEN + msg_len > packet.len() {
        bail!("STUN message attributes truncated");
    }

    let mut tx_id = [0u8; STUN_TRANSACTION_ID_LEN];
    tx_id.copy_from_slice(&packet[8..20]);

    let mut offset = STUN_HEADER_LEN;
    let end = STUN_HEADER_LEN + msg_len;

    let mut xor_mapped: Option<SocketAddr> = None;
    let mut plain_mapped: Option<SocketAddr> = None;

    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let attr_len = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > end {
            break;
        }

        let attr_val = &packet[offset..offset + attr_len];
        if attr_type == ATTR_XOR_MAPPED_ADDRESS && attr_val.len() >= 4 {
            if let Ok(addr) = parse_xor_mapped_address(attr_val, &tx_id) {
                xor_mapped = Some(addr);
            }
        } else if attr_type == ATTR_MAPPED_ADDRESS && attr_val.len() >= 4 {
            if let Ok(addr) = parse_mapped_address(attr_val) {
                plain_mapped = Some(addr);
            }
        }

        // RFC 5389: Attributes are padded to 4-byte boundaries
        let padded_len = (attr_len + 3) & !3;
        offset += padded_len;
    }

    if let Some(addr) = xor_mapped.or(plain_mapped) {
        Ok((tx_id, addr))
    } else {
        bail!("STUN response did not contain mapped address");
    }
}

fn parse_xor_mapped_address(val: &[u8], tx_id: &TransactionId) -> Result<SocketAddr> {
    let family = val[1];
    let x_port = u16::from_be_bytes([val[2], val[3]]);
    let port = x_port ^ 0x2112;

    match family {
        0x01 => {
            // IPv4
            if val.len() < 8 {
                bail!("XOR-MAPPED-ADDRESS IPv4 value too short");
            }
            let x_ip = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
            let magic = u32::from_be_bytes(STUN_MAGIC_COOKIE);
            let ip = Ipv4Addr::from(x_ip ^ magic);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            // IPv6
            if val.len() < 20 {
                bail!("XOR-MAPPED-ADDRESS IPv6 value too short");
            }
            let mut xor_key = [0u8; 16];
            xor_key[..4].copy_from_slice(&STUN_MAGIC_COOKIE);
            xor_key[4..].copy_from_slice(tx_id);

            let mut ip_bytes = [0u8; 16];
            for i in 0..16 {
                ip_bytes[i] = val[4 + i] ^ xor_key[i];
            }
            let ip = Ipv6Addr::from(ip_bytes);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        other => bail!(
            "unsupported address family in STUN response: 0x{:02x}",
            other
        ),
    }
}

fn parse_mapped_address(val: &[u8]) -> Result<SocketAddr> {
    let family = val[1];
    let port = u16::from_be_bytes([val[2], val[3]]);

    match family {
        0x01 => {
            if val.len() < 8 {
                bail!("MAPPED-ADDRESS IPv4 value too short");
            }
            let ip = Ipv4Addr::new(val[4], val[5], val[6], val[7]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            if val.len() < 20 {
                bail!("MAPPED-ADDRESS IPv6 value too short");
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&val[4..20]);
            let ip = Ipv6Addr::from(ip_bytes);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        other => bail!(
            "unsupported address family in STUN response: 0x{:02x}",
            other
        ),
    }
}

/// Helper to parse "host" or "host:port", defaulting port to 3478.
pub fn parse_stun_server_endpoint(server: &str) -> (String, u16) {
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return (addr.ip().to_string(), addr.port());
    }
    if let Some((h, p)) = server.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (
                h.trim_start_matches('[').trim_end_matches(']').to_string(),
                port,
            );
        }
    }
    (
        server
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string(),
        3478,
    )
}

/// Queries configured STUN servers and returns discovered public addresses.
pub async fn discover(
    socket: &tokio::net::UdpSocket,
    servers: &[String],
    stun_timeout: Duration,
    family: super::punch::AddrFamily,
) -> Result<Vec<SocketAddr>> {
    if servers.is_empty() {
        bail!("at least one STUN server is required");
    }

    let mut stun_targets = Vec::new();
    for s in servers {
        let (host, port) = parse_stun_server_endpoint(s);
        let target_str = format!("{}:{}", host, port);
        if let Ok(addrs) = tokio::net::lookup_host(&target_str).await {
            for addr in addrs {
                if family.allows(addr.ip()) {
                    stun_targets.push(addr);
                }
            }
        }
    }

    if stun_targets.is_empty() {
        bail!("no STUN server addresses match the local socket family");
    }

    let mut pending_txs: HashMap<TransactionId, SocketAddr> = HashMap::new();

    for &target in &stun_targets {
        let tx_id: TransactionId = rand::random::<[u8; STUN_TRANSACTION_ID_LEN]>();
        let req = build_binding_request(tx_id);
        if socket.send_to(&req, target).await.is_ok() {
            pending_txs.insert(tx_id, target);
        }
    }

    if pending_txs.is_empty() {
        bail!("failed to send STUN binding requests");
    }

    let deadline = Instant::now() + stun_timeout;
    let mut results: HashSet<SocketAddr> = HashSet::new();
    let mut buf = [0u8; 1500];

    while !pending_txs.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;

        match timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _from))) => {
                if let Ok((tx_id, mapped_addr)) = parse_binding_response(&buf[..n]) {
                    if pending_txs.remove(&tx_id).is_some() {
                        results.insert(mapped_addr);
                    }
                }
            }
            Ok(Err(_)) => break,
            Err(_) => break, // timeout
        }
    }

    if results.is_empty() {
        bail!("no STUN responses received");
    }

    let mut out: Vec<SocketAddr> = results.into_iter().collect();
    out.sort_by_key(|a| a.to_string());
    Ok(out)
}

/// Queries configured STUN servers and returns discovered public addresses via PunchUdpSocket demux.
pub async fn discover_with_demux(
    socket: &super::punch_socket::PunchUdpSocket,
    servers: &[String],
    stun_timeout: Duration,
    family: super::punch::AddrFamily,
) -> Result<Vec<SocketAddr>> {
    if servers.is_empty() {
        bail!("at least one STUN server is required");
    }

    let mut stun_targets = Vec::new();
    for s in servers {
        let (host, port) = parse_stun_server_endpoint(s);
        let target_str = format!("{}:{}", host, port);
        if let Ok(addrs) = tokio::net::lookup_host(&target_str).await {
            for addr in addrs {
                if family.allows(addr.ip()) {
                    stun_targets.push(addr);
                }
            }
        }
    }

    if stun_targets.is_empty() {
        bail!("no STUN server addresses match the local socket family");
    }

    let mut pending_txs: HashMap<TransactionId, SocketAddr> = HashMap::new();
    let mut stun_rx = socket.state().subscribe_stun();

    for &target in &stun_targets {
        let tx_id: TransactionId = rand::random::<[u8; STUN_TRANSACTION_ID_LEN]>();
        let req = build_binding_request(tx_id);
        if socket.send_to(&req, target).await.is_ok() {
            pending_txs.insert(tx_id, target);
        }
    }

    if pending_txs.is_empty() {
        bail!("failed to send STUN binding requests");
    }

    let deadline = Instant::now() + stun_timeout;
    let mut results: HashSet<SocketAddr> = HashSet::new();

    while !pending_txs.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;

        match timeout(remaining, stun_rx.recv()).await {
            Ok(Ok((tx_id, mapped_addr))) => {
                if pending_txs.remove(&tx_id).is_some() {
                    results.insert(mapped_addr);
                }
            }
            Ok(Err(_)) => break,
            Err(_) => break, // timeout
        }
    }

    if results.is_empty() {
        bail!("no STUN responses received");
    }

    let mut out: Vec<SocketAddr> = results.into_iter().collect();
    out.sort_by_key(|a| a.to_string());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_binding_roundtrip() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let req = build_binding_request(tx_id);

        assert!(is_stun_message(&req));
        assert_eq!(&req[8..20], &tx_id);

        // Build mock BindingSuccess response with XOR-MAPPED-ADDRESS IPv4: 203.0.113.5:12345
        let mapped_ip = Ipv4Addr::new(203, 0, 113, 5);
        let mapped_port = 12345u16;

        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        resp.extend_from_slice(&12u16.to_be_bytes()); // attr length: 12
        resp.extend_from_slice(&STUN_MAGIC_COOKIE);
        resp.extend_from_slice(&tx_id);

        // XOR-MAPPED-ADDRESS attribute:
        resp.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        resp.extend_from_slice(&8u16.to_be_bytes()); // attr len
        resp.push(0); // reserved
        resp.push(1); // IPv4
        resp.extend_from_slice(&(mapped_port ^ 0x2112).to_be_bytes());
        let xor_ip = u32::from(mapped_ip) ^ u32::from_be_bytes(STUN_MAGIC_COOKIE);
        resp.extend_from_slice(&xor_ip.to_be_bytes());

        let (parsed_tx, parsed_addr) = parse_binding_response(&resp).unwrap();
        assert_eq!(parsed_tx, tx_id);
        assert_eq!(
            parsed_addr,
            SocketAddr::new(IpAddr::V4(mapped_ip), mapped_port)
        );
    }

    #[tokio::test]
    async fn test_stun_discover_with_mock_server() {
        let server_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();

        let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_sock.local_addr().unwrap();

        // Spawn mock STUN server
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            if let Ok((n, from)) = server_sock.recv_from(&mut buf).await {
                if is_stun_message(&buf[..n]) {
                    let mut tx_id = [0u8; 12];
                    tx_id.copy_from_slice(&buf[8..20]);

                    // Send response with sender's mapped address
                    let mut resp = Vec::new();
                    resp.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
                    resp.extend_from_slice(&12u16.to_be_bytes());
                    resp.extend_from_slice(&STUN_MAGIC_COOKIE);
                    resp.extend_from_slice(&tx_id);

                    resp.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
                    resp.extend_from_slice(&8u16.to_be_bytes());
                    resp.push(0);
                    resp.push(1);
                    resp.extend_from_slice(&(from.port() ^ 0x2112).to_be_bytes());
                    if let IpAddr::V4(v4) = from.ip() {
                        let xor_ip = u32::from(v4) ^ u32::from_be_bytes(STUN_MAGIC_COOKIE);
                        resp.extend_from_slice(&xor_ip.to_be_bytes());
                    }
                    let _ = server_sock.send_to(&resp, from).await;
                }
            }
        });

        let addrs = discover(
            &client_sock,
            &[server_addr.to_string()],
            Duration::from_secs(2),
            super::super::punch::AddrFamily::IPv4,
        )
        .await
        .unwrap();

        assert_eq!(addrs, vec![client_addr]);
    }
}
