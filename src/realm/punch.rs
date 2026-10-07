use anyhow::{Context, Result, bail};
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::time::{Instant, timeout};

pub const MAX_PUNCH_PADDING: usize = 1024;
pub const PUNCH_SALT_LEN: usize = 8;
pub const PUNCH_HEADER_LEN: usize = 25; // 8 magic + 1 type + 16 nonce
pub const PUNCH_MIN_WIRE_LEN: usize = PUNCH_SALT_LEN + PUNCH_HEADER_LEN; // 33
pub const PUNCH_MAX_WIRE_LEN: usize = PUNCH_MIN_WIRE_LEN + MAX_PUNCH_PADDING; // 1057

pub const PUNCH_MAGIC: [u8; 8] = *b"HYRLMv1\0";
pub const PUNCH_NONCE_SIZE: usize = 16;
pub const PUNCH_OBFS_KEY_SIZE: usize = 32;

pub const DEFAULT_PUNCH_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_PUNCH_INTERVAL: Duration = Duration::from_millis(100);

const SYMMETRIC_NAT_PORT_GAP: u16 = 4;
const SYMMETRIC_NAT_EXTRA_PORTS: u16 = 4;
const SYMMETRIC_NAT_MAX_PORTS_PER_HOST: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PunchPacketType {
    Hello = 0x01,
    Ack = 0x02,
}

impl PunchPacketType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(PunchPacketType::Hello),
            0x02 => Some(PunchPacketType::Ack),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchPacket {
    pub packet_type: PunchPacketType,
    pub padding_length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PunchMetadata {
    pub nonce: String,
    pub obfs: String,
}

impl PunchMetadata {
    pub fn new_random() -> Self {
        let mut rng = rand::rng();
        let mut nonce_bytes = [0u8; PUNCH_NONCE_SIZE];
        let mut obfs_bytes = [0u8; PUNCH_OBFS_KEY_SIZE];
        rng.fill(&mut nonce_bytes);
        rng.fill(&mut obfs_bytes);
        Self {
            nonce: hex::encode(nonce_bytes),
            obfs: hex::encode(obfs_bytes),
        }
    }

    pub fn decode_bytes(&self) -> Result<([u8; PUNCH_NONCE_SIZE], [u8; PUNCH_OBFS_KEY_SIZE])> {
        let nonce_vec = hex::decode(&self.nonce).context("invalid hex in punch nonce")?;
        if nonce_vec.len() != PUNCH_NONCE_SIZE {
            bail!("invalid punch nonce length (expected {})", PUNCH_NONCE_SIZE);
        }
        let obfs_vec = hex::decode(&self.obfs).context("invalid hex in punch obfs key")?;
        if obfs_vec.len() != PUNCH_OBFS_KEY_SIZE {
            bail!(
                "invalid punch obfs key length (expected {})",
                PUNCH_OBFS_KEY_SIZE
            );
        }

        let mut nonce = [0u8; PUNCH_NONCE_SIZE];
        let mut obfs = [0u8; PUNCH_OBFS_KEY_SIZE];
        nonce.copy_from_slice(&nonce_vec);
        obfs.copy_from_slice(&obfs_vec);
        Ok((nonce, obfs))
    }
}

pub fn encode_punch_packet(packet_type: PunchPacketType, meta: &PunchMetadata) -> Result<Vec<u8>> {
    let (nonce, obfs_key) = meta.decode_bytes()?;
    let mut rng = rand::rng();
    let padding_len: usize = rng.random_range(0..=MAX_PUNCH_PADDING);

    let mut plain = vec![0u8; PUNCH_HEADER_LEN + padding_len];
    plain[..8].copy_from_slice(&PUNCH_MAGIC);
    plain[8] = packet_type as u8;
    plain[9..25].copy_from_slice(&nonce);
    if padding_len > 0 {
        rng.fill(&mut plain[25..]);
    }

    let mut salt = [0u8; PUNCH_SALT_LEN];
    rng.fill(&mut salt);

    let mut packet = Vec::with_capacity(PUNCH_SALT_LEN + plain.len());
    packet.extend_from_slice(&salt);
    packet.extend_from_slice(&plain);

    xor_punch_packet(&mut packet[PUNCH_SALT_LEN..], &obfs_key, &salt);
    Ok(packet)
}

pub fn decode_punch_packet(packet: &[u8], meta: &PunchMetadata) -> Result<PunchPacket> {
    if packet.len() < PUNCH_MIN_WIRE_LEN {
        bail!("punch packet too short");
    }
    if packet.len() > PUNCH_MAX_WIRE_LEN {
        bail!("punch packet too long");
    }

    let (nonce, obfs_key) = meta.decode_bytes()?;
    let salt = &packet[..PUNCH_SALT_LEN];
    let mut plain = packet[PUNCH_SALT_LEN..].to_vec();

    xor_punch_packet(&mut plain, &obfs_key, salt);

    if plain[..8] != PUNCH_MAGIC {
        bail!("bad punch packet magic");
    }

    let packet_type = PunchPacketType::from_u8(plain[8]).context("unknown punch packet type")?;

    if plain[9..25] != nonce {
        bail!("punch packet nonce mismatch");
    }

    let padding_length = plain.len() - PUNCH_HEADER_LEN;
    Ok(PunchPacket {
        packet_type,
        padding_length,
    })
}

fn xor_punch_packet(payload: &mut [u8], obfs_key: &[u8; PUNCH_OBFS_KEY_SIZE], salt: &[u8]) {
    let mut hasher = Sha256::new();
    hasher.update(obfs_key);
    hasher.update(salt);
    let mask = hasher.finalize();

    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i % mask.len()];
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddrFamily {
    #[default]
    Any,
    IPv4,
    IPv6,
}

impl AddrFamily {
    pub fn allows(&self, addr: IpAddr) -> bool {
        match self {
            AddrFamily::Any => true,
            AddrFamily::IPv4 => addr.is_ipv4(),
            AddrFamily::IPv6 => addr.is_ipv6(),
        }
    }
}

pub fn candidate_punch_addrs(
    local_addrs: &[SocketAddr],
    peer_addrs: &[SocketAddr],
    family: AddrFamily,
) -> Vec<SocketAddr> {
    let (allow_v4, allow_v6) = match family {
        AddrFamily::IPv4 => (true, false),
        AddrFamily::IPv6 => (false, true),
        AddrFamily::Any => {
            let mut v4 = false;
            let mut v6 = false;
            for a in local_addrs {
                if a.is_ipv4() {
                    v4 = true;
                } else if a.is_ipv6() {
                    v6 = true;
                }
            }
            if !v4 && !v6 { (true, true) } else { (v4, v6) }
        }
    };

    let mut seen = HashSet::new();
    let mut candidates = Vec::new();

    for &addr in peer_addrs {
        if addr.port() == 0 {
            continue;
        }
        if addr.is_ipv4() && !allow_v4 {
            continue;
        }
        if addr.is_ipv6() && !allow_v6 {
            continue;
        }
        if seen.insert(addr) {
            candidates.push(addr);
        }
    }

    expand_symmetric_nat_candidates(&mut candidates, &mut seen);
    candidates.sort_by_key(|a| a.to_string());
    candidates
}

fn expand_symmetric_nat_candidates(
    candidates: &mut Vec<SocketAddr>,
    seen: &mut HashSet<SocketAddr>,
) {
    let mut ports_by_ip: HashMap<IpAddr, Vec<u16>> = HashMap::new();
    for &addr in candidates.iter() {
        if addr.is_ipv4() {
            ports_by_ip.entry(addr.ip()).or_default().push(addr.port());
        }
    }

    for (ip, mut ports) in ports_by_ip {
        ports.sort_unstable();
        ports.dedup();

        if !predictable_port_group(&ports) {
            continue;
        }

        let start = ports[0];
        let last = ports[ports.len() - 1];
        let end = (last as u32 + SYMMETRIC_NAT_EXTRA_PORTS as u32).min(65535) as u16;

        let mut added = 0;
        for port in start..=end {
            if added >= SYMMETRIC_NAT_MAX_PORTS_PER_HOST {
                break;
            }
            let candidate = SocketAddr::new(ip, port);
            if seen.insert(candidate) {
                candidates.push(candidate);
                added += 1;
            }
        }
    }
}

fn predictable_port_group(ports: &[u16]) -> bool {
    if ports.len() < 2 {
        return false;
    }
    for i in 1..ports.len() {
        if ports[i].saturating_sub(ports[i - 1]) > SYMMETRIC_NAT_PORT_GAP {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone)]
pub struct PunchConfig {
    pub timeout: Duration,
    pub interval: Duration,
    pub family: AddrFamily,
}

impl Default for PunchConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_PUNCH_TIMEOUT,
            interval: DEFAULT_PUNCH_INTERVAL,
            family: AddrFamily::Any,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchResult {
    pub peer_addr: SocketAddr,
    pub packet: PunchPacket,
}

/// Run client-side UDP hole punch on the socket before handing it over to QUIC.
pub async fn punch(
    socket: &tokio::net::UdpSocket,
    local_addrs: &[SocketAddr],
    peer_addrs: &[SocketAddr],
    meta: &PunchMetadata,
    config: &PunchConfig,
) -> Result<PunchResult> {
    let candidates = candidate_punch_addrs(local_addrs, peer_addrs, config.family);
    if candidates.is_empty() {
        bail!("no compatible peer addresses for punch");
    }

    let hello_packet = encode_punch_packet(PunchPacketType::Hello, meta)?;
    let ack_packet = encode_punch_packet(PunchPacketType::Ack, meta)?;

    let deadline = Instant::now() + config.timeout;
    let mut next_send = Instant::now();
    let mut buf = [0u8; PUNCH_MAX_WIRE_LEN];

    loop {
        let now = Instant::now();
        if now >= deadline {
            bail!("UDP punch timed out");
        }

        if now >= next_send {
            for &candidate in &candidates {
                let _ = socket.send_to(&hello_packet, candidate).await;
            }
            next_send = now + config.interval;
        }

        let time_until_send = next_send.saturating_duration_since(now);
        let time_until_deadline = deadline.saturating_duration_since(now);
        let read_wait = time_until_send.min(time_until_deadline);

        match timeout(read_wait, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                if let Ok(packet) = decode_punch_packet(&buf[..n], meta) {
                    if packet.packet_type == PunchPacketType::Hello {
                        // Immediately reply with ACK to finalize punch
                        let _ = socket.send_to(&ack_packet, from).await;
                    }
                    return Ok(PunchResult {
                        peer_addr: from,
                        packet,
                    });
                }
            }
            Ok(Err(e)) => {
                tracing::debug!("socket error during punch recv: {}", e);
            }
            Err(_) => {
                // Timeout on read; will loop and send again
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_punch_packet_roundtrip() {
        let meta = PunchMetadata::new_random();

        for p_type in [PunchPacketType::Hello, PunchPacketType::Ack] {
            let encoded = encode_punch_packet(p_type, &meta).unwrap();
            assert!(encoded.len() >= PUNCH_MIN_WIRE_LEN);
            assert!(encoded.len() <= PUNCH_MAX_WIRE_LEN);

            let decoded = decode_punch_packet(&encoded, &meta).unwrap();
            assert_eq!(decoded.packet_type, p_type);
        }
    }

    #[test]
    fn test_punch_packet_bad_magic_or_nonce() {
        let meta1 = PunchMetadata::new_random();
        let meta2 = PunchMetadata::new_random();

        let encoded = encode_punch_packet(PunchPacketType::Hello, &meta1).unwrap();
        // Decoding with different metadata must fail
        assert!(decode_punch_packet(&encoded, &meta2).is_err());

        // Corrupt packet
        let mut corrupt = encoded.clone();
        corrupt[10] ^= 0xFF;
        assert!(decode_punch_packet(&corrupt, &meta1).is_err());
    }

    #[test]
    fn test_predictable_port_group() {
        assert!(predictable_port_group(&[1000, 1002, 1005]));
        assert!(!predictable_port_group(&[1000, 1006])); // gap is 6 > 4
        assert!(!predictable_port_group(&[1000])); // < 2
    }

    #[test]
    fn test_symmetric_nat_candidate_expansion() {
        let mut candidates = vec![
            "198.51.100.1:2000".parse().unwrap(),
            "198.51.100.1:2002".parse().unwrap(),
        ];
        let mut seen = candidates.iter().cloned().collect();
        expand_symmetric_nat_candidates(&mut candidates, &mut seen);

        // Should expand up to 2002 + 4 = 2006
        assert!(candidates.contains(&"198.51.100.1:2001".parse().unwrap()));
        assert!(candidates.contains(&"198.51.100.1:2003".parse().unwrap()));
        assert!(candidates.contains(&"198.51.100.1:2006".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_punch_between_two_sockets() {
        let s1 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s2 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let addr1 = s1.local_addr().unwrap();
        let addr2 = s2.local_addr().unwrap();

        let meta = PunchMetadata::new_random();
        let config = PunchConfig {
            timeout: Duration::from_secs(2),
            interval: Duration::from_millis(20),
            family: AddrFamily::IPv4,
        };

        let meta_clone = meta.clone();
        let cfg_clone = config.clone();

        let h1 =
            tokio::spawn(
                async move { punch(&s1, &[addr1], &[addr2], &meta_clone, &cfg_clone).await },
            );

        let h2 = tokio::spawn(async move { punch(&s2, &[addr2], &[addr1], &meta, &config).await });

        let (r1, r2) = tokio::join!(h1, h2);
        let res1 = r1.unwrap().unwrap();
        let res2 = r2.unwrap().unwrap();

        assert_eq!(res1.peer_addr, addr2);
        assert_eq!(res2.peer_addr, addr1);
    }
}
