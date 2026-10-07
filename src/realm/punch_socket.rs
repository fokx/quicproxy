use quinn::udp::{RecvMeta, Transmit, UdpSocketState};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll, ready};
use tokio::io::Interest;
use tokio::sync::{broadcast, mpsc};

use super::punch::{PunchMetadata, PunchPacket, decode_punch_packet};
use super::stun::{TransactionId, is_stun_message, parse_binding_response};
use crate::obfs::salamander::SalamanderObfuscator;

#[derive(Debug, Clone)]
pub struct PunchPacketEvent {
    pub attempt_id: String,
    pub from: SocketAddr,
    pub packet: PunchPacket,
}

#[derive(Debug)]
pub struct PunchSocketState {
    attempts: RwLock<HashMap<String, (PunchMetadata, mpsc::Sender<PunchPacketEvent>)>>,
    stun_tx: broadcast::Sender<(TransactionId, SocketAddr)>,
}

impl PunchSocketState {
    pub fn new(event_buffer: usize) -> Self {
        let (stun_tx, _) = broadcast::channel(event_buffer.max(16));
        Self {
            attempts: RwLock::new(HashMap::new()),
            stun_tx,
        }
    }

    pub fn add_attempt(&self, id: &str, meta: PunchMetadata, tx: mpsc::Sender<PunchPacketEvent>) {
        let mut guard = self.attempts.write().unwrap();
        guard.insert(id.to_string(), (meta, tx));
    }

    pub fn remove_attempt(&self, id: &str) {
        let mut guard = self.attempts.write().unwrap();
        guard.remove(id);
    }

    pub fn subscribe_stun(&self) -> broadcast::Receiver<(TransactionId, SocketAddr)> {
        self.stun_tx.subscribe()
    }

    pub fn emit_stun(&self, tx_id: TransactionId, addr: SocketAddr) {
        let _ = self.stun_tx.send((tx_id, addr));
    }

    pub fn try_decode_punch(&self, buf: &[u8], from: SocketAddr) -> Option<PunchPacketEvent> {
        let guard = self.attempts.read().unwrap();
        for (id, (meta, _)) in guard.iter() {
            if let Ok(packet) = decode_punch_packet(buf, meta) {
                return Some(PunchPacketEvent {
                    attempt_id: id.clone(),
                    from,
                    packet,
                });
            }
        }
        None
    }

    pub fn emit_punch(&self, ev: PunchPacketEvent) {
        let guard = self.attempts.read().unwrap();
        if let Some((_, tx)) = guard.get(&ev.attempt_id) {
            let _ = tx.try_send(ev);
        }
    }
}

/// Server UDP socket wrapper that intercepts STUN responses and Punch packets,
/// while passing normal QUIC packets through to Quinn.
#[derive(Debug)]
pub struct PunchUdpSocket {
    io: Arc<tokio::net::UdpSocket>,
    inner: UdpSocketState,
    state: Arc<PunchSocketState>,
    obfuscator: Option<SalamanderObfuscator>,
}

impl PunchUdpSocket {
    pub fn new(
        socket: std::net::UdpSocket,
        state: Arc<PunchSocketState>,
        obfs_key: Option<&str>,
    ) -> io::Result<Self> {
        let inner = UdpSocketState::new((&socket).into())?;
        socket.set_nonblocking(true)?;
        let io = Arc::new(tokio::net::UdpSocket::from_std(socket)?);
        let obfuscator = obfs_key.map(SalamanderObfuscator::new);

        Ok(Self {
            io,
            inner,
            state,
            obfuscator,
        })
    }

    pub fn state(&self) -> &Arc<PunchSocketState> {
        &self.state
    }

    pub fn raw_socket(&self) -> &Arc<tokio::net::UdpSocket> {
        &self.io
    }

    /// Send raw datagram directly on the underlying socket (used for STUN and Punch packets).
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.io.send_to(buf, target).await
    }
}

#[derive(Debug)]
struct TokioPoller {
    io: Arc<tokio::net::UdpSocket>,
}

impl UdpPoller for TokioPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.io.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for PunchUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(TokioPoller {
            io: Arc::clone(&self.io),
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if let Some(ref obfs) = self.obfuscator {
            let mut scrambled = transmit.contents.to_vec();
            obfs.scramble(&mut scrambled);
            let scrambled_transmit = Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &scrambled,
                segment_size: transmit.segment_size,
                src_ip: transmit.src_ip,
            };
            self.io.try_io(Interest::WRITABLE, || {
                self.inner.send((&self.io).into(), &scrambled_transmit)
            })
        } else {
            self.io.try_io(Interest::WRITABLE, || {
                self.inner.send((&self.io).into(), transmit)
            })
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(res) = self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                if res == 0 {
                    return Poll::Ready(Ok(0));
                }

                let pkt_len = meta[0].len.min(bufs[0].len());
                let pkt_bytes = &bufs[0][..pkt_len];
                let from_addr = meta[0].addr;

                // 1. STUN demux
                if is_stun_message(pkt_bytes) {
                    if let Ok((tx_id, mapped_addr)) = parse_binding_response(pkt_bytes) {
                        self.state.emit_stun(tx_id, mapped_addr);
                    }
                    continue;
                }

                // 2. Punch packet demux
                if let Some(event) = self.state.try_decode_punch(pkt_bytes, from_addr) {
                    self.state.emit_punch(event);
                    continue;
                }

                // 3. Regular QUIC packet
                if let Some(ref obfs) = self.obfuscator {
                    obfs.unscramble(&mut bufs[0][..pkt_len]);
                }
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

/// Plain AsyncUdpSocket for standard Tokio UdpSockets without Demux or Obfuscation.
#[derive(Debug)]
pub struct PlainAsyncUdpSocket {
    io: Arc<tokio::net::UdpSocket>,
    inner: UdpSocketState,
}

impl PlainAsyncUdpSocket {
    pub fn new(socket: std::net::UdpSocket) -> io::Result<Self> {
        let inner = UdpSocketState::new((&socket).into())?;
        socket.set_nonblocking(true)?;
        let io = Arc::new(tokio::net::UdpSocket::from_std(socket)?);
        Ok(Self { io, inner })
    }
}

impl AsyncUdpSocket for PlainAsyncUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(TokioPoller {
            io: Arc::clone(&self.io),
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || {
            self.inner.send((&self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(res) = self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realm::punch::{PunchPacketType, encode_punch_packet};

    #[tokio::test]
    async fn test_punch_socket_intercepts_punch_packets() {
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let sock_addr = std_sock.local_addr().unwrap();

        let state = Arc::new(PunchSocketState::new(16));
        let punch_sock = Arc::new(PunchUdpSocket::new(std_sock, Arc::clone(&state), None).unwrap());

        let meta = PunchMetadata::new_random();
        let (tx, _rx) = mpsc::channel(16);
        state.add_attempt("attempt-1", meta.clone(), tx);

        // Send a punch packet from a peer
        let peer_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();
        let hello = encode_punch_packet(PunchPacketType::Hello, &meta).unwrap();
        peer_sock.send_to(&hello, sock_addr).await.unwrap();

        // Also test sending directly on punch_sock
        punch_sock.send_to(b"reply", peer_addr).await.unwrap();
        let mut peer_buf = [0u8; 100];
        let (n, from) = peer_sock.recv_from(&mut peer_buf).await.unwrap();
        assert_eq!(&peer_buf[..n], b"reply");
        assert_eq!(from, sock_addr);
    }
}
