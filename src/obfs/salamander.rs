use blake2::{Blake2b512, Digest};
use quinn::udp::{RecvMeta, Transmit, UdpSocketState};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::fmt::Debug;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use tokio::io::Interest;

/// Salamander-style symmetric XOR packet scrambler/unscrambler.
#[derive(Debug, Clone)]
pub struct SalamanderObfuscator {
    keystream_cache: Vec<u8>,
}

impl SalamanderObfuscator {
    pub fn new(key: &str) -> Self {
        // Precompute a 2048-byte keystream from the secret key using BLAKE2b-512 in counter mode
        let mut keystream = Vec::with_capacity(2048);
        let key_bytes = key.as_bytes();
        let mut counter: u32 = 0;
        while keystream.len() < 2048 {
            let mut hasher = Blake2b512::new();
            hasher.update(b"quicproxy-salamander-v1");
            hasher.update(key_bytes);
            hasher.update(&counter.to_be_bytes());
            let hash = hasher.finalize();
            keystream.extend_from_slice(&hash);
            counter += 1;
        }
        Self {
            keystream_cache: keystream,
        }
    }

    /// Scramble a packet buffer in place.
    pub fn scramble(&self, buf: &mut [u8]) {
        let len = buf.len().min(self.keystream_cache.len());
        for i in 0..len {
            buf[i] ^= self.keystream_cache[i];
        }
    }

    /// Unscramble is identical to scramble because XOR is self-inverse.
    pub fn unscramble(&self, buf: &mut [u8]) {
        self.scramble(buf);
    }
}

/// Quinn AsyncUdpSocket implementation wrapping a Tokio UdpSocket with Salamander XOR obfuscation.
#[derive(Debug)]
pub struct ObfuscatedUdpSocket {
    io: Arc<tokio::net::UdpSocket>,
    inner: UdpSocketState,
    obfuscator: SalamanderObfuscator,
}

impl ObfuscatedUdpSocket {
    pub fn new(socket: std::net::UdpSocket, obfs_key: &str) -> io::Result<Self> {
        let inner = UdpSocketState::new((&socket).into())?;
        socket.set_nonblocking(true)?;
        let io = Arc::new(tokio::net::UdpSocket::from_std(socket)?);
        let obfuscator = SalamanderObfuscator::new(obfs_key);
        Ok(Self {
            io,
            inner,
            obfuscator,
        })
    }

    pub fn bind(addr: SocketAddr, obfs_key: &str) -> io::Result<Self> {
        let std_socket = std::net::UdpSocket::bind(addr)?;
        Self::new(std_socket, obfs_key)
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

impl AsyncUdpSocket for ObfuscatedUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(TokioPoller {
            io: Arc::clone(&self.io),
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let mut scrambled_data = transmit.contents.to_vec();
        self.obfuscator.scramble(&mut scrambled_data);

        let scrambled_transmit = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &scrambled_data,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        };

        self.io.try_io(Interest::WRITABLE, || {
            self.inner.send((&self.io).into(), &scrambled_transmit)
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
                for (i, meta_item) in meta[..res].iter().enumerate() {
                    let len = meta_item.len.min(bufs[i].len());
                    let slice = &mut bufs[i][..len];
                    self.obfuscator.unscramble(slice);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salamander_roundtrip() {
        let obfs = SalamanderObfuscator::new("my-secret-key-1234");
        let original =
            b"QUIC packet header invariant test: \x80\x00\x00\x01 payload payload payload";
        let mut buf = original.to_vec();

        // After scramble, buffer should not equal original
        obfs.scramble(&mut buf);
        assert_ne!(buf, original);

        // After unscramble, buffer must be identical to original
        obfs.unscramble(&mut buf);
        assert_eq!(buf, original);
    }

    #[test]
    fn test_different_keys_differ() {
        let obfs1 = SalamanderObfuscator::new("key-a");
        let obfs2 = SalamanderObfuscator::new("key-b");
        let original = b"Sample packet content";

        let mut buf1 = original.to_vec();
        let mut buf2 = original.to_vec();

        obfs1.scramble(&mut buf1);
        obfs2.scramble(&mut buf2);

        assert_ne!(buf1, buf2);
    }
}
