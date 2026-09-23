use anyhow::{bail, Context, Result};
use ring::aead::{self, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, CHACHA20_POLY1305};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::hmac::{Key, HMAC_SHA256, sign};
use ring::rand::SystemRandom;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context as TaskContext, Poll, Waker};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex as TokioMutex};

use super::ProxyStream;
use crate::auth::{generate_auth_token_from_secret, verify_auth_token_from_secret};
use crate::protocol::{
    read_auth_request, read_auth_response, write_auth_request, write_auth_response, AuthRequest,
    AuthResponse, STATUS_AUTH_FAILED, STATUS_SUCCESS,
};

pub const FRAME_TYPE_DATA: u8 = 0x01;
pub const FRAME_TYPE_FIN: u8 = 0x02;
pub const FRAME_TYPE_RST: u8 = 0x03;
pub const FRAME_TYPE_DATAGRAM: u8 = 0x04;

pub const MAX_FRAME_PAYLOAD: usize = 16384;
pub const MAX_STREAM_BUFFER: usize = 65536; // 64KB per-stream backpressure limit
pub const SALT: &[u8] = b"quicproxy-tcp-v1-salt";
pub const INFO: &[u8] = b"quicproxy-tcp-v1-keys";

pub struct CounterNonce(pub u64);

impl NonceSequence for CounterNonce {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        let mut bytes = [0u8; 12];
        bytes[4..12].copy_from_slice(&self.0.to_be_bytes());
        self.0 = self.0.checked_add(1).ok_or(ring::error::Unspecified)?;
        Nonce::try_assume_unique_for_key(&bytes)
    }
}

/// Derive directional keys and exporter secret via HKDF-SHA256
pub fn hkdf_derive_keys(shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let prk_key = Key::new(HMAC_SHA256, SALT);
    let prk = sign(&prk_key, shared_secret);

    let key = Key::new(HMAC_SHA256, prk.as_ref());

    // T(1) -> client_write_key
    let mut step1_input = Vec::with_capacity(INFO.len() + 1);
    step1_input.extend_from_slice(INFO);
    step1_input.push(0x01);
    let t1 = sign(&key, &step1_input);

    // T(2) -> server_write_key
    let mut step2_input = Vec::with_capacity(32 + INFO.len() + 1);
    step2_input.extend_from_slice(t1.as_ref());
    step2_input.extend_from_slice(INFO);
    step2_input.push(0x02);
    let t2 = sign(&key, &step2_input);

    // T(3) -> exporter_secret
    let mut step3_input = Vec::with_capacity(32 + INFO.len() + 1);
    step3_input.extend_from_slice(t2.as_ref());
    step3_input.extend_from_slice(INFO);
    step3_input.push(0x03);
    let t3 = sign(&key, &step3_input);

    let mut client_key = [0u8; 32];
    let mut server_key = [0u8; 32];
    let mut exporter_secret = [0u8; 32];

    client_key.copy_from_slice(t1.as_ref());
    server_key.copy_from_slice(t2.as_ref());
    exporter_secret.copy_from_slice(t3.as_ref());

    (client_key, server_key, exporter_secret)
}

pub struct MuxFrame {
    pub stream_id: u32,
    pub frame_type: u8,
    pub payload: Vec<u8>,
    pub in_flight: Option<(Arc<AtomicUsize>, usize, Arc<StdMutex<Option<Waker>>>)>,
}

#[derive(Debug)]
pub enum StreamEvent {
    Data(Vec<u8>),
    Fin,
    Rst,
}

/// A multiplexed virtual stream operating over a single encrypted TCP connection.
pub struct VirtualStream {
    stream_id: u32,
    tx: mpsc::UnboundedSender<MuxFrame>,
    rx: mpsc::Receiver<StreamEvent>,
    read_buf: Option<Vec<u8>>,
    read_pos: usize,
    in_flight: Arc<AtomicUsize>,
    write_waker: Arc<StdMutex<Option<Waker>>>,
    write_closed: bool,
    read_closed: bool,
    cleanly_closed: bool,
}

impl VirtualStream {
    pub fn new(
        stream_id: u32,
        tx: mpsc::UnboundedSender<MuxFrame>,
        rx: mpsc::Receiver<StreamEvent>,
    ) -> Self {
        Self {
            stream_id,
            tx,
            rx,
            read_buf: None,
            read_pos: 0,
            in_flight: Arc::new(AtomicUsize::new(0)),
            write_waker: Arc::new(StdMutex::new(None)),
            write_closed: false,
            read_closed: false,
            cleanly_closed: false,
        }
    }

    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }
}

impl Drop for VirtualStream {
    fn drop(&mut self) {
        if !self.cleanly_closed && !self.write_closed {
            let _ = self.tx.send(MuxFrame {
                stream_id: self.stream_id,
                frame_type: FRAME_TYPE_RST,
                payload: Vec::new(),
                in_flight: None,
            });
        }
    }
}

impl AsyncRead for VirtualStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();

        loop {
            if let Some(ref data) = this.read_buf {
                let remaining = data.len() - this.read_pos;
                if remaining > 0 {
                    let to_copy = remaining.min(buf.remaining());
                    buf.put_slice(&data[this.read_pos..this.read_pos + to_copy]);
                    this.read_pos += to_copy;
                    if this.read_pos >= data.len() {
                        this.read_buf = None;
                        this.read_pos = 0;
                    }
                    return Poll::Ready(Ok(()));
                } else {
                    this.read_buf = None;
                    this.read_pos = 0;
                }
            }

            if this.read_closed {
                return Poll::Ready(Ok(()));
            }

            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(StreamEvent::Data(data))) => {
                    this.read_buf = Some(data);
                    this.read_pos = 0;
                    // Continue loop to copy
                }
                Poll::Ready(Some(StreamEvent::Fin)) => {
                    this.read_closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(StreamEvent::Rst)) => {
                    this.read_closed = true;
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::ConnectionReset,
                        "Virtual stream reset by peer",
                    )));
                }
                Poll::Ready(None) => {
                    this.read_closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

impl AsyncWrite for VirtualStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();

        if this.write_closed {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "Virtual stream write half is closed",
            )));
        }

        // Check per-stream buffer backpressure
        if this.in_flight.load(Ordering::Relaxed) >= MAX_STREAM_BUFFER {
            *this.write_waker.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let max_payload = MAX_FRAME_PAYLOAD.saturating_sub(5);
        let to_send = buf.len().min(max_payload);

        this.in_flight.fetch_add(to_send, Ordering::Relaxed);
        let frame = MuxFrame {
            stream_id: this.stream_id,
            frame_type: FRAME_TYPE_DATA,
            payload: buf[..to_send].to_vec(),
            in_flight: Some((
                Arc::clone(&this.in_flight),
                to_send,
                Arc::clone(&this.write_waker),
            )),
        };

        if this.tx.send(frame).is_err() {
            this.write_closed = true;
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "Multiplexer connection closed",
            )));
        }

        Poll::Ready(Ok(to_send))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();

        if this.write_closed {
            return Poll::Ready(Ok(()));
        }

        let _ = this.tx.send(MuxFrame {
            stream_id: this.stream_id,
            frame_type: FRAME_TYPE_FIN,
            payload: Vec::new(),
            in_flight: None,
        });
        this.write_closed = true;
        this.cleanly_closed = true;
        Poll::Ready(Ok(()))
    }
}

/// Helper function to write an encrypted frame to the TCP write half.
async fn write_encrypted_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    sealing_key: &mut SealingKey<CounterNonce>,
    stream_id: u32,
    frame_type: u8,
    payload: &[u8],
) -> Result<()> {
    let payload_len = 5 + payload.len();
    if payload_len > MAX_FRAME_PAYLOAD {
        bail!("Frame payload too large: {}", payload_len);
    }

    // 1. Seal length record (2 bytes + 16 bytes tag = 18 bytes)
    let mut len_record = (payload_len as u16).to_be_bytes().to_vec();
    let len_tag = sealing_key
        .seal_in_place_separate_tag(aead::Aad::empty(), &mut len_record)
        .map_err(|_| anyhow::anyhow!("AEAD seal length failed"))?;
    len_record.extend_from_slice(len_tag.as_ref());

    // 2. Seal payload record (stream_id [4B] + frame_type [1B] + payload + 16B tag)
    let mut payload_record = Vec::with_capacity(payload_len + 16);
    payload_record.extend_from_slice(&stream_id.to_be_bytes());
    payload_record.push(frame_type);
    payload_record.extend_from_slice(payload);

    let payload_tag = sealing_key
        .seal_in_place_separate_tag(aead::Aad::empty(), &mut payload_record)
        .map_err(|_| anyhow::anyhow!("AEAD seal payload failed"))?;
    payload_record.extend_from_slice(payload_tag.as_ref());

    // 3. Write both records
    writer.write_all(&len_record).await?;
    writer.write_all(&payload_record).await?;
    writer.flush().await?;
    Ok(())
}

/// Helper function to read an encrypted frame from the TCP read half.
async fn read_encrypted_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    opening_key: &mut OpeningKey<CounterNonce>,
) -> Result<(u32, u8, Vec<u8>)> {
    // 1. Read sealed length record (18 bytes)
    let mut len_buf = [0u8; 18];
    reader.read_exact(&mut len_buf).await?;

    let dec_len_slice = opening_key
        .open_in_place(aead::Aad::empty(), &mut len_buf)
        .map_err(|_| anyhow::anyhow!("AEAD authentication failed on frame length"))?;

    let payload_len = u16::from_be_bytes([dec_len_slice[0], dec_len_slice[1]]) as usize;
    if payload_len < 5 || payload_len > MAX_FRAME_PAYLOAD {
        bail!("Invalid frame payload length: {}", payload_len);
    }

    // 2. Read sealed payload record (payload_len + 16 bytes tag)
    let mut payload_buf = vec![0u8; payload_len + 16];
    reader.read_exact(&mut payload_buf).await?;

    let dec_payload = opening_key
        .open_in_place(aead::Aad::empty(), &mut payload_buf)
        .map_err(|_| anyhow::anyhow!("AEAD authentication failed on frame payload"))?;

    let stream_id = u32::from_be_bytes([
        dec_payload[0],
        dec_payload[1],
        dec_payload[2],
        dec_payload[3],
    ]);
    let frame_type = dec_payload[4];
    let data = dec_payload[5..].to_vec();

    Ok((stream_id, frame_type, data))
}

/// Well-known stream ID used for datagram encapsulation over TCP fallback.
pub const DATAGRAM_STREAM_ID: u32 = 0xFFFFFFFE;

/// The multiplexer instance running over a single TCP connection.
pub struct TcpMuxer {
    tx_sender: mpsc::UnboundedSender<MuxFrame>,
    streams: Arc<TokioMutex<HashMap<u32, mpsc::Sender<StreamEvent>>>>,
    next_stream_id: Arc<AtomicU32>,
    accept_rx: TokioMutex<mpsc::Receiver<VirtualStream>>,
    datagram_rx: TokioMutex<mpsc::Receiver<Vec<u8>>>,
    is_alive: Arc<AtomicBool>,
}

impl TcpMuxer {
    pub fn new(
        tcp_stream: TcpStream,
        sealing_key_bytes: [u8; 32],
        opening_key_bytes: [u8; 32],
        is_server: bool,
    ) -> Result<(Self, Option<VirtualStream>)> {
        let (reader, writer) = tcp_stream.into_split();
        Self::new_from_split(reader, writer, sealing_key_bytes, opening_key_bytes, is_server)
    }

    pub fn new_from_split<R, W>(
        mut reader: R,
        mut writer: W,
        sealing_key_bytes: [u8; 32],
        opening_key_bytes: [u8; 32],
        is_server: bool,
    ) -> Result<(Self, Option<VirtualStream>)>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {

        let s_unbound = UnboundKey::new(&CHACHA20_POLY1305, &sealing_key_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid AEAD sealing key"))?;
        let mut sealing_key = SealingKey::new(s_unbound, CounterNonce(0));

        let o_unbound = UnboundKey::new(&CHACHA20_POLY1305, &opening_key_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid AEAD opening key"))?;
        let mut opening_key = OpeningKey::new(o_unbound, CounterNonce(0));

        let (tx_sender, mut tx_receiver) = mpsc::unbounded_channel::<MuxFrame>();
        let (accept_tx, accept_rx) = mpsc::channel::<VirtualStream>(64);
        let (datagram_tx, datagram_rx) = mpsc::channel::<Vec<u8>>(256);

        // Pre-allocate stream 0 for control/auth
        let (stream0_tx, stream0_rx) = mpsc::channel::<StreamEvent>(64);
        let stream0 = VirtualStream::new(0, tx_sender.clone(), stream0_rx);

        let mut initial_streams = HashMap::<u32, mpsc::Sender<StreamEvent>>::new();
        initial_streams.insert(0, stream0_tx);

        let streams = Arc::new(TokioMutex::new(initial_streams));
        let streams_reader = Arc::clone(&streams);

        let is_alive = Arc::new(AtomicBool::new(true));
        let is_alive_reader = Arc::clone(&is_alive);
        let is_alive_writer = Arc::clone(&is_alive);

        // Background TX task
        tokio::spawn(async move {
            while let Some(frame) = tx_receiver.recv().await {
                let in_flight_info = frame.in_flight;
                let res = write_encrypted_frame(
                    &mut writer,
                    &mut sealing_key,
                    frame.stream_id,
                    frame.frame_type,
                    &frame.payload,
                )
                .await;

                if let Some((counter, len, waker)) = in_flight_info {
                    counter.fetch_sub(len, Ordering::Relaxed);
                    if let Some(w) = waker.lock().unwrap().take() {
                        w.wake();
                    }
                }

                if let Err(e) = res {
                    tracing::debug!("TCP multiplexer write loop terminated: {}", e);
                    is_alive_writer.store(false, Ordering::SeqCst);
                    break;
                }
            }
            is_alive_writer.store(false, Ordering::SeqCst);
        });

        // Background RX task
        let tx_sender_for_accept = tx_sender.clone();
        tokio::spawn(async move {
            loop {
                match read_encrypted_frame(&mut reader, &mut opening_key).await {
                    Ok((stream_id, frame_type, data)) => {
                        // Route datagrams to the dedicated channel
                        if stream_id == DATAGRAM_STREAM_ID && frame_type == FRAME_TYPE_DATAGRAM {
                            let _ = datagram_tx.send(data).await;
                            continue;
                        }
                        let mut map = streams_reader.lock().await;
                        if let Some(stream_tx) = map.get(&stream_id) {
                            let event = match frame_type {
                                FRAME_TYPE_DATA => StreamEvent::Data(data),
                                FRAME_TYPE_FIN => StreamEvent::Fin,
                                FRAME_TYPE_RST => StreamEvent::Rst,
                                _ => continue,
                            };
                            let _ = stream_tx.send(event).await;
                            if frame_type == FRAME_TYPE_RST {
                                map.remove(&stream_id);
                            }
                        } else if is_server && frame_type == FRAME_TYPE_DATA {
                            // Incoming new client virtual stream on server
                            let (stream_tx, stream_rx) = mpsc::channel::<StreamEvent>(64);
                            let vstream =
                                VirtualStream::new(stream_id, tx_sender_for_accept.clone(), stream_rx);
                            let _ = stream_tx.send(StreamEvent::Data(data)).await;
                            map.insert(stream_id, stream_tx);

                            if accept_tx.send(vstream).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("TCP multiplexer read loop terminated: {}", e);
                        is_alive_reader.store(false, Ordering::SeqCst);
                        break;
                    }
                }
            }
            is_alive_reader.store(false, Ordering::SeqCst);
        });

        let next_id = if is_server { 2 } else { 1 };
        let muxer = Self {
            tx_sender,
            streams,
            next_stream_id: Arc::new(AtomicU32::new(next_id)),
            accept_rx: TokioMutex::new(accept_rx),
            datagram_rx: TokioMutex::new(datagram_rx),
            is_alive,
        };

        Ok((muxer, Some(stream0)))
    }

    /// Open a new virtual bidirectional stream (used by client)
    pub async fn open_stream(&self) -> Result<VirtualStream> {
        if !self.is_alive() {
            bail!("TCP multiplexer connection is closed");
        }

        let stream_id = self.next_stream_id.fetch_add(2, Ordering::SeqCst);
        let (stream_tx, stream_rx) = mpsc::channel::<StreamEvent>(64);

        {
            let mut map = self.streams.lock().await;
            map.insert(stream_id, stream_tx);
        }

        Ok(VirtualStream::new(stream_id, self.tx_sender.clone(), stream_rx))
    }

    /// Accept an incoming virtual stream (used by server)
    pub async fn accept_stream(&self) -> Option<VirtualStream> {
        let mut rx = self.accept_rx.lock().await;
        rx.recv().await
    }

    pub fn is_alive(&self) -> bool {
        self.is_alive.load(Ordering::SeqCst)
    }

    pub async fn close(&self) -> Result<()> {
        self.is_alive.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Send a datagram over the TCP multiplexer using FRAME_TYPE_DATAGRAM.
    pub fn send_datagram(&self, data: &[u8]) -> Result<()> {
        if !self.is_alive() {
            bail!("TCP multiplexer connection is closed");
        }
        let frame = MuxFrame {
            stream_id: DATAGRAM_STREAM_ID,
            frame_type: FRAME_TYPE_DATAGRAM,
            payload: data.to_vec(),
            in_flight: None,
        };
        self.tx_sender
            .send(frame)
            .map_err(|_| anyhow::anyhow!("TCP multiplexer datagram send failed"))?;
        Ok(())
    }

    /// Receive a datagram from the TCP multiplexer's datagram channel.
    pub async fn recv_datagram(&self) -> Result<Vec<u8>> {
        let mut rx = self.datagram_rx.lock().await;
        rx.recv()
            .await
            .context("TCP multiplexer datagram channel closed")
    }
}

/// Client-side TCP transport handle
#[derive(Clone)]
pub struct TcpTransport {
    muxer: Arc<TcpMuxer>,
}

impl TcpTransport {
    pub async fn connect(server_addr: &str, server_port: u16, auth_key: &str) -> Result<Self> {
        let target_str = format!("{}:{}", server_addr, server_port);
        let mut addrs = tokio::net::lookup_host(&target_str)
            .await
            .with_context(|| format!("Failed to resolve server TCP address: {}", target_str))?;

        let server_sockaddr = addrs
            .next()
            .context("No IP address resolved for server TCP fallback")?;

        let stream = TcpStream::connect(server_sockaddr)
            .await
            .with_context(|| format!("Failed to connect to server TCP at {}", server_sockaddr))?;

        let _ = stream.set_nodelay(true);
        Self::handshake_on_stream(stream, auth_key).await
    }

    /// Perform X25519 key exchange, ChaCha20-Poly1305 encryption setup, and auth handshake
    /// over an arbitrary bidirectional stream (e.g. TcpStream or a proxied virtual stream).
    pub async fn handshake_on_stream<S>(mut stream: S, auth_key: &str) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        // 1. Ephemeral X25519 Handshake
        let rng = SystemRandom::new();
        let my_priv = EphemeralPrivateKey::generate(&X25519, &rng)
            .map_err(|_| anyhow::anyhow!("Failed to generate ephemeral X25519 key"))?;
        let my_pub = my_priv
            .compute_public_key()
            .map_err(|_| anyhow::anyhow!("Failed to compute public key"))?;

        // Send client public key (32 bytes)
        stream.write_all(my_pub.as_ref()).await?;

        // Read server public key (32 bytes)
        let mut server_pub_bytes = [0u8; 32];
        stream.read_exact(&mut server_pub_bytes).await?;

        let server_peer_pub = UnparsedPublicKey::new(&X25519, &server_pub_bytes);
        let shared_secret: [u8; 32] = agreement::agree_ephemeral(my_priv, &server_peer_pub, |key| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(key);
            arr
        })
        .map_err(|_| anyhow::anyhow!("X25519 key agreement failed"))?;

        // 2. Derive keys
        let (client_write_key, server_write_key, exporter_secret) =
            hkdf_derive_keys(&shared_secret);

        // 3. Initialize multiplexer (client writes with client_write_key, reads with server_write_key)
        let (reader, writer) = tokio::io::split(stream);
        let (muxer, stream0_opt) =
            TcpMuxer::new_from_split(reader, writer, client_write_key, server_write_key, false)?;
        let mut stream0 = stream0_opt.context("Stream 0 must be initialized")?;

        // 4. Authenticate over Stream 0
        let token = generate_auth_token_from_secret(&exporter_secret, auth_key);
        let auth_req = AuthRequest::new(token);
        write_auth_request(&mut stream0, &auth_req)
            .await
            .context("Failed to send auth request on TCP fallback Stream 0")?;

        let auth_resp = read_auth_response(&mut stream0)
            .await
            .context("Failed to read auth response on TCP fallback Stream 0")?;

        if auth_resp.status != STATUS_SUCCESS {
            bail!(
                "TCP fallback authentication failed by server (status: {})",
                auth_resp.status
            );
        }

        let _ = stream0.shutdown().await;
        Ok(Self {
            muxer: Arc::new(muxer),
        })
    }

    pub async fn open_stream(&self) -> Result<ProxyStream> {
        let vstream = self.muxer.open_stream().await?;
        Ok(ProxyStream::Tcp(vstream))
    }

    pub fn is_alive(&self) -> bool {
        self.muxer.is_alive()
    }

    pub async fn close(&self) -> Result<()> {
        self.muxer.close().await
    }

    pub fn send_datagram(&self, data: &[u8]) -> Result<()> {
        self.muxer.send_datagram(data)
    }

    pub async fn recv_datagram(&self) -> Result<Vec<u8>> {
        self.muxer.recv_datagram().await
    }
}

/// Server-side TCP connection acceptor and authenticator
pub async fn accept_server_tcp(
    mut stream: TcpStream,
    auth_key: &str,
) -> Result<TcpMuxer> {
    let _ = stream.set_nodelay(true);

    // 1. Read client public key (32 bytes)
    let mut client_pub_bytes = [0u8; 32];
    stream.read_exact(&mut client_pub_bytes).await?;

    // 2. Generate server ephemeral keypair and send public key (32 bytes)
    let rng = SystemRandom::new();
    let my_priv = EphemeralPrivateKey::generate(&X25519, &rng)
        .map_err(|_| anyhow::anyhow!("Failed to generate server ephemeral X25519 key"))?;
    let my_pub = my_priv
        .compute_public_key()
        .map_err(|_| anyhow::anyhow!("Failed to compute server public key"))?;

    stream.write_all(my_pub.as_ref()).await?;

    // 3. Compute shared secret
    let client_peer_pub = UnparsedPublicKey::new(&X25519, &client_pub_bytes);
    let shared_secret: [u8; 32] = agreement::agree_ephemeral(my_priv, &client_peer_pub, |key| {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(key);
        arr
    })
    .map_err(|_| anyhow::anyhow!("Server X25519 key agreement failed"))?;

    // 4. Derive keys (server writes with server_write_key, reads with client_write_key)
    let (client_write_key, server_write_key, exporter_secret) =
        hkdf_derive_keys(&shared_secret);

    let (muxer, stream0_opt) =
        TcpMuxer::new(stream, server_write_key, client_write_key, true)?;
    let mut stream0 = stream0_opt.context("Stream 0 must be initialized")?;

    // 5. Auth verification on Stream 0
    let auth_req = match read_auth_request(&mut stream0).await {
        Ok(req) => req,
        Err(e) => {
            let resp = AuthResponse::new(STATUS_AUTH_FAILED);
            let _ = write_auth_response(&mut stream0, &resp).await;
            let _ = stream0.shutdown().await;
            bail!("Invalid TCP auth request: {}", e);
        }
    };

    let is_valid = verify_auth_token_from_secret(&exporter_secret, auth_key, &auth_req.token);
    if !is_valid {
        let resp = AuthResponse::new(STATUS_AUTH_FAILED);
        let _ = write_auth_response(&mut stream0, &resp).await;
        let _ = stream0.shutdown().await;
        bail!("TCP authentication token verification failed");
    }

    let resp = AuthResponse::new(STATUS_SUCCESS);
    write_auth_response(&mut stream0, &resp)
        .await
        .context("Failed to write TCP auth success response")?;
    let _ = stream0.shutdown().await;

    Ok(muxer)
}
