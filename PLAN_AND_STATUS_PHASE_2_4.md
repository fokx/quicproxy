# QuicProxy: Project Status & Implementation Plan for Phases 2–4

This document serves as the complete handoff and technical blueprint for continuing the development of **QuicProxy** in new sessions.

---

## 1. Project Context & Vision

**QuicProxy** is a high-performance, censorship-resistant proxy written in modern Rust (2024 edition). Inspired by **Hysteria2** and **TUIC**, it is packaged as a **unified executable** that can operate as either a server or a client:
- **Client**: Exposes a local SOCKS5 proxy endpoint (RFC 1928 / RFC 1929) for web browsers (Firefox, Chrome), CLI tools (`curl`), and other applications.
- **Server**: Accepts connections, authenticates clients with replay-resistant session-bound tokens, terminates proxy requests, resolves target DNS remotely (preventing client-side DNS leaks), and relays traffic.
- **Primary Transport**: Native QUIC (RFC 9000) over UDP using `quinn`, featuring TLS 1.3 encryption, ALPN `h3`, stream multiplexing, and zero head-of-line blocking.
- **Key Design Objective**: Provide censorship resistance, anti-probing, server camouflage, and an automatic/configurable **TCP fallback that strictly avoids the TLS-in-TLS problem**.

---

## 2. Phase 1 Implementation Summary (Completed)

Phase 1 has been fully implemented, verified via automated test suites, documented, and committed to git (`cf89991`).

### 2.1 File Map
```
/f/quicproxy/
├── Cargo.toml                    # Dependencies (quinn, rustls, tokio, clap, ring, etc.)
├── README.md                     # Full user & developer documentation
├── examples/
│   ├── server.toml               # Server configuration reference
│   └── client.toml               # Client configuration reference
├── src/
│   ├── lib.rs                    # Module declarations
│   ├── main.rs                   # Unified CLI with clap (server, client, cert-gen)
│   ├── config.rs                 # TOML configuration & CLI argument parsing
│   ├── protocol.rs               # Wire protocol frames, codecs & randomized padding
│   ├── auth.rs                   # TLS Keying Material Exporter (RFC 5705) + HMAC-SHA256
│   ├── tls.rs                    # TLS configs, rcgen self-signed generation, fingerprint verifier
│   ├── server/
│   │   ├── mod.rs                # Server listener & connection loop
│   │   ├── connection.rs         # QUIC connection handler & auth validation
│   │   └── relay.rs              # Bidirectional TCP relay for target endpoints
│   └── client/
│       ├── mod.rs                # Client runner & auto-reconnection loop
│       └── socks5.rs             # Full SOCKS5 server (RFC 1928 / 1929)
└── tests/
    └── integration_test.rs       # 3 end-to-end integration tests (echo, domain, auth rejection)
```

### 2.2 Wire Protocol (Phase 1 Baseline)
- **Protocol Version**: `0x01`
- **Authentication Handshake** (first bidirectional stream):
  ```
  Client -> Server: [1B version (0x01)][1B auth_type (0x01=PSK)][32B session token][1B pad_len][pad_bytes (16..64B)]
  Server -> Client: [1B version (0x01)][1B status (0x00=OK, 0x01=FAIL)][1B pad_len][pad_bytes (16..64B)]
  ```
  *Replay-Resistant Auth*: Token is computed as:
  $$\text{Token} = \text{HMAC-SHA256}(\text{Key} = \text{auth\_key}, \text{Data} = \text{TLS-Exporter}(\text{Label} = \text{"quicproxy-auth-v1"}, \text{Length} = 32))$$
  Because it is derived from the TLS 1.3 session keys, tokens cannot be captured and replayed by probers.
- **Proxy Stream Request** (each subsequent bidirectional stream):
  ```
  Client -> Server: [1B cmd (0x01=CONNECT)][1B atyp (0x01=IPv4, 0x03=Domain, 0x04=IPv6)][addr bytes][2B port][1B pad_len][pad_bytes]
  Server -> Client: [1B status (0x00=SUCCESS, 0x02=CONNECT_FAILED)][1B pad_len][pad_bytes]
  ... bidirectional data copy via tokio::io::copy ...
  ```

### 2.3 Zero-Friction TLS & Verification
- Server auto-generates a self-signed certificate if no cert files are configured and logs its SHA-256 fingerprint.
- Clients can connect via:
  1. `--cert-fingerprint <sha256>` (pins the certificate hash without installing system CAs).
  2. `--insecure` (skips cert verification for local testing).
  3. `--ca-cert <path>` (custom CA).
  4. Standard WebPKI (system root certificates for domains with Let's Encrypt).

### 2.4 Verification Status
- `cargo test` passes 6/6 unit and integration tests cleanly:
  - Protocol codec symmetry (`TargetAddr`, `AuthRequest`, `ProxyRequest`).
  - Full SOCKS5 -> QUIC -> Echo Server end-to-end proxying.
  - Remote domain resolution over QUIC.
  - Auth rejection on invalid pre-shared key.
- `cargo build --release` compiles with zero warnings.

---

## 3. Phase 2 Implementation Plan: TCP Fallback & Multiplexing

### 3.1 The Problem: Avoiding "TLS-in-TLS"
- **Why it matters**: When UDP is blocked or throttled by restrictive middleboxes/firewalls, proxy tools fall back to TCP.
- **The pitfall**: Tunneling QUIC inside an outer TLS-over-TCP connection triggers DPI classifiers because the inner encrypted QUIC/TLS handshake and outer TLS record sizes exhibit unmistakable dual-handshake signatures ("TLS-in-TLS"). Furthermore, tunneling TCP-over-TCP causes congestion control meltdown.
- **The solution**:
  1. Do **not** encapsulate QUIC inside an outer TLS tunnel.
  2. Implement an application-level **ChaCha20-Poly1305 encrypted framing protocol** over raw TCP, with an ephemeral X25519 Diffie-Hellman handshake.
  3. Multiplex independent virtual streams over this single TCP connection using length-prefixed frames (`smux` pattern) to avoid opening a new TCP connection per SOCKS request.

### 3.2 TCP Fallback Protocol Design

```
1. Ephemeral Handshake (Raw TCP):
   Client -> Server: [32 bytes client_ephemeral_x25519_pubkey]
   Server -> Client: [32 bytes server_ephemeral_x25519_pubkey]
   Both derive shared secret via X25519 -> HKDF-SHA256 to produce:
     - client_write_key (32B) + client_nonce_seq (u64)
     - server_write_key (32B) + server_nonce_seq (u64)

2. Multiplexed Framing:
   Each frame:
   [2 bytes encrypted_frame_len]   (ChaCha20-Poly1305 encrypted)
   [frame payload]                 (ChaCha20-Poly1305 encrypted)
     -> [4 bytes stream_id]
     -> [1 byte frame_type (0x01=DATA, 0x02=FIN, 0x03=RST)]
     -> [payload bytes]
   [16 bytes Poly1305 AEAD tag]
```

- **Stream 0**: Reserved for control/authentication. After the X25519 exchange, the same `AuthRequest`/`AuthResponse` handshake executes over Stream 0, using the HKDF-derived secret as the exporter input.
- **Stream 1+**: Virtual multiplexed streams. Each client SOCKS5 connection gets an atomically incremented odd stream ID.
- Virtual streams implement `tokio::io::AsyncRead + AsyncWrite` via bounded `mpsc` channels and a background frame dispatcher.

### 3.3 Unified Transport Abstraction (`src/transport/mod.rs`)

```rust
#[async_trait::async_trait]
pub trait ProxyTransport: Send + Sync {
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static;

    /// Open a new multiplexed bidirectional stream for a proxy request
    async fn open_stream(&self) -> Result<Self::Stream>;

    /// Check if transport is still healthy
    fn is_alive(&self) -> bool;

    /// Graceful shutdown
    async fn close(&self) -> Result<()>;
}
```

- `QuicTransport`: Wraps `quinn::Connection`, where `open_stream` calls `conn.open_bi()`.
- `TcpTransport`: Wraps the ChaCha20-Poly1305 multiplexer, where `open_stream` allocates a new `stream_id` and channel pair.

### 3.4 Client Transport Selector & Automatic Fallback
- Config option `transport = "auto" | "quic" | "tcp"` (default: `"auto"`).
- In `"auto"` mode:
  1. Client launches QUIC connection attempt with a 3-second timeout.
  2. If QUIC fails or times out (UDP blocked), automatically falls back to TCP transport.
  3. Caches the working transport and periodically probes QUIC in the background to upgrade back when UDP becomes viable.
- Support `--transport tcp` / `--transport quic` CLI overrides.

### 3.5 Server Dual-Listener
- Server binds both UDP (`quinn::Endpoint`) and TCP (`tokio::net::TcpListener`) on the configured port.
- Accepts both incoming QUIC and incoming multiplexed TCP connections, feeding both into the common `relay::handle_stream` logic.

### 3.6 Deliverables for Phase 2
1. `src/transport/mod.rs` — Transport trait definition.
2. `src/transport/quic.rs` — QUIC adapter.
3. `src/transport/tcp.rs` — X25519 + ChaCha20-Poly1305 stream multiplexer.
4. Update `src/client/mod.rs` & `src/server/mod.rs` to support dual-transport and auto fallback.
5. Integration test `tests/tcp_fallback_test.rs` — test TCP fallback, multiplexing stress (many concurrent streams), and auto-switching when UDP is unavailable.

---

## 4. Phase 3 Implementation Plan: Anti-Censorship & Camouflage

### 4.1 Active Probing Resistance & HTTP/3 Masquerade
- When an unauthorized client, scanner, or firewall prober connects via QUIC:
  - Rather than closing the connection or returning a custom error code (which acts as a fingerprint), the server invokes an **HTTP/3 masquerade engine** (`h3` + `h3-quinn`).
  - **Reverse Proxy Mode**: Transparently forwards HTTP/3 requests to a legitimate website (e.g. `https://www.example.com` or configured URL).
  - **File Server Mode**: Serves a legitimate static HTML/CSS web page from a local directory.
  - To any external prober, the server is indistinguishable from a standard web server hosting public content.

### 4.2 Probing Defense Parameters (`src/server/antiprobe.rs`)
- **Constant-Time Verification**: Prevent timing side-channels in token validation.
- **Random Response Jitter**: Inject configurable random delay (10–50 ms) on auth handshakes to defeat precise network timing analysis.
- **Rate Limiting**: Block IPs exceeding failed auth thresholds.
- **Silent Drop on Garbage**: For unsolicited raw UDP datagrams without valid QUIC headers, silently discard without sending ICMP port-unreachable packets.

### 4.3 Optional Salamander-Style Packet Scrambling (`src/obfs/mod.rs`)
- For networks where even standard QUIC headers are blocked:
  - BLAKE2b-derived XOR keystream from a pre-shared obfuscation key.
  - Scrambles QUIC fixed bits and header invariants so packets look like high-entropy white noise.
  - Applied directly at the `UdpSocket` layer before Quinn parsing.
  - *Note*: Mutually exclusive with HTTP/3 masquerading.

---

## 5. Phase 4 Implementation Plan: Advanced Features

### 5.1 SOCKS5 UDP Proxying (`UDP ASSOCIATE`)
- Implement SOCKS5 `CMD = 0x03 (UDP ASSOCIATE)` in `src/client/socks5.rs` and `src/client/udp.rs`.
- In QUIC mode: Forward UDP packets over **QUIC Unreliable Datagrams (RFC 9221)** via `quinn::Connection::send_datagram` and `read_datagram`.
  - Zero HOL blocking, native UDP latency (ideal for DNS and real-time UDP).
- In TCP fallback mode: Encapsulate UDP datagrams in length-prefixed stream frames.
- Server maintains a UDP session table with full-cone NAT emulation.
- Association lifetime strictly bound to the TCP control stream per RFC 1928.

### 5.2 Advanced TLS Fingerprinting (`src/tls/fingerprint.rs`)
- Configurable ALPN ordering (`h3`, `h2`, `http/1.1`).
- Custom SNI spoofing / domain fronting support.
- Cipher suite selection matching popular browser profiles.

### 5.3 Connection Management & Metrics
- Connection health keepalives and zero-downtime pool rotation.
- Real-time statistics: active streams, bytes sent/received, round-trip latency.

---

## 6. How to Resume Work in the Next Session

When starting the next conversation, you can instruct Antigravity:

> *"We are building `quicproxy` in Rust. Phase 1 is completed and committed to git. Please read `PLAN_AND_STATUS_PHASE_2_4.md` and proceed with implementing Phase 2: TCP Fallback & Multiplexing (avoiding TLS-in-TLS)."*

### Verification Commands
```bash
# Check existing build and run full test suite
cargo test

# Build release binary
cargo build --release

# Run server with auto-cert
./target/release/quicproxy server --listen 127.0.0.1:4433 --auth-key "test-pass"

# Run client pointing to server
./target/release/quicproxy client --server-addr 127.0.0.1 --server-port 4433 --auth-key "test-pass" --insecure --socks5-listen 127.0.0.1:1080
```
