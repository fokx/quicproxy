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

## 3. Phase 2: TCP Fallback & Multiplexing (Completed)

Phase 2 has been fully implemented, verified via automated test suites (4 new integration tests + 3 existing unit tests + 3 Phase 1 integration tests = 10/10 passed), and documented.

### 3.1 Architecture Highlights
- **Zero TLS-in-TLS**: Uses raw TCP with ephemeral X25519 DH handshake + HKDF-SHA256 derivation instead of nesting TLS inside TLS.
- **Two-Record ChaCha20-Poly1305 AEAD Framing**:
  - Record 1: 2-byte encrypted frame length + 16B Poly1305 tag (18B).
  - Record 2: Encrypted payload (`stream_id` [4B] + `frame_type` [1B] + payload) + 16B Poly1305 tag.
  - Zero plaintext header or length leakage, completely opaque to DPI inspection.
- **Smux-Style Virtual Stream Multiplexing**:
  - `Stream 0`: Reserved for authentication handshake (`AuthRequest`/`AuthResponse`), cryptographically bound to the HKDF exporter secret.
  - `Stream 1+`: Concurrent virtual bidirectional streams implementing standard Tokio `AsyncRead + AsyncWrite` with per-stream byte-level backpressure.
- **Unified Transport Layer (`src/transport/`)**:
  - `ProxyStream`: Abstracts QUIC bidirectional streams and TCP virtual streams.
  - `ActiveTransport`: Manages connection lifecycle and stream opening uniformly.
- **Server Dual-Listener & Client Auto-Fallback**:
  - Server listens simultaneously on UDP and TCP on the configured port.
  - Client defaults to `transport = "auto"`, attempting QUIC with 3-second timeout and seamlessly falling back to raw TCP ChaCha20-Poly1305 multiplexer when UDP is blocked.
  - Background probe automatically upgrades connection back to QUIC when UDP connectivity is restored.

### 3.2 Delivered Components
1. `src/transport/mod.rs` — Unified `ProxyStream` and `ActiveTransport` abstractions.
2. `src/transport/quic.rs` — `QuicTransport` adapter wrapping `quinn::Connection`.
3. `src/transport/tcp.rs` — X25519 + ChaCha20-Poly1305 framing, `VirtualStream`, and `TcpMuxer`.
4. `src/server/tcp.rs` — TCP fallback connection acceptor and stream dispatcher.
5. Dual listener in `src/server/mod.rs` binding both UDP and TCP on `config.listen`.
6. Transport selector (`auto`, `quic`, `tcp`) and auto-fallback with upgrade probing in `src/client/mod.rs` and `src/client/socks5.rs`.
7. Full integration test suite in `tests/tcp_fallback_test.rs`:
   - Direct TCP transport echo proxying.
   - 25 concurrent streams multiplexing stress test.
   - Automatic fallback when UDP is blocked.
   - Authentication rejection on incorrect auth key over TCP.

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
