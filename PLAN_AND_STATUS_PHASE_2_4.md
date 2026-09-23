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

## 4. Phase 3: Anti-Censorship & Camouflage (Completed)

Phase 3 has been fully implemented, verified via automated test suites (5 new Phase 3 integration tests + 4 Phase 2 tests + 3 Phase 1 tests + 7 unit tests = 19/19 passed), and documented.

### 4.1 Architecture Highlights
- **Active Probing Resistance & HTTP/3 Camouflage (`src/server/masquerade.rs`)**:
  - When unauthorized clients, scanners, or probers connect via QUIC:
    - Rather than abruptly closing the connection or returning custom error codes (which fingerprint the proxy), the server transparently responds with RFC 9114 / RFC 9204 HTTP/3 web responses.
    - **File Server Mode**: Serves a legitimate static HTML/CSS web page from a local directory or built-in default page.
    - **Reverse Proxy Mode**: Fetches and mirrors legitimate upstream websites via `reqwest`.
    - Opens the server HTTP/3 control stream (`[0x00, 0x04, 0x00]`) and writes HTTP/3 `HEADERS` (QPACK-encoded `:status: 200`) and `DATA` frames directly on request streams.
    - Probers, curl (`curl --http3`), and browsers see a genuine, functional HTTP/3 web server.
- **Anti-Probing Defenses (`src/server/antiprobe.rs`)**:
  - **Constant-Time Verification**: Replay-resistant HMAC verification using `ring::hmac::verify` prevents timing side channels.
  - **Random Response Jitter**: Injects configurable random delays (10–50 ms) on auth handshakes to thwart precise network timing analysis.
  - **In-Memory Sliding-Window Rate Limiter**: Tracks failed auth attempts by IP address via concurrent `DashMap`. Once the threshold (default: 5 failures / 60s) is exceeded, subsequent attempts are diverted to masquerade or dropped. Resets immediately on successful auth.
  - Applied to both QUIC and TCP fallback transports.
- **Salamander Packet Obfuscation (`src/obfs/`)**:
  - For censorship environments where QUIC packet headers (fixed bits, versions) are actively blocked by DPI:
    - Derives a 2048-byte keystream from a pre-shared passphrase using `BLAKE2b-512` in counter mode.
    - Symmetric XOR scrambles/unscrambles UDP datagrams in-place.
    - Implemented directly into Quinn via `quinn::AsyncUdpSocket` (`ObfuscatedUdpSocket`) using `Endpoint::new_with_abstract_socket`.
    - Configured with single-segment datagram processing (`max_transmit_segments = 1`, `max_receive_segments = 1`) to guarantee perfect 1:1 datagram XOR alignment without GSO/GRO boundary distortion.
    - Strictly mutually exclusive with HTTP/3 masquerade (validated at startup).

### 4.2 Delivered Components
1. `src/server/antiprobe.rs` — Sliding-window `RateLimiter` and `apply_auth_jitter`.
2. `src/server/masquerade.rs` — `MasqueradeHandler`, RFC 9114/9204 HTTP/3 frame generator, `FileServer`, and `ReverseProxy` modes.
3. `src/obfs/mod.rs` & `src/obfs/salamander.rs` — `SalamanderObfuscator` and `ObfuscatedUdpSocket` implementing Quinn's `AsyncUdpSocket`.
4. `src/config.rs` & `src/main.rs` — Updated CLI flags (`--masquerade-mode`, `--masquerade-dir`, `--masquerade-upstream`, `--obfs-key`, `--rate-limit-max`, `--jitter-min`, `--jitter-max`) and configuration structs with full `Default` implementations.
5. `src/tls.rs` — Configured `max_concurrent_bidi_streams(256)` and `max_concurrent_uni_streams(256)` on Quinn transport configs for bidirectional and unidirectional stream credits.
6. `tests/phase3_test.rs` — 5 integration tests:
   - `test_obfuscation_mutual_exclusion`: Validates server refuses to start with both obfuscation and masquerade enabled.
   - `test_masquerade_file_server`: Simulates an external HTTP/3 client receiving a valid HTTP/3 200 OK and static HTML page.
   - `test_masquerade_does_not_interfere_with_proxy`: Verifies proxy clients authenticate and relay traffic concurrently with masquerade enabled.
   - `test_obfuscation_roundtrip`: Verifies end-to-end SOCKS5 proxying over Salamander XOR-scrambled UDP datagrams.
   - `test_antiprobe_rate_limiting`: Verifies IP rate limiting after exceeding failed auth threshold.

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

> *"We are building `quicproxy` in Rust. Phases 1, 2, and 3 are completed and verified (19/19 tests pass). Please read `PLAN_AND_STATUS_PHASE_2_4.md` and proceed with implementing Phase 4: Advanced Features (starting with SOCKS5 UDP ASSOCIATE and QUIC Datagrams RFC 9221)."*

### Verification Commands
```bash
# Run full test suite across all phases (19 tests)
cargo test

# Run Phase 3 specific integration tests
cargo test --test phase3_test

# Build release binary
cargo build --release

# Run server with HTTP/3 file server masquerade
./target/release/quicproxy server --listen 127.0.0.1:4433 --auth-key "test-pass" --masquerade-mode file_server

# Run server with Salamander packet obfuscation
./target/release/quicproxy server --listen 127.0.0.1:4433 --auth-key "test-pass" --obfs-key "scramble-secret"

# Run client with Salamander packet obfuscation
./target/release/quicproxy client --server-addr 127.0.0.1 --server-port 4433 --auth-key "test-pass" --insecure --obfs-key "scramble-secret" --socks5-listen 127.0.0.1:1080
```
