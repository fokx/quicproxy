# QuicProxy

A high-performance, censorship-resistant QUIC proxy built in pure Rust.

Inspired by **Hysteria2** and **TUIC**, `quicproxy` provides a unified executable that can run as either a server or a client. On the client side, it exposes a standard SOCKS5 proxy endpoint for web browsers (such as Mozilla Firefox or Google Chrome), command-line tools (`curl`), and other software. On the server side, it accepts multiplexed QUIC streams, resolves domain targets remotely to prevent DNS leaks, and proxies traffic to destination servers.

---

## Key Highlights

- **Unified Executable**: Single binary with `server`, `client`, and `cert-gen` subcommands.
- **Native QUIC Transport**: Built on `quinn` (RFC 9000) over UDP with TLS 1.3 encryption and ALPN `h3`.
- **Stream Multiplexing**: Every TCP connection is routed through an independent bidirectional QUIC stream — eliminating TCP Head-of-Line (HOL) blocking.
- **Session-Bound Authentication**: Replay-resistant authentication derived using the **TLS Keying Material Exporter (RFC 5705)** and HMAC-SHA256, verified in constant time.
- **Anti-Fingerprinting**: Dynamic random-length padding on all protocol requests and responses.
- **DNS Leak Prevention**: SOCKS5 domain targets are forwarded unmolested across the QUIC tunnel to be resolved directly on the egress server.
- **Zero-Friction TLS**:
  - Automatic self-signed certificate generation on server startup.
  - Generates and logs the certificate's SHA-256 fingerprint.
  - Clients can pin the fingerprint (`--cert-fingerprint <sha256>`), provide custom CA files, skip verification (`--insecure`), or use standard WebPKI certs (e.g., Let's Encrypt).
- **Standards-Compliant SOCKS5**: Supports RFC 1928 (NO_AUTH, IPv4, IPv6, Domain) and RFC 1929 (Username/Password authentication).

---

## Architecture

```
+----------------------------------------------------------------------+
|                           CLIENT MACHINE                             |
|                                                                      |
|  [Firefox / Browser / App]                                           |
|            |                                                         |
|            | SOCKS5 (TCP 127.0.0.1:1080)                             |
|            v                                                         |
|    +---------------+                                                 |
|    | SOCKS5 Server | (RFC 1928 / 1929)                               |
|    +---------------+                                                 |
|            |                                                         |
|            | Bidirectional QUIC Streams                              |
|            v                                                         |
|    +---------------+                                                 |
|    |  QUIC Client  |                                                 |
|    +---------------+                                                 |
+------------|---------------------------------------------------------+
             |
             |  QUIC / UDP (TLS 1.3 + ALPN h3 + Random Padding)
             |
+------------v---------------------------------------------------------+
|                           SERVER MACHINE                             |
|                                                                      |
|    +---------------+                                                 |
|    |  QUIC Server  | (Endpoint: 0.0.0.0:4433)                        |
|    +---------------+                                                 |
|            |                                                         |
|            | Authenticate via TLS Keying Material Exporter           |
|            v                                                         |
|    +---------------+                                                 |
|    | Stream Relay  |                                                 |
|    +---------------+                                                 |
|            |                                                         |
|            | Direct TCP Connections (Remote DNS resolution)          |
|            v                                                         |
|    [ Target Hosts / Internet ]                                       |
+----------------------------------------------------------------------+
```

---

## Quick Start

### 1. Build from Source

Ensure you have Rust (1.80+ or latest stable) installed:

```bash
cargo build --release
# The compiled binary is located at ./target/release/quicproxy
```

### 2. Start the Server

Start a server with auto-generated self-signed certificate:

```bash
quicproxy server --listen 0.0.0.0:4433 --auth-key "my-strong-password"
```

The server will print its SHA-256 fingerprint:
```text
================================================================================
  QuicProxy Server is listening on UDP 0.0.0.0:4433
  Certificate SHA-256 Fingerprint: a3000d030f7ad41a2d5fff972b1bb5c6ab7c2ed68e66b8167c7c09941ac15405

  Quick connect command for clients:
  quicproxy client --server-addr <SERVER_IP> --server-port 4433 --auth-key "my-strong-password" --cert-fingerprint "a3000d030f7ad41a2d5fff972b1bb5c6ab7c2ed68e66b8167c7c09941ac15405"
================================================================================
```

### 3. Start the Client

Connect using the printed fingerprint:

```bash
quicproxy client \
  --server-addr 127.0.0.1 \
  --server-port 4433 \
  --auth-key "my-strong-password" \
  --cert-fingerprint "a3000d030f7ad41a2d5fff972b1bb5c6ab7c2ed68e66b8167c7c09941ac15405" \
  --socks5-listen 127.0.0.1:1080
```

### 4. Test with curl or Firefox

Verify traffic flows through the proxy:

```bash
curl -x socks5h://127.0.0.1:1080 https://ipinfo.io/json
```

> **Note**: Always use `socks5h://` with `curl` to ensure DNS is resolved remotely on the proxy server rather than leaking locally.

In **Mozilla Firefox**:
1. Open **Settings** -> **Network Settings**.
2. Select **Manual proxy configuration**.
3. Set **SOCKS Host** to `127.0.0.1` and **Port** to `1080`.
4. Select **SOCKS v5**.
5. Check the box **"Proxy DNS when using SOCKS v5"** to avoid local DNS leaks.

---

## Configuration Files

Instead of CLI flags, you can use TOML configuration files.

### Server Config (`server.toml`)

```toml
# Server listening socket (UDP)
listen = "0.0.0.0:4433"

# Pre-shared authentication key
auth_key = "my-strong-password"

# Optional: Custom certificate paths (e.g. Let's Encrypt)
# tls_cert = "/path/to/fullchain.pem"
# tls_key = "/path/to/privkey.pem"

# Self-signed certificate fallback
auto_cert = true
auto_cert_domain = "localhost"
```

Run with:
```bash
quicproxy server -c server.toml
```

### Client Config (`client.toml`)

```toml
# Local SOCKS5 endpoint
socks5_listen = "127.0.0.1:1080"

# Remote server
server_addr = "127.0.0.1"
server_port = 4433
auth_key = "my-strong-password"

# TLS verification: pin fingerprint, or set insecure = true, or ca_cert
cert_fingerprint = "a3000d030f7ad41a2d5fff972b1bb5c6ab7c2ed68e66b8167c7c09941ac15405"

# Optional: SOCKS5 client authentication
# socks5_user = "alice"
# socks5_password = "password123"
```

Run with:
```bash
quicproxy client -c client.toml
```

---

## Certificate Utility

To generate standalone self-signed certificate files:

```bash
quicproxy cert-gen --domain proxy.example.com --out-cert cert.pem --out-key key.pem
```

---

## Security & Anti-Censorship Design

### Replay-Resistant Authentication (TUIC style)
Traditional proxy protocols that send static passwords or hashes on the wire are vulnerable to recording and replay attacks. `quicproxy` derives an authentication token using the **TLS Keying Material Exporter (RFC 5705)**:
$$\text{Token} = \text{HMAC-SHA256}(\text{Key} = \text{auth\_key}, \text{Data} = \text{TLS-Exporter}(\text{Label} = \text{"quicproxy-auth-v1"}, \text{Length} = 32))$$

Because the exported keying material is cryptographically derived from the unique TLS 1.3 master secret of the current QUIC connection, no two sessions ever produce the same token. Captured packets cannot be replayed by active probes.

### Constant-Time Verification & Delayed Responses
Authentication tokens are validated using constant-time equality checks. Upon failed authentication attempts, the server introduces timing delays before closing the connection, hindering active probers from mapping valid vs. invalid endpoints via timing differentials.

### Traffic Camouflage
- Advertises standard ALPN `h3` (HTTP/3).
- Uses random byte padding (16 to 64 bytes) on all control messages to prevent packet-size fingerprinting.

---

## Verification & Testing

The repository includes both unit tests and end-to-end integration tests:

```bash
cargo test
```

Tests cover:
- Protocol encoding/decoding symmetry (`TargetAddr`, `AuthRequest`, `ProxyRequest`, etc.).
- End-to-end TCP echo proxying through the SOCKS5 client and QUIC server.
- Remote server domain resolution.
- Rejection of unauthenticated clients.

---

## Roadmap

- **Phase 1** (Completed): Core QUIC Proxy, unified CLI, auto self-signed certificates, replay-resistant exporter auth, SOCKS5 client.
- **Phase 2**: Automatic TCP fallback without the TLS-in-TLS problem (using ChaCha20-Poly1305 length-delimited stream multiplexing).
- **Phase 3**: Active-probing resistance with HTTP/3 masquerading (reverse-proxying legitimate web services when unauthenticated).
- **Phase 4**: SOCKS5 `UDP ASSOCIATE` via QUIC Unreliable Datagrams (RFC 9221) and advanced TLS fingerprint customization.

---

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
