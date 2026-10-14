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

## Multi-Server Connectivity & Traffic Routing

`quicproxy` allows the client to connect to multiple upstream servers simultaneously. Traffic can be steered according to high-performance aggregation policies or resilient active-standby failover rules, with an optional outbound relaying anchor to preserve a consistent Internet egress IP.

### 1. Traffic Modes

#### A. Aggregation Mode (`mode = "aggregation"`)
Designed for high-throughput acceleration. When using multi-connection download utilities such as **`aria2c`** (e.g. `aria2c -x 16 -s 16 --all-proxy=socks5://127.0.0.1:1080 <url>`), incoming TCP connections are distributed across multiple upstream servers.

- **`round_robin`**: Cycles connections sequentially across all healthy upstream servers (`Server 1 -> Server 2 -> Server 3 -> Server 1...`).
- **`random`**: Dynamically distributes connections across healthy servers according to configured server `weight` values.

```
                    +-------------------+
                    | aria2c (16 Conns) |
                    +---------+---------+
                              | SOCKS5
                    +---------v---------+
                    | QuicProxy Client  |
                    +---+-----+-----+---+
           Conn 1, 4    |     |     |    Conn 3, 6
         +--------------+     |     +--------------+
         |         Conn 2, 5  |                    |
         v                    v                    v
  +---------------+   +---------------+   +---------------+
  | Server Node 1 |   | Server Node 2 |   | Server Node 3 |
  +-------+-------+   +-------+-------+   +-------+-------+
          |                   |                   |
          +-------------------+-------------------+
                              |
                              v
                  [ Internet Destination ]
         (Bandwidth aggregated across all 3 paths!)
```

#### B. Resilient Mode (`mode = "resilient"`)
Designed for high reliability and anti-censorship failover. All connections are routed through the primary server (the node with the lowest `priority` integer, e.g. `priority = 1`). If the primary server becomes unreachable or blocked by firewalls, the client instantly and transparently steers subsequent connections to the next healthy standby server (`priority = 2`, etc.). Once the primary server recovers, it automatically resumes service.

---

### 2. Outbound Relaying Anchor (`relay_to_server`)

By default (Normal Mode), whichever server handles a connection connects directly to the destination on the Internet. This means the destination server sees the respective IP of each server node.

In some environments, CDNs or download hosts terminate sessions if download chunks originate from differing IP addresses. To solve this, `quicproxy` provides the **Outbound Relaying Anchor** option:

Set `relay_to_server = "<name-or-address>"` in `[routing]`.

When enabled:
- Connections assigned to the designated anchor server exit directly to the Internet.
- Connections assigned to intermediate servers are securely tunneled (`Client -> Intermediate -> Anchor -> Internet`) before reaching the destination!
- **End-to-End Security**: The intermediate server acts only as a transport tunnel. The client conducts an end-to-end encrypted and authenticated ChaCha20-Poly1305 session directly with the anchor server. The intermediate server cannot view target hosts or decrypt data.
- **Result**: You aggregate bandwidth across all server routes, while the destination server on the Internet **ALWAYS sees a single, consistent outbound IP** (the anchor server's IP)!

```
                    +-------------------+
                    | aria2c (16 Conns) |
                    +---------+---------+
                              | SOCKS5
                    +---------v---------+
                    | QuicProxy Client  |
                    +---+-----------+---+
             Path 1     |           |     Path 2
         +--------------+           +--------------+
         | (Direct)                                | (Relayed)
         v                                         v
  +---------------+                        +---------------+
  |   Server 1    |<=======================|   Server 2    |
  | (Egress Node) |   Encrypted Relay Pipe | (Transit Hop) |
  +-------+-------+                        +---------------+
          |
          v
  [ Internet Destination ]
  (Always sees Server 1's IP!)
```

---

### 3. Example Multi-Server Configuration

Save as `client.toml`:

```toml
socks5_listen = "127.0.0.1:1080"

[routing]
mode = "aggregation"        # "aggregation" or "resilient"
strategy = "round_robin"    # "round_robin" or "random"

# Optional: Anchor all egress traffic to server-us-1
# relay_to_server = "server-us-1"
# relay_fallback_direct = true

[[servers]]
name = "server-us-1"
server_addr = "192.168.1.101"
server_port = 4433
auth_key = "secret-node-1"
transport = "auto"
insecure = true
weight = 1
priority = 1

[[servers]]
name = "server-hk-2"
server_addr = "192.168.1.102"
server_port = 4433
auth_key = "secret-node-2"
transport = "auto"
insecure = true
weight = 1
priority = 2
```

Start the client with:
```bash
quicproxy client -c client.toml
```

Accelerate downloads with `aria2c`:
```bash
aria2c -x 16 -s 16 --all-proxy="socks5://127.0.0.1:1080" "https://example.com/largefile.zip"
```

---

## Access Control List (ACL) & Outbounds

QuicProxy features an Access Control List engine compatible with **Hysteria 2's ACL specification**, configured using clean TOML syntax.

ACL rules allow granular traffic routing, ad blocking, domestic traffic bypass, DNS hijacking, and upstream proxy chaining for both TCP connections and UDP datagrams.

### Rule Syntax

```text
outbound(address[, proto_port[, hijack_address]])
```

Rules are evaluated from top to bottom; the **first matching rule** applies. Lines starting with `#` and empty lines are ignored.

- **`outbound`**: The target outbound name (`direct`, `reject`, `default`, or a custom outbound name).
- **`address`**: Destination host or IP pattern:
  - `all` or `*`: Matches every target.
  - IP Address: `1.2.3.4`, `2606:4700::1`
  - CIDR Subnet: `192.168.0.0/16`, `2606:4700::/44`
  - Exact Domain: `example.com`
  - Wildcard Domain: `*.example.com`, `google.*`
  - Domain Suffix: `suffix:google.com`
  - GeoIP: `geoip:cn`, `geoip:us`, `geoip:private`
  - GeoSite: `geosite:google`, `geosite:cn`, `geosite:category-ads-all`, `geosite:google @cn`
- **`proto_port`** (Optional): Protocol and port filter:
  - Omitted or `*` or `*/*`: All protocols and ports.
  - `tcp`, `udp`: Specific protocol, any port.
  - `tcp/80`, `udp/53`: Specific protocol and port.
  - `*/443`: Both TCP and UDP on port 443.
  - `tcp/8000-9000`: Port range.
- **`hijack_address`** (Optional): Rewrites destination IP to this address (e.g. DNS port hijacking).

### Server Configuration (`server.toml`)

```toml
listen = "0.0.0.0:4433"
auth_key = "secret-key"

[acl]
# Either inline rules or path to an ACL rule file:
# file = "/etc/quicproxy/acl.txt"
inline = [
    # Block internal LAN IPs
    "reject(10.0.0.0/8)",
    "reject(172.16.0.0/12)",
    "reject(192.168.0.0/16)",
    "reject(fc00::/7)",

    # Block advertising domains
    "reject(geosite:category-ads-all)",

    # Hijack outbound DNS queries to local resolver
    "direct(all, udp/53, 127.0.0.1)",

    # Route domestic destinations directly
    "direct(geoip:cn)",
    "direct(geosite:cn)",

    # Fallback outbound
    "direct(all)"
]

# Optional GeoIP / GeoSite paths (auto-downloads from Loyalsoldier v2ray-rules-dat if omitted):
# geoip = "/var/lib/quicproxy/geoip.dat"
# geosite = "/var/lib/quicproxy/geosite.dat"
# geo_update_interval = "168h" # 7 days
```

### Custom Outbounds

You can chain QuicProxy with upstream SOCKS5 or HTTP proxies, or bind to specific outgoing network interfaces:

```toml
# Custom Direct outbound binding to specific local IPv4 address:
[[outbounds]]
name = "direct-v4"
type = "direct"
[outbounds.direct]
mode = "4" # "auto", "4", "6", "46", "64"
bind_ipv4 = "192.0.2.10"

# Upstream SOCKS5 Proxy:
[[outbounds]]
name = "tor"
type = "socks5"
[outbounds.socks5]
addr = "127.0.0.1:9050"

# Upstream HTTP CONNECT Proxy:
[[outbounds]]
name = "corp-proxy"
type = "http"
[outbounds.http]
url = "http://proxy.corp.internal:8080"
```

### CLI Flag Support

You can also pass ACL rule files directly via the `--acl-file` command-line flag:

```bash
# Server with ACL rule file:
quicproxy server --listen 0.0.0.0:4433 --auth-key "password" --acl-file /path/to/rules.txt

# Client with ACL rule file:
quicproxy client -c client.toml --acl-file /path/to/client-rules.txt
```

---

## Realms (Peer-to-Peer NAT Hole Punching)

QuicProxy supports **Realms**, a peer-to-peer NAT traversal mode modeled after and wire-compatible with **Hysteria 2 Realm**.

Realms allows a QuicProxy server behind residential NAT, carrier-grade NAT (CGNAT), or firewall to be reached **without a public IP address or manual port forwarding**. A lightweight HTTP/SSE rendezvous server introduces the server and client to each other, after which they perform bidirectional UDP hole punching to establish a direct, multiplexed QUIC tunnel. Once the hole is open, the rendezvous server is completely out of the path — all proxy data flows directly peer-to-peer.

### How It Works

```
  +------------------+         +--------------------+         +------------------+
  |  Client (NAT B)  |         | Rendezvous Service |         |  Server (NAT A)  |
  +------------------+         +--------------------+         +------------------+
           |                             |                             |
           |----- 1. STUN Discovery ---->|                             |
           |                             |<---- 1. STUN Discovery -----|
           |                             |                             |
           |                             |<---- 2. Register Realm -----|
           |                             |      (Hold SSE Event Stream)|
           |                             |                             |
           |----- 3. Connect Request --->|                             |
           |      (Client Candidates)    |----- 4. SSE Punch Event --->|
           |<---- 5. Server Candidates --|                             |
           |                             |                             |
           |============ 6. Bidirectional UDP Hole Punch =============|
           |             (Encrypted HYRLMv1 Hello / Ack)               |
           |                                                           |
           |============ 7. Direct QUIC Tunnel Established ============|
           |             (Normal Proxying, zero relay latency)         |
```

1. **Discovery**: Server and client query RFC 5389 STUN servers (and optionally UPnP gateway port mapping) to discover their external candidate IP:port mappings.
2. **Registration**: Server registers its candidates with the rendezvous server and maintains an open SSE (Server-Sent Events) stream while sending periodic heartbeats.
3. **Coordination**: When a client dials the realm, it posts its candidates to the rendezvous server. The rendezvous pushes them to the server over the SSE stream and replies with the server's candidates.
4. **UDP Hole Punching**: Both sides immediately send obfuscated `HYRLMv1` UDP punch packets to each other's candidate addresses (including symmetric NAT port-group expansion).
5. **Direct QUIC**: Once the punch is confirmed, Quinn initiates a standard QUIC TLS 1.3 handshake directly over the opened hole. Salamander packet obfuscation remains fully supported.

### URI Scheme

Realm endpoints use standard Realm URLs:

- `realm://[TOKEN@]host[:port]/realm_id[?stun=s1,s2&lport=N]` (HTTPS rendezvous, default port 443)
- `realm+http://[TOKEN@]host[:port]/realm_id[?stun=s1,s2&lport=N]` (HTTP rendezvous, default port 80)

Parameters:
- `TOKEN`: Rendezvous authentication token (optional if rendezvous does not require auth).
- `realm_id`: Unique identifier for the realm (single URL path segment).
- `stun`: Comma-separated list of STUN servers (optional, falls back to Google/Cloudflare STUN servers).
- `lport`: Local UDP bind port (optional, binds ephemeral `0` if omitted).

### Server Setup

Run directly from the command line:

```bash
quicproxy server \
  --listen "realm://my-token@rendezvous.example.com/home-server" \
  --auth-key "my-strong-password"
```

Or configure via `server.toml`:

```toml
listen = "realm://my-token@rendezvous.example.com/home-server"
auth_key = "my-strong-password"

[realm]
stun = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"]
stun_timeout = "3s"
punch_timeout = "5s"
ip_mode = "dual" # "v4", "v6", or "dual"

[realm.port_mapping]
enabled = true
timeout = "3s"
lifetime = "2h"
```

### Client Setup

Connect via CLI:

```bash
quicproxy client \
  --server-addr "realm://my-token@rendezvous.example.com/home-server" \
  --auth-key "my-strong-password" \
  --cert-fingerprint "<SERVER_SHA256_FINGERPRINT>" \
  --socks5-listen 127.0.0.1:1080
```

Or configure via `client.toml` (compatible with multi-server aggregation and resilient routing):

```toml
socks5_listen = "127.0.0.1:1080"

[[servers]]
name = "home-nas"
server_addr = "realm://my-token@rendezvous.example.com/home-server"
auth_key = "my-strong-password"
cert_fingerprint = "<SERVER_SHA256_FINGERPRINT>"
weight = 1
priority = 1
```

---

## Android Client Support

For Android devices, you can use our customized fork of [NekoBoxForAndroid](https://github.com/fokx/NekoBoxForAndroid):

- **Repository**: [https://github.com/fokx/NekoBoxForAndroid](https://github.com/fokx/NekoBoxForAndroid)
- **Features**: Complete Android GUI and VPN-service integration, routing rules, subscription management, and native high-speed core built for mobile devices.
- **Build from source**: Refer to the build & signing instructions in the [repository's README](https://github.com/fokx/NekoBoxForAndroid#readme) to compile and self-sign a release APK for your target architecture (e.g., `arm64-v8a` via `./gradlew app:assembleOssRelease`).
- **Install**: Note own release build is incompatible with the original one due to signing, you have to back up config and uninstall it before installing.
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
