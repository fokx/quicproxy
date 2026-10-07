use anyhow::{Context, Result, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::ClientConfig;
use crate::protocol::{
    ProxyRequest, STATUS_SUCCESS, TargetAddr, read_proxy_response, write_proxy_request,
};
use crate::transport::ActiveTransport;

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDR_NOT_SUPPORTED: u8 = 0x08;

static NEXT_UDP_SESSION_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

pub async fn run_socks5_listener(
    config: Arc<ClientConfig>,
    conn_provider: Arc<dyn Fn() -> Option<Arc<ActiveTransport>> + Send + Sync>,
    datagram_router: Arc<crate::client::udp::DatagramRouter>,
    acl_engine: Arc<crate::acl::ACLEngine>,
) -> Result<()> {
    let listener = TcpListener::bind(config.socks5_listen)
        .await
        .with_context(|| format!("Failed to bind SOCKS5 listener on {}", config.socks5_listen))?;

    tracing::info!(
        "SOCKS5 proxy server is listening on {}",
        config.socks5_listen
    );

    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                let config_clone = Arc::clone(&config);
                let conn_provider_clone = Arc::clone(&conn_provider);
                let router_clone = Arc::clone(&datagram_router);
                let acl_clone = Arc::clone(&acl_engine);
                tokio::spawn(async move {
                    if let Err(e) = handle_socks5_client(
                        stream,
                        client_addr,
                        config_clone,
                        conn_provider_clone,
                        router_clone,
                        acl_clone,
                    )
                    .await
                    {
                        tracing::debug!("SOCKS5 client {} error: {:#}", client_addr, e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!("Failed to accept SOCKS5 connection: {}", e);
            }
        }
    }
}

async fn handle_socks5_client(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    config: Arc<ClientConfig>,
    conn_provider: Arc<dyn Fn() -> Option<Arc<ActiveTransport>> + Send + Sync>,
    datagram_router: Arc<crate::client::udp::DatagramRouter>,
    acl_engine: Arc<crate::acl::ACLEngine>,
) -> Result<()> {
    let _ = stream.set_nodelay(true);

    // 1. Negotiation phase
    let ver = stream
        .read_u8()
        .await
        .context("Failed to read SOCKS version")?;
    if ver != SOCKS_VERSION {
        bail!("Unsupported SOCKS version: {}", ver);
    }

    let nmethods = stream.read_u8().await.context("Failed to read nmethods")? as usize;
    let mut methods = vec![0u8; nmethods];
    stream
        .read_exact(&mut methods)
        .await
        .context("Failed to read methods")?;

    let require_auth = config.socks5_user.is_some() && config.socks5_password.is_some();

    if require_auth {
        if !methods.contains(&METHOD_USER_PASS) {
            stream
                .write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE])
                .await?;
            bail!("Client does not support username/password auth");
        }
        stream.write_all(&[SOCKS_VERSION, METHOD_USER_PASS]).await?;

        // Subnegotiation RFC 1929
        let sub_ver = stream.read_u8().await?;
        if sub_ver != 0x01 {
            stream.write_all(&[0x01, 0x01]).await?;
            bail!("Unsupported auth subnegotiation version: {}", sub_ver);
        }
        let ulen = stream.read_u8().await? as usize;
        let mut uname_buf = vec![0u8; ulen];
        stream.read_exact(&mut uname_buf).await?;
        let plen = stream.read_u8().await? as usize;
        let mut pass_buf = vec![0u8; plen];
        stream.read_exact(&mut pass_buf).await?;

        let uname = String::from_utf8_lossy(&uname_buf);
        let pass = String::from_utf8_lossy(&pass_buf);

        if Some(uname.as_ref()) != config.socks5_user.as_deref()
            || Some(pass.as_ref()) != config.socks5_password.as_deref()
        {
            stream.write_all(&[0x01, 0x01]).await?;
            bail!("SOCKS5 username/password auth failed for {}", client_addr);
        }
        stream.write_all(&[0x01, 0x00]).await?;
    } else {
        if !methods.contains(&METHOD_NO_AUTH) {
            stream
                .write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE])
                .await?;
            bail!("Client does not support NO_AUTH");
        }
        stream.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
    }

    // 2. Request phase
    let ver = stream
        .read_u8()
        .await
        .context("Failed to read request version")?;
    if ver != SOCKS_VERSION {
        bail!("Invalid SOCKS request version: {}", ver);
    }
    let cmd = stream.read_u8().await.context("Failed to read command")?;
    let _rsv = stream.read_u8().await.context("Failed to read RSV")?;
    let atyp = stream.read_u8().await.context("Failed to read ATYP")?;

    if cmd != CMD_CONNECT && cmd != CMD_UDP_ASSOCIATE {
        // Reply with command not supported
        stream
            .write_all(&[
                SOCKS_VERSION,
                REP_CMD_NOT_SUPPORTED,
                0x00,
                0x01,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await?;
        bail!("Unsupported SOCKS command: 0x{:02x}", cmd);
    }

    let target = match atyp {
        0x01 => {
            let mut ip_bytes = [0u8; 4];
            stream.read_exact(&mut ip_bytes).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip_bytes)), port))
        }
        0x03 => {
            let len = stream.read_u8().await? as usize;
            let mut domain_bytes = vec![0u8; len];
            stream.read_exact(&mut domain_bytes).await?;
            let domain = String::from_utf8(domain_bytes).context("Invalid domain UTF-8")?;
            let port = stream.read_u16().await?;
            TargetAddr::Domain(domain, port)
        }
        0x04 => {
            let mut ip_bytes = [0u8; 16];
            stream.read_exact(&mut ip_bytes).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port))
        }
        _ => {
            stream
                .write_all(&[
                    SOCKS_VERSION,
                    REP_ADDR_NOT_SUPPORTED,
                    0x00,
                    0x01,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
                .await?;
            bail!("Unsupported ATYP: 0x{:02x}", atyp);
        }
    };

    if cmd == CMD_CONNECT {
        let (outbound, matched_target) =
            acl_engine.handle(&target, crate::acl::Protocol::Tcp).await;

        if outbound.name() == "reject" {
            tracing::debug!("SOCKS5 CONNECT to {} rejected by ACL", target);
            // REP_CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02
            stream
                .write_all(&[SOCKS_VERSION, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            bail!("Connection to {} rejected by ACL", target);
        }

        if outbound.name() != "default" {
            tracing::debug!(
                "Routing CONNECT to {} via outbound [{}]",
                matched_target,
                outbound.name()
            );
            let remote_stream = match outbound.tcp_connect(&matched_target).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        "Failed outbound ({}) connection to {}: {}",
                        outbound.name(),
                        matched_target,
                        e
                    );
                    stream
                        .write_all(&[
                            SOCKS_VERSION,
                            REP_GENERAL_FAILURE,
                            0x00,
                            0x01,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                        ])
                        .await?;
                    return Err(e);
                }
            };

            // Success response to SOCKS5 client
            stream
                .write_all(&[SOCKS_VERSION, REP_SUCCESS, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;

            let (mut tcp_read, mut tcp_write) = stream.into_split();
            let (mut rem_read, mut rem_write) = tokio::io::split(remote_stream);

            let client_to_remote = async {
                let res = tokio::io::copy(&mut tcp_read, &mut rem_write).await;
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut rem_write).await;
                res
            };

            let remote_to_client = async {
                let res = tokio::io::copy(&mut rem_read, &mut tcp_write).await;
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut tcp_write).await;
                res
            };

            let _ = tokio::join!(client_to_remote, remote_to_client);
            tracing::trace!("SOCKS5 session finished for target {}", target);
            return Ok(());
        }

        // Default outbound: tunnel through upstream proxy server
        let start_wait = std::time::Instant::now();
        let transport = loop {
            if let Some(t) = conn_provider() {
                break t;
            }
            if start_wait.elapsed() > Duration::from_millis(6000) {
                tracing::warn!("No active proxy transport available to handle SOCKS request");
                stream
                    .write_all(&[
                        SOCKS_VERSION,
                        REP_GENERAL_FAILURE,
                        0x00,
                        0x01,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ])
                    .await?;
                bail!("Proxy transport not available");
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        };

        tracing::debug!(
            "SOCKS5 CONNECT request for target {} (final: {})",
            target,
            matched_target
        );

        // Open a new bidirectional stream on the active transport
        let proxy_stream = match transport.open_stream().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    "Failed to open stream on transport ({}): {}",
                    transport.mode_name(),
                    e
                );
                stream
                    .write_all(&[
                        SOCKS_VERSION,
                        REP_GENERAL_FAILURE,
                        0x00,
                        0x01,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ])
                    .await?;
                return Err(e);
            }
        };

        let (mut stream_read, mut stream_write) = tokio::io::split(proxy_stream);

        // Send ProxyRequest with matched_target (which may be hijacked)
        let req = ProxyRequest::connect(matched_target);
        if let Err(e) = write_proxy_request(&mut stream_write, &req).await {
            stream
                .write_all(&[
                    SOCKS_VERSION,
                    REP_GENERAL_FAILURE,
                    0x00,
                    0x01,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
                .await?;
            return Err(e);
        }

        // Read ProxyResponse from server
        let resp = match read_proxy_response(&mut stream_read).await {
            Ok(resp) => resp,
            Err(e) => {
                stream
                    .write_all(&[
                        SOCKS_VERSION,
                        REP_GENERAL_FAILURE,
                        0x00,
                        0x01,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ])
                    .await?;
                return Err(e);
            }
        };

        if resp.status != STATUS_SUCCESS {
            tracing::warn!(
                "Server failed proxy request for target {}: status {}",
                target,
                resp.status
            );
            stream
                .write_all(&[
                    SOCKS_VERSION,
                    REP_GENERAL_FAILURE,
                    0x00,
                    0x01,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
                .await?;
            return Ok(());
        }

        // Success response to SOCKS5 client
        stream
            .write_all(&[SOCKS_VERSION, REP_SUCCESS, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;

        // Bidirectional stream relay
        let (mut tcp_read, mut tcp_write) = stream.into_split();

        let client_to_remote = async {
            let res = tokio::io::copy(&mut tcp_read, &mut stream_write).await;
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream_write).await;
            res
        };

        let remote_to_client = async {
            let res = tokio::io::copy(&mut stream_read, &mut tcp_write).await;
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut tcp_write).await;
            res
        };

        let _ = tokio::join!(client_to_remote, remote_to_client);

        tracing::trace!("SOCKS5 session finished for target {}", target);
        return Ok(());
    }

    // CMD_UDP_ASSOCIATE
    let start_wait = std::time::Instant::now();
    let transport = loop {
        if let Some(t) = conn_provider() {
            break t;
        }
        if start_wait.elapsed() > Duration::from_millis(6000) {
            tracing::warn!("No active proxy transport available to handle SOCKS request");
            stream
                .write_all(&[
                    SOCKS_VERSION,
                    REP_GENERAL_FAILURE,
                    0x00,
                    0x01,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
                .await?;
            bail!("Proxy transport not available");
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    };

    if cmd == CMD_UDP_ASSOCIATE {
        tracing::debug!(
            "SOCKS5 UDP ASSOCIATE request from {} for {}",
            client_addr,
            target
        );

        let session_id = NEXT_UDP_SESSION_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let incoming_rx = datagram_router.register(session_id);

        let udp_bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let relay =
            match crate::client::udp::UdpRelay::new(session_id, udp_bind_addr, incoming_rx).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Failed to bind client UDP relay socket: {}", e);
                    datagram_router.deregister(session_id);
                    stream
                        .write_all(&[
                            SOCKS_VERSION,
                            REP_GENERAL_FAILURE,
                            0x00,
                            0x01,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                        ])
                        .await?;
                    return Err(e);
                }
            };

        let relay_bound_addr = relay.local_addr()?;
        let relay = Arc::new(relay);

        // Open a control stream to the server for this UDP association
        let proxy_stream = match transport.open_stream().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Failed to open control stream on transport: {}", e);
                datagram_router.deregister(session_id);
                stream
                    .write_all(&[
                        SOCKS_VERSION,
                        REP_GENERAL_FAILURE,
                        0x00,
                        0x01,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ])
                    .await?;
                return Err(e);
            }
        };

        let (mut stream_read, mut stream_write) = tokio::io::split(proxy_stream);
        let req = ProxyRequest::udp_associate(target.clone());
        if let Err(e) = write_proxy_request(&mut stream_write, &req).await {
            datagram_router.deregister(session_id);
            stream
                .write_all(&[
                    SOCKS_VERSION,
                    REP_GENERAL_FAILURE,
                    0x00,
                    0x01,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
                .await?;
            return Err(e);
        }

        let resp = match read_proxy_response(&mut stream_read).await {
            Ok(resp) => resp,
            Err(e) => {
                datagram_router.deregister(session_id);
                stream
                    .write_all(&[
                        SOCKS_VERSION,
                        REP_GENERAL_FAILURE,
                        0x00,
                        0x01,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ])
                    .await?;
                return Err(e);
            }
        };

        if resp.status != STATUS_SUCCESS {
            datagram_router.deregister(session_id);
            stream
                .write_all(&[
                    SOCKS_VERSION,
                    REP_GENERAL_FAILURE,
                    0x00,
                    0x01,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
                .await?;
            return Ok(());
        }

        // Send success reply to SOCKS5 client containing bound UDP relay address
        let mut reply = vec![SOCKS_VERSION, REP_SUCCESS, 0x00];
        match relay_bound_addr {
            SocketAddr::V4(v4) => {
                reply.push(0x01); // ATYP IPv4
                reply.extend_from_slice(&v4.ip().octets());
                reply.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                reply.push(0x04); // ATYP IPv6
                reply.extend_from_slice(&v6.ip().octets());
                reply.extend_from_slice(&v6.port().to_be_bytes());
            }
        }
        stream.write_all(&reply).await?;

        // Spawn UDP relay tasks
        let relay_c2s = Arc::clone(&relay);
        let transport_c2s = Arc::clone(&transport);
        let acl_c2s = Arc::clone(&acl_engine);
        let c2s_handle = tokio::spawn(async move {
            let _ = relay_c2s.run_client_to_server(transport_c2s, acl_c2s).await;
        });

        let relay_s2c = Arc::clone(&relay);
        let s2c_handle = tokio::spawn(async move {
            let _ = relay_s2c.run_server_to_client().await;
        });

        // RFC 1928: The UDP association terminates when the TCP control connection terminates
        let mut eof_buf = [0u8; 1];
        let _ = stream.read(&mut eof_buf).await;

        c2s_handle.abort();
        s2c_handle.abort();
        datagram_router.deregister(session_id);
        tracing::debug!("SOCKS5 UDP ASSOCIATE session {} terminated", session_id);
        return Ok(());
    }

    tracing::debug!("SOCKS5 CONNECT request for target {}", target);

    // Open a new bidirectional stream on the active transport
    let proxy_stream = match transport.open_stream().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "Failed to open stream on transport ({}): {}",
                transport.mode_name(),
                e
            );
            stream
                .write_all(&[
                    SOCKS_VERSION,
                    REP_GENERAL_FAILURE,
                    0x00,
                    0x01,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
                .await?;
            return Err(e);
        }
    };

    let (mut stream_read, mut stream_write) = tokio::io::split(proxy_stream);

    // Send ProxyRequest
    let req = ProxyRequest::connect(target.clone());
    if let Err(e) = write_proxy_request(&mut stream_write, &req).await {
        stream
            .write_all(&[
                SOCKS_VERSION,
                REP_GENERAL_FAILURE,
                0x00,
                0x01,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await?;
        return Err(e);
    }

    // Read ProxyResponse from server
    let resp = match read_proxy_response(&mut stream_read).await {
        Ok(resp) => resp,
        Err(e) => {
            stream
                .write_all(&[
                    SOCKS_VERSION,
                    REP_GENERAL_FAILURE,
                    0x00,
                    0x01,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
                .await?;
            return Err(e);
        }
    };

    if resp.status != STATUS_SUCCESS {
        tracing::warn!(
            "Server failed proxy request for target {}: status {}",
            target,
            resp.status
        );
        stream
            .write_all(&[
                SOCKS_VERSION,
                REP_GENERAL_FAILURE,
                0x00,
                0x01,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await?;
        return Ok(());
    }

    // Success response to SOCKS5 client
    stream
        .write_all(&[SOCKS_VERSION, REP_SUCCESS, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // Bidirectional stream relay
    let (mut tcp_read, mut tcp_write) = stream.into_split();

    let client_to_remote = async {
        let res = tokio::io::copy(&mut tcp_read, &mut stream_write).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream_write).await;
        res
    };

    let remote_to_client = async {
        let res = tokio::io::copy(&mut stream_read, &mut tcp_write).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut tcp_write).await;
        res
    };

    let _ = tokio::join!(client_to_remote, remote_to_client);

    tracing::trace!("SOCKS5 session finished for target {}", target);
    Ok(())
}
