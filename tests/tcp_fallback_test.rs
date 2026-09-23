use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

use quicproxy::client::run_client;
use quicproxy::config::{ClientConfig, ServerConfig, TransportMode};
use quicproxy::server::run_server;

/// Spawn a simple TCP echo server that echoes all received bytes back to the sender
async fn spawn_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        }
    });

    addr
}

/// Helper to execute a SOCKS5 connect request and send/receive data
async fn socks5_proxy_echo(
    socks5_addr: SocketAddr,
    target_addr: SocketAddr,
    payload: &[u8],
) -> Vec<u8> {
    let mut socks_conn = timeout(Duration::from_secs(5), TcpStream::connect(socks5_addr))
        .await
        .expect("Timeout connecting to SOCKS5 listener")
        .expect("Failed to connect to SOCKS5 listener");

    // SOCKS5 Handshake: Version 5, 1 Method: NO_AUTH (0x00)
    socks_conn.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    socks_conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00], "SOCKS5 handshake failed");

    // SOCKS5 Request: CONNECT to target (IPv4)
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    let ip = match target_addr.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => panic!("Expected IPv4"),
    };
    req.extend_from_slice(&ip);
    req.extend_from_slice(&target_addr.port().to_be_bytes());

    socks_conn.write_all(&req).await.unwrap();

    let mut socks_reply = [0u8; 10];
    socks_conn.read_exact(&mut socks_reply).await.unwrap();
    assert_eq!(
        socks_reply[1], 0x00,
        "SOCKS5 CONNECT failed with status 0x{:02x}",
        socks_reply[1]
    );

    // Send payload through proxy
    socks_conn.write_all(payload).await.unwrap();

    let mut recv_buf = vec![0u8; payload.len()];
    timeout(Duration::from_secs(5), socks_conn.read_exact(&mut recv_buf))
        .await
        .expect("Timeout reading echo response")
        .expect("Error reading echo response");

    recv_buf
}

#[tokio::test]
async fn test_tcp_transport_direct_echo() {
    let echo_addr = spawn_echo_server().await;

    let server_addr: SocketAddr = {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap()
    };
    let socks5_addr: SocketAddr = {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap()
    };

    let auth_key = "tcp-fallback-secret-key-1".to_string();

    let server_cfg = ServerConfig {
        listen: server_addr,
        auth_key: auth_key.clone(),
        tls_cert: None,
        tls_key: None,
        auto_cert: true,
        auto_cert_domain: "localhost".to_string(),
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_server(server_cfg).await;
    });

    sleep(Duration::from_millis(200)).await;

    // Explicitly configure client for TCP transport mode
    let client_cfg = ClientConfig {
        socks5_listen: socks5_addr,
        server_addr: "127.0.0.1".to_string(),
        server_port: server_addr.port(),
        auth_key: auth_key.clone(),
        transport: TransportMode::Tcp,
        server_name: Some("localhost".to_string()),
        insecure: true,
        cert_fingerprint: None,
        ca_cert: None,
        socks5_user: None,
        socks5_password: None,
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    sleep(Duration::from_millis(600)).await;

    let msg = b"Hello from QuicProxy Phase 2 TCP ChaCha20-Poly1305 fallback!";
    let echoed = socks5_proxy_echo(socks5_addr, echo_addr, msg).await;
    assert_eq!(echoed, msg);
}

#[tokio::test]
async fn test_tcp_multiplexing_concurrent_stress() {
    let echo_addr = spawn_echo_server().await;

    let server_addr: SocketAddr = {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap()
    };
    let socks5_addr: SocketAddr = {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap()
    };

    let auth_key = "tcp-multiplexing-stress-key".to_string();

    let server_cfg = ServerConfig {
        listen: server_addr,
        auth_key: auth_key.clone(),
        tls_cert: None,
        tls_key: None,
        auto_cert: true,
        auto_cert_domain: "localhost".to_string(),
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_server(server_cfg).await;
    });

    sleep(Duration::from_millis(200)).await;

    let client_cfg = ClientConfig {
        socks5_listen: socks5_addr,
        server_addr: "127.0.0.1".to_string(),
        server_port: server_addr.port(),
        auth_key: auth_key.clone(),
        transport: TransportMode::Tcp,
        server_name: Some("localhost".to_string()),
        insecure: true,
        cert_fingerprint: None,
        ca_cert: None,
        socks5_user: None,
        socks5_password: None,
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    sleep(Duration::from_millis(600)).await;

    // Launch 25 concurrent SOCKS5 connections through the single TCP multiplexed tunnel
    const CONCURRENCY: usize = 25;
    let mut handles = Vec::with_capacity(CONCURRENCY);

    for i in 0..CONCURRENCY {
        let handle = tokio::spawn(async move {
            let payload = format!("Multiplexed concurrent stream request payload #{}! Repeating extra data to ensure varied frame sizes...", i);
            let echoed = socks5_proxy_echo(socks5_addr, echo_addr, payload.as_bytes()).await;
            assert_eq!(echoed, payload.as_bytes());
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("Concurrent stream task failed");
    }
}

#[tokio::test]
async fn test_auto_fallback_when_udp_blocked() {
    let echo_addr = spawn_echo_server().await;

    // Set up a server where ONLY the TCP listener accepts connections,
    // simulating a network environment where UDP/QUIC is completely blocked.
    let tcp_listen_addr: SocketAddr = {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap()
    };
    let socks5_addr: SocketAddr = {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap()
    };

    let auth_key = Arc::new("udp-blocked-auto-fallback-test".to_string());
    let auth_key_server = Arc::clone(&auth_key);
    let rate_limiter = Arc::new(quicproxy::server::antiprobe::RateLimiter::new(10, 60));
    let anti_probe = Arc::new(quicproxy::server::antiprobe::AntiProbeConfig::default());

    // Bind TCP listener only
    let tcp_listener = TcpListener::bind(tcp_listen_addr).await.unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = tcp_listener.accept().await {
            let key = Arc::clone(&auth_key_server);
            let rl = Arc::clone(&rate_limiter);
            let ap = Arc::clone(&anti_probe);
            tokio::spawn(async move {
                let _ = quicproxy::server::tcp::handle_tcp_connection(stream, key, rl, ap).await;
            });
        }
    });

    // Configure client in "auto" mode (default)
    let client_cfg = ClientConfig {
        socks5_listen: socks5_addr,
        server_addr: "127.0.0.1".to_string(),
        server_port: tcp_listen_addr.port(),
        auth_key: (*auth_key).clone(),
        transport: TransportMode::Auto, // Auto-fallback
        server_name: Some("localhost".to_string()),
        insecure: true,
        cert_fingerprint: None,
        ca_cert: None,
        socks5_user: None,
        socks5_password: None,
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    // Give time for QUIC attempt to fail / timeout (3s timeout) and fall back to TCP
    sleep(Duration::from_millis(3500)).await;

    let msg = b"Testing automatic fallback to TCP multiplexer when UDP is blocked!";
    let echoed = socks5_proxy_echo(socks5_addr, echo_addr, msg).await;
    assert_eq!(echoed, msg);
}

#[tokio::test]
async fn test_tcp_transport_auth_failure() {
    let server_addr: SocketAddr = {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap()
    };
    let socks5_addr: SocketAddr = {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap()
    };

    let server_cfg = ServerConfig {
        listen: server_addr,
        auth_key: "correct-server-password".to_string(),
        tls_cert: None,
        tls_key: None,
        auto_cert: true,
        auto_cert_domain: "localhost".to_string(),
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_server(server_cfg).await;
    });

    sleep(Duration::from_millis(200)).await;

    // Client connects with WRONG auth key
    let client_cfg = ClientConfig {
        socks5_listen: socks5_addr,
        server_addr: "127.0.0.1".to_string(),
        server_port: server_addr.port(),
        auth_key: "wrong-password".to_string(),
        transport: TransportMode::Tcp,
        server_name: Some("localhost".to_string()),
        insecure: true,
        cert_fingerprint: None,
        ca_cert: None,
        socks5_user: None,
        socks5_password: None,
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    sleep(Duration::from_millis(800)).await;

    let mut socks_conn = TcpStream::connect(socks5_addr).await.unwrap();

    // SOCKS5 negotiation succeeds locally
    socks_conn.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    socks_conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // But CONNECT should fail because TCP fallback authentication was rejected
    let req = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80];
    socks_conn.write_all(&req).await.unwrap();

    let mut socks_reply = [0u8; 10];
    socks_conn.read_exact(&mut socks_reply).await.unwrap();
    assert_ne!(
        socks_reply[1], 0x00,
        "Should have rejected proxy request when unauthenticated on TCP fallback"
    );
}
