use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

use quicproxy::client::run_client;
use quicproxy::config::{ClientConfig, ServerConfig, ServerNodeConfig};
use quicproxy::server::run_server;
use quicproxy::tls::generate_self_signed;

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

#[tokio::test]
async fn test_quicproxy_end_to_end_echo() {
    let echo_addr = spawn_echo_server().await;

    // Pick random available ports
    let server_udp_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let socks5_addr: SocketAddr = {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap()
    };

    let auth_key = "test-secret-key-12345".to_string();

    // 1. Generate self-signed cert for server
    let (cert_pem, key_pem, fingerprint) = generate_self_signed("localhost").unwrap();
    let cert_file = tempfile_named("cert.pem", &cert_pem);
    let key_file = tempfile_named("key.pem", &key_pem);

    let server_cfg = ServerConfig {
        listen: server_udp_addr,
        auth_key: auth_key.clone(),
        tls_cert: Some(cert_file.clone()),
        tls_key: Some(key_file.clone()),
        auto_cert: false,
        auto_cert_domain: "localhost".to_string(),
        ..Default::default()
    };

    // Spawn server
    tokio::spawn(async move {
        let _ = run_server(server_cfg).await;
    });

    sleep(Duration::from_millis(200)).await;

    // 2. Configure and run client with pinned cert fingerprint
    let client_cfg = ClientConfig::new_single_server(
        socks5_addr,
        ServerNodeConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: server_udp_addr.port(),
            auth_key: auth_key.clone(),
            server_name: Some("localhost".to_string()),
            cert_fingerprint: Some(fingerprint),
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    // Wait for client to connect and SOCKS5 to bind
    sleep(Duration::from_millis(800)).await;

    // 3. Connect to SOCKS5 proxy as a client (like Firefox would)
    let mut socks_conn = timeout(Duration::from_secs(5), TcpStream::connect(socks5_addr))
        .await
        .expect("Timeout connecting to SOCKS5 listener")
        .expect("Failed to connect to SOCKS5 listener");

    // SOCKS5 Handshake: Version 5, 1 Method: NO_AUTH (0x00)
    socks_conn.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    socks_conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00], "SOCKS5 handshake failed");

    // SOCKS5 Request: CONNECT to echo_addr (IPv4)
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    let ip = match echo_addr.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => panic!("Expected IPv4"),
    };
    req.extend_from_slice(&ip);
    req.extend_from_slice(&echo_addr.port().to_be_bytes());

    socks_conn.write_all(&req).await.unwrap();

    let mut socks_reply = [0u8; 10];
    socks_conn.read_exact(&mut socks_reply).await.unwrap();
    assert_eq!(socks_reply[0], 0x05);
    assert_eq!(
        socks_reply[1], 0x00,
        "SOCKS5 CONNECT failed with status 0x{:02x}",
        socks_reply[1]
    );

    // Send payload through proxy
    let test_msg = b"Hello world over QuicProxy QUIC tunnel!";
    socks_conn.write_all(test_msg).await.unwrap();

    let mut recv_buf = vec![0u8; test_msg.len()];
    timeout(Duration::from_secs(5), socks_conn.read_exact(&mut recv_buf))
        .await
        .expect("Timeout reading echo response")
        .expect("Error reading echo response");

    assert_eq!(recv_buf, test_msg);

    // Clean up temporary cert files
    let _ = std::fs::remove_file(cert_file);
    let _ = std::fs::remove_file(key_file);
}

#[tokio::test]
async fn test_quicproxy_domain_resolution_on_server() {
    let echo_addr = spawn_echo_server().await;

    let server_udp_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let socks5_addr: SocketAddr = {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap()
    };

    let auth_key = "domain-test-secret".to_string();

    let server_cfg = ServerConfig {
        listen: server_udp_addr,
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

    // Use insecure = true for fast testing
    let client_cfg = ClientConfig::new_single_server(
        socks5_addr,
        ServerNodeConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: server_udp_addr.port(),
            auth_key: auth_key.clone(),
            server_name: Some("localhost".to_string()),
            insecure: true,
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    sleep(Duration::from_millis(800)).await;

    let mut socks_conn = timeout(Duration::from_secs(5), TcpStream::connect(socks5_addr))
        .await
        .expect("Timeout connecting to SOCKS5")
        .expect("Failed to connect to SOCKS5");

    // Handshake
    socks_conn.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    socks_conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // Request with Domain name: "127.0.0.1" as ATYP_DOMAIN (0x03)
    let domain = "127.0.0.1";
    let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    req.extend_from_slice(domain.as_bytes());
    req.extend_from_slice(&echo_addr.port().to_be_bytes());

    socks_conn.write_all(&req).await.unwrap();

    let mut socks_reply = [0u8; 10];
    socks_conn.read_exact(&mut socks_reply).await.unwrap();
    assert_eq!(socks_reply[1], 0x00, "SOCKS5 domain connect failed");

    // Send payload
    let test_msg = b"Testing domain-based target routing over QUIC!";
    socks_conn.write_all(test_msg).await.unwrap();

    let mut recv_buf = vec![0u8; test_msg.len()];
    socks_conn.read_exact(&mut recv_buf).await.unwrap();
    assert_eq!(recv_buf, test_msg);
}

fn tempfile_named(name: &str, content: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let unique = rand::random::<u64>();
    path.push(format!("quicproxy_test_{}_{}", unique, name));
    std::fs::write(&path, content).unwrap();
    path
}

#[tokio::test]
async fn test_quicproxy_auth_failure_rejected() {
    let server_udp_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let socks5_addr: SocketAddr = {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap()
    };

    let server_cfg = ServerConfig {
        listen: server_udp_addr,
        auth_key: "server-real-password".to_string(),
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

    // Client uses the WRONG auth key
    let client_cfg = ClientConfig::new_single_server(
        socks5_addr,
        ServerNodeConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: server_udp_addr.port(),
            auth_key: "wrong-password-attacker".to_string(),
            server_name: Some("localhost".to_string()),
            insecure: true,
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    sleep(Duration::from_millis(800)).await;

    let mut socks_conn = TcpStream::connect(socks5_addr).await.unwrap();

    // SOCKS5 Handshake succeeds locally
    socks_conn.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    socks_conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // But when attempting CONNECT, it should fail with general failure (0x01) because QUIC is not authenticated
    let req = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80];
    socks_conn.write_all(&req).await.unwrap();

    let mut socks_reply = [0u8; 10];
    socks_conn.read_exact(&mut socks_reply).await.unwrap();
    assert_ne!(
        socks_reply[1], 0x00,
        "Should have failed CONNECT when unauthenticated"
    );
}
