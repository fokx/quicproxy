use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

use quicproxy::client::run_client;
use quicproxy::config::{
    ClientConfig, MultiServerRoutingConfig, ServerConfig, ServerNodeConfig, TransportMode,
};
use quicproxy::obfs::ObfuscationConfig;
use quicproxy::realm::RendezvousServer;
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

/// Spawn a mock RFC 5389 STUN server that responds with XOR-MAPPED-ADDRESS for IPv4
async fn spawn_mock_stun_server() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                res = socket.recv_from(&mut buf) => {
                    let Ok((n, from)) = res else { break; };
                    if n >= 20 {
                        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
                        if msg_type == 0x0001 {
                            let mut tx_id = [0u8; 12];
                            tx_id.copy_from_slice(&buf[8..20]);

                            let mut resp = Vec::new();
                            resp.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Success
                            resp.extend_from_slice(&12u16.to_be_bytes());     // Attribute length (12)
                            resp.extend_from_slice(&0x2112A442u32.to_be_bytes());
                            resp.extend_from_slice(&tx_id);

                            // ATTR_XOR_MAPPED_ADDRESS (0x0020)
                            resp.extend_from_slice(&0x0020u16.to_be_bytes());
                            resp.extend_from_slice(&8u16.to_be_bytes());
                            resp.push(0);
                            resp.push(1);
                            resp.extend_from_slice(&(from.port() ^ 0x2112).to_be_bytes());
                            if let std::net::IpAddr::V4(v4) = from.ip() {
                                let xor_ip = u32::from(v4) ^ 0x2112A442;
                                resp.extend_from_slice(&xor_ip.to_be_bytes());
                            }
                            let _ = socket.send_to(&resp, from).await;
                        }
                    }
                }
            }
        }
    });

    (addr, shutdown_tx)
}

#[tokio::test]
async fn test_realm_e2e_direct_hole_punch_and_proxy() {
    let echo_addr = spawn_echo_server().await;
    let (stun_addr, _stun_shutdown) = spawn_mock_stun_server().await;

    // 1. Spawn Rendezvous server
    let (_r_server, r_addr) = RendezvousServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Some("test-token".to_string()),
    )
    .await
    .unwrap();

    let realm_uri = format!(
        "realm+http://test-token@{}/test-realm-1?stun={}",
        r_addr, stun_addr
    );

    let socks5_addr: SocketAddr = {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap()
    };

    let auth_key = "test-secret-key-realm-1".to_string();

    // 2. Start QuicProxy Server in Realm mode
    let server_cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        realm_listen: Some(realm_uri.clone()),
        auth_key: auth_key.clone(),
        auto_cert: true,
        auto_cert_domain: "localhost".to_string(),
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_server(server_cfg).await;
    });

    // Allow server to perform initial STUN and register with rendezvous
    sleep(Duration::from_millis(500)).await;

    // 3. Start QuicProxy Client pointing to realm URI
    let node = ServerNodeConfig {
        name: "realm-server-1".to_string(),
        server_addr: realm_uri.clone(),
        server_port: 0,
        auth_key: auth_key.clone(),
        transport: TransportMode::Quic,
        insecure: true,
        server_name: Some("localhost".to_string()),
        weight: 1,
        priority: 1,
        obfuscation: None,
        tls_fingerprint: None,
        realm: None,
        ca_cert: None,
        cert_fingerprint: None,
    };

    let client_cfg = ClientConfig {
        socks5_listen: socks5_addr,
        servers: vec![node],
        routing: MultiServerRoutingConfig::default(),
        socks5_user: None,
        socks5_password: None,
        acl: None,
        outbounds: Vec::new(),
    };

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    // Wait for client hole punching to finish and SOCKS5 proxy to become ready
    let mut connected = false;
    for _ in 0..20 {
        sleep(Duration::from_millis(300)).await;
        if TcpStream::connect(socks5_addr).await.is_ok() {
            connected = true;
            break;
        }
    }
    assert!(connected, "Client SOCKS5 listener did not become available");

    // 4. Test SOCKS5 TCP connect through hole-punched QUIC tunnel
    let mut socks_conn = timeout(Duration::from_secs(5), TcpStream::connect(socks5_addr))
        .await
        .expect("Timeout connecting to SOCKS5 listener")
        .expect("Failed to connect to SOCKS5 listener");

    // SOCKS5 greeting
    socks_conn.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    socks_conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00], "SOCKS5 greeting failed");

    // SOCKS5 CONNECT request
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

    // Send payload through punched QUIC proxy tunnel
    let test_msg = b"Hello from hole-punched Realm QUIC tunnel!";
    socks_conn.write_all(test_msg).await.unwrap();

    let mut recv_buf = vec![0u8; test_msg.len()];
    timeout(Duration::from_secs(5), socks_conn.read_exact(&mut recv_buf))
        .await
        .expect("Timeout reading echo response over Realm tunnel")
        .expect("Error reading echo response over Realm tunnel");

    assert_eq!(recv_buf, test_msg);
}

#[tokio::test]
async fn test_realm_with_obfuscation() {
    let echo_addr = spawn_echo_server().await;
    let (stun_addr, _stun_shutdown) = spawn_mock_stun_server().await;

    // 1. Spawn Rendezvous server
    let (_r_server, r_addr) = RendezvousServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Some("test-token-obfs".to_string()),
    )
    .await
    .unwrap();

    let realm_uri = format!(
        "realm+http://test-token-obfs@{}/test-realm-obfs?stun={}",
        r_addr, stun_addr
    );

    let socks5_addr: SocketAddr = {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap()
    };

    let auth_key = "test-secret-key-realm-obfs".to_string();
    let obfs_key = "salamander-realm-obfs-key".to_string();

    // 2. Start QuicProxy Server in Realm mode with Salamander obfuscation
    let server_cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        realm_listen: Some(realm_uri.clone()),
        auth_key: auth_key.clone(),
        auto_cert: true,
        auto_cert_domain: "localhost".to_string(),
        obfuscation: Some(ObfuscationConfig {
            enabled: true,
            key: obfs_key.clone(),
        }),
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_server(server_cfg).await;
    });

    sleep(Duration::from_millis(500)).await;

    // 3. Start QuicProxy Client pointing to realm URI with matching Salamander obfuscation
    let node = ServerNodeConfig {
        name: "realm-server-obfs".to_string(),
        server_addr: realm_uri.clone(),
        server_port: 0,
        auth_key: auth_key.clone(),
        transport: TransportMode::Quic,
        insecure: true,
        server_name: Some("localhost".to_string()),
        weight: 1,
        priority: 1,
        obfuscation: Some(ObfuscationConfig {
            enabled: true,
            key: obfs_key.clone(),
        }),
        tls_fingerprint: None,
        realm: None,
        ca_cert: None,
        cert_fingerprint: None,
    };

    let client_cfg = ClientConfig {
        socks5_listen: socks5_addr,
        servers: vec![node],
        routing: MultiServerRoutingConfig::default(),
        socks5_user: None,
        socks5_password: None,
        acl: None,
        outbounds: Vec::new(),
    };

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    let mut connected = false;
    for _ in 0..20 {
        sleep(Duration::from_millis(300)).await;
        if TcpStream::connect(socks5_addr).await.is_ok() {
            connected = true;
            break;
        }
    }
    assert!(connected, "Client SOCKS5 listener did not become available");

    let mut socks_conn = timeout(Duration::from_secs(5), TcpStream::connect(socks5_addr))
        .await
        .expect("Timeout connecting to SOCKS5 listener")
        .expect("Failed to connect to SOCKS5 listener");

    socks_conn.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    socks_conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

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
    assert_eq!(socks_reply[1], 0x00);

    let test_msg = b"Hello from obfuscated Realm QUIC tunnel!";
    socks_conn.write_all(test_msg).await.unwrap();

    let mut recv_buf = vec![0u8; test_msg.len()];
    timeout(Duration::from_secs(5), socks_conn.read_exact(&mut recv_buf))
        .await
        .expect("Timeout reading echo response over Obfuscated Realm tunnel")
        .expect("Error reading echo response over Obfuscated Realm tunnel");

    assert_eq!(recv_buf, test_msg);
}
