use quicproxy::client::run_client;
use quicproxy::config::{ClientConfig, ServerConfig, ServerNodeConfig, TransportMode};
use quicproxy::server::run_server;
use quicproxy::tls_fingerprint::TlsFingerprintConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

async fn start_udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            if let Ok((len, src)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&buf[..len], src).await;
            }
        }
    });
    addr
}

/// Perform SOCKS5 UDP ASSOCIATE handshake and return the bound UDP relay address and control TCP stream
async fn socks5_udp_associate_handshake(socks5_addr: SocketAddr) -> (SocketAddr, TcpStream) {
    let mut tcp_stream = TcpStream::connect(socks5_addr).await.unwrap();

    // 1. Negotiation: NO_AUTH
    tcp_stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    tcp_stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // 2. Request: CMD = 0x03 (UDP ASSOCIATE) with 0.0.0.0:0
    let req = [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    tcp_stream.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    tcp_stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00, "SOCKS5 UDP ASSOCIATE request failed");
    assert_eq!(reply[3], 0x01, "Expected IPv4 BND.ADDR");

    let bound_ip = std::net::Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
    let bound_port = u16::from_be_bytes([reply[8], reply[9]]);
    let relay_addr = SocketAddr::new(std::net::IpAddr::V4(bound_ip), bound_port);

    (relay_addr, tcp_stream)
}

#[tokio::test]
async fn test_udp_associate_quic() {
    let udp_echo_addr = start_udp_echo_server().await;

    let server_listen_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let socks5_addr: SocketAddr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };

    let auth_key = "phase4-udp-quic-auth-key".to_string();

    let server_cfg = ServerConfig {
        listen: server_listen_addr,
        auth_key: auth_key.clone(),
        auto_cert: true,
        auto_cert_domain: "localhost".to_string(),
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_server(server_cfg).await;
    });

    sleep(Duration::from_millis(300)).await;

    let client_cfg = ClientConfig::new_single_server(
        socks5_addr,
        ServerNodeConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: server_listen_addr.port(),
            auth_key: auth_key.clone(),
            transport: TransportMode::Quic,
            insecure: true,
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    sleep(Duration::from_millis(800)).await;

    let (relay_addr, _control_stream) = socks5_udp_associate_handshake(socks5_addr).await;

    // Send UDP packet with RFC 1928 header to the relay address
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let msg = b"Testing UDP ASSOCIATE over native QUIC datagrams!";
    let target_addr = quicproxy::protocol::TargetAddr::Ip(udp_echo_addr);
    let packet = quicproxy::client::udp::build_socks5_udp_header(&target_addr, msg);

    client_sock.send_to(&packet, relay_addr).await.unwrap();

    let mut recv_buf = [0u8; 2048];
    let (n, from_addr) = timeout(Duration::from_secs(5), client_sock.recv_from(&mut recv_buf))
        .await
        .expect("Timeout waiting for echoed UDP packet")
        .expect("Error receiving UDP packet");

    assert_eq!(from_addr, relay_addr);
    let (parsed_target, payload) = quicproxy::client::udp::parse_socks5_udp_header(&recv_buf[..n]).unwrap();
    assert_eq!(parsed_target, target_addr);
    assert_eq!(payload, msg);
}

#[tokio::test]
async fn test_udp_associate_tcp_fallback() {
    let udp_echo_addr = start_udp_echo_server().await;

    let server_listen_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let socks5_addr: SocketAddr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };

    let auth_key = "phase4-udp-tcp-auth-key".to_string();

    let server_cfg = ServerConfig {
        listen: server_listen_addr,
        auth_key: auth_key.clone(),
        auto_cert: true,
        auto_cert_domain: "localhost".to_string(),
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_server(server_cfg).await;
    });

    sleep(Duration::from_millis(300)).await;

    // Force client into TCP fallback mode
    let client_cfg = ClientConfig::new_single_server(
        socks5_addr,
        ServerNodeConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: server_listen_addr.port(),
            auth_key: auth_key.clone(),
            transport: TransportMode::Tcp,
            insecure: true,
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    sleep(Duration::from_millis(800)).await;

    let (relay_addr, _control_stream) = socks5_udp_associate_handshake(socks5_addr).await;

    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let msg = b"Testing UDP ASSOCIATE over raw TCP ChaCha20-Poly1305 fallback encapsulation!";
    let target_addr = quicproxy::protocol::TargetAddr::Ip(udp_echo_addr);
    let packet = quicproxy::client::udp::build_socks5_udp_header(&target_addr, msg);

    client_sock.send_to(&packet, relay_addr).await.unwrap();

    let mut recv_buf = [0u8; 2048];
    let (n, from_addr) = timeout(Duration::from_secs(5), client_sock.recv_from(&mut recv_buf))
        .await
        .expect("Timeout waiting for echoed UDP packet via TCP fallback")
        .expect("Error receiving UDP packet");

    assert_eq!(from_addr, relay_addr);
    let (parsed_target, payload) = quicproxy::client::udp::parse_socks5_udp_header(&recv_buf[..n]).unwrap();
    assert_eq!(parsed_target, target_addr);
    assert_eq!(payload, msg);
}

#[tokio::test]
async fn test_udp_association_lifetime() {
    let udp_echo_addr = start_udp_echo_server().await;

    let server_listen_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let socks5_addr: SocketAddr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };

    let auth_key = "phase4-udp-lifetime-key".to_string();

    let server_cfg = ServerConfig {
        listen: server_listen_addr,
        auth_key: auth_key.clone(),
        auto_cert: true,
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_server(server_cfg).await;
    });

    sleep(Duration::from_millis(300)).await;

    let client_cfg = ClientConfig::new_single_server(
        socks5_addr,
        ServerNodeConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: server_listen_addr.port(),
            auth_key: auth_key.clone(),
            insecure: true,
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    sleep(Duration::from_millis(800)).await;

    let (relay_addr, control_stream) = socks5_udp_associate_handshake(socks5_addr).await;

    // Drop control stream to simulate client TCP disconnect
    drop(control_stream);
    sleep(Duration::from_millis(300)).await;

    // Sending a packet to relay socket after control disconnect should NOT receive an echo
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let msg = b"This should not be echoed!";
    let target_addr = quicproxy::protocol::TargetAddr::Ip(udp_echo_addr);
    let packet = quicproxy::client::udp::build_socks5_udp_header(&target_addr, msg);

    let _ = client_sock.send_to(&packet, relay_addr).await;

    let mut recv_buf = [0u8; 512];
    let res = timeout(Duration::from_millis(500), client_sock.recv_from(&mut recv_buf)).await;
    assert!(res.is_err(), "Expected timeout since UDP association terminated");
}

#[tokio::test]
async fn test_udp_concurrent_sessions() {
    let udp_echo_addr = start_udp_echo_server().await;

    let server_listen_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let socks5_addr: SocketAddr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };

    let auth_key = "phase4-udp-concurrent-key".to_string();

    let server_cfg = ServerConfig {
        listen: server_listen_addr,
        auth_key: auth_key.clone(),
        auto_cert: true,
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_server(server_cfg).await;
    });

    sleep(Duration::from_millis(300)).await;

    let client_cfg = ClientConfig::new_single_server(
        socks5_addr,
        ServerNodeConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: server_listen_addr.port(),
            auth_key: auth_key.clone(),
            insecure: true,
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    sleep(Duration::from_millis(800)).await;

    let mut handles = Vec::new();

    for i in 0..5 {
        let s5_addr = socks5_addr;
        let echo_addr = udp_echo_addr;
        handles.push(tokio::spawn(async move {
            let (relay_addr, _ctrl) = socks5_udp_associate_handshake(s5_addr).await;
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let msg = format!("Concurrent UDP stream message #{}", i);
            let target = quicproxy::protocol::TargetAddr::Ip(echo_addr);
            let packet = quicproxy::client::udp::build_socks5_udp_header(&target, msg.as_bytes());

            sock.send_to(&packet, relay_addr).await.unwrap();

            let mut buf = [0u8; 1024];
            let (n, _) = timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
                .await
                .expect("Timeout waiting for response in concurrent task")
                .expect("Failed to receive packet");

            let (_, payload) = quicproxy::client::udp::parse_socks5_udp_header(&buf[..n]).unwrap();
            assert_eq!(payload, msg.as_bytes());
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn test_tls_fingerprint_alpn() {
    let custom_alpn = vec!["h3-29".to_string(), "h3".to_string()];
    let fp_config = TlsFingerprintConfig {
        alpn: custom_alpn.clone(),
        cipher_profile: "chrome".to_string(),
    };

    let client_config_res = quicproxy::tls::make_client_config_with_fingerprint(
        true,
        None,
        None,
        Some(&fp_config),
    );

    assert!(client_config_res.is_ok());
}

#[tokio::test]
async fn test_metrics_counting() {
    let metrics = Arc::new(quicproxy::metrics::Metrics::new());

    assert_eq!(metrics.active_tcp_streams.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(metrics.active_udp_sessions.load(std::sync::atomic::Ordering::Relaxed), 0);

    metrics.inc_active_tcp_streams();
    metrics.inc_active_tcp_streams();
    assert_eq!(metrics.active_tcp_streams.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert_eq!(metrics.total_tcp_streams.load(std::sync::atomic::Ordering::Relaxed), 2);

    metrics.dec_active_tcp_streams();
    assert_eq!(metrics.active_tcp_streams.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(metrics.total_tcp_streams.load(std::sync::atomic::Ordering::Relaxed), 2);

    metrics.inc_active_udp_sessions();
    assert_eq!(metrics.active_udp_sessions.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(metrics.total_udp_sessions.load(std::sync::atomic::Ordering::Relaxed), 1);

    metrics.add_bytes_sent(1024);
    metrics.add_bytes_received(2048);
    assert_eq!(metrics.bytes_sent.load(std::sync::atomic::Ordering::Relaxed), 1024);
    assert_eq!(metrics.bytes_received.load(std::sync::atomic::Ordering::Relaxed), 2048);

    metrics.inc_datagrams_sent();
    metrics.inc_datagrams_received();
    assert_eq!(metrics.datagrams_sent.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(metrics.datagrams_received.load(std::sync::atomic::Ordering::Relaxed), 1);

    // Verify log_summary executes without panic
    metrics.log_summary();
}
