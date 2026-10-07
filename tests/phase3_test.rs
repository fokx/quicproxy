use http::StatusCode;
use quicproxy::client::run_client;
use quicproxy::config::{ClientConfig, ServerConfig, ServerNodeConfig};
use quicproxy::obfs::ObfuscationConfig;
use quicproxy::server::antiprobe::AntiProbeConfig;
use quicproxy::server::masquerade::{MasqueradeConfig, MasqueradeMode};
use quicproxy::server::run_server;
use quicproxy::tls::make_client_config;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });
    addr
}

async fn socks5_proxy_echo(
    socks5_addr: SocketAddr,
    target_addr: SocketAddr,
    message: &[u8],
) -> Vec<u8> {
    let mut stream = TcpStream::connect(socks5_addr).await.unwrap();

    // SOCKS5 greeting
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // SOCKS5 connect request
    let ip = match target_addr.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => panic!("IPv4 expected"),
    };
    let port = target_addr.port();
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00);

    // Send payload
    stream.write_all(message).await.unwrap();

    let mut echo_buf = vec![0u8; message.len()];
    stream.read_exact(&mut echo_buf).await.unwrap();
    echo_buf
}

#[tokio::test]
async fn test_obfuscation_mutual_exclusion() {
    let server_udp_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };

    let server_cfg = ServerConfig {
        listen: server_udp_addr,
        auth_key: "auth-pass".to_string(),
        obfuscation: Some(ObfuscationConfig {
            enabled: true,
            key: "obfs-secret".to_string(),
        }),
        masquerade: Some(MasqueradeConfig {
            mode: MasqueradeMode::FileServer,
            static_dir: None,
            upstream_url: None,
        }),
        ..Default::default()
    };

    // run_server must fail because obfuscation and masquerade are mutually exclusive
    let result = run_server(server_cfg).await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("mutually exclusive"));
}

#[tokio::test]
async fn test_masquerade_does_not_interfere_with_proxy() {
    let echo_addr = start_echo_server().await;
    let server_udp_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let socks5_addr: SocketAddr = {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap()
    };

    let auth_key = "proxy-with-masq-pass".to_string();

    let server_cfg = ServerConfig {
        listen: server_udp_addr,
        auth_key: auth_key.clone(),
        masquerade: Some(MasqueradeConfig {
            mode: MasqueradeMode::FileServer,
            static_dir: None,
            upstream_url: None,
        }),
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_server(server_cfg).await;
    });

    sleep(Duration::from_millis(200)).await;

    let client_cfg = ClientConfig::new_single_server(
        socks5_addr,
        ServerNodeConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: server_udp_addr.port(),
            auth_key: auth_key.clone(),
            insecure: true,
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    sleep(Duration::from_millis(600)).await;

    let msg = b"Testing proxy traffic with masquerade engine enabled concurrently!";
    let echoed = socks5_proxy_echo(socks5_addr, echo_addr, msg).await;
    assert_eq!(echoed, msg);
}

#[tokio::test]
async fn test_masquerade_file_server() {
    let server_udp_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };

    // Create a temporary static site directory
    let temp_dir =
        std::env::temp_dir().join(format!("quicproxy_masq_site_{}", rand::random::<u32>()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let index_file = temp_dir.join("index.html");
    std::fs::write(
        &index_file,
        "<html><body><h1>Legitimate Static Website</h1></body></html>",
    )
    .unwrap();

    let server_cfg = ServerConfig {
        listen: server_udp_addr,
        auth_key: "real-proxy-key".to_string(),
        masquerade: Some(MasqueradeConfig {
            mode: MasqueradeMode::FileServer,
            static_dir: Some(temp_dir.clone()),
            upstream_url: None,
        }),
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_server(server_cfg).await;
    });

    sleep(Duration::from_millis(200)).await;

    // Simulate an external prober / browser connecting via HTTP/3 without any proxy authentication!
    let client_crypto = make_client_config(true, None, None).unwrap();
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_crypto);

    let conn = endpoint
        .connect(server_udp_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    let h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::builder()
        .build::<_, _, bytes::Bytes>(h3_conn)
        .await
        .unwrap();

    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let req = http::Request::builder()
        .uri("https://localhost/")
        .body(())
        .unwrap();

    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();

    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Read body
    let mut body_bytes = Vec::new();
    while let Some(chunk) = stream.recv_data().await.unwrap() {
        use bytes::Buf;
        let mut b = chunk;
        while b.has_remaining() {
            body_bytes.push(b.get_u8());
        }
    }
    let body_str = String::from_utf8(body_bytes).unwrap();
    assert!(body_str.contains("Legitimate Static Website"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_obfuscation_roundtrip() {
    let echo_addr = start_echo_server().await;
    let server_udp_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let socks5_addr: SocketAddr = {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap()
    };

    let auth_key = "secret-auth-key".to_string();
    let obfs_key = "salamander-scramble-pass-xyz-987".to_string();

    let server_cfg = ServerConfig {
        listen: server_udp_addr,
        auth_key: auth_key.clone(),
        obfuscation: Some(ObfuscationConfig {
            enabled: true,
            key: obfs_key.clone(),
        }),
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_server(server_cfg).await;
    });

    sleep(Duration::from_millis(200)).await;

    let client_cfg = ClientConfig::new_single_server(
        socks5_addr,
        ServerNodeConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: server_udp_addr.port(),
            auth_key: auth_key.clone(),
            transport: quicproxy::config::TransportMode::Quic,
            insecure: true,
            obfuscation: Some(ObfuscationConfig {
                enabled: true,
                key: obfs_key.clone(),
            }),
            ..Default::default()
        },
    );

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    sleep(Duration::from_millis(600)).await;

    let msg = b"Testing end-to-end QUIC proxy through Salamander scrambled UDP packets!";
    let echoed = socks5_proxy_echo(socks5_addr, echo_addr, msg).await;
    assert_eq!(echoed, msg);
}

#[tokio::test]
async fn test_antiprobe_rate_limiting() {
    let server_udp_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };

    // Threshold of 2 failures, window of 10s
    let server_cfg = ServerConfig {
        listen: server_udp_addr,
        auth_key: "server-real-password".to_string(),
        anti_probe: Some(AntiProbeConfig {
            auth_jitter_min_ms: 5,
            auth_jitter_max_ms: 10,
            rate_limit_max_failures: 2,
            rate_limit_window_secs: 10,
        }),
        ..Default::default()
    };

    tokio::spawn(async move {
        let _ = run_server(server_cfg).await;
    });

    sleep(Duration::from_millis(200)).await;

    let client_crypto = make_client_config(true, None, None).unwrap();
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_crypto);

    // Attempt 1: Connect and send invalid auth token
    let conn1 = endpoint
        .connect(server_udp_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut send1, mut recv1) = conn1.open_bi().await.unwrap();
    let invalid_req = quicproxy::protocol::AuthRequest::new([0xee; 32]);
    let _ = quicproxy::protocol::write_auth_request(&mut send1, &invalid_req).await;
    let _ = quicproxy::protocol::read_auth_response(&mut recv1).await;

    // Attempt 2: Connect and send invalid auth token (reaches threshold = 2)
    let conn2 = endpoint
        .connect(server_udp_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut send2, mut recv2) = conn2.open_bi().await.unwrap();
    let _ = quicproxy::protocol::write_auth_request(&mut send2, &invalid_req).await;
    let _ = quicproxy::protocol::read_auth_response(&mut recv2).await;

    sleep(Duration::from_millis(50)).await;

    // Attempt 3: Now rate limited! The server closes connection immediately with code 1
    let conn3 = endpoint
        .connect(server_udp_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let bi_res = conn3.open_bi().await;
    // Should be closed by server due to rate limit
    match bi_res {
        Ok((_s, mut r)) => {
            let res = quicproxy::protocol::read_auth_response(&mut r).await;
            assert!(res.is_err());
        }
        Err(e) => {
            assert!(e.to_string().contains("closed") || e.to_string().contains("reset"));
        }
    }
}
