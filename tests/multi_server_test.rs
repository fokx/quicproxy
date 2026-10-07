use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

use quicproxy::client::run_client;
use quicproxy::config::{
    AggregationStrategy, ClientConfig, MultiServerRoutingConfig, ServerConfig,
    ServerNodeConfig, TrafficMode, TransportMode,
};
use quicproxy::server::run_server;

/// A test target server that tracks which remote peer connected and echoes payload
struct TargetServer {
    pub addr: SocketAddr,
    pub connections_handled: Arc<AtomicUsize>,
    #[allow(dead_code)]
    pub peer_ports: Arc<tokio::sync::Mutex<Vec<u16>>>,
}

async fn spawn_target_server() -> TargetServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections_handled = Arc::new(AtomicUsize::new(0));
    let peer_ports = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let count_clone = Arc::clone(&connections_handled);
    let ports_clone = Arc::clone(&peer_ports);

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, peer)) = listener.accept().await {
                count_clone.fetch_add(1, Ordering::SeqCst);
                {
                    let mut lock = ports_clone.lock().await;
                    lock.push(peer.port());
                }
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

    TargetServer {
        addr,
        connections_handled,
        peer_ports,
    }
}

async fn socks5_proxy_request(socks_addr: SocketAddr, target: SocketAddr, msg: &[u8]) -> Vec<u8> {
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(socks_addr))
        .await
        .expect("Timeout connecting to SOCKS5")
        .expect("Failed to connect to SOCKS5");

    // SOCKS5 greeting
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // SOCKS5 connect request
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    match target {
        SocketAddr::V4(v4) => {
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        _ => panic!("IPv4 expected"),
    }
    stream.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00, "SOCKS5 connect request failed");

    // Send payload and read response
    stream.write_all(msg).await.unwrap();
    let mut echoed = vec![0u8; msg.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    echoed
}

#[tokio::test]
async fn test_multi_server_aggregation_round_robin() {
    let target = spawn_target_server().await;

    // Server 1
    let s1_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let s1_key = "server1-secret-key".to_string();
    let s1_cfg = ServerConfig {
        listen: s1_addr,
        auth_key: s1_key.clone(),
        auto_cert: true,
        ..Default::default()
    };
    tokio::spawn(async move {
        let _ = run_server(s1_cfg).await;
    });

    // Server 2
    let s2_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let s2_key = "server2-secret-key".to_string();
    let s2_cfg = ServerConfig {
        listen: s2_addr,
        auth_key: s2_key.clone(),
        auto_cert: true,
        ..Default::default()
    };
    tokio::spawn(async move {
        let _ = run_server(s2_cfg).await;
    });

    sleep(Duration::from_millis(300)).await;

    // Client with 2 servers in Aggregation Round-Robin mode
    let socks5_addr: SocketAddr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };

    let client_cfg = ClientConfig {
        socks5_listen: socks5_addr,
        servers: vec![
            ServerNodeConfig {
                name: "node-1".to_string(),
                server_addr: "127.0.0.1".to_string(),
                server_port: s1_addr.port(),
                auth_key: s1_key,
                transport: TransportMode::Auto,
                insecure: true,
                ..Default::default()
            },
            ServerNodeConfig {
                name: "node-2".to_string(),
                server_addr: "127.0.0.1".to_string(),
                server_port: s2_addr.port(),
                auth_key: s2_key,
                transport: TransportMode::Auto,
                insecure: true,
                ..Default::default()
            },
        ],
        routing: MultiServerRoutingConfig {
            mode: TrafficMode::Aggregation,
            strategy: AggregationStrategy::RoundRobin,
            relay_to_server: None,
            relay_fallback_direct: true,
        },
        socks5_user: None,
        socks5_password: None,
        acl: None,
        outbounds: Vec::new(),
    };

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    // Wait for client to connect to both servers
    sleep(Duration::from_millis(1000)).await;

    // Send 10 concurrent / sequential requests to simulate aria2c downloading 10 chunks
    for i in 0..10 {
        let payload = format!("Chunk #{} from aria2c test", i);
        let echoed = socks5_proxy_request(socks5_addr, target.addr, payload.as_bytes()).await;
        assert_eq!(echoed, payload.as_bytes());
    }

    assert_eq!(target.connections_handled.load(Ordering::SeqCst), 10);
}

#[tokio::test]
async fn test_multi_server_aggregation_random() {
    let target = spawn_target_server().await;

    // Server 1
    let s1_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let s1_key = "rand-s1-key".to_string();
    let s1_cfg = ServerConfig {
        listen: s1_addr,
        auth_key: s1_key.clone(),
        auto_cert: true,
        ..Default::default()
    };
    tokio::spawn(async move {
        let _ = run_server(s1_cfg).await;
    });

    // Server 2
    let s2_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let s2_key = "rand-s2-key".to_string();
    let s2_cfg = ServerConfig {
        listen: s2_addr,
        auth_key: s2_key.clone(),
        auto_cert: true,
        ..Default::default()
    };
    tokio::spawn(async move {
        let _ = run_server(s2_cfg).await;
    });

    sleep(Duration::from_millis(300)).await;

    let socks5_addr: SocketAddr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };

    let client_cfg = ClientConfig {
        socks5_listen: socks5_addr,
        servers: vec![
            ServerNodeConfig {
                name: "node-1".to_string(),
                server_addr: "127.0.0.1".to_string(),
                server_port: s1_addr.port(),
                auth_key: s1_key,
                transport: TransportMode::Auto,
                insecure: true,
                weight: 5,
                ..Default::default()
            },
            ServerNodeConfig {
                name: "node-2".to_string(),
                server_addr: "127.0.0.1".to_string(),
                server_port: s2_addr.port(),
                auth_key: s2_key,
                transport: TransportMode::Auto,
                insecure: true,
                weight: 5,
                ..Default::default()
            },
        ],
        routing: MultiServerRoutingConfig {
            mode: TrafficMode::Aggregation,
            strategy: AggregationStrategy::Random,
            relay_to_server: None,
            relay_fallback_direct: true,
        },
        socks5_user: None,
        socks5_password: None,
        acl: None,
        outbounds: Vec::new(),
    };

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    sleep(Duration::from_millis(1000)).await;

    for i in 0..15 {
        let payload = format!("Random hit request #{}", i);
        let echoed = socks5_proxy_request(socks5_addr, target.addr, payload.as_bytes()).await;
        assert_eq!(echoed, payload.as_bytes());
    }

    assert_eq!(target.connections_handled.load(Ordering::SeqCst), 15);
}

#[tokio::test]
async fn test_multi_server_resilient_failover() {
    let target = spawn_target_server().await;

    // Primary Server
    let s1_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let s1_key = "primary-server-key".to_string();
    let s1_cfg = ServerConfig {
        listen: s1_addr,
        auth_key: s1_key.clone(),
        auto_cert: true,
        ..Default::default()
    };
    let (s1_shutdown_tx, mut s1_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tokio::select! {
            _ = run_server(s1_cfg) => {},
            _ = &mut s1_shutdown_rx => {},
        }
    });

    // Secondary / Backup Server
    let s2_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let s2_key = "backup-server-key".to_string();
    let s2_cfg = ServerConfig {
        listen: s2_addr,
        auth_key: s2_key.clone(),
        auto_cert: true,
        ..Default::default()
    };
    tokio::spawn(async move {
        let _ = run_server(s2_cfg).await;
    });

    sleep(Duration::from_millis(300)).await;

    let socks5_addr: SocketAddr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };

    let client_cfg = ClientConfig {
        socks5_listen: socks5_addr,
        servers: vec![
            ServerNodeConfig {
                name: "primary".to_string(),
                server_addr: "127.0.0.1".to_string(),
                server_port: s1_addr.port(),
                auth_key: s1_key,
                transport: TransportMode::Auto,
                insecure: true,
                priority: 1, // Preferred
                ..Default::default()
            },
            ServerNodeConfig {
                name: "backup".to_string(),
                server_addr: "127.0.0.1".to_string(),
                server_port: s2_addr.port(),
                auth_key: s2_key,
                transport: TransportMode::Auto,
                insecure: true,
                priority: 2, // Standby
                ..Default::default()
            },
        ],
        routing: MultiServerRoutingConfig {
            mode: TrafficMode::Resilient,
            strategy: AggregationStrategy::RoundRobin,
            relay_to_server: None,
            relay_fallback_direct: true,
        },
        socks5_user: None,
        socks5_password: None,
        acl: None,
        outbounds: Vec::new(),
    };

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    sleep(Duration::from_millis(1000)).await;

    // 1. Initial request: routed through Primary
    let msg1 = b"Hello through Primary!";
    let echoed1 = socks5_proxy_request(socks5_addr, target.addr, msg1).await;
    assert_eq!(echoed1, msg1);

    // 2. Shut down Primary Server
    let _ = s1_shutdown_tx.send(());
    sleep(Duration::from_millis(500)).await;

    // 3. Next request: automatically fails over to Backup Server!
    let msg2 = b"Hello through Backup after failover!";
    let echoed2 = socks5_proxy_request(socks5_addr, target.addr, msg2).await;
    assert_eq!(echoed2, msg2);

    assert_eq!(target.connections_handled.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_multi_server_outbound_relaying() {
    let target = spawn_target_server().await;

    // Server 1: The designated outbound anchor server
    let s1_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let s1_key = "anchor-server-secret".to_string();
    let s1_cfg = ServerConfig {
        listen: s1_addr,
        auth_key: s1_key.clone(),
        auto_cert: true,
        ..Default::default()
    };
    tokio::spawn(async move {
        let _ = run_server(s1_cfg).await;
    });

    // Server 2: Intermediate entry node
    let s2_addr: SocketAddr = {
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        u.local_addr().unwrap()
    };
    let s2_key = "intermediate-server-secret".to_string();
    let s2_cfg = ServerConfig {
        listen: s2_addr,
        auth_key: s2_key.clone(),
        auto_cert: true,
        ..Default::default()
    };
    tokio::spawn(async move {
        let _ = run_server(s2_cfg).await;
    });

    sleep(Duration::from_millis(300)).await;

    let socks5_addr: SocketAddr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };

    // Client connects to both servers in Aggregation mode,
    // BUT sets relay_to_server = "anchor" so all egress exits through Server 1
    let client_cfg = ClientConfig {
        socks5_listen: socks5_addr,
        servers: vec![
            ServerNodeConfig {
                name: "anchor".to_string(),
                server_addr: "127.0.0.1".to_string(),
                server_port: s1_addr.port(),
                auth_key: s1_key,
                transport: TransportMode::Auto,
                insecure: true,
                ..Default::default()
            },
            ServerNodeConfig {
                name: "intermediate".to_string(),
                server_addr: "127.0.0.1".to_string(),
                server_port: s2_addr.port(),
                auth_key: s2_key,
                transport: TransportMode::Auto,
                insecure: true,
                ..Default::default()
            },
        ],
        routing: MultiServerRoutingConfig {
            mode: TrafficMode::Aggregation,
            strategy: AggregationStrategy::RoundRobin,
            relay_to_server: Some("anchor".to_string()),
            relay_fallback_direct: false,
        },
        socks5_user: None,
        socks5_password: None,
        acl: None,
        outbounds: Vec::new(),
    };

    tokio::spawn(async move {
        let _ = run_client(client_cfg).await;
    });

    // Allow time for intermediate node to establish relayed egress tunnel to anchor
    sleep(Duration::from_millis(1500)).await;

    // Send 6 requests alternating between the two paths
    for i in 0..6 {
        let payload = format!("Relayed packet #{}", i);
        let echoed = socks5_proxy_request(socks5_addr, target.addr, payload.as_bytes()).await;
        assert_eq!(echoed, payload.as_bytes());
    }

    assert_eq!(target.connections_handled.load(Ordering::SeqCst), 6);
}
