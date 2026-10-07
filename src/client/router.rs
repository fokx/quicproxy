use anyhow::{Context, Result, bail};
use quinn::{Connection, Endpoint};
use rand::RngExt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};

use crate::auth::generate_auth_token;
use crate::config::{
    AggregationStrategy, ClientConfig, MultiServerRoutingConfig, ServerNodeConfig, TrafficMode,
    TransportMode,
};
use crate::obfs::salamander::ObfuscatedUdpSocket;
use crate::protocol::{
    AuthRequest, ProxyRequest, STATUS_SUCCESS, TargetAddr, read_auth_response, read_proxy_response,
    write_auth_request, write_proxy_request,
};
use crate::realm::{
    AddrFamily, DEFAULT_REALM_STUN_SERVERS, PlainAsyncUdpSocket, PunchConfig, PunchMetadata,
    RendezvousClient, parse_realm_addr,
};
use crate::transport::ActiveTransport;
use crate::transport::quic::QuicTransport;
use crate::transport::tcp::TcpTransport;

pub struct ServerNodeHandle {
    pub config: ServerNodeConfig,
    pub active_transport: Arc<RwLock<Option<Arc<ActiveTransport>>>>,
    pub is_relay_anchor: bool,
}

pub struct MultiServerRouter {
    nodes: Vec<Arc<ServerNodeHandle>>,
    routing: MultiServerRoutingConfig,
    rr_counter: AtomicUsize,
    datagram_router: Arc<crate::client::udp::DatagramRouter>,
}

impl MultiServerRouter {
    pub fn new(
        config: &ClientConfig,
        datagram_router: Arc<crate::client::udp::DatagramRouter>,
    ) -> Arc<Self> {
        let relay_target_name = config.routing.relay_to_server.as_deref();

        let nodes: Vec<Arc<ServerNodeHandle>> = config
            .servers
            .iter()
            .map(|s| {
                let is_relay_anchor = if let Some(target) = relay_target_name {
                    s.name == target || s.server_addr == target
                } else {
                    false
                };
                Arc::new(ServerNodeHandle {
                    config: s.clone(),
                    active_transport: Arc::new(RwLock::new(None)),
                    is_relay_anchor,
                })
            })
            .collect();

        Arc::new(Self {
            nodes,
            routing: config.routing.clone(),
            rr_counter: AtomicUsize::new(0),
            datagram_router,
        })
    }

    /// Start background connection managers for all configured server nodes.
    pub fn start_connection_managers(self: &Arc<Self>, all_servers: &[ServerNodeConfig]) {
        let relay_anchor_node = self.routing.relay_to_server.as_ref().and_then(|target| {
            all_servers
                .iter()
                .find(|s| s.name == *target || s.server_addr == *target)
                .cloned()
        });

        for node_handle in &self.nodes {
            let handle_clone = Arc::clone(node_handle);
            let router_clone = Arc::clone(&self.datagram_router);
            let routing_cfg = self.routing.clone();
            let anchor_cfg = relay_anchor_node.clone();

            tokio::spawn(async move {
                node_connection_manager_loop(handle_clone, routing_cfg, anchor_cfg, router_clone)
                    .await;
            });
        }
    }

    /// Select an active transport according to the configured routing policy (Aggregation or Resilient).
    pub async fn select_transport(&self) -> Option<Arc<ActiveTransport>> {
        match self.routing.mode {
            TrafficMode::Aggregation => self.select_aggregation().await,
            TrafficMode::Resilient => self.select_resilient().await,
        }
    }

    /// Synchronous version of select_transport (using try_read for fast non-blocking lookups in SOCKS5 provider)
    pub fn try_select_transport(&self) -> Option<Arc<ActiveTransport>> {
        match self.routing.mode {
            TrafficMode::Aggregation => self.try_select_aggregation(),
            TrafficMode::Resilient => self.try_select_resilient(),
        }
    }

    fn try_select_aggregation(&self) -> Option<Arc<ActiveTransport>> {
        let mut healthy_transports = Vec::new();
        let mut weights = Vec::new();

        for node in &self.nodes {
            if let Ok(guard) = node.active_transport.try_read() {
                if let Some(t) = guard.as_ref().filter(|t| t.is_alive()) {
                    healthy_transports.push(Arc::clone(t));
                    weights.push(node.config.weight.max(1));
                }
            }
        }

        if healthy_transports.is_empty() {
            return None;
        }

        match self.routing.strategy {
            AggregationStrategy::RoundRobin => {
                let idx =
                    self.rr_counter.fetch_add(1, Ordering::Relaxed) % healthy_transports.len();
                Some(healthy_transports[idx].clone())
            }
            AggregationStrategy::Random => {
                let total_weight: u32 = weights.iter().sum();
                let mut pick = rand::rng().random_range(0..total_weight);
                for (i, &w) in weights.iter().enumerate() {
                    if pick < w {
                        return Some(healthy_transports[i].clone());
                    }
                    pick -= w;
                }
                Some(healthy_transports[0].clone())
            }
        }
    }

    async fn select_aggregation(&self) -> Option<Arc<ActiveTransport>> {
        let mut healthy_transports = Vec::new();
        let mut weights = Vec::new();

        for node in &self.nodes {
            let guard = node.active_transport.read().await;
            if let Some(t) = guard.as_ref().filter(|t| t.is_alive()) {
                healthy_transports.push(Arc::clone(t));
                weights.push(node.config.weight.max(1));
            }
        }

        if healthy_transports.is_empty() {
            return None;
        }

        match self.routing.strategy {
            AggregationStrategy::RoundRobin => {
                let idx =
                    self.rr_counter.fetch_add(1, Ordering::Relaxed) % healthy_transports.len();
                Some(healthy_transports[idx].clone())
            }
            AggregationStrategy::Random => {
                let total_weight: u32 = weights.iter().sum();
                let mut pick = rand::rng().random_range(0..total_weight);
                for (i, &w) in weights.iter().enumerate() {
                    if pick < w {
                        return Some(healthy_transports[i].clone());
                    }
                    pick -= w;
                }
                Some(healthy_transports[0].clone())
            }
        }
    }

    fn try_select_resilient(&self) -> Option<Arc<ActiveTransport>> {
        // Collect nodes sorted by priority (lowest number = highest priority)
        let mut sorted_nodes = self.nodes.clone();
        sorted_nodes.sort_by_key(|n| n.config.priority);

        for node in sorted_nodes {
            if let Ok(guard) = node.active_transport.try_read() {
                if let Some(t) = guard.as_ref().filter(|t| t.is_alive()) {
                    return Some(Arc::clone(t));
                }
            }
        }
        None
    }

    async fn select_resilient(&self) -> Option<Arc<ActiveTransport>> {
        let mut sorted_nodes = self.nodes.clone();
        sorted_nodes.sort_by_key(|n| n.config.priority);

        for node in sorted_nodes {
            let guard = node.active_transport.read().await;
            if let Some(t) = guard.as_ref().filter(|t| t.is_alive()) {
                return Some(Arc::clone(t));
            }
        }
        None
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn nodes(&self) -> &[Arc<ServerNodeHandle>] {
        &self.nodes
    }
}

/// Dedicated connection lifecycle loop for a single server node.
async fn node_connection_manager_loop(
    node: Arc<ServerNodeHandle>,
    routing_cfg: MultiServerRoutingConfig,
    relay_anchor_cfg: Option<ServerNodeConfig>,
    datagram_router: Arc<crate::client::udp::DatagramRouter>,
) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(10);

    let quic_endpoint = if node.config.is_realm() {
        None
    } else {
        create_node_quic_endpoint(&node.config).await.ok()
    };
    let mut current_dgram_task: Option<tokio::task::JoinHandle<()>> = None;

    let is_relayed_node = relay_anchor_cfg.is_some() && !node.is_relay_anchor;

    loop {
        let is_connected = {
            let guard = node.active_transport.read().await;
            if let Some(transport) = guard.as_ref() {
                transport.is_alive()
            } else {
                false
            }
        };

        if !is_connected {
            if let Some(h) = current_dgram_task.take() {
                h.abort();
            }

            tracing::info!(
                "Node [{}]: Connecting to {}:{} (transport: {})...",
                node.config.name,
                node.config.server_addr,
                node.config.server_port,
                node.config.transport
            );

            let direct_connect_res =
                connect_node_direct(&node.config, quic_endpoint.as_ref()).await;

            let final_transport_res = match direct_connect_res {
                Ok(entry_transport) => {
                    if is_relayed_node {
                        let anchor = relay_anchor_cfg.as_ref().unwrap();
                        tracing::info!(
                            "Node [{}]: Direct connection established. Establishing relayed egress tunnel to outbound server [{}] at {}:{}...",
                            node.config.name,
                            anchor.name,
                            anchor.server_addr,
                            anchor.server_port
                        );

                        match setup_relayed_transport(&entry_transport, anchor).await {
                            Ok(relayed_transport) => {
                                tracing::info!(
                                    "Node [{}]: Relayed egress tunnel to [{}] authenticated successfully!",
                                    node.config.name,
                                    anchor.name
                                );
                                Ok(relayed_transport)
                            }
                            Err(e) => {
                                if routing_cfg.relay_fallback_direct {
                                    tracing::warn!(
                                        "Node [{}]: Failed to establish relay tunnel to [{}]: {:#}. Falling back to direct exit on this node.",
                                        node.config.name,
                                        anchor.name,
                                        e
                                    );
                                    Ok(entry_transport)
                                } else {
                                    Err(e)
                                }
                            }
                        }
                    } else {
                        Ok(entry_transport)
                    }
                }
                Err(e) => Err(e),
            };

            match final_transport_res {
                Ok(transport) => {
                    let mode_name = transport.mode_name();
                    tracing::info!(
                        "Node [{}]: Successfully connected and ready (transport: {})!",
                        node.config.name,
                        mode_name
                    );

                    let transport_arc = Arc::new(transport);
                    {
                        let mut guard = node.active_transport.write().await;
                        *guard = Some(Arc::clone(&transport_arc));
                    }
                    backoff = Duration::from_secs(1);

                    // Spawn datagram receiver loop
                    let router_recv = Arc::clone(&datagram_router);
                    let transport_recv = Arc::clone(&transport_arc);
                    current_dgram_task = Some(tokio::spawn(async move {
                        router_recv.recv_and_route_loop(transport_recv).await;
                    }));

                    // Probing QUIC upgrade if running direct TCP in Auto mode
                    if !is_relayed_node
                        && !node.config.is_realm()
                        && node.config.transport == TransportMode::Auto
                        && mode_name == "TCP"
                    {
                        if let Some(ref ep) = quic_endpoint {
                            let ep_clone = ep.clone();
                            let node_clone = Arc::clone(&node);
                            let router_probe = Arc::clone(&datagram_router);
                            tokio::spawn(async move {
                                probe_node_quic_upgrade(ep_clone, node_clone, router_probe).await;
                            });
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Node [{}]: Connection attempt failed: {:#}",
                        node.config.name,
                        e
                    );
                    tracing::info!(
                        "Node [{}]: Retrying in {}s...",
                        node.config.name,
                        backoff.as_secs()
                    );
                    sleep(backoff).await;
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        } else {
            sleep(Duration::from_secs(2)).await;
        }
    }
}

/// Establish an end-to-end authenticated multiplexed transport to the anchor outbound server
/// through an intermediate server's active transport.
async fn setup_relayed_transport(
    intermediate_transport: &ActiveTransport,
    anchor: &ServerNodeConfig,
) -> Result<ActiveTransport> {
    // 1. Open a virtual stream on the intermediate server
    let stream = intermediate_transport
        .open_stream()
        .await
        .context("Failed to open virtual stream on intermediate node")?;

    let (mut stream_read, mut stream_write) = tokio::io::split(stream);

    // 2. Request intermediate server to connect to anchor server's address:port
    let target = TargetAddr::Domain(anchor.server_addr.clone(), anchor.server_port);
    let req = ProxyRequest::connect(target);
    write_proxy_request(&mut stream_write, &req)
        .await
        .context("Failed to send proxy connect request to intermediate node")?;

    let resp = read_proxy_response(&mut stream_read)
        .await
        .context("Failed to read proxy response from intermediate node")?;

    if resp.status != STATUS_SUCCESS {
        bail!(
            "Intermediate server rejected connection to anchor server (status: {})",
            resp.status
        );
    }

    // 3. Re-combine stream halves and execute end-to-end TcpTransport handshake directly with anchor server
    let rejoined_stream = tokio::io::join(stream_read, stream_write);
    let tcp_transport = TcpTransport::handshake_on_stream(rejoined_stream, &anchor.auth_key)
        .await
        .context(
            "Failed to perform end-to-end ChaCha20-Poly1305 handshake with outbound anchor server",
        )?;

    Ok(ActiveTransport::Tcp(tcp_transport))
}

async fn connect_node_direct(
    config: &ServerNodeConfig,
    quic_endpoint: Option<&Endpoint>,
) -> Result<ActiveTransport> {
    if config.is_realm() {
        return connect_realm_node(config).await;
    }

    match config.transport {
        TransportMode::Quic => {
            if let Some(ep) = quic_endpoint {
                let conn = connect_and_auth_node_quic(ep, config).await?;
                Ok(ActiveTransport::Quic(QuicTransport::new(conn)))
            } else {
                bail!("QUIC endpoint unavailable for node {}", config.name);
            }
        }
        TransportMode::Tcp => {
            let tcp =
                TcpTransport::connect(&config.server_addr, config.server_port, &config.auth_key)
                    .await?;
            Ok(ActiveTransport::Tcp(tcp))
        }
        TransportMode::Auto => {
            let quic_attempt = if let Some(ep) = quic_endpoint {
                match timeout(
                    Duration::from_secs(3),
                    connect_and_auth_node_quic(ep, config),
                )
                .await
                {
                    Ok(Ok(conn)) => Some(ActiveTransport::Quic(QuicTransport::new(conn))),
                    Ok(Err(e)) => {
                        tracing::debug!("Node [{}]: QUIC connection failed: {:#}", config.name, e);
                        None
                    }
                    Err(_) => {
                        tracing::debug!("Node [{}]: QUIC connection timed out (3s)", config.name);
                        None
                    }
                }
            } else {
                None
            };

            if let Some(t) = quic_attempt {
                Ok(t)
            } else {
                tracing::info!(
                    "Node [{}]: QUIC unavailable; falling back to TCP ChaCha20-Poly1305 multiplexer...",
                    config.name
                );
                let tcp = TcpTransport::connect(
                    &config.server_addr,
                    config.server_port,
                    &config.auth_key,
                )
                .await?;
                Ok(ActiveTransport::Tcp(tcp))
            }
        }
    }
}

async fn connect_realm_node(config: &ServerNodeConfig) -> Result<ActiveTransport> {
    let realm_addr = parse_realm_addr(&config.server_addr)
        .with_context(|| format!("Failed to parse realm address: {}", config.server_addr))?;

    let family = match config.realm.as_ref().and_then(|r| r.ip_mode.as_deref()) {
        Some("v4") => AddrFamily::IPv4,
        Some("v6") => AddrFamily::IPv6,
        _ => AddrFamily::Any,
    };

    let local_port = realm_addr.local_port.unwrap_or(0);
    let bind_addr: SocketAddr = if family == AddrFamily::IPv6 {
        SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            local_port,
        )
    } else {
        SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            local_port,
        )
    };

    let std_socket = std::net::UdpSocket::bind(bind_addr)
        .with_context(|| format!("Failed to bind client UDP socket on {}", bind_addr))?;

    let mut mapper = None;
    if let Some(r_cfg) = &config.realm {
        if let Some(pm) = r_cfg.port_mapping.as_ref().filter(|p| p.enabled) {
            let port = std_socket.local_addr()?.port();
            let to = pm.timeout_duration();
            let lt = pm.lifetime_duration();
            match crate::realm::PortMapper::new(port, to, lt).await {
                Ok(m) => {
                    tracing::debug!("Realm client UPnP port mapped: {:?}", m.external_addr());
                    mapper = Some(Arc::new(m));
                }
                Err(e) => {
                    tracing::debug!("Realm client UPnP port mapping skipped: {}", e);
                }
            }
        }
    }

    std_socket.set_nonblocking(true)?;
    let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)?;

    let stun_servers: Vec<String> = if !realm_addr.stun_servers.is_empty() {
        realm_addr.stun_servers.clone()
    } else if let Some(r_cfg) = &config.realm {
        if !r_cfg.stun_servers.is_empty() {
            r_cfg.stun_servers.clone()
        } else {
            DEFAULT_REALM_STUN_SERVERS
                .iter()
                .map(|s| s.to_string())
                .collect()
        }
    } else {
        DEFAULT_REALM_STUN_SERVERS
            .iter()
            .map(|s| s.to_string())
            .collect()
    };

    let stun_timeout = config
        .realm
        .as_ref()
        .map(|r| r.stun_timeout_duration())
        .unwrap_or(Duration::from_secs(3));

    let mut local_addrs =
        crate::realm::discover(&tokio_socket, &stun_servers, stun_timeout, family)
            .await
            .context("STUN discovery failed")?;

    if let Some(ref m) = mapper {
        if let Some(ext) = m.external_addr() {
            if !local_addrs.contains(&ext) {
                local_addrs.push(ext);
            }
        }
    }

    if local_addrs.is_empty() {
        local_addrs.push(tokio_socket.local_addr()?);
    }

    let meta = PunchMetadata::new_random();
    let insecure = config.insecure || config.realm.as_ref().is_some_and(|r| r.insecure);
    let r_client = RendezvousClient::from_addr(&realm_addr, insecure)
        .context("Failed to create rendezvous client")?;

    tracing::debug!(
        "Connecting to realm [{}] at {} (attempt: {}) with candidates {:?}",
        realm_addr.realm_id,
        realm_addr.host_port,
        hex::encode(&meta.nonce[..4]),
        local_addrs
    );

    let connect_req = crate::realm::client::ConnectRequest {
        addresses: local_addrs.iter().map(|a| a.to_string()).collect(),
        nonce: meta.nonce.clone(),
        obfs: meta.obfs.clone(),
    };

    let connect_resp = r_client
        .connect(&realm_addr.realm_id, &connect_req)
        .await
        .context("Rendezvous connect request failed")?;

    tracing::debug!(
        "Received realm connect response with server candidates: {:?}",
        connect_resp.addresses
    );

    let peer_addrs: Vec<SocketAddr> = connect_resp
        .addresses
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    let punch_meta = connect_resp.punch_metadata();

    let punch_timeout = config
        .realm
        .as_ref()
        .map(|r| r.punch_timeout_duration())
        .unwrap_or(Duration::from_secs(5));

    let punch_config = PunchConfig {
        timeout: punch_timeout,
        family,
        ..Default::default()
    };

    let punch_result = crate::realm::punch(
        &tokio_socket,
        &local_addrs,
        &peer_addrs,
        &punch_meta,
        &punch_config,
    )
    .await
    .context("UDP hole punching failed")?;

    tracing::info!(
        "UDP hole punched successfully to peer {}!",
        punch_result.peer_addr
    );

    let std_socket = tokio_socket.into_std()?;
    std_socket.set_nonblocking(true)?;

    let abstract_socket: Arc<dyn quinn::AsyncUdpSocket> =
        if let Some(obfs_cfg) = config.obfuscation.as_ref().filter(|o| o.enabled) {
            let obfs = ObfuscatedUdpSocket::new(std_socket, &obfs_cfg.key)
                .context("Failed to create ObfuscatedUdpSocket")?;
            Arc::new(obfs)
        } else {
            let plain = PlainAsyncUdpSocket::new(std_socket)
                .context("Failed to create PlainAsyncUdpSocket")?;
            Arc::new(plain)
        };

    let client_crypto = crate::tls::make_client_config_with_fingerprint(
        config.insecure,
        config.cert_fingerprint.as_deref(),
        config.ca_cert.as_deref(),
        config.tls_fingerprint.as_ref(),
    )?;

    let runtime = quinn::default_runtime().context("No default Quinn runtime")?;
    let mut endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        abstract_socket,
        runtime,
    )
    .context("Failed to create Quinn client endpoint for punched socket")?;
    endpoint.set_default_client_config(client_crypto);

    let server_name = config
        .server_name
        .clone()
        .unwrap_or_else(|| realm_addr.host.clone());

    let connecting = endpoint
        .connect(punch_result.peer_addr, &server_name)
        .context("Failed to initiate QUIC connection to punched peer")?;

    let conn = connecting
        .await
        .context("QUIC handshake failed with punched peer")?;

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open QUIC auth stream")?;

    let token = generate_auth_token(&conn, &config.auth_key)
        .context("Failed to generate session auth token")?;

    let auth_req = AuthRequest::new(token);
    write_auth_request(&mut send, &auth_req)
        .await
        .context("Failed to send QUIC auth request")?;

    let auth_resp = read_auth_response(&mut recv)
        .await
        .context("Failed to read QUIC auth response from server")?;

    if auth_resp.status != STATUS_SUCCESS {
        bail!(
            "Authentication failed by realm server (status: {})",
            auth_resp.status
        );
    }

    let _ = send.shutdown().await;

    if let Some(m) = mapper {
        let realm_id = realm_addr.realm_id.clone();
        tokio::spawn(async move {
            let interval = m.lifetime() / 2;
            loop {
                tokio::time::sleep(interval).await;
                if let Err(e) = m.renew(Duration::from_secs(3)).await {
                    tracing::debug!("Realm client [{}] port map renewal failed: {}", realm_id, e);
                }
            }
        });
    }

    Ok(ActiveTransport::Quic(QuicTransport::new(conn)))
}

async fn probe_node_quic_upgrade(
    endpoint: Endpoint,
    node: Arc<ServerNodeHandle>,
    datagram_router: Arc<crate::client::udp::DatagramRouter>,
) {
    loop {
        sleep(Duration::from_secs(15)).await;

        let is_on_tcp = {
            let guard = node.active_transport.read().await;
            matches!(guard.as_ref(), Some(t) if t.mode_name() == "TCP" && t.is_alive())
        };

        if !is_on_tcp {
            break;
        }

        tracing::debug!(
            "Node [{}]: Probing QUIC connectivity for transport upgrade...",
            node.config.name
        );
        match timeout(
            Duration::from_secs(3),
            connect_and_auth_node_quic(&endpoint, &node.config),
        )
        .await
        {
            Ok(Ok(conn)) => {
                tracing::info!(
                    "Node [{}]: QUIC probed successfully! Upgrading transport to QUIC...",
                    node.config.name
                );
                let quic_arc = Arc::new(ActiveTransport::Quic(QuicTransport::new(conn)));
                {
                    let mut guard = node.active_transport.write().await;
                    *guard = Some(Arc::clone(&quic_arc));
                }
                let router_recv = Arc::clone(&datagram_router);
                tokio::spawn(async move {
                    router_recv.recv_and_route_loop(quic_arc).await;
                });
                break;
            }
            _ => {
                tracing::debug!(
                    "Node [{}]: QUIC probe did not succeed yet; continuing on TCP fallback",
                    node.config.name
                );
            }
        }
    }
}

async fn create_node_quic_endpoint(config: &ServerNodeConfig) -> Result<Endpoint> {
    let client_crypto = crate::tls::make_client_config_with_fingerprint(
        config.insecure,
        config.cert_fingerprint.as_deref(),
        config.ca_cert.as_deref(),
        config.tls_fingerprint.as_ref(),
    )?;

    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

    let mut endpoint = if let Some(obfs_cfg) = config.obfuscation.as_ref().filter(|o| o.enabled) {
        let obfs_sock =
            crate::obfs::salamander::ObfuscatedUdpSocket::bind(bind_addr, &obfs_cfg.key)
                .context("Failed to bind obfuscated client UDP socket")?;
        let runtime = quinn::default_runtime().context("No default Quinn runtime")?;
        Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            Arc::new(obfs_sock),
            runtime,
        )
        .context("Failed to create QUIC client endpoint with obfuscated socket")?
    } else {
        Endpoint::client(bind_addr).context("Failed to bind QUIC client endpoint")?
    };

    endpoint.set_default_client_config(client_crypto);
    Ok(endpoint)
}

async fn connect_and_auth_node_quic(
    endpoint: &Endpoint,
    config: &ServerNodeConfig,
) -> Result<Connection> {
    let target_str = format!("{}:{}", config.server_addr, config.server_port);
    let mut addrs = tokio::net::lookup_host(&target_str)
        .await
        .with_context(|| format!("Failed to resolve server address: {}", target_str))?;

    let server_sockaddr = addrs.next().context("No IP address resolved for server")?;

    let server_name = config
        .server_name
        .clone()
        .unwrap_or_else(|| config.server_addr.clone());

    let connecting = endpoint
        .connect(server_sockaddr, &server_name)
        .context("Failed to initiate QUIC connection")?;

    let conn = connecting
        .await
        .context("QUIC connection handshake failed")?;

    // Perform auth handshake on first stream
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open QUIC auth stream")?;

    let token = generate_auth_token(&conn, &config.auth_key)
        .context("Failed to generate session auth token")?;

    let auth_req = AuthRequest::new(token);
    write_auth_request(&mut send, &auth_req)
        .await
        .context("Failed to send QUIC auth request")?;

    let auth_resp = read_auth_response(&mut recv)
        .await
        .context("Failed to read QUIC auth response from server")?;

    if auth_resp.status != STATUS_SUCCESS {
        bail!(
            "Authentication failed by server (status: {})",
            auth_resp.status
        );
    }

    let _ = send.shutdown().await;
    Ok(conn)
}
