pub mod socks5;

use anyhow::{bail, Context, Result};
use quinn::{Connection, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};

use crate::auth::generate_auth_token;
use crate::config::{ClientConfig, TransportMode};
use crate::protocol::{
    read_auth_response, write_auth_request, AuthRequest, STATUS_SUCCESS,
};
use crate::tls::make_client_config;
use crate::transport::quic::QuicTransport;
use crate::transport::tcp::TcpTransport;
use crate::transport::ActiveTransport;

pub async fn run_client(config: ClientConfig) -> Result<()> {
    let active_transport = Arc::new(RwLock::new(None::<Arc<ActiveTransport>>));
    let active_transport_clone = Arc::clone(&active_transport);

    let config = Arc::new(config);
    let config_clone = Arc::clone(&config);

    // Start background connection manager loop
    tokio::spawn(async move {
        connection_manager_loop(config_clone, active_transport_clone).await;
    });

    println!("================================================================================");
    println!("  QuicProxy Client is starting...");
    println!("  SOCKS5 proxy endpoint: {}", config.socks5_listen);
    println!(
        "  Target server: {}:{} (Transport mode: {})",
        config.server_addr, config.server_port, config.transport
    );
    println!("================================================================================");

    // Connection provider closure for SOCKS5 listener
    let transport_reader = Arc::clone(&active_transport);
    let conn_provider: Arc<dyn Fn() -> Option<Arc<ActiveTransport>> + Send + Sync> =
        Arc::new(move || {
            let guard = transport_reader.try_read().ok()?;
            guard.as_ref().filter(|t| t.is_alive()).cloned()
        });

    socks5::run_socks5_listener(config, conn_provider).await
}

async fn create_quic_endpoint(config: &ClientConfig) -> Result<Endpoint> {
    let client_crypto = make_client_config(
        config.insecure,
        config.cert_fingerprint.as_deref(),
        config.ca_cert.as_deref(),
    )?;

    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut endpoint = Endpoint::client(bind_addr)
        .context("Failed to bind QUIC client endpoint")?;
    endpoint.set_default_client_config(client_crypto);
    Ok(endpoint)
}

async fn connection_manager_loop(
    config: Arc<ClientConfig>,
    active_transport: Arc<RwLock<Option<Arc<ActiveTransport>>>>,
) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(10);

    let quic_endpoint = create_quic_endpoint(&config).await.ok();

    loop {
        let is_connected = {
            let guard = active_transport.read().await;
            if let Some(transport) = guard.as_ref() {
                transport.is_alive()
            } else {
                false
            }
        };

        if !is_connected {
            tracing::info!(
                "Attempting connection to {}:{} (mode: {})...",
                config.server_addr,
                config.server_port,
                config.transport
            );

            let connect_result = match config.transport {
                TransportMode::Quic => {
                    if let Some(ref ep) = quic_endpoint {
                        connect_quic(ep, &config).await
                    } else {
                        Err(anyhow::anyhow!("Failed to initialize QUIC client endpoint"))
                    }
                }
                TransportMode::Tcp => connect_tcp(&config).await,
                TransportMode::Auto => {
                    // Try QUIC with 3-second timeout first
                    let quic_attempt = if let Some(ref ep) = quic_endpoint {
                        match timeout(Duration::from_secs(3), connect_quic(ep, &config)).await {
                            Ok(Ok(transport)) => Some(transport),
                            Ok(Err(e)) => {
                                tracing::debug!("QUIC connection failed: {:#}", e);
                                None
                            }
                            Err(_) => {
                                tracing::debug!("QUIC connection timed out (3s)");
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
                            "QUIC unavailable (UDP may be blocked); falling back to raw TCP ChaCha20-Poly1305 multiplexer..."
                        );
                        connect_tcp(&config).await
                    }
                }
            };

            match connect_result {
                Ok(transport) => {
                    let mode_name = transport.mode_name();
                    tracing::info!("Successfully connected and authenticated via {} transport!", mode_name);
                    let transport_arc = Arc::new(transport);
                    {
                        let mut guard = active_transport.write().await;
                        *guard = Some(Arc::clone(&transport_arc));
                    }
                    backoff = Duration::from_secs(1);

                    // If connected via TCP in Auto mode, spawn background probe to upgrade to QUIC
                    if config.transport == TransportMode::Auto && mode_name == "TCP" {
                        if let Some(ref ep) = quic_endpoint {
                            let ep_clone = ep.clone();
                            let config_probe = Arc::clone(&config);
                            let active_probe = Arc::clone(&active_transport);
                            tokio::spawn(async move {
                                probe_quic_upgrade(ep_clone, config_probe, active_probe).await;
                            });
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to establish connection: {:#}", e);
                    tracing::info!("Retrying connection in {}s...", backoff.as_secs());
                    sleep(backoff).await;
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        } else {
            sleep(Duration::from_secs(2)).await;
        }
    }
}

async fn probe_quic_upgrade(
    endpoint: Endpoint,
    config: Arc<ClientConfig>,
    active_transport: Arc<RwLock<Option<Arc<ActiveTransport>>>>,
) {
    loop {
        sleep(Duration::from_secs(15)).await;

        // Verify if still running on TCP fallback
        let is_on_tcp = {
            let guard = active_transport.read().await;
            match guard.as_ref() {
                Some(t) if t.mode_name() == "TCP" && t.is_alive() => true,
                _ => false,
            }
        };

        if !is_on_tcp {
            break;
        }

        tracing::debug!("Probing QUIC connectivity in background for transport upgrade...");
        match timeout(Duration::from_secs(3), connect_quic(&endpoint, &config)).await {
            Ok(Ok(quic_transport)) => {
                tracing::info!("QUIC transport probed successfully! Upgrading active transport to QUIC...");
                let mut guard = active_transport.write().await;
                *guard = Some(Arc::new(quic_transport));
                break;
            }
            _ => {
                tracing::debug!("QUIC probe did not succeed yet; remaining on TCP fallback");
            }
        }
    }
}

async fn connect_quic(endpoint: &Endpoint, config: &ClientConfig) -> Result<ActiveTransport> {
    let conn = connect_and_auth_quic(endpoint, config).await?;
    Ok(ActiveTransport::Quic(QuicTransport::new(conn)))
}

async fn connect_tcp(config: &ClientConfig) -> Result<ActiveTransport> {
    let tcp = TcpTransport::connect(&config.server_addr, config.server_port, &config.auth_key).await?;
    Ok(ActiveTransport::Tcp(tcp))
}

async fn connect_and_auth_quic(endpoint: &Endpoint, config: &ClientConfig) -> Result<Connection> {
    let target_str = format!("{}:{}", config.server_addr, config.server_port);
    let mut addrs = tokio::net::lookup_host(&target_str)
        .await
        .with_context(|| format!("Failed to resolve server address: {}", target_str))?;

    let server_sockaddr = addrs
        .next()
        .context("No IP address resolved for server")?;

    let server_name = config
        .server_name
        .clone()
        .unwrap_or_else(|| config.server_addr.clone());

    let connecting = endpoint
        .connect(server_sockaddr, &server_name)
        .context("Failed to initiate QUIC connection")?;

    let conn = connecting.await.context("QUIC connection handshake failed")?;

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
        bail!("Authentication failed by server (status: {})", auth_resp.status);
    }

    let _ = send.shutdown().await;
    Ok(conn)
}
