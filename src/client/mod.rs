pub mod socks5;

use anyhow::{bail, Context, Result};
use quinn::{Connection, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;

use crate::auth::generate_auth_token;
use crate::config::ClientConfig;
use crate::protocol::{
    read_auth_response, write_auth_request, AuthRequest, STATUS_SUCCESS,
};
use crate::tls::make_client_config;

pub async fn run_client(config: ClientConfig) -> Result<()> {
    let client_crypto = make_client_config(
        config.insecure,
        config.cert_fingerprint.as_deref(),
        config.ca_cert.as_deref(),
    )?;

    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut endpoint = Endpoint::client(bind_addr)
        .context("Failed to bind QUIC client endpoint")?;
    endpoint.set_default_client_config(client_crypto);

    let active_conn = Arc::new(RwLock::new(None::<Connection>));
    let active_conn_clone = Arc::clone(&active_conn);

    let config = Arc::new(config);
    let config_clone = Arc::clone(&config);

    // Initial connection attempt before starting SOCKS5 or in parallel
    let endpoint_clone = endpoint.clone();
    tokio::spawn(async move {
        connection_manager_loop(endpoint_clone, config_clone, active_conn_clone).await;
    });

    println!("================================================================================");
    println!("  QuicProxy Client is starting...");
    println!("  SOCKS5 proxy endpoint: {}", config.socks5_listen);
    println!("  Connecting to QUIC server at {}:{}", config.server_addr, config.server_port);
    println!("================================================================================");

    // Connection provider closure for SOCKS5 handler
    let conn_reader = Arc::clone(&active_conn);
    let conn_provider: Arc<dyn Fn() -> Option<Connection> + Send + Sync> = Arc::new(move || {
        let guard = conn_reader.try_read().ok()?;
        guard.as_ref().cloned()
    });

    socks5::run_socks5_listener(config, conn_provider).await
}

async fn connection_manager_loop(
    endpoint: Endpoint,
    config: Arc<ClientConfig>,
    active_conn: Arc<RwLock<Option<Connection>>>,
) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(10);

    loop {
        let is_connected = {
            let guard = active_conn.read().await;
            if let Some(conn) = guard.as_ref() {
                conn.close_reason().is_none()
            } else {
                false
            }
        };

        if !is_connected {
            tracing::info!(
                "Attempting connection to {}:{}...",
                config.server_addr,
                config.server_port
            );

            match connect_and_auth(&endpoint, &config).await {
                Ok(conn) => {
                    tracing::info!("Successfully connected and authenticated with QUIC server!");
                    let mut guard = active_conn.write().await;
                    *guard = Some(conn);
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    tracing::warn!("Failed to connect to server: {:#}", e);
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

async fn connect_and_auth(endpoint: &Endpoint, config: &ClientConfig) -> Result<Connection> {
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
        .context("Failed to initiate connection")?;

    let conn = connecting.await.context("QUIC connection handshake failed")?;

    // Perform auth handshake on first stream
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open auth stream")?;

    let token = generate_auth_token(&conn, &config.auth_key)
        .context("Failed to generate session auth token")?;

    let auth_req = AuthRequest::new(token);
    write_auth_request(&mut send, &auth_req)
        .await
        .context("Failed to send auth request")?;

    let auth_resp = read_auth_response(&mut recv)
        .await
        .context("Failed to read auth response from server")?;

    if auth_resp.status != STATUS_SUCCESS {
        bail!("Authentication failed by server (status: {})", auth_resp.status);
    }

    let _ = send.finish();
    Ok(conn)
}
