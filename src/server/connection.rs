use anyhow::{bail, Context, Result};
use quinn::Connection;
use std::sync::Arc;
use std::time::Duration;

use super::antiprobe::{apply_auth_jitter, AntiProbeConfig, RateLimiter};
use super::masquerade::MasqueradeHandler;
use super::relay;
use crate::auth::verify_auth_token;
use crate::protocol::{
    read_auth_request, write_auth_response, AuthResponse, STATUS_AUTH_FAILED, STATUS_SUCCESS,
};

pub async fn handle_connection(
    conn: Connection,
    auth_key: Arc<String>,
    masquerade: Arc<MasqueradeHandler>,
    rate_limiter: Arc<RateLimiter>,
    anti_probe: Arc<AntiProbeConfig>,
    udp_session_timeout: u64,
    acl_engine: Arc<crate::acl::ACLEngine>,
) -> Result<()> {
    let remote_addr = conn.remote_address();
    tracing::info!("Accepted incoming QUIC connection from {}", remote_addr);

    // 1. IP Rate Limiting Check
    if !rate_limiter.check_allowed(&remote_addr.ip()) {
        tracing::warn!("Remote IP {} is rate-limited; diverting/rejecting", remote_addr.ip());
        if masquerade.is_enabled() {
            return masquerade.handle_quic_connection(conn).await;
        } else {
            conn.close(1u32.into(), b"Rate limited");
            return Ok(());
        }
    }

    // 2. Accept first bidirectional stream (timeout to avoid hanging connections)
    let accept_bi_result = tokio::time::timeout(Duration::from_secs(3), conn.accept_bi()).await;
    let (mut auth_send, mut auth_recv) = match accept_bi_result {
        Ok(Ok(streams)) => streams,
        Ok(Err(e)) => {
            tracing::warn!("Connection from {} closed before opening stream: {}", remote_addr, e);
            if masquerade.is_enabled() {
                return masquerade.handle_quic_connection(conn).await;
            }
            return Ok(());
        }
        Err(_) => {
            tracing::debug!("Connection from {} timed out waiting for bidi stream", remote_addr);
            if masquerade.is_enabled() {
                return masquerade.handle_quic_connection(conn).await;
            }
            return Ok(());
        }
    };

    // 3. Attempt to read AuthRequest
    let auth_req_result = tokio::time::timeout(Duration::from_secs(3), read_auth_request(&mut auth_recv)).await;
    let auth_req = match auth_req_result {
        Ok(Ok(req)) => req,
        _ => {
            tracing::warn!("Non-proxy or invalid auth packet from {}", remote_addr);
            rate_limiter.record_failure(remote_addr.ip());

            if masquerade.is_enabled() {
                return masquerade.handle_quic_stream(&conn, auth_send).await;
            } else {
                apply_auth_jitter(anti_probe.auth_jitter_min_ms, anti_probe.auth_jitter_max_ms).await;
                let resp = AuthResponse::new(STATUS_AUTH_FAILED);
                let _ = write_auth_response(&mut auth_send, &resp).await;
                let _ = auth_send.finish();
                conn.close(1u32.into(), b"Auth failed");
                return Ok(());
            }
        }
    };

    // 4. Verify auth token
    let is_valid = verify_auth_token(&conn, &auth_key, &auth_req.token)
        .context("Error verifying auth token")?;

    // Apply random response jitter
    apply_auth_jitter(anti_probe.auth_jitter_min_ms, anti_probe.auth_jitter_max_ms).await;

    if !is_valid {
        tracing::warn!("Authentication failed for client {}", remote_addr);
        rate_limiter.record_failure(remote_addr.ip());

        if masquerade.is_enabled() {
            return masquerade.handle_quic_stream(&conn, auth_send).await;
        } else {
            let resp = AuthResponse::new(STATUS_AUTH_FAILED);
            let _ = write_auth_response(&mut auth_send, &resp).await;
            let _ = auth_send.finish();
            conn.close(1u32.into(), b"Auth failed");
            bail!("Authentication failed for {}", remote_addr);
        }
    }

    // Auth succeeded!
    rate_limiter.record_success(&remote_addr.ip());
    let resp = AuthResponse::new(STATUS_SUCCESS);
    write_auth_response(&mut auth_send, &resp)
        .await
        .context("Failed to write auth success response")?;
    let _ = auth_send.finish();

    tracing::info!("Client {} successfully authenticated", remote_addr);

    // Set up UDP session table and datagram receiver loop for this connection
    let session_table = std::sync::Arc::new(
        crate::server::udp_session::UdpSessionTable::new(udp_session_timeout, Arc::clone(&acl_engine)),
    );

    // Spawn datagram receiver loop
    let conn_dgram = conn.clone();
    let session_table_dgram = session_table.clone();
    tokio::spawn(async move {
        loop {
            match conn_dgram.read_datagram().await {
                Ok(dgram_bytes) => {
                    match crate::protocol::UdpDatagram::decode(&dgram_bytes) {
                        Ok(dgram) => {
                            let conn_for_send = conn_dgram.clone();
                            if let Err(e) = session_table_dgram
                                .handle_outbound(
                                    dgram.session_id,
                                    dgram.target,
                                    &dgram.payload,
                                    move |b| conn_for_send.send_datagram(b).map_err(|e| e.to_string()),
                                )
                                .await
                            {
                                tracing::debug!("UDP session outbound error: {:#}", e);
                            }
                        }
                        Err(e) => {
                            tracing::debug!("Failed to decode UDP datagram: {:#}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Datagram receiver loop ended: {}", e);
                    break;
                }
            }
        }
    });

    // Spawn session table reaper
    let session_table_reaper = session_table.clone();
    tokio::spawn(async move {
        session_table_reaper.reaper_loop().await;
    });

    let acl_engine_relay = Arc::clone(&acl_engine);

    // Accept subsequent proxy streams
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let acl_clone = Arc::clone(&acl_engine_relay);
                tokio::spawn(async move {
                    if let Err(e) = relay::handle_stream(send, recv, acl_clone).await {
                        tracing::debug!("Proxy stream error: {:#}", e);
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                tracing::info!("Client {} closed connection normally", remote_addr);
                break;
            }
            Err(quinn::ConnectionError::LocallyClosed) => {
                break;
            }
            Err(e) => {
                tracing::debug!("Connection from {} closed: {}", remote_addr, e);
                break;
            }
        }
    }

    Ok(())
}
