use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::net::TcpStream;

use super::antiprobe::{apply_auth_jitter, AntiProbeConfig, RateLimiter};
use super::relay;
use crate::transport::tcp::accept_server_tcp;

pub async fn handle_tcp_connection(
    stream: TcpStream,
    auth_key: Arc<String>,
    rate_limiter: Arc<RateLimiter>,
    anti_probe: Arc<AntiProbeConfig>,
    udp_session_timeout: u64,
    acl_engine: Arc<crate::acl::ACLEngine>,
) -> Result<()> {
    let peer_addr = stream.peer_addr().context("Failed to get TCP peer address")?;
    tracing::info!("Accepted incoming TCP fallback connection from {}", peer_addr);

    if !rate_limiter.check_allowed(&peer_addr.ip()) {
        tracing::warn!("TCP fallback client IP {} is rate-limited", peer_addr.ip());
        return Ok(());
    }

    let muxer = match accept_server_tcp(stream, &auth_key).await {
        Ok(muxer) => {
            rate_limiter.record_success(&peer_addr.ip());
            apply_auth_jitter(anti_probe.auth_jitter_min_ms, anti_probe.auth_jitter_max_ms).await;
            muxer
        }
        Err(e) => {
            tracing::warn!("TCP fallback authentication failed for {}: {:#}", peer_addr, e);
            rate_limiter.record_failure(peer_addr.ip());
            apply_auth_jitter(anti_probe.auth_jitter_min_ms, anti_probe.auth_jitter_max_ms).await;
            return Err(e);
        }
    };

    tracing::info!("Client {} successfully authenticated over TCP fallback", peer_addr);

    let muxer = Arc::new(muxer);

    // Set up UDP session table for datagrams encapsulated over TCP fallback
    let session_table = Arc::new(
        crate::server::udp_session::UdpSessionTable::new(udp_session_timeout, Arc::clone(&acl_engine)),
    );

    // Spawn datagram receiver loop over TCP muxer
    let muxer_dgram = Arc::clone(&muxer);
    let session_table_dgram = Arc::clone(&session_table);
    tokio::spawn(async move {
        loop {
            match muxer_dgram.recv_datagram().await {
                Ok(dgram_bytes) => {
                    match crate::protocol::UdpDatagram::decode(&dgram_bytes) {
                        Ok(dgram) => {
                            let muxer_send = Arc::clone(&muxer_dgram);
                            if let Err(e) = session_table_dgram
                                .handle_outbound(
                                    dgram.session_id,
                                    dgram.target,
                                    &dgram.payload,
                                    move |b| muxer_send.send_datagram(&b).map_err(|e| e.to_string()),
                                )
                                .await
                            {
                                tracing::debug!("TCP UDP session outbound error: {:#}", e);
                            }
                        }
                        Err(e) => {
                            tracing::debug!("Failed to decode TCP encapsulated UDP datagram: {:#}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("TCP fallback datagram receiver loop ended: {}", e);
                    break;
                }
            }
        }
    });

    let session_table_reaper = Arc::clone(&session_table);
    tokio::spawn(async move {
        session_table_reaper.reaper_loop().await;
    });

    let acl_engine_relay = Arc::clone(&acl_engine);

    while let Some(vstream) = muxer.accept_stream().await {
        let (read_half, write_half) = tokio::io::split(vstream);
        let acl_clone = Arc::clone(&acl_engine_relay);
        tokio::spawn(async move {
            if let Err(e) = relay::handle_stream(write_half, read_half, acl_clone).await {
                tracing::debug!("TCP fallback proxy stream error: {:#}", e);
            }
        });
    }

    tracing::info!("TCP fallback connection from {} closed", peer_addr);
    Ok(())
}
