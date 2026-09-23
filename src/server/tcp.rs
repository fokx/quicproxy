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

    while let Some(vstream) = muxer.accept_stream().await {
        let (read_half, write_half) = tokio::io::split(vstream);
        tokio::spawn(async move {
            if let Err(e) = relay::handle_stream(write_half, read_half).await {
                tracing::debug!("TCP fallback proxy stream error: {:#}", e);
            }
        });
    }

    tracing::info!("TCP fallback connection from {} closed", peer_addr);
    Ok(())
}
