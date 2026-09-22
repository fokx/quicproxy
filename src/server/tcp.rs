use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::net::TcpStream;

use super::relay;
use crate::transport::tcp::accept_server_tcp;

pub async fn handle_tcp_connection(stream: TcpStream, auth_key: Arc<String>) -> Result<()> {
    let peer_addr = stream.peer_addr().context("Failed to get TCP peer address")?;
    tracing::info!("Accepted incoming TCP fallback connection from {}", peer_addr);

    let muxer = match accept_server_tcp(stream, &auth_key).await {
        Ok(muxer) => muxer,
        Err(e) => {
            tracing::warn!("TCP fallback authentication failed for {}: {:#}", peer_addr, e);
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
