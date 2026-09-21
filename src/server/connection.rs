use anyhow::{bail, Context, Result};
use quinn::Connection;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use super::relay;
use crate::auth::verify_auth_token;
use crate::protocol::{
    read_auth_request, write_auth_response, AuthResponse, STATUS_AUTH_FAILED, STATUS_SUCCESS,
};

pub async fn handle_connection(conn: Connection, auth_key: Arc<String>) -> Result<()> {
    let remote_addr = conn.remote_address();
    tracing::info!("Accepted incoming QUIC connection from {}", remote_addr);

    // First bidirectional stream must perform authentication
    let (mut auth_send, mut auth_recv) = match conn.accept_bi().await {
        Ok(streams) => streams,
        Err(e) => {
            tracing::warn!("Connection from {} closed before auth: {}", remote_addr, e);
            return Ok(());
        }
    };

    let auth_req = match read_auth_request(&mut auth_recv).await {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!("Invalid auth packet from {}: {}", remote_addr, e);
            // Delay slightly to prevent rapid probing
            sleep(Duration::from_millis(50)).await;
            let resp = AuthResponse::new(STATUS_AUTH_FAILED);
            let _ = write_auth_response(&mut auth_send, &resp).await;
            let _ = auth_send.finish();
            conn.close(1u32.into(), b"Auth failed");
            return Ok(());
        }
    };

    let is_valid = verify_auth_token(&conn, &auth_key, &auth_req.token)
        .context("Error verifying auth token")?;

    if !is_valid {
        tracing::warn!("Authentication failed for client {}", remote_addr);
        // Delay slightly before responding to deter timing attacks
        sleep(Duration::from_millis(50)).await;
        let resp = AuthResponse::new(STATUS_AUTH_FAILED);
        let _ = write_auth_response(&mut auth_send, &resp).await;
        let _ = auth_send.finish();
        conn.close(1u32.into(), b"Auth failed");
        bail!("Authentication failed for {}", remote_addr);
    }

    // Auth succeeded
    let resp = AuthResponse::new(STATUS_SUCCESS);
    write_auth_response(&mut auth_send, &resp)
        .await
        .context("Failed to write auth success response")?;
    let _ = auth_send.finish();

    tracing::info!("Client {} successfully authenticated", remote_addr);

    // Accept subsequent proxy streams
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                tokio::spawn(async move {
                    if let Err(e) = relay::handle_stream(send, recv).await {
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
