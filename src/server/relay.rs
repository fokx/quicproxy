use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::acl::ACLEngine;
use crate::protocol::{
    read_proxy_request, write_proxy_response, CMD_CONNECT, CMD_UDP_ASSOCIATE, ProxyResponse,
    STATUS_CONNECT_FAILED, STATUS_SUCCESS, STATUS_UNSUPPORTED, TargetAddr,
};

pub async fn handle_stream<W, R>(
    mut send: W,
    mut recv: R,
    acl_engine: Arc<ACLEngine>,
) -> Result<()>
where
    W: AsyncWrite + AsyncWriteExt + Unpin + Send + 'static,
    R: AsyncRead + AsyncReadExt + Unpin + Send + 'static,
{
    let req = read_proxy_request(&mut recv)
        .await
        .context("Failed to read proxy request")?;

    match req.cmd {
        CMD_CONNECT => handle_connect(send, recv, req.target, acl_engine).await,
        CMD_UDP_ASSOCIATE => handle_udp_associate(send, recv, req.target, acl_engine).await,
        _ => {
            let resp = ProxyResponse::new(STATUS_UNSUPPORTED);
            let _ = write_proxy_response(&mut send, &resp).await;
            let _ = send.shutdown().await;
            Ok(())
        }
    }
}

/// Handle a TCP CONNECT proxy request through ACL and Outbounds.
async fn handle_connect<W, R>(
    mut send: W,
    mut recv: R,
    target: TargetAddr,
    acl_engine: Arc<ACLEngine>,
) -> Result<()>
where
    W: AsyncWrite + AsyncWriteExt + Unpin + Send + 'static,
    R: AsyncRead + AsyncReadExt + Unpin + Send + 'static,
{
    tracing::debug!("Proxy CONNECT request to {}", target);

    let (outbound, final_target) = acl_engine.handle(&target, crate::acl::Protocol::Tcp).await;

    if outbound.is_reject() {
        tracing::warn!("Target {} rejected by ACL", target);
        let resp = ProxyResponse::new(STATUS_CONNECT_FAILED);
        let _ = write_proxy_response(&mut send, &resp).await;
        let _ = send.shutdown().await;
        return Ok(());
    }

    let tcp_stream = match outbound.tcp_connect(&final_target).await {
        Ok(stream) => {
            let resp = ProxyResponse::new(STATUS_SUCCESS);
            write_proxy_response(&mut send, &resp)
                .await
                .context("Failed to write proxy success response")?;
            stream
        }
        Err(err) => {
            tracing::warn!("Failed to connect to target {}: {}", final_target, err);
            let resp = ProxyResponse::new(STATUS_CONNECT_FAILED);
            let _ = write_proxy_response(&mut send, &resp).await;
            let _ = send.shutdown().await;
            return Ok(());
        }
    };

    // Bidirectional data transfer between proxy client stream and target stream
    let (mut target_read, mut target_write) = tokio::io::split(tcp_stream);

    let client_to_target = async {
        let res = tokio::io::copy(&mut recv, &mut target_write).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut target_write).await;
        res
    };

    let target_to_client = async {
        let res = tokio::io::copy(&mut target_read, &mut send).await;
        let _ = send.shutdown().await;
        res
    };

    let _ = tokio::join!(client_to_target, target_to_client);

    tracing::trace!("Completed relay session for {}", final_target);
    Ok(())
}

/// Handle a UDP ASSOCIATE proxy request.
/// The actual UDP datagram forwarding is handled at the connection level
/// via the datagram receiver loop. This stream serves as the control stream
/// whose lifetime bounds the UDP association (per RFC 1928).
async fn handle_udp_associate<W, R>(
    mut send: W,
    mut recv: R,
    target: TargetAddr,
    acl_engine: Arc<ACLEngine>,
) -> Result<()>
where
    W: AsyncWrite + AsyncWriteExt + Unpin + Send + 'static,
    R: AsyncRead + AsyncReadExt + Unpin + Send + 'static,
{
    tracing::debug!("UDP ASSOCIATE request for {}", target);

    let (outbound, _final_target) = acl_engine.handle(&target, crate::acl::Protocol::Udp).await;
    if outbound.is_reject() {
        tracing::warn!("UDP ASSOCIATE for {} rejected by ACL", target);
        let resp = ProxyResponse::new(STATUS_CONNECT_FAILED);
        let _ = write_proxy_response(&mut send, &resp).await;
        let _ = send.shutdown().await;
        return Ok(());
    }

    // Send success response to confirm we're ready for datagrams
    let resp = ProxyResponse::new(STATUS_SUCCESS);
    write_proxy_response(&mut send, &resp)
        .await
        .context("Failed to write UDP ASSOCIATE success response")?;

    // Hold the stream open as the control stream.
    // When the client drops the TCP control connection, the UDP association terminates.
    // We just read until EOF or error.
    let mut buf = [0u8; 64];
    loop {
        match recv.read(&mut buf).await {
            Ok(0) => {
                tracing::debug!("UDP ASSOCIATE control stream closed for {}", target);
                break;
            }
            Ok(_) => {
                // Ignore any data on the control stream
            }
            Err(e) => {
                tracing::debug!("UDP ASSOCIATE control stream error for {}: {}", target, e);
                break;
            }
        }
    }

    Ok(())
}
