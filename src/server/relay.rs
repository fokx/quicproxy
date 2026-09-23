use anyhow::{Context, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::protocol::{
    read_proxy_request, write_proxy_response, CMD_CONNECT, CMD_UDP_ASSOCIATE, ProxyResponse,
    STATUS_CONNECT_FAILED, STATUS_SUCCESS, STATUS_UNSUPPORTED, TargetAddr,
};

const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn handle_stream<W, R>(mut send: W, mut recv: R) -> Result<()>
where
    W: AsyncWrite + AsyncWriteExt + Unpin + Send + 'static,
    R: AsyncRead + AsyncReadExt + Unpin + Send + 'static,
{
    let req = read_proxy_request(&mut recv)
        .await
        .context("Failed to read proxy request")?;

    match req.cmd {
        CMD_CONNECT => handle_connect(send, recv, req.target).await,
        CMD_UDP_ASSOCIATE => handle_udp_associate(send, recv, req.target).await,
        _ => {
            let resp = ProxyResponse::new(STATUS_UNSUPPORTED);
            let _ = write_proxy_response(&mut send, &resp).await;
            let _ = send.shutdown().await;
            Ok(())
        }
    }
}

/// Handle a TCP CONNECT proxy request.
async fn handle_connect<W, R>(mut send: W, mut recv: R, target: TargetAddr) -> Result<()>
where
    W: AsyncWrite + AsyncWriteExt + Unpin + Send + 'static,
    R: AsyncRead + AsyncReadExt + Unpin + Send + 'static,
{
    tracing::debug!("Proxy CONNECT request to {}", target);

    let tcp_conn_result = match &target {
        TargetAddr::Ip(addr) => timeout(TARGET_CONNECT_TIMEOUT, TcpStream::connect(*addr)).await,
        TargetAddr::Domain(host, port) => {
            timeout(TARGET_CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), *port))).await
        }
    };

    let tcp_stream = match tcp_conn_result {
        Ok(Ok(stream)) => {
            let resp = ProxyResponse::new(STATUS_SUCCESS);
            write_proxy_response(&mut send, &resp)
                .await
                .context("Failed to write proxy success response")?;
            stream
        }
        Ok(Err(err)) => {
            tracing::warn!("Failed to connect to target {}: {}", target, err);
            let resp = ProxyResponse::new(STATUS_CONNECT_FAILED);
            let _ = write_proxy_response(&mut send, &resp).await;
            let _ = send.shutdown().await;
            return Ok(());
        }
        Err(_) => {
            tracing::warn!("Timeout connecting to target {}", target);
            let resp = ProxyResponse::new(STATUS_CONNECT_FAILED);
            let _ = write_proxy_response(&mut send, &resp).await;
            let _ = send.shutdown().await;
            return Ok(());
        }
    };

    let _ = tcp_stream.set_nodelay(true);

    // Bidirectional data transfer between QUIC stream and TCP socket
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    let client_to_target = async {
        let res = tokio::io::copy(&mut recv, &mut tcp_write).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut tcp_write).await;
        res
    };

    let target_to_client = async {
        let res = tokio::io::copy(&mut tcp_read, &mut send).await;
        let _ = send.shutdown().await;
        res
    };

    let _ = tokio::join!(client_to_target, target_to_client);

    tracing::trace!("Completed relay session for {}", target);
    Ok(())
}

/// Handle a UDP ASSOCIATE proxy request.
/// The actual UDP datagram forwarding is handled at the connection level
/// via the datagram receiver loop. This stream serves as the control stream
/// whose lifetime bounds the UDP association (per RFC 1928).
async fn handle_udp_associate<W, R>(mut send: W, mut recv: R, target: TargetAddr) -> Result<()>
where
    W: AsyncWrite + AsyncWriteExt + Unpin + Send + 'static,
    R: AsyncRead + AsyncReadExt + Unpin + Send + 'static,
{
    tracing::debug!("UDP ASSOCIATE request for {}", target);

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
