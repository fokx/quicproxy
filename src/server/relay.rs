use anyhow::{Context, Result};
use quinn::{RecvStream, SendStream};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::protocol::{
    read_proxy_request, write_proxy_response, CMD_CONNECT, ProxyResponse,
    STATUS_CONNECT_FAILED, STATUS_SUCCESS, STATUS_UNSUPPORTED, TargetAddr,
};

const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn handle_stream(mut send: SendStream, mut recv: RecvStream) -> Result<()> {
    let req = read_proxy_request(&mut recv)
        .await
        .context("Failed to read proxy request")?;

    if req.cmd != CMD_CONNECT {
        let resp = ProxyResponse::new(STATUS_UNSUPPORTED);
        let _ = write_proxy_response(&mut send, &resp).await;
        let _ = send.finish();
        return Ok(());
    }

    tracing::debug!("Proxy CONNECT request to {}", req.target);

    let tcp_conn_result = match &req.target {
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
            tracing::warn!("Failed to connect to target {}: {}", req.target, err);
            let resp = ProxyResponse::new(STATUS_CONNECT_FAILED);
            let _ = write_proxy_response(&mut send, &resp).await;
            let _ = send.finish();
            return Ok(());
        }
        Err(_) => {
            tracing::warn!("Timeout connecting to target {}", req.target);
            let resp = ProxyResponse::new(STATUS_CONNECT_FAILED);
            let _ = write_proxy_response(&mut send, &resp).await;
            let _ = send.finish();
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
        let _ = send.finish();
        res
    };

    let _ = tokio::join!(client_to_target, target_to_client);

    tracing::trace!("Completed relay session for {}", req.target);
    Ok(())
}
