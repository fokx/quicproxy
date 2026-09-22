use anyhow::{bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::ClientConfig;
use crate::protocol::{
    read_proxy_response, write_proxy_request, ProxyRequest, STATUS_SUCCESS, TargetAddr,
};
use crate::transport::ActiveTransport;

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;

const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDR_NOT_SUPPORTED: u8 = 0x08;

pub async fn run_socks5_listener(
    config: Arc<ClientConfig>,
    conn_provider: Arc<dyn Fn() -> Option<Arc<ActiveTransport>> + Send + Sync>,
) -> Result<()> {
    let listener = TcpListener::bind(config.socks5_listen)
        .await
        .with_context(|| format!("Failed to bind SOCKS5 listener on {}", config.socks5_listen))?;

    tracing::info!("SOCKS5 proxy server is listening on {}", config.socks5_listen);

    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                let config_clone = Arc::clone(&config);
                let conn_provider_clone = Arc::clone(&conn_provider);
                tokio::spawn(async move {
                    if let Err(e) = handle_socks5_client(stream, client_addr, config_clone, conn_provider_clone).await {
                        tracing::debug!("SOCKS5 client {} error: {:#}", client_addr, e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!("Failed to accept SOCKS5 connection: {}", e);
            }
        }
    }
}

async fn handle_socks5_client(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    config: Arc<ClientConfig>,
    conn_provider: Arc<dyn Fn() -> Option<Arc<ActiveTransport>> + Send + Sync>,
) -> Result<()> {
    let _ = stream.set_nodelay(true);

    // 1. Negotiation phase
    let ver = stream.read_u8().await.context("Failed to read SOCKS version")?;
    if ver != SOCKS_VERSION {
        bail!("Unsupported SOCKS version: {}", ver);
    }

    let nmethods = stream.read_u8().await.context("Failed to read nmethods")? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await.context("Failed to read methods")?;

    let require_auth = config.socks5_user.is_some() && config.socks5_password.is_some();

    if require_auth {
        if !methods.contains(&METHOD_USER_PASS) {
            stream.write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE]).await?;
            bail!("Client does not support username/password auth");
        }
        stream.write_all(&[SOCKS_VERSION, METHOD_USER_PASS]).await?;

        // Subnegotiation RFC 1929
        let sub_ver = stream.read_u8().await?;
        if sub_ver != 0x01 {
            stream.write_all(&[0x01, 0x01]).await?;
            bail!("Unsupported auth subnegotiation version: {}", sub_ver);
        }
        let ulen = stream.read_u8().await? as usize;
        let mut uname_buf = vec![0u8; ulen];
        stream.read_exact(&mut uname_buf).await?;
        let plen = stream.read_u8().await? as usize;
        let mut pass_buf = vec![0u8; plen];
        stream.read_exact(&mut pass_buf).await?;

        let uname = String::from_utf8_lossy(&uname_buf);
        let pass = String::from_utf8_lossy(&pass_buf);

        if Some(uname.as_ref()) != config.socks5_user.as_deref()
            || Some(pass.as_ref()) != config.socks5_password.as_deref()
        {
            stream.write_all(&[0x01, 0x01]).await?;
            bail!("SOCKS5 username/password auth failed for {}", client_addr);
        }
        stream.write_all(&[0x01, 0x00]).await?;
    } else {
        if !methods.contains(&METHOD_NO_AUTH) {
            stream.write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE]).await?;
            bail!("Client does not support NO_AUTH");
        }
        stream.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
    }

    // 2. Request phase
    let ver = stream.read_u8().await.context("Failed to read request version")?;
    if ver != SOCKS_VERSION {
        bail!("Invalid SOCKS request version: {}", ver);
    }
    let cmd = stream.read_u8().await.context("Failed to read command")?;
    let _rsv = stream.read_u8().await.context("Failed to read RSV")?;
    let atyp = stream.read_u8().await.context("Failed to read ATYP")?;

    if cmd != CMD_CONNECT {
        // Reply with command not supported
        stream.write_all(&[SOCKS_VERSION, REP_CMD_NOT_SUPPORTED, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        bail!("Unsupported SOCKS command: 0x{:02x}", cmd);
    }

    let target = match atyp {
        0x01 => {
            let mut ip_bytes = [0u8; 4];
            stream.read_exact(&mut ip_bytes).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip_bytes)), port))
        }
        0x03 => {
            let len = stream.read_u8().await? as usize;
            let mut domain_bytes = vec![0u8; len];
            stream.read_exact(&mut domain_bytes).await?;
            let domain = String::from_utf8(domain_bytes).context("Invalid domain UTF-8")?;
            let port = stream.read_u16().await?;
            TargetAddr::Domain(domain, port)
        }
        0x04 => {
            let mut ip_bytes = [0u8; 16];
            stream.read_exact(&mut ip_bytes).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port))
        }
        _ => {
            stream.write_all(&[SOCKS_VERSION, REP_ADDR_NOT_SUPPORTED, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            bail!("Unsupported ATYP: 0x{:02x}", atyp);
        }
    };

    tracing::debug!("SOCKS5 CONNECT request for target {}", target);

    // Obtain active transport (wait briefly if initial connection handshake is still completing)
    let start_wait = std::time::Instant::now();
    let transport = loop {
        if let Some(t) = conn_provider() {
            break t;
        }
        if start_wait.elapsed() > Duration::from_millis(1500) {
            tracing::warn!("No active proxy transport available to handle SOCKS request");
            stream.write_all(&[SOCKS_VERSION, REP_GENERAL_FAILURE, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            bail!("Proxy transport not available");
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    };

    // Open a new bidirectional stream on the active transport
    let proxy_stream = match transport.open_stream().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Failed to open stream on transport ({}): {}", transport.mode_name(), e);
            stream.write_all(&[SOCKS_VERSION, REP_GENERAL_FAILURE, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(e);
        }
    };

    let (mut stream_read, mut stream_write) = tokio::io::split(proxy_stream);

    // Send ProxyRequest
    let req = ProxyRequest::connect(target.clone());
    if let Err(e) = write_proxy_request(&mut stream_write, &req).await {
        stream.write_all(&[SOCKS_VERSION, REP_GENERAL_FAILURE, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err(e);
    }

    // Read ProxyResponse from server
    let resp = match read_proxy_response(&mut stream_read).await {
        Ok(resp) => resp,
        Err(e) => {
            stream.write_all(&[SOCKS_VERSION, REP_GENERAL_FAILURE, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(e);
        }
    };

    if resp.status != STATUS_SUCCESS {
        tracing::warn!("Server failed proxy request for target {}: status {}", target, resp.status);
        stream.write_all(&[SOCKS_VERSION, REP_GENERAL_FAILURE, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Ok(());
    }

    // Success response to SOCKS5 client
    stream.write_all(&[SOCKS_VERSION, REP_SUCCESS, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

    // Bidirectional stream relay
    let (mut tcp_read, mut tcp_write) = stream.into_split();

    let client_to_remote = async {
        let res = tokio::io::copy(&mut tcp_read, &mut stream_write).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream_write).await;
        res
    };

    let remote_to_client = async {
        let res = tokio::io::copy(&mut stream_read, &mut tcp_write).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut tcp_write).await;
        res
    };

    let _ = tokio::join!(client_to_remote, remote_to_client);

    tracing::trace!("SOCKS5 session finished for target {}", target);
    Ok(())
}
