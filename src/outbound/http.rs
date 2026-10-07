use anyhow::{Context, Result, bail};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::{AsyncReadWrite, Outbound};
use crate::protocol::TargetAddr;

const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct HttpOutbound {
    name: String,
    proxy_addr: String,
    auth_header: Option<String>,
}

impl HttpOutbound {
    pub fn new(name: impl Into<String>, url_str: &str, _insecure: bool) -> Result<Self> {
        let name = name.into();
        // Parse url e.g. "http://user:pass@127.0.0.1:8080" or "http://127.0.0.1:8080"
        let parsed = url::Url::parse(url_str)
            .with_context(|| format!("Invalid HTTP proxy URL '{}'", url_str))?;

        let host = parsed
            .host_str()
            .with_context(|| format!("Missing host in HTTP proxy URL '{}'", url_str))?;
        let port = parsed.port().unwrap_or(8080);
        let proxy_addr = format!("{}:{}", host, port);

        let auth_header = if !parsed.username().is_empty() {
            let user = parsed.username();
            let pass = parsed.password().unwrap_or("");
            let cred = format!("{}:{}", user, pass);
            let b64 = format!("Basic {}", base64_encode(cred.as_bytes()));
            Some(b64)
        } else {
            None
        };

        Ok(Self {
            name,
            proxy_addr,
            auth_header,
        })
    }
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);

        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

impl Outbound for HttpOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn tcp_connect<'a>(
        &'a self,
        target: &'a TargetAddr,
    ) -> super::BoxFuture<'a, Result<Box<dyn AsyncReadWrite>>> {
        Box::pin(async move {
            let mut stream = timeout(HTTP_CONNECT_TIMEOUT, TcpStream::connect(&self.proxy_addr))
                .await
                .with_context(|| format!("Timeout connecting to HTTP proxy {}", self.proxy_addr))?
                .with_context(|| format!("Failed to connect to HTTP proxy {}", self.proxy_addr))?;
            let _ = stream.set_nodelay(true);

            let target_str = target.to_string();
            let mut req = format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: quicproxy\r\nProxy-Connection: Keep-Alive\r\n",
                target_str, target_str
            );
            if let Some(auth) = &self.auth_header {
                req.push_str(&format!("Proxy-Authorization: {}\r\n", auth));
            }
            req.push_str("\r\n");

            stream.write_all(req.as_bytes()).await?;

            // Read response headers
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while buf.len() < 4096 {
                let n = stream.read(&mut byte).await?;
                if n == 0 {
                    bail!("HTTP proxy closed connection prematurely");
                }
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }

            let resp_str = String::from_utf8_lossy(&buf);
            let first_line = resp_str.lines().next().unwrap_or("");
            if !first_line.contains(" 200 ") && !first_line.ends_with(" 200") {
                bail!("HTTP proxy rejected CONNECT request: {}", first_line);
            }

            Ok(Box::new(stream) as Box<dyn AsyncReadWrite>)
        })
    }
}
