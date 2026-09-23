use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MasqueradeMode {
    #[default]
    Off,
    FileServer,
    ReverseProxy,
}

impl std::str::FromStr for MasqueradeMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "off" | "none" => Ok(MasqueradeMode::Off),
            "file" | "file_server" | "fileserver" => Ok(MasqueradeMode::FileServer),
            "proxy" | "reverse_proxy" | "reverseproxy" => Ok(MasqueradeMode::ReverseProxy),
            other => anyhow::bail!(
                "Unknown masquerade mode '{}', expected 'off', 'file_server', or 'reverse_proxy'",
                other
            ),
        }
    }
}

impl std::fmt::Display for MasqueradeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MasqueradeMode::Off => write!(f, "off"),
            MasqueradeMode::FileServer => write!(f, "file_server"),
            MasqueradeMode::ReverseProxy => write!(f, "reverse_proxy"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasqueradeConfig {
    #[serde(default)]
    pub mode: MasqueradeMode,

    pub static_dir: Option<PathBuf>,

    pub upstream_url: Option<String>,
}

impl Default for MasqueradeConfig {
    fn default() -> Self {
        Self {
            mode: MasqueradeMode::Off,
            static_dir: None,
            upstream_url: None,
        }
    }
}

impl MasqueradeConfig {
    pub fn is_enabled(&self) -> bool {
        self.mode != MasqueradeMode::Off
    }
}

pub struct MasqueradeHandler {
    config: MasqueradeConfig,
    http_client: Option<reqwest::Client>,
}

impl MasqueradeHandler {
    pub fn new(config: MasqueradeConfig) -> Self {
        let http_client = if config.mode == MasqueradeMode::ReverseProxy {
            Some(
                reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .unwrap_or_default(),
            )
        } else {
            None
        };

        Self {
            config,
            http_client,
        }
    }

    pub fn mode(&self) -> MasqueradeMode {
        self.config.mode
    }

    pub fn is_enabled(&self) -> bool {
        self.config.mode != MasqueradeMode::Off
    }

    pub async fn handle_quic_connection(&self, conn: quinn::Connection) -> Result<()> {
        let remote_addr = conn.remote_address();
        tracing::info!("Diverting connection from {} to HTTP/3 masquerade engine", remote_addr);

        let h3_conn = h3_quinn::Connection::new(conn);
        let mut server = h3::server::builder()
            .build(h3_conn)
            .await
            .context("Failed to initialize HTTP/3 server endpoint")?;

        while let Some(resolver) = server.accept().await? {
            let (req, mut stream) = match resolver.resolve_request().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::debug!("Failed to resolve incoming HTTP/3 request from {}: {}", remote_addr, e);
                    continue;
                }
            };
            let path = req.uri().path().to_string();
            tracing::debug!("HTTP/3 prober request from {}: {} {}", remote_addr, req.method(), path);

            match self.config.mode {
                MasqueradeMode::FileServer => {
                    let (status, content_type, body) = self.serve_file(&path).await;
                    let resp = Response::builder()
                        .status(status)
                        .header("content-type", content_type)
                        .header("server", "cloudflare")
                        .body(())?;

                    stream.send_response(resp).await?;
                    if !body.is_empty() {
                        stream.send_data(body).await?;
                    }
                    stream.finish().await?;
                }
                MasqueradeMode::ReverseProxy => {
                    let (status, content_type, body) = self.proxy_request(&path).await;
                    let resp = Response::builder()
                        .status(status)
                        .header("content-type", content_type)
                        .header("server", "nginx")
                        .body(())?;

                    stream.send_response(resp).await?;
                    if !body.is_empty() {
                        stream.send_data(body).await?;
                    }
                    stream.finish().await?;
                }
                MasqueradeMode::Off => {
                    let resp = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(())?;
                    stream.send_response(resp).await?;
                    stream.finish().await?;
                }
            }
        }

        Ok(())
    }

    async fn serve_file(&self, path: &str) -> (StatusCode, &'static str, Bytes) {
        let default_html = b"<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Welcome to our service</h1><p>The server is operating normally.</p></body></html>";

        let dir = match &self.config.static_dir {
            Some(d) => d,
            None => {
                return (StatusCode::OK, "text/html; charset=utf-8", Bytes::from_static(default_html));
            }
        };

        let req_path = path.trim_start_matches('/');
        let rel_path = if req_path.is_empty() || req_path == "/" {
            "index.html"
        } else {
            req_path
        };

        // Prevent directory traversal
        if rel_path.contains("..") {
            return (StatusCode::FORBIDDEN, "text/plain", Bytes::from_static(b"Forbidden"));
        }

        let full_path = dir.join(rel_path);
        if full_path.is_file() {
            match tokio::fs::read(&full_path).await {
                Ok(content) => {
                    let mime = guess_mime_type(&full_path);
                    (StatusCode::OK, mime, Bytes::from(content))
                }
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "text/plain", Bytes::from_static(b"Error reading file")),
            }
        } else {
            (StatusCode::NOT_FOUND, "text/html; charset=utf-8", Bytes::from_static(b"<html><body><h1>404 Not Found</h1></body></html>"))
        }
    }

    async fn proxy_request(&self, path: &str) -> (StatusCode, &'static str, Bytes) {
        let upstream = match &self.config.upstream_url {
            Some(u) => u.trim_end_matches('/'),
            None => return (StatusCode::BAD_GATEWAY, "text/plain", Bytes::from_static(b"Bad Gateway: No upstream URL")),
        };

        let target_url = format!("{}{}", upstream, path);
        if let Some(ref client) = self.http_client {
            match client.get(&target_url).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let content_type = resp
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("text/html; charset=utf-8");

                    // For content_type, we return a known string or fall back to generic
                    let mime: &'static str = if content_type.contains("text/html") {
                        "text/html; charset=utf-8"
                    } else if content_type.contains("application/json") {
                        "application/json"
                    } else {
                        "text/plain; charset=utf-8"
                    };

                    match resp.bytes().await {
                        Ok(b) => (status, mime, b),
                        Err(_) => (StatusCode::BAD_GATEWAY, "text/plain", Bytes::from_static(b"Error reading upstream response")),
                    }
                }
                Err(e) => {
                    tracing::warn!("Masquerade reverse proxy upstream fetch failed: {}", e);
                    (StatusCode::BAD_GATEWAY, "text/plain", Bytes::from_static(b"Bad Gateway"))
                }
            }
        } else {
            (StatusCode::BAD_GATEWAY, "text/plain", Bytes::from_static(b"Bad Gateway: HTTP client not initialized"))
        }
    }
}

fn guess_mime_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
