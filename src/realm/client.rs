use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

use super::addr::RealmAddr;
use super::punch::PunchMetadata;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub session_id: String,
    pub ttl: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub ttl: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeartbeatRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub addresses: Vec<String>,
    pub nonce: String,
    pub obfs: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectResponse {
    pub addresses: Vec<String>,
    pub nonce: String,
    pub obfs: String,
}

impl ConnectResponse {
    pub fn punch_metadata(&self) -> PunchMetadata {
        PunchMetadata {
            nonce: self.nonce.clone(),
            obfs: self.obfs.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectResponseRequest {
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PunchEvent {
    pub addresses: Vec<String>,
    pub nonce: String,
    pub obfs: String,
}

impl PunchEvent {
    pub fn punch_metadata(&self) -> PunchMetadata {
        PunchMetadata {
            nonce: self.nonce.clone(),
            obfs: self.obfs.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ErrorResponse {
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct StatusError {
    pub status_code: u16,
    pub response: ErrorResponse,
}

impl fmt::Display for StatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.response.error.is_empty() || !self.response.message.is_empty() {
            write!(
                f,
                "realm server returned {}: {}: {}",
                self.status_code, self.response.error, self.response.message
            )
        } else {
            write!(f, "realm server returned {}", self.status_code)
        }
    }
}

impl std::error::Error for StatusError {}

pub fn is_realm_session_invalid(err: &anyhow::Error) -> bool {
    if let Some(status_err) = err.downcast_ref::<StatusError>() {
        status_err.status_code == 401 || status_err.status_code == 404
    } else {
        false
    }
}

pub fn is_realm_register_fatal(err: &anyhow::Error) -> bool {
    if let Some(status_err) = err.downcast_ref::<StatusError>() {
        status_err.status_code == 400
    } else {
        false
    }
}

#[derive(Debug, Clone)]
pub struct RendezvousClient {
    base_url: String,
    token: String,
    http_client: reqwest::Client,
}

impl RendezvousClient {
    pub fn new(base_url: &str, token: &str, insecure: bool) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let base_url = base_url.trim_end_matches('/').to_string();
        let mut builder = reqwest::Client::builder();
        if insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let http_client = builder
            .build()
            .context("failed to build HTTP client for rendezvous")?;

        Ok(Self {
            base_url,
            token: token.to_string(),
            http_client,
        })
    }

    pub fn from_addr(addr: &RealmAddr, insecure: bool) -> Result<Self> {
        Self::new(&addr.base_url(), &addr.token, insecure)
    }

    pub async fn register(&self, realm_id: &str, addresses: &[String]) -> Result<RegisterResponse> {
        #[derive(Serialize)]
        struct Req<'a> {
            addresses: &'a [String],
        }

        let url = format!("{}/v1/{}", self.base_url, urlencoding_encode(realm_id));
        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&Req { addresses })
            .send()
            .await
            .context("failed to send realm register request")?;

        if resp.status() != reqwest::StatusCode::OK {
            return Err(decode_status_error(resp).await);
        }

        let body = resp
            .json::<RegisterResponse>()
            .await
            .context("failed to parse register response JSON")?;
        Ok(body)
    }

    pub async fn deregister(&self, realm_id: &str, session_id: &str) -> Result<()> {
        let url = format!("{}/v1/{}", self.base_url, urlencoding_encode(realm_id));
        let resp = self
            .http_client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", session_id))
            .send()
            .await
            .context("failed to send realm deregister request")?;

        if resp.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(decode_status_error(resp).await);
        }
        Ok(())
    }

    pub async fn heartbeat(
        &self,
        realm_id: &str,
        session_id: &str,
        addresses: Option<&[String]>,
    ) -> Result<HeartbeatResponse> {
        let url = format!(
            "{}/v1/{}/heartbeat",
            self.base_url,
            urlencoding_encode(realm_id)
        );
        let req = HeartbeatRequest {
            addresses: addresses.map(|a| a.to_vec()),
        };

        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", session_id))
            .json(&req)
            .send()
            .await
            .context("failed to send realm heartbeat request")?;

        if resp.status() != reqwest::StatusCode::OK {
            return Err(decode_status_error(resp).await);
        }

        let body = resp
            .json::<HeartbeatResponse>()
            .await
            .context("failed to parse heartbeat response JSON")?;
        Ok(body)
    }

    pub async fn connect(&self, realm_id: &str, req: &ConnectRequest) -> Result<ConnectResponse> {
        let url = format!(
            "{}/v1/{}/connect",
            self.base_url,
            urlencoding_encode(realm_id)
        );
        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .json(req)
            .send()
            .await
            .context("failed to send realm connect request")?;

        if resp.status() != reqwest::StatusCode::OK {
            return Err(decode_status_error(resp).await);
        }

        let body = resp
            .json::<ConnectResponse>()
            .await
            .context("failed to parse connect response JSON")?;
        Ok(body)
    }

    pub async fn connect_response(
        &self,
        realm_id: &str,
        session_id: &str,
        nonce: &str,
        addresses: &[String],
    ) -> Result<()> {
        let url = format!(
            "{}/v1/{}/connects/{}",
            self.base_url,
            urlencoding_encode(realm_id),
            urlencoding_encode(nonce)
        );
        let req = ConnectResponseRequest {
            addresses: addresses.to_vec(),
        };

        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", session_id))
            .json(&req)
            .send()
            .await
            .context("failed to send realm connect-response post")?;

        if resp.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(decode_status_error(resp).await);
        }
        Ok(())
    }

    pub async fn events(&self, realm_id: &str, session_id: &str) -> Result<EventStream> {
        let url = format!(
            "{}/v1/{}/events",
            self.base_url,
            urlencoding_encode(realm_id)
        );
        let resp = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", session_id))
            .send()
            .await
            .context("failed to initiate realm events stream")?;

        if resp.status() != reqwest::StatusCode::OK {
            return Err(decode_status_error(resp).await);
        }

        Ok(EventStream::new(resp))
    }
}

fn urlencoding_encode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

async fn decode_status_error(resp: reqwest::Response) -> anyhow::Error {
    let status_code = resp.status().as_u16();
    let err_resp = resp
        .json::<ErrorResponse>()
        .await
        .unwrap_or_else(|_| ErrorResponse {
            error: "unknown".to_string(),
            message: format!("HTTP status {}", status_code),
        });

    StatusError {
        status_code,
        response: err_resp,
    }
    .into()
}

pub struct EventStream {
    response: reqwest::Response,
    buffer: String,
    current_event: String,
    current_data: String,
}

impl EventStream {
    pub fn new(response: reqwest::Response) -> Self {
        Self {
            response,
            buffer: String::new(),
            current_event: String::new(),
            current_data: String::new(),
        }
    }

    /// Read next `PunchEvent` from the SSE stream.
    pub async fn next(&mut self) -> Result<Option<PunchEvent>> {
        loop {
            // Check if buffer contains a line
            if let Some(pos) = self.buffer.find('\n') {
                let mut line = self.buffer[..pos].to_string();
                self.buffer.drain(..=pos);
                if line.ends_with('\r') {
                    line.pop();
                }

                if line.is_empty() {
                    // Empty line signals end of an SSE message block
                    if self.current_event == "punch" && !self.current_data.is_empty() {
                        let ev_result = serde_json::from_str::<PunchEvent>(&self.current_data);
                        self.current_event.clear();
                        self.current_data.clear();
                        match ev_result {
                            Ok(ev) => return Ok(Some(ev)),
                            Err(e) => {
                                tracing::warn!("failed to deserialize punch event JSON: {}", e);
                                continue;
                            }
                        }
                    }
                    self.current_event.clear();
                    self.current_data.clear();
                    continue;
                }

                if line.starts_with(':') {
                    // SSE comment, ignore
                    continue;
                }

                if let Some((field, val)) = line.split_once(':') {
                    let value = val.strip_prefix(' ').unwrap_or(val);
                    match field {
                        "event" => self.current_event = value.to_string(),
                        "data" => {
                            if !self.current_data.is_empty() {
                                self.current_data.push('\n');
                            }
                            self.current_data.push_str(value);
                        }
                        _ => {}
                    }
                }
                continue;
            }

            // Need more data from network
            match self.response.chunk().await? {
                Some(chunk) => {
                    let text = String::from_utf8_lossy(&chunk);
                    self.buffer.push_str(&text);
                }
                None => {
                    // End of stream
                    return Ok(None);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_stream_parsing() {
        let (_server, addr) = crate::realm::rendezvous_server::RendezvousServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            None,
        )
        .await
        .unwrap();

        let client = RendezvousClient::new(&format!("http://{}", addr), "token", false).unwrap();
        let reg = client.register("realm-1", &[]).await.unwrap();
        let mut events = client.events("realm-1", &reg.session_id).await.unwrap();

        let meta = PunchMetadata::new_random();
        let _ = client
            .connect(
                "realm-1",
                &ConnectRequest {
                    addresses: vec!["1.2.3.4:5678".to_string()],
                    nonce: meta.nonce.clone(),
                    obfs: meta.obfs.clone(),
                },
            )
            .await
            .unwrap();

        let ev = events.next().await.unwrap().unwrap();
        assert_eq!(ev.addresses, vec!["1.2.3.4:5678"]);
        assert_eq!(ev.nonce, meta.nonce);
    }
}
