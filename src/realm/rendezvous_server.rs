use anyhow::Result;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::Frame;
use hyper::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use super::client::{
    ConnectRequest, ConnectResponse, ErrorResponse, HeartbeatRequest, HeartbeatResponse,
    PunchEvent, RegisterResponse,
};

struct RealmSession {
    token: String,
    session_id: String,
    addresses: Vec<String>,
    events_tx: broadcast::Sender<PunchEvent>,
    ttl_secs: u64,
    last_seen: Instant,
}

#[derive(Clone)]
pub struct RendezvousServer {
    realms: Arc<RwLock<HashMap<String, RealmSession>>>,
    required_token: Option<String>,
}

impl RendezvousServer {
    pub fn new(required_token: Option<String>) -> Self {
        Self {
            realms: Arc::new(RwLock::new(HashMap::new())),
            required_token,
        }
    }

    pub async fn bind(
        addr: SocketAddr,
        required_token: Option<String>,
    ) -> Result<(Self, SocketAddr)> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        let server = Self::new(required_token);
        let server_clone = server.clone();

        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => break,
                };
                let io = TokioIo::new(stream);
                let server_inner = server_clone.clone();

                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let server_dispatch = server_inner.clone();
                        async move { server_dispatch.handle_request(req).await }
                    });

                    if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                        tracing::debug!("rendezvous HTTP connection ended: {}", e);
                    }
                });
            }
        });

        Ok((server, local_addr))
    }

    async fn handle_request(
        self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let (parts, body) = req.into_parts();
        let path = parts.uri.path().trim_start_matches('/');
        let segments: Vec<&str> = path.split('/').collect();

        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .trim();
        let bearer_token = auth_header.strip_prefix("Bearer ").unwrap_or("");

        // Routes:
        // /v1/{realm_id}
        // /v1/{realm_id}/heartbeat
        // /v1/{realm_id}/events
        // /v1/{realm_id}/connect
        // /v1/{realm_id}/connects/{nonce}

        if segments.is_empty() || segments[0] != "v1" || segments.len() < 2 {
            return Ok(json_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "path not found",
            ));
        }

        let realm_id = match percent_encoding::percent_decode_str(segments[1]).decode_utf8() {
            Ok(s) => s.to_string(),
            Err(_) => {
                return Ok(json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_realm",
                    "invalid realm encoding",
                ));
            }
        };

        if segments.len() == 2 {
            match parts.method {
                Method::POST => {
                    // Register realm
                    if let Some(ref req_tok) = self.required_token {
                        if bearer_token != req_tok {
                            return Ok(json_error(
                                StatusCode::UNAUTHORIZED,
                                "unauthorized",
                                "invalid token",
                            ));
                        }
                    } else if bearer_token.is_empty() {
                        return Ok(json_error(
                            StatusCode::UNAUTHORIZED,
                            "unauthorized",
                            "token is required",
                        ));
                    }

                    let body_bytes = match body.collect().await {
                        Ok(b) => b.to_bytes(),
                        Err(_) => {
                            return Ok(json_error(
                                StatusCode::BAD_REQUEST,
                                "invalid_body",
                                "failed to read body",
                            ));
                        }
                    };

                    #[derive(Deserialize)]
                    struct RegReq {
                        addresses: Vec<String>,
                    }
                    let reg_req: RegReq = match serde_json::from_slice(&body_bytes) {
                        Ok(r) => r,
                        Err(_) => {
                            return Ok(json_error(
                                StatusCode::BAD_REQUEST,
                                "invalid_json",
                                "failed to parse JSON",
                            ));
                        }
                    };

                    let session_id = hex::encode(rand::random::<[u8; 16]>());
                    let ttl_secs = 60;
                    let (events_tx, _) = broadcast::channel(32);

                    {
                        let mut guard = self.realms.write().unwrap();
                        guard.insert(
                            realm_id,
                            RealmSession {
                                token: bearer_token.to_string(),
                                session_id: session_id.clone(),
                                addresses: reg_req.addresses,
                                events_tx,
                                ttl_secs,
                                last_seen: Instant::now(),
                            },
                        );
                    }

                    let resp = RegisterResponse {
                        session_id,
                        ttl: ttl_secs,
                    };
                    return Ok(json_ok(&resp));
                }
                Method::DELETE => {
                    // Deregister realm
                    let mut guard = self.realms.write().unwrap();
                    if let Some(entry) = guard.get(&realm_id) {
                        if entry.session_id != bearer_token {
                            return Ok(json_error(
                                StatusCode::UNAUTHORIZED,
                                "unauthorized",
                                "invalid session",
                            ));
                        }
                        guard.remove(&realm_id);
                        return Ok(Response::builder()
                            .status(StatusCode::NO_CONTENT)
                            .body(empty_body())
                            .unwrap());
                    } else {
                        return Ok(json_error(
                            StatusCode::NOT_FOUND,
                            "not_found",
                            "realm not registered",
                        ));
                    }
                }
                _ => {
                    return Ok(json_error(
                        StatusCode::METHOD_NOT_ALLOWED,
                        "bad_method",
                        "method not allowed",
                    ));
                }
            }
        }

        match (segments[2], parts.method) {
            ("heartbeat", Method::POST) => {
                let body_bytes = match body.collect().await {
                    Ok(b) => b.to_bytes(),
                    Err(_) => {
                        return Ok(json_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_body",
                            "failed to read body",
                        ));
                    }
                };
                let hb_req: HeartbeatRequest =
                    serde_json::from_slice(&body_bytes).unwrap_or_default();

                let mut guard = self.realms.write().unwrap();
                if let Some(entry) = guard.get_mut(&realm_id) {
                    if entry.session_id != bearer_token {
                        return Ok(json_error(
                            StatusCode::UNAUTHORIZED,
                            "unauthorized",
                            "invalid session",
                        ));
                    }
                    entry.last_seen = Instant::now();
                    if let Some(addrs) = hb_req.addresses {
                        if !addrs.is_empty() {
                            entry.addresses = addrs;
                        }
                    }
                    let resp = HeartbeatResponse {
                        ttl: entry.ttl_secs,
                    };
                    Ok(json_ok(&resp))
                } else {
                    Ok(json_error(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "realm session lost",
                    ))
                }
            }
            ("events", Method::GET) => {
                let guard = self.realms.read().unwrap();
                if let Some(entry) = guard.get(&realm_id) {
                    if entry.session_id != bearer_token {
                        return Ok(json_error(
                            StatusCode::UNAUTHORIZED,
                            "unauthorized",
                            "invalid session",
                        ));
                    }
                    let rx = entry.events_tx.subscribe();
                    drop(guard);

                    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
                        Ok(ev) => {
                            let json_str = serde_json::to_string(&ev).ok()?;
                            let sse_str = format!("event: punch\ndata: {}\n\n", json_str);
                            Some(Ok::<_, Infallible>(Frame::data(Bytes::from(sse_str))))
                        }
                        Err(_) => None,
                    });

                    let body = StreamBody::new(stream);
                    let resp = Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "text/event-stream")
                        .header(CACHE_CONTROL, "no-cache")
                        .body(BoxBody::new(body))
                        .unwrap();
                    Ok(resp)
                } else {
                    Ok(json_error(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "realm session lost",
                    ))
                }
            }
            ("connect", Method::POST) => {
                let body_bytes = match body.collect().await {
                    Ok(b) => b.to_bytes(),
                    Err(_) => {
                        return Ok(json_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_body",
                            "failed to read body",
                        ));
                    }
                };
                let conn_req: ConnectRequest = match serde_json::from_slice(&body_bytes) {
                    Ok(r) => r,
                    Err(_) => {
                        return Ok(json_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_json",
                            "failed to parse JSON",
                        ));
                    }
                };

                let guard = self.realms.read().unwrap();
                if let Some(entry) = guard.get(&realm_id) {
                    if entry.token != bearer_token {
                        return Ok(json_error(
                            StatusCode::UNAUTHORIZED,
                            "unauthorized",
                            "invalid token",
                        ));
                    }

                    // Push event to server
                    let _ = entry.events_tx.send(PunchEvent {
                        addresses: conn_req.addresses,
                        nonce: conn_req.nonce.clone(),
                        obfs: conn_req.obfs.clone(),
                    });

                    let resp = ConnectResponse {
                        addresses: entry.addresses.clone(),
                        nonce: conn_req.nonce,
                        obfs: conn_req.obfs,
                    };
                    Ok(json_ok(&resp))
                } else {
                    Ok(json_error(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "realm not found",
                    ))
                }
            }
            ("connects", Method::POST) => {
                // Server connect-response
                let guard = self.realms.read().unwrap();
                if let Some(entry) = guard.get(&realm_id) {
                    if entry.session_id != bearer_token {
                        return Ok(json_error(
                            StatusCode::UNAUTHORIZED,
                            "unauthorized",
                            "invalid session",
                        ));
                    }
                    Ok(Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(empty_body())
                        .unwrap())
                } else {
                    Ok(json_error(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "realm session lost",
                    ))
                }
            }
            _ => Ok(json_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "endpoint not found",
            )),
        }
    }
}

fn empty_body() -> BoxBody<Bytes, Infallible> {
    BoxBody::new(Empty::new())
}

fn json_ok<T: Serialize>(val: &T) -> Response<BoxBody<Bytes, Infallible>> {
    let bs = serde_json::to_vec(val).unwrap();
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(BoxBody::new(Full::new(Bytes::from(bs))))
        .unwrap()
}

fn json_error(
    status: StatusCode,
    error: &str,
    message: &str,
) -> Response<BoxBody<Bytes, Infallible>> {
    let resp = ErrorResponse {
        error: error.to_string(),
        message: message.to_string(),
    };
    let bs = serde_json::to_vec(&resp).unwrap();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(BoxBody::new(Full::new(Bytes::from(bs))))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realm::client::RendezvousClient;
    use crate::realm::punch::PunchMetadata;

    #[tokio::test]
    async fn test_rendezvous_server_flow() {
        let (_server, addr) = RendezvousServer::bind("127.0.0.1:0".parse().unwrap(), None)
            .await
            .unwrap();

        let base_url = format!("http://{}", addr);
        let client = RendezvousClient::new(&base_url, "test-token", false).unwrap();

        // 1. Register
        let reg = client
            .register("my-realm", &["203.0.113.1:4433".to_string()])
            .await
            .unwrap();
        assert_eq!(reg.ttl, 60);

        // 2. Open events stream
        let mut events = client.events("my-realm", &reg.session_id).await.unwrap();

        // 3. Connect from another client
        let meta = PunchMetadata::new_random();
        let conn_client = RendezvousClient::new(&base_url, "test-token", false).unwrap();
        let conn_resp = conn_client
            .connect(
                "my-realm",
                &ConnectRequest {
                    addresses: vec!["198.51.100.1:5555".to_string()],
                    nonce: meta.nonce.clone(),
                    obfs: meta.obfs.clone(),
                },
            )
            .await
            .unwrap();

        assert_eq!(conn_resp.addresses, vec!["203.0.113.1:4433"]);
        assert_eq!(conn_resp.nonce, meta.nonce);

        // 4. Server receives PunchEvent on SSE stream
        let ev = events.next().await.unwrap().unwrap();
        assert_eq!(ev.addresses, vec!["198.51.100.1:5555"]);
        assert_eq!(ev.nonce, meta.nonce);

        // 5. Server posts connect-response
        client
            .connect_response(
                "my-realm",
                &reg.session_id,
                &meta.nonce,
                &["203.0.113.1:4433".to_string()],
            )
            .await
            .unwrap();

        // 6. Heartbeat
        let hb = client
            .heartbeat("my-realm", &reg.session_id, None)
            .await
            .unwrap();
        assert_eq!(hb.ttl, 60);

        // 7. Deregister
        client
            .deregister("my-realm", &reg.session_id)
            .await
            .unwrap();
    }
}
