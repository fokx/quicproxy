use anyhow::{Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tracing::debug;

use crate::protocol::{TargetAddr, UdpDatagram};

pub struct UdpSession {
    pub session_id: u32,
    socket: Arc<UdpSocket>,
    last_activity: Arc<AtomicU64>, // unix timestamp seconds
    _task_handle: tokio::task::JoinHandle<()>,
}

pub struct UdpSessionTable {
    sessions: DashMap<u32, Arc<UdpSession>>,
    timeout_secs: u64,
    acl_engine: Arc<crate::acl::ACLEngine>,
}

impl UdpSessionTable {
    pub fn new(timeout_secs: u64, acl_engine: Arc<crate::acl::ACLEngine>) -> Self {
        Self {
            sessions: DashMap::new(),
            timeout_secs,
            acl_engine,
        }
    }

    pub async fn handle_outbound<F>(
        &self,
        session_id: u32,
        target: TargetAddr,
        payload: &[u8],
        send_back: F,
    ) -> Result<()>
    where
        F: Fn(Bytes) -> Result<(), String> + Send + Sync + 'static,
    {
        let (outbound, final_target) = self
            .acl_engine
            .handle(&target, crate::acl::Protocol::Udp)
            .await;
        if outbound.is_reject() {
            debug!("UDP datagram to {} rejected by ACL", target);
            return Ok(());
        }

        let session = if let Some(sess) = self.sessions.get(&session_id) {
            sess.clone()
        } else {
            let socket = Arc::new(
                UdpSocket::bind("0.0.0.0:0")
                    .await
                    .context("Failed to bind UDP socket")?,
            );
            let last_activity = Arc::new(AtomicU64::new(get_current_timestamp()));

            let socket_clone = socket.clone();
            let last_activity_clone = last_activity.clone();

            let task_handle = tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    match socket_clone.recv_from(&mut buf).await {
                        Ok((len, src_addr)) => {
                            update_timestamp(&last_activity_clone);

                            let dgram = UdpDatagram {
                                session_id,
                                target: TargetAddr::Ip(src_addr),
                                payload: buf[..len].to_vec(),
                            };

                            let encoded = dgram.encode();
                            if let Err(e) = send_back(Bytes::from(encoded)) {
                                debug!(
                                    "Failed to send datagram to client for session {}: {}",
                                    session_id, e
                                );
                            }
                        }
                        Err(e) => {
                            debug!("UDP socket error for session {}: {}", session_id, e);
                            break;
                        }
                    }
                }
            });

            let session = Arc::new(UdpSession {
                session_id,
                socket,
                last_activity,
                _task_handle: task_handle,
            });

            self.sessions.insert(session_id, session.clone());
            session
        };

        // Resolve the target address
        let resolved_addr = match &final_target {
            TargetAddr::Ip(addr) => *addr,
            TargetAddr::Domain(host, port) => {
                let host_str = format!("{}:{}", host, port);
                let mut addrs = tokio::net::lookup_host(&host_str)
                    .await
                    .context("Failed to resolve domain")?;
                addrs.next().context("Domain resolved to no addresses")?
            }
        };

        session
            .socket
            .send_to(payload, resolved_addr)
            .await
            .context("Failed to send UDP payload")?;
        update_timestamp(&session.last_activity);

        Ok(())
    }

    pub async fn reaper_loop(&self) {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;

            let now = get_current_timestamp();
            let mut to_remove = Vec::new();

            for entry in self.sessions.iter() {
                let session = entry.value();
                let last = get_timestamp(&session.last_activity);
                if now > last + self.timeout_secs {
                    to_remove.push(*entry.key());
                }
            }

            for id in to_remove {
                if let Some((_, session)) = self.sessions.remove(&id) {
                    debug!("Reaping UDP session {}", id);
                    session._task_handle.abort();
                }
            }
        }
    }

    pub fn remove_session(&self, session_id: u32) {
        if let Some((_, session)) = self.sessions.remove(&session_id) {
            session._task_handle.abort();
        }
    }
}

fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn update_timestamp(last_activity: &AtomicU64) {
    last_activity.store(get_current_timestamp(), Ordering::Relaxed);
}

fn get_timestamp(last_activity: &AtomicU64) -> u64 {
    last_activity.load(Ordering::Relaxed)
}
