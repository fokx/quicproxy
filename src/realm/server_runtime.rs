use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use super::addr::RealmAddr;
use super::client::{RendezvousClient, is_realm_register_fatal};
use super::config::RealmConfig;
use super::portmap::PortMapper;
use super::punch::{AddrFamily, PunchConfig};
use super::punch_socket::PunchUdpSocket;
use super::server_punch::ServerPuncher;
use super::stun::discover_with_demux;

const REALM_CONNECT_STUN_CACHE_TTL: Duration = Duration::from_secs(10);

type CachedAddresses = Arc<Mutex<Option<(Vec<SocketAddr>, Instant)>>>;

pub struct RealmServerRuntime {
    addr: RealmAddr,
    client: RendezvousClient,
    punch_socket: Arc<PunchUdpSocket>,
    puncher: Arc<ServerPuncher>,
    config: RealmConfig,
    family: AddrFamily,
    mapper: Option<Arc<PortMapper>>,
    _cancel_tx: Option<tokio::sync::oneshot::Sender<()>>,

    cached_addrs: CachedAddresses,
    current_session_id: Arc<Mutex<Option<String>>>,
}

impl RealmServerRuntime {
    pub async fn start(
        addr: RealmAddr,
        punch_socket: Arc<PunchUdpSocket>,
        puncher: Arc<ServerPuncher>,
        config: RealmConfig,
        mapper: Option<Arc<PortMapper>>,
    ) -> Result<Arc<Self>> {
        let client = RendezvousClient::from_addr(&addr, config.insecure)?;
        let family = config.ip_mode_family();
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();

        let cached_addrs = Arc::new(Mutex::new(None));
        let current_session_id = Arc::new(Mutex::new(None));

        let stun_servers = config.effective_stun_servers(&addr.stun_servers);
        let stun_timeout = config.stun_timeout_duration();

        debug!(
            "Realm [{}] server STUN discovery started on servers: {:?}",
            addr.realm_id, stun_servers
        );

        let initial_addrs = discover_with_demux(&punch_socket, &stun_servers, stun_timeout, family)
            .await
            .context("initial realm STUN discovery failed")?;

        let mut all_addrs = initial_addrs;
        if let Some(ref m) = mapper {
            if let Some(ext) = m.external_addr() {
                if !all_addrs.contains(&ext) {
                    all_addrs.push(ext);
                }
            }
        }
        all_addrs.sort_by_key(|a| a.to_string());

        debug!(
            "Realm [{}] server STUN discovery completed with addresses: {:?}",
            addr.realm_id, all_addrs
        );

        let addr_strings: Vec<String> = all_addrs.iter().map(|a| a.to_string()).collect();
        info!("Registering realm [{}] with rendezvous...", addr.realm_id);
        let reg_resp = client
            .register(&addr.realm_id, &addr_strings)
            .await
            .context("realm registration failed")?;

        info!(
            "Realm [{}] registered successfully! session_id={}, ttl={}s",
            addr.realm_id, reg_resp.session_id, reg_resp.ttl
        );

        *cached_addrs.lock().unwrap() = Some((all_addrs, Instant::now()));
        *current_session_id.lock().unwrap() = Some(reg_resp.session_id.clone());

        let runtime = Arc::new(Self {
            addr: addr.clone(),
            client: client.clone(),
            punch_socket: Arc::clone(&punch_socket),
            puncher: Arc::clone(&puncher),
            config: config.clone(),
            family,
            mapper,
            _cancel_tx: Some(cancel_tx),
            cached_addrs: Arc::clone(&cached_addrs),
            current_session_id: Arc::clone(&current_session_id),
        });

        // Spawn background session loop
        let runtime_weak = Arc::downgrade(&runtime);
        tokio::spawn(async move {
            let mut session_id = reg_resp.session_id;
            let mut ttl = reg_resp.ttl;

            loop {
                let Some(rt) = runtime_weak.upgrade() else {
                    break;
                };

                let session_res = tokio::select! {
                    _ = &mut cancel_rx => {
                        debug!("Realm [{}] runtime loop cancelled", rt.addr.realm_id);
                        break;
                    }
                    res = rt.run_session(&session_id, ttl) => res,
                };

                if let Err(e) = session_res {
                    warn!(
                        "Realm [{}] session lost: {:#}. Re-registering...",
                        rt.addr.realm_id, e
                    );
                }

                // Re-register with backoff
                match rt.register_with_backoff().await {
                    Some((new_sess, new_ttl)) => {
                        session_id = new_sess.clone();
                        ttl = new_ttl;
                        *rt.current_session_id.lock().unwrap() = Some(new_sess);
                    }
                    None => {
                        error!(
                            "Realm [{}] registration permanently failed; stopping runtime loop",
                            rt.addr.realm_id
                        );
                        break;
                    }
                }
            }
        });

        Ok(runtime)
    }

    async fn run_session(&self, session_id: &str, ttl: u64) -> Result<()> {
        let (err_tx, mut err_rx) = mpsc::channel::<anyhow::Error>(2);

        let hb_err_tx = err_tx.clone();
        let hb_sess = session_id.to_string();
        let hb_client = self.client.clone();
        let hb_realm_id = self.addr.realm_id.clone();
        let hb_interval = self
            .config
            .heartbeat_interval_duration(Duration::from_secs(ttl / 2).max(Duration::from_secs(5)));
        let cached_addrs = Arc::clone(&self.cached_addrs);

        let hb_handle = tokio::spawn(async move {
            let mut last_published: Vec<SocketAddr> = cached_addrs
                .lock()
                .unwrap()
                .as_ref()
                .map(|(a, _)| a.clone())
                .unwrap_or_default();

            loop {
                sleep(hb_interval).await;
                let current_addrs: Vec<SocketAddr> = cached_addrs
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|(a, _)| a.clone())
                    .unwrap_or_default();

                let addrs_arg = if current_addrs != last_published {
                    let s: Vec<String> = current_addrs.iter().map(|a| a.to_string()).collect();
                    last_published = current_addrs;
                    Some(s)
                } else {
                    None
                };

                let addr_slice_ref = addrs_arg.as_deref();
                match hb_client
                    .heartbeat(&hb_realm_id, &hb_sess, addr_slice_ref)
                    .await
                {
                    Ok(resp) => {
                        debug!(
                            "Realm [{}] heartbeat successful (ttl={})",
                            hb_realm_id, resp.ttl
                        );
                    }
                    Err(e) => {
                        let _ = hb_err_tx.send(e).await;
                        break;
                    }
                }
            }
        });

        let ev_sess = session_id.to_string();
        let ev_err_tx = err_tx;
        let rt_self = self.clone_for_events();

        let ev_handle = tokio::spawn(async move {
            let mut stream = match rt_self
                .client
                .events(&rt_self.addr.realm_id, &ev_sess)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    let _ = ev_err_tx.send(e).await;
                    return;
                }
            };

            info!("Realm [{}] events stream connected!", rt_self.addr.realm_id);

            loop {
                match stream.next().await {
                    Ok(Some(ev)) => {
                        debug!(
                            "Realm [{}] received punch event (nonce: {}, peer addrs: {:?})",
                            rt_self.addr.realm_id, ev.nonce, ev.addresses
                        );
                        let ev_clone = ev;
                        let rt_clone = rt_self.clone_for_events();
                        let sess_clone = ev_sess.clone();

                        tokio::spawn(async move {
                            rt_clone.handle_punch_event(&sess_clone, ev_clone).await;
                        });
                    }
                    Ok(None) => {
                        let _ = ev_err_tx.send(anyhow::anyhow!("events stream EOF")).await;
                        break;
                    }
                    Err(e) => {
                        let _ = ev_err_tx.send(e).await;
                        break;
                    }
                }
            }
        });

        let err = err_rx
            .recv()
            .await
            .unwrap_or_else(|| anyhow::anyhow!("session ended"));
        hb_handle.abort();
        ev_handle.abort();
        Err(err)
    }

    async fn handle_punch_event(&self, session_id: &str, ev: super::client::PunchEvent) {
        let meta = ev.punch_metadata();
        let mut peer_addrs = Vec::new();
        for s in &ev.addresses {
            if let Ok(addr) = s.parse::<SocketAddr>() {
                peer_addrs.push(addr);
            }
        }
        if peer_addrs.is_empty() {
            warn!(
                "Realm [{}] punch event had no valid peer addresses",
                self.addr.realm_id
            );
            return;
        }

        let fresh_addrs = self.get_fresh_or_cached_addrs().await;
        let addr_strings: Vec<String> = fresh_addrs.iter().map(|a| a.to_string()).collect();

        // Send connect-response to rendezvous
        let _ = self
            .client
            .connect_response(&self.addr.realm_id, session_id, &ev.nonce, &addr_strings)
            .await;

        let punch_cfg = PunchConfig {
            timeout: self.config.punch_timeout_duration(),
            interval: Duration::from_millis(100),
            family: self.family,
        };

        info!(
            "Realm [{}] responding to client punch (nonce: {}, client candidates: {})...",
            self.addr.realm_id,
            ev.nonce,
            peer_addrs.len()
        );

        match self
            .puncher
            .respond(&ev.nonce, &fresh_addrs, &peer_addrs, &meta, &punch_cfg)
            .await
        {
            Ok(res) => {
                info!(
                    "Realm [{}] punch succeeded with peer {} (packet: {:?})!",
                    self.addr.realm_id, res.peer_addr, res.packet.packet_type
                );
            }
            Err(e) => {
                warn!(
                    "Realm [{}] punch attempt failed: {:#}",
                    self.addr.realm_id, e
                );
            }
        }
    }

    async fn get_fresh_or_cached_addrs(&self) -> Vec<SocketAddr> {
        let now = Instant::now();
        {
            let guard = self.cached_addrs.lock().unwrap();
            if let Some((ref addrs, timestamp)) = *guard {
                if now.duration_since(timestamp) < REALM_CONNECT_STUN_CACHE_TTL {
                    return addrs.clone();
                }
            }
        }

        let stun_servers = self.config.effective_stun_servers(&self.addr.stun_servers);
        let stun_timeout = Duration::from_secs(2);

        if let Ok(fresh) =
            discover_with_demux(&self.punch_socket, &stun_servers, stun_timeout, self.family).await
        {
            let mut all = fresh;
            if let Some(ref m) = self.mapper {
                if let Some(ext) = m.external_addr() {
                    if !all.contains(&ext) {
                        all.push(ext);
                    }
                }
            }
            all.sort_by_key(|a| a.to_string());
            *self.cached_addrs.lock().unwrap() = Some((all.clone(), Instant::now()));
            all
        } else {
            // Fall back to last known
            self.cached_addrs
                .lock()
                .unwrap()
                .as_ref()
                .map(|(a, _)| a.clone())
                .unwrap_or_default()
        }
    }

    async fn register_with_backoff(&self) -> Option<(String, u64)> {
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(30);

        loop {
            let addrs = self.get_fresh_or_cached_addrs().await;
            let addr_strings: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();

            match self
                .client
                .register(&self.addr.realm_id, &addr_strings)
                .await
            {
                Ok(resp) => {
                    info!(
                        "Realm [{}] re-registered successfully! session_id={}, ttl={}",
                        self.addr.realm_id, resp.session_id, resp.ttl
                    );
                    return Some((resp.session_id, resp.ttl));
                }
                Err(e) => {
                    if is_realm_register_fatal(&e) {
                        error!(
                            "Realm [{}] registration fatal error: {:#}. Giving up.",
                            self.addr.realm_id, e
                        );
                        return None;
                    }
                    warn!(
                        "Realm [{}] re-registration failed: {:#}. Retrying in {}s...",
                        self.addr.realm_id,
                        e,
                        backoff.as_secs()
                    );
                    sleep(backoff).await;
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
    }

    fn clone_for_events(&self) -> Self {
        Self {
            addr: self.addr.clone(),
            client: self.client.clone(),
            punch_socket: Arc::clone(&self.punch_socket),
            puncher: Arc::clone(&self.puncher),
            config: self.config.clone(),
            family: self.family,
            mapper: self.mapper.clone(),
            _cancel_tx: None,
            cached_addrs: Arc::clone(&self.cached_addrs),
            current_session_id: Arc::clone(&self.current_session_id),
        }
    }
}

impl Drop for RealmServerRuntime {
    fn drop(&mut self) {
        if let Some(session_id) = self.current_session_id.lock().unwrap().take() {
            let client = self.client.clone();
            let realm_id = self.addr.realm_id.clone();
            tokio::spawn(async move {
                debug!("Deregistering realm [{}]...", realm_id);
                let _ = client.deregister(&realm_id, &session_id).await;
                info!("Realm [{}] deregistered", realm_id);
            });
        }
        if let Some(ref m) = self.mapper {
            m.close();
        }
    }
}
