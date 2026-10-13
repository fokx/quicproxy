use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::{Duration, interval};

/// Lightweight proxy metrics collected via atomic counters.
#[derive(Debug)]
pub struct Metrics {
    /// Currently open TCP proxy streams.
    pub active_tcp_streams: AtomicU64,
    /// Total TCP proxy streams ever opened.
    pub total_tcp_streams: AtomicU64,
    /// Currently active UDP associations.
    pub active_udp_sessions: AtomicU64,
    /// Total UDP associations ever created.
    pub total_udp_sessions: AtomicU64,
    /// Total bytes sent through proxy.
    pub bytes_sent: AtomicU64,
    /// Total bytes received through proxy.
    pub bytes_received: AtomicU64,
    /// Total UDP datagrams sent.
    pub datagrams_sent: AtomicU64,
    /// Total UDP datagrams received.
    pub datagrams_received: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            active_tcp_streams: AtomicU64::new(0),
            total_tcp_streams: AtomicU64::new(0),
            active_udp_sessions: AtomicU64::new(0),
            total_udp_sessions: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            datagrams_sent: AtomicU64::new(0),
            datagrams_received: AtomicU64::new(0),
        }
    }
}

impl Metrics {
    /// Create a new `Metrics` instance with all counters initialized to zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment active TCP streams and total TCP streams ever opened.
    pub fn inc_active_tcp_streams(&self) {
        self.active_tcp_streams.fetch_add(1, Ordering::Relaxed);
        self.total_tcp_streams.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active TCP streams.
    pub fn dec_active_tcp_streams(&self) {
        self.active_tcp_streams.fetch_sub(1, Ordering::Relaxed);
    }

    /// Increment active UDP sessions and total UDP sessions ever created.
    pub fn inc_active_udp_sessions(&self) {
        self.active_udp_sessions.fetch_add(1, Ordering::Relaxed);
        self.total_udp_sessions.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active UDP sessions.
    pub fn dec_active_udp_sessions(&self) {
        self.active_udp_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    /// Add `n` bytes to the total bytes sent counter.
    pub fn add_bytes_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    /// Add `n` bytes to the total bytes received counter.
    pub fn add_bytes_received(&self, n: u64) {
        self.bytes_received.fetch_add(n, Ordering::Relaxed);
    }

    /// Increment total UDP datagrams sent counter.
    pub fn inc_datagrams_sent(&self) {
        self.datagrams_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment total UDP datagrams received counter.
    pub fn inc_datagrams_received(&self) {
        self.datagrams_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns true if all metrics counters are zero (no activity recorded).
    pub fn is_empty(&self) -> bool {
        self.active_tcp_streams.load(Ordering::Relaxed) == 0
            && self.total_tcp_streams.load(Ordering::Relaxed) == 0
            && self.active_udp_sessions.load(Ordering::Relaxed) == 0
            && self.total_udp_sessions.load(Ordering::Relaxed) == 0
            && self.bytes_sent.load(Ordering::Relaxed) == 0
            && self.bytes_received.load(Ordering::Relaxed) == 0
            && self.datagrams_sent.load(Ordering::Relaxed) == 0
            && self.datagrams_received.load(Ordering::Relaxed) == 0
    }

    /// Log a summary of all metrics at the INFO level using `tracing::info!`.
    /// Does nothing if all metrics counters are zero.
    pub fn log_summary(&self) {
        if self.is_empty() {
            return;
        }

        let active_tcp = self.active_tcp_streams.load(Ordering::Relaxed);
        let total_tcp = self.total_tcp_streams.load(Ordering::Relaxed);
        let active_udp = self.active_udp_sessions.load(Ordering::Relaxed);
        let total_udp = self.total_udp_sessions.load(Ordering::Relaxed);
        let bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        let bytes_recv = self.bytes_received.load(Ordering::Relaxed);
        let dgrams_sent = self.datagrams_sent.load(Ordering::Relaxed);
        let dgrams_recv = self.datagrams_received.load(Ordering::Relaxed);

        tracing::info!(
            active_tcp_streams = active_tcp,
            total_tcp_streams = total_tcp,
            active_udp_sessions = active_udp,
            total_udp_sessions = total_udp,
            bytes_sent = bytes_sent,
            bytes_received = bytes_recv,
            datagrams_sent = dgrams_sent,
            datagrams_received = dgrams_recv,
            "Proxy metrics: TCP streams: {} active ({} total), UDP sessions: {} active ({} total), Bytes: {} sent / {} received, Datagrams: {} sent / {} received",
            active_tcp,
            total_tcp,
            active_udp,
            total_udp,
            bytes_sent,
            bytes_recv,
            dgrams_sent,
            dgrams_recv,
        );
    }

    /// Spawn a background tokio task that logs metric summaries every 30 seconds.
    pub fn start_periodic_logging(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(30));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                self.log_summary();
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_default_zeros() {
        let metrics = Metrics::default();
        assert_eq!(metrics.active_tcp_streams.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.total_tcp_streams.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.active_udp_sessions.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.total_udp_sessions.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.bytes_sent.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.bytes_received.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.datagrams_sent.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.datagrams_received.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_tcp_streams_metrics() {
        let metrics = Metrics::new();
        metrics.inc_active_tcp_streams();
        assert_eq!(metrics.active_tcp_streams.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.total_tcp_streams.load(Ordering::Relaxed), 1);

        metrics.inc_active_tcp_streams();
        assert_eq!(metrics.active_tcp_streams.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.total_tcp_streams.load(Ordering::Relaxed), 2);

        metrics.dec_active_tcp_streams();
        assert_eq!(metrics.active_tcp_streams.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.total_tcp_streams.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_udp_sessions_metrics() {
        let metrics = Metrics::new();
        metrics.inc_active_udp_sessions();
        assert_eq!(metrics.active_udp_sessions.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.total_udp_sessions.load(Ordering::Relaxed), 1);

        metrics.inc_active_udp_sessions();
        assert_eq!(metrics.active_udp_sessions.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.total_udp_sessions.load(Ordering::Relaxed), 2);

        metrics.dec_active_udp_sessions();
        assert_eq!(metrics.active_udp_sessions.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.total_udp_sessions.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_bytes_and_datagrams_metrics() {
        let metrics = Metrics::new();
        metrics.add_bytes_sent(1024);
        metrics.add_bytes_received(2048);
        assert_eq!(metrics.bytes_sent.load(Ordering::Relaxed), 1024);
        assert_eq!(metrics.bytes_received.load(Ordering::Relaxed), 2048);

        metrics.inc_datagrams_sent();
        metrics.inc_datagrams_sent();
        metrics.inc_datagrams_received();
        assert_eq!(metrics.datagrams_sent.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.datagrams_received.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_log_summary() {
        let metrics = Metrics::new();
        // Logging while empty returns immediately without logging
        assert!(metrics.is_empty());
        metrics.log_summary();

        metrics.inc_active_tcp_streams();
        metrics.add_bytes_sent(512);
        assert!(!metrics.is_empty());
        // Should execute with data without panicking
        metrics.log_summary();
    }

    #[test]
    fn test_metrics_is_empty() {
        let metrics = Metrics::new();
        assert!(metrics.is_empty());

        metrics.inc_active_tcp_streams();
        assert!(!metrics.is_empty());
        metrics.dec_active_tcp_streams();
        // Note: total_tcp_streams is now 1, so not empty
        assert!(!metrics.is_empty());
    }

    #[tokio::test]
    async fn test_periodic_logging_spawn() {
        let metrics = Arc::new(Metrics::new());
        let handle = metrics.start_periodic_logging();
        assert!(!handle.is_finished());
        handle.abort();
    }
}
