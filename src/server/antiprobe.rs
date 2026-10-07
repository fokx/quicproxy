use dashmap::DashMap;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiProbeConfig {
    #[serde(default = "default_auth_jitter_min_ms")]
    pub auth_jitter_min_ms: u64,

    #[serde(default = "default_auth_jitter_max_ms")]
    pub auth_jitter_max_ms: u64,

    #[serde(default = "default_rate_limit_max_failures")]
    pub rate_limit_max_failures: u32,

    #[serde(default = "default_rate_limit_window_secs")]
    pub rate_limit_window_secs: u64,
}

fn default_auth_jitter_min_ms() -> u64 {
    10
}

fn default_auth_jitter_max_ms() -> u64 {
    50
}

fn default_rate_limit_max_failures() -> u32 {
    5
}

fn default_rate_limit_window_secs() -> u64 {
    60
}

impl Default for AntiProbeConfig {
    fn default() -> Self {
        Self {
            auth_jitter_min_ms: default_auth_jitter_min_ms(),
            auth_jitter_max_ms: default_auth_jitter_max_ms(),
            rate_limit_max_failures: default_rate_limit_max_failures(),
            rate_limit_window_secs: default_rate_limit_window_secs(),
        }
    }
}

/// In-memory sliding-window IP rate limiter for failed authentication attempts.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    failures: Arc<DashMap<IpAddr, (u32, Instant)>>,
    max_failures: u32,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_failures: u32, window_secs: u64) -> Self {
        Self {
            failures: Arc::new(DashMap::new()),
            max_failures,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Check if the given IP address is currently allowed to attempt authentication.
    /// Returns `true` if allowed, `false` if rate-limited.
    pub fn check_allowed(&self, ip: &IpAddr) -> bool {
        if self.max_failures == 0 {
            return true;
        }

        if let Some(entry) = self.failures.get(ip) {
            let (count, start_time) = *entry;
            if start_time.elapsed() < self.window {
                if count >= self.max_failures {
                    return false;
                }
            }
        }
        true
    }

    /// Record a failed authentication attempt from the specified IP.
    pub fn record_failure(&self, ip: IpAddr) {
        if self.max_failures == 0 {
            return;
        }

        let now = Instant::now();
        let mut entry = self.failures.entry(ip).or_insert((0, now));
        let (ref mut count, ref mut start_time) = *entry;

        if start_time.elapsed() >= self.window {
            // Reset sliding window
            *count = 1;
            *start_time = now;
        } else {
            *count = count.saturating_add(1);
        }
    }

    /// Reset failure count on a successful authentication.
    pub fn record_success(&self, ip: &IpAddr) {
        self.failures.remove(ip);
    }

    /// Prune expired entries from memory.
    pub fn cleanup(&self) {
        self.failures
            .retain(|_, (_, start_time)| start_time.elapsed() < self.window);
    }
}

/// Injects a randomized delay to thwart timing attacks and network fingerprinting.
pub async fn apply_auth_jitter(min_ms: u64, max_ms: u64) {
    if max_ms == 0 || max_ms < min_ms {
        return;
    }
    let delay_ms = if min_ms == max_ms {
        min_ms
    } else {
        rand::rng().random_range(min_ms..=max_ms)
    };
    sleep(Duration::from_millis(delay_ms)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_threshold() {
        let limiter = RateLimiter::new(3, 10);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();

        assert!(limiter.check_allowed(&ip));
        limiter.record_failure(ip);
        assert!(limiter.check_allowed(&ip));
        limiter.record_failure(ip);
        assert!(limiter.check_allowed(&ip));
        limiter.record_failure(ip);
        // Exceeded 3 failures
        assert!(!limiter.check_allowed(&ip));

        // Different IP should still be allowed
        let ip2: IpAddr = "192.0.2.2".parse().unwrap();
        assert!(limiter.check_allowed(&ip2));

        // Successful auth resets the failure counter
        limiter.record_success(&ip);
        assert!(limiter.check_allowed(&ip));
    }

    #[tokio::test]
    async fn test_auth_jitter() {
        let start = Instant::now();
        apply_auth_jitter(15, 30).await;
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(14));
    }
}
