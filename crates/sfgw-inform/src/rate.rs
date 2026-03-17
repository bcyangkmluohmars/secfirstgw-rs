// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rate limiting for Ubiquiti Inform endpoint.
//!
//! Two-tier rate limiting per source IP:
//! - **Soft limit** (>10 informs/min): drop silently, warn in log
//! - **Hard limit** (>50 informs/min OR >5 distinct MACs from one IP): IDS event,
//!   temporary firewall block, admin alert

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Soft limit: maximum informs per minute per source IP.
const SOFT_LIMIT: usize = 10;

/// Hard limit: maximum informs per minute per source IP.
const HARD_LIMIT: usize = 50;

/// Hard limit: maximum distinct MACs per minute from one source IP.
const MAX_MACS_PER_IP: usize = 5;

/// Window duration for rate counting.
const WINDOW: Duration = Duration::from_secs(60);

/// Result of a rate limit check.
pub enum RateResult {
    /// Within limits, proceed.
    Ok,
    /// Soft limit exceeded — drop but no IDS event.
    SoftLimit,
    /// Hard limit exceeded — IDS event + block.
    HardLimit { distinct_macs: usize },
}

/// Per-IP tracking state.
struct IpState {
    /// Timestamps of recent inform requests.
    hits: Vec<Instant>,
    /// Distinct MACs seen from this IP within the window.
    macs: HashSet<String>,
    /// Start of the current window.
    window_start: Instant,
}

impl IpState {
    fn new() -> Self {
        Self {
            hits: Vec::new(),
            macs: HashSet::new(),
            window_start: Instant::now(),
        }
    }

    /// Prune entries older than the rate window.
    fn prune(&mut self) {
        let cutoff = Instant::now() - WINDOW;
        if self.window_start < cutoff {
            self.hits.clear();
            self.macs.clear();
            self.window_start = Instant::now();
        } else {
            self.hits.retain(|t| *t >= cutoff);
        }
    }
}

/// Thread-safe rate limiter for Inform requests.
pub struct RateLimiter {
    state: Mutex<HashMap<String, IpState>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Check whether a request from `source_ip` should be allowed.
    pub fn check(&self, source_ip: &str) -> RateResult {
        let mut state = self.state.lock().expect("rate limiter lock poisoned");
        let entry = state
            .entry(source_ip.to_string())
            .or_insert_with(IpState::new);

        entry.prune();
        entry.hits.push(Instant::now());

        let count = entry.hits.len();
        let mac_count = entry.macs.len();

        if count > HARD_LIMIT || mac_count > MAX_MACS_PER_IP {
            RateResult::HardLimit {
                distinct_macs: mac_count,
            }
        } else if count > SOFT_LIMIT {
            RateResult::SoftLimit
        } else {
            RateResult::Ok
        }
    }

    /// Record a MAC address seen from a source IP (for multi-MAC detection).
    pub fn record_mac(&self, source_ip: &str, mac: &str) {
        let mut state = self.state.lock().expect("rate limiter lock poisoned");
        if let Some(entry) = state.get_mut(source_ip) {
            entry.macs.insert(mac.to_string());
        }
    }

    /// Periodic cleanup of expired entries (call from a background task).
    pub fn cleanup(&self) {
        let mut state = self.state.lock().expect("rate limiter lock poisoned");
        let cutoff = Instant::now() - WINDOW * 2;
        state.retain(|_, v| v.window_start >= cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_limit() {
        let limiter = RateLimiter::new();
        for _ in 0..SOFT_LIMIT {
            assert!(matches!(limiter.check("10.0.0.1"), RateResult::Ok));
        }
    }

    #[test]
    fn soft_limit_triggers() {
        let limiter = RateLimiter::new();
        for _ in 0..=SOFT_LIMIT {
            limiter.check("10.0.0.1");
        }
        assert!(matches!(limiter.check("10.0.0.1"), RateResult::SoftLimit));
    }

    #[test]
    fn multi_mac_hard_limit() {
        let limiter = RateLimiter::new();
        // Simulate 6 distinct MACs from one IP
        for i in 0..=MAX_MACS_PER_IP {
            limiter.check("10.0.0.1");
            limiter.record_mac("10.0.0.1", &format!("aa:bb:cc:dd:ee:{i:02x}"));
        }
        assert!(matches!(
            limiter.check("10.0.0.1"),
            RateResult::HardLimit { .. }
        ));
    }

    #[test]
    fn different_ips_independent() {
        let limiter = RateLimiter::new();
        for _ in 0..SOFT_LIMIT {
            limiter.check("10.0.0.1");
        }
        // Different IP should still be OK
        assert!(matches!(limiter.check("10.0.0.2"), RateResult::Ok));
    }
}
