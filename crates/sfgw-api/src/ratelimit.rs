// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-IP rate limiting middleware.
//!
//! Provides a configurable rate limiter that tracks request counts per client
//! IP address within sliding time windows. Expired entries are pruned on each
//! check to prevent unbounded growth.

use axum::{
    extract::ConnectInfo,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Per-IP rate limiter state.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<RateLimiterInner>>,
}

struct RateLimiterInner {
    /// Maximum number of requests allowed within `window`.
    max_requests: u64,
    /// Time window for the rate limit.
    window: Duration,
    /// Per-IP counters: maps IP to (count, window_start).
    buckets: HashMap<IpAddr, (u64, Instant)>,
}

impl RateLimiter {
    /// Create a new rate limiter allowing `max_requests` per `window` duration.
    pub fn new(max_requests: u64, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RateLimiterInner {
                max_requests,
                window,
                buckets: HashMap::new(),
            })),
        }
    }

    /// Check whether the given IP is allowed to make a request.
    ///
    /// Returns `Ok(())` if allowed, or `Err(retry_after_secs)` if rate limited.
    async fn check(&self, ip: IpAddr) -> Result<(), u64> {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();
        let max_requests = inner.max_requests;
        let window = inner.window;

        // Prune expired entries (at most every check, keeps map bounded)
        inner
            .buckets
            .retain(|_, (_, start)| now.duration_since(*start) < window);

        let entry = inner.buckets.entry(ip).or_insert((0, now));

        // If the window has expired for this IP, reset
        if now.duration_since(entry.1) >= window {
            entry.0 = 0;
            entry.1 = now;
        }

        entry.0 += 1;

        if entry.0 > max_requests {
            let elapsed = now.duration_since(entry.1);
            let retry_after = window.saturating_sub(elapsed).as_secs().max(1);
            Err(retry_after)
        } else {
            Ok(())
        }
    }
}

/// Axum middleware function for rate limiting.
///
/// Use with `axum::middleware::from_fn_with_state`.
pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::State(limiter): axum::extract::State<RateLimiter>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    match limiter.check(addr.ip()).await {
        Ok(()) => next.run(request).await,
        Err(retry_after) => {
            let body = axum::Json(json!({
                "error": "rate limit exceeded",
                "retry_after_secs": retry_after,
            }));
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, retry_after.to_string())],
                body,
            )
                .into_response()
        }
    }
}
