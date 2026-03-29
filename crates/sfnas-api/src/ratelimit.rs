#![deny(unsafe_code)]

//! Per-IP rate limiting for the NAS API.
//!
//! Simple token-bucket style limiter: each IP gets `max_requests` within a
//! sliding `window`. Expired entries are pruned on every check.

use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
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
    max_requests: u64,
    window: Duration,
    buckets: HashMap<IpAddr, (u64, Instant)>,
}

impl RateLimiter {
    /// Create a new rate limiter allowing `max_requests` per `window`.
    pub fn new(max_requests: u64, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RateLimiterInner {
                max_requests,
                window,
                buckets: HashMap::new(),
            })),
        }
    }

    /// Check whether the given IP is allowed. Returns `Ok(())` if allowed,
    /// or `Err(retry_after_secs)` if rate-limited.
    async fn check(&self, ip: IpAddr) -> Result<(), u64> {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();
        let max_requests = inner.max_requests;
        let window = inner.window;

        // Prune expired entries
        inner
            .buckets
            .retain(|_, (_, start)| now.duration_since(*start) < window);

        let entry = inner.buckets.entry(ip).or_insert((0, now));

        // Reset window if expired for this IP
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
/// Use with `axum::middleware::from_fn_with_state` and a `RateLimiter` state.
/// Different route tiers can use different limiters (e.g. 10/min for auth, 120/min for general).
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
                "success": false,
                "error": "too many requests",
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
