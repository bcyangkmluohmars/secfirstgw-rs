// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::type_complexity)]

//! Live event stream via Server-Sent Events (SSE).
//!
//! A custom tracing layer captures log events from all sfgw-* crates and
//! broadcasts them to connected SSE clients.  This gives the web UI a live
//! view of system activity without SSH access.
//!
//! A ring buffer keeps the last HISTORY_SIZE events so that newly connected
//! clients immediately see recent history (boot, WAN connect, etc.).

use axum::response::sse::{Event, Sse};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::sync::{Mutex, broadcast};
use tracing_subscriber::Layer;

/// Maximum events buffered per client before they start dropping.
const CHANNEL_CAPACITY: usize = 256;

/// Number of recent events kept in the ring buffer for new clients.
const HISTORY_SIZE: usize = 200;

/// A single log event sent to the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct LogEvent {
    /// ISO 8601 timestamp
    pub ts: String,
    /// Level: "ERROR", "WARN", "INFO", "DEBUG", "TRACE"
    pub level: String,
    /// Target module (e.g. "sfgw_net::wan")
    pub target: String,
    /// Human-readable message
    pub message: String,
    /// Structured fields as key=value pairs
    pub fields: Vec<String>,
}

/// Shared state: broadcast sender + ring buffer of recent events.
pub struct EventBus {
    tx: broadcast::Sender<LogEvent>,
    history: Mutex<VecDeque<LogEvent>>,
    /// Short-lived SSE tokens: token → (user_id, created_at).
    /// One-time use, 30-second TTL. Prevents real session tokens from
    /// appearing in URLs (EventSource API doesn't support custom headers).
    sse_tokens: Mutex<HashMap<String, (i64, Instant)>>,
}

/// Maximum age of an SSE token before it expires (30 seconds).
const SSE_TOKEN_TTL_SECS: u64 = 30;

/// Maximum number of pending SSE tokens (prevents memory exhaustion).
const SSE_TOKEN_MAX: usize = 1000;

/// Shared broadcast sender — cloned into the tracing layer and the SSE handler.
pub type EventTx = Arc<EventBus>;

/// Create the broadcast channel, ring buffer, and return (sender, tracing layer).
pub fn init() -> (EventTx, BroadcastLayer) {
    let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
    let bus = Arc::new(EventBus {
        tx,
        history: Mutex::new(VecDeque::with_capacity(HISTORY_SIZE)),
        sse_tokens: Mutex::new(HashMap::new()),
    });
    let layer = BroadcastLayer { bus: bus.clone() };
    (bus, layer)
}

/// Create a short-lived, one-time-use SSE token for the given user.
///
/// The token is valid for 30 seconds and can only be used once.
/// This prevents the real session token from appearing in SSE URLs.
pub async fn create_sse_token(bus: &EventTx, user_id: i64) -> String {
    let token = uuid::Uuid::new_v4().to_string();
    let mut store = bus.sse_tokens.lock().await;

    // Prune expired tokens.
    let now = Instant::now();
    store.retain(|_, (_, created)| {
        now.duration_since(*created) < std::time::Duration::from_secs(SSE_TOKEN_TTL_SECS)
    });

    // Enforce capacity limit.
    if store.len() >= SSE_TOKEN_MAX {
        tracing::warn!("SSE token store full, rejecting new token");
        return String::new();
    }

    store.insert(token.clone(), (user_id, now));
    token
}

/// Validate and consume a short-lived SSE token.
///
/// Returns the user ID if the token is valid and not expired.
/// The token is removed from the store on use (one-time only).
async fn validate_sse_token(bus: &EventTx, token: &str) -> Option<i64> {
    let mut store = bus.sse_tokens.lock().await;

    if let Some((user_id, created)) = store.remove(token) {
        let age = Instant::now().duration_since(created);
        if age < std::time::Duration::from_secs(SSE_TOKEN_TTL_SECS) {
            return Some(user_id);
        }
        // Expired — already removed, just return None.
    }

    None
}

// ── SSE handler ─────────────────────────────────────────────────────

/// Stream wrapper that first drains history, then receives live events.
struct EventStream {
    /// Buffered history events to send first (drained on connect).
    history: VecDeque<LogEvent>,
    /// Live broadcast receiver for new events.
    rx: broadcast::Receiver<LogEvent>,
}

impl futures_core::Stream for EventStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        // Phase 1: drain history buffer first
        if let Some(event) = self.history.pop_front()
            && let Ok(json) = serde_json::to_string(&event)
        {
            return Poll::Ready(Some(Ok(Event::default().data(json))));
        }

        // Phase 2: live events from broadcast channel
        match self.rx.try_recv() {
            Ok(event) => {
                if let Ok(json) = serde_json::to_string(&event) {
                    Poll::Ready(Some(Ok(Event::default().data(json))))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Err(broadcast::error::TryRecvError::Empty) => {
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    waker.wake();
                });
                Poll::Pending
            }
            Err(broadcast::error::TryRecvError::Lagged(n)) => {
                let msg = format!(
                    r#"{{"ts":"","level":"WARN","target":"sse","message":"skipped {} events (client too slow)","fields":[]}}"#,
                    n
                );
                Poll::Ready(Some(Ok(Event::default().data(msg))))
            }
            Err(broadcast::error::TryRecvError::Closed) => Poll::Ready(None),
        }
    }
}

/// Query parameters for the SSE stream endpoint.
#[derive(serde::Deserialize)]
pub struct SseQuery {
    /// Short-lived SSE token (from POST /api/v1/events/sse-token).
    pub token: Option<String>,
}

/// Axum handler: streams log events as SSE to the client.
/// Sends buffered history first, then switches to live streaming.
///
/// Accepts a short-lived SSE token via query parameter (`?token=...`).
/// The real session token should NOT be passed in the URL — use the
/// `/api/v1/events/sse-token` endpoint to obtain a short-lived token.
pub async fn event_stream_handler(
    axum::extract::Query(query): axum::extract::Query<SseQuery>,
    axum::Extension(bus): axum::Extension<EventTx>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // Validate SSE token.
    let token = match &query.token {
        Some(t) if !t.is_empty() => t.as_str(),
        _ => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({ "error": "SSE token required" })),
            )
                .into_response();
        }
    };

    if validate_sse_token(&bus, token).await.is_none() {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({ "error": "invalid or expired SSE token" })),
        )
            .into_response();
    }

    // Token valid — snapshot history and subscribe to live events.
    let history = bus.history.lock().await.clone();
    let rx = bus.tx.subscribe();

    Sse::new(EventStream { history, rx })
        .keep_alive(
            axum::response::sse::KeepAlive::new()
                .interval(std::time::Duration::from_secs(15))
                .text("ping"),
        )
        .into_response()
}

// ── Tracing layer ───────────────────────────────────────────────────

/// A tracing layer that broadcasts events to SSE clients and keeps history.
pub struct BroadcastLayer {
    bus: EventTx,
}

impl<S> Layer<S> for BroadcastLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let meta = event.metadata();

        // Only broadcast sfgw-* events (skip noisy third-party crates)
        let target = meta.target();
        if !target.starts_with("sfgw") {
            return;
        }

        let level = meta.level().as_str().to_uppercase();

        // Extract message and fields
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        let log_event = LogEvent {
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            level,
            target: target.to_string(),
            message: visitor.message,
            fields: visitor.fields,
        };

        // Store in ring buffer (best-effort — skip if lock is contended)
        if let Ok(mut history) = self.bus.history.try_lock() {
            if history.len() >= HISTORY_SIZE {
                history.pop_front();
            }
            history.push_back(log_event.clone());
        }

        // Broadcast to live clients (no-op if nobody is subscribed)
        let _ = self.bus.tx.send(log_event);
    }
}

/// Visitor that extracts the `message` field and collects other fields.
#[derive(Default)]
struct FieldVisitor {
    message: String,
    fields: Vec<String>,
}

impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
            if self.message.starts_with('"') && self.message.ends_with('"') {
                self.message = self.message[1..self.message.len() - 1].to_string();
            }
        } else {
            self.fields.push(format!("{}={:?}", field.name(), value));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields.push(format!("{}={}", field.name(), value));
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.push(format!("{}={}", field.name(), value));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.push(format!("{}={}", field.name(), value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields.push(format!("{}={}", field.name(), value));
    }
}
