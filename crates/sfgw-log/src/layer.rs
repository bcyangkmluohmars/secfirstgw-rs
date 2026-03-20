// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(unsafe_code)] // None used -- but module-level deny is from parent

//! Tracing [`Layer`] that writes all log events to the forward-secret
//! encrypted log store.
//!
//! Each tracing event is serialized and encrypted with the current day's
//! AES-256-GCM key before being stored.  The layer also handles automatic
//! midnight key rotation.

use crate::LogHandle;
use std::fmt;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// A tracing layer that encrypts log events and writes them to the database
/// via the [`LogManager`](crate::LogManager).
pub struct EncryptedLogLayer {
    handle: LogHandle,
}

impl EncryptedLogLayer {
    /// Create a new encrypted log layer backed by the given `LogHandle`.
    #[must_use]
    pub fn new(handle: LogHandle) -> Self {
        Self { handle }
    }
}

impl<S: Subscriber> Layer<S> for EncryptedLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let level = meta.level().to_string();
        let target = meta.target().to_string();

        // Extract the message and fields from the event.
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let message = if visitor.fields.is_empty() {
            visitor.message
        } else {
            format!("{} {}", visitor.message, visitor.fields.join(" "))
        };

        // Skip empty messages.
        if message.is_empty() {
            return;
        }

        // Write to the encrypted log store.  We spawn a blocking task because
        // the tracing layer callback is synchronous.
        let handle = self.handle.clone();
        let level_clone = level.clone();
        let target_clone = target.clone();
        let message_clone = message.clone();

        // Use tokio::spawn to write asynchronously.  If the runtime is not
        // available (e.g. during shutdown), silently drop the log entry.
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let mgr = handle.lock().await;

                // Try to rotate if date changed.
                // We cannot call rotate_key because that needs &mut, and we have
                // a shared lock.  Rotation is handled by the background task.

                if let Err(e) = mgr
                    .write_log(&level_clone, &target_clone, &message_clone)
                    .await
                {
                    // Cannot use tracing here (infinite recursion), write to stderr directly.
                    let _ = std::io::Write::write_fmt(
                        &mut std::io::stderr(),
                        format_args!("sfgw-log: encrypted write failed: {e}\n"),
                    );
                }
            });
        }
    }
}

/// Visitor that extracts the message field and any additional fields.
#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: Vec<String>,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
            // Remove surrounding quotes if present (tracing wraps strings).
            if self.message.starts_with('"') && self.message.ends_with('"') {
                self.message = self.message[1..self.message.len() - 1].to_string();
            }
        } else {
            self.fields.push(format!("{}={:?}", field.name(), value));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields.push(format!("{}={}", field.name(), value));
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields.push(format!("{}={}", field.name(), value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields.push(format!("{}={}", field.name(), value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields.push(format!("{}={}", field.name(), value));
    }
}
