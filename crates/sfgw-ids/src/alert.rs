// SPDX-License-Identifier: AGPL-3.0-or-later

//! Alert dispatch — routes IDS events to notification channels
//!
//! Channels:
//! - Telegram bot (primary)
//! - Webhook (generic, for SIEM integration)
//! - Local log (always, via sfgw-log)
//! - API websocket (live dashboard)

use anyhow::Result;
use super::{IdsEvent, ResponseAction};

pub struct AlertDispatcher {
    telegram_token: Option<String>,
    telegram_chat_id: Option<String>,
    webhook_urls: Vec<String>,
}

impl AlertDispatcher {
    pub fn new() -> Self {
        todo!()
    }

    /// Dispatch an IDS event to all configured channels
    pub async fn dispatch(&self, event: &IdsEvent) -> Result<()> {
        todo!()
    }

    /// Execute an automatic response action
    pub async fn execute_response(&self, action: &ResponseAction) -> Result<()> {
        todo!()
    }
}
