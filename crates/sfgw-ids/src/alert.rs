// SPDX-License-Identifier: AGPL-3.0-or-later

//! Alert & Response Engine
//!
//! Stores IDS events in the database, executes auto-response actions,
//! and rate-limits alerts to avoid flooding.
//!
//! Channels:
//! - Database (ids_events table) — always
//! - Telegram bot (primary, if configured)
//! - Webhook (generic, for SIEM integration)
//! - Local tracing log — always

use std::collections::HashMap;

use anyhow::{Context, Result};
use chrono::Utc;

use super::{IdsEvent, ResponseAction, Severity};

/// Minimum seconds between alerts for the same (detector, source_mac/ip) pair.
const ALERT_RATE_LIMIT_SECS: i64 = 30;

/// Key for deduplicating/rate-limiting alerts.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct AlertKey {
    detector: String,
    source: String, // MAC or IP
}

pub struct AlertEngine {
    /// Database handle for persisting events.
    db: sfgw_db::Db,
    /// Configured response actions per severity level.
    severity_actions: HashMap<SeverityLevel, Vec<AutoAction>>,
    /// Rate limiting: last alert time per (detector, source) key.
    last_alert: HashMap<AlertKey, chrono::DateTime<Utc>>,
    /// Telegram config (optional).
    telegram_token: Option<String>,
    telegram_chat_id: Option<String>,
    /// Webhook URLs (optional).
    webhook_urls: Vec<String>,
}

/// Severity level for action mapping (mirrors Severity but usable as HashMap key).
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum SeverityLevel {
    Info,
    Warning,
    Critical,
}

impl From<&Severity> for SeverityLevel {
    fn from(s: &Severity) -> Self {
        match s {
            Severity::Info => SeverityLevel::Info,
            Severity::Warning => SeverityLevel::Warning,
            Severity::Critical => SeverityLevel::Critical,
        }
    }
}

/// Automatic response actions the engine can execute.
#[derive(Debug, Clone)]
pub enum AutoAction {
    Log,
    IsolatePort,
    BlockMac,
    RateLimit,
}

impl AlertEngine {
    pub fn new(db: sfgw_db::Db) -> Self {
        // Default actions per severity
        let mut severity_actions = HashMap::new();
        severity_actions.insert(SeverityLevel::Info, vec![AutoAction::Log]);
        severity_actions.insert(
            SeverityLevel::Warning,
            vec![AutoAction::Log, AutoAction::RateLimit],
        );
        severity_actions.insert(
            SeverityLevel::Critical,
            vec![AutoAction::Log, AutoAction::BlockMac, AutoAction::IsolatePort],
        );

        Self {
            db,
            severity_actions,
            last_alert: HashMap::new(),
            telegram_token: None,
            telegram_chat_id: None,
            webhook_urls: Vec::new(),
        }
    }

    /// Configure Telegram notifications.
    pub fn set_telegram(&mut self, token: String, chat_id: String) {
        self.telegram_token = Some(token);
        self.telegram_chat_id = Some(chat_id);
    }

    /// Add a webhook URL for SIEM integration.
    pub fn add_webhook(&mut self, url: String) {
        self.webhook_urls.push(url);
    }

    /// Process an IDS event: store in DB, rate-limit, execute responses.
    /// Returns the response actions taken.
    pub async fn process_event(&mut self, event: &IdsEvent) -> Result<Vec<ResponseAction>> {
        // --- Rate limiting ---
        let key = AlertKey {
            detector: event.detector.to_string(),
            source: event
                .source_mac
                .clone()
                .or_else(|| event.source_ip.clone())
                .unwrap_or_default(),
        };

        let now = Utc::now();
        if let Some(last) = self.last_alert.get(&key) {
            if (now - *last).num_seconds() < ALERT_RATE_LIMIT_SECS {
                // Rate limited — still store in DB but don't dispatch alerts/actions
                self.store_event(event).await?;
                return Ok(vec![ResponseAction::LogOnly]);
            }
        }
        self.last_alert.insert(key, now);

        // Prune old rate-limit entries (older than 5 minutes)
        self.last_alert
            .retain(|_, ts| (now - *ts).num_seconds() < 300);

        // --- Store in database ---
        self.store_event(event).await?;

        // --- Log via tracing ---
        match event.severity {
            Severity::Info => tracing::info!(
                detector = event.detector,
                "IDS: {}",
                event.description
            ),
            Severity::Warning => tracing::warn!(
                detector = event.detector,
                "IDS: {}",
                event.description
            ),
            Severity::Critical => tracing::error!(
                detector = event.detector,
                "IDS: {}",
                event.description
            ),
        }

        // --- Determine and execute response actions ---
        let level = SeverityLevel::from(&event.severity);
        let actions = self
            .severity_actions
            .get(&level)
            .cloned()
            .unwrap_or_else(|| vec![AutoAction::Log]);

        let mut responses = Vec::new();
        for action in &actions {
            match action {
                AutoAction::Log => {
                    responses.push(ResponseAction::LogOnly);
                }
                AutoAction::BlockMac => {
                    if let Some(ref mac) = event.source_mac {
                        let response = ResponseAction::BlockMac {
                            mac: mac.clone(),
                            duration_secs: 300, // 5 minutes
                        };
                        self.execute_response(&response).await?;
                        responses.push(response);
                    }
                }
                AutoAction::IsolatePort => {
                    if let Some(ref mac) = event.source_mac {
                        let response = ResponseAction::IsolatePort {
                            interface: event.interface.clone(),
                            mac: mac.clone(),
                        };
                        self.execute_response(&response).await?;
                        responses.push(response);
                    }
                }
                AutoAction::RateLimit => {
                    if let Some(ref ip) = event.source_ip {
                        let response = ResponseAction::RateLimit {
                            ip: ip.clone(),
                            pps: 100,
                        };
                        self.execute_response(&response).await?;
                        responses.push(response);
                    }
                }
            }
        }

        Ok(responses)
    }

    /// Store an IDS event in the database.
    async fn store_event(&self, event: &IdsEvent) -> Result<()> {
        let conn = self.db.lock().await;
        conn.execute(
            "INSERT INTO ids_events (timestamp, severity, detector, source_mac, source_ip, interface, vlan, description)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                event.timestamp.to_rfc3339(),
                format!("{:?}", event.severity),
                event.detector,
                event.source_mac,
                event.source_ip,
                event.interface,
                event.vlan,
                event.description,
            ],
        )
        .context("failed to insert IDS event into database")?;
        Ok(())
    }

    /// Execute an automatic response action.
    async fn execute_response(&self, action: &ResponseAction) -> Result<()> {
        match action {
            ResponseAction::LogOnly => {
                // Already logged above
            }
            ResponseAction::Alert(event) => {
                tracing::warn!("IDS alert: {}", event.description);
            }
            ResponseAction::IsolatePort { interface, mac } => {
                tracing::warn!("IDS: isolating port {} for MAC {}", interface, mac);
                // Use nftables to drop traffic from this MAC on this interface
                let rule = format!(
                    "nft add rule inet filter forward iifname \"{}\" ether saddr {} drop",
                    interface, mac
                );
                match tokio::process::Command::new("sh")
                    .arg("-c")
                    .arg(&rule)
                    .output()
                    .await
                {
                    Ok(output) => {
                        if !output.status.success() {
                            tracing::error!(
                                "nftables isolate failed: {}",
                                String::from_utf8_lossy(&output.stderr)
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!("failed to execute nftables isolate: {e}");
                    }
                }
            }
            ResponseAction::BlockMac { mac, duration_secs } => {
                tracing::warn!("IDS: blocking MAC {} for {}s", mac, duration_secs);
                // Use nftables set with timeout for automatic expiry.
                // Requires a pre-configured set:
                //   nft add set inet sfgw blocked_macs { type ether_addr; flags timeout; }
                // and an input chain rule:
                //   nft add rule inet sfgw input ether saddr @blocked_macs drop
                let cmd = format!(
                    "nft add element inet sfgw blocked_macs {{ {} timeout {}s }}",
                    mac, duration_secs
                );
                match tokio::process::Command::new("sh")
                    .arg("-c")
                    .arg(&cmd)
                    .output()
                    .await
                {
                    Ok(output) => {
                        if !output.status.success() {
                            tracing::error!(
                                "nftables block failed: {}",
                                String::from_utf8_lossy(&output.stderr)
                            );
                        } else {
                            tracing::info!(
                                "Blocked MAC {} via nftables set (auto-expires in {}s)",
                                mac,
                                duration_secs
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!("failed to execute nftables block: {e}");
                    }
                }
            }
            ResponseAction::RateLimit { ip, pps } => {
                tracing::warn!("IDS: rate limiting {} to {} pps", ip, pps);
                // Use nftables to rate limit traffic from this IP
                let rule = format!(
                    "nft add rule inet filter forward ip saddr {} limit rate over {}/second drop",
                    ip, pps
                );
                match tokio::process::Command::new("sh")
                    .arg("-c")
                    .arg(&rule)
                    .output()
                    .await
                {
                    Ok(output) => {
                        if !output.status.success() {
                            tracing::error!(
                                "nftables rate-limit failed: {}",
                                String::from_utf8_lossy(&output.stderr)
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!("failed to execute nftables rate-limit: {e}");
                    }
                }
            }
        }
        Ok(())
    }
}
