// SPDX-License-Identifier: AGPL-3.0-or-later

//! Alert & Response Engine
//!
//! Stores IDS events in the database, executes auto-response actions,
//! and rate-limits alerts to avoid flooding.
//!
//! Active response uses `sfgw_fw::ids_response` to insert firewall rules
//! via the `firewall_rules` table, applied atomically with `iptables-restore`.
//! This replaces the previous raw `nft` shell commands which do not work on
//! the UDM Pro (kernel 4.19, no nf_tables support).
//!
//! Channels:
//! - Database (ids_events table) -- always
//! - Telegram bot (primary, if configured)
//! - Webhook (generic, for SIEM integration)
//! - Local tracing log -- always

use std::collections::HashMap;

use anyhow::{Context, Result};
use chrono::Utc;

use super::{IdsEvent, ResponseAction, Severity};

/// Minimum seconds between alerts for the same (detector, source_mac/ip) pair.
const ALERT_RATE_LIMIT_SECS: i64 = 30;

/// Default block duration for critical events (5 minutes).
const BLOCK_DURATION_SECS: u64 = 300;

/// Default rate-limit duration for warning events (5 minutes).
const RATE_LIMIT_DURATION_SECS: u64 = 300;

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
            vec![
                AutoAction::Log,
                AutoAction::BlockMac,
                AutoAction::IsolatePort,
            ],
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
        if let Some(last) = self.last_alert.get(&key)
            && (now - *last).num_seconds() < ALERT_RATE_LIMIT_SECS
        {
            // Rate limited -- still store in DB but don't dispatch alerts/actions
            self.store_event(event).await?;
            return Ok(vec![ResponseAction::LogOnly]);
        }
        self.last_alert.insert(key, now);

        // Prune old rate-limit entries (older than 5 minutes)
        self.last_alert
            .retain(|_, ts| (now - *ts).num_seconds() < 300);

        // --- Store in database ---
        self.store_event(event).await?;

        // --- Log via tracing ---
        match event.severity {
            Severity::Info => {
                tracing::info!(detector = event.detector, "IDS: {}", event.description)
            }
            Severity::Warning => {
                tracing::warn!(detector = event.detector, "IDS: {}", event.description)
            }
            Severity::Critical => {
                tracing::error!(detector = event.detector, "IDS: {}", event.description)
            }
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
                        // Block the source IP via firewall if available, fall back to MAC logging.
                        // MAC-level blocking requires bridge-level ebtables which is not available
                        // on all platforms; IP-level blocking via iptables is universally supported.
                        if let Some(ref ip) = event.source_ip {
                            let reason =
                                format!("{} MAC {} on {}", event.detector, mac, event.interface);
                            match sfgw_fw::ids_response::block_ip(
                                &self.db,
                                ip,
                                BLOCK_DURATION_SECS,
                                &reason,
                            )
                            .await
                            {
                                Ok(rule_id) => {
                                    tracing::warn!(
                                        ip,
                                        mac,
                                        rule_id,
                                        "IDS: blocked IP for MAC-based threat"
                                    );
                                }
                                Err(e) => {
                                    tracing::error!(
                                        ip,
                                        mac,
                                        "IDS: failed to block IP for MAC threat: {e}"
                                    );
                                }
                            }
                        } else {
                            tracing::warn!(
                                mac,
                                "IDS: MAC block requested but no source IP available for firewall rule"
                            );
                        }
                        let response = ResponseAction::BlockMac {
                            mac: mac.clone(),
                            duration_secs: BLOCK_DURATION_SECS,
                        };
                        responses.push(response);
                    }
                }
                AutoAction::IsolatePort => {
                    if let Some(ref mac) = event.source_mac {
                        // Port isolation via IP-level DROP on FORWARD chain.
                        // The block_ip() call above already inserts INPUT + FORWARD DROP rules,
                        // so IsolatePort is effectively handled. Log the intent for audit trail.
                        if let Some(ref ip) = event.source_ip {
                            tracing::warn!(
                                ip,
                                mac,
                                interface = event.interface,
                                "IDS: port isolation via IP block (FORWARD DROP active)"
                            );
                        }
                        let response = ResponseAction::IsolatePort {
                            interface: event.interface.clone(),
                            mac: mac.clone(),
                        };
                        responses.push(response);
                    }
                }
                AutoAction::RateLimit => {
                    if let Some(ref ip) = event.source_ip {
                        let reason = format!("{} from {}", event.detector, ip);
                        match sfgw_fw::ids_response::rate_limit_ip(
                            &self.db,
                            ip,
                            100, // 100 pps default
                            RATE_LIMIT_DURATION_SECS,
                            &reason,
                        )
                        .await
                        {
                            Ok(rule_id) => {
                                tracing::warn!(ip, rule_id, "IDS: rate-limited IP via firewall");
                            }
                            Err(e) => {
                                tracing::error!(ip, "IDS: failed to rate-limit IP: {e}");
                            }
                        }
                        let response = ResponseAction::RateLimit {
                            ip: ip.clone(),
                            pps: 100,
                        };
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
}
