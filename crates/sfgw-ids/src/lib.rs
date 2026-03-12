// SPDX-License-Identifier: AGPL-3.0-or-later

//! Distributed Intrusion Detection System
//!
//! Runs on gateway, switches, and APs. Each node monitors locally,
//! reports to the gateway controller which correlates and alerts.

use anyhow::Result;

pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod vlan;
pub mod alert;
pub mod collector;

/// IDS role — determines which detectors are active
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdsRole {
    /// Gateway: full packet inspection + correlation engine
    Gateway,
    /// Switch: local ARP/DHCP/DNS monitoring, reports to gateway
    Switch,
    /// AP: wireless-specific detection (deauth, evil twin, rogue AP)
    AccessPoint,
}

/// Severity of a detected event
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// A detected security event
#[derive(Debug, Clone, serde::Serialize)]
pub struct IdsEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub severity: Severity,
    pub detector: &'static str,
    pub source_mac: Option<String>,
    pub source_ip: Option<String>,
    pub interface: String,
    pub vlan: Option<u16>,
    pub description: String,
}

/// Automatic response action
#[derive(Debug, Clone, serde::Serialize)]
pub enum ResponseAction {
    LogOnly,
    Alert(IdsEvent),
    IsolatePort { interface: String, mac: String },
    BlockMac { mac: String, duration_secs: u64 },
    RateLimit { ip: String, pps: u32 },
}

/// Start the IDS engine
pub async fn start(db: &sfgw_db::Db, role: IdsRole) -> Result<()> {
    let _ = db;
    tracing::info!("IDS engine started (role: {role:?}, detectors pending)");
    Ok(())
}

/// Process an IDS event reported by a remote node
pub async fn process_remote_event(db: &sfgw_db::Db, event: IdsEvent) -> Result<ResponseAction> {
    let _ = (db, &event);
    tracing::info!("remote IDS event: {}", event.description);
    Ok(ResponseAction::LogOnly)
}
