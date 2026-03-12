// SPDX-License-Identifier: AGPL-3.0-or-later

//! Distributed Intrusion Detection System
//!
//! Runs on gateway, switches, and APs. Each node monitors locally,
//! reports to the gateway controller which correlates and alerts.
//!
//! ## Detection Capabilities
//!
//! ### Gateway + Switch
//! - ARP spoofing (duplicate MAC, gratuitous ARP flood, gateway impersonation)
//! - DHCP spoofing (rogue DHCP servers)
//! - VLAN hopping (802.1Q double-tagging)
//! - DNS spoofing (responses from unexpected sources)
//! - Port scan detection
//! - MAC flood detection (CAM table overflow attempts)
//!
//! ### AP (later phase)
//! - Deauth flood detection
//! - Evil twin / rogue AP detection
//! - PMKID harvesting detection
//! - Karma attack detection

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
    /// Gateway: full packet inspection on all interfaces + correlation engine
    Gateway,
    /// Switch: local ARP/DHCP/DNS monitoring + port security, reports to gateway
    Switch,
    /// AP: wireless-specific detection (deauth, evil twin, rogue AP)
    AccessPoint,
}

/// Severity of a detected event
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Severity {
    /// Informational — logged, no action
    Info,
    /// Warning — logged + alert
    Warning,
    /// Critical — logged + alert + automatic response (port isolate, block MAC)
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
    /// Log only
    LogOnly,
    /// Send alert (Telegram, webhook)
    Alert(IdsEvent),
    /// Isolate port on switch
    IsolatePort { interface: String, mac: String },
    /// Block MAC address across all switches
    BlockMac { mac: String, duration_secs: u64 },
    /// Rate limit a host
    RateLimit { ip: String, pps: u32 },
}

/// Start the IDS engine on the gateway
pub async fn start(db: &sfgw_db::Db, role: IdsRole) -> Result<()> {
    todo!()
}

/// Process an IDS event reported by a remote node (switch/AP)
pub async fn process_remote_event(db: &sfgw_db::Db, event: IdsEvent) -> Result<ResponseAction> {
    todo!()
}
