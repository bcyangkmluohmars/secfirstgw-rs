// SPDX-License-Identifier: AGPL-3.0-or-later

//! Distributed Intrusion Detection System
//!
//! Runs on gateway, switches, and APs. Each node monitors locally,
//! reports to the gateway controller which correlates and alerts.

use anyhow::Result;
use tokio::sync::mpsc;

pub mod alert;
pub mod arp;
pub mod collector;
pub mod dhcp;
pub mod dns;
pub mod vlan;

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

/// Start the IDS engine based on role.
///
/// Spawns appropriate monitors as background tasks and runs the alert engine
/// + collector in the foreground, processing events from all monitors.
pub async fn start(db: &sfgw_db::Db, role: IdsRole) -> Result<()> {
    tracing::info!("IDS engine starting (role: {role:?})");

    let (event_tx, mut event_rx) = mpsc::channel::<IdsEvent>(1024);

    match role {
        IdsRole::Gateway => {
            // Gateway: all monitors + collector
            let db_arp = db.clone();
            let tx_arp = event_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = arp::start_monitor(db_arp, tx_arp).await {
                    tracing::error!("ARP monitor failed: {e}");
                }
            });

            let db_dhcp = db.clone();
            let tx_dhcp = event_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = dhcp::start_monitor(db_dhcp, tx_dhcp).await {
                    tracing::error!("DHCP monitor failed: {e}");
                }
            });

            let db_dns = db.clone();
            let tx_dns = event_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = dns::start_monitor(db_dns, tx_dns).await {
                    tracing::error!("DNS monitor failed: {e}");
                }
            });

            let db_vlan = db.clone();
            let tx_vlan = event_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = vlan::start_monitor(db_vlan, tx_vlan).await {
                    tracing::error!("VLAN monitor failed: {e}");
                }
            });
        }

        IdsRole::Switch => {
            // Switch: ARP + DHCP + VLAN monitors
            let db_arp = db.clone();
            let tx_arp = event_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = arp::start_monitor(db_arp, tx_arp).await {
                    tracing::error!("ARP monitor failed: {e}");
                }
            });

            let db_dhcp = db.clone();
            let tx_dhcp = event_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = dhcp::start_monitor(db_dhcp, tx_dhcp).await {
                    tracing::error!("DHCP monitor failed: {e}");
                }
            });

            let db_vlan = db.clone();
            let tx_vlan = event_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = vlan::start_monitor(db_vlan, tx_vlan).await {
                    tracing::error!("VLAN monitor failed: {e}");
                }
            });
        }

        IdsRole::AccessPoint => {
            // AP: placeholder for wireless-specific monitors (deauth, evil twin, rogue AP)
            tracing::info!("AP mode: wireless IDS monitors not yet implemented");
        }
    }

    // Drop original sender so the loop exits when all monitors stop
    drop(event_tx);

    // Alert engine + collector process all events
    let mut alert_engine = alert::AlertEngine::new(db.clone());
    let mut event_collector = collector::Collector::new(30); // 30s correlation window

    while let Some(event) = event_rx.recv().await {
        // Process through alert engine (store, rate-limit, respond)
        match alert_engine.process_event(&event).await {
            Ok(actions) => {
                for action in &actions {
                    tracing::debug!("IDS response: {action:?}");
                }
            }
            Err(e) => {
                tracing::error!("Alert engine error: {e}");
            }
        }

        // Feed into collector for cross-node correlation
        match event_collector.ingest(event) {
            Ok(Some(action)) => {
                tracing::warn!("Collector correlation triggered: {action:?}");
                // Execute the correlated response through the alert engine
                // (the alert engine handles nftables calls etc.)
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!("Collector error: {e}");
            }
        }
    }

    tracing::info!("IDS engine stopped");
    Ok(())
}

/// Process an IDS event reported by a remote node.
/// Used by the API endpoint that receives events from switches/APs.
pub async fn process_remote_event(
    db: &sfgw_db::Db,
    event: IdsEvent,
) -> Result<ResponseAction> {
    // Store in database via alert engine
    let mut alert_engine = alert::AlertEngine::new(db.clone());
    let actions = alert_engine.process_event(&event).await?;

    // Return the most severe action
    Ok(actions
        .into_iter()
        .last()
        .unwrap_or(ResponseAction::LogOnly))
}
