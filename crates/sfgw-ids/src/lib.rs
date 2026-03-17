// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! Distributed Intrusion Detection System
//!
//! Runs on gateway, switches, and APs. Each node monitors locally,
//! reports to the gateway controller which correlates and alerts.

use tokio::sync::mpsc;

/// Errors from the IDS crate.
#[derive(Debug, thiserror::Error)]
pub enum IdsError {
    /// Database error.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// Wrapped anyhow error for internal context propagation.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Convenience alias for results from this crate.
type Result<T> = std::result::Result<T, IdsError>;

pub mod alert;
pub mod arp;
pub mod collector;
pub mod dhcp;
pub mod dns;
pub mod vlan;

/// IDS role — determines which detectors are active.
///
/// ```
/// use sfgw_ids::IdsRole;
///
/// // Gateway runs all monitors + correlation engine
/// let role = IdsRole::Gateway;
/// assert_eq!(format!("{role:?}"), "Gateway");
///
/// // Switch monitors ARP/DHCP/VLAN and reports to gateway
/// let role = IdsRole::Switch;
/// assert_ne!(role, IdsRole::Gateway);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdsRole {
    /// Gateway: full packet inspection + correlation engine
    Gateway,
    /// Switch: local ARP/DHCP/DNS monitoring, reports to gateway
    Switch,
    /// AP: wireless-specific detection (deauth, evil twin, rogue AP)
    AccessPoint,
}

/// Severity of a detected event.
///
/// ```
/// use sfgw_ids::Severity;
///
/// let sev = Severity::Critical;
/// let json = serde_json::to_string(&sev).unwrap();
/// assert_eq!(json, r#""Critical""#);
/// ```
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
            // Future work: wireless-specific IDS monitors.
            //
            // AP-mode detection targets:
            // - Deauthentication floods: mass deauth frames targeting clients (Wi-Fi DoS).
            // - Evil twin detection: another AP advertising the same SSID with a
            //   different BSSID or on a different channel.
            // - Rogue AP discovery: unauthorized access points appearing on the
            //   managed network (detected via beacon frame analysis).
            // - Client disassociation anomalies: unexpected patterns in
            //   disassoc/deauth frames that indicate an active attack.
            //
            // These require monitor-mode wireless interfaces (e.g. via nl80211)
            // and 802.11 frame parsing, which will be added in a future release.
            tracing::info!("AP mode: wireless IDS monitors not yet implemented (see roadmap)");
        }
    }

    // Drop original sender so the loop exits when all monitors stop
    drop(event_tx);

    // Spawn alert engine + collector as background task so start() returns
    let db_alert = db.clone();
    tokio::spawn(async move {
        let mut alert_engine = alert::AlertEngine::new(db_alert);
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
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::error!("Collector error: {e}");
                }
            }
        }

        tracing::info!("IDS engine stopped");
    });

    Ok(())
}

/// Log an IDS event directly to the database.
///
/// Convenience function for other crates (e.g. sfgw-inform) to record
/// security events without going through the full alert pipeline.
#[allow(clippy::too_many_arguments)]
pub async fn log_event(
    db: &sfgw_db::Db,
    severity: &str,
    detector: &'static str,
    source_mac: Option<&str>,
    source_ip: Option<&str>,
    interface: Option<&str>,
    vlan: Option<u16>,
    description: &str,
) -> Result<()> {
    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO ids_events (timestamp, severity, detector, source_mac, source_ip, interface, vlan, description)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            chrono::Utc::now().to_rfc3339(),
            severity,
            detector,
            source_mac,
            source_ip,
            interface.unwrap_or(""),
            vlan,
            description,
        ],
    )
    .map_err(IdsError::Database)?;

    tracing::warn!(
        severity,
        detector,
        source_mac,
        source_ip,
        description,
        "IDS event logged"
    );
    Ok(())
}

/// Process an IDS event reported by a remote node.
/// Used by the API endpoint that receives events from switches/APs.
pub async fn process_remote_event(db: &sfgw_db::Db, event: IdsEvent) -> Result<ResponseAction> {
    // Store in database via alert engine
    let mut alert_engine = alert::AlertEngine::new(db.clone());
    let actions = alert_engine.process_event(&event).await?;

    // Return the most severe action
    Ok(actions
        .into_iter()
        .last()
        .unwrap_or(ResponseAction::LogOnly))
}
