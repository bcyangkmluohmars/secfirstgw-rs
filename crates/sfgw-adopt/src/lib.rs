// SPDX-License-Identifier: AGPL-3.0-or-later

//! Device adoption protocol for secfirstgw.
//!
//! Implements the security requirements from SECURITY-DESIGN.md:
//! - No default key — unique secret per device at adoption time
//! - Manual approval — admin must confirm (no auto-adopt)
//! - Mutual TLS — device gets client cert signed by gateway CA
//! - Certificate pinning — device accepts only the gateway CA
//! - Hybrid PQ key exchange — X25519 + ML-KEM-1024 (placeholder)
//! - Monotone sequence numbers — prevents config replay / firmware downgrade
//! - Signed configs — Ed25519 (+ ML-DSA-65 TODO)
//! - Signed firmware — Ed25519 (+ ML-DSA-65 TODO)

pub mod ca;
pub mod inform;
pub mod protocol;
pub mod signing;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sfgw_db::Db;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// Adoption lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdoptionState {
    /// Device has broadcast / connected but is not yet recorded.
    Discovered,
    /// Recorded, awaiting admin approval.
    Pending,
    /// Admin approved, adoption handshake in progress.
    Approved,
    /// Fully adopted — has cert, key, sequence number.
    Adopted,
    /// Admin rejected this device.
    Rejected,
}

impl std::fmt::Display for AdoptionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Discovered => write!(f, "Discovered"),
            Self::Pending => write!(f, "Pending"),
            Self::Approved => write!(f, "Approved"),
            Self::Adopted => write!(f, "Adopted"),
            Self::Rejected => write!(f, "Rejected"),
        }
    }
}

/// Information about a discovered (not-yet-adopted) device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub mac: String,
    pub model: String,
    pub ip: String,
    pub firmware_version: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// A fully adopted device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdoptedDevice {
    pub id: i64,
    pub mac: String,
    pub name: Option<String>,
    pub model: String,
    /// PEM-encoded client certificate signed by gateway CA.
    pub certificate: String,
    /// Base64-encoded X25519 public key.
    pub public_key: String,
    /// Monotone sequence number (increments with every config push).
    pub sequence_number: u64,
    /// RFC 3339 timestamp.
    pub adopted_at: String,
}

/// Request to adopt a device (submitted after admin approval).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdoptionRequest {
    pub device_mac: String,
    pub device_model: String,
    pub device_ip: String,
    /// Base64-encoded X25519 public key provided by the device.
    pub device_public_key: String,
}

/// Summary row returned by list functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub id: i64,
    pub mac: String,
    pub name: Option<String>,
    pub model: Option<String>,
    pub ip: Option<String>,
    pub adopted: bool,
    pub last_seen: Option<String>,
    pub state: AdoptionState,
}

// ---------------------------------------------------------------------------
// Public API (consumed by sfgw-api)
// ---------------------------------------------------------------------------

/// Initialise the adoption service: ensure the gateway CA exists and return
/// a handle to it.
pub async fn start(db: &Db) -> Result<ca::GatewayCA> {
    let ca = ca::GatewayCA::init(db).await?;
    tracing::info!("adoption service ready (PQ key exchange pending)");
    Ok(ca)
}

/// List all known devices (any state).
pub async fn list_devices(db: &Db) -> Result<Vec<DeviceSummary>> {
    let conn = db.lock().await;
    let mut stmt = conn.prepare(
        "SELECT id, mac, name, model, ip, adopted, last_seen, config FROM devices",
    )?;
    let rows = stmt.query_map([], |row| {
        let config_json: String = row.get(7)?;
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, Option<String>>(6)?,
            config_json,
        ))
    })?;

    let mut devices = Vec::new();
    for row in rows {
        let (id, mac, name, model, ip, adopted, last_seen, config_json) = row?;
        let state = protocol::parse_state(&config_json);
        devices.push(DeviceSummary {
            id,
            mac,
            name,
            model,
            ip,
            adopted: adopted != 0,
            last_seen,
            state,
        });
    }
    Ok(devices)
}

/// List devices awaiting admin approval.
pub async fn list_pending(db: &Db) -> Result<Vec<DeviceSummary>> {
    let all = list_devices(db).await?;
    Ok(all
        .into_iter()
        .filter(|d| d.state == AdoptionState::Pending)
        .collect())
}

/// Approve a pending device — performs the full adoption handshake.
pub async fn approve_device(
    db: &Db,
    ca: &ca::GatewayCA,
    request: &AdoptionRequest,
) -> Result<protocol::AdoptionResponse> {
    protocol::approve_device(db, ca, request).await
}

/// Reject a pending device.
pub async fn reject_device(db: &Db, mac: &str) -> Result<()> {
    protocol::reject_device(db, mac).await
}

/// Get the current config JSON for a device.
pub async fn get_device_config(db: &Db, mac: &str) -> Result<serde_json::Value> {
    let conn = db.lock().await;
    let cfg_json: String = conn
        .query_row(
            "SELECT config FROM devices WHERE mac = ?1",
            [mac],
            |r| r.get(0),
        )
        .context("device not found")?;
    serde_json::from_str(&cfg_json).context("corrupt device config JSON")
}

/// Push a new config to a device.
///
/// The config is stored as `pending_config` in the device row. On the next
/// inform cycle the gateway will sign it and deliver it with an incremented
/// sequence number.  The device MUST reject any config with
/// `sequence_number <= current` (monotone enforcement).
pub async fn push_config(db: &Db, mac: &str, new_config: serde_json::Value) -> Result<u64> {
    let conn = db.lock().await;
    let (device_id, cfg_json): (i64, String) = conn
        .query_row(
            "SELECT id, config FROM devices WHERE mac = ?1 AND adopted = 1",
            [mac],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .context("adopted device not found")?;

    let mut cfg: serde_json::Value =
        serde_json::from_str(&cfg_json).unwrap_or(serde_json::json!({}));

    let current_seq = cfg
        .get("sequence_number")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let next_seq = current_seq + 1;

    cfg["pending_config"] = new_config;
    cfg["sequence_number"] = serde_json::json!(next_seq);

    conn.execute(
        "UPDATE devices SET config = ?1 WHERE id = ?2",
        rusqlite::params![serde_json::to_string(&cfg)?, device_id],
    )?;

    tracing::info!(mac = %mac, seq = next_seq, "config push queued");
    Ok(next_seq)
}
