// SPDX-License-Identifier: AGPL-3.0-or-later

//! Inform protocol for adopted devices.
//!
//! Adopted devices periodically POST to `/api/v1/inform` on :8080.
//! The payload is encrypted JSON containing device status, metrics, and
//! IDS events.  The gateway responds with config updates, firmware URL,
//! and the next sequence number.
//!
//! **Monotone sequence numbers**: the device MUST reject any config where
//! `sequence_number <= current`.  This prevents config replay attacks and
//! firmware downgrades.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sfgw_db::Db;

use crate::signing;

/// Inform payload sent by the device (after decryption).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InformPayload {
    pub mac: String,
    pub uptime_secs: u64,
    pub firmware_version: String,
    pub sequence_number: u64,
    #[serde(default)]
    pub metrics: serde_json::Value,
    #[serde(default)]
    pub ids_events: Vec<serde_json::Value>,
}

/// Response sent back to the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InformResponse {
    /// Current sequence number the device should track.
    pub sequence_number: u64,
    /// Signed config blob (if there is a pending config update).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_update: Option<signing::SignedPayload>,
    /// Firmware update manifest (if a new firmware is available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firmware_update: Option<signing::FirmwareManifest>,
    /// Interval in seconds until the next inform.
    pub inform_interval_secs: u64,
}

/// Default inform interval (30 seconds).
const DEFAULT_INFORM_INTERVAL: u64 = 30;

/// Process an inform from an adopted device.
///
/// Validates the device is adopted, updates last_seen, and returns any
/// pending config/firmware updates.
pub async fn handle_inform(
    db: &Db,
    ca: &crate::ca::GatewayCA,
    payload: &InformPayload,
) -> Result<InformResponse> {
    let conn = db.lock().await;
    let now = Utc::now().to_rfc3339();

    // Look up device.
    let (device_id, adopted, cfg_json): (i64, i64, String) = conn
        .query_row(
            "SELECT id, adopted, config FROM devices WHERE mac = ?1",
            [&payload.mac],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .context("unknown device")?;

    if adopted != 1 {
        bail!("device {} is not adopted", payload.mac);
    }

    let mut cfg: serde_json::Value =
        serde_json::from_str(&cfg_json).unwrap_or(serde_json::json!({}));

    let stored_seq = cfg
        .get("sequence_number")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // Validate the device's reported sequence number.
    if payload.sequence_number < stored_seq {
        tracing::warn!(
            mac = %payload.mac,
            device_seq = payload.sequence_number,
            stored_seq,
            "device reported stale sequence number"
        );
    }

    // Update last_seen.
    conn.execute(
        "UPDATE devices SET ip = NULL, last_seen = ?1 WHERE id = ?2",
        rusqlite::params![now, device_id],
    )?;

    // Check if there is a pending config update.
    let config_update = if let Some(pending) = cfg.get("pending_config") {
        if !pending.is_null() {
            let new_seq = stored_seq + 1;
            let config_blob = serde_json::to_vec(pending)?;
            let signed = signing::sign_config(&config_blob, ca);

            // Update stored sequence number and clear pending config.
            cfg["sequence_number"] = serde_json::json!(new_seq);
            cfg["pending_config"] = serde_json::json!(null);
            conn.execute(
                "UPDATE devices SET config = ?1 WHERE id = ?2",
                rusqlite::params![serde_json::to_string(&cfg)?, device_id],
            )?;

            Some(signed)
        } else {
            None
        }
    } else {
        None
    };

    // Check for firmware updates — TODO: compare against a firmware repo.
    let firmware_update = if let Some(fw) = cfg.get("pending_firmware") {
        if !fw.is_null() {
            let version = fw.get("version").and_then(|v| v.as_str()).unwrap_or("");
            let sha256 = fw.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
            let url = fw.get("url").and_then(|v| v.as_str()).unwrap_or("");
            if !version.is_empty() {
                let manifest = signing::sign_firmware_manifest(version, sha256, url, ca);
                cfg["pending_firmware"] = serde_json::json!(null);
                conn.execute(
                    "UPDATE devices SET config = ?1 WHERE id = ?2",
                    rusqlite::params![serde_json::to_string(&cfg)?, device_id],
                )?;
                Some(manifest)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    let current_seq = cfg
        .get("sequence_number")
        .and_then(|v| v.as_u64())
        .unwrap_or(stored_seq);

    Ok(InformResponse {
        sequence_number: current_seq,
        config_update,
        firmware_update,
        inform_interval_secs: DEFAULT_INFORM_INTERVAL,
    })
}

/// Encrypt an inform response for a specific device using its symmetric key.
///
/// Returns base64-encoded ciphertext.
/// **TODO**: implement AES-256-GCM encryption using the device's symmetric key.
pub fn encrypt_response(_response: &InformResponse, _symmetric_key: &[u8]) -> Result<String> {
    // Placeholder — in production this would AES-256-GCM encrypt.
    let json = serde_json::to_string(_response)?;
    Ok(B64.encode(json.as_bytes()))
}

/// Decrypt an inform payload from a device.
///
/// **TODO**: implement AES-256-GCM decryption using the device's symmetric key.
pub fn decrypt_payload(_ciphertext: &str, _symmetric_key: &[u8]) -> Result<InformPayload> {
    // Placeholder — in production this would AES-256-GCM decrypt.
    let bytes = B64
        .decode(_ciphertext)
        .context("invalid base64 in inform payload")?;
    serde_json::from_slice(&bytes).context("invalid JSON in inform payload")
}
