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

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chrono::Utc;
use ring::aead::{self, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use sfgw_db::Db;

use crate::ca::GatewayCA;
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
            let signed = signing::sign_config(&config_blob, ca)?;

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

    // Check for firmware updates by comparing device's reported version
    // against the latest firmware manifest in the DB for that model.
    let model: Option<String> = conn
        .query_row(
            "SELECT model FROM devices WHERE id = ?1",
            [device_id],
            |r| r.get(0),
        )
        .ok()
        .flatten();

    let firmware_update = if let Some(ref model) = model {
        match load_latest_firmware_inner(&conn, model) {
            Ok(Some(row)) => {
                if is_newer_version(&row.version, &payload.firmware_version) {
                    tracing::info!(
                        mac = %payload.mac,
                        model = %model,
                        device_version = %payload.firmware_version,
                        latest_version = %row.version,
                        "firmware update available"
                    );
                    let manifest = signing::sign_firmware_manifest(
                        &row.version,
                        &row.sha256,
                        &row.url,
                        row.size_bytes,
                        ca,
                    )?;
                    Some(manifest)
                } else {
                    tracing::debug!(
                        mac = %payload.mac,
                        model = %model,
                        device_version = %payload.firmware_version,
                        "device firmware is up to date"
                    );
                    None
                }
            }
            Ok(None) => {
                tracing::debug!(
                    mac = %payload.mac,
                    model = %model,
                    "no firmware manifest registered for model"
                );
                None
            }
            Err(e) => {
                tracing::warn!(
                    mac = %payload.mac,
                    model = %model,
                    error = %e,
                    "failed to query firmware manifests"
                );
                None
            }
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
/// Uses AES-256-GCM. Returns base64-encoded `nonce || ciphertext || tag`.
pub fn encrypt_response(response: &InformResponse, symmetric_key: &[u8]) -> Result<String> {
    if symmetric_key.len() != 32 {
        bail!(
            "symmetric key must be 32 bytes, got {}",
            symmetric_key.len()
        );
    }
    let json = serde_json::to_vec(response)?;
    let encrypted = aes_256_gcm_encrypt(symmetric_key, &json)?;
    Ok(B64.encode(&encrypted))
}

/// Decrypt an inform payload from a device.
///
/// Expects base64-encoded `nonce || ciphertext || tag`.
pub fn decrypt_payload(ciphertext_b64: &str, symmetric_key: &[u8]) -> Result<InformPayload> {
    if symmetric_key.len() != 32 {
        bail!(
            "symmetric key must be 32 bytes, got {}",
            symmetric_key.len()
        );
    }
    let ciphertext = B64
        .decode(ciphertext_b64)
        .context("invalid base64 in inform payload")?;
    let plaintext = aes_256_gcm_decrypt(symmetric_key, &ciphertext)?;
    serde_json::from_slice(&plaintext).context("invalid JSON in decrypted inform payload")
}

// ---------------------------------------------------------------------------
// Firmware manifest management
// ---------------------------------------------------------------------------

/// Row from the `firmware_manifests` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareRow {
    pub id: i64,
    pub model: String,
    pub version: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub url: String,
    pub signature: String,
    pub created_at: String,
}

/// Load the latest firmware manifest for a given device model.
///
/// Returns `None` if no firmware has been registered for the model.
pub async fn load_latest_firmware(db: &Db, model: &str) -> Result<Option<FirmwareRow>> {
    let conn = db.lock().await;
    load_latest_firmware_inner(&conn, model)
}

/// Inner (synchronous) implementation so it can be called while holding the lock.
fn load_latest_firmware_inner(
    conn: &rusqlite::Connection,
    model: &str,
) -> Result<Option<FirmwareRow>> {
    let result = conn.query_row(
        "SELECT id, model, version, sha256, size_bytes, url, signature, created_at \
         FROM firmware_manifests \
         WHERE model = ?1 \
         ORDER BY id DESC \
         LIMIT 1",
        [model],
        |r| {
            Ok(FirmwareRow {
                id: r.get(0)?,
                model: r.get(1)?,
                version: r.get(2)?,
                sha256: r.get(3)?,
                size_bytes: r.get(4)?,
                url: r.get(5)?,
                signature: r.get(6)?,
                created_at: r.get(7)?,
            })
        },
    );
    match result {
        Ok(row) => Ok(Some(row)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e).context("failed to query firmware_manifests"),
    }
}

/// Register a new firmware manifest in the database.
///
/// The manifest is signed with the gateway CA (ML-DSA-65) and the signature is
/// stored alongside the metadata.  Callers should provide the SHA-256 hash of
/// the firmware binary and a download URL.
pub async fn register_firmware(
    db: &Db,
    ca: &GatewayCA,
    model: &str,
    version: &str,
    sha256: &str,
    size_bytes: i64,
    url: &str,
) -> Result<()> {
    // Build the canonical payload that gets signed.
    let inner = serde_json::json!({
        "model": model,
        "version": version,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "url": url,
    });
    let payload_bytes = serde_json::to_vec(&inner)?;
    let sig = ca.sign(&payload_bytes)?;
    let sig_b64 = B64.encode(&sig);

    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO firmware_manifests (model, version, sha256, size_bytes, url, signature) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![model, version, sha256, size_bytes, url, sig_b64],
    )?;

    tracing::info!(
        model = %model,
        version = %version,
        size_bytes = size_bytes,
        "firmware manifest registered"
    );
    Ok(())
}

/// Compare two semver-style version strings (e.g. "1.2.3" > "1.2.0").
///
/// Returns `true` if `candidate` is strictly newer than `current`.
/// Falls back to lexicographic comparison if parsing fails.
pub fn is_newer_version(candidate: &str, current: &str) -> bool {
    let parse = |v: &str| -> Option<Vec<u64>> {
        v.split('.').map(|part| part.parse::<u64>().ok()).collect()
    };

    match (parse(candidate), parse(current)) {
        (Some(c), Some(d)) => c > d,
        _ => candidate > current,
    }
}

// ---------------------------------------------------------------------------
// AES-256-GCM helpers
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` with AES-256-GCM. Returns `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
pub(crate) fn aes_256_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| anyhow::anyhow!("invalid AES-256-GCM key"))?;
    let sealing_key = LessSafeKey::new(unbound);

    let rng = ring::rand::SystemRandom::new();
    let mut nonce_bytes = [0u8; aead::NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("RNG failure generating nonce"))?;

    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| anyhow::anyhow!("AES-256-GCM seal failed"))?;

    // Prepend nonce to ciphertext+tag.
    let mut output = Vec::with_capacity(aead::NONCE_LEN + in_out.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&in_out);
    Ok(output)
}

/// Decrypt AES-256-GCM ciphertext. Input must be `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
pub(crate) fn aes_256_gcm_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < aead::NONCE_LEN + AES_256_GCM.tag_len() {
        bail!("ciphertext too short for AES-256-GCM");
    }
    let (nonce_bytes, encrypted) = data.split_at(aead::NONCE_LEN);
    let nonce_arr: [u8; aead::NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("nonce wrong length"))?;

    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| anyhow::anyhow!("invalid AES-256-GCM key"))?;
    let opening_key = LessSafeKey::new(unbound);

    let nonce = Nonce::assume_unique_for_key(nonce_arr);
    let mut in_out = encrypted.to_vec();
    let plaintext = opening_key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| anyhow::anyhow!("AES-256-GCM decryption/authentication failed"))?;
    Ok(plaintext.to_vec())
}
