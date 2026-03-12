// SPDX-License-Identifier: AGPL-3.0-or-later

//! Device adoption protocol.
//!
//! Flow:
//! 1. **Discovery** — device connects to gateway :8080, gateway records it as
//!    `Discovered`, then immediately transitions to `Pending`.
//! 2. **Pending** — admin sees the device in the UI and must manually approve.
//! 3. **Approval** — admin approves -> gateway initiates key exchange.
//! 4. **Key Exchange** — hybrid X25519 ECDH + ML-KEM-1024 (FIPS 203).
//! 5. **Certificate Issue** — gateway CA signs a client cert for the device.
//! 6. **Adoption Complete** — device receives: gateway CA cert (pinned), its
//!    own client cert, and the shared symmetric key derived from hybrid KE.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use fips203::ml_kem_1024;
use fips203::traits::{Encaps, SerDes};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use sfgw_crypto::secure_mem::SecureBox;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::ca::GatewayCA;
use crate::{AdoptedDevice, AdoptionRequest, AdoptionState, DeviceInfo};
use sfgw_db::Db;

/// Outcome of the key exchange + adoption handshake sent to the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdoptionResponse {
    /// Gateway CA certificate (PEM) — the device pins this.
    pub gateway_ca_cert: String,
    /// Device client certificate signed by the gateway CA (PEM).
    pub device_cert: String,
    /// Gateway's ephemeral X25519 public key for ECDH (base64).
    pub gateway_ecdh_public: String,
    /// Initial sequence number (monotone counter).
    pub initial_sequence: u64,
    /// ML-KEM-1024 ciphertext for hybrid PQ key exchange (base64).
    pub ml_kem_ciphertext: Option<String>,
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Record a newly-discovered device. Idempotent — if the MAC already exists
/// the record is updated with the latest IP and timestamp.
pub async fn discover_device(db: &Db, info: &DeviceInfo) -> Result<()> {
    let conn = db.lock().await;
    let now = Utc::now().to_rfc3339();

    // Check if already known.
    let existing: Option<String> = conn
        .query_row(
            "SELECT config FROM devices WHERE mac = ?1",
            [&info.mac],
            |r| r.get(0),
        )
        .ok();

    if let Some(cfg_json) = existing {
        // Already known — just update last_seen and IP.
        let mut cfg: serde_json::Value =
            serde_json::from_str(&cfg_json).unwrap_or(serde_json::json!({}));
        // Don't overwrite state if already adopted.
        if cfg.get("adoption_state").and_then(|v| v.as_str()) == Some("Adopted") {
            conn.execute(
                "UPDATE devices SET ip = ?1, last_seen = ?2 WHERE mac = ?3",
                rusqlite::params![info.ip, now, info.mac],
            )?;
            return Ok(());
        }
        // Update state to Pending if it was Discovered.
        if cfg.get("adoption_state").and_then(|v| v.as_str()) != Some("Pending") {
            cfg["adoption_state"] = serde_json::json!("Pending");
        }
        cfg["firmware_version"] = serde_json::json!(info.firmware_version);
        cfg["capabilities"] = serde_json::json!(info.capabilities);
        conn.execute(
            "UPDATE devices SET ip = ?1, model = ?2, last_seen = ?3, config = ?4 WHERE mac = ?5",
            rusqlite::params![
                info.ip,
                info.model,
                now,
                serde_json::to_string(&cfg)?,
                info.mac
            ],
        )?;
    } else {
        // New device — insert as Pending.
        let cfg = serde_json::json!({
            "adoption_state": "Pending",
            "firmware_version": info.firmware_version,
            "capabilities": info.capabilities,
        });
        conn.execute(
            "INSERT INTO devices (mac, model, ip, last_seen, config) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                info.mac,
                info.model,
                info.ip,
                now,
                serde_json::to_string(&cfg)?
            ],
        )?;
        tracing::info!(mac = %info.mac, model = %info.model, "new device discovered — pending admin approval");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Approval / Rejection
// ---------------------------------------------------------------------------

/// Approve a pending device and perform the adoption handshake.
///
/// Returns the [`AdoptionResponse`] to send to the device.
pub async fn approve_device(
    db: &Db,
    ca: &GatewayCA,
    request: &AdoptionRequest,
) -> Result<AdoptionResponse> {
    // 1. Verify device is pending.
    let (device_id, cfg_json) = {
        let conn = db.lock().await;
        let row: (i64, String) = conn
            .query_row(
                "SELECT id, config FROM devices WHERE mac = ?1",
                [&request.device_mac],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .context("device not found")?;
        row
    };

    let mut cfg: serde_json::Value =
        serde_json::from_str(&cfg_json).unwrap_or(serde_json::json!({}));
    let state = cfg
        .get("adoption_state")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    if state != "Pending" {
        bail!("device {} is not pending (state: {state})", request.device_mac);
    }

    // 2. X25519 ECDH key exchange.
    let rng = ring::rand::SystemRandom::new();
    let mut secret_bytes = [0u8; 32];
    rng.fill(&mut secret_bytes)
        .map_err(|_| anyhow::anyhow!("RNG failure during key exchange"))?;
    let gw_secret = StaticSecret::from(secret_bytes);
    let gw_public = PublicKey::from(&gw_secret);

    let device_pub_bytes = B64
        .decode(&request.device_public_key)
        .context("invalid device public key base64")?;
    if device_pub_bytes.len() != 32 {
        bail!("device X25519 public key must be 32 bytes");
    }
    let mut device_pub_arr = [0u8; 32];
    device_pub_arr.copy_from_slice(&device_pub_bytes);
    let device_pub = PublicKey::from(device_pub_arr);

    let x25519_shared = gw_secret.diffie_hellman(&device_pub);

    // 3. ML-KEM-1024 hybrid key encapsulation (FIPS 203).
    let mut ml_kem_ct_b64: Option<String> = None;
    let mut pq_shared_bytes: Option<[u8; 32]> = None;

    if let Some(ref device_kem_pk_b64) = request.device_kem_public_key {
        let device_ek_bytes = B64
            .decode(device_kem_pk_b64)
            .context("invalid device ML-KEM encapsulation key base64")?;
        let device_ek_arr: [u8; ml_kem_1024::EK_LEN] = device_ek_bytes
            .as_slice()
            .try_into()
            .map_err(|_| {
                anyhow::anyhow!(
                    "device ML-KEM-1024 encapsulation key must be {} bytes, got {}",
                    ml_kem_1024::EK_LEN,
                    device_ek_bytes.len()
                )
            })?;
        let device_ek = ml_kem_1024::EncapsKey::try_from_bytes(device_ek_arr)
            .map_err(|e| anyhow::anyhow!("invalid ML-KEM-1024 encapsulation key: {e:?}"))?;
        let (pq_ss, ct) = device_ek
            .try_encaps()
            .map_err(|e| anyhow::anyhow!("ML-KEM-1024 encapsulation failed: {e:?}"))?;
        let ct_bytes = ct.into_bytes();
        ml_kem_ct_b64 = Some(B64.encode(ct_bytes));
        pq_shared_bytes = Some(pq_ss.into_bytes());
    }

    // 4. Combine shared secrets via HKDF for hybrid key derivation.
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(x25519_shared.as_bytes());
    if let Some(pq_ss) = &pq_shared_bytes {
        ikm.extend_from_slice(pq_ss);
    }

    let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"sfgw-adopt-v1-hybrid");
    let prk = salt.extract(&ikm);
    let mut symmetric_key = [0u8; 32];
    let okm = prk
        .expand(&[b"device-symmetric-key"], ring::hkdf::HKDF_SHA256)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    okm.fill(&mut symmetric_key)
        .map_err(|_| anyhow::anyhow!("HKDF fill failed"))?;

    // Wrap the derived symmetric key in SecureBox immediately so the
    // plaintext is mlock'd, encrypted in RAM, and zeroized on drop.
    let symmetric_key_box = SecureBox::new(symmetric_key.to_vec())
        .context("failed to create SecureBox for symmetric key")?;
    // Zeroize the stack copy now that SecureBox owns the key material.
    zeroize::Zeroize::zeroize(&mut symmetric_key);

    // 5. Sign device certificate.
    let device_cert_pem = ca.sign_device_cert(&request.device_mac, &device_pub_bytes)?;

    let initial_sequence: u64 = 1;

    // 6. Persist adoption state.
    let adopted_device = AdoptedDevice {
        id: device_id,
        mac: request.device_mac.clone(),
        name: None,
        model: request.device_model.clone(),
        certificate: device_cert_pem.clone(),
        public_key: request.device_public_key.clone(),
        sequence_number: initial_sequence,
        adopted_at: Utc::now().to_rfc3339(),
    };

    cfg["adoption_state"] = serde_json::json!("Adopted");
    cfg["certificate"] = serde_json::json!(adopted_device.certificate);
    cfg["public_key"] = serde_json::json!(adopted_device.public_key);
    cfg["sequence_number"] = serde_json::json!(initial_sequence);
    cfg["adopted_at"] = serde_json::json!(adopted_device.adopted_at);
    // Temporarily decrypt the symmetric key for base64 encoding to DB.
    {
        let sk_plain = symmetric_key_box.open()
            .context("failed to decrypt symmetric key from SecureBox")?;
        cfg["symmetric_key"] = serde_json::json!(B64.encode(&sk_plain));
    }

    {
        let conn = db.lock().await;
        conn.execute(
            "UPDATE devices SET adopted = 1, config = ?1 WHERE id = ?2",
            rusqlite::params![serde_json::to_string(&cfg)?, device_id],
        )?;
    }

    tracing::info!(
        mac = %request.device_mac,
        hybrid_pq = pq_shared_bytes.is_some(),
        "device adopted successfully"
    );

    Ok(AdoptionResponse {
        gateway_ca_cert: ca.cert_pem.clone(),
        device_cert: device_cert_pem,
        gateway_ecdh_public: B64.encode(gw_public.as_bytes()),
        initial_sequence,
        ml_kem_ciphertext: ml_kem_ct_b64,
    })
}

/// Reject a pending device.
pub async fn reject_device(db: &Db, mac: &str) -> Result<()> {
    let conn = db.lock().await;
    let cfg = serde_json::json!({ "adoption_state": "Rejected" });
    let affected = conn.execute(
        "UPDATE devices SET config = ?1 WHERE mac = ?2",
        rusqlite::params![serde_json::to_string(&cfg)?, mac],
    )?;
    if affected == 0 {
        bail!("device {mac} not found");
    }
    tracing::info!(mac = %mac, "device rejected");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse the adoption state from the device config JSON.
pub fn parse_state(config_json: &str) -> AdoptionState {
    let v: serde_json::Value = serde_json::from_str(config_json).unwrap_or_default();
    match v.get("adoption_state").and_then(|s| s.as_str()) {
        Some("Discovered") => AdoptionState::Discovered,
        Some("Pending") => AdoptionState::Pending,
        Some("Approved") => AdoptionState::Approved,
        Some("Adopted") => AdoptionState::Adopted,
        Some("Rejected") => AdoptionState::Rejected,
        _ => AdoptionState::Discovered,
    }
}
