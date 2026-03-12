// SPDX-License-Identifier: AGPL-3.0-or-later

//! Device adoption protocol for secfirstgw.
//!
//! Implements the security requirements from SECURITY-DESIGN.md:
//! - No default key — unique secret per device at adoption time
//! - Manual approval — admin must confirm (no auto-adopt)
//! - Mutual TLS — device gets client cert signed by gateway CA
//! - Certificate pinning — device accepts only the gateway CA
//! - Hybrid PQ key exchange — X25519 + ML-KEM-1024 (FIPS 203)
//! - Monotone sequence numbers — prevents config replay / firmware downgrade
//! - Signed configs — ML-DSA-65 (FIPS 204)
//! - Signed firmware — ML-DSA-65 (FIPS 204)

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
    /// Base64-encoded ML-KEM-1024 encapsulation key provided by the device
    /// for hybrid post-quantum key exchange (FIPS 203). Optional for
    /// backwards compatibility with devices that do not support PQ.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_kem_public_key: Option<String>,
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
    tracing::info!("adoption service ready (hybrid X25519 + ML-KEM-1024, ML-DSA-65 signing)");
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    /// ML-KEM-1024 keygen / encaps / decaps roundtrip.
    #[test]
    fn ml_kem_1024_roundtrip() {
        use fips203::ml_kem_1024;
        use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};

        // Keygen
        let (ek, dk) = ml_kem_1024::KG::try_keygen().expect("ML-KEM-1024 keygen");

        // Serialise and deserialise the encapsulation key (simulates network transit).
        let ek_bytes = ek.into_bytes();
        let ek2 = ml_kem_1024::EncapsKey::try_from_bytes(ek_bytes)
            .expect("deserialise encapsulation key");

        // Encapsulate
        let (ss_enc, ct) = ek2.try_encaps().expect("encapsulation");

        // Serialise ciphertext (simulates network transit).
        let ct_bytes = ct.into_bytes();
        let ct2 = ml_kem_1024::CipherText::try_from_bytes(ct_bytes)
            .expect("deserialise ciphertext");

        // Decapsulate
        let ss_dec = dk.try_decaps(&ct2).expect("decapsulation");

        assert_eq!(
            ss_enc.into_bytes(),
            ss_dec.into_bytes(),
            "shared secrets must match after encaps/decaps roundtrip"
        );
    }

    /// ML-DSA-65 sign / verify roundtrip.
    #[test]
    fn ml_dsa_65_sign_verify_roundtrip() {
        use fips204::ml_dsa_65;
        use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

        let (vk, sk) = ml_dsa_65::KG::try_keygen().expect("ML-DSA-65 keygen");

        let message = b"test payload for ML-DSA-65 signing";
        let context = b"";

        let sig_bytes = sk.try_sign(message, context).expect("signing");

        // Deserialise and verify.
        let vk_bytes = vk.into_bytes();
        let vk2 = ml_dsa_65::PublicKey::try_from_bytes(vk_bytes)
            .expect("deserialise public key");

        let valid = vk2.verify(message, &sig_bytes, context);
        assert!(valid, "ML-DSA-65 signature must verify");

        // Tampered message must not verify.
        let invalid = vk2.verify(b"tampered message", &sig_bytes, context);
        assert!(!invalid, "tampered message must not verify");
    }

    /// Hybrid key derivation: HKDF over X25519 + ML-KEM-1024 shared secrets.
    #[test]
    fn hybrid_key_derivation() {
        use fips203::ml_kem_1024;
        use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
        use ring::hkdf;
        use x25519_dalek::{PublicKey, StaticSecret};

        // X25519
        let rng = ring::rand::SystemRandom::new();
        let mut dev_bytes = [0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut dev_bytes).expect("rng");
        let device_secret = StaticSecret::from(dev_bytes);
        let device_public = PublicKey::from(&device_secret);
        let mut gw_bytes = [0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut gw_bytes).expect("rng");
        let gw_secret = StaticSecret::from(gw_bytes);
        let gw_public = PublicKey::from(&gw_secret);

        let x25519_ss_device = device_secret.diffie_hellman(&gw_public);
        let x25519_ss_gw = gw_secret.diffie_hellman(&device_public);
        assert_eq!(x25519_ss_device.as_bytes(), x25519_ss_gw.as_bytes());

        // ML-KEM-1024
        let (ek, dk) = ml_kem_1024::KG::try_keygen().expect("keygen");
        let ek_bytes = ek.into_bytes();
        let ek2 = ml_kem_1024::EncapsKey::try_from_bytes(ek_bytes).expect("deser ek");
        let (pq_ss_enc, ct) = ek2.try_encaps().expect("encaps");
        let ct2 = ml_kem_1024::CipherText::try_from_bytes(ct.into_bytes()).expect("deser ct");
        let pq_ss_dec = dk.try_decaps(&ct2).expect("decaps");
        let pq_enc_bytes = pq_ss_enc.into_bytes();
        let pq_dec_bytes = pq_ss_dec.into_bytes();
        assert_eq!(pq_enc_bytes, pq_dec_bytes);

        // Hybrid HKDF
        let mut ikm = Vec::new();
        ikm.extend_from_slice(x25519_ss_gw.as_bytes());
        ikm.extend_from_slice(&pq_dec_bytes);

        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"sfgw-adopt-v1-hybrid");
        let prk = salt.extract(&ikm);
        let mut key = [0u8; 32];
        let okm = prk
            .expand(&[b"device-symmetric-key"], hkdf::HKDF_SHA256)
            .expect("HKDF expand");
        okm.fill(&mut key).expect("HKDF fill");

        // Key must be non-zero (extremely unlikely to be all zeros).
        assert_ne!(key, [0u8; 32], "derived key must not be all zeros");
    }

    /// AES-256-GCM encrypt / decrypt roundtrip via inform helpers.
    #[test]
    fn inform_encrypt_decrypt_roundtrip() {
        use crate::inform::InformResponse;

        let response = InformResponse {
            sequence_number: 42,
            config_update: None,
            firmware_update: None,
            inform_interval_secs: 30,
        };

        let key = [0xABu8; 32];
        let encrypted = crate::inform::encrypt_response(&response, &key)
            .expect("encryption");

        // Decrypt the base64 ciphertext back.
        let ct_bytes = B64.decode(&encrypted).expect("base64 decode");
        let plaintext = crate::inform::aes_256_gcm_decrypt(&key, &ct_bytes)
            .expect("decryption");
        let recovered: InformResponse =
            serde_json::from_slice(&plaintext).expect("JSON parse");

        assert_eq!(recovered.sequence_number, 42);
        assert_eq!(recovered.inform_interval_secs, 30);
    }

    /// AES-256-GCM: tampered ciphertext must fail authentication.
    #[test]
    fn inform_decrypt_tampered_fails() {
        use crate::inform::InformResponse;

        let response = InformResponse {
            sequence_number: 1,
            config_update: None,
            firmware_update: None,
            inform_interval_secs: 30,
        };

        let key = [0xCDu8; 32];
        let encrypted = crate::inform::encrypt_response(&response, &key)
            .expect("encryption");

        let mut ct_bytes = B64.decode(&encrypted).expect("base64 decode");
        // Flip a byte in the ciphertext (after the 12-byte nonce).
        if ct_bytes.len() > 13 {
            ct_bytes[13] ^= 0xFF;
        }

        let result = crate::inform::aes_256_gcm_decrypt(&key, &ct_bytes);
        assert!(result.is_err(), "tampered ciphertext must fail decryption");
    }
}
