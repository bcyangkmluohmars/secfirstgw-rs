// SPDX-License-Identifier: AGPL-3.0-or-later

//! Gateway Certificate Authority.
//!
//! Manages the gateway's hybrid signing keypairs:
//!   - Ed25519 (classical)
//!   - ML-DSA-65 (FIPS 204, post-quantum)
//!
//! Both signatures are always produced and both must verify (hybrid requirement
//! from CLAUDE.md).  Keys are stored in the `meta` table and the private keys
//! are held in [`SecureBox`] so they are mlock'd, zeroize-on-drop, and
//! encrypted at rest in RAM.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer};
use sfgw_crypto::secure_mem::SecureBox;
use sfgw_db::Db;

/// PEM tag used for the CA certificate (self-signed).
const CA_CERT_PEM_TAG: &str = "SFGW CA CERTIFICATE";
/// PEM tag used for device client certificates.
const DEVICE_CERT_PEM_TAG: &str = "SFGW DEVICE CERTIFICATE";

/// Minimal self-describing certificate payload (JSON inside PEM).
/// A real implementation would use X.509 / ASN.1; this is intentionally
/// simple so the rest of the adoption protocol can be built and tested
/// without pulling in an X.509 stack.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertPayload {
    pub version: u8,
    pub subject: String,
    pub issuer: String,
    pub public_key: String,
    /// Ed25519 verifying key (base64). Present in v2+ certs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ed25519_public_key: Option<String>,
    pub not_before: String,
    pub not_after: String,
    /// ML-DSA-65 signature over the canonical fields (base64).
    pub signature: String,
    /// Ed25519 signature over the canonical fields (base64).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_ed25519: Option<String>,
}

/// In-memory representation of the gateway CA.
pub struct GatewayCA {
    /// ML-DSA-65 private key bytes (encrypted at rest in RAM).
    signing_key: SecureBox<Vec<u8>>,
    /// ML-DSA-65 public key bytes.
    verifying_key: Vec<u8>,
    /// Ed25519 private key bytes (encrypted at rest in RAM).
    ed25519_signing_key: SecureBox<Vec<u8>>,
    /// Ed25519 verifying (public) key bytes.
    ed25519_verifying_key: Vec<u8>,
    pub cert_pem: String,
}

impl GatewayCA {
    /// Initialise the CA — loads from DB or generates on first boot.
    pub async fn init(db: &Db) -> Result<Self> {
        let conn = db.lock().await;

        // Try to load existing key material.
        let existing_key: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'gateway_ca_key'",
                [],
                |row| row.get(0),
            )
            .ok();

        let existing_vk: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'gateway_ca_vk'",
                [],
                |row| row.get(0),
            )
            .ok();

        let existing_ed_key: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'gateway_ca_ed25519_key'",
                [],
                |row| row.get(0),
            )
            .ok();

        let existing_ed_vk: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'gateway_ca_ed25519_vk'",
                [],
                |row| row.get(0),
            )
            .ok();

        let existing_cert: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'gateway_ca_cert'",
                [],
                |row| row.get(0),
            )
            .ok();

        // Full hybrid load: both ML-DSA-65 and Ed25519 present.
        if let (Some(key_b64), Some(vk_b64), Some(ed_key_b64), Some(ed_vk_b64), Some(cert_pem)) = (
            existing_key.clone(),
            existing_vk.clone(),
            existing_ed_key,
            existing_ed_vk,
            existing_cert.clone(),
        ) {
            let sk_bytes = B64
                .decode(&key_b64)
                .context("corrupt CA ML-DSA signing key in database")?;
            let vk_bytes = B64
                .decode(&vk_b64)
                .context("corrupt CA ML-DSA verifying key in database")?;
            let ed_sk_bytes = B64
                .decode(&ed_key_b64)
                .context("corrupt CA Ed25519 signing key in database")?;
            let ed_vk_bytes = B64
                .decode(&ed_vk_b64)
                .context("corrupt CA Ed25519 verifying key in database")?;

            // Validate that the ML-DSA key material deserialises correctly.
            let _sk = ml_dsa_65::PrivateKey::try_from_bytes(
                sk_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("CA ML-DSA signing key wrong length"))?,
            )
            .map_err(|e| anyhow::anyhow!("failed to load CA ML-DSA signing key: {e:?}"))?;

            // Validate Ed25519 key material.
            let ed_sk_arr: [u8; 32] = ed_sk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("CA Ed25519 signing key wrong length"))?;
            let _ed_sk = SigningKey::from_bytes(&ed_sk_arr);

            let signing_key = SecureBox::new(sk_bytes)
                .context("failed to create SecureBox for CA ML-DSA signing key")?;
            let ed25519_signing_key = SecureBox::new(ed_sk_bytes)
                .context("failed to create SecureBox for CA Ed25519 signing key")?;

            tracing::info!("gateway CA loaded from database (hybrid Ed25519 + ML-DSA-65)");
            return Ok(Self {
                signing_key,
                verifying_key: vk_bytes,
                ed25519_signing_key,
                ed25519_verifying_key: ed_vk_bytes,
                cert_pem,
            });
        }

        // ---- First-boot or upgrade: generate keypairs ----

        // ML-DSA-65 keypair
        let (vk, sk) = ml_dsa_65::KG::try_keygen()
            .map_err(|e| anyhow::anyhow!("ML-DSA-65 CA keygen failed: {e:?}"))?;
        let sk_bytes = sk.into_bytes().to_vec();
        let vk_bytes = vk.into_bytes().to_vec();

        // Ed25519 keypair — use ring's SystemRandom for entropy.
        let rng = ring::rand::SystemRandom::new();
        let mut ed_seed = [0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut ed_seed)
            .map_err(|_| anyhow::anyhow!("failed to generate Ed25519 seed"))?;
        let ed_sk = SigningKey::from_bytes(&ed_seed);
        let ed_vk = VerifyingKey::from(&ed_sk);
        let ed_sk_bytes = ed_sk.to_bytes().to_vec();
        let ed_vk_bytes = ed_vk.to_bytes().to_vec();

        let now = chrono::Utc::now();
        let not_after = now + chrono::Duration::days(3650); // 10 years

        let pub_key_b64 = B64.encode(&vk_bytes);
        let ed_pub_key_b64 = B64.encode(&ed_vk_bytes);

        // Build the self-signed CA certificate with both signatures.
        let mut payload = CertPayload {
            version: 2,
            subject: "secfirstgw-ca".into(),
            issuer: "secfirstgw-ca".into(),
            public_key: pub_key_b64,
            ed25519_public_key: Some(ed_pub_key_b64),
            not_before: now.to_rfc3339(),
            not_after: not_after.to_rfc3339(),
            signature: String::new(),
            signature_ed25519: None,
        };
        let (ml_dsa_sig, ed_sig) =
            Self::sign_payload_hybrid_static(&sk_bytes, &ed_sk_bytes, &payload)?;
        payload.signature = ml_dsa_sig;
        payload.signature_ed25519 = Some(ed_sig);

        let cert_pem = encode_pem(CA_CERT_PEM_TAG, &serde_json::to_vec(&payload)?);

        // Persist all keys to DB.
        let key_b64 = B64.encode(&sk_bytes);
        let vk_b64 = B64.encode(&vk_bytes);
        let ed_key_b64 = B64.encode(&ed_sk_bytes);
        let ed_vk_b64 = B64.encode(&ed_vk_bytes);
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('gateway_ca_key', ?1)",
            [&key_b64],
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('gateway_ca_vk', ?1)",
            [&vk_b64],
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('gateway_ca_ed25519_key', ?1)",
            [&ed_key_b64],
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('gateway_ca_ed25519_vk', ?1)",
            [&ed_vk_b64],
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('gateway_ca_cert', ?1)",
            [&cert_pem],
        )?;

        let signing_key = SecureBox::new(sk_bytes)
            .context("failed to create SecureBox for CA ML-DSA signing key")?;
        let ed25519_signing_key = SecureBox::new(ed_sk_bytes)
            .context("failed to create SecureBox for CA Ed25519 signing key")?;

        tracing::info!("gateway CA generated and stored (first boot, hybrid Ed25519 + ML-DSA-65)");
        Ok(Self {
            signing_key,
            verifying_key: vk_bytes,
            ed25519_signing_key,
            ed25519_verifying_key: ed_vk_bytes,
            cert_pem,
        })
    }

    /// Sign a device client certificate for `device_mac`.
    ///
    /// Returns the PEM-encoded certificate with both Ed25519 and ML-DSA-65
    /// signatures.
    pub fn sign_device_cert(&self, device_mac: &str, device_pub_key: &[u8]) -> Result<String> {
        let now = chrono::Utc::now();
        let not_after = now + chrono::Duration::days(3650);

        let mut payload = CertPayload {
            version: 2,
            subject: device_mac.to_string(),
            issuer: "secfirstgw-ca".into(),
            public_key: B64.encode(device_pub_key),
            ed25519_public_key: Some(B64.encode(&self.ed25519_verifying_key)),
            not_before: now.to_rfc3339(),
            not_after: not_after.to_rfc3339(),
            signature: String::new(),
            signature_ed25519: None,
        };

        let sk_bytes = self
            .signing_key
            .open()
            .context("failed to decrypt CA ML-DSA signing key from SecureBox")?;
        let ed_sk_bytes = self
            .ed25519_signing_key
            .open()
            .context("failed to decrypt CA Ed25519 signing key from SecureBox")?;

        let (ml_dsa_sig, ed_sig) =
            Self::sign_payload_hybrid_static(&sk_bytes, &ed_sk_bytes, &payload)?;
        payload.signature = ml_dsa_sig;
        payload.signature_ed25519 = Some(ed_sig);

        let pem = encode_pem(DEVICE_CERT_PEM_TAG, &serde_json::to_vec(&payload)?);
        Ok(pem)
    }

    /// Return the CA ML-DSA-65 public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.verifying_key
    }

    /// Return the CA Ed25519 public key bytes.
    pub fn ed25519_public_key(&self) -> &[u8] {
        &self.ed25519_verifying_key
    }

    /// Sign arbitrary data with both CA keys (hybrid Ed25519 + ML-DSA-65).
    ///
    /// Returns `(ml_dsa_65_signature, ed25519_signature)`.
    pub fn sign_hybrid(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let sk_bytes = self
            .signing_key
            .open()
            .context("failed to decrypt CA ML-DSA signing key from SecureBox")?;
        let ed_sk_bytes = self
            .ed25519_signing_key
            .open()
            .context("failed to decrypt CA Ed25519 signing key from SecureBox")?;

        // ML-DSA-65
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(
            sk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("CA ML-DSA signing key wrong length"))?,
        )
        .map_err(|e| anyhow::anyhow!("failed to deserialise CA ML-DSA signing key: {e:?}"))?;
        let ml_sig = sk
            .try_sign(data, b"")
            .map_err(|e| anyhow::anyhow!("ML-DSA-65 signing failed: {e:?}"))?;

        // Ed25519
        let ed_sk_arr: [u8; 32] = ed_sk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("CA Ed25519 signing key wrong length"))?;
        let ed_sk = SigningKey::from_bytes(&ed_sk_arr);
        let ed_sig = ed_sk.sign(data);

        Ok((ml_sig.to_vec(), ed_sig.to_bytes().to_vec()))
    }

    /// Sign arbitrary data with the CA key (ML-DSA-65 only).
    ///
    /// Retained for backwards compatibility; prefer [`sign_hybrid`].
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let (ml_sig, _) = self.sign_hybrid(data)?;
        Ok(ml_sig)
    }

    // Internal: produce base64 signatures (both Ed25519 + ML-DSA-65) over the
    // canonicalised cert fields.
    fn sign_payload_hybrid_static(
        ml_dsa_key: &[u8],
        ed25519_key: &[u8],
        p: &CertPayload,
    ) -> Result<(String, String)> {
        let canonical = format!(
            "v={};sub={};iss={};pk={};nb={};na={}",
            p.version, p.subject, p.issuer, p.public_key, p.not_before, p.not_after
        );

        // ML-DSA-65
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(
            ml_dsa_key
                .try_into()
                .map_err(|_| anyhow::anyhow!("ML-DSA signing key wrong length"))?,
        )
        .map_err(|e| anyhow::anyhow!("failed to deserialise ML-DSA signing key: {e:?}"))?;
        let ml_sig = sk
            .try_sign(canonical.as_bytes(), b"")
            .map_err(|e| anyhow::anyhow!("ML-DSA-65 signing failed: {e:?}"))?;

        // Ed25519
        let ed_sk_arr: [u8; 32] = ed25519_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("Ed25519 signing key wrong length"))?;
        let ed_sk = SigningKey::from_bytes(&ed_sk_arr);
        let ed_sig = ed_sk.sign(canonical.as_bytes());

        Ok((B64.encode(ml_sig), B64.encode(ed_sig.to_bytes())))
    }
}

// ---------------------------------------------------------------------------
// PEM helpers
// ---------------------------------------------------------------------------

fn encode_pem(tag: &str, der: &[u8]) -> String {
    let b64 = B64.encode(der);
    let mut pem = format!("-----BEGIN {tag}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {tag}-----\n"));
    pem
}

pub fn decode_pem(pem: &str) -> Result<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    B64.decode(body.trim())
        .context("invalid PEM base64")
}
