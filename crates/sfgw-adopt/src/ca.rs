// SPDX-License-Identifier: AGPL-3.0-or-later

//! Gateway Certificate Authority.
//!
//! Manages the gateway's Ed25519 CA keypair used to sign device client
//! certificates during adoption.  The CA key is stored in the `meta` table
//! (key = `gateway_ca_key`) and the certificate in `gateway_ca_cert`.
//!
//! **TODO**: wrap the private key in `SecureBox<T>` so it is mlock'd,
//! zeroize-on-drop, and encrypted at rest in RAM.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
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
    pub not_before: String,
    pub not_after: String,
    /// Ed25519 signature over the above fields (base64).
    pub signature: String,
}

/// In-memory representation of the gateway CA.
pub struct GatewayCA {
    keypair: Ed25519KeyPair,
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

        let existing_cert: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'gateway_ca_cert'",
                [],
                |row| row.get(0),
            )
            .ok();

        if let (Some(key_b64), Some(cert_pem)) = (existing_key, existing_cert) {
            let pkcs8 = B64
                .decode(&key_b64)
                .context("corrupt CA key in database")?;
            let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8)
                .map_err(|e| anyhow::anyhow!("failed to load CA keypair: {e}"))?;
            tracing::info!("gateway CA loaded from database");
            return Ok(Self { keypair, cert_pem });
        }

        // ---- First-boot: generate a new CA keypair ----
        let rng = SystemRandom::new();
        let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| anyhow::anyhow!("CA keygen failed: {e}"))?;
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref())
            .map_err(|e| anyhow::anyhow!("failed to parse generated CA key: {e}"))?;

        let now = chrono::Utc::now();
        let not_after = now + chrono::Duration::days(3650); // 10 years

        let pub_key_b64 = B64.encode(keypair.public_key().as_ref());

        // Build the self-signed CA certificate.
        let mut payload = CertPayload {
            version: 1,
            subject: "secfirstgw-ca".into(),
            issuer: "secfirstgw-ca".into(),
            public_key: pub_key_b64,
            not_before: now.to_rfc3339(),
            not_after: not_after.to_rfc3339(),
            signature: String::new(),
        };
        payload.signature = Self::sign_payload_static(&keypair, &payload)?;

        let cert_pem = encode_pem(CA_CERT_PEM_TAG, &serde_json::to_vec(&payload)?);

        // Persist — TODO: encrypt CA key with SecureBox before storing.
        let key_b64 = B64.encode(pkcs8_doc.as_ref());
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('gateway_ca_key', ?1)",
            [&key_b64],
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('gateway_ca_cert', ?1)",
            [&cert_pem],
        )?;

        tracing::info!("gateway CA generated and stored (first boot)");
        Ok(Self { keypair, cert_pem })
    }

    /// Sign a device client certificate for `device_mac`.
    ///
    /// Returns the PEM-encoded certificate.
    pub fn sign_device_cert(&self, device_mac: &str, device_pub_key: &[u8]) -> Result<String> {
        let now = chrono::Utc::now();
        let not_after = now + chrono::Duration::days(3650);

        let mut payload = CertPayload {
            version: 1,
            subject: device_mac.to_string(),
            issuer: "secfirstgw-ca".into(),
            public_key: B64.encode(device_pub_key),
            not_before: now.to_rfc3339(),
            not_after: not_after.to_rfc3339(),
            signature: String::new(),
        };
        payload.signature = Self::sign_payload_static(&self.keypair, &payload)?;

        let pem = encode_pem(DEVICE_CERT_PEM_TAG, &serde_json::to_vec(&payload)?);
        Ok(pem)
    }

    /// Return the CA public key bytes (Ed25519).
    pub fn public_key(&self) -> &[u8] {
        self.keypair.public_key().as_ref()
    }

    /// Sign arbitrary data with the CA key.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.keypair.sign(data).as_ref().to_vec()
    }

    // Internal: produce a base64 signature over the canonicalised cert fields.
    fn sign_payload_static(keypair: &Ed25519KeyPair, p: &CertPayload) -> Result<String> {
        let canonical = format!(
            "v={};sub={};iss={};pk={};nb={};na={}",
            p.version, p.subject, p.issuer, p.public_key, p.not_before, p.not_after
        );
        let sig = keypair.sign(canonical.as_bytes());
        Ok(B64.encode(sig.as_ref()))
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
