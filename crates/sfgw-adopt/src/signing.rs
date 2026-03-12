// SPDX-License-Identifier: AGPL-3.0-or-later

//! Config and firmware signing.
//!
//! Uses Ed25519 (via the gateway CA key) to sign config blobs and firmware
//! manifests.  A device verifies the signature before applying any update.
//!
//! **TODO**: Add ML-DSA-65 hybrid signing (FIPS 204) — the signature
//! envelope should carry both an Ed25519 and an ML-DSA-65 signature,
//! and both must verify for the payload to be accepted.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

/// A signed envelope wrapping an arbitrary payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPayload {
    /// The raw payload bytes, base64-encoded.
    pub payload: String,
    /// Ed25519 signature over the raw payload bytes, base64-encoded.
    pub signature_ed25519: String,
    /// **TODO**: ML-DSA-65 signature (placeholder).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_ml_dsa_65: Option<String>,
}

/// Sign `payload` with the gateway CA key, returning a [`SignedPayload`].
pub fn sign_config(payload: &[u8], ca: &crate::ca::GatewayCA) -> SignedPayload {
    let sig = ca.sign(payload);
    SignedPayload {
        payload: B64.encode(payload),
        signature_ed25519: B64.encode(&sig),
        signature_ml_dsa_65: None, // TODO: hybrid PQ signing
    }
}

/// Verify a [`SignedPayload`] against the given Ed25519 public key.
pub fn verify_signature(signed: &SignedPayload, public_key: &[u8]) -> Result<Vec<u8>> {
    let payload_bytes = B64
        .decode(&signed.payload)
        .context("invalid base64 in signed payload")?;
    let sig_bytes = B64
        .decode(&signed.signature_ed25519)
        .context("invalid base64 in Ed25519 signature")?;

    let pk = UnparsedPublicKey::new(&ED25519, public_key);
    pk.verify(&payload_bytes, &sig_bytes)
        .map_err(|_| anyhow::anyhow!("Ed25519 signature verification failed"))?;

    // TODO: also verify ML-DSA-65 signature when present.

    Ok(payload_bytes)
}

/// Sign a firmware manifest.
///
/// The manifest contains: version, sha256 hash of firmware blob, download URL.
/// Devices reject any firmware with version <= current (monotone version).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareManifest {
    pub version: String,
    pub sha256: String,
    pub url: String,
    pub signed: SignedPayload,
}

/// Create a signed firmware manifest.
pub fn sign_firmware_manifest(
    version: &str,
    sha256: &str,
    url: &str,
    ca: &crate::ca::GatewayCA,
) -> FirmwareManifest {
    let inner = serde_json::json!({
        "version": version,
        "sha256": sha256,
        "url": url,
    });
    let payload = serde_json::to_vec(&inner).expect("JSON serialisation cannot fail");
    let signed = sign_config(&payload, ca);
    FirmwareManifest {
        version: version.to_string(),
        sha256: sha256.to_string(),
        url: url.to_string(),
        signed,
    }
}
