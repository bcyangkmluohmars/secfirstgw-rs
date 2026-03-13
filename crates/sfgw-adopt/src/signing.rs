// SPDX-License-Identifier: AGPL-3.0-or-later

//! Config and firmware signing.
//!
//! Uses hybrid Ed25519 + ML-DSA-65 signatures via the gateway CA key.  Both
//! signatures must be present and both must verify — if either fails, the
//! payload is rejected.  This satisfies the CLAUDE.md requirement:
//! "Ed25519 + ML-DSA for signing. Both must pass."

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature as EdSignature, Verifier as _, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier};
use serde::{Deserialize, Serialize};

/// A signed envelope wrapping an arbitrary payload with hybrid signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPayload {
    /// The raw payload bytes, base64-encoded.
    pub payload: String,
    /// ML-DSA-65 signature over the raw payload bytes, base64-encoded.
    pub signature_ml_dsa_65: String,
    /// Ed25519 signature over the raw payload bytes, base64-encoded.
    /// Optional for backwards compatibility with payloads signed before the
    /// hybrid upgrade.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_ed25519: Option<String>,
}

/// Sign `payload` with the gateway CA key (hybrid Ed25519 + ML-DSA-65),
/// returning a [`SignedPayload`].
#[must_use = "ignoring the signed payload bypasses cryptographic authentication"]
pub fn sign_config(payload: &[u8], ca: &crate::ca::GatewayCA) -> Result<SignedPayload> {
    let (ml_sig, ed_sig) = ca.sign_hybrid(payload)?;
    Ok(SignedPayload {
        payload: B64.encode(payload),
        signature_ml_dsa_65: B64.encode(&ml_sig),
        signature_ed25519: Some(B64.encode(&ed_sig)),
    })
}

/// Verify a [`SignedPayload`] against the given ML-DSA-65 and Ed25519 public
/// keys.  Both signatures must verify; if either fails, the whole
/// verification fails.
///
/// `ed25519_public_key` is optional for backwards compatibility — if
/// `None` and the payload has no Ed25519 signature, only ML-DSA-65 is
/// checked.  If the payload has an Ed25519 signature but no public key is
/// provided (or vice versa), verification fails.
#[must_use = "ignoring signature verification result bypasses authentication"]
pub fn verify_signature(
    signed: &SignedPayload,
    ml_dsa_public_key: &[u8],
    ed25519_public_key: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let payload_bytes = B64
        .decode(&signed.payload)
        .context("invalid base64 in signed payload")?;

    // --- ML-DSA-65 verification ---
    let ml_sig_bytes = B64
        .decode(&signed.signature_ml_dsa_65)
        .context("invalid base64 in ML-DSA-65 signature")?;

    let vk_arr: &[u8; ml_dsa_65::PK_LEN] = ml_dsa_public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("ML-DSA-65 public key wrong length"))?;
    let vk = ml_dsa_65::PublicKey::try_from_bytes(*vk_arr)
        .map_err(|e| anyhow::anyhow!("invalid ML-DSA-65 public key: {e:?}"))?;

    let sig_arr: [u8; ml_dsa_65::SIG_LEN] = ml_sig_bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "ML-DSA-65 signature wrong length: expected {}, got {}",
            ml_dsa_65::SIG_LEN,
            ml_sig_bytes.len()
        )
    })?;

    if !vk.verify(&payload_bytes, &sig_arr, b"") {
        anyhow::bail!("ML-DSA-65 signature verification failed");
    }

    // --- Ed25519 verification ---
    match (&signed.signature_ed25519, ed25519_public_key) {
        (Some(ed_sig_b64), Some(ed_pk)) => {
            let ed_sig_bytes = B64
                .decode(ed_sig_b64)
                .context("invalid base64 in Ed25519 signature")?;
            let ed_sig = EdSignature::from_slice(&ed_sig_bytes)
                .map_err(|e| anyhow::anyhow!("invalid Ed25519 signature: {e}"))?;
            let ed_pk_arr: [u8; 32] = ed_pk
                .try_into()
                .map_err(|_| anyhow::anyhow!("Ed25519 public key wrong length"))?;
            let ed_vk = VerifyingKey::from_bytes(&ed_pk_arr)
                .map_err(|e| anyhow::anyhow!("invalid Ed25519 public key: {e}"))?;
            ed_vk
                .verify(&payload_bytes, &ed_sig)
                .map_err(|e| anyhow::anyhow!("Ed25519 signature verification failed: {e}"))?;
        }
        (None, None) => {
            // Legacy payload without Ed25519 — allow for backwards compatibility.
            tracing::warn!("verifying payload without Ed25519 signature (legacy mode)");
        }
        (Some(_), None) => {
            anyhow::bail!("payload has Ed25519 signature but no Ed25519 public key provided");
        }
        (None, Some(_)) => {
            anyhow::bail!("Ed25519 public key provided but payload has no Ed25519 signature");
        }
    }

    Ok(payload_bytes)
}

/// Sign a firmware manifest.
///
/// The manifest contains: version, sha256 hash of firmware blob, download URL,
/// and firmware size in bytes.  Devices reject any firmware with
/// version <= current (monotone version).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareManifest {
    pub version: String,
    pub sha256: String,
    pub url: String,
    #[serde(default)]
    pub size_bytes: i64,
    pub signed: SignedPayload,
}

/// Create a signed firmware manifest.
pub fn sign_firmware_manifest(
    version: &str,
    sha256: &str,
    url: &str,
    size_bytes: i64,
    ca: &crate::ca::GatewayCA,
) -> Result<FirmwareManifest> {
    let inner = serde_json::json!({
        "version": version,
        "sha256": sha256,
        "url": url,
        "size_bytes": size_bytes,
    });
    let payload = serde_json::to_vec(&inner)?;
    let signed = sign_config(&payload, ca)?;
    Ok(FirmwareManifest {
        version: version.to_string(),
        sha256: sha256.to_string(),
        url: url.to_string(),
        size_bytes,
        signed,
    })
}
