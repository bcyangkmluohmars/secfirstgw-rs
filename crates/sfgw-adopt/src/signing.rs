// SPDX-License-Identifier: AGPL-3.0-or-later

//! Config and firmware signing.
//!
//! Uses ML-DSA-65 (FIPS 204) via the gateway CA key to sign config blobs and
//! firmware manifests.  A device verifies the signature before applying any
//! update.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier};
use serde::{Deserialize, Serialize};

/// A signed envelope wrapping an arbitrary payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPayload {
    /// The raw payload bytes, base64-encoded.
    pub payload: String,
    /// ML-DSA-65 signature over the raw payload bytes, base64-encoded.
    pub signature_ml_dsa_65: String,
}

/// Sign `payload` with the gateway CA key, returning a [`SignedPayload`].
pub fn sign_config(payload: &[u8], ca: &crate::ca::GatewayCA) -> Result<SignedPayload> {
    let sig = ca.sign(payload)?;
    Ok(SignedPayload {
        payload: B64.encode(payload),
        signature_ml_dsa_65: B64.encode(&sig),
    })
}

/// Verify a [`SignedPayload`] against the given ML-DSA-65 public key.
pub fn verify_signature(signed: &SignedPayload, public_key: &[u8]) -> Result<Vec<u8>> {
    let payload_bytes = B64
        .decode(&signed.payload)
        .context("invalid base64 in signed payload")?;
    let sig_bytes = B64
        .decode(&signed.signature_ml_dsa_65)
        .context("invalid base64 in ML-DSA-65 signature")?;

    let vk_arr: &[u8; ml_dsa_65::PK_LEN] = public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("ML-DSA-65 public key wrong length"))?;
    let vk = ml_dsa_65::PublicKey::try_from_bytes(*vk_arr)
        .map_err(|e| anyhow::anyhow!("invalid ML-DSA-65 public key: {e:?}"))?;

    let sig_arr: [u8; ml_dsa_65::SIG_LEN] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| {
            anyhow::anyhow!(
                "ML-DSA-65 signature wrong length: expected {}, got {}",
                ml_dsa_65::SIG_LEN,
                sig_bytes.len()
            )
        })?;

    let valid = vk.verify(&payload_bytes, &sig_arr, b"");
    if !valid {
        anyhow::bail!("ML-DSA-65 signature verification failed");
    }

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
) -> Result<FirmwareManifest> {
    let inner = serde_json::json!({
        "version": version,
        "sha256": sha256,
        "url": url,
    });
    let payload = serde_json::to_vec(&inner).expect("JSON serialisation cannot fail");
    let signed = sign_config(&payload, ca)?;
    Ok(FirmwareManifest {
        version: version.to_string(),
        sha256: sha256.to_string(),
        url: url.to_string(),
        signed,
    })
}
