// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod secure_mem;

use anyhow::{Context, Result};
use ring::hkdf;

/// Path to the LUKS key file used in VM mode.
const VM_KEY_FILE: &str = "/etc/sfgw/luks.key";

/// HKDF info string for bare-metal key derivation.
const HKDF_INFO: &[u8] = b"secfirstgw-luks2-auto-unlock-v1";

/// Automatically unlock LUKS2 volumes using hardware-derived keys.
///
/// - Bare metal: derives key from hardware identity (product_serial + board_serial)
///   via HKDF-SHA256.
/// - VM: uses a key file at `/etc/sfgw/luks.key` if it exists.
/// - Docker: no-op (volumes are mounted from host).
pub async fn auto_unlock(platform: &sfgw_hal::Platform) -> Result<()> {
    match platform {
        sfgw_hal::Platform::Docker => {
            tracing::info!("docker mode — skipping disk encryption (using volume mounts)");
            Ok(())
        }
        sfgw_hal::Platform::Vm => auto_unlock_vm().await,
        sfgw_hal::Platform::BareMetal => auto_unlock_bare_metal().await,
    }
}

/// VM auto-unlock: look for a pre-provisioned key file.
async fn auto_unlock_vm() -> Result<()> {
    let key_path = std::path::Path::new(VM_KEY_FILE);
    if key_path.exists() {
        let mut key_data = tokio::fs::read(key_path)
            .await
            .with_context(|| format!("failed to read VM LUKS key file at {VM_KEY_FILE}"))?;

        tracing::info!("vm mode — found LUKS key file at {VM_KEY_FILE}");

        // TODO: call cryptsetup to unlock the LUKS2 volume with key_data
        // e.g. cryptsetup open --type luks2 --key-file=- /dev/sda2 sfgw-data

        // Zeroize key material after use
        zeroize::Zeroize::zeroize(&mut key_data[..]);
        Ok(())
    } else {
        tracing::info!(
            "vm mode — no LUKS key file at {VM_KEY_FILE}, skipping auto-unlock"
        );
        Ok(())
    }
}

/// Bare-metal auto-unlock: derive a LUKS key from hardware identity.
///
/// Reads `/sys/class/dmi/id/product_serial` and `/sys/class/dmi/id/board_serial`,
/// concatenates them, then runs HKDF-SHA256 to produce a 32-byte key.
async fn auto_unlock_bare_metal() -> Result<()> {
    let product_serial = read_dmi_field("product_serial").await?;
    let board_serial = read_dmi_field("board_serial").await?;

    if product_serial.is_empty() && board_serial.is_empty() {
        anyhow::bail!(
            "bare metal LUKS auto-unlock: both product_serial and board_serial are empty"
        );
    }

    // Build input keying material: product_serial || ":" || board_serial
    let mut ikm = Vec::with_capacity(product_serial.len() + 1 + board_serial.len());
    ikm.extend_from_slice(product_serial.as_bytes());
    ikm.push(b':');
    ikm.extend_from_slice(board_serial.as_bytes());

    // Derive key via HKDF-SHA256
    let mut derived_key = [0u8; 32];
    hkdf_sha256(&ikm, HKDF_INFO, &mut derived_key)?;

    tracing::info!("bare metal — derived LUKS key from hardware identity");

    // TODO: call cryptsetup to unlock the LUKS2 volume with derived_key
    // e.g. cryptsetup open --type luks2 --key-file=- /dev/sda2 sfgw-data

    // Zeroize all sensitive material
    zeroize::Zeroize::zeroize(&mut ikm[..]);
    zeroize::Zeroize::zeroize(&mut derived_key[..]);

    Ok(())
}

/// Read a DMI identity field, trimming whitespace.
async fn read_dmi_field(field: &str) -> Result<String> {
    let path = format!("/sys/class/dmi/id/{field}");
    match tokio::fs::read_to_string(&path).await {
        Ok(val) => Ok(val.trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            tracing::warn!("permission denied reading {path} — running without root?");
            Ok(String::new())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!("{path} not found — not a physical machine?");
            Ok(String::new())
        }
        Err(e) => Err(e).with_context(|| format!("failed to read {path}")),
    }
}

/// Derive a key using HKDF-SHA256 with no salt (salt = all zeros).
fn hkdf_sha256(ikm: &[u8], info: &[u8], out: &mut [u8; 32]) -> Result<()> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(ikm);
    let info_refs = [info];
    let okm = prk
        .expand(&info_refs, HkdfLen(32))
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    okm.fill(out)
        .map_err(|_| anyhow::anyhow!("HKDF fill failed"))?;
    Ok(())
}

/// Helper type for ring HKDF output length.
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_sha256_deterministic() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        hkdf_sha256(b"test-ikm", b"test-info", &mut out1).unwrap();
        hkdf_sha256(b"test-ikm", b"test-info", &mut out2).unwrap();
        assert_eq!(out1, out2);
        // Should not be all zeros
        assert!(out1.iter().any(|&b| b != 0));
    }

    #[test]
    fn hkdf_sha256_different_inputs() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        hkdf_sha256(b"input-a", HKDF_INFO, &mut out1).unwrap();
        hkdf_sha256(b"input-b", HKDF_INFO, &mut out2).unwrap();
        assert_ne!(out1, out2);
    }

    #[tokio::test]
    async fn docker_auto_unlock_is_noop() {
        // Should always succeed with no side effects
        auto_unlock(&sfgw_hal::Platform::Docker).await.unwrap();
    }
}
