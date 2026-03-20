// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

pub mod credential;
pub mod db_key;
pub mod secure_mem;

use anyhow::Context;
use ring::hkdf;
use std::path::Path;
use std::process::Command;

/// Errors from the crypto crate.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// I/O error (e.g., reading DMI fields, key files).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptographic operation failed.
    #[error("crypto operation failed: {0}")]
    CryptoFailed(String),

    /// Wrapped anyhow error for internal context propagation.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Convenience alias for results from this crate.
type Result<T> = std::result::Result<T, CryptoError>;

/// Path to the LUKS key file used in VM mode.
const VM_KEY_FILE: &str = "/etc/sfgw/luks.key";

/// Block device expected to hold the LUKS2 partition.
const LUKS_DEVICE: &str = "/dev/sda1";

/// dm-crypt mapper name for the unlocked volume.
const MAPPER_NAME: &str = "sfgw-data";

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

        let result = cryptsetup_open_keyfile(VM_KEY_FILE);

        // Zeroize key material after use (the on-disk file remains, but our copy is cleared)
        zeroize::Zeroize::zeroize(&mut key_data[..]);

        result
    } else {
        tracing::info!("vm mode — no LUKS key file at {VM_KEY_FILE}, skipping auto-unlock");
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
        // ARM boards (e.g. UDM Pro) have no DMI — skip LUKS for now.
        // TODO: use eMMC serial or /dev/ubnthal for hardware-bound key on ARM.
        tracing::warn!("bare metal — no DMI serial found (ARM?), skipping LUKS auto-unlock");
        return Ok(());
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

    let result = cryptsetup_open_stdin(&derived_key);

    // Zeroize all sensitive material
    zeroize::Zeroize::zeroize(&mut ikm[..]);
    zeroize::Zeroize::zeroize(&mut derived_key[..]);

    result
}

/// Open a LUKS2 volume using a key file on disk.
fn cryptsetup_open_keyfile(key_file: &str) -> Result<()> {
    if !Path::new(LUKS_DEVICE).exists() {
        tracing::info!("{LUKS_DEVICE} not found — no HDD present, skipping LUKS unlock");
        return Ok(());
    }

    if Path::new(&format!("/dev/mapper/{MAPPER_NAME}")).exists() {
        tracing::info!("/dev/mapper/{MAPPER_NAME} already exists — volume already unlocked");
        return Ok(());
    }

    let output = Command::new("cryptsetup")
        .args(["luksOpen", LUKS_DEVICE, MAPPER_NAME, "--key-file", key_file])
        .output()
        .context("failed to execute cryptsetup")?;

    if output.status.success() {
        tracing::info!("LUKS volume unlocked as /dev/mapper/{MAPPER_NAME}");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(CryptoError::CryptoFailed(format!(
            "cryptsetup luksOpen failed: {stderr}"
        )))
    }
}

/// Open a LUKS2 volume by piping key material to cryptsetup via stdin.
///
/// The key is written to stdin and never logged or written to disk.
fn cryptsetup_open_stdin(key: &[u8]) -> Result<()> {
    use std::io::Write;

    if !Path::new(LUKS_DEVICE).exists() {
        tracing::info!("{LUKS_DEVICE} not found — no HDD present, skipping LUKS unlock");
        return Ok(());
    }

    if Path::new(&format!("/dev/mapper/{MAPPER_NAME}")).exists() {
        tracing::info!("/dev/mapper/{MAPPER_NAME} already exists — volume already unlocked");
        return Ok(());
    }

    let mut child = Command::new("cryptsetup")
        .args(["luksOpen", LUKS_DEVICE, MAPPER_NAME, "--key-file", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn cryptsetup")?;

    // Write key to stdin — never log this data
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(key)
            .context("failed to write key to cryptsetup stdin")?;
        // stdin is dropped here, closing the pipe
    }

    let output = child
        .wait_with_output()
        .context("failed to wait for cryptsetup")?;

    if output.status.success() {
        tracing::info!("LUKS volume unlocked as /dev/mapper/{MAPPER_NAME}");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(CryptoError::CryptoFailed(format!(
            "cryptsetup luksOpen failed: {stderr}"
        )))
    }
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
        Err(e) => Err(anyhow::Error::from(e)
            .context(format!("failed to read {path}"))
            .into()),
    }
}

/// Derive a key using HKDF-SHA256 with no salt (salt = all zeros).
#[must_use = "failing to check HKDF result may use uninitialized key material"]
fn hkdf_sha256(ikm: &[u8], info: &[u8], out: &mut [u8; 32]) -> Result<()> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(ikm);
    let info_refs = [info];
    let okm = prk
        .expand(&info_refs, HkdfLen(32))
        .map_err(|_| CryptoError::CryptoFailed("HKDF expand failed".to_string()))?;
    okm.fill(out)
        .map_err(|_| CryptoError::CryptoFailed("HKDF fill failed".to_string()))?;
    Ok(())
}

/// Helper type for ring HKDF output length.
pub struct HkdfLen(pub usize);

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
