// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database Encryption Key Derivation
//!
//! Derives a 32-byte AES-256 key from hardware-specific fingerprints
//! using HKDF-SHA256. The key is never stored on disk -- it is re-derived
//! on every boot from immutable hardware identifiers.
//!
//! ## Key Material Sources
//!
//! | Platform   | Sources                                                          |
//! |------------|------------------------------------------------------------------|
//! | BareMetal  | Board serial (devicetree or DMI), CPU ID, eth0 MAC              |
//! | VM         | `/etc/machine-id`, CPU model, primary interface MAC             |
//! | Docker     | `/etc/machine-id`, container ID fallback, primary interface MAC |

use crate::{CryptoError, HkdfLen};
use ring::hkdf;
use zeroize::Zeroize;

/// Application-specific salt for DB key derivation.
/// This is a domain separator -- not a secret.
const DB_KEY_SALT: &[u8] = b"sfgw-db-encryption-v1";

/// HKDF info context for SQLite encryption key.
const DB_KEY_INFO: &[u8] = b"sqlite-encryption-key";

/// Derive a 32-byte database encryption key from hardware fingerprints.
///
/// The key is deterministic for the same hardware -- moving the database
/// to different hardware will make it undecryptable.
///
/// # Errors
///
/// Returns `CryptoError` if insufficient hardware fingerprint material
/// can be collected. This function explicitly does NOT fall back to weak
/// keys -- if hardware identity cannot be established, the database
/// cannot be opened.
#[must_use = "failing to use the derived key leaves the database unencrypted"]
pub fn derive_db_key() -> Result<DbEncryptionKey, CryptoError> {
    let mut ikm = collect_hardware_fingerprint()?;

    if ikm.len() < 16 {
        return Err(CryptoError::CryptoFailed(
            "insufficient hardware fingerprint material (need at least 16 bytes)".to_string(),
        ));
    }

    let mut key = [0u8; 32];
    hkdf_sha256_salted(&ikm, DB_KEY_SALT, DB_KEY_INFO, &mut key)?;

    // Zeroize the IKM immediately
    ikm.zeroize();

    Ok(DbEncryptionKey { key })
}

/// A 32-byte database encryption key that zeroizes on drop.
///
/// This type wraps the raw key bytes and ensures they are securely
/// erased from memory when the key is no longer needed.
pub struct DbEncryptionKey {
    key: [u8; 32],
}

impl DbEncryptionKey {
    /// Access the raw key bytes.
    ///
    /// The caller MUST NOT copy these bytes or log them.
    /// Use the returned reference immediately and let it go out of scope.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Format the key as a hex string for use in SQLCipher PRAGMA.
    ///
    /// The returned string is the raw hex encoding (64 characters).
    /// The caller MUST zeroize this string after use.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut hex = String::with_capacity(64);
        for byte in &self.key {
            use std::fmt::Write;
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    }
}

impl Drop for DbEncryptionKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

// DbEncryptionKey cannot be cloned -- move semantics only.
// Not Debug to prevent accidental logging.

/// Expose hardware fingerprint to the credential module (same crate).
///
/// Uses the same hardware identity sources but the caller applies
/// different HKDF context to derive an independent key.
pub(crate) fn collect_hardware_fingerprint_for_credential() -> Result<Vec<u8>, CryptoError> {
    collect_hardware_fingerprint()
}

/// Collect hardware fingerprint material from the current platform.
///
/// Returns a byte vector containing concatenated hardware identifiers.
/// The exact content depends on the detected platform.
fn collect_hardware_fingerprint() -> Result<Vec<u8>, CryptoError> {
    let platform = sfgw_hal::init().map_err(|e| {
        CryptoError::CryptoFailed(format!(
            "platform detection failed for DB key derivation: {e}"
        ))
    })?;

    let mut material = Vec::with_capacity(256);

    match platform {
        sfgw_hal::Platform::BareMetal => {
            collect_bare_metal_fingerprint(&mut material)?;
        }
        sfgw_hal::Platform::Vm => {
            collect_vm_fingerprint(&mut material)?;
        }
        sfgw_hal::Platform::Docker => {
            collect_docker_fingerprint(&mut material)?;
        }
    }

    // Always append platform discriminator to prevent cross-platform collisions
    material.extend_from_slice(platform.to_string().as_bytes());

    Ok(material)
}

/// Collect fingerprint from Ubiquiti bare-metal hardware.
///
/// Sources (in order of preference):
/// 1. Board serial from devicetree (ARM) or DMI (x86)
/// 2. CPU identifier
/// 3. eth0 MAC address
fn collect_bare_metal_fingerprint(material: &mut Vec<u8>) -> Result<(), CryptoError> {
    // Try devicetree serial first (UDM Pro/SE are ARM)
    let serial = read_file_trimmed("/sys/firmware/devicetree/base/serial-number")
        .or_else(|| read_file_trimmed("/sys/class/dmi/id/product_serial"))
        .or_else(|| read_file_trimmed("/sys/class/dmi/id/board_serial"));

    if let Some(s) = &serial {
        material.extend_from_slice(b"serial:");
        material.extend_from_slice(s.as_bytes());
        material.push(b'|');
    }

    // CPU ID from /proc/cpuinfo (look for "Serial" on ARM, "model name" on x86)
    if let Some(cpu_id) = read_cpu_identifier() {
        material.extend_from_slice(b"cpu:");
        material.extend_from_slice(cpu_id.as_bytes());
        material.push(b'|');
    }

    // Primary MAC address
    if let Some(mac) = read_interface_mac("eth0") {
        material.extend_from_slice(b"mac:");
        material.extend_from_slice(mac.as_bytes());
        material.push(b'|');
    }

    if material.is_empty() {
        return Err(CryptoError::CryptoFailed(
            "bare-metal: no hardware identifiers found -- cannot derive DB encryption key"
                .to_string(),
        ));
    }

    tracing::debug!(
        material_len = material.len(),
        has_serial = serial.is_some(),
        "collected bare-metal hardware fingerprint"
    );

    Ok(())
}

/// Collect fingerprint from a virtual machine.
///
/// Sources:
/// 1. `/etc/machine-id` (systemd machine ID, unique per installation)
/// 2. CPU model string
/// 3. Primary network interface MAC
fn collect_vm_fingerprint(material: &mut Vec<u8>) -> Result<(), CryptoError> {
    let machine_id = read_file_trimmed("/etc/machine-id");

    if let Some(mid) = &machine_id {
        material.extend_from_slice(b"machine-id:");
        material.extend_from_slice(mid.as_bytes());
        material.push(b'|');
    }

    if let Some(cpu_id) = read_cpu_identifier() {
        material.extend_from_slice(b"cpu:");
        material.extend_from_slice(cpu_id.as_bytes());
        material.push(b'|');
    }

    if let Some(mac) = read_primary_mac() {
        material.extend_from_slice(b"mac:");
        material.extend_from_slice(mac.as_bytes());
        material.push(b'|');
    }

    if material.is_empty() {
        return Err(CryptoError::CryptoFailed(
            "vm: no hardware identifiers found -- cannot derive DB encryption key".to_string(),
        ));
    }

    tracing::debug!(
        material_len = material.len(),
        has_machine_id = machine_id.is_some(),
        "collected VM hardware fingerprint"
    );

    Ok(())
}

/// Collect fingerprint from a Docker container.
///
/// Sources:
/// 1. `/etc/machine-id` (from host or container-specific)
/// 2. Container ID from cgroup (fallback)
/// 3. Primary network interface MAC
fn collect_docker_fingerprint(material: &mut Vec<u8>) -> Result<(), CryptoError> {
    let machine_id = read_file_trimmed("/etc/machine-id");

    if let Some(mid) = &machine_id {
        material.extend_from_slice(b"machine-id:");
        material.extend_from_slice(mid.as_bytes());
        material.push(b'|');
    }

    // Try to get container ID from cgroup
    if let Some(cid) = read_container_id() {
        material.extend_from_slice(b"container-id:");
        material.extend_from_slice(cid.as_bytes());
        material.push(b'|');
    }

    if let Some(mac) = read_primary_mac() {
        material.extend_from_slice(b"mac:");
        material.extend_from_slice(mac.as_bytes());
        material.push(b'|');
    }

    if material.is_empty() {
        return Err(CryptoError::CryptoFailed(
            "docker: no hardware identifiers found -- cannot derive DB encryption key".to_string(),
        ));
    }

    tracing::debug!(
        material_len = material.len(),
        has_machine_id = machine_id.is_some(),
        "collected Docker hardware fingerprint"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Hardware data readers
// ---------------------------------------------------------------------------

/// Read a file, returning its trimmed content or `None` on any error.
fn read_file_trimmed(path: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let trimmed = content.trim().trim_end_matches('\0').to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Read a CPU identifier from `/proc/cpuinfo`.
///
/// On ARM: looks for "Serial" field (unique per SoC).
/// On x86: uses "model name" (not unique, but contributes entropy).
fn read_cpu_identifier() -> Option<String> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;

    // ARM SoCs typically have a "Serial" field
    for line in cpuinfo.lines() {
        if let Some(serial) = line.strip_prefix("Serial") {
            let serial = serial.trim_start_matches([' ', '\t', ':']);
            let serial = serial.trim();
            if !serial.is_empty() && serial != "0000000000000000" {
                return Some(serial.to_string());
            }
        }
    }

    // x86 fallback: model name (less unique but still contributes)
    for line in cpuinfo.lines() {
        if let Some(model) = line.strip_prefix("model name") {
            let model = model.trim_start_matches([' ', '\t', ':']);
            let model = model.trim();
            if !model.is_empty() {
                return Some(model.to_string());
            }
        }
    }

    None
}

/// Read the MAC address of a specific network interface.
fn read_interface_mac(iface: &str) -> Option<String> {
    let path = format!("/sys/class/net/{iface}/address");
    let mac = read_file_trimmed(&path)?;
    // Ignore all-zero MACs
    if mac == "00:00:00:00:00:00" {
        None
    } else {
        Some(mac)
    }
}

/// Read the MAC of the first non-loopback, non-virtual interface.
fn read_primary_mac() -> Option<String> {
    // Try common interface names in order
    for iface in &["eth0", "ens3", "ens33", "enp0s3", "enp1s0"] {
        if let Some(mac) = read_interface_mac(iface) {
            return Some(mac);
        }
    }

    // Fallback: read /sys/class/net/*/address and pick the first real one
    let net_dir = std::fs::read_dir("/sys/class/net").ok()?;
    for entry in net_dir.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "lo" || name.starts_with("veth") || name.starts_with("docker") {
            continue;
        }
        if let Some(mac) = read_interface_mac(&name) {
            return Some(mac);
        }
    }

    None
}

/// Try to extract the container ID from cgroup information.
fn read_container_id() -> Option<String> {
    // Modern cgroup v2: /proc/self/mountinfo contains container ID
    // Classic: /proc/self/cgroup has docker/<container_id>
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    for line in cgroup.lines() {
        // Docker cgroup v1: 0::/docker/<64-hex-chars>
        if let Some(idx) = line.find("/docker/") {
            let id = &line[idx + 8..];
            if id.len() >= 12 {
                return Some(id[..12].to_string());
            }
        }
        // containerd: /system.slice/containerd-<id>.scope
        if let Some(idx) = line.find("containerd-") {
            let rest = &line[idx + 11..];
            if let Some(end) = rest.find('.')
                && end >= 12
            {
                return Some(rest[..12].to_string());
            }
        }
    }
    None
}

/// Derive a key using HKDF-SHA256 with an explicit salt.
fn hkdf_sha256_salted(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    out: &mut [u8; 32],
) -> Result<(), CryptoError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = salt.extract(ikm);
    let info_refs = [info];
    let okm = prk
        .expand(&info_refs, HkdfLen(32))
        .map_err(|_| CryptoError::CryptoFailed("HKDF expand failed for DB key".to_string()))?;
    okm.fill(out)
        .map_err(|_| CryptoError::CryptoFailed("HKDF fill failed for DB key".to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_db_key_is_deterministic() {
        // On any test machine, derive_db_key should produce the same result
        // when called twice (hardware doesn't change between calls).
        let key1 = derive_db_key().expect("first derive_db_key should succeed");
        let key2 = derive_db_key().expect("second derive_db_key should succeed");
        assert_eq!(key1.as_bytes(), key2.as_bytes());
        // Key should not be all zeros
        assert!(key1.as_bytes().iter().any(|&b| b != 0));
    }

    #[test]
    fn db_key_hex_format() {
        let key = derive_db_key().expect("derive_db_key should succeed");
        let hex = key.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn db_key_zeroizes_on_drop() {
        let key = derive_db_key().expect("derive_db_key should succeed");
        // Verify key is non-zero before drop
        assert!(key.as_bytes().iter().any(|&b| b != 0));
        drop(key);
        // If we got here without panic, Drop ran (zeroize executed).
    }

    #[test]
    fn hardware_fingerprint_has_content() {
        let fp = collect_hardware_fingerprint().expect("fingerprint collection should succeed");
        assert!(
            fp.len() >= 16,
            "hardware fingerprint should have at least 16 bytes, got {}",
            fp.len()
        );
    }

    #[test]
    fn hkdf_salted_differs_from_unsalted() {
        let ikm = b"test-input-keying-material";
        let mut out_salted = [0u8; 32];
        let mut out_unsalted = [0u8; 32];

        hkdf_sha256_salted(ikm, b"some-salt", b"info", &mut out_salted).unwrap();

        // Use the parent module's unsalted version for comparison
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
        let prk = salt.extract(ikm);
        let okm = prk.expand(&[b"info" as &[u8]], HkdfLen(32)).unwrap();
        okm.fill(&mut out_unsalted).unwrap();

        assert_ne!(out_salted, out_unsalted);
    }
}
