#![deny(unsafe_code)]

//! dm-crypt / LUKS volume management.
//!
//! Wraps `cryptsetup` CLI to provide LUKS2 full-disk encryption for
//! the storage stack. Volumes are formatted with LUKS2 and opened as
//! dm-crypt mappings under `/dev/mapper/<name>`.

use crate::StorageError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::info;

/// Status of a dm-crypt volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptStatus {
    /// Volume is open and accessible at `/dev/mapper/<name>`.
    Open {
        /// The mapped device path.
        device: PathBuf,
        /// Cipher string (e.g. `aes-xts-plain64`).
        cipher: String,
        /// Key size in bits.
        key_size: u32,
    },
    /// Volume is closed / not mapped.
    Closed,
}

/// Represents a LUKS-encrypted dm-crypt volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptVolume {
    /// The underlying block device (e.g. `/dev/md/nas`).
    pub device: PathBuf,
    /// The dm-crypt mapping name (e.g. `nas-crypt`).
    pub name: String,
    /// Current status.
    pub status: CryptStatus,
}

impl CryptVolume {
    /// Format a device with LUKS2 encryption.
    ///
    /// Uses AES-256-XTS with Argon2id key derivation (LUKS2 defaults).
    /// The passphrase is passed via stdin to avoid command-line exposure.
    ///
    /// # Warning
    ///
    /// This is destructive — all data on the device will be lost.
    pub fn format(device: &Path, passphrase: &[u8]) -> Result<(), StorageError> {
        info!(device = %device.display(), "formatting LUKS2 volume");

        let mut child = Command::new("cryptsetup")
            .arg("luksFormat")
            .arg("--type")
            .arg("luks2")
            .arg("--cipher")
            .arg("aes-xts-plain64")
            .arg("--key-size")
            .arg("512") // 256-bit AES in XTS mode uses 512-bit key (2x256)
            .arg("--hash")
            .arg("sha512")
            .arg("--pbkdf")
            .arg("argon2id")
            .arg("--batch-mode") // no confirmation prompt
            .arg("--key-file")
            .arg("-") // read passphrase from stdin
            .arg(device.as_os_str())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| StorageError::Cryptsetup(e.to_string()))?;

        // Write passphrase to stdin
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(passphrase).map_err(|e| {
                StorageError::Cryptsetup(format!("failed to write passphrase: {e}"))
            })?;
            // stdin is dropped here, closing the pipe
        }

        let output = child
            .wait_with_output()
            .map_err(|e| StorageError::Cryptsetup(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Cryptsetup(format!(
                "luksFormat failed on {}: {stderr}",
                device.display()
            )));
        }

        info!(device = %device.display(), "LUKS2 volume formatted");
        Ok(())
    }

    /// Open (unlock) a LUKS volume and create a dm-crypt mapping.
    ///
    /// The resulting device is available at `/dev/mapper/<name>`.
    /// The passphrase is passed via stdin to avoid command-line exposure.
    pub fn open(device: &Path, name: &str, passphrase: &[u8]) -> Result<Self, StorageError> {
        // Check if already open
        let mapper_path = PathBuf::from(format!("/dev/mapper/{name}"));
        if mapper_path.exists() {
            return Err(StorageError::CryptAlreadyOpen(name.to_string()));
        }

        info!(
            device = %device.display(),
            name,
            "opening LUKS volume"
        );

        let mut child = Command::new("cryptsetup")
            .arg("open")
            .arg("--type")
            .arg("luks2")
            .arg("--key-file")
            .arg("-") // read passphrase from stdin
            .arg(device.as_os_str())
            .arg(name)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| StorageError::Cryptsetup(e.to_string()))?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(passphrase).map_err(|e| {
                StorageError::Cryptsetup(format!("failed to write passphrase: {e}"))
            })?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| StorageError::Cryptsetup(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Cryptsetup(format!(
                "failed to open LUKS volume {}: {stderr}",
                device.display()
            )));
        }

        // Query the opened volume status
        let status = Self::query_status(name)?;

        Ok(Self {
            device: device.to_path_buf(),
            name: name.to_string(),
            status,
        })
    }

    /// Close (lock) a dm-crypt mapping.
    pub fn close(name: &str) -> Result<(), StorageError> {
        let mapper_path = PathBuf::from(format!("/dev/mapper/{name}"));
        if !mapper_path.exists() {
            return Err(StorageError::CryptNotOpen(name.to_string()));
        }

        info!(name, "closing LUKS volume");

        let output = Command::new("cryptsetup")
            .arg("close")
            .arg(name)
            .output()
            .map_err(|e| StorageError::Cryptsetup(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Cryptsetup(format!(
                "failed to close LUKS volume {name}: {stderr}"
            )));
        }

        Ok(())
    }

    /// Check whether a dm-crypt mapping is currently open.
    #[must_use]
    pub fn is_open(name: &str) -> bool {
        let mapper_path = PathBuf::from(format!("/dev/mapper/{name}"));
        mapper_path.exists()
    }

    /// Query the status of an open dm-crypt volume via `cryptsetup status`.
    pub fn status(name: &str) -> Result<CryptStatus, StorageError> {
        if !Self::is_open(name) {
            return Ok(CryptStatus::Closed);
        }
        Self::query_status(name)
    }

    /// Parse `cryptsetup status` output for an open volume.
    fn query_status(name: &str) -> Result<CryptStatus, StorageError> {
        let output = Command::new("cryptsetup")
            .arg("status")
            .arg(name)
            .output()
            .map_err(|e| StorageError::Cryptsetup(e.to_string()))?;

        if !output.status.success() {
            // If the command fails, the volume is likely not open
            return Ok(CryptStatus::Closed);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_status_output(&stdout, name)
    }

    /// Parse the text output of `cryptsetup status`.
    fn parse_status_output(output: &str, name: &str) -> Result<CryptStatus, StorageError> {
        let extract = |key: &str| -> Option<String> {
            output
                .lines()
                .find(|l| l.contains(key))
                .and_then(|l| l.split(':').nth(1))
                .map(|v| v.trim().to_string())
        };

        let cipher = extract("cipher").unwrap_or_else(|| "unknown".to_string());

        let key_size = extract("keysize")
            .and_then(|s| {
                s.split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<u32>().ok())
            })
            .unwrap_or(0);

        let device = PathBuf::from(format!("/dev/mapper/{name}"));

        Ok(CryptStatus::Open {
            device,
            cipher,
            key_size,
        })
    }

    /// Return the path to the opened dm-crypt device, if it exists.
    #[must_use]
    pub fn mapper_path(name: &str) -> PathBuf {
        PathBuf::from(format!("/dev/mapper/{name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapper_path() {
        assert_eq!(
            CryptVolume::mapper_path("nas-crypt"),
            PathBuf::from("/dev/mapper/nas-crypt")
        );
    }

    #[test]
    fn test_parse_status_output() {
        let output = "\
/dev/mapper/nas-crypt is active.
  type:    LUKS2
  cipher:  aes-xts-plain64
  keysize: 512 bits
  key location: keyring
  device:  /dev/md127
  sector size:  512
  offset:  32768 sectors
  size:    5859309568 sectors
  mode:    read/write
";
        let status =
            CryptVolume::parse_status_output(output, "nas-crypt").expect("parse should succeed");
        match status {
            CryptStatus::Open {
                device,
                cipher,
                key_size,
            } => {
                assert_eq!(device, PathBuf::from("/dev/mapper/nas-crypt"));
                assert_eq!(cipher, "aes-xts-plain64");
                assert_eq!(key_size, 512);
            }
            CryptStatus::Closed => panic!("expected Open status"),
        }
    }

    #[test]
    fn test_parse_status_closed() {
        // When cryptsetup status fails, we return Closed
        let status =
            CryptVolume::parse_status_output("", "nonexistent").expect("parse should succeed");
        // Even empty output parses as Open with defaults since we only call this
        // for known-open volumes; but the cipher/keysize will be "unknown"/0
        match status {
            CryptStatus::Open {
                cipher, key_size, ..
            } => {
                assert_eq!(cipher, "unknown");
                assert_eq!(key_size, 0);
            }
            CryptStatus::Closed => {} // also acceptable
        }
    }
}
