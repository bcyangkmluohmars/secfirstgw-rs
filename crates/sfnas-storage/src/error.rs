#![deny(unsafe_code)]

use thiserror::Error;

/// All errors that can occur in storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// mdadm command failed or returned unexpected output.
    #[error("mdadm command failed: {0}")]
    Mdadm(String),

    /// cryptsetup command failed.
    #[error("cryptsetup command failed: {0}")]
    Cryptsetup(String),

    /// btrfs command failed.
    #[error("btrfs command failed: {0}")]
    Btrfs(String),

    /// wipefs / partition tool command failed.
    #[error("disk tool command failed: {0}")]
    DiskTool(String),

    /// A disk was requested but does not exist.
    #[error("disk not found: {0}")]
    DiskNotFound(String),

    /// A bay slot is empty when a disk was expected.
    #[error("bay {0} is empty")]
    BayEmpty(u8),

    /// Bay slot number is out of range.
    #[error("invalid bay slot: {0} (valid: 0-3)")]
    InvalidBaySlot(u8),

    /// SMART self-assessment indicates a failing drive.
    #[error("SMART health check failed for {0}: {1}")]
    SmartFailed(String, String),

    /// A RAID array is in degraded state.
    #[error("array {0} is degraded")]
    ArrayDegraded(String),

    /// The RAID configuration is invalid (wrong disk count, etc.).
    #[error("invalid RAID configuration: {0}")]
    InvalidConfig(String),

    /// A dm-crypt volume is already open under this name.
    #[error("dm-crypt volume already open: {0}")]
    CryptAlreadyOpen(String),

    /// A dm-crypt volume is not open.
    #[error("dm-crypt volume not open: {0}")]
    CryptNotOpen(String),

    /// A subvolume or snapshot already exists at the given path.
    #[error("btrfs subvolume already exists: {0}")]
    SubvolumeExists(String),

    /// Parse error when reading system files (mdstat, sysfs, etc.).
    #[error("parse error: {0}")]
    Parse(String),

    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
