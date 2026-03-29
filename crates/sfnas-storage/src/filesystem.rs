#![deny(unsafe_code)]

//! Btrfs filesystem management.
//!
//! Wraps `mkfs.btrfs`, `btrfs subvolume`, and `btrfs scrub` to provide
//! a clean API for formatting, mounting, and managing Btrfs volumes and
//! subvolumes.
//!
//! In the secfirstNAS stack, Btrfs sits on top of dm-crypt in "single"
//! data/metadata mode (since redundancy comes from the underlying MD RAID).

use crate::StorageError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::info;

/// Status of a Btrfs scrub operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScrubStatus {
    /// Scrub is currently running.
    Running {
        /// Percentage completed (0.0 – 100.0).
        progress: f32,
    },
    /// Scrub completed successfully.
    Finished {
        /// Total bytes scrubbed.
        bytes_scrubbed: u64,
        /// Number of errors found.
        errors: u64,
    },
    /// No scrub has been run or status is unavailable.
    Idle,
}

/// Represents a Btrfs filesystem volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtrfsVolume {
    /// The block device holding the filesystem (e.g. `/dev/mapper/nas-crypt`).
    pub device: PathBuf,
    /// Current mount point, if mounted.
    pub mount_point: Option<PathBuf>,
    /// Filesystem UUID.
    pub uuid: String,
    /// Filesystem label.
    pub label: String,
}

impl BtrfsVolume {
    /// Format a device with Btrfs.
    ///
    /// Uses single data/metadata profile since redundancy is provided
    /// by the underlying MD RAID array. Enables LZ4 compression by default
    /// via mount options (not mkfs — compression is a mount-time option).
    ///
    /// # Warning
    ///
    /// This is destructive — all data on the device will be lost.
    pub fn format(device: &Path, label: &str) -> Result<Self, StorageError> {
        info!(
            device = %device.display(),
            label,
            "formatting Btrfs filesystem"
        );

        let output = Command::new("mkfs.btrfs")
            .arg("--force") // allow formatting even if signatures exist
            .arg("--label")
            .arg(label)
            .arg("--data")
            .arg("single")
            .arg("--metadata")
            .arg("single")
            .arg(device.as_os_str())
            .output()
            .map_err(|e| StorageError::Btrfs(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Btrfs(format!(
                "mkfs.btrfs failed on {}: {stderr}",
                device.display()
            )));
        }

        // Extract UUID from mkfs output
        let stdout = String::from_utf8_lossy(&output.stdout);
        let uuid = stdout
            .lines()
            .find(|l| l.contains("UUID"))
            .and_then(|l| l.split(':').nth(1))
            .map(|v| v.trim().to_string())
            .unwrap_or_default();

        info!(
            device = %device.display(),
            uuid = %uuid,
            "Btrfs filesystem created"
        );

        Ok(Self {
            device: device.to_path_buf(),
            mount_point: None,
            uuid,
            label: label.to_string(),
        })
    }

    /// Mount a Btrfs filesystem with ZSTD compression enabled.
    ///
    /// Mount options: `compress=zstd,noatime,space_cache=v2`
    pub fn mount(device: &Path, mount_path: &Path) -> Result<(), StorageError> {
        // Ensure mount point directory exists
        if !mount_path.exists() {
            std::fs::create_dir_all(mount_path).map_err(|e| {
                StorageError::Btrfs(format!(
                    "failed to create mount point {}: {e}",
                    mount_path.display()
                ))
            })?;
        }

        info!(
            device = %device.display(),
            mount_point = %mount_path.display(),
            "mounting Btrfs filesystem"
        );

        let output = Command::new("mount")
            .arg("-t")
            .arg("btrfs")
            .arg("-o")
            .arg("compress=zstd,noatime,space_cache=v2")
            .arg(device.as_os_str())
            .arg(mount_path.as_os_str())
            .output()
            .map_err(|e| StorageError::Btrfs(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Btrfs(format!(
                "mount failed for {} at {}: {stderr}",
                device.display(),
                mount_path.display()
            )));
        }

        Ok(())
    }

    /// Unmount a Btrfs filesystem.
    pub fn unmount(mount_path: &Path) -> Result<(), StorageError> {
        info!(mount_point = %mount_path.display(), "unmounting Btrfs filesystem");

        let output = Command::new("umount")
            .arg(mount_path.as_os_str())
            .output()
            .map_err(|e| StorageError::Btrfs(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Btrfs(format!(
                "umount failed for {}: {stderr}",
                mount_path.display()
            )));
        }

        Ok(())
    }

    /// Create a Btrfs subvolume at the given path.
    ///
    /// Subvolumes are used to separate NAS file shares from NVR recording
    /// storage, allowing independent snapshot policies.
    pub fn create_subvolume(mount_point: &Path, name: &str) -> Result<PathBuf, StorageError> {
        let subvol_path = mount_point.join(name);

        if subvol_path.exists() {
            return Err(StorageError::SubvolumeExists(
                subvol_path.display().to_string(),
            ));
        }

        info!(
            path = %subvol_path.display(),
            "creating Btrfs subvolume"
        );

        let output = Command::new("btrfs")
            .arg("subvolume")
            .arg("create")
            .arg(subvol_path.as_os_str())
            .output()
            .map_err(|e| StorageError::Btrfs(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Btrfs(format!(
                "subvolume create failed at {}: {stderr}",
                subvol_path.display()
            )));
        }

        Ok(subvol_path)
    }

    /// Delete a Btrfs subvolume.
    pub fn delete_subvolume(subvol_path: &Path) -> Result<(), StorageError> {
        info!(
            path = %subvol_path.display(),
            "deleting Btrfs subvolume"
        );

        let output = Command::new("btrfs")
            .arg("subvolume")
            .arg("delete")
            .arg(subvol_path.as_os_str())
            .output()
            .map_err(|e| StorageError::Btrfs(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Btrfs(format!(
                "subvolume delete failed at {}: {stderr}",
                subvol_path.display()
            )));
        }

        Ok(())
    }

    /// List subvolumes under a mount point.
    pub fn list_subvolumes(mount_point: &Path) -> Result<Vec<SubvolumeInfo>, StorageError> {
        let output = Command::new("btrfs")
            .arg("subvolume")
            .arg("list")
            .arg(mount_point.as_os_str())
            .output()
            .map_err(|e| StorageError::Btrfs(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Btrfs(format!(
                "subvolume list failed at {}: {stderr}",
                mount_point.display()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let subvols = Self::parse_subvolume_list(&stdout);
        Ok(subvols)
    }

    /// Parse the output of `btrfs subvolume list`.
    ///
    /// Each line looks like:
    /// `ID 257 gen 8 top level 5 path nas-data`
    fn parse_subvolume_list(output: &str) -> Vec<SubvolumeInfo> {
        output
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // Expected: ID <id> gen <gen> top level <tl> path <path>
                if parts.len() < 9 {
                    return None;
                }
                let id = parts.get(1).and_then(|v| v.parse::<u64>().ok())?;
                let generation = parts.get(3).and_then(|v| v.parse::<u64>().ok())?;
                let top_level = parts.get(6).and_then(|v| v.parse::<u64>().ok())?;
                let path = parts.get(8).map(|v| v.to_string())?;

                Some(SubvolumeInfo {
                    id,
                    generation,
                    top_level,
                    path,
                })
            })
            .collect()
    }

    /// Create a read-only snapshot of a subvolume.
    ///
    /// Snapshots are created as sibling directories alongside the source
    /// subvolume, with a `.snap` suffix and timestamp.
    pub fn snapshot(subvol_path: &Path, snapshot_name: &str) -> Result<PathBuf, StorageError> {
        let parent = subvol_path.parent().ok_or_else(|| {
            StorageError::Btrfs(format!(
                "cannot determine parent directory of {}",
                subvol_path.display()
            ))
        })?;
        let snapshot_path = parent.join(snapshot_name);

        if snapshot_path.exists() {
            return Err(StorageError::SubvolumeExists(
                snapshot_path.display().to_string(),
            ));
        }

        info!(
            source = %subvol_path.display(),
            snapshot = %snapshot_path.display(),
            "creating Btrfs snapshot"
        );

        let output = Command::new("btrfs")
            .arg("subvolume")
            .arg("snapshot")
            .arg("-r") // read-only snapshot
            .arg(subvol_path.as_os_str())
            .arg(snapshot_path.as_os_str())
            .output()
            .map_err(|e| StorageError::Btrfs(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Btrfs(format!(
                "snapshot creation failed from {} to {}: {stderr}",
                subvol_path.display(),
                snapshot_path.display()
            )));
        }

        Ok(snapshot_path)
    }

    /// Initiate a Btrfs scrub on a mounted filesystem.
    ///
    /// Scrub reads all data and metadata and verifies checksums,
    /// repairing any corruption using redundant copies where available.
    pub fn scrub(mount_path: &Path) -> Result<(), StorageError> {
        info!(
            mount_point = %mount_path.display(),
            "initiating Btrfs scrub"
        );

        let output = Command::new("btrfs")
            .arg("scrub")
            .arg("start")
            .arg(mount_path.as_os_str())
            .output()
            .map_err(|e| StorageError::Btrfs(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Btrfs(format!(
                "scrub start failed on {}: {stderr}",
                mount_path.display()
            )));
        }

        Ok(())
    }

    /// Query the status of a running or completed Btrfs scrub.
    pub fn scrub_status(mount_path: &Path) -> Result<ScrubStatus, StorageError> {
        let output = Command::new("btrfs")
            .arg("scrub")
            .arg("status")
            .arg(mount_path.as_os_str())
            .output()
            .map_err(|e| StorageError::Btrfs(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_scrub_status(&stdout)
    }

    /// Parse the output of `btrfs scrub status`.
    fn parse_scrub_status(output: &str) -> Result<ScrubStatus, StorageError> {
        let lower = output.to_lowercase();

        if lower.contains("no stats available") {
            return Ok(ScrubStatus::Idle);
        }

        // Check the "Status:" line specifically for state — "Scrub started:"
        // appears in both running and completed output and is not a state indicator.
        let status_line = lower
            .lines()
            .find(|l| l.trim_start().starts_with("status:"))
            .unwrap_or("");

        if status_line.contains("running") {
            // Try to extract progress — btrfs scrub status -R shows progress
            return Ok(ScrubStatus::Running { progress: 0.0 });
        }

        if status_line.contains("finished")
            || status_line.contains("completed")
            || lower.contains("finished")
        {
            // Parse bytes_scrubbed and error count
            let bytes_scrubbed = output
                .lines()
                .find(|l| l.to_lowercase().contains("data_bytes_scrubbed"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(0);

            let errors = output
                .lines()
                .find(|l| l.to_lowercase().contains("errors"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(0);

            return Ok(ScrubStatus::Finished {
                bytes_scrubbed,
                errors,
            });
        }

        Ok(ScrubStatus::Idle)
    }

    /// Get Btrfs filesystem usage information.
    pub fn usage(mount_path: &Path) -> Result<BtrfsUsage, StorageError> {
        let output = Command::new("btrfs")
            .arg("filesystem")
            .arg("usage")
            .arg("-b") // bytes
            .arg(mount_path.as_os_str())
            .output()
            .map_err(|e| StorageError::Btrfs(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Btrfs(format!(
                "filesystem usage failed on {}: {stderr}",
                mount_path.display()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_usage(&stdout)
    }

    /// Parse the output of `btrfs filesystem usage -b`.
    fn parse_usage(output: &str) -> Result<BtrfsUsage, StorageError> {
        let extract_bytes = |key: &str| -> u64 {
            output
                .lines()
                .find(|l| l.contains(key))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| {
                    v.split_whitespace()
                        .next()
                        .and_then(|n| n.parse::<u64>().ok())
                })
                .unwrap_or(0)
        };

        Ok(BtrfsUsage {
            total_bytes: extract_bytes("Device size"),
            used_bytes: extract_bytes("Used"),
            free_estimated: extract_bytes("Free (estimated)"),
        })
    }
}

/// Information about a Btrfs subvolume from `btrfs subvolume list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubvolumeInfo {
    /// Subvolume ID.
    pub id: u64,
    /// Generation number.
    pub generation: u64,
    /// Parent subvolume ID.
    pub top_level: u64,
    /// Relative path from the filesystem root.
    pub path: String,
}

/// Btrfs filesystem usage statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtrfsUsage {
    /// Total device size in bytes.
    pub total_bytes: u64,
    /// Used space in bytes.
    pub used_bytes: u64,
    /// Estimated free space in bytes.
    pub free_estimated: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_subvolume_list() {
        let output = "\
ID 257 gen 8 top level 5 path nas-data
ID 258 gen 12 top level 5 path nvr-recordings
ID 259 gen 15 top level 5 path nas-data.snap.20260320
";
        let subvols = BtrfsVolume::parse_subvolume_list(output);
        assert_eq!(subvols.len(), 3);

        assert_eq!(subvols[0].id, 257);
        assert_eq!(subvols[0].generation, 8);
        assert_eq!(subvols[0].top_level, 5);
        assert_eq!(subvols[0].path, "nas-data");

        assert_eq!(subvols[1].id, 258);
        assert_eq!(subvols[1].path, "nvr-recordings");

        assert_eq!(subvols[2].id, 259);
        assert_eq!(subvols[2].path, "nas-data.snap.20260320");
    }

    #[test]
    fn test_parse_subvolume_list_empty() {
        let subvols = BtrfsVolume::parse_subvolume_list("");
        assert!(subvols.is_empty());
    }

    #[test]
    fn test_parse_scrub_status_idle() {
        let output = "no stats available\n";
        let status = BtrfsVolume::parse_scrub_status(output).expect("parse should succeed");
        assert!(matches!(status, ScrubStatus::Idle));
    }

    #[test]
    fn test_parse_scrub_status_running() {
        let output = "\
UUID:             12345678-abcd-efgh-ijkl-mnopqrstuvwx
Scrub started:    Thu Mar 20 12:00:00 2026
Status:           running
Duration:         0:01:30
Total to scrub:   2.72TiB
Rate:             500.00MiB/s
";
        let status = BtrfsVolume::parse_scrub_status(output).expect("parse should succeed");
        assert!(matches!(status, ScrubStatus::Running { .. }));
    }

    #[test]
    fn test_parse_usage() {
        let output = "\
Overall:
    Device size:                  3000592982016
    Device allocated:             2400474185728
    Device unallocated:            600118796288
    Used:                         2000395153408
    Free (estimated):             1000197828608
";
        let usage = BtrfsVolume::parse_usage(output).expect("parse should succeed");
        assert_eq!(usage.total_bytes, 3000592982016);
        assert_eq!(usage.used_bytes, 2000395153408);
        assert_eq!(usage.free_estimated, 1000197828608);
    }
}
