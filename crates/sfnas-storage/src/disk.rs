#![deny(unsafe_code)]

use crate::StorageError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

/// SMART overall health assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SmartStatus {
    /// SMART self-assessment passed.
    Passed,
    /// SMART self-assessment failed with a reason.
    Failed(String),
    /// SMART data could not be determined.
    Unknown,
}

/// Disk health information derived from SMART attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskHealth {
    /// Overall SMART assessment.
    pub smart_status: SmartStatus,
    /// Current temperature in degrees Celsius.
    pub temperature_celsius: Option<u32>,
    /// Cumulative power-on time in hours.
    pub power_on_hours: Option<u64>,
    /// Count of reallocated (bad) sectors.
    pub reallocated_sectors: Option<u64>,
    /// Count of sectors waiting to be remapped.
    pub pending_sectors: Option<u64>,
    /// Count of uncorrectable sectors.
    pub offline_uncorrectable: Option<u64>,
    /// Total bytes read over the drive lifetime (if reported).
    pub total_lbas_read: Option<u64>,
    /// Total bytes written over the drive lifetime (if reported).
    pub total_lbas_written: Option<u64>,
    /// Spin retry count — elevated values indicate mechanical issues.
    pub spin_retry_count: Option<u64>,
    /// Command timeout count.
    pub command_timeout: Option<u64>,
    /// Raw read error rate (vendor-specific meaning).
    pub raw_read_error_rate: Option<u64>,
    /// Seek error rate (vendor-specific meaning).
    pub seek_error_rate: Option<u64>,
}

/// Represents a physical disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disk {
    /// Device path (e.g. `/dev/sdb`).
    pub path: PathBuf,
    /// Drive model string.
    pub model: String,
    /// Drive serial number.
    pub serial: String,
    /// Drive capacity in bytes.
    pub size_bytes: u64,
    /// Whether the drive is rotational (HDD) vs solid-state (SSD).
    pub rotational: bool,
    /// SMART health data.
    pub health: DiskHealth,
}

impl Disk {
    /// Discover a disk by its device path, reading sysfs and SMART data.
    pub fn from_path(path: &Path) -> Result<Self, StorageError> {
        let model =
            Self::read_sysfs_attr(path, "device/model").unwrap_or_else(|_| "Unknown".into());
        let serial =
            Self::read_sysfs_attr(path, "device/serial").unwrap_or_else(|_| "Unknown".into());
        let size_str = Self::read_sysfs_attr(path, "size").unwrap_or_else(|_| "0".into());
        let size_bytes: u64 = size_str
            .trim()
            .parse::<u64>()
            .unwrap_or(0)
            .saturating_mul(512);
        let rotational = Self::read_sysfs_attr(path, "queue/rotational")
            .map(|s| s.trim() == "1")
            .unwrap_or(true);

        let (health, smart_stdout) = match Self::smart_health(path) {
            Ok((h, out)) => (h, Some(out)),
            Err(e) => {
                debug!(
                    path = %path.display(),
                    error = %e,
                    "SMART query failed, using defaults"
                );
                (
                    DiskHealth {
                        smart_status: SmartStatus::Unknown,
                        temperature_celsius: None,
                        power_on_hours: None,
                        reallocated_sectors: None,
                        pending_sectors: None,
                        offline_uncorrectable: None,
                        total_lbas_read: None,
                        total_lbas_written: None,
                        spin_retry_count: None,
                        command_timeout: None,
                        raw_read_error_rate: None,
                        seek_error_rate: None,
                    },
                    None,
                )
            }
        };

        // Fall back to smartctl info section if sysfs returns "Unknown"
        let mut model = model.trim().to_string();
        let mut serial = serial.trim().to_string();
        if let Some(ref out) = smart_stdout {
            if (serial == "Unknown" || serial.is_empty())
                && let Some(s) = Self::extract_smart_info(out, "Serial Number")
            {
                serial = s;
            }
            if (model == "Unknown" || model.is_empty())
                && let Some(m) = Self::extract_smart_info(out, "Device Model")
            {
                model = m;
            }
        }

        Ok(Self {
            path: path.to_path_buf(),
            model,
            serial,
            size_bytes,
            rotational,
            health,
        })
    }

    /// Read a sysfs attribute for a block device.
    fn read_sysfs_attr(dev: &Path, attr: &str) -> Result<String, StorageError> {
        let dev_name = dev
            .file_name()
            .ok_or_else(|| StorageError::DiskNotFound(dev.display().to_string()))?;
        let sysfs_path = Path::new("/sys/block").join(dev_name).join(attr);
        std::fs::read_to_string(&sysfs_path).map_err(StorageError::Io)
    }

    /// Query SMART health attributes via `smartctl -a` with a 5 second timeout.
    /// Without the timeout, a removed or hung disk blocks the entire API.
    /// Returns the parsed health data and the raw stdout for info extraction.
    fn smart_health(path: &Path) -> Result<(DiskHealth, String), StorageError> {
        let output = Command::new("timeout")
            .arg("5")
            .arg("smartctl")
            .arg("-a")
            .arg(path.as_os_str())
            .output()
            .map_err(|e| StorageError::SmartFailed(path.display().to_string(), e.to_string()))?;

        // timeout(1) returns exit code 124 when it kills the child
        if output.status.code() == Some(124) {
            warn!(disk = %path.display(), "smartctl timed out after 5s — disk removed or unresponsive");
            return Err(StorageError::SmartFailed(
                path.display().to_string(),
                "timed out (disk removed or unresponsive)".into(),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        let smart_status = if stdout.contains("PASSED") {
            SmartStatus::Passed
        } else if stdout.contains("FAILED") {
            SmartStatus::Failed("SMART self-assessment failed".into())
        } else {
            SmartStatus::Unknown
        };

        let temperature_celsius = Self::extract_smart_value(&stdout, "Temperature_Celsius")
            .or_else(|| Self::extract_smart_value(&stdout, "Airflow_Temperature_Cel"));

        let power_on_hours = Self::extract_smart_u64(&stdout, "Power_On_Hours");
        let reallocated_sectors = Self::extract_smart_u64(&stdout, "Reallocated_Sector_Ct");
        let pending_sectors = Self::extract_smart_u64(&stdout, "Current_Pending_Sector");
        let offline_uncorrectable = Self::extract_smart_u64(&stdout, "Offline_Uncorrectable");
        let total_lbas_read = Self::extract_smart_u64(&stdout, "Total_LBAs_Read");
        let total_lbas_written = Self::extract_smart_u64(&stdout, "Total_LBAs_Written");
        let spin_retry_count = Self::extract_smart_u64(&stdout, "Spin_Retry_Count");
        let command_timeout = Self::extract_smart_u64(&stdout, "Command_Timeout");
        let raw_read_error_rate = Self::extract_smart_u64(&stdout, "Raw_Read_Error_Rate");
        let seek_error_rate = Self::extract_smart_u64(&stdout, "Seek_Error_Rate");

        Ok((
            DiskHealth {
                smart_status,
                temperature_celsius,
                power_on_hours,
                reallocated_sectors,
                pending_sectors,
                offline_uncorrectable,
                total_lbas_read,
                total_lbas_written,
                spin_retry_count,
                command_timeout,
                raw_read_error_rate,
                seek_error_rate,
            },
            stdout.into_owned(),
        ))
    }

    /// Extract a u32 value from the last whitespace-separated field of a SMART attribute line.
    fn extract_smart_value(output: &str, attr: &str) -> Option<u32> {
        output
            .lines()
            .find(|l| l.contains(attr))
            .and_then(|l| l.split_whitespace().last())
            .and_then(|v| v.parse().ok())
    }

    /// Extract a u64 value from the last whitespace-separated field of a SMART attribute line.
    fn extract_smart_u64(output: &str, attr: &str) -> Option<u64> {
        output
            .lines()
            .find(|l| l.contains(attr))
            .and_then(|l| l.split_whitespace().last())
            .and_then(|v| v.parse().ok())
    }

    /// Extract a string value from smartctl's information section.
    /// Handles lines like "Serial Number:    Z500ABCD" or "Device Model:    ST3000DM008".
    fn extract_smart_info(output: &str, key: &str) -> Option<String> {
        output
            .lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_once(':').map(|x| x.1))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    /// List all SATA/SCSI block devices suitable for NAS use.
    ///
    /// On the UNVR, SATA disks are attached to SCSI hosts 0–7 via the
    /// Marvell 88SE9235 controller. This function enumerates `/sys/block`
    /// for `sd*` devices and filters out the eMMC boot device (`sda`).
    pub fn list_all() -> Result<Vec<PathBuf>, StorageError> {
        let mut disks = Vec::new();
        let block_dir = Path::new("/sys/block");

        let entries = std::fs::read_dir(block_dir).map_err(StorageError::Io)?;

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // We want whole-disk devices like "sdb", "sdc" — not partitions
            // like "sdb1". On UNVR the only non-NAS sd device is sda (eMMC).
            if !name_str.starts_with("sd") {
                continue;
            }

            // Skip partition devices: "sdb1", "sdc2", etc.
            // A whole-disk device is "sd" followed by one or more letters only.
            let suffix = &name_str[2..];
            if suffix.is_empty() || suffix.chars().any(|c| !c.is_ascii_alphabetic()) {
                continue;
            }

            // Verify this is a real SCSI/SATA disk by checking for the
            // `device` symlink in sysfs (filters out virtual devices).
            let device_link = Path::new("/sys/block").join(&*name_str).join("device");
            if !device_link.exists() {
                continue;
            }

            // Skip non-SATA devices (eMMC via USB, etc.)
            // Check sysfs device path — SATA disks are on the internal PCIe bus (fbc00000)
            let real_path = std::fs::canonicalize(&device_link).unwrap_or_default();
            let real_path_str = real_path.display().to_string();
            if !real_path_str.contains("fbc00000") {
                debug!(device = %name_str, path = %real_path_str, "skipping non-SATA device");
                continue;
            }

            disks.push(PathBuf::from(format!("/dev/{name_str}")));
        }

        disks.sort();
        Ok(disks)
    }

    /// Wipe all filesystem signatures and partition tables from a device.
    ///
    /// Runs `wipefs -a` to remove all recognizable signatures.
    pub fn wipe(path: &Path) -> Result<(), StorageError> {
        info!(device = %path.display(), "wiping filesystem signatures");

        let output = Command::new("wipefs")
            .arg("-a")
            .arg(path.as_os_str())
            .output()
            .map_err(|e| StorageError::DiskTool(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::DiskTool(format!(
                "wipefs failed on {}: {stderr}",
                path.display()
            )));
        }

        Ok(())
    }

    /// Create a single GPT partition covering the entire disk.
    ///
    /// Uses `sgdisk` to create one Linux RAID partition (type fd00)
    /// spanning the full device.
    pub fn partition(path: &Path) -> Result<PathBuf, StorageError> {
        info!(device = %path.display(), "creating GPT partition table");

        // First, zap any existing partition table
        let zap_output = Command::new("sgdisk")
            .arg("--zap-all")
            .arg(path.as_os_str())
            .output()
            .map_err(|e| StorageError::DiskTool(e.to_string()))?;

        if !zap_output.status.success() {
            let stderr = String::from_utf8_lossy(&zap_output.stderr);
            return Err(StorageError::DiskTool(format!(
                "sgdisk --zap-all failed on {}: {stderr}",
                path.display()
            )));
        }

        // Create a single partition spanning the full disk, type fd00 (Linux RAID)
        let create_output = Command::new("sgdisk")
            .arg("--new=1:0:0")
            .arg("--typecode=1:fd00")
            .arg(path.as_os_str())
            .output()
            .map_err(|e| StorageError::DiskTool(e.to_string()))?;

        if !create_output.status.success() {
            let stderr = String::from_utf8_lossy(&create_output.stderr);
            return Err(StorageError::DiskTool(format!(
                "sgdisk partition creation failed on {}: {stderr}",
                path.display()
            )));
        }

        // The new partition is the device path with "1" appended
        let dev_str = path.display().to_string();
        let partition_path = PathBuf::from(format!("{dev_str}1"));

        info!(
            device = %path.display(),
            partition = %partition_path.display(),
            "GPT partition created"
        );

        Ok(partition_path)
    }

    /// Check whether this disk's SMART status indicates imminent failure.
    ///
    /// Returns `true` if any critical SMART attributes exceed thresholds.
    #[must_use]
    pub fn is_failing(&self) -> bool {
        // Explicit SMART failure
        if matches!(self.health.smart_status, SmartStatus::Failed(_)) {
            return true;
        }

        // Reallocated sectors > 100 is a strong failure indicator
        if self.health.reallocated_sectors.is_some_and(|v| v > 100) {
            return true;
        }

        // Pending sectors > 10 — drive is having trouble reading
        if self.health.pending_sectors.is_some_and(|v| v > 10) {
            return true;
        }

        // Offline uncorrectable > 0 — confirmed bad sectors
        if self.health.offline_uncorrectable.is_some_and(|v| v > 0) {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_failing_passed() {
        let disk = Disk {
            path: PathBuf::from("/dev/sdb"),
            model: "Test".into(),
            serial: "ABC123".into(),
            size_bytes: 1_000_000_000_000,
            rotational: true,
            health: DiskHealth {
                smart_status: SmartStatus::Passed,
                temperature_celsius: Some(35),
                power_on_hours: Some(10000),
                reallocated_sectors: Some(0),
                pending_sectors: Some(0),
                offline_uncorrectable: Some(0),
                total_lbas_read: None,
                total_lbas_written: None,
                spin_retry_count: Some(0),
                command_timeout: Some(0),
                raw_read_error_rate: None,
                seek_error_rate: None,
            },
        };
        assert!(!disk.is_failing());
    }

    #[test]
    fn test_is_failing_reallocated() {
        let disk = Disk {
            path: PathBuf::from("/dev/sdb"),
            model: "Test".into(),
            serial: "ABC123".into(),
            size_bytes: 1_000_000_000_000,
            rotational: true,
            health: DiskHealth {
                smart_status: SmartStatus::Passed,
                temperature_celsius: Some(35),
                power_on_hours: Some(10000),
                reallocated_sectors: Some(200),
                pending_sectors: Some(0),
                offline_uncorrectable: Some(0),
                total_lbas_read: None,
                total_lbas_written: None,
                spin_retry_count: None,
                command_timeout: None,
                raw_read_error_rate: None,
                seek_error_rate: None,
            },
        };
        assert!(disk.is_failing());
    }

    #[test]
    fn test_is_failing_smart_failed() {
        let disk = Disk {
            path: PathBuf::from("/dev/sdb"),
            model: "Test".into(),
            serial: "ABC123".into(),
            size_bytes: 1_000_000_000_000,
            rotational: true,
            health: DiskHealth {
                smart_status: SmartStatus::Failed("bad".into()),
                temperature_celsius: None,
                power_on_hours: None,
                reallocated_sectors: None,
                pending_sectors: None,
                offline_uncorrectable: None,
                total_lbas_read: None,
                total_lbas_written: None,
                spin_retry_count: None,
                command_timeout: None,
                raw_read_error_rate: None,
                seek_error_rate: None,
            },
        };
        assert!(disk.is_failing());
    }

    #[test]
    fn test_extract_smart_value() {
        let output = "  5 Reallocated_Sector_Ct   0x0033   100   100   036    Pre-fail  Always       -       0\n\
                       194 Temperature_Celsius     0x0022   111   099   000    Old_age   Always       -       37";
        assert_eq!(
            Disk::extract_smart_value(output, "Temperature_Celsius"),
            Some(37)
        );
        assert_eq!(
            Disk::extract_smart_u64(output, "Reallocated_Sector_Ct"),
            Some(0)
        );
        assert_eq!(Disk::extract_smart_value(output, "Nonexistent"), None);
    }
}
