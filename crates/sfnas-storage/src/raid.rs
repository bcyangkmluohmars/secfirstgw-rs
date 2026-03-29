#![deny(unsafe_code)]

use crate::StorageError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

/// Supported RAID levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaidLevel {
    /// Striping — no redundancy, maximum performance.
    Raid0,
    /// Mirroring — full redundancy, 50% capacity.
    Raid1,
    /// Distributed parity — one disk of fault tolerance.
    Raid5,
    /// Striped mirrors — balance of speed and redundancy.
    Raid10,
}

impl RaidLevel {
    /// Minimum number of disks required for this RAID level.
    #[must_use]
    pub fn min_disks(&self) -> usize {
        match self {
            Self::Raid0 => 2,
            Self::Raid1 => 2,
            Self::Raid5 => 3,
            Self::Raid10 => 4,
        }
    }

    /// The mdadm `--level` argument string.
    fn mdadm_level(&self) -> &str {
        match self {
            Self::Raid0 => "0",
            Self::Raid1 => "1",
            Self::Raid5 => "5",
            Self::Raid10 => "10",
        }
    }

    /// Usable capacity as a fraction of total raw capacity.
    #[must_use]
    pub fn capacity_ratio(&self, disk_count: usize) -> f64 {
        match self {
            Self::Raid0 => 1.0,
            Self::Raid1 => 1.0 / disk_count as f64,
            Self::Raid5 => (disk_count - 1) as f64 / disk_count as f64,
            Self::Raid10 => 0.5,
        }
    }

    /// Try to parse a RAID level from an mdadm detail string (e.g. "raid5").
    fn from_mdadm_str(s: &str) -> Option<Self> {
        let s = s.trim().to_lowercase();
        match s.as_str() {
            "raid0" => Some(Self::Raid0),
            "raid1" => Some(Self::Raid1),
            "raid5" => Some(Self::Raid5),
            "raid10" => Some(Self::Raid10),
            _ => None,
        }
    }
}

/// RAID array status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RaidStatus {
    /// Array is fully operational with all disks present.
    Active,
    /// Array is running but one or more disks are missing/failed.
    Degraded {
        /// Number of missing/failed disks.
        missing: usize,
    },
    /// Array is rebuilding after a disk replacement.
    Rebuilding {
        /// Rebuild progress as a percentage (0.0 – 100.0).
        progress: f32,
    },
    /// Array is stopped / not started.
    Inactive,
    /// Array is being checked (scrub).
    Checking {
        /// Check progress as a percentage (0.0 – 100.0).
        progress: f32,
    },
}

/// Parsed output of `mdadm --detail` for a single array.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaidDetail {
    /// MD device path (e.g. `/dev/md/nas`).
    pub device: PathBuf,
    /// Array name.
    pub name: String,
    /// RAID level.
    pub level: Option<RaidLevel>,
    /// Total array size in bytes.
    pub size_bytes: u64,
    /// Number of configured RAID devices.
    pub raid_devices: usize,
    /// Current state string from mdadm.
    pub state: String,
    /// UUID of the array.
    pub uuid: String,
    /// Member disks currently active.
    pub active_disks: Vec<PathBuf>,
    /// Member disks marked as spare.
    pub spare_disks: Vec<PathBuf>,
    /// Parsed status.
    pub status: RaidStatus,
}

/// Real-time status of a single array from `/proc/mdstat`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdstatEntry {
    /// Device name (e.g. `md127`).
    pub device: String,
    /// Whether the array is active.
    pub active: bool,
    /// RAID level string (e.g. `raid5`).
    pub level: String,
    /// Component devices (e.g. `sdb1[0]`, `sdc1[1]`).
    pub components: Vec<String>,
    /// Disk status bitmap (e.g. `[UUU_]` → `"UUU_"`).
    pub bitmap: String,
    /// Resync/rebuild/check progress if any (0.0 – 100.0).
    pub recovery_progress: Option<f32>,
    /// Recovery action in progress, if any (e.g. "recovery", "check", "reshape").
    pub recovery_action: Option<String>,
    /// Speed in KB/sec (e.g. 141258).
    pub speed_kbps: Option<u64>,
    /// Estimated finish time in minutes (e.g. 343.7).
    pub finish_minutes: Option<f32>,
}

/// Represents an MD RAID array.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaidArray {
    /// User-defined name for the array.
    pub name: String,
    /// MD device path (e.g. `/dev/md/nas`).
    pub device: PathBuf,
    /// RAID level.
    pub level: RaidLevel,
    /// Member disk paths.
    pub disks: Vec<PathBuf>,
    /// Current status.
    pub status: RaidStatus,
    /// Total usable size in bytes.
    pub size_bytes: u64,
}

impl RaidArray {
    /// Create a new RAID array from the given disks.
    ///
    /// Runs `mdadm --create` with the specified level and disk set.
    pub fn create(name: &str, level: RaidLevel, disks: &[&Path]) -> Result<Self, StorageError> {
        if disks.len() < level.min_disks() {
            return Err(StorageError::InvalidConfig(format!(
                "RAID{} requires at least {} disks, got {}",
                level.mdadm_level(),
                level.min_disks(),
                disks.len()
            )));
        }

        let md_device = format!("/dev/md/{name}");

        let mut cmd = Command::new("mdadm");
        cmd.arg("--create")
            .arg(&md_device)
            .arg("--level")
            .arg(level.mdadm_level())
            .arg("--raid-devices")
            .arg(disks.len().to_string())
            .arg("--name")
            .arg(name)
            .arg("--run");

        for disk in disks {
            cmd.arg(disk.as_os_str());
        }

        info!(
            name,
            level = level.mdadm_level(),
            disks = disks.len(),
            "creating RAID array"
        );

        let output = cmd
            .output()
            .map_err(|e| StorageError::Mdadm(e.to_string()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Mdadm(stderr.to_string()));
        }

        Ok(Self {
            name: name.to_string(),
            device: PathBuf::from(&md_device),
            level,
            disks: disks.iter().map(|d| d.to_path_buf()).collect(),
            status: RaidStatus::Active,
            size_bytes: 0, // populated by subsequent status query
        })
    }

    /// Assemble (activate) an existing RAID array that was previously created.
    ///
    /// Runs `mdadm --assemble` to bring an existing array online.
    pub fn assemble(device: &Path) -> Result<(), StorageError> {
        info!(device = %device.display(), "assembling RAID array");

        let output = Command::new("mdadm")
            .arg("--assemble")
            .arg(device.as_os_str())
            .arg("--scan")
            .output()
            .map_err(|e| StorageError::Mdadm(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Mdadm(stderr.to_string()));
        }

        Ok(())
    }

    /// Add a disk to an existing array (grow or replace a failed member).
    ///
    /// Runs `mdadm --add` to introduce a new/replacement disk.
    pub fn add_disk(device: &Path, disk: &Path) -> Result<(), StorageError> {
        info!(
            device = %device.display(),
            disk = %disk.display(),
            "adding disk to RAID array"
        );

        let output = Command::new("mdadm")
            .arg(device.as_os_str())
            .arg("--add")
            .arg(disk.as_os_str())
            .output()
            .map_err(|e| StorageError::Mdadm(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Mdadm(stderr.to_string()));
        }

        Ok(())
    }

    /// Remove (fail + remove) a disk from an existing array.
    ///
    /// Runs `mdadm --fail` followed by `mdadm --remove`.
    pub fn remove_disk(device: &Path, disk: &Path) -> Result<(), StorageError> {
        info!(
            device = %device.display(),
            disk = %disk.display(),
            "removing disk from RAID array"
        );

        // Mark the disk as failed first
        let fail_output = Command::new("mdadm")
            .arg(device.as_os_str())
            .arg("--fail")
            .arg(disk.as_os_str())
            .output()
            .map_err(|e| StorageError::Mdadm(e.to_string()))?;

        if !fail_output.status.success() {
            let stderr = String::from_utf8_lossy(&fail_output.stderr);
            warn!(
                device = %device.display(),
                disk = %disk.display(),
                stderr = %stderr,
                "mdadm --fail returned error (disk may already be failed)"
            );
        }

        // Now remove it
        let remove_output = Command::new("mdadm")
            .arg(device.as_os_str())
            .arg("--remove")
            .arg(disk.as_os_str())
            .output()
            .map_err(|e| StorageError::Mdadm(e.to_string()))?;

        if !remove_output.status.success() {
            let stderr = String::from_utf8_lossy(&remove_output.stderr);
            return Err(StorageError::Mdadm(stderr.to_string()));
        }

        Ok(())
    }

    /// Parse full `mdadm --detail` output for a device into a [`RaidDetail`].
    pub fn detail(device: &Path) -> Result<RaidDetail, StorageError> {
        let output = Command::new("mdadm")
            .arg("--detail")
            .arg(device.as_os_str())
            .output()
            .map_err(|e| StorageError::Mdadm(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Mdadm(stderr.to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_detail(&stdout, device)
    }

    /// Parse the text output of `mdadm --detail` into a [`RaidDetail`].
    fn parse_detail(output: &str, device: &Path) -> Result<RaidDetail, StorageError> {
        let extract = |key: &str| -> String {
            output
                .lines()
                .find(|l| l.contains(key))
                .and_then(|l| l.split(':').nth(1))
                .map(|v| v.trim().to_string())
                .unwrap_or_default()
        };

        let name = extract("Name");
        let level_str = extract("Raid Level");
        let level = RaidLevel::from_mdadm_str(&level_str);
        let state = extract("State");
        let uuid = extract("UUID");

        // Parse "Array Size" — reported in KiB by mdadm
        let size_bytes = output
            .lines()
            .find(|l| l.contains("Array Size"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| {
                // Format: "  1234567 (1.17 GiB 1.26 GB)"
                v.split_whitespace().next()
            })
            .and_then(|v| v.parse::<u64>().ok())
            .map(|kib| kib * 1024)
            .unwrap_or(0);

        let raid_devices = extract("Raid Devices").parse::<usize>().unwrap_or(0);

        // Parse member disks from the device table at the bottom
        let mut active_disks = Vec::new();
        let mut spare_disks = Vec::new();
        let mut in_device_table = false;

        for line in output.lines() {
            if line.contains("Number") && line.contains("Major") && line.contains("Minor") {
                in_device_table = true;
                continue;
            }

            if in_device_table {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                // Each device line looks like:
                //    0       8       17        0      active sync   /dev/sdb1
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if let Some(dev_path) = parts.last()
                    && dev_path.starts_with("/dev/")
                {
                    let path = PathBuf::from(dev_path);
                    if trimmed.contains("spare") {
                        spare_disks.push(path);
                    } else {
                        active_disks.push(path);
                    }
                }
            }
        }

        // Determine status from state string
        let status = Self::parse_state_string(&state);

        Ok(RaidDetail {
            device: device.to_path_buf(),
            name,
            level,
            size_bytes,
            raid_devices,
            state,
            uuid,
            active_disks,
            spare_disks,
            status,
        })
    }

    /// Convert the mdadm "State" field into a [`RaidStatus`].
    fn parse_state_string(state: &str) -> RaidStatus {
        let lower = state.to_lowercase();
        if lower.contains("rebuild") || lower.contains("recovering") {
            RaidStatus::Rebuilding { progress: 0.0 }
        } else if lower.contains("degraded") {
            // Count commas to estimate missing disks — mdadm reports
            // "active, degraded" for 1 missing, we default to 1.
            RaidStatus::Degraded { missing: 1 }
        } else if lower.contains("check") {
            RaidStatus::Checking { progress: 0.0 }
        } else if lower.contains("inactive") {
            RaidStatus::Inactive
        } else if lower.contains("active") || lower.contains("clean") {
            RaidStatus::Active
        } else {
            RaidStatus::Inactive
        }
    }

    /// Get the status of an existing array.
    pub fn status(device: &Path) -> Result<RaidStatus, StorageError> {
        let detail = Self::detail(device)?;
        Ok(detail.status)
    }

    /// Stop (deactivate) an array.
    pub fn stop(device: &Path) -> Result<(), StorageError> {
        info!(device = %device.display(), "stopping RAID array");

        let output = Command::new("mdadm")
            .arg("--stop")
            .arg(device.as_os_str())
            .output()
            .map_err(|e| StorageError::Mdadm(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::Mdadm(stderr.to_string()));
        }

        Ok(())
    }

    /// Scan for existing arrays via `mdadm --detail --scan`.
    ///
    /// Returns the raw ARRAY lines from mdadm output.
    pub fn scan() -> Result<Vec<String>, StorageError> {
        let output = Command::new("mdadm")
            .arg("--detail")
            .arg("--scan")
            .output()
            .map_err(|e| StorageError::Mdadm(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let arrays: Vec<String> = stdout
            .lines()
            .filter(|l| l.starts_with("ARRAY"))
            .map(|l| l.to_string())
            .collect();

        Ok(arrays)
    }

    /// Initiate a scrub (data consistency check) on an array.
    ///
    /// Writes `check` to `/sys/block/<md_dev>/md/sync_action`.
    pub fn scrub(device: &Path) -> Result<(), StorageError> {
        let dev_name = device.file_name().ok_or_else(|| {
            StorageError::Mdadm(format!(
                "cannot determine device name from path: {}",
                device.display()
            ))
        })?;

        let sync_action_path = Path::new("/sys/block")
            .join(dev_name)
            .join("md/sync_action");

        info!(
            device = %device.display(),
            path = %sync_action_path.display(),
            "initiating RAID scrub"
        );

        std::fs::write(&sync_action_path, "check").map_err(|e| {
            StorageError::Mdadm(format!(
                "failed to initiate scrub on {}: {e}",
                device.display()
            ))
        })?;

        Ok(())
    }

    /// Read current sync action from sysfs (e.g. "idle", "check", "recover").
    pub fn sync_action(device: &Path) -> Result<String, StorageError> {
        let dev_name = device.file_name().ok_or_else(|| {
            StorageError::Mdadm(format!(
                "cannot determine device name from path: {}",
                device.display()
            ))
        })?;

        let path = Path::new("/sys/block")
            .join(dev_name)
            .join("md/sync_action");

        let action = std::fs::read_to_string(&path).map_err(|e| {
            StorageError::Mdadm(format!(
                "failed to read sync_action for {}: {e}",
                device.display()
            ))
        })?;

        Ok(action.trim().to_string())
    }

    /// Parse `/proc/mdstat` and return status for all arrays.
    pub fn parse_mdstat() -> Result<Vec<MdstatEntry>, StorageError> {
        let content = std::fs::read_to_string("/proc/mdstat")
            .map_err(|e| StorageError::Mdadm(format!("failed to read /proc/mdstat: {e}")))?;

        Self::parse_mdstat_content(&content)
    }

    /// Parse the text content of `/proc/mdstat`.
    ///
    /// Exposed for testing without requiring a live system.
    fn parse_mdstat_content(content: &str) -> Result<Vec<MdstatEntry>, StorageError> {
        let mut entries = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];

            // Array lines look like: "md127 : active raid5 sdd1[3] sdc1[2] sdb1[1] sda1[0]"
            if line.starts_with("md") && line.contains(" : ") {
                let parts: Vec<&str> = line.splitn(2, " : ").collect();
                if parts.len() < 2 {
                    i += 1;
                    continue;
                }

                let device = parts[0].trim().to_string();
                let rest = parts[1];

                let active = rest.starts_with("active");

                // Extract RAID level — it's the word after "active" (or first word if inactive)
                let tokens: Vec<&str> = rest.split_whitespace().collect();
                let level_idx = if active { 1 } else { 0 };
                let level = tokens
                    .get(level_idx)
                    .map(|s| s.to_string())
                    .unwrap_or_default();

                // Component devices are tokens that contain '[' (e.g. "sdb1[0]")
                let components: Vec<String> = tokens
                    .iter()
                    .filter(|t| t.contains('['))
                    .map(|t| t.to_string())
                    .collect();

                // Next line(s) contain size info and bitmap like "[UUU_]"
                let mut bitmap = String::new();
                let mut recovery_progress = None;
                let mut recovery_action = None;
                let mut speed_kbps = None;
                let mut finish_minutes = None;

                // Look at subsequent lines until we hit a blank line or another md device
                let mut j = i + 1;
                while j < lines.len() {
                    let next_line = lines[j].trim();
                    if next_line.is_empty()
                        || (next_line.starts_with("md") && next_line.contains(" : "))
                    {
                        break;
                    }

                    // Parse bitmap like "[UUUU]" or "[UU_U]"
                    // There may be multiple bracket groups on a line
                    // (e.g. "[3/3] [UUU]"), so scan all of them.
                    {
                        let mut search_from = 0;
                        while let Some(start) = next_line[search_from..].find('[') {
                            let abs_start = search_from + start;
                            if let Some(end) = next_line[abs_start..].find(']') {
                                let candidate = &next_line[abs_start + 1..abs_start + end];
                                // Bitmaps contain only U and _ characters
                                if !candidate.is_empty()
                                    && candidate.chars().all(|c| c == 'U' || c == '_')
                                {
                                    bitmap = candidate.to_string();
                                }
                                search_from = abs_start + end + 1;
                            } else {
                                break;
                            }
                        }
                    }

                    // Parse recovery/check progress like "recovery = 45.6% ..."
                    // or "check = 12.3% ..."
                    for action_word in &["recovery", "check", "reshape", "resync"] {
                        if next_line.contains(action_word) {
                            recovery_action = Some(action_word.to_string());
                            // Look for percentage
                            if let Some(pct_pos) = next_line.find('%') {
                                let before_pct = &next_line[..pct_pos];
                                let num_str: String = before_pct
                                    .chars()
                                    .rev()
                                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                                    .collect::<String>()
                                    .chars()
                                    .rev()
                                    .collect();
                                if let Ok(pct) = num_str.parse::<f32>() {
                                    recovery_progress = Some(pct);
                                }
                            }
                            // Parse speed: "speed=141258K/sec"
                            if let Some(sp) = next_line.find("speed=") {
                                let after = &next_line[sp + 6..];
                                let num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
                                if let Ok(s) = num.parse::<u64>() {
                                    speed_kbps = Some(s);
                                }
                            }
                            // Parse finish: "finish=343.7min"
                            if let Some(fp) = next_line.find("finish=") {
                                let after = &next_line[fp + 7..];
                                let num: String = after.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
                                if let Ok(f) = num.parse::<f32>() {
                                    finish_minutes = Some(f);
                                }
                            }
                        }
                    }

                    j += 1;
                }

                entries.push(MdstatEntry {
                    device,
                    active,
                    level,
                    components,
                    bitmap,
                    recovery_progress,
                    recovery_action,
                    speed_kbps,
                    finish_minutes,
                });

                i = j;
            } else {
                i += 1;
            }
        }

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raid_level_min_disks() {
        assert_eq!(RaidLevel::Raid0.min_disks(), 2);
        assert_eq!(RaidLevel::Raid1.min_disks(), 2);
        assert_eq!(RaidLevel::Raid5.min_disks(), 3);
        assert_eq!(RaidLevel::Raid10.min_disks(), 4);
    }

    #[test]
    fn test_capacity_ratio() {
        let eps = 0.001;
        assert!((RaidLevel::Raid0.capacity_ratio(4) - 1.0).abs() < eps);
        assert!((RaidLevel::Raid1.capacity_ratio(2) - 0.5).abs() < eps);
        assert!((RaidLevel::Raid5.capacity_ratio(4) - 0.75).abs() < eps);
        assert!((RaidLevel::Raid10.capacity_ratio(4) - 0.5).abs() < eps);
    }

    #[test]
    fn test_parse_mdstat_healthy() {
        let content = "\
Personalities : [raid6] [raid5] [raid4]
md127 : active raid5 sdd1[3] sdc1[2] sdb1[1]
      2929893888 blocks super 1.2 level 5, 512k chunk, algorithm 2 [3/3] [UUU]

unused devices: <none>
";
        let entries = RaidArray::parse_mdstat_content(content).expect("parse should succeed");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].device, "md127");
        assert!(entries[0].active);
        assert_eq!(entries[0].level, "raid5");
        assert_eq!(entries[0].components.len(), 3);
        assert_eq!(entries[0].bitmap, "UUU");
        assert!(entries[0].recovery_progress.is_none());
    }

    #[test]
    fn test_parse_mdstat_rebuilding() {
        let content = "\
Personalities : [raid5]
md127 : active raid5 sdd1[3] sdc1[2] sdb1[1]
      2929893888 blocks super 1.2 level 5, 512k chunk, algorithm 2 [3/2] [UU_]
      [==>..................]  recovery = 12.5% (183118208/1464946944) finish=120.5min speed=177211K/sec

unused devices: <none>
";
        let entries = RaidArray::parse_mdstat_content(content).expect("parse should succeed");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].bitmap, "UU_");
        assert_eq!(entries[0].recovery_action.as_deref(), Some("recovery"));
        let progress = entries[0].recovery_progress.expect("should have progress");
        assert!((progress - 12.5).abs() < 0.1);
    }

    #[test]
    fn test_parse_mdstat_checking() {
        let content = "\
Personalities : [raid5]
md0 : active raid5 sdc1[2] sdb1[1] sda1[0]
      1234567 blocks super 1.2 level 5, 512k chunk, algorithm 2 [3/3] [UUU]
      [======>.............]  check = 33.3% (411522/1234567) finish=45.2min speed=100000K/sec

unused devices: <none>
";
        let entries = RaidArray::parse_mdstat_content(content).expect("parse should succeed");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].recovery_action.as_deref(), Some("check"));
        let progress = entries[0].recovery_progress.expect("should have progress");
        assert!((progress - 33.3).abs() < 0.1);
    }

    #[test]
    fn test_parse_detail_active() {
        let output = "\
/dev/md/nas:
           Version : 1.2
     Creation Time : Thu Mar 20 12:00:00 2026
        Raid Level : raid5
     Array Size : 2929893888 (2.72 TiB 2.99 TB)
  Used Dev Size : 1464946944 (1.36 TiB 1.49 TB)
   Raid Devices : 3
  Total Devices : 3
    Persistence : Superblock is persistent

          State : clean
 Active Devices : 3
Working Devices : 3
 Failed Devices : 0
  Spare Devices : 0

           Name : nas
           UUID : 12345678:abcdef01:23456789:deadbeef

    Number   Major   Minor   RaidDevice State
       0       8       17        0      active sync   /dev/sdb1
       1       8       33        1      active sync   /dev/sdc1
       2       8       49        2      active sync   /dev/sdd1
";
        let detail = RaidArray::parse_detail(output, Path::new("/dev/md/nas"))
            .expect("parse should succeed");
        assert_eq!(detail.name, "nas");
        assert_eq!(detail.level, Some(RaidLevel::Raid5));
        assert_eq!(detail.raid_devices, 3);
        assert_eq!(detail.active_disks.len(), 3);
        assert!(detail.spare_disks.is_empty());
        assert!(matches!(detail.status, RaidStatus::Active));
        assert_eq!(detail.size_bytes, 2929893888 * 1024);
    }

    #[test]
    fn test_parse_detail_degraded() {
        let output = "\
/dev/md/nas:
        Raid Level : raid5
     Array Size : 1000000 (1 GiB)
   Raid Devices : 3
          State : active, degraded
           Name : nas
           UUID : aaaaaaaa:bbbbbbbb:cccccccc:dddddddd

    Number   Major   Minor   RaidDevice State
       0       8       17        0      active sync   /dev/sdb1
       1       8       33        1      active sync   /dev/sdc1
       -       0        0        2      removed
";
        let detail = RaidArray::parse_detail(output, Path::new("/dev/md/nas"))
            .expect("parse should succeed");
        assert!(matches!(detail.status, RaidStatus::Degraded { missing: 1 }));
        assert_eq!(detail.active_disks.len(), 2);
    }

    #[test]
    fn test_parse_state_string() {
        assert!(matches!(
            RaidArray::parse_state_string("active"),
            RaidStatus::Active
        ));
        assert!(matches!(
            RaidArray::parse_state_string("clean"),
            RaidStatus::Active
        ));
        assert!(matches!(
            RaidArray::parse_state_string("active, degraded"),
            RaidStatus::Degraded { .. }
        ));
        assert!(matches!(
            RaidArray::parse_state_string("active, degraded, recovering"),
            RaidStatus::Rebuilding { .. }
        ));
        assert!(matches!(
            RaidArray::parse_state_string("inactive"),
            RaidStatus::Inactive
        ));
    }

    #[test]
    fn test_create_validates_disk_count() {
        let result = RaidArray::create("test", RaidLevel::Raid5, &[Path::new("/dev/sdb")]);
        assert!(result.is_err());
        let err_msg = result.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err_msg.contains("requires at least 3"));
    }
}
