#![deny(unsafe_code)]

use crate::StorageError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::debug;

/// Physical bay state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BayState {
    /// No disk detected in the bay.
    Empty,
    /// A disk is physically present and healthy.
    Present,
    /// The bay has a fault condition.
    Fault,
}

/// LED mode for a bay — determines which LEDs are on/off/blinking.
///
/// Each bay has two LEDs:
/// - **White** (activity): SGPO gpiochip8
/// - **Red/Orange** (fault): PCA9575 gpiochip1
///
/// LED patterns:
/// - `Off`: both LEDs off (empty bay)
/// - `Normal`: white steady on (disk present, healthy)
/// - `Active`: white blinking (disk I/O in progress)
/// - `Identify`: white+red alternating blink (user requested identification)
/// - `SmartWarning`: red blinking (SMART error, disk still active)
/// - `Degraded`: red steady on (disk failed / RAID degraded)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BayLedMode {
    /// Both LEDs off — empty bay.
    Off,
    /// White steady — disk present, healthy, idle.
    Normal,
    /// White blinking — disk I/O activity.
    Active,
    /// White+Red alternating blink — identify via Web UI.
    Identify,
    /// Red blinking — SMART warning, disk still functional.
    SmartWarning,
    /// Red steady — disk error, RAID degraded.
    Degraded,
}

/// UNVR bay-to-SATA host mapping.
///
/// Verified on actual hardware (2026-03-21):
///   sysfs path:  .../0000:00:09.0/ata7/host6/target6:0:0/6:0:0:0
///   extract_scsi_address → host=6, target=0
///
/// | Slot | PCI   | ATA  | SCSI Host | Target |
/// |------|-------|------|-----------|--------|
/// | 1    | 00:09 | ata7 | host6     | 0      |
/// | 2    | 00:09 | ata5 | host4     | 0      |
/// | 3    | 00:08 | ata1 | host0     | 0      |
/// | 4    | 00:08 | ata3 | host2     | 0      |
#[derive(Debug, Clone, Copy)]
struct BayMapping {
    host: u8,
    port: u8,
}

const BAY_MAPPINGS: [BayMapping; 4] = [
    BayMapping { host: 6, port: 0 }, // Slot 1 — PCI 00:09.0, ata7
    BayMapping { host: 4, port: 0 }, // Slot 2 — PCI 00:09.0, ata5
    BayMapping { host: 0, port: 0 }, // Slot 3 — PCI 00:08.0, ata1
    BayMapping { host: 2, port: 0 }, // Slot 4 — PCI 00:08.0, ata3
];

/// Verified LED GPIO mapping (tested 2026-03-21).
///
/// White (activity) LEDs — SGPO gpiochip8:
/// Red/Orange (fault) LEDs — PCA9575 gpiochip1:
pub(crate) const LED_WHITE_CHIP: u8 = 8;
pub(crate) const LED_RED_CHIP: u8 = 1;

/// SGPO pin for white activity LED, indexed by slot (0-3).
pub(crate) const LED_WHITE_PIN: [u8; 4] = [22, 20, 16, 18]; // Slot 1,2,3,4

/// PCA9575 pin for red fault LED, indexed by slot (0-3).
pub(crate) const LED_RED_PIN: [u8; 4] = [12, 13, 14, 15]; // Slot 1,2,3,4

/// Represents a physical HDD bay on the UNVR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bay {
    /// Slot number (1-4, human-readable).
    pub slot: u8,
    /// Current state based on presence GPIO.
    pub state: BayState,
    /// Current LED mode.
    pub led_mode: BayLedMode,
}

impl Bay {
    /// Read all four bay states via SATA link detection.
    pub fn read_all() -> Vec<Bay> {
        (0..4)
            .map(|idx| {
                let present = Self::read_presence(idx);
                Bay {
                    slot: idx + 1,
                    state: if present {
                        BayState::Present
                    } else {
                        BayState::Empty
                    },
                    led_mode: if present {
                        BayLedMode::Normal
                    } else {
                        BayLedMode::Off
                    },
                }
            })
            .collect()
    }

    /// Map this bay slot to its corresponding `/dev/sdX` device path.
    pub fn map_to_disk(&self) -> Result<PathBuf, StorageError> {
        let idx = (self.slot - 1) as usize;
        if idx > 3 {
            return Err(StorageError::InvalidBaySlot(self.slot));
        }
        let mapping = &BAY_MAPPINGS[idx];
        Self::find_disk_by_host_port(mapping.host, mapping.port)
    }

    /// Detect presence by checking SATA PHY link speed.
    ///
    /// Reads `/sys/class/ata_link/linkN/sata_spd` — returns `<unknown>` when
    /// no disk is connected, or a speed like `6.0 Gbps` when linked.
    /// This reflects physical state immediately (no SCSI cleanup delay).
    fn read_presence(idx: u8) -> bool {
        let mapping = &BAY_MAPPINGS[idx as usize];
        // ATA link number = SCSI host + 1 (host0 → ata1/link1, host6 → ata7/link7)
        let link_num = mapping.host + 1;
        let path = format!("/sys/class/ata_link/link{link_num}/sata_spd");
        std::fs::read_to_string(&path)
            .map(|s| !s.trim().contains("unknown"))
            .unwrap_or(false)
    }

    /// Find the `/dev/sdX` block device for a given SATA host and port.
    fn find_disk_by_host_port(host: u8, port: u8) -> Result<PathBuf, StorageError> {
        let block_dir = Path::new("/sys/block");
        let entries = std::fs::read_dir(block_dir)
            .map_err(|e| StorageError::DiskNotFound(format!("cannot read /sys/block: {e}")))?;

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if !name_str.starts_with("sd") {
                continue;
            }
            let suffix = &name_str[2..];
            if suffix.is_empty() || suffix.chars().any(|c| !c.is_ascii_alphabetic()) {
                continue;
            }

            let device_link = block_dir.join(&*name_str).join("device");
            // Use read_link instead of canonicalize — canonicalize blocks
            // for 30+ seconds on zombie devices during SCSI cleanup.
            // Symlink target: "../../../H:C:T:L" — last component is the SCSI address.
            let link_target = match std::fs::read_link(&device_link) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let scsi_addr = link_target.file_name().and_then(|f| f.to_str());
            let (scsi_host, scsi_target) = match scsi_addr {
                Some(s) => {
                    let parts: Vec<&str> = s.split(':').collect();
                    if parts.len() != 4 {
                        continue;
                    }
                    match (parts[0].parse::<u8>(), parts[2].parse::<u8>()) {
                        (Ok(h), Ok(t)) => (h, t),
                        _ => continue,
                    }
                }
                None => continue,
            };

            if scsi_host == host && scsi_target == port {
                let dev_path = PathBuf::from(format!("/dev/{name_str}"));
                debug!(
                    bay_host = host,
                    bay_port = port,
                    device = %dev_path.display(),
                    "mapped bay to disk"
                );
                return Ok(dev_path);
            }
        }

        Err(StorageError::DiskNotFound(format!(
            "no disk found for SATA host {host} port {port}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_led_mapping_constants() {
        // White LEDs on SGPO gpiochip8
        assert_eq!(LED_WHITE_PIN[0], 22); // Slot 1
        assert_eq!(LED_WHITE_PIN[1], 20); // Slot 2
        assert_eq!(LED_WHITE_PIN[2], 16); // Slot 3
        assert_eq!(LED_WHITE_PIN[3], 18); // Slot 4

        // Red LEDs on PCA9575 gpiochip1
        assert_eq!(LED_RED_PIN[0], 12); // Slot 1
        assert_eq!(LED_RED_PIN[1], 13); // Slot 2
        assert_eq!(LED_RED_PIN[2], 14); // Slot 3
        assert_eq!(LED_RED_PIN[3], 15); // Slot 4
    }

    #[test]
    fn test_bay_slot_numbering() {
        // Slots are 1-indexed for human readability
        assert_eq!(BAY_MAPPINGS[0].host, 6); // Slot 1 — ata7/host6
        assert_eq!(BAY_MAPPINGS[0].port, 0);
        assert_eq!(BAY_MAPPINGS[2].host, 0); // Slot 3 — ata1/host0
    }
}
