// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read hardware identity from SPI-NOR flash EEPROM (MTD).
//!
//! On Ubiquiti Alpine V2 devices (UDM Pro, UDM SE, UNVR, …) the factory
//! identity is burned into a 64 KB EEPROM partition on the SPI-NOR flash.
//! The stock firmware exposes this through the proprietary `ubnthal.ko`
//! module at `/proc/ubnthal/board`.  Since we run a custom kernel without
//! ubnthal, we read the raw MTD device directly.
//!
//! # EEPROM layout (mtd "eeprom", typically `/dev/mtd4ro`)
//!
//! ```text
//! Offset  Size  Field
//! 0x0000  6     Base MAC address
//! 0x0006  6     Secondary MAC (locally administered variant)
//! 0x000C  2     Board ID (e.g. 0xEA15 = UDM Pro)
//! 0x000E  2     Hardware revision
//! 0x0010  4     Device ID (unique per unit)
//!
//! 0x8000  4     Magic "UBNT" (redundant copy header)
//! 0x8012  2     Board ID  (redundant)
//! 0x8014  4     Device ID (redundant)
//! 0x8018  6     Base MAC  (redundant)
//! 0x8030+ …     Crypto material / factory keys
//! ```
//!
//! # Usage
//!
//! ```no_run
//! use sfgw_hal::identity::HwIdentity;
//!
//! if let Some(id) = HwIdentity::read() {
//!     println!("Board: {}  MAC: {}  Device: {}", id.board_id, id.mac, id.device_id);
//! }
//! ```

use std::fmt;
use std::fs;
use std::io::Read;
use std::path::Path;

/// Hardware identity read from the factory EEPROM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HwIdentity {
    /// Board ID as hex string, e.g. `"ea15"`.
    pub board_id: String,
    /// Base MAC address, e.g. `"74:ac:b9:14:46:39"`.
    pub mac: String,
    /// Base MAC as raw bytes (6 bytes).
    pub mac_raw: [u8; 6],
    /// Hardware revision as hex string, e.g. `"0777"`.
    pub hw_revision: String,
    /// Device ID (unique per unit) as hex string, e.g. `"0002d308"`.
    pub device_id: String,
    /// Device ID as raw u32.
    pub device_id_raw: u32,
}

impl fmt::Display for HwIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "board={} mac={} dev={} rev={}",
            self.board_id, self.mac, self.device_id, self.hw_revision
        )
    }
}

impl HwIdentity {
    /// Read hardware identity from the EEPROM MTD device.
    ///
    /// Tries `/dev/mtd4ro` first, then scans `/proc/mtd` to find the
    /// partition named "eeprom" and opens the corresponding read-only device.
    ///
    /// Returns `None` if the EEPROM is not available or contains no valid data.
    #[must_use]
    pub fn read() -> Option<Self> {
        let dev = find_eeprom_mtd()?;
        let data = read_mtd_bytes(&dev, 0, 0x14)?;

        // Validate: at least the MAC must not be all-FF or all-00
        let mac_bytes: [u8; 6] = data[0..6].try_into().ok()?;
        if mac_bytes == [0xFF; 6] || mac_bytes == [0x00; 6] {
            return None;
        }

        let board_id_raw = u16::from_be_bytes([data[0x0C], data[0x0D]]);
        let hw_rev_raw = u16::from_be_bytes([data[0x0E], data[0x0F]]);
        let device_id_raw =
            u32::from_be_bytes([data[0x10], data[0x11], data[0x12], data[0x13]]);

        let id = HwIdentity {
            board_id: format!("{board_id_raw:04x}"),
            mac: format_mac(&mac_bytes),
            mac_raw: mac_bytes,
            hw_revision: format!("{hw_rev_raw:04x}"),
            device_id: format!("{device_id_raw:08x}"),
            device_id_raw,
        };

        Some(id)
    }

    /// Return the identity as a stable byte fingerprint for key derivation.
    ///
    /// Format: `mac_raw(6) || device_id_be(4) || board_id_be(2)`
    /// Total: 12 bytes, deterministic across reboots.
    #[must_use]
    pub fn fingerprint(&self) -> Vec<u8> {
        let mut fp = Vec::with_capacity(12);
        fp.extend_from_slice(&self.mac_raw);
        fp.extend_from_slice(&self.device_id_raw.to_be_bytes());
        fp.extend_from_slice(
            &u16::from_str_radix(&self.board_id, 16)
                .unwrap_or(0)
                .to_be_bytes(),
        );
        fp
    }
}

/// Find the MTD device for the "eeprom" partition.
fn find_eeprom_mtd() -> Option<String> {
    // Fast path: DTS puts eeprom at mtd4 on all known Ubiquiti Alpine V2 boards
    let default = "/dev/mtd4ro";
    if Path::new(default).exists() {
        // Verify it's actually named "eeprom"
        if let Some(name) = mtd_partition_name("mtd4") {
            if name == "eeprom" {
                return Some(default.to_string());
            }
        }
        // Even if we can't verify the name, try it (might work on minimal systems)
    }

    // Slow path: scan /proc/mtd for the "eeprom" partition
    let proc_mtd = fs::read_to_string("/proc/mtd").ok()?;
    for line in proc_mtd.lines().skip(1) {
        // Format: mtdN: SIZE ERASESIZE "name"
        if line.contains("\"eeprom\"") {
            let dev = line.split(':').next()?.trim();
            let path = format!("/dev/{dev}ro");
            if Path::new(&path).exists() {
                return Some(path);
            }
            // Try without "ro" suffix
            let path = format!("/dev/{dev}");
            if Path::new(&path).exists() {
                return Some(path);
            }
        }
    }

    // Last resort: try the default path even without name verification
    if Path::new(default).exists() {
        return Some(default.to_string());
    }

    None
}

/// Read the partition name from sysfs for a given MTD device.
fn mtd_partition_name(dev: &str) -> Option<String> {
    let path = format!("/sys/class/mtd/{dev}/name");
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// Read `len` bytes from an MTD device starting at `offset`.
fn read_mtd_bytes(path: &str, offset: u64, len: usize) -> Option<Vec<u8>> {
    let mut file = fs::File::open(path).ok()?;
    if offset > 0 {
        std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(offset)).ok()?;
    }
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).ok()?;
    Some(buf)
}

/// Format 6 bytes as a colon-separated MAC address.
fn format_mac(bytes: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_mac() {
        assert_eq!(
            format_mac(&[0x74, 0xAC, 0xB9, 0x14, 0x46, 0x39]),
            "74:ac:b9:14:46:39"
        );
    }

    #[test]
    fn test_fingerprint_length() {
        let id = HwIdentity {
            board_id: "ea15".to_string(),
            mac: "74:ac:b9:14:46:39".to_string(),
            mac_raw: [0x74, 0xAC, 0xB9, 0x14, 0x46, 0x39],
            hw_revision: "0777".to_string(),
            device_id: "0002d308".to_string(),
            device_id_raw: 0x0002d308,
        };
        let fp = id.fingerprint();
        assert_eq!(fp.len(), 12);
        // MAC bytes
        assert_eq!(&fp[0..6], &[0x74, 0xAC, 0xB9, 0x14, 0x46, 0x39]);
        // Device ID big-endian
        assert_eq!(&fp[6..10], &[0x00, 0x02, 0xD3, 0x08]);
        // Board ID big-endian
        assert_eq!(&fp[10..12], &[0xEA, 0x15]);
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let id = HwIdentity {
            board_id: "ea15".to_string(),
            mac: "74:ac:b9:14:46:39".to_string(),
            mac_raw: [0x74, 0xAC, 0xB9, 0x14, 0x46, 0x39],
            hw_revision: "0777".to_string(),
            device_id: "0002d308".to_string(),
            device_id_raw: 0x0002d308,
        };
        assert_eq!(id.fingerprint(), id.fingerprint());
    }

    #[test]
    fn test_display() {
        let id = HwIdentity {
            board_id: "ea15".to_string(),
            mac: "74:ac:b9:14:46:39".to_string(),
            mac_raw: [0x74, 0xAC, 0xB9, 0x14, 0x46, 0x39],
            hw_revision: "0777".to_string(),
            device_id: "0002d308".to_string(),
            device_id_raw: 0x0002d308,
        };
        let s = id.to_string();
        assert!(s.contains("ea15"));
        assert!(s.contains("74:ac:b9:14:46:39"));
    }

    #[test]
    fn test_read_does_not_panic() {
        // On dev machines without MTD, should return None gracefully
        let _ = HwIdentity::read();
    }
}
