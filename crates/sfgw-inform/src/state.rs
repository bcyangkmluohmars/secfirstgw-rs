// SPDX-License-Identifier: AGPL-3.0-or-later

//! Device state machine for Ubiquiti Inform adoption.
//!
//! States:
//! - **Pending**  — passed passive validation, waiting for admin decision
//! - **Ignored**  — admin clicked "Ignore", separate tab, still accepts informs
//! - **Adopting** — admin clicked "Adopt", SSH verification + hardening in progress
//! - **Adopted**  — verified, authkey exchanged, system_cfg provisioned
//! - **Phantom**  — passive validation failed, logged as security event

use crate::payload::{IfStats, SwitchPortStats, SysStats, SystemStats};
use crate::port_config::SwitchConfig;
use serde::{Deserialize, Serialize};

/// Ubiquiti device lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UbntDeviceState {
    /// Passed passive validation, awaiting admin decision.
    Pending,
    /// Admin ignored — separate UI tab, informs still accepted silently.
    Ignored,
    /// Adoption in progress (SSH verification + hardening).
    Adopting,
    /// Fully adopted — authkey exchanged, system_cfg provisioned.
    Adopted,
    /// Passive validation failed — security event logged.
    Phantom,
}

impl std::fmt::Display for UbntDeviceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Ignored => write!(f, "ignored"),
            Self::Adopting => write!(f, "adopting"),
            Self::Adopted => write!(f, "adopted"),
            Self::Phantom => write!(f, "phantom"),
        }
    }
}

/// Trust indicators from passive Inform validation (Stufe 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Does the MAC have a known Ubiquiti OUI?
    pub oui_valid: bool,
    /// Does the source IP match the self-declared inform IP?
    pub ip_matches: bool,
    /// Is the model code recognized?
    pub model_known: bool,
    /// Human-readable reason if validation failed.
    pub reason: Option<String>,
}

impl ValidationResult {
    /// Whether all passive checks passed.
    pub fn is_valid(&self) -> bool {
        self.oui_valid && self.ip_matches && self.model_known
    }
}

/// Stored info about a Ubiquiti device seen via Inform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbntDevice {
    /// MAC address (colon-separated hex, lowercase).
    pub mac: String,
    /// Device model code (e.g. "USXG").
    pub model: String,
    /// Human-readable model name (e.g. "USW-Flex").
    pub model_display: String,
    /// Source IP address (from TCP connection, not self-declared).
    pub source_ip: String,
    /// Self-declared IP from Inform payload.
    pub claimed_ip: String,
    /// Firmware version.
    pub firmware_version: String,
    /// Hostname.
    pub hostname: String,
    /// Current state.
    pub state: UbntDeviceState,
    /// Per-device authkey (32-char hex). None until adopted.
    pub authkey: Option<String>,
    /// Per-device SSH username. None until adopted.
    pub ssh_username: Option<String>,
    /// Per-device SSH password (plaintext, for gateway→device management SSH).
    /// Stored so the gateway can SSH back to the device for management ops.
    pub ssh_password: Option<String>,
    /// Per-device SSH password hash (SHA-512 crypt). None until adopted.
    pub ssh_password_hash: Option<String>,
    /// Whether the device has applied its system_cfg (confirmed via cfgversion AND SSH verified).
    #[serde(default)]
    pub config_applied: bool,
    /// How many times we've delivered system_cfg without successful verification.
    /// Reset to 0 on successful verification. After 3 failures, alert admin.
    #[serde(default)]
    pub config_delivery_attempts: u32,
    /// Hardware fingerprint from `/proc/ubnthal/system.info`. None until SSH-verified.
    pub fingerprint: Option<HardwareFingerprint>,
    /// Last seen timestamp (RFC 3339).
    pub last_seen: String,
    /// First seen timestamp (RFC 3339).
    pub first_seen: String,
    /// Passive validation result.
    pub validation: ValidationResult,
    /// Per-port switch configuration (VLAN, PoE, isolation, etc.).
    /// Stored in DB, applied via SSH swconfig commands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_config: Option<SwitchConfig>,
    /// Latest device stats from Inform (updated every cycle in memory).
    /// Stored as null in DB — populated from live inform data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<DeviceStats>,
}

/// Live device statistics extracted from Inform payloads.
/// Updated every inform cycle (~30s), kept in memory only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStats {
    /// Per-port stats (switches). APs will have radio_table separately.
    pub port_table: Vec<SwitchPortStats>,
    /// System resource stats.
    pub sys_stats: Option<SysStats>,
    /// Compact system stats (CPU%, MEM%).
    pub system_stats: Option<SystemStats>,
    /// Network interface table.
    pub if_table: Vec<IfStats>,
    /// Device uptime in seconds.
    pub uptime: u64,
    /// Human-readable uptime.
    pub uptime_str: String,
    /// Satisfaction score (0-100).
    pub satisfaction: i32,
    /// PoE input voltage (PoE-powered devices).
    pub power_source_voltage: Option<String>,
    /// Max PoE power budget (watts).
    pub total_max_power: Option<u32>,
    /// Overheating flag.
    pub overheating: bool,
    /// Internet connectivity.
    pub internet: bool,
    /// Kernel version.
    pub kernel_version: String,
    /// CPU architecture.
    pub architecture: String,
    /// Device serial.
    pub serial: String,
    /// Total MACs in FDB.
    pub total_mac_in_used: u32,
    /// Gateway IP as seen by device.
    pub gateway_ip: String,
    /// Timestamp of this stats snapshot.
    pub updated_at: String,
}

/// Hardware fingerprint from EEPROM (not software-alterable).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareFingerprint {
    pub cpuid: String,
    pub serialno: String,
    pub device_hashid: String,
    pub systemid: String,
    pub boardrevision: String,
    pub vendorid: String,
    pub manufid: String,
    pub mfgweek: String,
}
