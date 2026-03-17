// SPDX-License-Identifier: AGPL-3.0-or-later

//! JSON payload types for Ubiquiti Inform protocol.
//!
//! Inform payloads are JSON objects sent by the device and responses from the
//! controller. These types model the subset we need for adoption and hardening.

use serde::{Deserialize, Serialize};

/// Inform payload sent by a device (decrypted JSON).
///
/// Fields marked `default` are optional — not all devices/firmware versions
/// send every field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InformPayload {
    /// Whether the device is in factory-default state.
    #[serde(default)]
    pub default: bool,

    /// Device hostname.
    #[serde(default)]
    pub hostname: String,

    /// Device IP (self-declared — do NOT trust, compare with source IP).
    #[serde(default)]
    pub ip: String,

    /// Device MAC address (colon-separated hex).
    #[serde(default)]
    pub mac: String,

    /// Model code (e.g. "US16P150" for USW-16-POE, "U7PG2" for UAP-AC-Pro).
    #[serde(default)]
    pub model: String,

    /// Human-readable model name.
    #[serde(default)]
    pub model_display: String,

    /// Device state: 0 = unknown/default, 1 = connected, 2 = adopting, etc.
    #[serde(default)]
    pub state: u32,

    /// Firmware version string.
    #[serde(default)]
    pub version: String,

    /// Board revision.
    #[serde(default)]
    pub board_rev: u32,

    /// Bootrom version string.
    #[serde(default)]
    pub bootrom_version: String,

    /// Configuration version hash (16 hex chars). "0000000000000000" if unconfigured.
    #[serde(default)]
    pub cfgversion: String,

    /// Firmware capabilities bitmask.
    #[serde(default)]
    pub fw_caps: u64,

    /// Guest portal token.
    #[serde(default)]
    pub guest_token: String,

    /// Whether this is a discovery/broadcast response.
    #[serde(default)]
    pub discovery_response: bool,

    /// Unix timestamp from device.
    #[serde(default)]
    pub time: u64,

    /// Device uptime in seconds.
    #[serde(default)]
    pub uptime: u64,

    // --- Stats fields (sent every inform cycle) ---

    /// Per-port statistics (switches). APs send radio_table instead (caught by extra).
    #[serde(default)]
    pub port_table: Vec<SwitchPortStats>,

    /// System resource stats (loadavg, mem).
    #[serde(default)]
    pub sys_stats: Option<SysStats>,

    /// Compact system stats (cpu%, mem%, uptime as strings).
    #[serde(default, rename = "system-stats")]
    pub system_stats: Option<SystemStats>,

    /// Network interface table.
    #[serde(default)]
    pub if_table: Vec<IfStats>,

    /// Kernel version.
    #[serde(default)]
    pub kernel_version: String,

    /// CPU architecture (mips, arm, aarch64, etc.).
    #[serde(default)]
    pub architecture: String,

    /// Device serial number.
    #[serde(default)]
    pub serial: String,

    /// Human-readable uptime string (e.g. "44m35s").
    #[serde(default)]
    pub uptime_str: String,

    /// Overall satisfaction score (0-100).
    #[serde(default)]
    pub satisfaction: i32,

    /// PoE input voltage (for PoE-powered devices like USW-Flex).
    #[serde(default)]
    pub power_source_voltage: Option<String>,

    /// Max PoE power budget in watts.
    #[serde(default)]
    pub total_max_power: Option<u32>,

    /// Whether device reports overheating.
    #[serde(default)]
    pub overheating: bool,

    /// Whether device has internet connectivity.
    #[serde(default)]
    pub internet: bool,

    /// Gateway IP as seen by device.
    #[serde(default)]
    pub gateway_ip: String,

    /// Total MACs in forwarding table.
    #[serde(default)]
    pub total_mac_in_used: u32,

    /// Catch-all for unknown fields (forward compatibility).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

// =============================================================================
// Common stats types (all device types)
// =============================================================================

/// System resource statistics (loadavg, memory).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysStats {
    #[serde(default)]
    pub loadavg_1: String,
    #[serde(default)]
    pub loadavg_5: String,
    #[serde(default)]
    pub loadavg_15: String,
    #[serde(default)]
    pub mem_total: u64,
    #[serde(default)]
    pub mem_used: u64,
    #[serde(default)]
    pub mem_buffer: u64,
}

/// Compact system stats (CPU%, MEM% as strings).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStats {
    #[serde(default)]
    pub cpu: String,
    #[serde(default)]
    pub mem: String,
    #[serde(default)]
    pub uptime: String,
}

/// Network interface stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IfStats {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub netmask: String,
    #[serde(default)]
    pub up: bool,
    #[serde(default)]
    pub speed: u32,
    #[serde(default)]
    pub full_duplex: bool,
    #[serde(default)]
    pub num_port: u32,
    #[serde(default)]
    pub rx_bytes: u64,
    #[serde(default)]
    pub rx_packets: u64,
    #[serde(default)]
    pub tx_bytes: u64,
    #[serde(default)]
    pub tx_packets: u64,
}

// =============================================================================
// Switch-specific types
// =============================================================================

/// Per-port statistics (switches only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchPortStats {
    pub port_idx: u32,
    #[serde(default)]
    pub up: bool,
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub speed: u32,
    #[serde(default)]
    pub full_duplex: bool,
    #[serde(default)]
    pub media: String,
    #[serde(default)]
    pub is_uplink: bool,
    // Traffic counters
    #[serde(default)]
    pub rx_bytes: u64,
    #[serde(default)]
    pub rx_packets: u64,
    #[serde(default)]
    pub rx_errors: u64,
    #[serde(default)]
    pub rx_dropped: u64,
    #[serde(default)]
    pub rx_broadcast: u64,
    #[serde(default)]
    pub rx_multicast: u64,
    #[serde(default)]
    pub tx_bytes: u64,
    #[serde(default)]
    pub tx_packets: u64,
    #[serde(default)]
    pub tx_errors: u64,
    #[serde(default)]
    pub tx_dropped: u64,
    #[serde(default)]
    pub tx_broadcast: u64,
    #[serde(default)]
    pub tx_multicast: u64,
    // PoE (per-port)
    #[serde(default)]
    pub port_poe: bool,
    #[serde(default)]
    pub poe_caps: u32,
    #[serde(default)]
    pub poe_enable: Option<bool>,
    #[serde(default)]
    pub poe_good: Option<bool>,
    #[serde(default)]
    pub poe_mode: Option<String>,
    #[serde(default)]
    pub poe_class: Option<String>,
    #[serde(default)]
    pub poe_current: Option<String>,
    #[serde(default)]
    pub poe_voltage: Option<String>,
    #[serde(default)]
    pub poe_power: Option<String>,
    // STP
    #[serde(default)]
    pub stp_state: String,
    // MAC table on this port
    #[serde(default)]
    pub mac_table: Vec<MacEntry>,
    #[serde(default)]
    pub satisfaction: i32,
}

/// MAC address table entry on a switch port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacEntry {
    pub mac: String,
    #[serde(default)]
    pub age: u64,
    #[serde(default)]
    pub uptime: u64,
    #[serde(default)]
    pub vlan: u32,
    #[serde(rename = "static", default)]
    pub is_static: bool,
}

// =============================================================================
// AP-specific types (placeholder — expand when we have an AP to test)
// =============================================================================

// TODO: radio_table, vap_table, sta_table when AP inform dumps are available

/// Server response to an Inform (sent back encrypted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InformResponse {
    /// Response type. Common values:
    /// - `"noop"` — nothing to do, come back later
    /// - `"setparam"` — deliver management config (authkey, inform URL, etc.)
    /// - `"upgrade"` — trigger firmware upgrade
    /// - `"cmd"` — execute a command
    #[serde(rename = "_type")]
    pub response_type: String,

    /// Interval in seconds until the next inform.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,

    /// Server time as Unix timestamp in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_time_in_utc: Option<String>,

    /// Management config string (newline-separated key=value pairs).
    /// Sent with `_type: "setparam"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mgmt_cfg: Option<String>,

    /// System configuration (full device config).
    /// Sent after adoption when device re-informs with authkey.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_cfg: Option<String>,

    /// Catch-all for extra fields.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl InformResponse {
    /// Create a "noop" response — device should re-inform after `interval` seconds.
    pub fn noop(interval: u64) -> Self {
        Self {
            response_type: "noop".into(),
            interval: Some(interval),
            server_time_in_utc: Some(now_millis()),
            mgmt_cfg: None,
            system_cfg: None,
            extra: serde_json::Map::new(),
        }
    }

    /// Create a "setparam" response with management config (authkey delivery).
    pub fn setparam(mgmt_cfg: String, interval: u64) -> Self {
        Self {
            response_type: "setparam".into(),
            interval: Some(interval),
            server_time_in_utc: Some(now_millis()),
            mgmt_cfg: Some(mgmt_cfg),
            system_cfg: None,
            extra: serde_json::Map::new(),
        }
    }

    /// Create a "setparam" response with full system configuration.
    pub fn setparam_with_system_cfg(mgmt_cfg: String, system_cfg: String, interval: u64) -> Self {
        Self {
            response_type: "setparam".into(),
            interval: Some(interval),
            server_time_in_utc: Some(now_millis()),
            mgmt_cfg: Some(mgmt_cfg),
            system_cfg: Some(system_cfg),
            extra: serde_json::Map::new(),
        }
    }
}

/// Current time as millisecond Unix timestamp string (for server_time_in_utc).
fn now_millis() -> String {
    chrono::Utc::now().timestamp_millis().to_string()
}

/// Known Ubiquiti MAC OUI prefixes (first 3 bytes).
/// Used for passive validation of Inform source.
const UBIQUITI_OUIS: &[[u8; 3]] = &[
    [0x04, 0x18, 0xD6],
    [0x18, 0xE8, 0x29],
    [0x24, 0x5A, 0x4C],
    [0x24, 0xA4, 0x3C],
    [0x44, 0xD9, 0xE7],
    [0x68, 0x72, 0x51],
    [0x74, 0x83, 0xC2],
    [0x74, 0xAC, 0xB9],
    [0x78, 0x8A, 0x20],
    [0x80, 0x2A, 0xA8],
    [0xAC, 0x8B, 0xA9],
    [0xB4, 0xFB, 0xE4],
    [0xD0, 0x21, 0xF9],
    [0xDC, 0x9F, 0xDB],
    [0xE0, 0x63, 0xDA],
    [0xF0, 0x9F, 0xC2],
    [0xFC, 0xEC, 0xDA],
];

/// Check whether a MAC address has a known Ubiquiti OUI prefix.
pub fn is_ubiquiti_oui(mac: &[u8; 6]) -> bool {
    let oui = [mac[0], mac[1], mac[2]];
    UBIQUITI_OUIS.contains(&oui)
}

/// Known Ubiquiti model codes and their human-readable names.
pub fn model_name(code: &str) -> Option<&'static str> {
    match code {
        // Switches
        "USF5P" => Some("USW-Flex"),
        "USXG" => Some("USW-Flex-XG"),
        "US8" => Some("US-8"),
        "US8P60" => Some("US-8-60W"),
        "US8P150" => Some("US-8-150W"),
        "US16P150" => Some("USW-16-POE"),
        "US24" => Some("US-24"),
        "US24P250" => Some("USW-24-POE"),
        "US24P500" => Some("USW-Pro-24-POE"),
        "US48" => Some("US-48"),
        "US48P500" => Some("USW-48-POE"),
        "US48P750" => Some("USW-Pro-48-POE"),
        "USMINI" => Some("USW-Flex-Mini"),
        // APs
        "BZ2" => Some("UAP"),
        "BZ2LR" => Some("UAP-LR"),
        "U2S48" => Some("UAP-Outdoor+"),
        "U7E" => Some("UAP-AC"),
        "U7PG2" => Some("UAP-AC-Pro"),
        "U7LT" => Some("UAP-AC-Lite"),
        "U7LR" => Some("UAP-AC-LR"),
        "U7MSH" => Some("UAP-AC-Mesh"),
        "U7MP" => Some("UAP-AC-Mesh-Pro"),
        "U6PRO" => Some("U6-Pro"),
        "U6LITE" => Some("U6-Lite"),
        "U6LR" => Some("U6-LR"),
        "U6PLUS" => Some("U6+"),
        "U6ENT" => Some("U6-Enterprise"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_response_serializes() {
        let resp = InformResponse::noop(30);
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(json.contains("\"_type\":\"noop\""));
        assert!(json.contains("\"interval\":30"));
    }

    #[test]
    fn ubiquiti_oui_check() {
        // AC:8B:A9 is Ubiquiti (USW-Flex MAC)
        assert!(is_ubiquiti_oui(&[0xAC, 0x8B, 0xA9, 0xA8, 0xA5, 0xE1]));
        // 74:AC:B9 is Ubiquiti
        assert!(is_ubiquiti_oui(&[0x74, 0xAC, 0xB9, 0xDE, 0xAD, 0x01]));
        // Random MAC is not
        assert!(!is_ubiquiti_oui(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    }

    #[test]
    fn known_models() {
        assert_eq!(model_name("U7PG2"), Some("UAP-AC-Pro"));
        assert_eq!(model_name("USXG"), Some("USW-Flex-XG"));
        assert_eq!(model_name("USF5P"), Some("USW-Flex"));
        assert_eq!(model_name("UNKNOWN"), None);
    }

    #[test]
    fn inform_payload_deserialize_minimal() {
        let json = r#"{"mac":"aa:bb:cc:dd:ee:ff","default":true}"#;
        let payload: InformPayload = serde_json::from_str(json).expect("deserialize");
        assert!(payload.default);
        assert_eq!(payload.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(payload.model, ""); // default empty
    }

    #[test]
    fn inform_payload_parses_real_usf5p_dump() {
        let json = include_str!("../../../docs/inform_dump_usf5p.json");
        let payload: InformPayload = serde_json::from_str(json).expect("deserialize USF5P dump");
        assert_eq!(payload.mac, "ac:8b:a9:a8:a5:e1");
        assert_eq!(payload.model, "USF5P");
        assert_eq!(payload.hostname, "USW-Flex");
        assert_eq!(payload.architecture, "mips");
        assert_eq!(payload.kernel_version, "4.4.153");
        assert_eq!(payload.serial, "AC8BA9A8A5E1");
        assert!(!payload.overheating);
        assert!(payload.internet);
        assert_eq!(payload.satisfaction, 100);
        assert_eq!(payload.gateway_ip, "10.0.0.1");

        // port_table: 5 ports
        assert_eq!(payload.port_table.len(), 5);
        let port1 = &payload.port_table[0];
        assert_eq!(port1.port_idx, 1);
        assert!(port1.up);
        assert!(port1.is_uplink);
        assert_eq!(port1.speed, 1000);
        assert!(port1.full_duplex);
        assert!(!port1.port_poe);
        assert_eq!(port1.mac_table.len(), 2);
        assert_eq!(port1.mac_table[0].mac, "76:ac:b9:14:46:3a");

        let port2 = &payload.port_table[1];
        assert!(!port2.up);
        assert!(port2.port_poe);
        assert_eq!(port2.poe_caps, 3);

        // sys_stats
        let sys = payload.sys_stats.as_ref().expect("sys_stats");
        assert_eq!(sys.mem_total, 127266816);
        assert!(sys.mem_used > 0);

        // system-stats
        let ss = payload.system_stats.as_ref().expect("system-stats");
        assert!(!ss.cpu.is_empty());
        assert!(!ss.mem.is_empty());

        // if_table
        assert_eq!(payload.if_table.len(), 1);
        assert_eq!(payload.if_table[0].name, "eth0");
        assert_eq!(payload.if_table[0].num_port, 5);
    }
}
