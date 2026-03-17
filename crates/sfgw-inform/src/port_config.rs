// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-port configuration for managed UniFi switches.
//!
//! Port config is stored in the DB as part of the device record and applied
//! to the switch via SSH (`swconfig` commands). The switch's `swconfig` driver
//! (MT7621 on USW-Flex) supports: PVID, port disable, egress tagging mode,
//! port isolation, egress rate limit, and PoE control.

use serde::{Deserialize, Serialize};

/// Per-port configuration for a switch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchPortConfig {
    /// Physical port index (1-based, matching port_table from Inform).
    pub port_idx: u32,
    /// Human-readable label (e.g. "Office AP", "Camera NVR").
    #[serde(default)]
    pub name: String,
    /// Whether the port is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// PVID — native/untagged VLAN ID for this port.
    /// Determines which zone/network the port belongs to.
    #[serde(default = "default_vlan")]
    pub pvid: u16,
    /// PoE mode: "auto", "off", "passthrough" (if port supports PoE).
    #[serde(default = "default_poe_mode")]
    pub poe_mode: String,
    /// Egress tagging mode for non-native VLANs.
    /// "untagged" (default), "tagged" (trunk), "disabled" (access-only).
    #[serde(default = "default_egress_mode")]
    pub egress_mode: String,
    /// Tagged VLAN IDs this port should trunk (empty = access port).
    #[serde(default)]
    pub tagged_vlans: Vec<u16>,
    /// Port isolation (prevents inter-client traffic on same VLAN).
    #[serde(default)]
    pub isolation: bool,
    /// Egress rate limit in Kbps (0 = unlimited).
    #[serde(default)]
    pub egress_rate_limit_kbps: u32,
}

/// Full switch port configuration (all ports).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SwitchConfig {
    pub ports: Vec<SwitchPortConfig>,
}

fn default_true() -> bool {
    true
}

fn default_vlan() -> u16 {
    1
}

fn default_poe_mode() -> String {
    "auto".into()
}

fn default_egress_mode() -> String {
    "untagged".into()
}

impl SwitchConfig {
    /// Generate default config for a switch with `num_ports` user-facing ports.
    pub fn default_for_ports(num_ports: u32) -> Self {
        Self {
            ports: (1..=num_ports)
                .map(|idx| SwitchPortConfig {
                    port_idx: idx,
                    name: String::new(),
                    enabled: true,
                    pvid: 1,
                    poe_mode: "auto".into(),
                    egress_mode: "untagged".into(),
                    tagged_vlans: Vec::new(),
                    isolation: false,
                    egress_rate_limit_kbps: 0,
                })
                .collect(),
        }
    }

    /// Generate swconfig commands to apply this config to the switch.
    ///
    /// Returns a shell script fragment that uses `swconfig dev switch0`.
    /// Port mapping: user port 1 = swconfig port 4, port 2 = 3, etc.
    /// (MT7621 on USW-Flex maps physical ports in reverse order,
    /// CPU port is always 6.)
    pub fn to_swconfig_commands(&self, port_map: &dyn Fn(u32) -> u32) -> String {
        let mut cmds = Vec::new();

        // Enable VLAN mode
        cmds.push("swconfig dev switch0 set enable_vlan 1".into());

        // Collect all VLANs we need
        let mut vlan_ports: std::collections::HashMap<u16, Vec<(u32, bool)>> =
            std::collections::HashMap::new();

        for port in &self.ports {
            let sw_port = port_map(port.port_idx);

            // Port enable/disable
            cmds.push(format!(
                "swconfig dev switch0 port {} set disable {}",
                sw_port,
                if port.enabled { 0 } else { 1 }
            ));

            // PVID
            cmds.push(format!(
                "swconfig dev switch0 port {} set pvid {}",
                sw_port, port.pvid
            ));

            // Native VLAN — port is untagged member
            vlan_ports
                .entry(port.pvid)
                .or_default()
                .push((sw_port, false)); // false = untagged

            // Tagged VLANs — port is tagged member
            for &vid in &port.tagged_vlans {
                vlan_ports.entry(vid).or_default().push((sw_port, true)); // true = tagged
            }

            // Port isolation
            cmds.push(format!(
                "swconfig dev switch0 port {} set protected {}",
                sw_port,
                if port.isolation { 1 } else { 0 }
            ));

            // Egress rate limit (in multiples of 32Kbps)
            let cir = port.egress_rate_limit_kbps / 32;
            cmds.push(format!(
                "swconfig dev switch0 port {} set qos_egress_cir {}",
                sw_port, cir
            ));
        }

        // CPU port (6) must be tagged member of all VLANs
        let cpu_port = 6u32;
        for ports in vlan_ports.values_mut() {
            ports.push((cpu_port, true));
        }

        // Configure VLANs
        for (vid, ports) in &vlan_ports {
            let port_str: String = ports
                .iter()
                .map(|(p, tagged)| {
                    if *tagged {
                        format!("{}t", p)
                    } else {
                        p.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            cmds.push(format!("swconfig dev switch0 vlan {} set vid {}", vid, vid));
            cmds.push(format!(
                "swconfig dev switch0 vlan {} set ports \"{}\"",
                vid, port_str
            ));
        }

        // Apply
        cmds.push("swconfig dev switch0 set apply".into());

        cmds.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_all_ports() {
        let cfg = SwitchConfig::default_for_ports(5);
        assert_eq!(cfg.ports.len(), 5);
        assert_eq!(cfg.ports[0].port_idx, 1);
        assert_eq!(cfg.ports[4].port_idx, 5);
        assert!(cfg.ports[0].enabled);
        assert_eq!(cfg.ports[0].pvid, 1);
        assert_eq!(cfg.ports[0].poe_mode, "auto");
    }

    #[test]
    fn swconfig_commands_basic() {
        let mut cfg = SwitchConfig::default_for_ports(2);
        cfg.ports[0].pvid = 10;
        cfg.ports[1].pvid = 20;
        cfg.ports[1].enabled = false;

        // Simple identity mapping for test
        let cmds = cfg.to_swconfig_commands(&|p| p);
        assert!(cmds.contains("set enable_vlan 1"));
        assert!(cmds.contains("port 1 set pvid 10"));
        assert!(cmds.contains("port 2 set pvid 20"));
        assert!(cmds.contains("port 1 set disable 0"));
        assert!(cmds.contains("port 2 set disable 1"));
        assert!(cmds.contains("set apply"));
    }

    #[test]
    fn swconfig_tagged_vlans() {
        let mut cfg = SwitchConfig::default_for_ports(1);
        cfg.ports[0].pvid = 1;
        cfg.ports[0].tagged_vlans = vec![10, 20];

        let cmds = cfg.to_swconfig_commands(&|p| p);
        // Port should be in VLAN 1 (untagged), 10 (tagged), 20 (tagged)
        assert!(cmds.contains("vlan 1 set ports"));
        assert!(cmds.contains("vlan 10 set ports"));
        assert!(cmds.contains("vlan 20 set ports"));
    }

    #[test]
    fn serialization_roundtrip() {
        let cfg = SwitchConfig::default_for_ports(5);
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: SwitchConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.ports.len(), 5);
        assert_eq!(parsed.ports[2].port_idx, 3);
    }
}
