// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hardware switch ASIC configuration and Linux bridge/VLAN setup.
//!
//! This module is platform-agnostic. Hardware-specific details (switch device
//! name, port layout, CPU port) are passed in via [`SwitchLayout`].
//! On platforms without a switch ASIC, only Linux bridges are created.
//!
//! # Bridge migration
//!
//! Legacy bridges (br0, br1, ...) from previous firmware are migrated
//! rather than deleted-and-recreated. This preserves connectivity during
//! the transition:
//!
//! 1. br0 is renamed to br-lan (keeps members, IPs, state)
//! 2. New bridges (br-mgmt, br-guest, br-dmz) are created fresh
//! 3. VLAN sub-interfaces are attached to their bridges
//! 4. Gateway IPs are assigned
//!
//! This means SSH connections survive the firmware transition.

use crate::Result;
use anyhow::Context;
use std::process::Command;

/// Describes the hardware switch port layout.
///
/// Provided by platform-specific detection (e.g. Ubiquiti board ID).
/// On platforms without a switch ASIC this is `None` and only Linux
/// bridges are created.
#[derive(Debug, Clone)]
pub struct SwitchLayout {
    /// swconfig device name (e.g. "switch0").
    pub device: String,
    /// Switch port numbers that are LAN ports (e.g. [0,1,2,3,4,5,6]).
    pub lan_ports: Vec<u8>,
    /// CPU port number (internal, always tagged in every VLAN).
    pub cpu_port: u8,
    /// Additional internal ports that should be tagged in every VLAN
    /// (e.g. SFP+ LAN uplink port).
    pub internal_ports: Vec<u8>,
    /// Dedicated MGMT port number, if any. This port gets its own PVID
    /// set to the MGMT VLAN and is excluded from the LAN VLAN.
    pub mgmt_port: Option<u8>,
}

/// A network zone to be provisioned on the switch and as a Linux bridge.
#[derive(Debug)]
pub struct NetworkSetup {
    pub zone: String,
    pub vlan_id: Option<i32>,
    pub subnet: String,
    pub gateway: String,
}

/// Configure VLANs and bridges for all enabled networks.
///
/// - With a [`SwitchLayout`]: configures hardware switch VLANs via swconfig,
///   creates VLAN sub-interfaces, and sets up Linux bridges.
/// - Without: creates only Linux bridges (VM/Docker mode).
///
/// Legacy bridges are migrated, not destroyed. SSH survives.
pub async fn setup_networks(db: &sfgw_db::Db, switch: Option<&SwitchLayout>) -> Result<()> {
    let networks = load_enabled_networks(db).await?;

    if networks.is_empty() {
        tracing::debug!("no enabled networks — skipping bridge setup");
        return Ok(());
    }

    // Step 1: Migrate legacy bridges (br0 → br-lan, etc.)
    migrate_legacy_bridges(&networks);

    // Step 2: Configure hardware switch VLANs
    if let Some(sw) = switch {
        setup_switch_vlans(sw, &networks)?;
    }

    // Step 3: Ensure all bridges exist with correct VLAN attachments and IPs
    let switch_dev = switch.map(|sw| sw.device.as_str());
    setup_bridges(&networks, switch_dev)?;

    Ok(())
}

/// Load enabled networks from the `networks` table.
async fn load_enabled_networks(db: &sfgw_db::Db) -> Result<Vec<NetworkSetup>> {
    let conn = db.lock().await;
    let mut stmt = conn
        .prepare("SELECT zone, vlan_id, subnet, gateway FROM networks WHERE enabled = 1")
        .context("failed to query enabled networks")?;

    let rows = stmt
        .query_map([], |row| {
            Ok(NetworkSetup {
                zone: row.get(0)?,
                vlan_id: row.get(1)?,
                subnet: row.get(2)?,
                gateway: row.get(3)?,
            })
        })
        .context("failed to read networks")?;

    let mut networks = Vec::new();
    for row in rows {
        networks.push(row.context("failed to read network row")?);
    }

    Ok(networks)
}

// ── Bridge migration ────────────────────────────────────────────────

/// Migrate legacy bridges to our naming scheme without losing connectivity.
///
/// Strategy:
/// - br0 → br-lan (rename, preserves members + IPs + state)
/// - br1, br2, ... → delete (no equivalent, will be recreated)
///
/// If br-lan already exists, legacy bridges are just cleaned up.
fn migrate_legacy_bridges(networks: &[NetworkSetup]) {
    let has_lan = networks.iter().any(|n| n.zone == "lan");

    // Try to rename br0 → br-lan if br-lan doesn't exist yet
    if has_lan && link_exists("br0") && !link_exists("br-lan") {
        tracing::info!("migrating br0 → br-lan (preserving connectivity)");

        // Rename keeps all members, IPs, and state
        let _ = run_ip(&["link", "set", "br0", "down"]);
        match run_ip(&["link", "set", "br0", "name", "br-lan"]) {
            Ok(()) => {
                let _ = run_ip(&["link", "set", "br-lan", "up"]);
                tracing::info!("bridge migration br0 → br-lan complete");
            }
            Err(e) => {
                // Rename failed — bring br0 back up to keep connectivity
                let _ = run_ip(&["link", "set", "br0", "up"]);
                tracing::warn!("bridge rename failed, keeping br0: {e}");
            }
        }
    }

    // Clean up any remaining legacy bridges (br1, br2, ...)
    let sysfs = std::path::Path::new("/sys/class/net");
    let entries = match std::fs::read_dir(sysfs) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();

        // Only clean up brN pattern (not br-lan, br-mgmt, etc.)
        if !name.starts_with("br") || name.starts_with("br-") {
            continue;
        }
        let suffix = &name[2..];
        if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        // Don't touch br0 if we didn't rename it
        if name == "br0" {
            continue;
        }
        if !entry.path().join("bridge").exists() {
            continue;
        }

        tracing::info!(bridge = %name, "removing legacy bridge");
        let _ = run_ip(&["link", "set", &name, "down"]);
        let _ = run_ip(&["link", "del", &name]);
    }
}

// ── Switch ASIC (swconfig) ──────────────────────────────────────────

/// Configure VLANs on the hardware switch ASIC via `swconfig`.
///
/// All VLANs are placed on all LAN ports (tagged). Exceptions:
/// - LAN (VLAN 1): LAN ports untagged, MGMT port excluded
/// - MGMT port gets its own PVID for untagged MGMT access
/// - CPU and internal ports: always tagged in every VLAN
///
/// Cleans up stale VLANs from previous firmware before applying.
fn setup_switch_vlans(sw: &SwitchLayout, networks: &[NetworkSetup]) -> Result<()> {
    // Collect our VLAN IDs
    let our_vlans: Vec<i32> = networks
        .iter()
        .map(|n| match &n.zone[..] {
            "lan" => 1,
            _ => n.vlan_id.unwrap_or(-1),
        })
        .filter(|v| *v > 0)
        .collect();

    // Clean up stale VLAN sub-interfaces (switch0.X where X is not one of ours)
    let sysfs = std::path::Path::new("/sys/class/net");
    if let Ok(entries) = std::fs::read_dir(sysfs) {
        let prefix = format!("{}.", sw.device);
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(vid_str) = name.strip_prefix(&prefix) {
                if let Ok(vid) = vid_str.parse::<i32>() {
                    if !our_vlans.contains(&vid) {
                        tracing::info!(iface = %name, vlan = vid, "removing stale VLAN sub-interface");
                        let _ = run_ip(&["link", "set", &name, "down"]);
                        let _ = run_ip(&["link", "del", &name]);
                    }
                }
            }
        }
    }

    // Clear stale VLANs on the switch ASIC.
    // Only check VLANs that had a Linux sub-interface (already discovered above)
    // plus a small range of commonly used VLANs (2-100) for thoroughness.
    let mut stale_vids: Vec<i32> = Vec::new();

    // Collect VLAN IDs from deleted sub-interfaces
    if let Ok(entries) = std::fs::read_dir(sysfs) {
        let prefix = format!("{}.", sw.device);
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(vid_str) = name.strip_prefix(&prefix) {
                if let Ok(vid) = vid_str.parse::<i32>() {
                    if !our_vlans.contains(&vid) {
                        stale_vids.push(vid);
                    }
                }
            }
        }
    }
    // Also check low VLANs (commonly used by other firmware)
    for vid in 2..100i32 {
        if !our_vlans.contains(&vid) && !stale_vids.contains(&vid) {
            if swconfig_vlan_has_ports(&sw.device, vid) {
                stale_vids.push(vid);
            }
        }
    }

    for vid in &stale_vids {
        tracing::info!(vlan = vid, "clearing stale switch VLAN");
        let _ = swconfig_set_vlan_ports(&sw.device, *vid, "");
    }

    for net in networks {
        let vid = match &net.zone[..] {
            "lan" => 1i32,
            _ => match net.vlan_id {
                Some(v) => v,
                None => {
                    tracing::warn!(
                        zone = %net.zone,
                        "no VLAN ID for non-LAN network, skipping switch setup"
                    );
                    continue;
                }
            },
        };

        let ports_str = build_port_string(vid, sw);
        swconfig_set_vlan_ports(&sw.device, vid, &ports_str)?;

        tracing::info!(
            vlan = vid,
            zone = %net.zone,
            ports = %ports_str,
            "configured switch VLAN"
        );
    }

    // Set MGMT port PVID
    if let Some(mp) = sw.mgmt_port {
        if let Some(mgmt_net) = networks.iter().find(|n| n.zone == "mgmt") {
            if let Some(vid) = mgmt_net.vlan_id {
                swconfig_set_pvid(&sw.device, mp, vid)?;
                tracing::info!(port = mp, pvid = vid, "set MGMT port PVID");
            }
        }
    }

    // Apply all changes atomically
    swconfig_apply(&sw.device)?;

    Ok(())
}

/// Build the swconfig port string for a VLAN.
///
/// - VLAN 1 (LAN): LAN ports untagged, MGMT port excluded
/// - Other VLANs: all ports tagged (LAN + MGMT)
/// - CPU and internal ports: always tagged
fn build_port_string(vlan_id: i32, sw: &SwitchLayout) -> String {
    let mut parts = Vec::new();

    if vlan_id == 1 {
        // LAN VLAN: LAN ports untagged, MGMT port excluded
        for &p in &sw.lan_ports {
            parts.push(format!("{p}"));
        }
    } else {
        // Non-LAN VLANs: all LAN ports tagged
        for &p in &sw.lan_ports {
            parts.push(format!("{p}t"));
        }
        // MGMT port tagged (PVID handles untagged ingress separately)
        if let Some(mp) = sw.mgmt_port {
            parts.push(format!("{mp}t"));
        }
    }

    // CPU port always tagged
    parts.push(format!("{}t", sw.cpu_port));

    // Internal uplink ports always tagged
    for &p in &sw.internal_ports {
        parts.push(format!("{p}t"));
    }

    parts.join(" ")
}

fn swconfig_set_vlan_ports(device: &str, vlan_id: i32, ports: &str) -> Result<()> {
    run_swconfig(&[
        "dev",
        device,
        "vlan",
        &vlan_id.to_string(),
        "set",
        "ports",
        ports,
    ])
}

fn swconfig_set_pvid(device: &str, port: u8, pvid: i32) -> Result<()> {
    run_swconfig(&[
        "dev",
        device,
        "port",
        &port.to_string(),
        "set",
        "pvid",
        &pvid.to_string(),
    ])
}

/// Check if a VLAN has any ports assigned on the switch.
fn swconfig_vlan_has_ports(device: &str, vlan_id: i32) -> bool {
    let output = Command::new("swconfig")
        .args(["dev", device, "vlan", &vlan_id.to_string(), "get", "ports"])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            !stdout.trim().is_empty()
        }
        _ => false,
    }
}

fn swconfig_apply(device: &str) -> Result<()> {
    run_swconfig(&["dev", device, "set", "apply"])
}

fn run_swconfig(args: &[&str]) -> Result<()> {
    let output = Command::new("swconfig")
        .args(args)
        .output()
        .with_context(|| format!("failed to execute swconfig {}", args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(crate::NetError::Internal(anyhow::anyhow!(
            "swconfig {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }

    Ok(())
}

// ── Linux bridges ───────────────────────────────────────────────────

/// Ensure all bridges exist with correct VLAN attachments and IPs.
///
/// This is idempotent — safe to call on every boot:
/// - Bridges that already exist (e.g. from migration) are kept
/// - VLAN sub-interfaces are created and attached if missing
/// - Gateway IPs are assigned if not already set
fn setup_bridges(networks: &[NetworkSetup], switch_dev: Option<&str>) -> Result<()> {
    for net in networks {
        let bridge_name = format!("br-{}", net.zone);

        let vlan_id = match &net.zone[..] {
            "lan" => Some(1),
            _ => net.vlan_id,
        };

        // Create bridge if it doesn't exist (may already exist from migration)
        if !link_exists(&bridge_name) {
            run_ip(&["link", "add", &bridge_name, "type", "bridge"])?;
            tracing::info!(bridge = %bridge_name, "created bridge");
        }

        // Create VLAN sub-interface and attach to bridge
        if let (Some(dev), Some(vid)) = (switch_dev, vlan_id) {
            let vlan_iface = format!("{dev}.{vid}");

            if !link_exists(&vlan_iface) {
                run_ip(&[
                    "link",
                    "add",
                    "link",
                    dev,
                    "name",
                    &vlan_iface,
                    "type",
                    "vlan",
                    "id",
                    &vid.to_string(),
                ])?;
                tracing::info!(iface = %vlan_iface, "created VLAN sub-interface");
            }

            // Attach to bridge (ignore error if already attached)
            let _ = run_ip(&["link", "set", &vlan_iface, "master", &bridge_name]);

            // Bring up VLAN sub-interface
            run_ip(&["link", "set", &vlan_iface, "up"])?;
        }

        // Assign gateway IP if not already set
        let cidr = gateway_to_cidr(&net.gateway, &net.subnet);
        if !has_address(&bridge_name, &cidr) {
            // Flush stale addresses but don't fail on empty
            let _ = run_ip(&["addr", "flush", "dev", &bridge_name]);
            run_ip(&["addr", "add", &cidr, "dev", &bridge_name])?;
            tracing::info!(bridge = %bridge_name, addr = %cidr, "assigned IP to bridge");
        }

        // Bring up bridge
        run_ip(&["link", "set", &bridge_name, "up"])?;

        tracing::info!(
            zone = %net.zone,
            bridge = %bridge_name,
            vlan = ?vlan_id,
            gateway = %net.gateway,
            "network zone ready"
        );
    }

    Ok(())
}

/// Convert gateway IP + subnet to CIDR notation.
fn gateway_to_cidr(gateway: &str, subnet: &str) -> String {
    if let Some(prefix) = subnet.split('/').nth(1) {
        format!("{gateway}/{prefix}")
    } else {
        format!("{gateway}/24")
    }
}

fn link_exists(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{name}")).exists()
}

fn has_address(iface: &str, cidr: &str) -> bool {
    let output = Command::new("ip")
        .args(["addr", "show", "dev", iface])
        .output();
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.contains(cidr)
        }
        Err(_) => false,
    }
}

fn run_ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .with_context(|| format!("failed to execute ip {}", args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(crate::NetError::Internal(anyhow::anyhow!(
            "ip {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udm_pro_layout() -> SwitchLayout {
        SwitchLayout {
            device: "switch0".to_string(),
            lan_ports: vec![0, 1, 2, 3, 4, 5, 6],
            cpu_port: 8,
            internal_ports: vec![9],
            mgmt_port: Some(7),
        }
    }

    fn generic_layout() -> SwitchLayout {
        SwitchLayout {
            device: "switch0".to_string(),
            lan_ports: vec![0, 1, 2, 3],
            cpu_port: 4,
            internal_ports: vec![],
            mgmt_port: None,
        }
    }

    #[test]
    fn test_gateway_to_cidr() {
        assert_eq!(
            gateway_to_cidr("192.168.1.1", "192.168.1.0/24"),
            "192.168.1.1/24"
        );
        assert_eq!(gateway_to_cidr("10.0.0.1", "10.0.0.0/24"), "10.0.0.1/24");
        assert_eq!(
            gateway_to_cidr("172.16.0.1", "172.16.0.0/16"),
            "172.16.0.1/16"
        );
    }

    #[test]
    fn test_build_port_string_lan_udm_pro() {
        let sw = udm_pro_layout();
        let result = build_port_string(1, &sw);
        assert_eq!(result, "0 1 2 3 4 5 6 8t 9t");
    }

    #[test]
    fn test_build_port_string_mgmt_vlan_udm_pro() {
        let sw = udm_pro_layout();
        let result = build_port_string(3000, &sw);
        assert_eq!(result, "0t 1t 2t 3t 4t 5t 6t 7t 8t 9t");
    }

    #[test]
    fn test_build_port_string_guest_vlan_udm_pro() {
        let sw = udm_pro_layout();
        let result = build_port_string(3001, &sw);
        assert_eq!(result, "0t 1t 2t 3t 4t 5t 6t 7t 8t 9t");
    }

    #[test]
    fn test_build_port_string_generic_no_mgmt() {
        let sw = generic_layout();
        let result = build_port_string(1, &sw);
        assert_eq!(result, "0 1 2 3 4t");
    }

    #[test]
    fn test_build_port_string_generic_tagged() {
        let sw = generic_layout();
        let result = build_port_string(100, &sw);
        assert_eq!(result, "0t 1t 2t 3t 4t");
    }
}
