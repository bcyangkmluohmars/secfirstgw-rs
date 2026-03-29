// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hardware switch ASIC configuration and Linux bridge/VLAN setup.
//!
//! This module is platform-agnostic. Hardware-specific details (switch port
//! layout, SMI interface, trunk interface) are passed in via [`SwitchLayout`].
//! On platforms without a switch ASIC, only Linux bridges are created.
//!
//! # Switch programming model
//!
//! The RTL8370MB is programmed via direct SMI register writes (MDIO ioctl on
//! the SMI interface). No `swconfig` or DSA framework is used — the custom
//! kernel exposes only the raw MDIO bus.
//!
//! # VLAN programming model
//!
//! The switch is programmed from per-port PVID + tagged VLAN config stored in
//! the `interfaces` DB table. Each port only carries VLANs it is configured
//! for:
//!
//! - A port's PVID VLAN carries that port **untagged** (ingress/egress for
//!   untagged frames).
//! - Each entry in `tagged_vlans` carries that port **tagged** (trunk).
//! - Ports with `pvid = 0` (WAN) are excluded entirely — they are outside the
//!   internal VLAN numbering space.
//! - VLAN 1 is always programmed as a **catch-all sink**: all switch ports
//!   tagged, but no Linux bridge. Any untagged frame on an unconfigured port
//!   lands on VLAN 1 and is dropped at the CPU.
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
use crate::rtl8370mb::{Rtl8370mb, Vlan4kEntry, VlanMcEntry};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::process::Command;

/// Describes the hardware switch port layout.
///
/// Provided by platform-specific detection (e.g. Ubiquiti board ID).
/// On platforms without a switch ASIC this is `None` and only Linux
/// bridges are created.
#[derive(Debug, Clone)]
pub struct SwitchLayout {
    /// Linux interface for VLAN sub-interfaces (e.g. "sw0").
    /// VLAN sub-interfaces are created as `{trunk_iface}.{vid}`.
    pub trunk_iface: String,
    /// Linux interface whose MDIO bus connects to the switch (e.g. "eth8").
    pub smi_iface: String,
    /// MDIO PHY address of the switch ASIC (0x1D for RTL8370MB).
    pub smi_phy_addr: u8,
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

impl SwitchLayout {
    /// Open an RTL8370MB driver handle for this layout.
    fn open_driver(&self) -> crate::Result<Rtl8370mb> {
        Rtl8370mb::new(&self.smi_iface, self.smi_phy_addr)
            .map_err(|e| crate::NetError::Internal(anyhow::anyhow!("failed to open SMI: {e}")))
    }
}

/// A network zone to be provisioned on the switch and as a Linux bridge.
#[derive(Debug)]
pub struct NetworkSetup {
    pub zone: String,
    pub vlan_id: Option<i32>,
    pub subnet: String,
    pub gateway: String,
}

/// Per-port VLAN config loaded from the `interfaces` DB table.
#[derive(Debug, Clone)]
struct PortVlanConfig {
    name: String,
    pvid: u16,
    tagged_vlans: Vec<u16>,
}

/// Membership of a single switch port in a VLAN.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PortMember {
    port: u8,
    tagged: bool,
}

/// Re-run network setup after a port config change.
///
/// This is the entry point called by the API after a `PUT /api/v1/ports/{name}`
/// request. It detects the board at call time (same pattern as
/// `detect_interfaces_for_platform` in lib.rs) and delegates to [`setup_networks`].
///
/// On bare-metal platforms with a hardware switch the ASIC and Linux bridges are
/// reprogrammed. On VM/Docker platforms only Linux bridges are updated.
pub async fn reconfigure_networks(db: &sfgw_db::Db) -> Result<()> {
    let switch_layout = if let Some(board) = sfgw_hal::detect_board() {
        board.switch.map(|sw| SwitchLayout {
            trunk_iface: sw.trunk_iface.to_string(),
            smi_iface: sw.smi_iface.to_string(),
            smi_phy_addr: sw.smi_phy_addr,
            lan_ports: sw.lan_ports.to_vec(),
            cpu_port: sw.cpu_port,
            internal_ports: sw.internal_ports.to_vec(),
            mgmt_port: sw.mgmt_port,
        })
    } else {
        None
    };

    setup_networks(db, switch_layout.as_ref()).await
}

/// Configure VLANs and bridges for all enabled networks.
///
/// - With a [`SwitchLayout`]: configures hardware switch VLANs via SMI,
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

    // Step 0: Ensure trunk interface exists (rename PCI eth to sw0 if needed)
    if let Some(sw) = switch {
        ensure_trunk_iface(sw)?;
    }

    // Step 1: Migrate legacy bridges (br0 → br-lan, etc.)
    migrate_legacy_bridges(&networks);

    // Step 2: Configure hardware switch VLANs (reads per-port config from DB)
    if let Some(sw) = switch {
        setup_switch_vlans(sw, db).await?;
    }

    // Step 3: Ensure all bridges exist with correct VLAN attachments and IPs,
    // and register them in the interfaces table so the API can see them.
    let trunk_iface = switch.map(|sw| sw.trunk_iface.as_str());
    setup_bridges(&networks, trunk_iface, db).await?;

    // Step 4: Attach direct physical ports (not on the switch ASIC) to their
    // bridges based on PVID. E.g. eth10 (SFP+ LAN) → br-lan.
    if let Some(sw) = switch {
        attach_direct_ports(&networks, sw, db).await?;
    }

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

/// Load per-port VLAN config from the `interfaces` DB table.
///
/// Only returns ports with `pvid > 0` — WAN ports (`pvid = 0`) are excluded
/// because they are outside the internal VLAN numbering space.
async fn load_port_vlan_config(db: &sfgw_db::Db) -> Result<Vec<PortVlanConfig>> {
    let conn = db.lock().await;
    let mut stmt = conn
        .prepare("SELECT name, pvid, tagged_vlans FROM interfaces WHERE pvid > 0")
        .context("failed to query port VLAN config")?;

    let rows = stmt
        .query_map([], |row| {
            let name: String = row.get(0)?;
            let pvid_raw: i32 = row.get(1)?;
            let tagged_json: String = row.get(2)?;
            Ok((name, pvid_raw, tagged_json))
        })
        .context("failed to read port VLAN config")?;

    let mut ports = Vec::new();
    for row in rows {
        let (name, pvid_raw, tagged_json) = row.context("failed to read port VLAN config row")?;
        let pvid = pvid_raw.clamp(1, u16::MAX as i32) as u16;
        let tagged_vlans: Vec<u16> = serde_json::from_str(&tagged_json).unwrap_or_default();
        ports.push(PortVlanConfig {
            name,
            pvid,
            tagged_vlans,
        });
    }

    Ok(ports)
}

/// Map a Linux interface name to its switch port number.
///
/// Mapping is positional: `ethN` → port `N`, for ports in `lan_ports` or
/// `mgmt_port`. Returns `None` if the interface is not switch-managed.
fn iface_to_switch_port(name: &str, sw: &SwitchLayout) -> Option<u8> {
    // Interface must start with "eth" followed by a decimal number.
    let n: u8 = name.strip_prefix("eth")?.parse().ok()?;

    // Check if this port number is a LAN port or the MGMT port.
    if sw.lan_ports.contains(&n) || sw.mgmt_port == Some(n) {
        Some(n)
    } else {
        None
    }
}

/// Compute the per-VLAN port membership map from per-port config.
///
/// For each port:
/// - Its PVID VLAN gets the port as **untagged**.
/// - Each entry in `tagged_vlans` gets the port as **tagged**.
///
/// After processing all ports:
/// - CPU port is added as **tagged** to every VLAN.
/// - Internal ports are added as **tagged** to every VLAN.
/// - VLAN 1 is added (if not already present) with all LAN + MGMT + CPU +
///   internal ports tagged — the void catch-all sink.
///
/// WAN ports (pvid = 0) are not present in `ports` (filtered by SQL).
fn compute_vlan_port_map(
    ports: &[PortVlanConfig],
    sw: &SwitchLayout,
) -> BTreeMap<u16, Vec<PortMember>> {
    let mut map: BTreeMap<u16, Vec<PortMember>> = BTreeMap::new();

    for port_cfg in ports {
        let Some(switch_port) = iface_to_switch_port(&port_cfg.name, sw) else {
            tracing::debug!(
                iface = %port_cfg.name,
                "interface not on switch — skipping VLAN membership"
            );
            continue;
        };

        // PVID VLAN → untagged
        map.entry(port_cfg.pvid).or_default().push(PortMember {
            port: switch_port,
            tagged: false,
        });

        // Tagged VLANs → tagged
        for &vid in &port_cfg.tagged_vlans {
            map.entry(vid).or_default().push(PortMember {
                port: switch_port,
                tagged: true,
            });
        }
    }

    // Add CPU port as tagged to every VLAN we've collected so far.
    for members in map.values_mut() {
        members.push(PortMember {
            port: sw.cpu_port,
            tagged: true,
        });
    }

    // Add internal ports as tagged to every VLAN.
    for members in map.values_mut() {
        for &ip in &sw.internal_ports {
            members.push(PortMember {
                port: ip,
                tagged: true,
            });
        }
    }

    // VLAN 1: void catch-all sink.
    // All LAN + MGMT + CPU + internal ports, all tagged.
    // Only added if not already present (no port should have pvid=1).
    map.entry(1).or_insert_with(|| {
        let mut vlan1_members: Vec<PortMember> = sw
            .lan_ports
            .iter()
            .map(|&p| PortMember {
                port: p,
                tagged: true,
            })
            .collect();
        if let Some(mp) = sw.mgmt_port {
            vlan1_members.push(PortMember {
                port: mp,
                tagged: true,
            });
        }
        vlan1_members.push(PortMember {
            port: sw.cpu_port,
            tagged: true,
        });
        for &ip in &sw.internal_ports {
            vlan1_members.push(PortMember {
                port: ip,
                tagged: true,
            });
        }
        vlan1_members
    });

    map
}

/// Build RTL8370MB 4K table entries, MC table entries, and PVID mappings.
///
/// Returns `(vlan_4k_entries, mc_entries, pvids)` where:
/// - `vlan_4k_entries`: one per VLAN, written to indirect 4K table
/// - `mc_entries`: one per VLAN, written to direct MC table (index 0..N)
/// - `pvids`: (port, mc_index) for each switch port
fn build_switch_config(
    vlan_map: &BTreeMap<u16, Vec<PortMember>>,
    port_configs: &[PortVlanConfig],
    sw: &SwitchLayout,
) -> (Vec<Vlan4kEntry>, Vec<VlanMcEntry>, Vec<(u8, u8)>) {
    let mut vlan_4k = Vec::new();
    let mut mc = Vec::new();
    let mut fid: u8 = 0;

    // Build a VID → MC index map
    let mut vid_to_mc: BTreeMap<u16, u8> = BTreeMap::new();

    for (mc_idx, (&vid, members)) in vlan_map.iter().enumerate() {
        let mut member_mask: u16 = 0;
        let mut untag_mask: u16 = 0;

        for m in members {
            member_mask |= 1 << m.port;
            if !m.tagged {
                untag_mask |= 1 << m.port;
            }
        }

        vlan_4k.push(Vlan4kEntry {
            vid,
            member: member_mask,
            untag: untag_mask,
            fid,
        });

        mc.push(VlanMcEntry {
            index: mc_idx as u8,
            vid,
            member: member_mask,
            fid,
        });

        vid_to_mc.insert(vid, mc_idx as u8);
        fid = fid.wrapping_add(1).min(15);
    }

    // Build PVID map: each port → MC index of its PVID VLAN
    let mut pvids: Vec<(u8, u8)> = Vec::new();
    for port_cfg in port_configs {
        if let Some(switch_port) = iface_to_switch_port(&port_cfg.name, sw) {
            if let Some(&mc_idx) = vid_to_mc.get(&port_cfg.pvid) {
                pvids.push((switch_port, mc_idx));
            }
        }
    }
    // CPU port → MC index for VLAN 1 (catch-all)
    if let Some(&mc_idx) = vid_to_mc.get(&1) {
        pvids.push((sw.cpu_port, mc_idx));
    }

    (vlan_4k, mc, pvids)
}

// ── Trunk interface setup ───────────────────────────────────────────

/// Ensure the trunk interface exists by renaming the PCI interface if needed.
///
/// On the UDM Pro with our custom kernel, the switch uplink (PCI 00:03.0)
/// comes up as a regular ethN interface. We rename it to the configured
/// trunk name (e.g. "sw0") so that eth0–eth7 are free for logical switch
/// port names in the DB.
///
/// The rename is idempotent: if the trunk already exists, this is a no-op.
fn ensure_trunk_iface(sw: &SwitchLayout) -> Result<()> {
    if link_exists(&sw.trunk_iface) {
        return Ok(());
    }

    // Find the PCI interface to rename by checking the expected device path.
    // On UDM Pro: PCI 00:03.0 → ethN → sw0
    // We identify it by reading the sysfs device symlink.
    let pci_addr = "0000:00:03.0";
    let sysfs = std::path::Path::new("/sys/class/net");
    let mut source_iface: Option<String> = None;

    if let Ok(entries) = std::fs::read_dir(sysfs) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip non-eth interfaces
            if !name.starts_with("eth") {
                continue;
            }
            // Check if this interface is on the right PCI device
            let device_link = entry.path().join("device");
            if let Ok(target) = std::fs::read_link(&device_link) {
                let target_str = target.to_string_lossy();
                if target_str.contains(pci_addr) {
                    source_iface = Some(name);
                    break;
                }
            }
        }
    }

    let Some(src) = source_iface else {
        tracing::warn!(
            trunk = %sw.trunk_iface,
            "trunk interface not found and no PCI device {pci_addr} to rename"
        );
        return Ok(());
    };

    tracing::info!(from = %src, to = %sw.trunk_iface, "renaming switch uplink interface");

    // Must bring down before rename, then back up
    let _ = run_ip(&["link", "set", &src, "down"]);
    run_ip(&["link", "set", &src, "name", &sw.trunk_iface])?;
    run_ip(&["link", "set", &sw.trunk_iface, "up"])?;

    Ok(())
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

// ── Switch ASIC (SMI) ─────────────────────────────────────────────

/// Configure VLANs on the hardware switch ASIC via SMI register writes.
///
/// Reads per-port PVID + tagged VLAN config from the DB and computes per-VLAN
/// port membership. Each port only carries VLANs it is explicitly configured
/// for. VLAN 1 is always programmed as a void catch-all sink (no bridge).
async fn setup_switch_vlans(sw: &SwitchLayout, db: &sfgw_db::Db) -> Result<()> {
    let driver = sw.open_driver()?;

    // Verify chip responds before programming
    match driver.verify_chip() {
        Ok((chip_id, chip_ver)) => {
            tracing::info!(
                chip_id = format!("0x{chip_id:04X}"),
                chip_ver = format!("0x{chip_ver:04X}"),
                "RTL8370MB chip detected via SMI"
            );
        }
        Err(e) => {
            return Err(crate::NetError::Internal(anyhow::anyhow!(
                "RTL8370MB not responding on SMI ({}:{:#04X}): {e}",
                sw.smi_iface,
                sw.smi_phy_addr,
            )));
        }
    }

    // Load per-port config from DB (pvid > 0 only — excludes WAN ports)
    let port_configs = load_port_vlan_config(db).await?;

    // Compute per-VLAN port membership
    let vlan_map = compute_vlan_port_map(&port_configs, sw);

    // Build 4K table entries, MC table entries, and PVID mappings
    let (vlan_4k, mc_entries, pvids) = build_switch_config(&vlan_map, &port_configs, sw);

    // Program the switch ASIC (4K table + MC table + PVIDs)
    driver
        .apply_vlan_config(&mc_entries, &vlan_4k, &pvids)
        .map_err(|e| {
            crate::NetError::Internal(anyhow::anyhow!(
                "failed to program switch VLANs via SMI: {e}"
            ))
        })?;

    for entry in &vlan_4k {
        tracing::info!(
            vlan = entry.vid,
            members = format!("0x{:03X}", entry.member),
            untag = format!("0x{:03X}", entry.untag),
            fid = entry.fid,
            "configured 4K VLAN table via SMI"
        );
    }

    for &(port, mc_idx) in &pvids {
        tracing::info!(port, mc_idx, "set port PVID MC index via SMI");
    }

    // Clean up stale VLAN sub-interfaces on the trunk
    let our_vlans: std::collections::HashSet<u16> = vlan_map.keys().copied().collect();
    let sysfs = std::path::Path::new("/sys/class/net");
    if let Ok(dir_entries) = std::fs::read_dir(sysfs) {
        let prefix = format!("{}.", sw.trunk_iface);
        for entry in dir_entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(vid_str) = name.strip_prefix(&prefix)
                && let Ok(vid) = vid_str.parse::<u16>()
                && !our_vlans.contains(&vid)
            {
                tracing::info!(iface = %name, vlan = vid, "removing stale VLAN sub-interface");
                let _ = run_ip(&["link", "set", &name, "down"]);
                let _ = run_ip(&["link", "del", &name]);
            }
        }
    }

    Ok(())
}

// ── Switch ASIC watchdog ────────────────────────────────────────────

/// Verify the switch ASIC config matches the DB and reprogram if drifted.
///
/// This is called periodically by the controller watchdog. If another process
/// (e.g. ubios-udapi-server restarting) reprograms the switch ASIC, this
/// detects the PVID drift and re-applies sfgw's VLAN config.
///
/// Returns `true` if a correction was applied.
pub async fn verify_switch_config(db: &sfgw_db::Db) -> bool {
    let switch_layout = match sfgw_hal::detect_board() {
        Some(board) => match board.switch {
            Some(sw) => SwitchLayout {
                trunk_iface: sw.trunk_iface.to_string(),
                smi_iface: sw.smi_iface.to_string(),
                smi_phy_addr: sw.smi_phy_addr,
                lan_ports: sw.lan_ports.to_vec(),
                cpu_port: sw.cpu_port,
                internal_ports: sw.internal_ports.to_vec(),
                mgmt_port: sw.mgmt_port,
            },
            None => return false, // No switch ASIC on this platform
        },
        None => return false,
    };

    let driver = match switch_layout.open_driver() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "switch watchdog: failed to open SMI");
            return false;
        }
    };

    // Load expected per-port config from DB
    let port_configs = match load_port_vlan_config(db).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "switch watchdog: failed to load port config from DB");
            return false;
        }
    };

    // Compute expected VLAN config to know expected MC indices
    let vlan_map = compute_vlan_port_map(&port_configs, &switch_layout);
    let (_, _, expected_pvids) = build_switch_config(&vlan_map, &port_configs, &switch_layout);

    // Compare expected vs actual MC indices (read via SMI)
    let mut drifted = false;
    for &(port, expected_mc) in &expected_pvids {
        match driver.read_pvid_locked(port) {
            Ok(actual_mc) if actual_mc != expected_mc => {
                tracing::warn!(
                    port,
                    expected_mc,
                    actual_mc,
                    "switch ASIC PVID MC index drift detected"
                );
                drifted = true;
            }
            Err(e) => {
                tracing::warn!(port, error = %e, "switch watchdog: failed to read PVID MC index");
                drifted = true;
            }
            _ => {}
        }
    }

    if !drifted {
        return false;
    }

    // Drift detected — rebuild everything.
    tracing::warn!("switch ASIC drift detected — rebuilding full network stack");

    // Step 1: Re-apply switch VLANs + PVIDs
    if let Err(e) = setup_switch_vlans(&switch_layout, db).await {
        tracing::error!(error = %e, "switch watchdog: failed to reprogram switch ASIC");
        return false;
    }

    // Step 2: Rebuild bridges, VLAN sub-interfaces, and gateway IPs
    let networks = match load_enabled_networks(db).await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(error = %e, "switch watchdog: failed to load networks");
            return false;
        }
    };
    if let Err(e) = setup_bridges(&networks, Some(&switch_layout.trunk_iface), db).await {
        tracing::error!(error = %e, "switch watchdog: failed to rebuild bridges");
        return false;
    }

    // Step 3: Re-apply firewall rules (ubios flushes iptables on exit)
    if let Err(e) = sfgw_fw::apply_rules(db).await {
        tracing::error!(error = %e, "switch watchdog: failed to re-apply firewall rules");
    }

    // Note: dnsmasq is a child process of sfgw (not in ubios's cgroup),
    // so it survives ubios teardown. No restart needed here.

    tracing::info!("full network stack rebuilt successfully by watchdog");
    true
}

/// Background loop: verify switch ASIC config every 10 seconds.
pub async fn watchdog_loop(db: sfgw_db::Db) {
    let interval = std::time::Duration::from_secs(10);
    let mut timer = tokio::time::interval(interval);
    tracing::info!(
        "switch ASIC watchdog started ({}s interval, SMI)",
        interval.as_secs()
    );
    loop {
        timer.tick().await;
        verify_switch_config(&db).await;
    }
}

// ── Linux bridges ───────────────────────────────────────────────────

/// Ensure all bridges exist with correct VLAN attachments and IPs.
///
/// This is idempotent — safe to call on every boot:
/// - Bridges that already exist (e.g. from migration) are kept
/// - VLAN sub-interfaces are created and attached if missing
/// - Gateway IPs are assigned if not already set
async fn setup_bridges(
    networks: &[NetworkSetup],
    trunk_iface: Option<&str>,
    db: &sfgw_db::Db,
) -> Result<()> {
    for net in networks {
        // Void zone creates no bridge — VLAN 1 traffic is dropped by firewall.
        if net.zone == "void" {
            tracing::debug!(zone = "void", "skipping bridge for void zone");
            continue;
        }

        let bridge_name = format!("br-{}", net.zone);

        // All zones use their actual vlan_id from the DB (LAN is now VLAN 10, not 1).
        let vlan_id = net.vlan_id;

        // Create bridge if it doesn't exist (may already exist from migration)
        if !link_exists(&bridge_name) {
            run_ip(&["link", "add", &bridge_name, "type", "bridge"])?;
            tracing::info!(bridge = %bridge_name, "created bridge");
        }

        // Create VLAN sub-interface on the trunk and attach to bridge
        if let (Some(dev), Some(vid)) = (trunk_iface, vlan_id) {
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

        // Register bridge in interfaces table so the API can serve it.
        // Reads live state from sysfs after the bridge is up.
        register_bridge_interface(&bridge_name, vlan_id.unwrap_or(0) as u16, db).await;

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

/// Attach direct physical ports (not managed by the switch ASIC) to their
/// bridges based on PVID.
///
/// Switch-managed ports (eth0–eth7 on UDM Pro) are behind the RTL8370MB and
/// reach bridges via the trunk VLAN sub-interfaces (sw0.10, sw0.3000, etc.).
/// Direct ports like eth10 (SFP+ LAN) are real Linux interfaces that must be
/// added to the bridge as regular members.
async fn attach_direct_ports(
    networks: &[NetworkSetup],
    sw: &SwitchLayout,
    db: &sfgw_db::Db,
) -> Result<()> {
    let port_configs = load_port_vlan_config(db).await?;

    // Build VLAN-ID → zone lookup from networks
    let vlan_to_zone: std::collections::HashMap<i32, &str> = networks
        .iter()
        .filter_map(|n| n.vlan_id.map(|vid| (vid, n.zone.as_str())))
        .collect();

    for port in &port_configs {
        // Skip ports that are on the switch ASIC — they use trunk sub-interfaces
        if iface_to_switch_port(&port.name, sw).is_some() {
            continue;
        }

        // Skip bridges, VLAN sub-interfaces, loopback, and the trunk itself
        if port.name.starts_with("br-")
            || port.name.contains('.')
            || port.name == "lo"
            || port.name == sw.trunk_iface
        {
            continue;
        }

        // Skip if the interface doesn't exist in Linux
        if !link_exists(&port.name) {
            continue;
        }

        // Find the zone for this port's PVID
        let Some(zone) = vlan_to_zone.get(&(port.pvid as i32)) else {
            tracing::debug!(
                iface = %port.name,
                pvid = port.pvid,
                "direct port PVID has no matching network zone"
            );
            continue;
        };

        let bridge_name = format!("br-{zone}");

        // Attach to bridge (ignore error if already attached)
        let _ = run_ip(&["link", "set", &port.name, "master", &bridge_name]);

        // Bring up the interface
        run_ip(&["link", "set", &port.name, "up"])?;

        tracing::info!(
            iface = %port.name,
            bridge = %bridge_name,
            pvid = port.pvid,
            "attached direct port to bridge"
        );
    }

    Ok(())
}

/// Register a bridge in the `interfaces` table by reading its live state from sysfs.
async fn register_bridge_interface(bridge: &str, pvid: u16, db: &sfgw_db::Db) {
    let sysfs_dir = std::path::Path::new("/sys/class/net").join(bridge);

    let mac = std::fs::read_to_string(sysfs_dir.join("address"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let mtu: u32 = std::fs::read_to_string(sysfs_dir.join("mtu"))
        .map(|s| s.trim().parse().unwrap_or(1500))
        .unwrap_or(1500);
    let is_up = std::fs::read_to_string(sysfs_dir.join("operstate"))
        .map(|s| s.trim() == "up")
        .unwrap_or(false);
    let ips = crate::read_ip_addresses(bridge);
    let ips_json = serde_json::to_string(&ips).unwrap_or_else(|_| "[]".to_string());

    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO interfaces (name, mac, ips, mtu, is_up, pvid, tagged_vlans)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, '[]')
         ON CONFLICT(name) DO UPDATE SET
             mac   = excluded.mac,
             ips   = excluded.ips,
             mtu   = excluded.mtu,
             is_up = excluded.is_up",
        rusqlite::params![bridge, mac, ips_json, mtu, is_up as i32, pvid as i32],
    )
    .ok();
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

/// Live link status for a switch-managed port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchPortLink {
    pub up: bool,
    pub speed_mbps: u16,
    pub full_duplex: bool,
    pub connector: String,
}

/// Read live link status for all switch-managed ports from the hardware ASIC.
///
/// Returns a map from interface name (e.g. "eth0") to link status.
/// Returns an empty map if no hardware switch is detected or on read error.
#[must_use]
pub fn read_switch_port_links() -> HashMap<String, SwitchPortLink> {
    let mut links = HashMap::new();

    let board = match sfgw_hal::detect_board() {
        Some(b) => b,
        None => return links,
    };
    let sw = match board.switch {
        Some(s) => s,
        None => return links,
    };
    let rtl = match Rtl8370mb::new(sw.smi_iface, sw.smi_phy_addr) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("failed to open SMI for port link status: {e}");
            return links;
        }
    };

    for port_def in board.ports {
        let n: u8 = match port_def
            .iface
            .strip_prefix("eth")
            .and_then(|s| s.parse().ok())
        {
            Some(n) => n,
            None => continue,
        };

        if !sw.lan_ports.contains(&n) && sw.mgmt_port != Some(n) {
            continue;
        }

        match rtl.port_get_link(n) {
            Ok(link) => {
                links.insert(
                    port_def.iface.to_string(),
                    SwitchPortLink {
                        up: link.up,
                        speed_mbps: link.speed_mbps,
                        full_duplex: link.full_duplex,
                        connector: port_def.connector.to_string(),
                    },
                );
            }
            Err(e) => {
                tracing::debug!(
                    port = n,
                    iface = port_def.iface,
                    "failed to read port link: {e}"
                );
            }
        }
    }

    links
}

/// Read complete switch ASIC state via SMI registers.
///
/// Returns `None` if no hardware switch is detected, or `Some(Err)` on
/// SMI access failure, or `Some(Ok(state))` with structured register data.
pub fn read_switch_state() -> Option<std::io::Result<crate::rtl8370mb::SwitchState>> {
    let board = sfgw_hal::detect_board()?;
    let sw = board.switch?;
    let rtl = match Rtl8370mb::new(sw.smi_iface, sw.smi_phy_addr) {
        Ok(r) => r,
        Err(e) => return Some(Err(e)),
    };
    Some(rtl.read_state())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udm_pro_layout() -> SwitchLayout {
        SwitchLayout {
            trunk_iface: "sw0".to_string(),
            smi_iface: "eth8".to_string(),
            smi_phy_addr: 0x1D,
            lan_ports: vec![0, 1, 2, 3, 4, 5, 6],
            cpu_port: 9,
            internal_ports: vec![],
            mgmt_port: Some(7),
        }
    }

    fn generic_layout() -> SwitchLayout {
        SwitchLayout {
            trunk_iface: "sw0".to_string(),
            smi_iface: "eth8".to_string(),
            smi_phy_addr: 0x1D,
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

    // ── iface_to_switch_port ───────────────────────────────────────

    #[test]
    fn test_iface_to_switch_port() {
        let sw = udm_pro_layout();
        // LAN ports eth0–eth6 → port 0–6
        assert_eq!(iface_to_switch_port("eth0", &sw), Some(0));
        assert_eq!(iface_to_switch_port("eth3", &sw), Some(3));
        assert_eq!(iface_to_switch_port("eth6", &sw), Some(6));
        // MGMT port eth7 → port 7
        assert_eq!(iface_to_switch_port("eth7", &sw), Some(7));
        // WAN ports eth8/eth9 are not in lan_ports or mgmt_port → None
        assert_eq!(iface_to_switch_port("eth8", &sw), None);
        assert_eq!(iface_to_switch_port("eth9", &sw), None);
        // Non-eth interfaces → None
        assert_eq!(iface_to_switch_port("lo", &sw), None);
        assert_eq!(iface_to_switch_port("br-lan", &sw), None);
    }

    // ── build_switch_config ─────────────────────────────────────────

    #[test]
    fn test_build_switch_config_basic() {
        let sw = udm_pro_layout();
        let ports: Vec<PortVlanConfig> = (0u8..=7)
            .map(|i| PortVlanConfig {
                name: format!("eth{i}"),
                pvid: if i < 7 { 10 } else { 3000 },
                tagged_vlans: vec![],
            })
            .collect();

        let vlan_map = compute_vlan_port_map(&ports, &sw);
        let (vlan_4k, mc, pvids) = build_switch_config(&vlan_map, &ports, &sw);

        // 3 VLANs: 1, 10, 3000
        assert_eq!(vlan_4k.len(), 3);
        assert_eq!(mc.len(), 3);

        // 4K: VLAN 10 = ports 0-6 + CPU(9)
        let v10 = vlan_4k.iter().find(|e| e.vid == 10).unwrap();
        assert_eq!(v10.member, 0x027F);
        assert_eq!(v10.untag, 0x007F);

        // MC entries have sequential indices
        assert_eq!(mc[0].index, 0);
        assert_eq!(mc[1].index, 1);
        assert_eq!(mc[2].index, 2);

        // PVIDs: ports 0-6 → MC index of VID 10, port 7 → MC index of VID 3000
        let vid10_mc = mc.iter().find(|e| e.vid == 10).unwrap().index;
        let vid3000_mc = mc.iter().find(|e| e.vid == 3000).unwrap().index;
        for &(port, mc_idx) in &pvids {
            if port <= 6 {
                assert_eq!(mc_idx, vid10_mc, "port {port} should map to VID 10 MC");
            } else if port == 7 {
                assert_eq!(mc_idx, vid3000_mc, "port 7 should map to VID 3000 MC");
            }
        }
    }

    // ── compute_vlan_port_map ──────────────────────────────────────

    #[test]
    fn test_compute_vlan_port_map_default_udm_pro() {
        let sw = udm_pro_layout();

        // Default UDM Pro config: eth0–eth6 pvid=10, eth7 pvid=3000
        let ports: Vec<PortVlanConfig> = (0u8..=7)
            .map(|i| PortVlanConfig {
                name: format!("eth{i}"),
                pvid: if i < 7 { 10 } else { 3000 },
                tagged_vlans: vec![],
            })
            .collect();

        let map = compute_vlan_port_map(&ports, &sw);

        // VLAN 10: ports 0–6 untagged, CPU(9t)
        let vlan10 = map.get(&10).expect("VLAN 10 should exist");
        for port in 0u8..=6 {
            assert!(
                vlan10.contains(&PortMember {
                    port,
                    tagged: false
                }),
                "port {port} should be untagged in VLAN 10"
            );
        }
        assert!(
            vlan10.contains(&PortMember {
                port: 9,
                tagged: true
            }),
            "CPU port in VLAN 10"
        );
        // MGMT port 7 must NOT be in VLAN 10
        assert!(
            !vlan10.iter().any(|m| m.port == 7),
            "MGMT port must not be in VLAN 10"
        );

        // VLAN 3000: port 7 untagged, CPU(9t)
        let vlan3000 = map.get(&3000).expect("VLAN 3000 should exist");
        assert!(
            vlan3000.contains(&PortMember {
                port: 7,
                tagged: false
            }),
            "MGMT port 7 should be untagged in VLAN 3000"
        );
        assert!(
            vlan3000.contains(&PortMember {
                port: 9,
                tagged: true
            }),
            "CPU in VLAN 3000"
        );
        for port in 0u8..=6 {
            assert!(
                !vlan3000.iter().any(|m| m.port == port),
                "LAN port {port} must not be in VLAN 3000"
            );
        }

        // VLAN 1: all LAN + MGMT + CPU ports tagged (catch-all sink)
        let vlan1 = map.get(&1).expect("VLAN 1 should always exist");
        for port in [0u8, 1, 2, 3, 4, 5, 6, 7, 9] {
            assert!(
                vlan1.contains(&PortMember { port, tagged: true }),
                "port {port} should be tagged in VLAN 1"
            );
        }
    }

    #[test]
    fn test_compute_vlan_port_map_trunk_port() {
        let sw = udm_pro_layout();

        // Port 0 is a trunk: pvid=10, tagged_vlans=[3000, 3001]
        let ports = vec![PortVlanConfig {
            name: "eth0".to_string(),
            pvid: 10,
            tagged_vlans: vec![3000, 3001],
        }];

        let map = compute_vlan_port_map(&ports, &sw);

        // VLAN 10: port 0 untagged
        let vlan10 = map.get(&10).expect("VLAN 10 should exist");
        assert!(vlan10.contains(&PortMember {
            port: 0,
            tagged: false
        }));
        // CPU always tagged
        assert!(vlan10.contains(&PortMember {
            port: 9,
            tagged: true
        }));

        // VLAN 3000: port 0 tagged
        let vlan3000 = map.get(&3000).expect("VLAN 3000 should exist");
        assert!(vlan3000.contains(&PortMember {
            port: 0,
            tagged: true
        }));

        // VLAN 3001: port 0 tagged
        let vlan3001 = map.get(&3001).expect("VLAN 3001 should exist");
        assert!(vlan3001.contains(&PortMember {
            port: 0,
            tagged: true
        }));
    }

    #[test]
    fn test_compute_vlan_port_map_vlan1_always_present() {
        let sw = udm_pro_layout();
        let ports = vec![PortVlanConfig {
            name: "eth0".to_string(),
            pvid: 10,
            tagged_vlans: vec![],
        }];

        let map = compute_vlan_port_map(&ports, &sw);
        assert!(map.contains_key(&1), "VLAN 1 must always be in the map");

        let vlan1 = &map[&1];
        // All LAN + MGMT + CPU ports tagged
        for port in [0u8, 7, 9] {
            assert!(
                vlan1.contains(&PortMember { port, tagged: true }),
                "port {port} should be tagged in VLAN 1"
            );
        }
    }

    #[test]
    fn test_compute_vlan_port_map_wan_excluded() {
        let sw = udm_pro_layout();

        let ports = vec![PortVlanConfig {
            name: "eth0".to_string(),
            pvid: 10,
            tagged_vlans: vec![],
        }];

        let map = compute_vlan_port_map(&ports, &sw);

        let vlan10 = map.get(&10).unwrap();
        // Port 0 untagged (from config)
        assert!(vlan10.contains(&PortMember {
            port: 0,
            tagged: false
        }));
        // Port 9 (cpu) tagged
        assert!(vlan10.contains(&PortMember {
            port: 9,
            tagged: true
        }));
    }

    #[test]
    fn test_mgmt_port_not_in_lan_vlan() {
        let sw = udm_pro_layout();

        // Default config: eth0–eth6 pvid=10, eth7 (MGMT) pvid=3000
        let ports: Vec<PortVlanConfig> = (0u8..=7)
            .map(|i| PortVlanConfig {
                name: format!("eth{i}"),
                pvid: if i < 7 { 10 } else { 3000 },
                tagged_vlans: vec![],
            })
            .collect();

        let map = compute_vlan_port_map(&ports, &sw);

        let vlan10 = map.get(&10).expect("VLAN 10 must exist");
        assert!(
            !vlan10.iter().any(|m| m.port == 7),
            "MGMT port 7 must not appear in VLAN 10"
        );

        let vlan3000 = map.get(&3000).expect("VLAN 3000 must exist");
        assert!(
            vlan3000.contains(&PortMember {
                port: 7,
                tagged: false
            }),
            "MGMT port 7 must be untagged in VLAN 3000"
        );
        for port in 0u8..=6 {
            assert!(
                !vlan3000.iter().any(|m| m.port == port),
                "LAN port {port} must not appear in VLAN 3000"
            );
        }
    }

    // ── Integration-level: full UDM Pro VLAN map ───────────────────

    #[tokio::test]
    async fn test_setup_switch_vlans_produces_correct_commands() {
        let db = sfgw_db::open_in_memory()
            .await
            .expect("failed to open in-memory db");
        let sw = udm_pro_layout();

        // Insert interface rows (simulating what configure() would populate).
        // eth8, eth9 have pvid=0 (WAN) — excluded from query.
        {
            let conn = db.lock().await;
            let ifaces: &[(&str, i32, &str)] = &[
                ("eth0", 10, "[]"),
                ("eth1", 10, "[]"),
                ("eth2", 10, "[]"),
                ("eth3", 10, "[]"),
                ("eth4", 10, "[]"),
                ("eth5", 10, "[]"),
                ("eth6", 10, "[]"),
                ("eth7", 3000, "[]"),
                ("eth8", 0, "[]"), // WAN: excluded
                ("eth9", 0, "[]"), // WAN: excluded
            ];
            for (name, pvid, tagged) in ifaces {
                conn.execute(
                    "INSERT INTO interfaces (name, mac, ips, mtu, is_up, pvid, tagged_vlans)
                     VALUES (?1, '00:00:00:00:00:00', '[]', 1500, 1, ?2, ?3)",
                    rusqlite::params![name, pvid, tagged],
                )
                .expect("failed to insert interface");
            }
        }

        // Load per-port config (WAN excluded by pvid > 0 filter)
        let port_configs = load_port_vlan_config(&db)
            .await
            .expect("load_port_vlan_config failed");

        // Verify WAN ports excluded
        assert!(
            !port_configs
                .iter()
                .any(|p| p.name == "eth8" || p.name == "eth9"),
            "WAN ports must be excluded from port VLAN config"
        );
        assert_eq!(port_configs.len(), 8, "should have 8 non-WAN ports");

        // Compute VLAN map and build switch config
        let vlan_map = compute_vlan_port_map(&port_configs, &sw);
        let (vlan_4k, mc, pvids) = build_switch_config(&vlan_map, &port_configs, &sw);

        // 3 VLANs: 1 (catch-all), 10 (LAN), 3000 (MGMT)
        assert_eq!(vlan_4k.len(), 3);

        let e1 = vlan_4k.iter().find(|e| e.vid == 1).expect("VLAN 1");
        let e10 = vlan_4k.iter().find(|e| e.vid == 10).expect("VLAN 10");
        let e3000 = vlan_4k.iter().find(|e| e.vid == 3000).expect("VLAN 3000");

        assert_eq!(e1.member, 0x02FF);
        assert_eq!(e1.untag, 0x0000);
        assert_eq!(e10.member, 0x027F);
        assert_eq!(e10.untag, 0x007F);
        assert_eq!(e3000.member, 0x0280);
        assert_eq!(e3000.untag, 0x0080);

        // MC entries: sequential indices, matching VIDs
        assert_eq!(mc.len(), 3);
        let mc10 = mc.iter().find(|e| e.vid == 10).expect("MC for VID 10");
        let mc3000 = mc.iter().find(|e| e.vid == 3000).expect("MC for VID 3000");

        // PVIDs: port 0-6 → MC index of VID 10, port 7 → MC index of VID 3000
        for &(port, mc_idx) in &pvids {
            if port <= 6 {
                assert_eq!(mc_idx, mc10.index, "port {port} MC index");
            } else if port == 7 {
                assert_eq!(mc_idx, mc3000.index, "port 7 MC index");
            }
        }
    }

    #[test]
    fn test_compute_vlan_port_map_generic_no_mgmt() {
        let sw = generic_layout();
        // All ports pvid=10
        let ports: Vec<PortVlanConfig> = (0u8..=3)
            .map(|i| PortVlanConfig {
                name: format!("eth{i}"),
                pvid: 10,
                tagged_vlans: vec![],
            })
            .collect();

        let map = compute_vlan_port_map(&ports, &sw);

        // VLAN 10: ports 0–3 untagged, CPU(4t)
        let vlan10 = map.get(&10).expect("VLAN 10 should exist");
        for port in 0u8..=3 {
            assert!(vlan10.contains(&PortMember {
                port,
                tagged: false
            }));
        }
        assert!(vlan10.contains(&PortMember {
            port: 4,
            tagged: true
        }));

        // VLAN 1: all LAN ports + CPU tagged (no MGMT port)
        let vlan1 = map.get(&1).expect("VLAN 1 must exist");
        for port in 0u8..=4 {
            assert!(
                vlan1.contains(&PortMember { port, tagged: true }),
                "port {port} tagged in VLAN 1"
            );
        }
    }
}
