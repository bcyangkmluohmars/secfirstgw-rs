// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

pub mod switch;
pub mod wan;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Errors from the network crate.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// Database error.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Wrapped anyhow error for internal context propagation.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Convenience alias for results from this crate.
type Result<T> = std::result::Result<T, NetError>;

/// Information about a discovered network interface.
///
/// ```
/// use sfgw_net::InterfaceInfo;
///
/// let iface = InterfaceInfo {
///     name: "eth0".to_string(),
///     mac: "aa:bb:cc:dd:ee:ff".to_string(),
///     ips: vec!["192.168.1.1".to_string()],
///     mtu: 1500,
///     is_up: true,
///     pvid: 10,
///     tagged_vlans: vec![],
/// };
///
/// // Roundtrip via JSON
/// let json = serde_json::to_string(&iface).unwrap();
/// let back: InterfaceInfo = serde_json::from_str(&json).unwrap();
/// assert_eq!(back.name, "eth0");
/// assert_eq!(back.pvid, 10);
/// assert!(back.tagged_vlans.is_empty());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub mac: String,
    pub ips: Vec<String>,
    pub mtu: u32,
    pub is_up: bool,
    /// Port VLAN ID (PVID). 0 = WAN (not an internal VLAN port). 10 = default LAN.
    pub pvid: u16,
    /// Tagged VLANs trunked on this port. Empty by default; user-configured.
    pub tagged_vlans: Vec<u16>,
}

const SYSFS_NET: &str = "/sys/class/net";

/// Detect network interfaces on the system and store them in the database.
///
/// Role assignment is platform-aware:
/// - **Docker**: single NIC → LAN (web UI must be reachable)
/// - **Bare metal**: eth0/ens*/enp* first physical → WAN, rest → LAN
/// - **VM**: same as bare metal
pub async fn configure(db: &sfgw_db::Db, platform: &sfgw_hal::Platform) -> Result<()> {
    let (interfaces, switch_layout) = detect_interfaces_for_platform(platform)?;

    let conn = db.lock().await;
    for iface in &interfaces {
        let ips_json = serde_json::to_string(&iface.ips).context("failed to serialize IPs")?;

        let tagged_json =
            serde_json::to_string(&iface.tagged_vlans).context("failed to serialize tagged_vlans")?;

        // Update live state (mac, ips, mtu, is_up) on every boot.
        // PVID and tagged_vlans are only set on first discovery — never overwritten on
        // subsequent boots so that user-assigned VLAN config is preserved.
        conn.execute(
            "INSERT INTO interfaces (name, mac, ips, mtu, is_up, pvid, tagged_vlans)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(name) DO UPDATE SET
                 mac   = excluded.mac,
                 ips   = excluded.ips,
                 mtu   = excluded.mtu,
                 is_up = excluded.is_up",
            rusqlite::params![
                iface.name,
                iface.mac,
                ips_json,
                iface.mtu,
                iface.is_up as i32,
                iface.pvid as i32,
                tagged_json,
            ],
        )
        .with_context(|| format!("failed to upsert interface '{}'", iface.name))?;

        tracing::info!(
            name = %iface.name,
            mac = %iface.mac,
            ips = ?iface.ips,
            mtu = iface.mtu,
            is_up = iface.is_up,
            pvid = iface.pvid,
            "discovered network interface"
        );
    }

    tracing::info!(
        count = interfaces.len(),
        "network interface detection complete"
    );

    // Drop the lock before calling wan functions (they acquire their own lock)
    drop(conn);

    // Auto-create default WAN configs (DHCP) for interfaces with pvid=0 (WAN ports)
    // that don't already have a wan_config entry.
    for iface in &interfaces {
        if iface.pvid == 0
            && let Ok(existing) = wan::get_wan_config(db, &iface.name).await
            && existing.is_none()
        {
            let priority = if iface.name == "eth8" { 1 } else { 2 };
            let default_config = wan::WanPortConfig {
                interface: iface.name.clone(),
                enabled: true,
                connection: wan::WanConnectionType::Dhcp,
                priority,
                weight: 100,
                health_check: "1.1.1.1".to_string(),
                health_interval_secs: 5,
                mtu: None,
                dns_override: None,
                mac_override: None,
            };
            if let Err(e) = wan::set_wan_config(db, &default_config).await {
                tracing::warn!(
                    interface = %iface.name,
                    "failed to create default WAN config: {e}"
                );
            } else {
                tracing::info!(
                    interface = %iface.name,
                    priority,
                    "created default WAN config (DHCP)"
                );
            }
        }
    }

    // Ensure default network zones exist. Uses INSERT OR IGNORE so that
    // existing user-configured zones are never overwritten, but missing
    // defaults (e.g. Guest/DMZ added in a later version) are backfilled.
    let conn2 = db.lock().await;

    #[allow(clippy::type_complexity)]
    let defaults: &[(&str, &str, Option<i32>, &str, &str, &str, &str, bool)] = &[
        (
            "LAN",
            "lan",
            Some(10),
            "192.168.1.0/24",
            "192.168.1.1",
            "192.168.1.100",
            "192.168.1.254",
            true,
        ),
        (
            "Management",
            "mgmt",
            Some(3000),
            "10.0.0.0/24",
            "10.0.0.1",
            "10.0.0.100",
            "10.0.0.254",
            true,
        ),
        (
            "Guest",
            "guest",
            Some(3001),
            "192.168.3.0/24",
            "192.168.3.1",
            "192.168.3.100",
            "192.168.3.254",
            true,
        ),
        (
            "DMZ",
            "dmz",
            Some(3002),
            "172.16.0.0/24",
            "172.16.0.1",
            "172.16.0.100",
            "172.16.0.254",
            true,
        ),
    ];

    for (name, zone, vlan_id, subnet, gateway, dhcp_start, dhcp_end, enabled) in defaults {
        let inserted = conn2.execute(
            "INSERT OR IGNORE INTO networks (name, zone, vlan_id, subnet, gateway, dhcp_start, dhcp_end, dhcp_enabled, enabled)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
            rusqlite::params![name, zone, vlan_id, subnet, gateway, dhcp_start, dhcp_end, *enabled as i32],
        ).map_err(NetError::Database)?;

        if inserted > 0 {
            tracing::info!(
                name,
                zone,
                ?vlan_id,
                subnet,
                enabled,
                "created default network zone"
            );
        }
    }
    drop(conn2);

    // Enable IPv4/IPv6 forwarding — required for routing between zones and WAN.
    for path in &[
        "/proc/sys/net/ipv4/ip_forward",
        "/proc/sys/net/ipv6/conf/all/forwarding",
    ] {
        if let Err(e) = tokio::fs::write(path, "1").await {
            tracing::warn!(path, "failed to enable forwarding: {e}");
        } else {
            tracing::info!(path, "IP forwarding enabled");
        }
    }

    // Setup hardware switch VLANs and Linux bridges for all enabled networks.
    switch::setup_networks(db, switch_layout.as_ref()).await?;

    // Start switch ASIC watchdog if we have a hardware switch.
    // Detects external reprogramming (e.g. ubios-udapi-server restart)
    // and rebuilds the full network stack within 10 seconds.
    if switch_layout.is_some() {
        let db_watch = db.clone();
        tokio::spawn(async move {
            switch::watchdog_loop(db_watch).await;
        });
    }

    // Apply all enabled WAN configs (start DHCP clients, PPPoE, set static routes, etc.)
    let wan_configs = wan::list_wan_configs(db).await.unwrap_or_default();
    for wc in &wan_configs {
        if wc.enabled {
            if let Err(e) = wan::apply_wan_config(wc).await {
                tracing::warn!(
                    interface = %wc.interface,
                    "failed to apply WAN config at boot: {e}"
                );
            }
        }
    }

    Ok(())
}

/// Return all stored interfaces from the database.
pub async fn list_interfaces(db: &sfgw_db::Db) -> Result<Vec<InterfaceInfo>> {
    let conn = db.lock().await;
    let mut stmt = conn
        .prepare("SELECT name, mac, ips, mtu, is_up, pvid, tagged_vlans FROM interfaces")
        .context("failed to prepare interface query")?;

    let rows = stmt
        .query_map([], |row| {
            let name: String = row.get(0)?;
            let mac: String = row.get(1)?;
            let ips_json: String = row.get(2)?;
            let mtu: u32 = row.get(3)?;
            let is_up: bool = row.get(4)?;
            let pvid_raw: i32 = row.get(5)?;
            let tagged_json: String = row.get(6)?;
            Ok((name, mac, ips_json, mtu, is_up, pvid_raw, tagged_json))
        })
        .context("failed to query interfaces")?;

    let mut interfaces = Vec::new();
    for row in rows {
        let (name, mac, ips_json, mtu, is_up, pvid_raw, tagged_json) = row?;
        let ips: Vec<String> = serde_json::from_str(&ips_json).unwrap_or_default();
        let pvid = pvid_raw.clamp(0, u16::MAX as i32) as u16;
        let tagged_vlans: Vec<u16> = serde_json::from_str(&tagged_json).unwrap_or_default();
        interfaces.push(InterfaceInfo {
            name,
            mac,
            ips,
            mtu,
            is_up,
            pvid,
            tagged_vlans,
        });
    }

    Ok(interfaces)
}

// ---------------------------------------------------------------------------
// Private helpers: read from /sys/class/net/
// ---------------------------------------------------------------------------

/// Platform-aware interface detection.
///
/// PVID assignment per platform:
/// - **Docker**: all interfaces → pvid=10 (LAN; web UI must be reachable)
/// - **Bare metal (UDM Pro)**: eth8/eth9 → pvid=0 (WAN), eth7 → pvid=3000 (MGMT), rest → pvid=10
/// - **Bare metal (generic)**: first physical → pvid=0 (WAN), rest → pvid=10
/// - **VM**: same as generic bare metal
fn detect_interfaces_for_platform(
    platform: &sfgw_hal::Platform,
) -> Result<(Vec<InterfaceInfo>, Option<switch::SwitchLayout>)> {
    let mut interfaces = detect_interfaces()?;
    let mut switch_layout: Option<switch::SwitchLayout> = None;

    match platform {
        sfgw_hal::Platform::Docker => {
            for iface in &mut interfaces {
                if iface.pvid == 0 {
                    iface.pvid = 10;
                    tracing::info!(
                        name = %iface.name,
                        "Docker mode: reassigned interface from WAN (pvid=0) to LAN (pvid=10)"
                    );
                }
            }
        }
        sfgw_hal::Platform::BareMetal => {
            if let Some(board) = sfgw_hal::detect_board() {
                let wan = board.wan_ifaces();
                let mgmt = board.mgmt_iface();
                for iface in &mut interfaces {
                    if wan.contains(&iface.name.as_str()) {
                        iface.pvid = 0; // WAN: outside internal VLAN space
                    } else if mgmt == Some(iface.name.as_str()) {
                        iface.pvid = 3000;
                    } else if iface.pvid == 0 {
                        // Default-guessed WAN that isn't actually WAN on this board
                        iface.pvid = 10;
                    }
                }
                tracing::info!(
                    board_id = %board.board_id,
                    model = board.short_name,
                    ?wan,
                    ?mgmt,
                    "port PVIDs assigned from board ID"
                );
                switch_layout = board.switch.map(|sw| switch::SwitchLayout {
                    device: sw.device.to_string(),
                    lan_ports: sw.lan_ports.to_vec(),
                    cpu_port: sw.cpu_port,
                    internal_ports: sw.internal_ports.to_vec(),
                    mgmt_port: sw.mgmt_port,
                });
            }
        }
        sfgw_hal::Platform::Vm => {}
    }

    Ok((interfaces, switch_layout))
}

/// Detect all network interfaces by reading sysfs.
fn detect_interfaces() -> Result<Vec<InterfaceInfo>> {
    let sysfs = Path::new(SYSFS_NET);
    if !sysfs.exists() {
        return Err(NetError::Internal(anyhow::anyhow!(
            "{SYSFS_NET} does not exist; cannot detect interfaces"
        )));
    }

    let mut interfaces = Vec::new();

    let entries = fs::read_dir(sysfs).with_context(|| format!("failed to read {SYSFS_NET}"))?;

    for entry in entries {
        let entry = entry?;
        let iface_name = entry.file_name().to_string_lossy().to_string();
        let iface_dir = entry.path();

        let mac = read_sysfs_trimmed(&iface_dir.join("address")).unwrap_or_default();
        let mtu = read_sysfs_trimmed(&iface_dir.join("mtu"))
            .unwrap_or_default()
            .parse::<u32>()
            .unwrap_or(1500);
        let operstate = read_sysfs_trimmed(&iface_dir.join("operstate")).unwrap_or_default();
        let is_up = operstate == "up";

        let ips = read_ip_addresses(&iface_name);
        let pvid = guess_pvid(&iface_name);
        let tagged_vlans = guess_tagged_vlans();

        interfaces.push(InterfaceInfo {
            name: iface_name,
            mac,
            ips,
            mtu,
            is_up,
            pvid,
            tagged_vlans,
        });
    }

    // Sort by name for deterministic output.
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(interfaces)
}

/// Read a sysfs file and return its trimmed contents.
fn read_sysfs_trimmed(path: &Path) -> Result<String> {
    Ok(fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .with_context(|| format!("failed to read {}", path.display()))?)
}

/// Read IP addresses assigned to an interface by scanning
/// `/sys/class/net/<iface>/address` is per-interface, but IPs are not
/// directly in sysfs. We fall back to parsing `/proc/net/if_inet6` (IPv6)
/// and the `RTNETLINK` entries in `/proc/net/fib_trie` (IPv4).
///
/// For simplicity and zero-dependency operation we parse /proc files.
pub(crate) fn read_ip_addresses(iface_name: &str) -> Vec<String> {
    let mut addrs = Vec::new();

    // IPv4: parse /proc/net/fib_trie is complex; use /proc/net/if_net (not available).
    // Instead, try reading the iface-specific path if available:
    //   /sys/class/net/<iface>/... doesn't expose IPs directly.
    //
    // Simpler approach: parse lines from /proc/net/fib_trie or /proc/net/route.
    // Most portable: parse each line of /proc/net/if_inet6 for IPv6
    // and /proc/net/fib_trie for IPv4.

    // --- IPv4 via /proc/net/fib_trie ---
    if let Some(ipv4) = read_ipv4_from_fib_trie(iface_name) {
        addrs.extend(ipv4);
    }

    // --- IPv6 via /proc/net/if_inet6 ---
    if let Ok(content) = fs::read_to_string("/proc/net/if_inet6") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Format: addr_hex index prefix_len scope flags iface_name
            if parts.len() >= 6
                && parts[5] == iface_name
                && let Some(addr) = hex_to_ipv6(parts[0])
            {
                let prefix_len = parts[2];
                addrs.push(format!("{addr}/{prefix_len}"));
            }
        }
    }

    addrs
}

/// Parse /proc/net/fib_trie to extract local IPv4 addresses for a given interface.
///
/// The file structure alternates between interface sections and trie entries.
/// We use /proc/net/fib_trie's "LOCAL" markers combined with
/// /proc/net/route to find per-interface addresses.
///
/// Actually, the simpler approach: read /proc/net/fib_trie*info* or just
/// iterate /proc/net/fib_trie looking for pattern. But the most reliable
/// zero-dep approach is to parse /proc/net/route for interface association
/// and then look up addresses from fib_trie.
///
/// Simplest reliable method: read lines from both files.
fn read_ipv4_from_fib_trie(iface_name: &str) -> Option<Vec<String>> {
    // Use /proc/net/fib_trie with the per-table format.
    // Each table is headed by the interface. We look for the "Local" section.
    let fib_path = PathBuf::from("/proc/net/fib_trie");
    let content = fs::read_to_string(&fib_path).ok()?;

    let mut addrs = Vec::new();
    // Track which table (interface) we're in by using /proc/net/fib_triestat
    // This is too complex. Use the simpler /proc/net/if_inet approach instead.
    //
    // Most reliable simple method for IPv4: read /proc/net/route to get
    // the interface->destination mapping, then check if we can read the
    // address from the binary socket interface. But that needs ioctls.
    //
    // Fallback: parse "ip addr show <iface>" would need Command::new.
    //
    // Let's just use the fib_trie approach properly:
    // The file has per-interface tables like:
    //   "Local:\n  /32 host LOCAL\n    +-- <ip>"
    // Actually, the format is nested. Let's just look at the structure:
    //   Main:
    //   Local:
    //     ... entries with /32 host LOCAL ...
    //
    // The per-interface view is at /proc/net/fib_trie but interface names
    // only appear in the header lines like "  +-- 0.0.0.0/0 ..." which is
    // not actually per-interface.
    //
    // Best zero-dependency approach: /proc/net/fib_trie for table "Local"
    // combined with /proc/net/route for interface mapping.
    //
    // Let's read /proc/net/route to get subnets per interface, then pull
    // actual addresses from the LOCAL table in fib_trie.

    // Step 1: Get network prefixes for this interface from /proc/net/route
    let route_content = fs::read_to_string("/proc/net/route").ok()?;
    let mut iface_dests = Vec::new();
    for line in route_content.lines().skip(1) {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 8 && parts[0] == iface_name {
            // Destination is hex-encoded little-endian IPv4
            if let Some(dest) = hex_le_to_ipv4(parts[1]) {
                let mask = hex_le_to_ipv4(parts[7]).unwrap_or_default();
                if dest != "0.0.0.0" {
                    iface_dests.push((dest, mask));
                }
            }
        }
    }

    // Step 2: Find LOCAL addresses in fib_trie that match any of the subnets
    let mut in_local = false;
    let mut last_ip = String::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "Local:" {
            in_local = true;
            continue;
        }
        if trimmed == "Main:" {
            in_local = false;
            continue;
        }
        if !in_local {
            continue;
        }

        // Lines like "  +-- 10.0.0.1/32 host LOCAL"
        // or "     |-- 10.0.0.1"
        if trimmed.starts_with("|--") || trimmed.starts_with("+--") {
            let ip_part = trimmed
                .trim_start_matches("|--")
                .trim_start_matches("+--")
                .trim();
            // Strip prefix if present
            last_ip = ip_part.split('/').next().unwrap_or("").to_string();
        }

        if trimmed.contains("/32 host LOCAL") {
            // last_ip is a local address; check if it belongs to our interface
            if !last_ip.is_empty()
                && last_ip != "127.0.0.1"
                && ip_in_any_subnet(&last_ip, &iface_dests)
            {
                addrs.push(last_ip.clone());
            }
        }
    }

    // If we found nothing from fib_trie but have routes, try getting
    // the IP directly. For loopback, just hardcode if matching.
    if addrs.is_empty() && iface_name == "lo" {
        addrs.push("127.0.0.1".to_string());
    }

    if addrs.is_empty() { None } else { Some(addrs) }
}

/// Check if an IP falls within any of the given (dest, mask) pairs.
fn ip_in_any_subnet(ip: &str, subnets: &[(String, String)]) -> bool {
    let ip_u32 = match ipv4_to_u32(ip) {
        Some(v) => v,
        None => return false,
    };

    for (dest, mask) in subnets {
        let dest_u32 = match ipv4_to_u32(dest) {
            Some(v) => v,
            None => continue,
        };
        let mask_u32 = match ipv4_to_u32(mask) {
            Some(v) => v,
            None => continue,
        };
        if (ip_u32 & mask_u32) == (dest_u32 & mask_u32) {
            return true;
        }
    }
    false
}

fn ipv4_to_u32(ip: &str) -> Option<u32> {
    let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() == 4 {
        Some(
            (u32::from(parts[0]) << 24)
                | (u32::from(parts[1]) << 16)
                | (u32::from(parts[2]) << 8)
                | u32::from(parts[3]),
        )
    } else {
        None
    }
}

/// Convert a hex-encoded little-endian IPv4 (from /proc/net/route) to dotted notation.
fn hex_le_to_ipv4(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let val = u32::from_str_radix(hex, 16).ok()?;
    // /proc/net/route stores in host byte order (little-endian on x86)
    Some(format!(
        "{}.{}.{}.{}",
        val & 0xFF,
        (val >> 8) & 0xFF,
        (val >> 16) & 0xFF,
        (val >> 24) & 0xFF,
    ))
}

/// Convert a 32-character hex string from /proc/net/if_inet6 to an IPv6 address.
fn hex_to_ipv6(hex: &str) -> Option<String> {
    if hex.len() != 32 {
        return None;
    }
    let groups: Vec<String> = (0..8)
        .map(|i| {
            let start = i * 4;
            hex[start..start + 4].to_string()
        })
        .collect();
    // Build a full address, then let it be; no need to compress for storage.
    Some(
        groups
            .iter()
            .map(|g| g.trim_start_matches('0'))
            .map(|g| if g.is_empty() { "0" } else { g })
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Guess the initial PVID for an interface based on naming conventions.
///
/// Returns 0 for loopback/VPN/container/virtual interfaces (not internal VLAN ports),
/// 0 for the first physical interface (likely WAN), and 10 (LAN) for everything else.
fn guess_pvid(name: &str) -> u16 {
    if name == "lo" {
        0 // Loopback: not a VLAN port
    } else if name.starts_with("wg") || name.starts_with("tun") || name.starts_with("tap") {
        0 // VPN tunnels: not a VLAN port
    } else if name.starts_with("docker") || name.starts_with("br-") || name.starts_with("veth") {
        0 // Container interfaces: not a VLAN port
    } else if name.starts_with("wl") || name.starts_with("wlan") {
        10 // WiFi: LAN by default
    } else if name.starts_with("virbr") {
        0 // Virtual bridge: not a VLAN port
    } else if name.starts_with("eth0") || name.starts_with("ens") || name.starts_with("enp") {
        // First physical interface is typically WAN; pvid=0 signals "not internal VLAN"
        0
    } else {
        // eth1+, en*, and anything else defaults to LAN
        10
    }
}

/// Guess tagged VLANs for an interface during auto-detection.
///
/// Always returns an empty list — tagged VLAN trunk membership is never
/// auto-detected, only user-configured. This makes the intent explicit.
fn guess_tagged_vlans() -> Vec<u16> {
    vec![]
}

/// I/O statistics for a single network interface.
///
/// ```
/// use sfgw_net::IfaceIoStats;
///
/// let stats = IfaceIoStats {
///     name: "eth0".to_string(),
///     rx_bytes: 1_000_000,
///     tx_bytes: 500_000,
/// };
/// assert_eq!(stats.rx_bytes, 1_000_000);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IfaceIoStats {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Aggregate network I/O statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetIoStats {
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub interfaces: Vec<IfaceIoStats>,
}

/// Read aggregate network I/O counters from `/proc/net/dev`.
///
/// Returns per-interface rx/tx bytes (excluding loopback and zero-traffic
/// interfaces) plus a total sum across all active interfaces.
///
/// ```
/// let stats = sfgw_net::read_net_io();
/// // On any Linux system, this returns a valid struct
/// assert!(stats.total_rx_bytes >= 0);
/// // Loopback is always excluded
/// assert!(stats.interfaces.iter().all(|i| i.name != "lo"));
/// ```
pub fn read_net_io() -> NetIoStats {
    let content = fs::read_to_string("/proc/net/dev").unwrap_or_default();
    let mut total_rx: u64 = 0;
    let mut total_tx: u64 = 0;
    let mut interfaces = Vec::new();

    // Skip header lines (first 2 lines)
    for line in content.lines().skip(2) {
        let line = line.trim();
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        // Skip loopback
        if name == "lo" {
            continue;
        }

        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        let rx_bytes: u64 = fields[0].parse().unwrap_or(0);
        let tx_bytes: u64 = fields[8].parse().unwrap_or(0);

        // Skip interfaces with zero traffic (not connected)
        if rx_bytes == 0 && tx_bytes == 0 {
            continue;
        }

        total_rx += rx_bytes;
        total_tx += tx_bytes;

        interfaces.push(IfaceIoStats {
            name: name.to_string(),
            rx_bytes,
            tx_bytes,
        });
    }

    NetIoStats {
        total_rx_bytes: total_rx,
        total_tx_bytes: total_tx,
        interfaces,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create an in-memory database with the sfgw schema.
    async fn test_db() -> sfgw_db::Db {
        sfgw_db::open_in_memory()
            .await
            .expect("failed to open in-memory db")
    }

    #[test]
    fn test_interface_info_construction() {
        let iface = InterfaceInfo {
            name: "eth0".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            ips: vec!["192.168.1.1".to_string()],
            mtu: 1500,
            is_up: true,
            pvid: 0,
            tagged_vlans: vec![],
        };
        assert_eq!(iface.name, "eth0");
        assert_eq!(iface.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(iface.ips.len(), 1);
        assert_eq!(iface.mtu, 1500);
        assert!(iface.is_up);
        assert_eq!(iface.pvid, 0);
        assert!(iface.tagged_vlans.is_empty());
    }

    #[test]
    fn test_interface_info_serialize_deserialize() {
        let iface = InterfaceInfo {
            name: "lo".to_string(),
            mac: "00:00:00:00:00:00".to_string(),
            ips: vec!["127.0.0.1".to_string(), "::1/128".to_string()],
            mtu: 65536,
            is_up: true,
            pvid: 0,
            tagged_vlans: vec![],
        };
        let json = serde_json::to_string(&iface).expect("serialize failed");
        let deserialized: InterfaceInfo = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(deserialized.name, "lo");
        assert_eq!(deserialized.ips.len(), 2);
        assert_eq!(deserialized.pvid, 0);
    }

    #[tokio::test]
    async fn test_list_interfaces_returns_empty_initially() {
        let db = test_db().await;
        let interfaces = list_interfaces(&db).await.expect("list_interfaces failed");
        assert!(interfaces.is_empty(), "fresh DB should have no interfaces");
    }

    #[tokio::test]
    async fn test_list_interfaces_after_insert() {
        let db = test_db().await;

        // Insert a test interface directly
        {
            let conn = db.lock().await;
            conn.execute(
                "INSERT INTO interfaces (name, mac, ips, mtu, is_up, pvid, tagged_vlans)
                 VALUES ('lo', '00:00:00:00:00:00', '[\"127.0.0.1\"]', 65536, 1, 0, '[]')",
                [],
            )
            .expect("failed to insert test interface");
        }

        let interfaces = list_interfaces(&db).await.expect("list_interfaces failed");
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].name, "lo");
        assert_eq!(interfaces[0].pvid, 0);
        assert!(interfaces[0].tagged_vlans.is_empty());
        assert!(interfaces[0].is_up);
    }

    #[test]
    fn test_guess_pvid_loopback() {
        assert_eq!(guess_pvid("lo"), 0); // loopback: not a VLAN port
    }

    #[test]
    fn test_guess_pvid_vpn() {
        assert_eq!(guess_pvid("wg0"), 0); // VPN: not a VLAN port
        assert_eq!(guess_pvid("tun0"), 0);
        assert_eq!(guess_pvid("tap0"), 0);
    }

    #[test]
    fn test_guess_pvid_container() {
        assert_eq!(guess_pvid("docker0"), 0); // container: not a VLAN port
        assert_eq!(guess_pvid("br-abc123"), 0);
        assert_eq!(guess_pvid("veth1234"), 0);
    }

    #[test]
    fn test_guess_pvid_wifi() {
        assert_eq!(guess_pvid("wlan0"), 10); // WiFi: LAN by default
        assert_eq!(guess_pvid("wlp2s0"), 10);
    }

    #[test]
    fn test_guess_pvid_virtual() {
        assert_eq!(guess_pvid("virbr0"), 0); // virtual bridge: not a VLAN port
    }

    #[test]
    fn test_guess_pvid_wan() {
        assert_eq!(guess_pvid("eth0"), 0); // first physical: WAN (pvid=0)
        assert_eq!(guess_pvid("ens33"), 0);
        assert_eq!(guess_pvid("enp0s3"), 0);
    }

    #[test]
    fn test_guess_pvid_lan() {
        assert_eq!(guess_pvid("eth1"), 10); // LAN default
        assert_eq!(guess_pvid("en1"), 10);
        assert_eq!(guess_pvid("someother"), 10);
    }

    #[test]
    fn test_guess_tagged_vlans_always_empty() {
        // Tagged VLANs are never auto-detected, always user-configured.
        assert!(guess_tagged_vlans().is_empty());
    }

    #[test]
    fn test_hex_to_ipv6_valid() {
        // ::1 in /proc/net/if_inet6 format
        let result = hex_to_ipv6("00000000000000000000000000000001");
        assert!(result.is_some());
        let addr = result.unwrap();
        assert!(
            addr.contains("1"),
            "expected ::1 representation, got: {addr}"
        );
    }

    #[test]
    fn test_hex_to_ipv6_invalid_length() {
        assert!(hex_to_ipv6("0000").is_none());
        assert!(hex_to_ipv6("").is_none());
    }

    #[test]
    fn test_hex_le_to_ipv4_valid() {
        // 0100007F: byte 0 = 0x01, byte 1 = 0x00, byte 2 = 0x00, byte 3 = 0x7F
        // The function reads the u32 and extracts bytes as val&0xFF, (val>>8)&0xFF, etc.
        // u32::from_str_radix("0100007F", 16) = 0x0100007F
        // So: byte0 = 0x7F = 127, byte1 = 0x00, byte2 = 0x00, byte3 = 0x01
        // Output: "127.0.0.1"
        let result = hex_le_to_ipv4("0100007F");
        assert_eq!(result, Some("127.0.0.1".to_string()));
    }

    #[test]
    fn test_hex_le_to_ipv4_invalid() {
        assert!(hex_le_to_ipv4("").is_none());
        assert!(hex_le_to_ipv4("ZZZZZZZZ").is_none());
        assert!(hex_le_to_ipv4("12345").is_none());
    }

    #[test]
    fn test_ipv4_to_u32() {
        assert_eq!(ipv4_to_u32("127.0.0.1"), Some(0x7F000001));
        assert_eq!(ipv4_to_u32("0.0.0.0"), Some(0));
        assert_eq!(ipv4_to_u32("255.255.255.255"), Some(0xFFFFFFFF));
        assert_eq!(ipv4_to_u32("invalid"), None);
    }

    #[test]
    fn test_ip_in_any_subnet() {
        let subnets = vec![("192.168.1.0".to_string(), "255.255.255.0".to_string())];
        assert!(ip_in_any_subnet("192.168.1.100", &subnets));
        assert!(!ip_in_any_subnet("10.0.0.1", &subnets));
    }

    #[tokio::test]
    async fn test_default_networks_seeded_on_empty_db() {
        let db = test_db().await;

        // After all migrations, the DB has exactly 1 network: void VLAN 1 (inserted by migration 005).
        // configure() uses a non-void count check so it seeds when no user-visible networks exist.
        {
            let conn = db.lock().await;
            let total: i64 = conn
                .query_row("SELECT COUNT(*) FROM networks", [], |r| r.get(0))
                .expect("networks table should exist");
            assert_eq!(total, 1, "fresh DB should have only the void entry from migration 005");

            let non_void: i64 = conn
                .query_row("SELECT COUNT(*) FROM networks WHERE zone != 'void'", [], |r| r.get(0))
                .expect("non-void count query failed");
            assert_eq!(non_void, 0, "fresh DB should have no user-visible networks");
        }

        // Insert defaults (same logic as configure() — does NOT re-insert void, migration handles it)
        {
            let conn = db.lock().await;
            let defaults: &[(&str, &str, Option<i32>, &str, &str, &str, &str, bool)] = &[
                (
                    "LAN",
                    "lan",
                    Some(10),
                    "192.168.1.0/24",
                    "192.168.1.1",
                    "192.168.1.100",
                    "192.168.1.254",
                    true,
                ),
                (
                    "Management",
                    "mgmt",
                    Some(3000),
                    "10.0.0.0/24",
                    "10.0.0.1",
                    "10.0.0.100",
                    "10.0.0.254",
                    true,
                ),
                (
                    "Guest",
                    "guest",
                    Some(3001),
                    "192.168.3.0/24",
                    "192.168.3.1",
                    "192.168.3.100",
                    "192.168.3.254",
                    true,
                ),
                (
                    "DMZ",
                    "dmz",
                    Some(3002),
                    "172.16.0.0/24",
                    "172.16.0.1",
                    "172.16.0.100",
                    "172.16.0.254",
                    true,
                ),
            ];

            for (name, zone, vlan_id, subnet, gateway, dhcp_start, dhcp_end, enabled) in defaults {
                conn.execute(
                    "INSERT OR IGNORE INTO networks (name, zone, vlan_id, subnet, gateway, dhcp_start, dhcp_end, dhcp_enabled, enabled)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
                    rusqlite::params![name, zone, vlan_id, subnet, gateway, dhcp_start, dhcp_end, *enabled as i32],
                ).expect("failed to insert default network");
            }
        }

        // Total = void (from migration) + 4 seeded = 5
        let conn = db.lock().await;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM networks", [], |r| r.get(0))
            .expect("count query failed");
        assert_eq!(count, 5, "should have 5 total networks (1 void from migration + 4 seeded)");

        // Verify Void VLAN 1 exists and is disabled (inserted by migration 005)
        let void_vlan: i32 = conn
            .query_row("SELECT vlan_id FROM networks WHERE zone = 'void'", [], |r| {
                r.get(0)
            })
            .expect("Void network should exist");
        assert_eq!(void_vlan, 1, "Void should have VLAN 1");
        let void_enabled: i32 = conn
            .query_row("SELECT enabled FROM networks WHERE zone = 'void'", [], |r| {
                r.get(0)
            })
            .expect("Void enabled should be readable");
        assert_eq!(void_enabled, 0, "Void should be disabled");

        // Verify LAN has vlan_id=10 (not NULL)
        let lan_vlan: i32 = conn
            .query_row("SELECT vlan_id FROM networks WHERE zone = 'lan'", [], |r| {
                r.get(0)
            })
            .expect("LAN network should exist");
        assert_eq!(lan_vlan, 10, "LAN should have VLAN 10");

        // Verify LAN is enabled
        let lan_enabled: i32 = conn
            .query_row("SELECT enabled FROM networks WHERE zone = 'lan'", [], |r| {
                r.get(0)
            })
            .expect("LAN enabled should be readable");
        assert_eq!(lan_enabled, 1, "LAN should be enabled");

        // Verify VLAN IDs for other zones
        let dmz_vlan: i32 = conn
            .query_row("SELECT vlan_id FROM networks WHERE zone = 'dmz'", [], |r| {
                r.get(0)
            })
            .expect("DMZ network should exist");
        assert_eq!(dmz_vlan, 3002, "DMZ should have VLAN 3002");
    }

    #[tokio::test]
    async fn test_existing_networks_not_overwritten() {
        let db = test_db().await;

        // Insert a custom LAN with non-default subnet to simulate user config.
        // INSERT OR IGNORE should skip this zone (name "LAN" already taken)
        // but still insert MGMT, Guest, DMZ defaults.
        {
            let conn = db.lock().await;
            conn.execute(
                "INSERT INTO networks (name, zone, vlan_id, subnet, gateway, enabled)
                 VALUES ('LAN', 'lan', 10, '10.10.0.0/24', '10.10.0.1', 1)",
                [],
            )
            .expect("failed to insert custom network");
        }

        // Run INSERT OR IGNORE for all defaults (same logic as configure())
        {
            let conn = db.lock().await;
            for (name, zone, vlan_id, subnet, gw) in &[
                ("LAN", "lan", 10, "192.168.1.0/24", "192.168.1.1"),
                ("Management", "mgmt", 3000, "10.0.0.0/24", "10.0.0.1"),
                ("Guest", "guest", 3001, "192.168.3.0/24", "192.168.3.1"),
                ("DMZ", "dmz", 3002, "172.16.0.0/24", "172.16.0.1"),
            ] {
                conn.execute(
                    "INSERT OR IGNORE INTO networks (name, zone, vlan_id, subnet, gateway, dhcp_enabled, enabled)
                     VALUES (?1, ?2, ?3, ?4, ?5, 1, 1)",
                    rusqlite::params![name, zone, vlan_id, subnet, gw],
                ).expect("insert or ignore failed");
            }
        }

        let conn = db.lock().await;

        // CustomLAN should keep its custom subnet (not overwritten)
        let lan_subnet: String = conn
            .query_row("SELECT subnet FROM networks WHERE zone = 'lan'", [], |r| r.get(0))
            .expect("LAN should exist");
        assert_eq!(lan_subnet, "10.10.0.0/24", "custom LAN subnet must not be overwritten");

        // Missing defaults should have been backfilled
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM networks WHERE zone != 'void'", [], |r| r.get(0))
            .expect("count query failed");
        assert_eq!(total, 4, "should have 4 non-void networks (custom LAN + 3 backfilled defaults)");
    }
}
