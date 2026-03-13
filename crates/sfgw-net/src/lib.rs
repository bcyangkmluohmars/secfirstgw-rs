// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

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
///     role: "wan".to_string(),
/// };
///
/// // Roundtrip via JSON
/// let json = serde_json::to_string(&iface).unwrap();
/// let back: InterfaceInfo = serde_json::from_str(&json).unwrap();
/// assert_eq!(back.name, "eth0");
/// assert_eq!(back.role, "wan");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub mac: String,
    pub ips: Vec<String>,
    pub mtu: u32,
    pub is_up: bool,
    pub role: String,
}

const SYSFS_NET: &str = "/sys/class/net";

/// Detect network interfaces on the system and store them in the database.
///
/// Role assignment is platform-aware:
/// - **Docker**: single NIC → LAN (web UI must be reachable)
/// - **Bare metal**: eth0/ens*/enp* first physical → WAN, rest → LAN
/// - **VM**: same as bare metal
pub async fn configure(db: &sfgw_db::Db, platform: &sfgw_hal::Platform) -> Result<()> {
    let interfaces = detect_interfaces_for_platform(platform)?;

    let conn = db.lock().await;
    for iface in &interfaces {
        let ips_json = serde_json::to_string(&iface.ips).context("failed to serialize IPs")?;

        conn.execute(
            "INSERT INTO interfaces (name, mac, ips, mtu, is_up, role)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(name) DO UPDATE SET
                 mac   = excluded.mac,
                 ips   = excluded.ips,
                 mtu   = excluded.mtu,
                 is_up = excluded.is_up,
                 role   = excluded.role",
            rusqlite::params![
                iface.name,
                iface.mac,
                ips_json,
                iface.mtu,
                iface.is_up as i32,
                iface.role,
            ],
        )
        .with_context(|| format!("failed to upsert interface '{}'", iface.name))?;

        tracing::info!(
            name = %iface.name,
            mac = %iface.mac,
            ips = ?iface.ips,
            mtu = iface.mtu,
            is_up = iface.is_up,
            role = %iface.role,
            "discovered network interface"
        );
    }

    tracing::info!(
        count = interfaces.len(),
        "network interface detection complete"
    );
    Ok(())
}

/// Return all stored interfaces from the database.
pub async fn list_interfaces(db: &sfgw_db::Db) -> Result<Vec<InterfaceInfo>> {
    let conn = db.lock().await;
    let mut stmt = conn
        .prepare("SELECT name, mac, ips, mtu, is_up, role FROM interfaces")
        .context("failed to prepare interface query")?;

    let rows = stmt
        .query_map([], |row| {
            let name: String = row.get(0)?;
            let mac: String = row.get(1)?;
            let ips_json: String = row.get(2)?;
            let mtu: u32 = row.get(3)?;
            let is_up: bool = row.get(4)?;
            let role: String = row.get(5)?;
            Ok((name, mac, ips_json, mtu, is_up, role))
        })
        .context("failed to query interfaces")?;

    let mut interfaces = Vec::new();
    for row in rows {
        let (name, mac, ips_json, mtu, is_up, role) = row?;
        let ips: Vec<String> = serde_json::from_str(&ips_json).unwrap_or_default();
        interfaces.push(InterfaceInfo {
            name,
            mac,
            ips,
            mtu,
            is_up,
            role,
        });
    }

    Ok(interfaces)
}

// ---------------------------------------------------------------------------
// Private helpers: read from /sys/class/net/
// ---------------------------------------------------------------------------

/// Platform-aware interface detection.
///
/// In Docker, all non-virtual interfaces are assigned LAN role because
/// there is only one NIC and the web UI must be reachable.
/// On bare metal / VM, the first physical interface is WAN, rest are LAN.
fn detect_interfaces_for_platform(platform: &sfgw_hal::Platform) -> Result<Vec<InterfaceInfo>> {
    let mut interfaces = detect_interfaces()?;

    if *platform == sfgw_hal::Platform::Docker {
        // Docker: only one NIC, must be LAN for web UI access.
        // Override any WAN assignments.
        for iface in &mut interfaces {
            if iface.role == "wan" {
                iface.role = "lan".to_string();
                tracing::info!(
                    name = %iface.name,
                    "Docker mode: reassigned interface from WAN to LAN"
                );
            }
        }
    }

    Ok(interfaces)
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
        let role = guess_role(&iface_name);

        interfaces.push(InterfaceInfo {
            name: iface_name,
            mac,
            ips,
            mtu,
            is_up,
            role,
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
fn read_ip_addresses(iface_name: &str) -> Vec<String> {
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

/// Guess a role for the interface based on naming conventions.
fn guess_role(name: &str) -> String {
    if name == "lo" {
        "loopback".to_string()
    } else if name.starts_with("wg") || name.starts_with("tun") || name.starts_with("tap") {
        "vpn".to_string()
    } else if name.starts_with("docker") || name.starts_with("br-") || name.starts_with("veth") {
        "container".to_string()
    } else if name.starts_with("wl") || name.starts_with("wlan") {
        "wifi".to_string()
    } else if name.starts_with("virbr") {
        "virtual".to_string()
    } else if name.starts_with("eth0") || name.starts_with("ens") || name.starts_with("enp") {
        // First physical interface is typically WAN
        "wan".to_string()
    } else {
        // eth1+, en*, and anything else defaults to LAN
        "lan".to_string()
    }
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
            role: "wan".to_string(),
        };
        assert_eq!(iface.name, "eth0");
        assert_eq!(iface.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(iface.ips.len(), 1);
        assert_eq!(iface.mtu, 1500);
        assert!(iface.is_up);
        assert_eq!(iface.role, "wan");
    }

    #[test]
    fn test_interface_info_serialize_deserialize() {
        let iface = InterfaceInfo {
            name: "lo".to_string(),
            mac: "00:00:00:00:00:00".to_string(),
            ips: vec!["127.0.0.1".to_string(), "::1/128".to_string()],
            mtu: 65536,
            is_up: true,
            role: "loopback".to_string(),
        };
        let json = serde_json::to_string(&iface).expect("serialize failed");
        let deserialized: InterfaceInfo = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(deserialized.name, "lo");
        assert_eq!(deserialized.ips.len(), 2);
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
                "INSERT INTO interfaces (name, mac, ips, mtu, is_up, role)
                 VALUES ('lo', '00:00:00:00:00:00', '[\"127.0.0.1\"]', 65536, 1, 'loopback')",
                [],
            )
            .expect("failed to insert test interface");
        }

        let interfaces = list_interfaces(&db).await.expect("list_interfaces failed");
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].name, "lo");
        assert_eq!(interfaces[0].role, "loopback");
        assert!(interfaces[0].is_up);
    }

    #[test]
    fn test_guess_role_loopback() {
        assert_eq!(guess_role("lo"), "loopback");
    }

    #[test]
    fn test_guess_role_vpn() {
        assert_eq!(guess_role("wg0"), "vpn");
        assert_eq!(guess_role("tun0"), "vpn");
        assert_eq!(guess_role("tap0"), "vpn");
    }

    #[test]
    fn test_guess_role_container() {
        assert_eq!(guess_role("docker0"), "container");
        assert_eq!(guess_role("br-abc123"), "container");
        assert_eq!(guess_role("veth1234"), "container");
    }

    #[test]
    fn test_guess_role_wifi() {
        assert_eq!(guess_role("wlan0"), "wifi");
        assert_eq!(guess_role("wlp2s0"), "wifi");
    }

    #[test]
    fn test_guess_role_virtual() {
        assert_eq!(guess_role("virbr0"), "virtual");
    }

    #[test]
    fn test_guess_role_wan() {
        assert_eq!(guess_role("eth0"), "wan");
        assert_eq!(guess_role("ens33"), "wan");
        assert_eq!(guess_role("enp0s3"), "wan");
    }

    #[test]
    fn test_guess_role_lan() {
        assert_eq!(guess_role("eth1"), "lan");
        assert_eq!(guess_role("en1"), "lan");
        assert_eq!(guess_role("someother"), "lan");
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
}
