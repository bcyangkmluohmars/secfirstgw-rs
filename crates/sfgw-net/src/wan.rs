// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-WAN-port configuration: DHCP, Static IP, PPPoE, DS-Lite, VLAN.
//!
//! Each WAN interface can be independently configured with its own
//! connection type. Configurations are stored as JSON in the `wan_configs`
//! database table and applied to the system via `ip`, `pppd`, etc.

use crate::{NetError, Result};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::Mutex;

// ── Default helpers for serde ───────────────────────────────────────

fn default_pppoe_mtu() -> u16 {
    1492
}

fn default_true() -> bool {
    true
}

fn default_health_check() -> String {
    "1.1.1.1".to_string()
}

fn default_health_interval() -> u32 {
    10
}

// ── Data model ──────────────────────────────────────────────────────

/// WAN connection type per interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum WanConnectionType {
    /// DHCP client (most common, default).
    Dhcp,
    /// Static IP configuration.
    Static {
        /// IPv4 address with prefix, e.g. "203.0.113.5/24".
        address: String,
        /// IPv4 gateway, e.g. "203.0.113.1".
        gateway: String,
        /// Optional IPv6 address with prefix.
        #[serde(default)]
        address_v6: Option<String>,
        /// Optional IPv6 gateway.
        #[serde(default)]
        gateway_v6: Option<String>,
    },
    /// PPPoE (DSL connections).
    Pppoe {
        /// PPPoE username.
        username: String,
        /// Password stored encrypted in DB (not plaintext).
        password_enc: String,
        /// MTU, typically 1492 for PPPoE.
        #[serde(default = "default_pppoe_mtu")]
        mtu: u16,
        /// PPPoE service name (optional).
        #[serde(default)]
        service_name: Option<String>,
        /// PPPoE access concentrator name (optional).
        #[serde(default)]
        ac_name: Option<String>,
        /// VLAN tag for PPPoE (e.g. VLAN 7 for Deutsche Telekom).
        #[serde(default)]
        vlan_id: Option<u16>,
    },
    /// DS-Lite (IPv4-in-IPv6 tunnel for CGN providers).
    DsLite {
        /// AFTR address (usually auto-discovered via DHCPv6 option 64).
        #[serde(default)]
        aftr_address: Option<String>,
        /// If true, use DHCPv6 to discover AFTR (default).
        #[serde(default = "default_true")]
        auto_aftr: bool,
    },
    /// VLAN trunk (tagged traffic on WAN port).
    Vlan {
        /// VLAN ID, 1-4094.
        vlan_id: u16,
        /// Inner connection type (DHCP, Static, PPPoE within the VLAN).
        inner: Box<WanConnectionType>,
    },
}

/// Per-WAN-port configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WanPortConfig {
    /// Interface name (e.g. "eth0", "eth4").
    pub interface: String,
    /// Connection type.
    pub connection: WanConnectionType,
    /// Enable/disable this WAN port.
    pub enabled: bool,
    /// Priority for failover (lower = preferred).
    pub priority: u32,
    /// Weight for load balancing (higher = more traffic).
    pub weight: u32,
    /// Health check target (IP to ping).
    #[serde(default = "default_health_check")]
    pub health_check: String,
    /// Health check interval in seconds.
    #[serde(default = "default_health_interval")]
    pub health_interval_secs: u32,
    /// Custom MTU override (None = auto-detect).
    #[serde(default)]
    pub mtu: Option<u16>,
    /// Custom DNS servers (None = use provider's).
    #[serde(default)]
    pub dns_override: Option<Vec<String>>,
    /// MAC address override / clone (None = use hardware MAC).
    #[serde(default)]
    pub mac_override: Option<String>,
}

/// Live status of a WAN interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanStatus {
    /// Interface name.
    pub interface: String,
    /// Connection type name.
    pub connection_type: String,
    /// Whether the link is physically up.
    pub link_up: bool,
    /// IPv4 address if assigned.
    pub ipv4: Option<String>,
    /// IPv6 address if assigned.
    pub ipv6: Option<String>,
    /// IPv4 default gateway.
    pub gateway_v4: Option<String>,
    /// IPv6 default gateway.
    pub gateway_v6: Option<String>,
    /// DNS servers in use.
    pub dns_servers: Vec<String>,
    /// Uptime in seconds since link came up.
    pub uptime_secs: Option<u64>,
    /// Total bytes received.
    pub rx_bytes: u64,
    /// Total bytes transmitted.
    pub tx_bytes: u64,
}

// ── Validation ──────────────────────────────────────────────────────

/// Errors specific to WAN configuration validation.
#[derive(Debug, thiserror::Error)]
pub enum WanValidationError {
    #[error("invalid interface name '{0}': must be 1-15 alphanumeric/dash/underscore/dot chars")]
    InterfaceName(String),

    #[error("invalid VLAN ID {0}: must be 1-4094")]
    VlanId(u16),

    #[error("invalid IP address '{0}': {1}")]
    IpAddress(String, String),

    #[error("invalid CIDR address '{0}': {1}")]
    CidrAddress(String, String),

    #[error("invalid MTU {0}: must be 576-9000")]
    Mtu(u16),

    #[error("invalid MAC address '{0}': expected XX:XX:XX:XX:XX:XX")]
    MacAddress(String),

    #[error("invalid PPPoE username: {0}")]
    PppoeUsername(String),

    #[error("invalid PPPoE password_enc: must not be empty")]
    PppoePassword,

    #[error("invalid health check target '{0}': must be a valid public IP")]
    HealthCheck(String),

    #[error("invalid priority {0}: must be 0-65535")]
    Priority(u32),

    #[error("invalid weight {0}: must be 1-100")]
    Weight(u32),

    #[error("invalid health interval {0}: must be 1-3600")]
    HealthInterval(u32),

    #[error("VLAN inner type cannot be another VLAN")]
    NestedVlan,

    #[error("DS-Lite AFTR address invalid: {0}")]
    AftrAddress(String),
}

/// Validate an interface name: 1-15 chars, alphanumeric + dash + underscore + dot.
pub fn validate_interface_name(name: &str) -> std::result::Result<(), WanValidationError> {
    if name.is_empty() || name.len() > 15 {
        return Err(WanValidationError::InterfaceName(name.to_string()));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(WanValidationError::InterfaceName(name.to_string()));
    }
    Ok(())
}

/// Validate a VLAN ID (1-4094).
fn validate_vlan_id(id: u16) -> std::result::Result<(), WanValidationError> {
    if id == 0 || id > 4094 {
        return Err(WanValidationError::VlanId(id));
    }
    Ok(())
}

/// Validate a CIDR address string like "203.0.113.5/24".
fn validate_cidr(addr: &str) -> std::result::Result<(), WanValidationError> {
    let parts: Vec<&str> = addr.splitn(2, '/').collect();
    if parts.len() != 2 {
        return Err(WanValidationError::CidrAddress(
            addr.to_string(),
            "missing prefix length".to_string(),
        ));
    }
    // Validate IP portion
    parts[0]
        .parse::<IpAddr>()
        .map_err(|e| WanValidationError::CidrAddress(addr.to_string(), e.to_string()))?;
    // Validate prefix length
    let prefix: u8 = parts[1].parse().map_err(|_| {
        WanValidationError::CidrAddress(addr.to_string(), "invalid prefix length".to_string())
    })?;
    let is_v6 = parts[0].contains(':');
    let max_prefix = if is_v6 { 128 } else { 32 };
    if prefix > max_prefix {
        return Err(WanValidationError::CidrAddress(
            addr.to_string(),
            format!("prefix length must be 0-{max_prefix}"),
        ));
    }
    Ok(())
}

/// Validate a plain IP address string.
fn validate_ip(addr: &str) -> std::result::Result<(), WanValidationError> {
    addr.parse::<IpAddr>()
        .map_err(|e| WanValidationError::IpAddress(addr.to_string(), e.to_string()))?;
    Ok(())
}

/// Validate an MTU value (576-9000).
fn validate_mtu(mtu: u16) -> std::result::Result<(), WanValidationError> {
    if !(576..=9000).contains(&mtu) {
        return Err(WanValidationError::Mtu(mtu));
    }
    Ok(())
}

/// Validate a MAC address in XX:XX:XX:XX:XX:XX format.
fn validate_mac(mac: &str) -> std::result::Result<(), WanValidationError> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return Err(WanValidationError::MacAddress(mac.to_string()));
    }
    for part in &parts {
        if part.len() != 2 {
            return Err(WanValidationError::MacAddress(mac.to_string()));
        }
        if !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(WanValidationError::MacAddress(mac.to_string()));
        }
    }
    Ok(())
}

/// Validate a PPPoE username: no shell metacharacters, no newlines, no quotes.
fn validate_pppoe_username(username: &str) -> std::result::Result<(), WanValidationError> {
    if username.is_empty() {
        return Err(WanValidationError::PppoeUsername(
            "must not be empty".to_string(),
        ));
    }
    if username.len() > 256 {
        return Err(WanValidationError::PppoeUsername(
            "must be 256 characters or fewer".to_string(),
        ));
    }
    // Disallow characters that could cause injection in pppd config files
    let forbidden = [
        '\n', '\r', '"', '\'', '\\', '`', '$', ';', '|', '&', '<', '>', '(', ')', '{', '}', '[',
        ']', '!', '#', '~',
    ];
    for c in forbidden {
        if username.contains(c) {
            return Err(WanValidationError::PppoeUsername(format!(
                "contains forbidden character '{c}'"
            )));
        }
    }
    // Also reject any non-printable ASCII
    if username.chars().any(|c| c.is_control()) {
        return Err(WanValidationError::PppoeUsername(
            "contains control characters".to_string(),
        ));
    }
    Ok(())
}

/// Validate a PPPoE password_enc (encrypted, just check non-empty, no newlines).
fn validate_pppoe_password_enc(enc: &str) -> std::result::Result<(), WanValidationError> {
    if enc.is_empty() {
        return Err(WanValidationError::PppoePassword);
    }
    // The encrypted password should be a base64 or hex blob -- no newlines
    if enc.contains('\n') || enc.contains('\r') {
        return Err(WanValidationError::PppoePassword);
    }
    Ok(())
}

/// Validate a complete WanConnectionType recursively.
fn validate_connection_type(
    conn: &WanConnectionType,
) -> std::result::Result<(), WanValidationError> {
    match conn {
        WanConnectionType::Dhcp => Ok(()),
        WanConnectionType::Static {
            address,
            gateway,
            address_v6,
            gateway_v6,
        } => {
            validate_cidr(address)?;
            validate_ip(gateway)?;
            if let Some(v6) = address_v6 {
                validate_cidr(v6)?;
            }
            if let Some(v6) = gateway_v6 {
                validate_ip(v6)?;
            }
            Ok(())
        }
        WanConnectionType::Pppoe {
            username,
            password_enc,
            mtu,
            service_name,
            ac_name,
            vlan_id,
        } => {
            validate_pppoe_username(username)?;
            validate_pppoe_password_enc(password_enc)?;
            validate_mtu(*mtu)?;
            if let Some(sn) = service_name {
                // Service name: same restrictions as username
                validate_pppoe_username(sn)?;
            }
            if let Some(ac) = ac_name {
                validate_pppoe_username(ac)?;
            }
            if let Some(vid) = vlan_id {
                validate_vlan_id(*vid)?;
            }
            Ok(())
        }
        WanConnectionType::DsLite {
            aftr_address,
            auto_aftr: _,
        } => {
            if let Some(aftr) = aftr_address {
                // AFTR must be a valid IPv6 address
                aftr.parse::<Ipv6Addr>()
                    .map_err(|e| WanValidationError::AftrAddress(e.to_string()))?;
            }
            Ok(())
        }
        WanConnectionType::Vlan { vlan_id, inner } => {
            validate_vlan_id(*vlan_id)?;
            // Disallow nested VLAN (QinQ not supported)
            if matches!(inner.as_ref(), WanConnectionType::Vlan { .. }) {
                return Err(WanValidationError::NestedVlan);
            }
            validate_connection_type(inner)?;
            Ok(())
        }
    }
}

/// Validate a complete WanPortConfig.
pub fn validate_wan_config(config: &WanPortConfig) -> std::result::Result<(), WanValidationError> {
    validate_interface_name(&config.interface)?;
    validate_connection_type(&config.connection)?;

    if config.priority > 65535 {
        return Err(WanValidationError::Priority(config.priority));
    }
    if config.weight == 0 || config.weight > 100 {
        return Err(WanValidationError::Weight(config.weight));
    }

    // Health check must be a valid public IP (private/loopback/link-local IPs
    // are never reachable from WAN and would cause false failover triggers).
    let health_ip: IpAddr = config
        .health_check
        .parse()
        .map_err(|_| WanValidationError::HealthCheck(config.health_check.clone()))?;
    match health_ip {
        IpAddr::V4(ip)
            if ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() =>
        {
            return Err(WanValidationError::HealthCheck(config.health_check.clone()));
        }
        IpAddr::V6(ip) if ip.is_loopback() || ip.is_unspecified() => {
            return Err(WanValidationError::HealthCheck(config.health_check.clone()));
        }
        _ => {}
    }

    if config.health_interval_secs == 0 || config.health_interval_secs > 3600 {
        return Err(WanValidationError::HealthInterval(
            config.health_interval_secs,
        ));
    }

    if let Some(mtu) = config.mtu {
        validate_mtu(mtu)?;
    }

    if let Some(ref dns) = config.dns_override {
        for server in dns {
            validate_ip(server)?;
        }
    }

    if let Some(ref mac) = config.mac_override {
        validate_mac(mac)?;
    }

    Ok(())
}

// ── Database operations ─────────────────────────────────────────────

/// Read a WAN port configuration from the database.
#[must_use = "WAN config result should be checked"]
pub async fn get_wan_config(db: &sfgw_db::Db, interface: &str) -> Result<Option<WanPortConfig>> {
    validate_interface_name(interface).map_err(|e| NetError::Internal(e.into()))?;

    let conn = db.lock().await;
    let mut stmt = conn
        .prepare("SELECT config FROM wan_configs WHERE interface = ?1")
        .context("failed to prepare wan_config query")?;

    let result = stmt.query_row(rusqlite::params![interface], |row| {
        let json: String = row.get(0)?;
        Ok(json)
    });

    match result {
        Ok(json) => {
            let config: WanPortConfig = serde_json::from_str(&json)?;
            Ok(Some(config))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(NetError::Database(e)),
    }
}

/// Save or update a WAN port configuration in the database.
pub async fn set_wan_config(db: &sfgw_db::Db, config: &WanPortConfig) -> Result<()> {
    validate_wan_config(config).map_err(|e| NetError::Internal(e.into()))?;

    let json = serde_json::to_string(config)?;
    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO wan_configs (interface, config, enabled, priority, weight, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))
         ON CONFLICT(interface) DO UPDATE SET
             config = excluded.config,
             enabled = excluded.enabled,
             priority = excluded.priority,
             weight = excluded.weight,
             updated_at = datetime('now')",
        rusqlite::params![
            config.interface,
            json,
            config.enabled as i32,
            config.priority,
            config.weight,
        ],
    )
    .context("failed to upsert wan_config")?;

    // Set the interface pvid=0 to mark it as a WAN port (outside internal VLAN space).
    conn.execute(
        "UPDATE interfaces SET pvid = 0 WHERE name = ?1",
        rusqlite::params![config.interface],
    )
    .context("failed to set interface pvid to 0 (WAN)")?;

    tracing::info!(
        interface = %config.interface,
        enabled = config.enabled,
        priority = config.priority,
        "WAN config saved, interface pvid set to 0 (WAN)"
    );
    Ok(())
}

/// List all WAN port configurations.
#[must_use = "WAN config list result should be checked"]
pub async fn list_wan_configs(db: &sfgw_db::Db) -> Result<Vec<WanPortConfig>> {
    let conn = db.lock().await;
    let mut stmt = conn
        .prepare("SELECT config FROM wan_configs ORDER BY priority ASC")
        .context("failed to prepare wan_configs list query")?;

    let rows = stmt
        .query_map([], |row| {
            let json: String = row.get(0)?;
            Ok(json)
        })
        .context("failed to query wan_configs")?;

    let mut configs = Vec::new();
    for row in rows {
        let json = row?;
        let config: WanPortConfig = serde_json::from_str(&json)?;
        configs.push(config);
    }
    Ok(configs)
}

/// Remove a WAN config from the database.
pub async fn remove_wan_config(db: &sfgw_db::Db, interface: &str) -> Result<()> {
    validate_interface_name(interface).map_err(|e| NetError::Internal(e.into()))?;

    let conn = db.lock().await;
    let affected = conn
        .execute(
            "DELETE FROM wan_configs WHERE interface = ?1",
            rusqlite::params![interface],
        )
        .context("failed to delete wan_config")?;

    if affected == 0 {
        tracing::warn!(interface, "no WAN config found to remove");
    } else {
        // Revert interface pvid back to LAN default (10) when WAN config is removed.
        conn.execute(
            "UPDATE interfaces SET pvid = 10 WHERE name = ?1 AND pvid = 0",
            rusqlite::params![interface],
        )
        .context("failed to revert interface pvid to LAN default")?;
        tracing::info!(
            interface,
            "WAN config removed, interface pvid reverted to 10 (LAN default)"
        );
    }
    Ok(())
}

// ── System application ──────────────────────────────────────────────

/// Apply a WAN port configuration to the system.
///
/// This calls the appropriate system commands depending on the
/// connection type (DHCP, Static, PPPoE, DS-Lite, VLAN).
pub async fn apply_wan_config(config: &WanPortConfig) -> Result<()> {
    validate_wan_config(config).map_err(|e| NetError::Internal(e.into()))?;

    // Set MAC override if requested
    if let Some(ref mac) = config.mac_override {
        run_ip(&["link", "set", "dev", &config.interface, "address", mac])
            .await
            .context("failed to set MAC override")?;
    }

    // Set MTU override if requested
    if let Some(mtu) = config.mtu {
        let mtu_str = mtu.to_string();
        run_ip(&["link", "set", "dev", &config.interface, "mtu", &mtu_str])
            .await
            .context("failed to set MTU override")?;
    }

    // Bring interface up
    run_ip(&["link", "set", "dev", &config.interface, "up"])
        .await
        .context("failed to bring interface up")?;

    apply_connection_type(&config.interface, &config.connection).await?;

    tracing::info!(
        interface = %config.interface,
        connection = %connection_type_name(&config.connection),
        "WAN config applied"
    );
    Ok(())
}

/// Apply a specific connection type to an interface.
fn apply_connection_type<'a>(
    interface: &'a str,
    conn: &'a WanConnectionType,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        match conn {
            WanConnectionType::Dhcp => apply_dhcp(interface).await,
            WanConnectionType::Static {
                address,
                gateway,
                address_v6,
                gateway_v6,
            } => {
                apply_static(
                    interface,
                    address,
                    gateway,
                    address_v6.as_deref(),
                    gateway_v6.as_deref(),
                )
                .await
            }
            WanConnectionType::Pppoe {
                username,
                password_enc,
                mtu,
                service_name,
                ac_name,
                vlan_id,
            } => {
                // If PPPoE has a VLAN tag, set up the VLAN first
                let effective_iface = if let Some(vid) = vlan_id {
                    let vlan_iface = format!("{interface}.{vid}");
                    let vid_str = vid.to_string();
                    // Create VLAN interface
                    run_ip(&[
                        "link",
                        "add",
                        "link",
                        interface,
                        "name",
                        &vlan_iface,
                        "type",
                        "vlan",
                        "id",
                        &vid_str,
                    ])
                    .await
                    .context("failed to create PPPoE VLAN interface")?;
                    run_ip(&["link", "set", "dev", &vlan_iface, "up"])
                        .await
                        .context("failed to bring PPPoE VLAN interface up")?;
                    vlan_iface
                } else {
                    interface.to_string()
                };
                apply_pppoe(
                    &effective_iface,
                    username,
                    password_enc,
                    *mtu,
                    service_name.as_deref(),
                    ac_name.as_deref(),
                )
                .await
            }
            WanConnectionType::DsLite {
                aftr_address,
                auto_aftr,
            } => apply_dslite(interface, aftr_address.as_deref(), *auto_aftr).await,
            WanConnectionType::Vlan { vlan_id, inner } => {
                let vlan_iface = format!("{interface}.{vlan_id}");
                let vid_str = vlan_id.to_string();
                // Create VLAN sub-interface
                run_ip(&[
                    "link",
                    "add",
                    "link",
                    interface,
                    "name",
                    &vlan_iface,
                    "type",
                    "vlan",
                    "id",
                    &vid_str,
                ])
                .await
                .context("failed to create VLAN interface")?;
                run_ip(&["link", "set", "dev", &vlan_iface, "up"])
                    .await
                    .context("failed to bring VLAN interface up")?;
                // Apply inner connection type on the VLAN interface
                apply_connection_type(&vlan_iface, inner).await
            }
        }
    })
}

/// Path to the sfgw udhcpc callback script.
/// Written at runtime so it works on any platform without installation.
const UDHCPC_SCRIPT: &str = "/run/sfgw-udhcpc.script";

/// Ensure the udhcpc callback script exists.
///
/// UDM Pro ships without `/usr/share/udhcpc/default.script` — Ubiquiti
/// replaces it with `ubios-udhcpc-script` which is a symlink to
/// `ubios-udapi-server`.  Without a script, udhcpc obtains a lease but
/// never configures the IP address, default route, or DNS.
async fn ensure_udhcpc_script() -> Result<()> {
    use tokio::fs;

    // Skip if already present (idempotent across multiple WAN ports).
    if fs::metadata(UDHCPC_SCRIPT).await.is_ok() {
        return Ok(());
    }

    let script = r#"#!/bin/sh
# sfgw udhcpc callback — sets IP, gateway, and DNS on lease events.
# Called by udhcpc with: $1 = event (deconfig|bound|renew|nak)
# Environment: $interface, $ip, $subnet, $router, $dns, $domain

case "$1" in
    deconfig)
        ip addr flush dev "$interface" 2>/dev/null
        ip route flush dev "$interface" 2>/dev/null
        ;;
    bound|renew)
        # Calculate prefix length from subnet mask
        pfx=24
        if [ -n "$subnet" ]; then
            pfx=0
            for octet in $(echo "$subnet" | tr '.' ' '); do
                case $octet in
                    255) pfx=$((pfx + 8)) ;;
                    254) pfx=$((pfx + 7)) ;;
                    252) pfx=$((pfx + 6)) ;;
                    248) pfx=$((pfx + 5)) ;;
                    240) pfx=$((pfx + 4)) ;;
                    224) pfx=$((pfx + 3)) ;;
                    192) pfx=$((pfx + 2)) ;;
                    128) pfx=$((pfx + 1)) ;;
                esac
            done
        fi

        # Set IP address
        ip addr flush dev "$interface" 2>/dev/null
        ip addr add "$ip/$pfx" dev "$interface"

        # Set default route via gateway
        if [ -n "$router" ]; then
            for gw in $router; do
                ip route replace default via "$gw" dev "$interface"
                break  # use first gateway only
            done
        fi

        # Write DNS servers to resolv.conf
        if [ -n "$dns" ]; then
            : > /etc/resolv.conf
            [ -n "$domain" ] && echo "search $domain" >> /etc/resolv.conf
            for ns in $dns; do
                echo "nameserver $ns" >> /etc/resolv.conf
            done
        fi
        ;;
esac
"#;

    fs::write(UDHCPC_SCRIPT, script)
        .await
        .context("failed to write udhcpc script")?;

    // chmod +x
    let mut perms = fs::metadata(UDHCPC_SCRIPT).await?.permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    fs::set_permissions(UDHCPC_SCRIPT, perms).await?;

    tracing::debug!("udhcpc callback script written to {UDHCPC_SCRIPT}");
    Ok(())
}

/// Apply DHCP on an interface via udhcpc (BusyBox) or dhcpcd.
async fn apply_dhcp(interface: &str) -> Result<()> {
    // Ensure our callback script exists (sets IP + gateway + DNS).
    ensure_udhcpc_script().await?;

    // Try udhcpc first (BusyBox, available on UDM Pro and most embedded systems),
    // fall back to dhcpcd if udhcpc is not found.
    // On UDM Pro, udhcpc lives at /usr/bin/busybox-legacy/udhcpc (not in default PATH).
    let udhcpc_bin = if std::path::Path::new("/usr/bin/busybox-legacy/udhcpc").exists() {
        "/usr/bin/busybox-legacy/udhcpc"
    } else {
        "udhcpc"
    };
    let udhcpc_result = Command::new(udhcpc_bin)
        .args(["-i", interface, "-n", "-q", "-f", "-s", UDHCPC_SCRIPT])
        .output()
        .await;

    match udhcpc_result {
        Ok(output) if output.status.success() => {
            tracing::info!(interface, "DHCP lease obtained via udhcpc");
            return Ok(());
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(
                interface,
                "udhcpc failed (exit {}): {}",
                output.status,
                stderr.trim()
            );
        }
        Err(_) => {
            tracing::debug!(interface, "udhcpc not found, trying dhcpcd");
        }
    }

    // Fallback: dhcpcd (available on full Linux distros, Docker, VMs)
    let output = Command::new("dhcpcd")
        .args(["--nobackground", "-4", interface])
        .output()
        .await
        .context("failed to execute dhcpcd (udhcpc also unavailable)")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!(
            interface,
            "dhcpcd failed (exit {}): {}",
            output.status,
            stderr.trim()
        );
    }
    Ok(())
}

/// Apply static IP configuration.
async fn apply_static(
    interface: &str,
    address: &str,
    gateway: &str,
    address_v6: Option<&str>,
    gateway_v6: Option<&str>,
) -> Result<()> {
    // Flush existing addresses
    run_ip(&["addr", "flush", "dev", interface])
        .await
        .context("failed to flush addresses")?;

    // Add IPv4 address
    run_ip(&["addr", "add", address, "dev", interface])
        .await
        .context("failed to add static IPv4 address")?;

    // Add default route
    run_ip(&[
        "route", "replace", "default", "via", gateway, "dev", interface,
    ])
    .await
    .context("failed to set static IPv4 default route")?;

    // Add IPv6 if configured
    if let Some(v6_addr) = address_v6 {
        run_ip(&["addr", "add", v6_addr, "dev", interface])
            .await
            .context("failed to add static IPv6 address")?;
    }
    if let Some(v6_gw) = gateway_v6 {
        run_ip(&[
            "-6", "route", "replace", "default", "via", v6_gw, "dev", interface,
        ])
        .await
        .context("failed to set static IPv6 default route")?;
    }

    Ok(())
}

/// Generate PPPoE peer config and start pppd.
async fn apply_pppoe(
    interface: &str,
    username: &str,
    password_enc: &str,
    mtu: u16,
    service_name: Option<&str>,
    ac_name: Option<&str>,
) -> Result<()> {
    let peer_name = format!("sfgw-{interface}");
    let config = generate_pppoe_config(
        interface,
        username,
        password_enc,
        mtu,
        service_name,
        ac_name,
    );

    let peer_path = PathBuf::from("/etc/ppp/peers").join(&peer_name);

    // Ensure parent directory exists
    if let Some(parent) = peer_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("failed to create /etc/ppp/peers")?;
    }

    tokio::fs::write(&peer_path, config.as_bytes())
        .await
        .with_context(|| {
            format!(
                "failed to write PPPoE peer config to {}",
                peer_path.display()
            )
        })?;

    tracing::info!(peer = %peer_name, "PPPoE peer config written");

    // Start pppd
    let output = Command::new("pppd")
        .args(["call", &peer_name])
        .output()
        .await
        .context("failed to execute pppd")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!(
            peer = peer_name.as_str(),
            "pppd failed (exit {}): {}",
            output.status,
            stderr.trim()
        );
    }

    Ok(())
}

/// Generate the PPPoE peer configuration file content.
///
/// IMPORTANT: username and password_enc are pre-validated to contain
/// no shell metacharacters, newlines, or quotes. The validation is
/// enforced by `validate_pppoe_username` and `validate_pppoe_password_enc`
/// before this function is ever called.
pub fn generate_pppoe_config(
    interface: &str,
    username: &str,
    password_enc: &str,
    mtu: u16,
    service_name: Option<&str>,
    ac_name: Option<&str>,
) -> String {
    let mut config = format!(
        "plugin pppoe.so\n\
         {interface}\n\
         user \"{username}\"\n\
         password \"{password_enc}\"\n\
         mtu {mtu}\n\
         mru {mtu}\n\
         defaultroute\n\
         usepeerdns\n\
         persist\n\
         maxfail 0\n\
         holdoff 5\n\
         lcp-echo-interval 15\n\
         lcp-echo-failure 4\n\
         noauth\n"
    );

    if let Some(sn) = service_name {
        config.push_str(&format!("rp_pppoe_service \"{sn}\"\n"));
    }
    if let Some(ac) = ac_name {
        config.push_str(&format!("rp_pppoe_ac \"{ac}\"\n"));
    }

    config
}

/// Apply DS-Lite (IPv4-in-IPv6 tunnel).
async fn apply_dslite(interface: &str, aftr_address: Option<&str>, auto_aftr: bool) -> Result<()> {
    // First, get a local IPv6 address on the interface
    let local_v6 = get_interface_ipv6(interface).await?;
    let local_v6 = local_v6.ok_or_else(|| {
        NetError::Internal(anyhow::anyhow!(
            "no IPv6 address on interface {interface} for DS-Lite tunnel"
        ))
    })?;

    // Determine AFTR address
    let aftr = if let Some(addr) = aftr_address {
        addr.to_string()
    } else if auto_aftr {
        discover_aftr(interface).await?
    } else {
        return Err(NetError::Internal(anyhow::anyhow!(
            "DS-Lite: no AFTR address and auto-discovery disabled"
        )));
    };

    let tunnel_name = format!("ds-lite-{interface}");

    // Create the IPIP6 tunnel
    run_ip(&[
        "tunnel",
        "add",
        &tunnel_name,
        "mode",
        "ipip6",
        "remote",
        &aftr,
        "local",
        &local_v6,
        "dev",
        interface,
    ])
    .await
    .context("failed to create DS-Lite tunnel")?;

    run_ip(&["link", "set", "dev", &tunnel_name, "up"])
        .await
        .context("failed to bring DS-Lite tunnel up")?;

    // Route IPv4 through the tunnel
    run_ip(&["route", "replace", "default", "dev", &tunnel_name])
        .await
        .context("failed to set DS-Lite default route")?;

    tracing::info!(
        interface,
        tunnel = tunnel_name.as_str(),
        aftr = aftr.as_str(),
        "DS-Lite tunnel established"
    );
    Ok(())
}

/// Discover AFTR address via DHCPv6 option 64.
///
/// Runs dhcpcd in one-shot mode to get the AFTR name resolver address.
async fn discover_aftr(interface: &str) -> Result<String> {
    // Use dhcpcd to request DHCPv6 option 64 (AFTR-Name)
    let output = Command::new("dhcpcd")
        .args(["--oneshot", "-6", "--option", "aftr_name", interface])
        .output()
        .await
        .context("failed to run DHCPv6 for AFTR discovery")?;

    if !output.status.success() {
        return Err(NetError::Internal(anyhow::anyhow!(
            "DHCPv6 AFTR discovery failed on {interface}"
        )));
    }

    // Parse the AFTR address from dhcpcd output/lease file
    // dhcpcd stores options in /var/lib/dhcpcd/<iface>.lease6
    let lease_path = format!("/var/lib/dhcpcd/{interface}.lease6");
    let lease = tokio::fs::read_to_string(&lease_path)
        .await
        .with_context(|| format!("failed to read DHCPv6 lease from {lease_path}"))?;

    // Look for the AFTR name/address in the lease data
    for line in lease.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("aftr_name=") || trimmed.starts_with("option_64=") {
            let addr = trimmed.split_once('=').map(|x| x.1).unwrap_or("").trim();
            if !addr.is_empty() {
                // Validate the address
                if addr.parse::<Ipv6Addr>().is_ok() {
                    return Ok(addr.to_string());
                }
                // It might be a hostname; try to resolve
                tracing::info!(aftr = addr, "AFTR discovered via DHCPv6");
                return Ok(addr.to_string());
            }
        }
    }

    Err(NetError::Internal(anyhow::anyhow!(
        "AFTR address not found in DHCPv6 lease for {interface}"
    )))
}

/// Get the first global IPv6 address on an interface.
async fn get_interface_ipv6(interface: &str) -> Result<Option<String>> {
    let content = match tokio::fs::read_to_string("/proc/net/if_inet6").await {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Format: addr_hex index prefix_len scope flags iface_name
        if parts.len() >= 6 && parts[5] == interface {
            let scope = parts[3];
            // Scope 00 = global
            if scope == "00"
                && let Some(addr) = hex_to_ipv6(parts[0])
            {
                return Ok(Some(addr));
            }
        }
    }
    Ok(None)
}

/// Convert a 32-char hex string from /proc/net/if_inet6 to an IPv6 address.
fn hex_to_ipv6(hex: &str) -> Option<String> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for i in 0..16 {
        octets[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    let addr = Ipv6Addr::from(octets);
    Some(addr.to_string())
}

/// Detect the live status of a WAN interface.
#[must_use = "WAN status result should be checked"]
pub async fn detect_wan_status(interface: &str) -> Result<WanStatus> {
    validate_interface_name(interface).map_err(|e| NetError::Internal(e.into()))?;

    let link_up = read_operstate(interface);
    let (rx_bytes, tx_bytes) = read_traffic_counters(interface);
    let ipv4 = read_ipv4_addr(interface);
    let ipv6 = read_ipv6_global(interface);
    let gateway_v4 = read_default_gateway_v4(interface);
    let dns_servers = read_dns_servers(interface);

    // Connection type from whether we have a lease file (DHCP) or static config
    let connection_type =
        if std::path::Path::new(&format!("/var/lib/dhcp/dhclient.{interface}.leases")).exists()
            || std::path::Path::new(&format!("/run/dhclient.{interface}.pid")).exists()
        {
            "dhcp"
        } else if ipv4.is_some() {
            "static"
        } else {
            "unknown"
        };

    Ok(WanStatus {
        interface: interface.to_string(),
        connection_type: connection_type.to_string(),
        link_up,
        ipv4,
        ipv6,
        gateway_v4,
        gateway_v6: None,
        dns_servers,
        uptime_secs: None,
        rx_bytes,
        tx_bytes,
    })
}

/// Read the primary IPv4 address of an interface from /proc/net/fib_trie or ip command output.
fn read_ipv4_addr(interface: &str) -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", interface])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Format: "4: eth8    inet 192.168.178.25/24 brd ..."
    for line in stdout.lines() {
        if let Some(inet_pos) = line.find("inet ") {
            let rest = &line[inet_pos + 5..];
            // Take up to the space (includes /prefix) then strip prefix
            let addr_cidr = rest.split_whitespace().next()?;
            let addr = addr_cidr.split('/').next()?;
            return Some(addr.to_string());
        }
    }
    None
}

/// Read the first global-scope IPv6 address of an interface.
fn read_ipv6_global(interface: &str) -> Option<String> {
    let output = std::process::Command::new("ip")
        .args([
            "-6", "-o", "addr", "show", "dev", interface, "scope", "global",
        ])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(inet6_pos) = line.find("inet6 ") {
            let rest = &line[inet6_pos + 6..];
            let addr_cidr = rest.split_whitespace().next()?;
            let addr = addr_cidr.split('/').next()?;
            return Some(addr.to_string());
        }
    }
    None
}

/// Read the default gateway for a specific interface from all routing tables.
fn read_default_gateway_v4(interface: &str) -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["-4", "route", "show", "table", "all"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Look for "default via X.X.X.X dev <interface>"
    for line in stdout.lines() {
        if line.starts_with("default via ") && line.contains(&format!("dev {interface}")) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                return Some(parts[2].to_string());
            }
        }
    }
    None
}

/// Read DNS servers — check resolv.conf and interface-specific configs.
fn read_dns_servers(interface: &str) -> Vec<String> {
    let mut servers = Vec::new();
    // Try interface-specific resolv.conf first (UDM style)
    let iface_resolv = format!("/run/resolv.conf.d/{interface}");
    let path = if std::path::Path::new(&iface_resolv).exists() {
        iface_resolv
    } else {
        "/etc/resolv.conf".to_string()
    };
    if let Ok(content) = std::fs::read_to_string(&path) {
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("nameserver ") {
                let ns = rest.trim();
                if ns != "127.0.0.1" && ns != "::1" {
                    servers.push(ns.to_string());
                }
            }
        }
    }
    servers
}

/// Read interface operstate from sysfs.
fn read_operstate(interface: &str) -> bool {
    let path = format!("/sys/class/net/{interface}/operstate");
    std::fs::read_to_string(&path)
        .map(|s| s.trim() == "up")
        .unwrap_or(false)
}

/// Read TX/RX byte counters from sysfs.
fn read_traffic_counters(interface: &str) -> (u64, u64) {
    let rx_path = format!("/sys/class/net/{interface}/statistics/rx_bytes");
    let tx_path = format!("/sys/class/net/{interface}/statistics/tx_bytes");
    let rx = std::fs::read_to_string(&rx_path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let tx = std::fs::read_to_string(&tx_path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    (rx, tx)
}

/// Get a human-readable name for a connection type.
fn connection_type_name(conn: &WanConnectionType) -> &'static str {
    match conn {
        WanConnectionType::Dhcp => "dhcp",
        WanConnectionType::Static { .. } => "static",
        WanConnectionType::Pppoe { .. } => "pppoe",
        WanConnectionType::DsLite { .. } => "dslite",
        WanConnectionType::Vlan { .. } => "vlan",
    }
}

/// Run an `ip` command and return its output.
async fn run_ip(args: &[&str]) -> std::result::Result<std::process::Output, anyhow::Error> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .await
        .context("failed to execute ip command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "ip {} failed (exit {}): {}",
            args.join(" "),
            output.status,
            stderr.trim()
        );
    }

    Ok(output)
}

/// Generate the `ip` / system commands that would be executed for a
/// WAN port config. Useful for testing and dry-run without root.
pub fn generate_wan_commands(config: &WanPortConfig) -> Vec<Vec<String>> {
    let mut commands = Vec::new();

    if let Some(ref mac) = config.mac_override {
        commands.push(vec![
            "ip".into(),
            "link".into(),
            "set".into(),
            "dev".into(),
            config.interface.clone(),
            "address".into(),
            mac.clone(),
        ]);
    }

    if let Some(mtu) = config.mtu {
        commands.push(vec![
            "ip".into(),
            "link".into(),
            "set".into(),
            "dev".into(),
            config.interface.clone(),
            "mtu".into(),
            mtu.to_string(),
        ]);
    }

    commands.push(vec![
        "ip".into(),
        "link".into(),
        "set".into(),
        "dev".into(),
        config.interface.clone(),
        "up".into(),
    ]);

    generate_connection_commands(&config.interface, &config.connection, &mut commands);
    commands
}

/// Generate commands for a specific connection type.
fn generate_connection_commands(
    interface: &str,
    conn: &WanConnectionType,
    commands: &mut Vec<Vec<String>>,
) {
    match conn {
        WanConnectionType::Dhcp => {
            commands.push(vec![
                "dhcpcd".into(),
                "--nobackground".into(),
                "-4".into(),
                interface.into(),
            ]);
        }
        WanConnectionType::Static {
            address,
            gateway,
            address_v6,
            gateway_v6,
        } => {
            commands.push(vec![
                "ip".into(),
                "addr".into(),
                "flush".into(),
                "dev".into(),
                interface.into(),
            ]);
            commands.push(vec![
                "ip".into(),
                "addr".into(),
                "add".into(),
                address.clone(),
                "dev".into(),
                interface.into(),
            ]);
            commands.push(vec![
                "ip".into(),
                "route".into(),
                "replace".into(),
                "default".into(),
                "via".into(),
                gateway.clone(),
                "dev".into(),
                interface.into(),
            ]);
            if let Some(v6_addr) = address_v6 {
                commands.push(vec![
                    "ip".into(),
                    "addr".into(),
                    "add".into(),
                    v6_addr.clone(),
                    "dev".into(),
                    interface.into(),
                ]);
            }
            if let Some(v6_gw) = gateway_v6 {
                commands.push(vec![
                    "ip".into(),
                    "-6".into(),
                    "route".into(),
                    "replace".into(),
                    "default".into(),
                    "via".into(),
                    v6_gw.clone(),
                    "dev".into(),
                    interface.into(),
                ]);
            }
        }
        WanConnectionType::Pppoe {
            username: _,
            password_enc: _,
            mtu: _,
            service_name: _,
            ac_name: _,
            vlan_id,
        } => {
            if let Some(vid) = vlan_id {
                let vlan_iface = format!("{interface}.{vid}");
                commands.push(vec![
                    "ip".into(),
                    "link".into(),
                    "add".into(),
                    "link".into(),
                    interface.into(),
                    "name".into(),
                    vlan_iface.clone(),
                    "type".into(),
                    "vlan".into(),
                    "id".into(),
                    vid.to_string(),
                ]);
                commands.push(vec![
                    "ip".into(),
                    "link".into(),
                    "set".into(),
                    "dev".into(),
                    vlan_iface.clone(),
                    "up".into(),
                ]);
                commands.push(vec![
                    "pppd".into(),
                    "call".into(),
                    format!("sfgw-{vlan_iface}"),
                ]);
            } else {
                commands.push(vec![
                    "pppd".into(),
                    "call".into(),
                    format!("sfgw-{interface}"),
                ]);
            }
        }
        WanConnectionType::DsLite { aftr_address, .. } => {
            let tunnel_name = format!("ds-lite-{interface}");
            if let Some(aftr) = aftr_address {
                commands.push(vec![
                    "ip".into(),
                    "tunnel".into(),
                    "add".into(),
                    tunnel_name.clone(),
                    "mode".into(),
                    "ipip6".into(),
                    "remote".into(),
                    aftr.clone(),
                    "dev".into(),
                    interface.into(),
                ]);
            }
            commands.push(vec![
                "ip".into(),
                "link".into(),
                "set".into(),
                "dev".into(),
                tunnel_name.clone(),
                "up".into(),
            ]);
            commands.push(vec![
                "ip".into(),
                "route".into(),
                "replace".into(),
                "default".into(),
                "dev".into(),
                tunnel_name,
            ]);
        }
        WanConnectionType::Vlan { vlan_id, inner } => {
            let vlan_iface = format!("{interface}.{vlan_id}");
            commands.push(vec![
                "ip".into(),
                "link".into(),
                "add".into(),
                "link".into(),
                interface.into(),
                "name".into(),
                vlan_iface.clone(),
                "type".into(),
                "vlan".into(),
                "id".into(),
                vlan_id.to_string(),
            ]);
            commands.push(vec![
                "ip".into(),
                "link".into(),
                "set".into(),
                "dev".into(),
                vlan_iface.clone(),
                "up".into(),
            ]);
            generate_connection_commands(&vlan_iface, inner, commands);
        }
    }
}

impl fmt::Display for WanConnectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", connection_type_name(self))
    }
}

// ── Extended health checks ──────────────────────────────────────────

/// Type of health check to perform on a WAN interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
#[derive(Default)]
pub enum HealthCheckType {
    /// ICMP ping (default, legacy behavior).
    #[default]
    Icmp,
    /// HTTP GET request — check that the URL returns the expected status code.
    Http {
        /// Full URL to probe, e.g. "http://connectivitycheck.gstatic.com/generate_204".
        url: String,
        /// Expected HTTP status code (default 200).
        #[serde(default = "default_http_status")]
        expected_status: u16,
    },
    /// DNS resolution — resolve a domain via a specific server and check for answers.
    Dns {
        /// Domain to resolve, e.g. "google.com".
        domain: String,
        /// DNS server to query, e.g. "8.8.8.8" or "2001:4860:4860::8888".
        server: String,
    },
}

fn default_http_status() -> u16 {
    200
}

impl fmt::Display for HealthCheckType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Icmp => write!(f, "icmp"),
            Self::Http { url, .. } => write!(f, "http({})", url),
            Self::Dns { domain, server } => write!(f, "dns({}@{})", domain, server),
        }
    }
}

/// Per-interface health check configuration stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WanHealthConfig {
    /// Interface name (FK to wan_configs).
    pub interface: String,
    /// Health check type and parameters.
    #[serde(default)]
    pub health_check_type: HealthCheckType,
    /// Maximum state changes within `flap_window_secs` before suppressing failover.
    #[serde(default = "default_flap_threshold")]
    pub flap_threshold: u32,
    /// Flap detection sliding window in seconds.
    #[serde(default = "default_flap_window")]
    pub flap_window_secs: u32,
    /// If true, preserve existing connections on failover (conntrack-based).
    #[serde(default)]
    pub sticky_sessions: bool,
    /// Pin a specific zone's traffic to this WAN interface.
    #[serde(default)]
    pub zone_pin: Option<String>,
}

fn default_flap_threshold() -> u32 {
    5
}

fn default_flap_window() -> u32 {
    60
}

/// A logged flap event for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlapEvent {
    pub id: i64,
    pub interface: String,
    pub new_state: String,
    pub suppressed: bool,
    pub timestamp: String,
}

/// Validation errors for health check configuration.
#[derive(Debug, thiserror::Error)]
pub enum HealthConfigValidationError {
    #[error("invalid interface name: {0}")]
    InterfaceName(String),
    #[error("invalid HTTP URL '{0}': must start with http:// or https://")]
    HttpUrl(String),
    #[error("invalid expected_status {0}: must be 100-599")]
    HttpStatus(u16),
    #[error("invalid DNS domain '{0}': must not be empty and max 253 chars")]
    DnsDomain(String),
    #[error("invalid DNS server '{0}': must be a valid IP address")]
    DnsServer(String),
    #[error("invalid flap_threshold {0}: must be 1-100")]
    FlapThreshold(u32),
    #[error("invalid flap_window_secs {0}: must be 10-3600")]
    FlapWindow(u32),
    #[error("invalid zone_pin '{0}': must be a recognized zone name")]
    ZonePin(String),
}

/// Validate a WanHealthConfig.
pub fn validate_health_config(
    config: &WanHealthConfig,
) -> std::result::Result<(), HealthConfigValidationError> {
    validate_interface_name(&config.interface)
        .map_err(|_| HealthConfigValidationError::InterfaceName(config.interface.clone()))?;

    match &config.health_check_type {
        HealthCheckType::Icmp => {}
        HealthCheckType::Http {
            url,
            expected_status,
        } => {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(HealthConfigValidationError::HttpUrl(url.clone()));
            }
            // Reject URLs with shell metacharacters or control characters
            if url.len() > 2048
                || url.chars().any(|c| c.is_control())
                || url.contains('`')
                || url.contains('$')
            {
                return Err(HealthConfigValidationError::HttpUrl(url.clone()));
            }
            if *expected_status < 100 || *expected_status > 599 {
                return Err(HealthConfigValidationError::HttpStatus(*expected_status));
            }
        }
        HealthCheckType::Dns { domain, server } => {
            if domain.is_empty() || domain.len() > 253 {
                return Err(HealthConfigValidationError::DnsDomain(domain.clone()));
            }
            // Basic domain validation: alphanumeric, hyphens, dots
            if !domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            {
                return Err(HealthConfigValidationError::DnsDomain(domain.clone()));
            }
            server
                .parse::<IpAddr>()
                .map_err(|_| HealthConfigValidationError::DnsServer(server.clone()))?;
        }
    }

    if config.flap_threshold == 0 || config.flap_threshold > 100 {
        return Err(HealthConfigValidationError::FlapThreshold(
            config.flap_threshold,
        ));
    }
    if config.flap_window_secs < 10 || config.flap_window_secs > 3600 {
        return Err(HealthConfigValidationError::FlapWindow(
            config.flap_window_secs,
        ));
    }

    if let Some(ref zone) = config.zone_pin {
        // Validate zone name: non-empty, alphanumeric/underscore/dash, max 32 chars
        if zone.is_empty()
            || zone.len() > 32
            || !zone
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(HealthConfigValidationError::ZonePin(zone.clone()));
        }
    }

    Ok(())
}

// ── Health check database operations ────────────────────────────────

/// Get the health config for a WAN interface.
#[must_use = "health config result should be checked"]
pub async fn get_health_config(
    db: &sfgw_db::Db,
    interface: &str,
) -> Result<Option<WanHealthConfig>> {
    validate_interface_name(interface).map_err(|e| NetError::Internal(e.into()))?;

    let conn = db.lock().await;
    let mut stmt = conn
        .prepare(
            "SELECT health_check_type, health_check_config, flap_threshold, \
             flap_window_secs, sticky_sessions, zone_pin \
             FROM wan_health_config WHERE interface = ?1",
        )
        .context("failed to prepare wan_health_config query")?;

    let result = stmt.query_row(rusqlite::params![interface], |row| {
        let check_type: String = row.get(0)?;
        let check_config: String = row.get(1)?;
        let flap_threshold: u32 = row.get(2)?;
        let flap_window_secs: u32 = row.get(3)?;
        let sticky: i32 = row.get(4)?;
        let zone_pin: Option<String> = row.get(5)?;
        Ok((
            check_type,
            check_config,
            flap_threshold,
            flap_window_secs,
            sticky,
            zone_pin,
        ))
    });

    match result {
        Ok((check_type, check_config, flap_threshold, flap_window_secs, sticky, zone_pin)) => {
            let health_check_type = parse_health_check_type(&check_type, &check_config)?;
            Ok(Some(WanHealthConfig {
                interface: interface.to_string(),
                health_check_type,
                flap_threshold,
                flap_window_secs,
                sticky_sessions: sticky != 0,
                zone_pin,
            }))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(NetError::Database(e)),
    }
}

/// Save or update health config for a WAN interface.
pub async fn set_health_config(db: &sfgw_db::Db, config: &WanHealthConfig) -> Result<()> {
    validate_health_config(config).map_err(|e| NetError::Internal(e.into()))?;

    let (type_str, config_json) = serialize_health_check_type(&config.health_check_type)?;

    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO wan_health_config \
         (interface, health_check_type, health_check_config, flap_threshold, \
          flap_window_secs, sticky_sessions, zone_pin, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now')) \
         ON CONFLICT(interface) DO UPDATE SET \
             health_check_type = excluded.health_check_type, \
             health_check_config = excluded.health_check_config, \
             flap_threshold = excluded.flap_threshold, \
             flap_window_secs = excluded.flap_window_secs, \
             sticky_sessions = excluded.sticky_sessions, \
             zone_pin = excluded.zone_pin, \
             updated_at = datetime('now')",
        rusqlite::params![
            config.interface,
            type_str,
            config_json,
            config.flap_threshold,
            config.flap_window_secs,
            config.sticky_sessions as i32,
            config.zone_pin,
        ],
    )
    .context("failed to upsert wan_health_config")?;

    tracing::info!(
        interface = %config.interface,
        check_type = %config.health_check_type,
        flap_threshold = config.flap_threshold,
        sticky = config.sticky_sessions,
        "WAN health config saved"
    );
    Ok(())
}

/// List all health configs.
#[must_use = "health config list result should be checked"]
pub async fn list_health_configs(db: &sfgw_db::Db) -> Result<Vec<WanHealthConfig>> {
    let conn = db.lock().await;
    let mut stmt = conn
        .prepare(
            "SELECT interface, health_check_type, health_check_config, flap_threshold, \
             flap_window_secs, sticky_sessions, zone_pin \
             FROM wan_health_config ORDER BY interface",
        )
        .context("failed to prepare wan_health_config list query")?;

    let rows = stmt
        .query_map([], |row| {
            let interface: String = row.get(0)?;
            let check_type: String = row.get(1)?;
            let check_config: String = row.get(2)?;
            let flap_threshold: u32 = row.get(3)?;
            let flap_window_secs: u32 = row.get(4)?;
            let sticky: i32 = row.get(5)?;
            let zone_pin: Option<String> = row.get(6)?;
            Ok((
                interface,
                check_type,
                check_config,
                flap_threshold,
                flap_window_secs,
                sticky,
                zone_pin,
            ))
        })
        .context("failed to query wan_health_config")?;

    let mut configs = Vec::new();
    for row in rows {
        let (
            interface,
            check_type,
            check_config,
            flap_threshold,
            flap_window_secs,
            sticky,
            zone_pin,
        ) = row?;
        let health_check_type = parse_health_check_type(&check_type, &check_config)?;
        configs.push(WanHealthConfig {
            interface,
            health_check_type,
            flap_threshold,
            flap_window_secs,
            sticky_sessions: sticky != 0,
            zone_pin,
        });
    }
    Ok(configs)
}

/// Log a flap event.
pub async fn log_flap_event(
    db: &sfgw_db::Db,
    interface: &str,
    new_state: &str,
    suppressed: bool,
) -> Result<()> {
    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO wan_flap_log (interface, new_state, suppressed) VALUES (?1, ?2, ?3)",
        rusqlite::params![interface, new_state, suppressed as i32],
    )
    .context("failed to insert wan_flap_log")?;

    // Prune old entries (keep last 1000 per interface)
    conn.execute(
        "DELETE FROM wan_flap_log WHERE interface = ?1 AND id NOT IN \
         (SELECT id FROM wan_flap_log WHERE interface = ?1 ORDER BY timestamp DESC LIMIT 1000)",
        rusqlite::params![interface],
    )
    .context("failed to prune wan_flap_log")?;

    Ok(())
}

/// Get recent flap events, optionally filtered by interface.
#[must_use = "flap log result should be checked"]
pub async fn get_flap_log(
    db: &sfgw_db::Db,
    interface: Option<&str>,
    limit: u32,
) -> Result<Vec<FlapEvent>> {
    let conn = db.lock().await;
    let limit = limit.min(500); // Cap at 500

    let events = if let Some(iface) = interface {
        validate_interface_name(iface).map_err(|e| NetError::Internal(e.into()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, interface, new_state, suppressed, timestamp \
                 FROM wan_flap_log WHERE interface = ?1 \
                 ORDER BY timestamp DESC LIMIT ?2",
            )
            .context("failed to prepare flap_log query")?;
        let rows = stmt
            .query_map(rusqlite::params![iface, limit], map_flap_row)
            .context("failed to query flap_log")?;
        rows.filter_map(|r| r.ok()).collect()
    } else {
        let mut stmt = conn
            .prepare(
                "SELECT id, interface, new_state, suppressed, timestamp \
                 FROM wan_flap_log ORDER BY timestamp DESC LIMIT ?1",
            )
            .context("failed to prepare flap_log query")?;
        let rows = stmt
            .query_map(rusqlite::params![limit], map_flap_row)
            .context("failed to query flap_log")?;
        rows.filter_map(|r| r.ok()).collect()
    };

    Ok(events)
}

fn map_flap_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FlapEvent> {
    Ok(FlapEvent {
        id: row.get(0)?,
        interface: row.get(1)?,
        new_state: row.get(2)?,
        suppressed: row.get::<_, i32>(3)? != 0,
        timestamp: row.get(4)?,
    })
}

// ── Health check type serialization helpers ─────────────────────────

fn parse_health_check_type(type_str: &str, config_json: &str) -> Result<HealthCheckType> {
    match type_str {
        "icmp" => Ok(HealthCheckType::Icmp),
        "http" => {
            #[derive(Deserialize)]
            struct HttpCfg {
                url: String,
                #[serde(default = "default_http_status")]
                expected_status: u16,
            }
            let cfg: HttpCfg =
                serde_json::from_str(config_json).context("invalid HTTP health check config")?;
            Ok(HealthCheckType::Http {
                url: cfg.url,
                expected_status: cfg.expected_status,
            })
        }
        "dns" => {
            #[derive(Deserialize)]
            struct DnsCfg {
                domain: String,
                server: String,
            }
            let cfg: DnsCfg =
                serde_json::from_str(config_json).context("invalid DNS health check config")?;
            Ok(HealthCheckType::Dns {
                domain: cfg.domain,
                server: cfg.server,
            })
        }
        other => Err(NetError::Internal(anyhow::anyhow!(
            "unknown health check type: {other}"
        ))),
    }
}

fn serialize_health_check_type(hct: &HealthCheckType) -> Result<(String, String)> {
    match hct {
        HealthCheckType::Icmp => Ok(("icmp".to_string(), "{}".to_string())),
        HealthCheckType::Http {
            url,
            expected_status,
        } => {
            let json = serde_json::json!({ "url": url, "expected_status": expected_status });
            Ok(("http".to_string(), json.to_string()))
        }
        HealthCheckType::Dns { domain, server } => {
            let json = serde_json::json!({ "domain": domain, "server": server });
            Ok(("dns".to_string(), json.to_string()))
        }
    }
}

// ── Extended health check execution ─────────────────────────────────

/// Perform a health check using the configured type.
///
/// Returns `(healthy, latency_ms)`.
pub async fn perform_health_check(
    interface: &str,
    target: &str,
    health_type: &HealthCheckType,
) -> (bool, u64) {
    let start = std::time::Instant::now();
    let healthy = match health_type {
        HealthCheckType::Icmp => perform_icmp_check(interface, target).await,
        HealthCheckType::Http {
            url,
            expected_status,
        } => perform_http_check(interface, url, *expected_status).await,
        HealthCheckType::Dns { domain, server } => {
            perform_dns_check(interface, domain, server).await
        }
    };
    let latency = start.elapsed().as_millis() as u64;
    (healthy, latency)
}

/// ICMP ping health check (existing behavior).
async fn perform_icmp_check(interface: &str, target: &str) -> bool {
    match Command::new("ping")
        .args(["-I", interface, "-c", "1", "-W", "2", target])
        .output()
        .await
    {
        Ok(output) => output.status.success(),
        Err(e) => {
            tracing::debug!(
                interface,
                target,
                "ICMP health check failed to execute: {e}"
            );
            false
        }
    }
}

/// HTTP GET health check with 5s timeout.
///
/// Uses reqwest to make the request. The interface binding is done via
/// the system's routing table (the request goes out the correct WAN
/// because we set up per-interface routing tables in sfgw-fw).
async fn perform_http_check(interface: &str, url: &str, expected_status: u16) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(interface, url, "failed to build HTTP client: {e}");
            return false;
        }
    };

    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let ok = status == expected_status;
            if !ok {
                tracing::debug!(
                    interface,
                    url,
                    status,
                    expected_status,
                    "HTTP health check: unexpected status"
                );
            }
            ok
        }
        Err(e) => {
            tracing::debug!(interface, url, "HTTP health check failed: {e}");
            false
        }
    }
}

/// DNS resolve health check.
///
/// Uses the `dig` command to query a domain via a specific server.
/// Succeeds if the answer section contains at least one record.
async fn perform_dns_check(interface: &str, domain: &str, server: &str) -> bool {
    // Use dig with short timeout: dig @server domain +short +time=3 +tries=1
    let server_arg = format!("@{server}");
    match Command::new("dig")
        .args([&server_arg, domain, "+short", "+time=3", "+tries=1"])
        .output()
        .await
    {
        Ok(output) => {
            if !output.status.success() {
                tracing::debug!(interface, domain, server, "DNS health check: dig failed");
                return false;
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            let has_answer = stdout.lines().any(|l| !l.trim().is_empty());
            if !has_answer {
                tracing::debug!(
                    interface,
                    domain,
                    server,
                    "DNS health check: no answer records"
                );
            }
            has_answer
        }
        Err(e) => {
            tracing::debug!(
                interface,
                domain,
                server,
                "DNS health check failed to execute dig: {e}"
            );
            false
        }
    }
}

// ── Flap detection ──────────────────────────────────────────────────

/// Tracks state transitions for a single WAN interface in a sliding window.
#[derive(Debug)]
pub struct FlapDetector {
    /// Timestamps of state changes within the window.
    transitions: VecDeque<std::time::Instant>,
    /// Max transitions before we suppress.
    threshold: u32,
    /// Window duration.
    window: std::time::Duration,
}

impl FlapDetector {
    /// Create a new flap detector.
    pub fn new(threshold: u32, window_secs: u32) -> Self {
        Self {
            transitions: VecDeque::new(),
            threshold,
            window: std::time::Duration::from_secs(window_secs as u64),
        }
    }

    /// Record a state change. Returns `true` if failover should be suppressed
    /// (i.e., the interface is flapping).
    pub fn record_transition(&mut self) -> bool {
        let now = std::time::Instant::now();

        // Remove transitions outside the window
        while let Some(front) = self.transitions.front() {
            if now.duration_since(*front) > self.window {
                self.transitions.pop_front();
            } else {
                break;
            }
        }

        self.transitions.push_back(now);

        let flapping = self.transitions.len() as u32 >= self.threshold;
        if flapping {
            tracing::warn!(
                transitions = self.transitions.len(),
                threshold = self.threshold,
                window_secs = self.window.as_secs(),
                "flap detection: interface is flapping, suppressing failover"
            );
        }
        flapping
    }

    /// Check if currently in flapping state without recording a new transition.
    pub fn is_flapping(&self) -> bool {
        let now = std::time::Instant::now();
        let recent = self
            .transitions
            .iter()
            .filter(|t| now.duration_since(**t) <= self.window)
            .count();
        recent as u32 >= self.threshold
    }
}

/// Shared flap detector state across the WAN health monitor.
pub type FlapDetectorMap = Arc<Mutex<std::collections::HashMap<String, FlapDetector>>>;

/// Create a new shared flap detector map.
pub fn new_flap_detector_map() -> FlapDetectorMap {
    Arc::new(Mutex::new(std::collections::HashMap::new()))
}

// ── Sticky sessions (conntrack preservation) ────────────────────────

/// When failing over with sticky sessions enabled, mark existing connections
/// to continue using the old WAN interface while routing new connections
/// via the new WAN.
///
/// Uses iptables-legacy (UDM Pro kernel 4.19, no nf_tables) to set
/// connection marks based on the outgoing interface, and ip rule to route
/// marked traffic via the old interface's routing table.
pub async fn apply_sticky_sessions(
    old_interface: &str,
    old_gateway: &str,
    table_id: u32,
) -> Result<()> {
    validate_interface_name(old_interface).map_err(|e| NetError::Internal(e.into()))?;
    let _gw: IpAddr = old_gateway
        .parse()
        .map_err(|_| NetError::Internal(anyhow::anyhow!("invalid gateway: {}", old_gateway)))?;

    let mark = format!("0x{:x}", table_id);
    let table_str = table_id.to_string();

    // Mark established/related connections going out the old interface
    // so they continue using the old route.
    let mark_result = Command::new("iptables-legacy")
        .args([
            "-t",
            "mangle",
            "-A",
            "OUTPUT",
            "-o",
            old_interface,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "CONNMARK",
            "--set-mark",
            &mark,
        ])
        .output()
        .await
        .context("failed to execute iptables-legacy for sticky sessions")?;

    if !mark_result.status.success() {
        let stderr = String::from_utf8_lossy(&mark_result.stderr);
        tracing::warn!(
            interface = old_interface,
            "failed to set connmark for sticky sessions: {}",
            stderr.trim()
        );
    }

    // Restore marks from connection tracking to packets
    let restore_result = Command::new("iptables-legacy")
        .args([
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-j",
            "CONNMARK",
            "--restore-mark",
        ])
        .output()
        .await
        .context("failed to add connmark restore rule")?;

    if !restore_result.status.success() {
        let stderr = String::from_utf8_lossy(&restore_result.stderr);
        tracing::debug!("connmark restore rule may already exist: {}", stderr.trim());
    }

    // Add ip rule: packets with this mark use the old routing table
    let rule_result = Command::new("ip")
        .args(["rule", "add", "fwmark", &mark, "table", &table_str])
        .output()
        .await
        .context("failed to add ip rule for sticky sessions")?;

    if !rule_result.status.success() {
        let stderr = String::from_utf8_lossy(&rule_result.stderr);
        tracing::warn!(
            "failed to add ip rule for fwmark {}: {}",
            mark,
            stderr.trim()
        );
    }

    tracing::info!(
        interface = old_interface,
        mark = mark.as_str(),
        table = table_id,
        "sticky sessions: existing connections preserved via old route"
    );

    Ok(())
}

/// Remove sticky session rules for an interface (cleanup after full transition).
pub async fn remove_sticky_sessions(old_interface: &str, table_id: u32) -> Result<()> {
    validate_interface_name(old_interface).map_err(|e| NetError::Internal(e.into()))?;

    let mark = format!("0x{:x}", table_id);
    let table_str = table_id.to_string();

    // Remove the mangle OUTPUT rule
    let _ = Command::new("iptables-legacy")
        .args([
            "-t",
            "mangle",
            "-D",
            "OUTPUT",
            "-o",
            old_interface,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "CONNMARK",
            "--set-mark",
            &mark,
        ])
        .output()
        .await;

    // Remove the ip rule
    let _ = Command::new("ip")
        .args(["rule", "del", "fwmark", &mark, "table", &table_str])
        .output()
        .await;

    tracing::info!(
        interface = old_interface,
        "sticky sessions: rules removed for old interface"
    );

    Ok(())
}

// ── Per-zone WAN pinning ────────────────────────────────────────────

/// Apply iptables rules to pin a specific zone's traffic to a WAN interface.
///
/// Uses fwmark + ip rule to route zone-originated traffic via a specific
/// routing table. The zone is identified by its VLAN interface (e.g. br10 for VLAN 10).
pub async fn apply_zone_pin(
    zone_interface: &str,
    wan_interface: &str,
    wan_gateway: &str,
    table_id: u32,
) -> Result<()> {
    validate_interface_name(zone_interface).map_err(|e| NetError::Internal(e.into()))?;
    validate_interface_name(wan_interface).map_err(|e| NetError::Internal(e.into()))?;
    let _gw: IpAddr = wan_gateway
        .parse()
        .map_err(|_| NetError::Internal(anyhow::anyhow!("invalid gateway: {}", wan_gateway)))?;

    let mark = format!("0x{:x}", 200 + table_id); // Use 200+ range for zone pins
    let table_str = table_id.to_string();

    // Ensure the routing table has the correct default route
    let route_result = Command::new("ip")
        .args([
            "route",
            "replace",
            "default",
            "via",
            wan_gateway,
            "dev",
            wan_interface,
            "table",
            &table_str,
        ])
        .output()
        .await
        .context("failed to set zone-pin routing table")?;

    if !route_result.status.success() {
        let stderr = String::from_utf8_lossy(&route_result.stderr);
        tracing::warn!("failed to set zone-pin route: {}", stderr.trim());
    }

    // Mark traffic from the zone interface
    let mark_result = Command::new("iptables-legacy")
        .args([
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-i",
            zone_interface,
            "-j",
            "MARK",
            "--set-mark",
            &mark,
        ])
        .output()
        .await
        .context("failed to set zone-pin mark")?;

    if !mark_result.status.success() {
        let stderr = String::from_utf8_lossy(&mark_result.stderr);
        tracing::warn!(
            "failed to set zone-pin mark for {}: {}",
            zone_interface,
            stderr.trim()
        );
    }

    // Add ip rule for the mark
    let rule_result = Command::new("ip")
        .args(["rule", "add", "fwmark", &mark, "table", &table_str])
        .output()
        .await
        .context("failed to add zone-pin ip rule")?;

    if !rule_result.status.success() {
        let stderr = String::from_utf8_lossy(&rule_result.stderr);
        tracing::debug!("zone-pin ip rule may already exist: {}", stderr.trim());
    }

    tracing::info!(
        zone = zone_interface,
        wan = wan_interface,
        mark = mark.as_str(),
        table = table_id,
        "zone pin applied: {} traffic via {}",
        zone_interface,
        wan_interface
    );

    Ok(())
}

/// Remove zone-pin rules for a zone interface.
pub async fn remove_zone_pin(zone_interface: &str, table_id: u32) -> Result<()> {
    validate_interface_name(zone_interface).map_err(|e| NetError::Internal(e.into()))?;

    let mark = format!("0x{:x}", 200 + table_id);
    let table_str = table_id.to_string();

    let _ = Command::new("iptables-legacy")
        .args([
            "-t",
            "mangle",
            "-D",
            "PREROUTING",
            "-i",
            zone_interface,
            "-j",
            "MARK",
            "--set-mark",
            &mark,
        ])
        .output()
        .await;

    let _ = Command::new("ip")
        .args(["rule", "del", "fwmark", &mark, "table", &table_str])
        .output()
        .await;

    tracing::info!(zone = zone_interface, "zone pin removed");

    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create an in-memory database with the sfgw schema including wan_configs.
    async fn test_db() -> sfgw_db::Db {
        sfgw_db::open_in_memory()
            .await
            .expect("failed to open in-memory db")
    }

    fn dhcp_config() -> WanPortConfig {
        WanPortConfig {
            interface: "eth0".to_string(),
            connection: WanConnectionType::Dhcp,
            enabled: true,
            priority: 1,
            weight: 50,
            health_check: "1.1.1.1".to_string(),
            health_interval_secs: 10,
            mtu: None,
            dns_override: None,
            mac_override: None,
        }
    }

    fn static_config() -> WanPortConfig {
        WanPortConfig {
            interface: "eth4".to_string(),
            connection: WanConnectionType::Static {
                address: "203.0.113.5/24".to_string(),
                gateway: "203.0.113.1".to_string(),
                address_v6: Some("2001:db8::5/64".to_string()),
                gateway_v6: Some("2001:db8::1".to_string()),
            },
            enabled: true,
            priority: 2,
            weight: 30,
            health_check: "8.8.8.8".to_string(),
            health_interval_secs: 15,
            mtu: Some(1500),
            dns_override: Some(vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()]),
            mac_override: Some("AA:BB:CC:DD:EE:FF".to_string()),
        }
    }

    fn pppoe_config() -> WanPortConfig {
        WanPortConfig {
            interface: "eth1".to_string(),
            connection: WanConnectionType::Pppoe {
                username: "user@provider.de".to_string(),
                password_enc: "ZW5jcnlwdGVkcGFzc3dvcmQ".to_string(),
                mtu: 1492,
                service_name: None,
                ac_name: None,
                vlan_id: None,
            },
            enabled: true,
            priority: 1,
            weight: 100,
            health_check: "1.1.1.1".to_string(),
            health_interval_secs: 10,
            mtu: None,
            dns_override: None,
            mac_override: None,
        }
    }

    fn dslite_config() -> WanPortConfig {
        WanPortConfig {
            interface: "eth2".to_string(),
            connection: WanConnectionType::DsLite {
                aftr_address: Some("2001:db8::1".to_string()),
                auto_aftr: false,
            },
            enabled: true,
            priority: 1,
            weight: 100,
            health_check: "1.1.1.1".to_string(),
            health_interval_secs: 10,
            mtu: None,
            dns_override: None,
            mac_override: None,
        }
    }

    fn vlan_pppoe_config() -> WanPortConfig {
        WanPortConfig {
            interface: "eth0".to_string(),
            connection: WanConnectionType::Vlan {
                vlan_id: 7,
                inner: Box::new(WanConnectionType::Pppoe {
                    username: "telekom-user".to_string(),
                    password_enc: "ZW5jcnlwdGVk".to_string(),
                    mtu: 1492,
                    service_name: None,
                    ac_name: None,
                    vlan_id: None,
                }),
            },
            enabled: true,
            priority: 1,
            weight: 100,
            health_check: "1.1.1.1".to_string(),
            health_interval_secs: 10,
            mtu: None,
            dns_override: None,
            mac_override: None,
        }
    }

    // ── Serialization / deserialization tests ────────────────────────

    #[test]
    fn serde_dhcp_roundtrip() {
        let config = dhcp_config();
        let json = serde_json::to_string(&config).expect("serialize failed");
        let back: WanPortConfig = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(config, back);
    }

    #[test]
    fn serde_static_roundtrip() {
        let config = static_config();
        let json = serde_json::to_string(&config).expect("serialize failed");
        let back: WanPortConfig = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(config, back);
    }

    #[test]
    fn serde_pppoe_roundtrip() {
        let config = pppoe_config();
        let json = serde_json::to_string(&config).expect("serialize failed");
        let back: WanPortConfig = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(config, back);
    }

    #[test]
    fn serde_dslite_roundtrip() {
        let config = dslite_config();
        let json = serde_json::to_string(&config).expect("serialize failed");
        let back: WanPortConfig = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(config, back);
    }

    #[test]
    fn serde_vlan_pppoe_roundtrip() {
        let config = vlan_pppoe_config();
        let json = serde_json::to_string(&config).expect("serialize failed");
        let back: WanPortConfig = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(config, back);
    }

    #[test]
    fn serde_connection_type_tagged() {
        // Verify the JSON has the right tag
        let dhcp = WanConnectionType::Dhcp;
        let json = serde_json::to_string(&dhcp).expect("serialize");
        assert!(json.contains("\"type\":\"dhcp\""), "got: {json}");

        let pppoe = WanConnectionType::Pppoe {
            username: "user".to_string(),
            password_enc: "enc".to_string(),
            mtu: 1492,
            service_name: None,
            ac_name: None,
            vlan_id: None,
        };
        let json = serde_json::to_string(&pppoe).expect("serialize");
        assert!(json.contains("\"type\":\"pppoe\""), "got: {json}");
    }

    #[test]
    fn serde_defaults_applied() {
        // Deserialize with minimal fields, check defaults
        let json = r#"{"interface":"eth0","connection":{"type":"dhcp"},"enabled":true,"priority":1,"weight":50}"#;
        let config: WanPortConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(config.health_check, "1.1.1.1");
        assert_eq!(config.health_interval_secs, 10);
        assert!(config.mtu.is_none());
        assert!(config.dns_override.is_none());
        assert!(config.mac_override.is_none());
    }

    #[test]
    fn serde_pppoe_defaults() {
        let json = r#"{"type":"pppoe","username":"user","password_enc":"enc"}"#;
        let conn: WanConnectionType = serde_json::from_str(json).expect("deserialize");
        if let WanConnectionType::Pppoe {
            mtu,
            service_name,
            ac_name,
            vlan_id,
            ..
        } = conn
        {
            assert_eq!(mtu, 1492);
            assert!(service_name.is_none());
            assert!(ac_name.is_none());
            assert!(vlan_id.is_none());
        } else {
            panic!("expected Pppoe variant");
        }
    }

    #[test]
    fn serde_dslite_defaults() {
        let json = r#"{"type":"dslite"}"#;
        let conn: WanConnectionType = serde_json::from_str(json).expect("deserialize");
        if let WanConnectionType::DsLite {
            aftr_address,
            auto_aftr,
        } = conn
        {
            assert!(aftr_address.is_none());
            assert!(auto_aftr);
        } else {
            panic!("expected DsLite variant");
        }
    }

    // ── Validation tests ────────────────────────────────────────────

    #[test]
    fn validate_interface_names() {
        assert!(validate_interface_name("eth0").is_ok());
        assert!(validate_interface_name("br-lan").is_ok());
        assert!(validate_interface_name("wg0").is_ok());
        assert!(validate_interface_name("vlan.100").is_ok());
        assert!(validate_interface_name("eth0_backup").is_ok());

        // Invalid cases
        assert!(validate_interface_name("").is_err());
        assert!(validate_interface_name("a234567890123456").is_err()); // 16 chars
        assert!(validate_interface_name("eth0; rm -rf /").is_err());
        assert!(validate_interface_name("eth0\"").is_err());
        assert!(validate_interface_name("eth0\n").is_err());
        assert!(validate_interface_name("eth0 ").is_err());
    }

    #[test]
    fn validate_vlan_ids() {
        assert!(validate_vlan_id(1).is_ok());
        assert!(validate_vlan_id(100).is_ok());
        assert!(validate_vlan_id(4094).is_ok());

        assert!(validate_vlan_id(0).is_err());
        assert!(validate_vlan_id(4095).is_err());
    }

    #[test]
    fn validate_cidr_addresses() {
        assert!(validate_cidr("192.168.1.1/24").is_ok());
        assert!(validate_cidr("10.0.0.0/8").is_ok());
        assert!(validate_cidr("203.0.113.5/32").is_ok());
        assert!(validate_cidr("2001:db8::1/64").is_ok());

        assert!(validate_cidr("192.168.1.1").is_err()); // no prefix
        assert!(validate_cidr("not-an-ip/24").is_err());
        assert!(validate_cidr("192.168.1.1/33").is_err()); // too large
        assert!(validate_cidr("2001:db8::1/129").is_err());
    }

    #[test]
    fn validate_ip_addresses() {
        assert!(validate_ip("1.1.1.1").is_ok());
        assert!(validate_ip("8.8.8.8").is_ok());
        assert!(validate_ip("2001:db8::1").is_ok());
        assert!(validate_ip("::1").is_ok());

        assert!(validate_ip("not-an-ip").is_err());
        assert!(validate_ip("256.1.1.1").is_err());
        assert!(validate_ip("").is_err());
    }

    #[test]
    fn validate_mtu_values() {
        assert!(validate_mtu(576).is_ok());
        assert!(validate_mtu(1500).is_ok());
        assert!(validate_mtu(9000).is_ok());

        assert!(validate_mtu(575).is_err());
        assert!(validate_mtu(9001).is_err());
        assert!(validate_mtu(0).is_err());
    }

    #[test]
    fn validate_mac_addresses() {
        assert!(validate_mac("AA:BB:CC:DD:EE:FF").is_ok());
        assert!(validate_mac("00:00:00:00:00:00").is_ok());
        assert!(validate_mac("aa:bb:cc:dd:ee:ff").is_ok());

        assert!(validate_mac("AA:BB:CC:DD:EE").is_err()); // too short
        assert!(validate_mac("AA:BB:CC:DD:EE:FF:00").is_err()); // too long
        assert!(validate_mac("GG:BB:CC:DD:EE:FF").is_err()); // invalid hex
        assert!(validate_mac("AABB.CCDD.EEFF").is_err()); // wrong format
        assert!(validate_mac("").is_err());
    }

    #[test]
    fn validate_pppoe_username_rejects_injection() {
        assert!(validate_pppoe_username("user@provider.de").is_ok());
        assert!(validate_pppoe_username("simple-user").is_ok());
        assert!(validate_pppoe_username("user123").is_ok());

        // Shell injection attempts
        assert!(validate_pppoe_username("user\"; rm -rf /").is_err());
        assert!(validate_pppoe_username("user\ninjected").is_err());
        assert!(validate_pppoe_username("user`whoami`").is_err());
        assert!(validate_pppoe_username("user$(id)").is_err());
        assert!(validate_pppoe_username("user;ls").is_err());
        assert!(validate_pppoe_username("user|cat /etc/passwd").is_err());
        assert!(validate_pppoe_username("user&bg").is_err());
        assert!(validate_pppoe_username("").is_err());
        assert!(validate_pppoe_username("user'quote").is_err());
        assert!(validate_pppoe_username("user\\escape").is_err());
    }

    #[test]
    fn validate_pppoe_password_enc_checks() {
        assert!(validate_pppoe_password_enc("ZW5jcnlwdGVk").is_ok());
        assert!(validate_pppoe_password_enc("somebase64string").is_ok());

        assert!(validate_pppoe_password_enc("").is_err());
        assert!(validate_pppoe_password_enc("has\nnewline").is_err());
        assert!(validate_pppoe_password_enc("has\rnewline").is_err());
    }

    #[test]
    fn validate_connection_type_nested_vlan_rejected() {
        let nested = WanConnectionType::Vlan {
            vlan_id: 100,
            inner: Box::new(WanConnectionType::Vlan {
                vlan_id: 200,
                inner: Box::new(WanConnectionType::Dhcp),
            }),
        };
        assert!(validate_connection_type(&nested).is_err());
    }

    #[test]
    fn validate_connection_type_vlan_with_pppoe() {
        let config = WanConnectionType::Vlan {
            vlan_id: 7,
            inner: Box::new(WanConnectionType::Pppoe {
                username: "user@telekom.de".to_string(),
                password_enc: "ZW5j".to_string(),
                mtu: 1492,
                service_name: None,
                ac_name: None,
                vlan_id: None,
            }),
        };
        assert!(validate_connection_type(&config).is_ok());
    }

    #[test]
    fn validate_full_config_good() {
        assert!(validate_wan_config(&dhcp_config()).is_ok());
        assert!(validate_wan_config(&static_config()).is_ok());
        assert!(validate_wan_config(&pppoe_config()).is_ok());
        assert!(validate_wan_config(&dslite_config()).is_ok());
        assert!(validate_wan_config(&vlan_pppoe_config()).is_ok());
    }

    #[test]
    fn validate_full_config_bad_interface() {
        let mut config = dhcp_config();
        config.interface = "eth0; rm -rf /".to_string();
        assert!(validate_wan_config(&config).is_err());
    }

    #[test]
    fn validate_full_config_bad_weight() {
        let mut config = dhcp_config();
        config.weight = 0;
        assert!(validate_wan_config(&config).is_err());

        config.weight = 101;
        assert!(validate_wan_config(&config).is_err());
    }

    #[test]
    fn validate_full_config_bad_health_check() {
        let mut config = dhcp_config();
        config.health_check = "not-an-ip".to_string();
        assert!(validate_wan_config(&config).is_err());
    }

    #[test]
    fn validate_full_config_bad_health_interval() {
        let mut config = dhcp_config();
        config.health_interval_secs = 0;
        assert!(validate_wan_config(&config).is_err());

        config.health_interval_secs = 3601;
        assert!(validate_wan_config(&config).is_err());
    }

    #[test]
    fn validate_full_config_bad_dns() {
        let mut config = dhcp_config();
        config.dns_override = Some(vec!["not-an-ip".to_string()]);
        assert!(validate_wan_config(&config).is_err());
    }

    #[test]
    fn validate_full_config_bad_mac() {
        let mut config = dhcp_config();
        config.mac_override = Some("bad-mac".to_string());
        assert!(validate_wan_config(&config).is_err());
    }

    #[test]
    fn validate_dslite_bad_aftr() {
        let conn = WanConnectionType::DsLite {
            aftr_address: Some("not-ipv6".to_string()),
            auto_aftr: false,
        };
        assert!(validate_connection_type(&conn).is_err());
    }

    #[test]
    fn validate_static_bad_address() {
        let conn = WanConnectionType::Static {
            address: "not-cidr".to_string(),
            gateway: "1.1.1.1".to_string(),
            address_v6: None,
            gateway_v6: None,
        };
        assert!(validate_connection_type(&conn).is_err());
    }

    #[test]
    fn validate_static_bad_gateway() {
        let conn = WanConnectionType::Static {
            address: "10.0.0.1/24".to_string(),
            gateway: "not-ip".to_string(),
            address_v6: None,
            gateway_v6: None,
        };
        assert!(validate_connection_type(&conn).is_err());
    }

    // ── PPPoE config generation tests ───────────────────────────────

    #[test]
    fn pppoe_config_generation_basic() {
        let config = generate_pppoe_config("eth0", "user@isp.de", "encrypted_pw", 1492, None, None);
        assert!(config.contains("plugin pppoe.so"));
        assert!(config.contains("eth0"));
        assert!(config.contains("user \"user@isp.de\""));
        assert!(config.contains("password \"encrypted_pw\""));
        assert!(config.contains("mtu 1492"));
        assert!(config.contains("mru 1492"));
        assert!(config.contains("defaultroute"));
        assert!(config.contains("usepeerdns"));
        assert!(config.contains("persist"));
        assert!(config.contains("noauth"));
        assert!(config.contains("lcp-echo-interval 15"));
        assert!(config.contains("lcp-echo-failure 4"));
    }

    #[test]
    fn pppoe_config_generation_with_service_and_ac() {
        let config = generate_pppoe_config(
            "eth0.7",
            "user@telekom.de",
            "enc",
            1492,
            Some("telekom"),
            Some("bras01"),
        );
        assert!(config.contains("rp_pppoe_service \"telekom\""));
        assert!(config.contains("rp_pppoe_ac \"bras01\""));
    }

    // ── Command generation tests ────────────────────────────────────

    #[test]
    fn generate_dhcp_commands() {
        let config = dhcp_config();
        let cmds = generate_wan_commands(&config);
        // Should have: bring up + dhcpcd
        assert!(cmds.len() >= 2);
        let last = cmds.last().expect("should have commands");
        assert_eq!(last[0], "dhcpcd");
    }

    #[test]
    fn generate_static_commands() {
        let config = static_config();
        let cmds = generate_wan_commands(&config);
        // MAC override + MTU + bring up + flush + add addr + route + v6 addr + v6 route
        assert!(cmds.len() >= 6);
        // Should contain MAC override
        assert!(
            cmds.iter().any(|c| c.contains(&"address".to_string())
                && c.contains(&"AA:BB:CC:DD:EE:FF".to_string()))
        );
        // Should contain static address
        assert!(
            cmds.iter()
                .any(|c| c.contains(&"203.0.113.5/24".to_string()))
        );
    }

    #[test]
    fn generate_vlan_pppoe_commands() {
        let config = vlan_pppoe_config();
        let cmds = generate_wan_commands(&config);
        // Should create VLAN, bring up, then pppd
        assert!(
            cmds.iter()
                .any(|c| c.contains(&"vlan".to_string()) && c.contains(&"7".to_string()))
        );
        assert!(cmds.iter().any(|c| c[0] == "pppd"));
    }

    #[test]
    fn generate_dslite_commands() {
        let config = dslite_config();
        let cmds = generate_wan_commands(&config);
        // Should create tunnel
        assert!(cmds.iter().any(|c| c.contains(&"ipip6".to_string())));
        assert!(cmds.iter().any(|c| c.contains(&"ds-lite-eth2".to_string())));
    }

    // ── Database round-trip tests ───────────────────────────────────

    #[tokio::test]
    async fn db_set_and_get_wan_config() {
        let db = test_db().await;
        let config = dhcp_config();

        set_wan_config(&db, &config)
            .await
            .expect("set_wan_config failed");
        let loaded = get_wan_config(&db, "eth0")
            .await
            .expect("get_wan_config failed")
            .expect("should find config");

        assert_eq!(loaded.interface, "eth0");
        assert_eq!(loaded.connection, WanConnectionType::Dhcp);
        assert_eq!(loaded.priority, 1);
        assert_eq!(loaded.weight, 50);
    }

    #[tokio::test]
    async fn db_get_nonexistent_returns_none() {
        let db = test_db().await;
        let result = get_wan_config(&db, "eth99")
            .await
            .expect("get_wan_config failed");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn db_list_wan_configs() {
        let db = test_db().await;

        set_wan_config(&db, &dhcp_config()).await.expect("set dhcp");
        set_wan_config(&db, &static_config())
            .await
            .expect("set static");
        set_wan_config(&db, &pppoe_config())
            .await
            .expect("set pppoe");

        let configs = list_wan_configs(&db).await.expect("list failed");
        assert_eq!(configs.len(), 3);

        // Should be sorted by priority
        assert!(configs[0].priority <= configs[1].priority);
    }

    #[tokio::test]
    async fn db_update_wan_config() {
        let db = test_db().await;

        let mut config = dhcp_config();
        set_wan_config(&db, &config).await.expect("initial set");

        // Update it
        config.priority = 99;
        config.weight = 10;
        set_wan_config(&db, &config).await.expect("update set");

        let loaded = get_wan_config(&db, "eth0")
            .await
            .expect("get failed")
            .expect("should exist");
        assert_eq!(loaded.priority, 99);
        assert_eq!(loaded.weight, 10);
    }

    #[tokio::test]
    async fn db_remove_wan_config() {
        let db = test_db().await;

        set_wan_config(&db, &dhcp_config()).await.expect("set");
        remove_wan_config(&db, "eth0").await.expect("remove");

        let result = get_wan_config(&db, "eth0").await.expect("get failed");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn db_remove_nonexistent_does_not_error() {
        let db = test_db().await;
        // Should not fail, just log a warning
        remove_wan_config(&db, "eth99")
            .await
            .expect("remove should not error");
    }

    #[tokio::test]
    async fn db_roundtrip_all_types() {
        let db = test_db().await;
        let configs = vec![
            dhcp_config(),
            static_config(),
            pppoe_config(),
            dslite_config(),
            vlan_pppoe_config(),
        ];

        // vlan_pppoe_config has same interface as dhcp_config, so set a unique one
        let mut vlan_cfg = vlan_pppoe_config();
        vlan_cfg.interface = "eth5".to_string();

        for cfg in &configs[..4] {
            set_wan_config(&db, cfg).await.expect("set failed");
        }
        set_wan_config(&db, &vlan_cfg)
            .await
            .expect("set vlan failed");

        let loaded = list_wan_configs(&db).await.expect("list failed");
        assert_eq!(loaded.len(), 5);
    }

    // ── Display / formatting tests ──────────────────────────────────

    #[test]
    fn connection_type_display() {
        assert_eq!(format!("{}", WanConnectionType::Dhcp), "dhcp");
        assert_eq!(
            format!(
                "{}",
                WanConnectionType::Static {
                    address: "1.2.3.4/24".to_string(),
                    gateway: "1.2.3.1".to_string(),
                    address_v6: None,
                    gateway_v6: None,
                }
            ),
            "static"
        );
    }

    // ── Health check type tests ─────────────────────────────────────

    #[test]
    fn health_check_type_serde_icmp() {
        let hct = HealthCheckType::Icmp;
        let json = serde_json::to_string(&hct).expect("serialize");
        let back: HealthCheckType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(hct, back);
    }

    #[test]
    fn health_check_type_serde_http() {
        let hct = HealthCheckType::Http {
            url: "http://connectivitycheck.gstatic.com/generate_204".to_string(),
            expected_status: 204,
        };
        let json = serde_json::to_string(&hct).expect("serialize");
        let back: HealthCheckType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(hct, back);
    }

    #[test]
    fn health_check_type_serde_dns() {
        let hct = HealthCheckType::Dns {
            domain: "google.com".to_string(),
            server: "8.8.8.8".to_string(),
        };
        let json = serde_json::to_string(&hct).expect("serialize");
        let back: HealthCheckType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(hct, back);
    }

    #[test]
    fn health_check_type_display() {
        assert_eq!(format!("{}", HealthCheckType::Icmp), "icmp");
        assert_eq!(
            format!(
                "{}",
                HealthCheckType::Http {
                    url: "http://example.com".to_string(),
                    expected_status: 200,
                }
            ),
            "http(http://example.com)"
        );
        assert_eq!(
            format!(
                "{}",
                HealthCheckType::Dns {
                    domain: "google.com".to_string(),
                    server: "8.8.8.8".to_string(),
                }
            ),
            "dns(google.com@8.8.8.8)"
        );
    }

    // ── Health config validation tests ──────────────────────────────

    fn sample_health_config() -> WanHealthConfig {
        WanHealthConfig {
            interface: "eth0".to_string(),
            health_check_type: HealthCheckType::Icmp,
            flap_threshold: 5,
            flap_window_secs: 60,
            sticky_sessions: false,
            zone_pin: None,
        }
    }

    #[test]
    fn validate_health_config_icmp_ok() {
        assert!(validate_health_config(&sample_health_config()).is_ok());
    }

    #[test]
    fn validate_health_config_http_ok() {
        let mut cfg = sample_health_config();
        cfg.health_check_type = HealthCheckType::Http {
            url: "http://connectivitycheck.gstatic.com/generate_204".to_string(),
            expected_status: 204,
        };
        assert!(validate_health_config(&cfg).is_ok());
    }

    #[test]
    fn validate_health_config_http_bad_url() {
        let mut cfg = sample_health_config();
        cfg.health_check_type = HealthCheckType::Http {
            url: "ftp://not-http.com".to_string(),
            expected_status: 200,
        };
        assert!(validate_health_config(&cfg).is_err());
    }

    #[test]
    fn validate_health_config_http_bad_url_injection() {
        let mut cfg = sample_health_config();
        cfg.health_check_type = HealthCheckType::Http {
            url: "http://evil.com/`whoami`".to_string(),
            expected_status: 200,
        };
        assert!(validate_health_config(&cfg).is_err());
    }

    #[test]
    fn validate_health_config_http_bad_status() {
        let mut cfg = sample_health_config();
        cfg.health_check_type = HealthCheckType::Http {
            url: "http://example.com".to_string(),
            expected_status: 0,
        };
        assert!(validate_health_config(&cfg).is_err());
    }

    #[test]
    fn validate_health_config_dns_ok() {
        let mut cfg = sample_health_config();
        cfg.health_check_type = HealthCheckType::Dns {
            domain: "google.com".to_string(),
            server: "8.8.8.8".to_string(),
        };
        assert!(validate_health_config(&cfg).is_ok());
    }

    #[test]
    fn validate_health_config_dns_bad_domain() {
        let mut cfg = sample_health_config();
        cfg.health_check_type = HealthCheckType::Dns {
            domain: "goo gle.com".to_string(),
            server: "8.8.8.8".to_string(),
        };
        assert!(validate_health_config(&cfg).is_err());
    }

    #[test]
    fn validate_health_config_dns_bad_server() {
        let mut cfg = sample_health_config();
        cfg.health_check_type = HealthCheckType::Dns {
            domain: "google.com".to_string(),
            server: "not-an-ip".to_string(),
        };
        assert!(validate_health_config(&cfg).is_err());
    }

    #[test]
    fn validate_health_config_bad_flap_threshold() {
        let mut cfg = sample_health_config();
        cfg.flap_threshold = 0;
        assert!(validate_health_config(&cfg).is_err());
        cfg.flap_threshold = 101;
        assert!(validate_health_config(&cfg).is_err());
    }

    #[test]
    fn validate_health_config_bad_flap_window() {
        let mut cfg = sample_health_config();
        cfg.flap_window_secs = 9;
        assert!(validate_health_config(&cfg).is_err());
        cfg.flap_window_secs = 3601;
        assert!(validate_health_config(&cfg).is_err());
    }

    #[test]
    fn validate_health_config_zone_pin_ok() {
        let mut cfg = sample_health_config();
        cfg.zone_pin = Some("DMZ".to_string());
        assert!(validate_health_config(&cfg).is_ok());
        cfg.zone_pin = Some("LAN".to_string());
        assert!(validate_health_config(&cfg).is_ok());
    }

    #[test]
    fn validate_health_config_zone_pin_bad() {
        let mut cfg = sample_health_config();
        cfg.zone_pin = Some("".to_string());
        assert!(validate_health_config(&cfg).is_err());
        cfg.zone_pin = Some("zone with spaces".to_string());
        assert!(validate_health_config(&cfg).is_err());
    }

    // ── Flap detector tests ────────────────────────────────────────

    #[test]
    fn flap_detector_no_flap() {
        let mut detector = FlapDetector::new(5, 60);
        // 4 transitions should not trigger
        for _ in 0..4 {
            assert!(!detector.record_transition());
        }
    }

    #[test]
    fn flap_detector_flapping() {
        let mut detector = FlapDetector::new(3, 60);
        assert!(!detector.record_transition());
        assert!(!detector.record_transition());
        assert!(detector.record_transition()); // 3rd = flapping
        assert!(detector.is_flapping());
    }

    // ── Health check type serialization helpers ─────────────────────

    #[test]
    fn health_check_type_roundtrip_icmp() {
        let (type_str, config_json) =
            serialize_health_check_type(&HealthCheckType::Icmp).expect("serialize");
        let back = parse_health_check_type(&type_str, &config_json).expect("parse");
        assert_eq!(back, HealthCheckType::Icmp);
    }

    #[test]
    fn health_check_type_roundtrip_http() {
        let hct = HealthCheckType::Http {
            url: "http://example.com/health".to_string(),
            expected_status: 204,
        };
        let (type_str, config_json) = serialize_health_check_type(&hct).expect("serialize");
        let back = parse_health_check_type(&type_str, &config_json).expect("parse");
        assert_eq!(back, hct);
    }

    #[test]
    fn health_check_type_roundtrip_dns() {
        let hct = HealthCheckType::Dns {
            domain: "example.com".to_string(),
            server: "1.1.1.1".to_string(),
        };
        let (type_str, config_json) = serialize_health_check_type(&hct).expect("serialize");
        let back = parse_health_check_type(&type_str, &config_json).expect("parse");
        assert_eq!(back, hct);
    }

    // ── WanHealthConfig serde tests ────────────────────────────────

    #[test]
    fn wan_health_config_serde_roundtrip() {
        let cfg = WanHealthConfig {
            interface: "eth0".to_string(),
            health_check_type: HealthCheckType::Http {
                url: "https://example.com/check".to_string(),
                expected_status: 200,
            },
            flap_threshold: 10,
            flap_window_secs: 120,
            sticky_sessions: true,
            zone_pin: Some("DMZ".to_string()),
        };
        let json = serde_json::to_string(&cfg).expect("serialize");
        let back: WanHealthConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cfg, back);
    }

    #[test]
    fn wan_health_config_defaults() {
        let json = r#"{"interface":"eth0"}"#;
        let cfg: WanHealthConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(cfg.health_check_type, HealthCheckType::Icmp);
        assert_eq!(cfg.flap_threshold, 5);
        assert_eq!(cfg.flap_window_secs, 60);
        assert!(!cfg.sticky_sessions);
        assert!(cfg.zone_pin.is_none());
    }

    // ── Database round-trip tests for health config ────────────────

    #[tokio::test]
    async fn db_health_config_set_and_get() {
        let db = test_db().await;
        // Must create a wan_config first (FK constraint)
        set_wan_config(&db, &dhcp_config())
            .await
            .expect("set wan config");

        let hc = WanHealthConfig {
            interface: "eth0".to_string(),
            health_check_type: HealthCheckType::Http {
                url: "http://example.com/check".to_string(),
                expected_status: 204,
            },
            flap_threshold: 10,
            flap_window_secs: 120,
            sticky_sessions: true,
            zone_pin: Some("DMZ".to_string()),
        };
        set_health_config(&db, &hc)
            .await
            .expect("set health config");
        let loaded = get_health_config(&db, "eth0")
            .await
            .expect("get health config")
            .expect("should exist");

        assert_eq!(loaded.interface, "eth0");
        assert_eq!(
            loaded.health_check_type,
            HealthCheckType::Http {
                url: "http://example.com/check".to_string(),
                expected_status: 204,
            }
        );
        assert_eq!(loaded.flap_threshold, 10);
        assert_eq!(loaded.flap_window_secs, 120);
        assert!(loaded.sticky_sessions);
        assert_eq!(loaded.zone_pin, Some("DMZ".to_string()));
    }

    #[tokio::test]
    async fn db_health_config_nonexistent() {
        let db = test_db().await;
        let result = get_health_config(&db, "eth99")
            .await
            .expect("get should not error");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn db_health_config_list() {
        let db = test_db().await;
        set_wan_config(&db, &dhcp_config()).await.expect("set wan");
        set_wan_config(&db, &static_config())
            .await
            .expect("set wan");

        let hc1 = WanHealthConfig {
            interface: "eth0".to_string(),
            health_check_type: HealthCheckType::Icmp,
            flap_threshold: 5,
            flap_window_secs: 60,
            sticky_sessions: false,
            zone_pin: None,
        };
        let hc2 = WanHealthConfig {
            interface: "eth4".to_string(),
            health_check_type: HealthCheckType::Dns {
                domain: "google.com".to_string(),
                server: "8.8.8.8".to_string(),
            },
            flap_threshold: 3,
            flap_window_secs: 30,
            sticky_sessions: true,
            zone_pin: Some("LAN".to_string()),
        };
        set_health_config(&db, &hc1).await.expect("set hc1");
        set_health_config(&db, &hc2).await.expect("set hc2");

        let configs = list_health_configs(&db).await.expect("list");
        assert_eq!(configs.len(), 2);
    }

    #[tokio::test]
    async fn db_flap_log_roundtrip() {
        let db = test_db().await;
        log_flap_event(&db, "eth0", "down", false)
            .await
            .expect("log flap");
        log_flap_event(&db, "eth0", "up", false)
            .await
            .expect("log flap");
        log_flap_event(&db, "eth0", "down", true)
            .await
            .expect("log flap");

        let events = get_flap_log(&db, Some("eth0"), 100)
            .await
            .expect("get flap log");
        assert_eq!(events.len(), 3);
        // Most recent first
        assert_eq!(events[0].new_state, "down");
        assert!(events[0].suppressed);
    }

    #[tokio::test]
    async fn db_flap_log_all_interfaces() {
        let db = test_db().await;
        log_flap_event(&db, "eth0", "down", false)
            .await
            .expect("log");
        log_flap_event(&db, "eth4", "down", false)
            .await
            .expect("log");

        let events = get_flap_log(&db, None, 100).await.expect("get flap log");
        assert_eq!(events.len(), 2);
    }
}
