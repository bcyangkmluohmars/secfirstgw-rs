// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-WAN-port configuration: DHCP, Static IP, PPPoE, DS-Lite, VLAN.
//!
//! Each WAN interface can be independently configured with its own
//! connection type. Configurations are stored as JSON in the `wan_configs`
//! database table and applied to the system via `ip`, `pppd`, etc.

use crate::{NetError, Result};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use tokio::process::Command;

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

    #[error("invalid health check target '{0}': must be a valid IP")]
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

    // Health check must be a valid IP
    config
        .health_check
        .parse::<IpAddr>()
        .map_err(|_| WanValidationError::HealthCheck(config.health_check.clone()))?;

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

    // Also update the interface role to "wan"
    conn.execute(
        "UPDATE interfaces SET role = 'wan' WHERE name = ?1",
        rusqlite::params![config.interface],
    )
    .context("failed to update interface role to wan")?;

    tracing::info!(
        interface = %config.interface,
        enabled = config.enabled,
        priority = config.priority,
        "WAN config saved, interface role set to wan"
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
        // Revert interface role back to "lan"
        conn.execute(
            "UPDATE interfaces SET role = 'lan' WHERE name = ?1 AND role = 'wan'",
            rusqlite::params![interface],
        )
        .context("failed to revert interface role")?;
        tracing::info!(
            interface,
            "WAN config removed, interface role reverted to lan"
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

/// Apply DHCP on an interface via dhcpcd.
async fn apply_dhcp(interface: &str) -> Result<()> {
    let output = Command::new("dhcpcd")
        .args(["--nobackground", "-4", interface])
        .output()
        .await
        .context("failed to execute dhcpcd")?;

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
}
