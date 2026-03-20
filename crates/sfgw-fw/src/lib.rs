// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! Firewall management — iptables rule generation and CRUD via DB.
//!
//! Security-first defaults: DROP input, DROP forward, ACCEPT output.
//! All rule application is atomic via `iptables-restore`.
//!
//! Zone-based security model: WAN, LAN, DMZ, MGMT, GUEST.

pub mod ids_response;
pub mod iptables;
pub mod qos;
pub mod wan;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ── Error types ─────────────────────────────────────────────────────

/// Errors from the firewall crate.
#[derive(Debug, thiserror::Error)]
pub enum FwError {
    /// Database query failed.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// JSON serialization/deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Rule not found in the database.
    #[error("firewall rule id={0} not found")]
    RuleNotFound(i64),

    /// Rule is missing a required field.
    #[error("rule missing id")]
    MissingId,

    /// Invalid rule JSON stored in the database.
    #[error("invalid JSON in rule id={id}: {json}")]
    InvalidRuleJson { id: i64, json: String },

    /// iptables command failed.
    #[error("iptables command failed: {0}")]
    IptablesFailed(String),

    /// Custom zone not found.
    #[error("custom zone id={0} not found")]
    CustomZoneNotFound(i64),

    /// Custom zone name conflict.
    #[error("custom zone name '{0}' already exists")]
    CustomZoneNameConflict(String),

    /// Custom zone VLAN conflict.
    #[error("VLAN {0} already assigned to another zone")]
    CustomZoneVlanConflict(u16),

    /// Validation error.
    #[error("validation error: {0}")]
    Validation(String),

    /// WAN routing command failed.
    #[error("WAN routing error: {0}")]
    WanRouting(String),

    /// Wrapped anyhow error for internal context propagation.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

// ── Zone model ──────────────────────────────────────────────────────

/// Network zone classification for firewall rules.
///
/// Core zones: WAN, LAN, DMZ. Others kept for compatibility.
///
/// ```
/// use sfgw_fw::FirewallZone;
///
/// let zone = FirewallZone::from_role("wan");
/// assert_eq!(zone, FirewallZone::Wan);
/// assert_eq!(zone.to_string(), "wan");
///
/// // Unknown roles become Custom
/// let custom = FirewallZone::from_role("cameras");
/// assert!(matches!(custom, FirewallZone::Custom(_)));
/// assert_eq!(custom.to_string(), "cameras");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallZone {
    Wan,
    Lan,
    Dmz,
    Guest,
    #[serde(rename = "iot")]
    IoT,
    Mgmt,
    Vpn,
    Custom(String),
}

impl std::fmt::Display for FirewallZone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wan => write!(f, "wan"),
            Self::Lan => write!(f, "lan"),
            Self::Dmz => write!(f, "dmz"),
            Self::Guest => write!(f, "guest"),
            Self::IoT => write!(f, "iot"),
            Self::Mgmt => write!(f, "mgmt"),
            Self::Vpn => write!(f, "vpn"),
            Self::Custom(name) => write!(f, "{name}"),
        }
    }
}

impl FirewallZone {
    /// Parse a zone from a zone name string (e.g. from the `networks.zone` column).
    pub fn from_role(role: &str) -> Self {
        match role.to_lowercase().as_str() {
            "wan" => Self::Wan,
            "lan" => Self::Lan,
            "dmz" => Self::Dmz,
            "guest" => Self::Guest,
            "iot" => Self::IoT,
            "mgmt" => Self::Mgmt,
            "vpn" => Self::Vpn,
            other => Self::Custom(other.to_string()),
        }
    }
}

// ── Zone policy ─────────────────────────────────────────────────────

/// Per-zone default security policies with assigned interfaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonePolicy {
    pub zone: FirewallZone,
    pub interfaces: Vec<String>,
    /// VLAN ID from the networks table. `None` for WAN (pvid=0, not an internal VLAN).
    pub vlan_id: Option<u16>,
}

// ── Custom zone model ───────────────────────────────────────────────

/// A user-defined custom zone (IoT, VPN, or fully custom).
///
/// Custom zones are stored in the `custom_zones` DB table and generate
/// iptables rules based on their policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomZone {
    pub id: Option<i64>,
    pub name: String,
    pub vlan_id: u16,
    pub policy_inbound: Action,
    pub policy_outbound: Action,
    pub policy_forward: Action,
    pub allowed_services: Vec<AllowedService>,
    pub description: String,
}

/// A service allowed through a custom zone's firewall policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedService {
    pub protocol: String,
    pub port: u16,
    #[serde(default)]
    pub description: Option<String>,
}

/// Request to create or update a custom zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomZoneRequest {
    pub name: String,
    pub vlan_id: u16,
    #[serde(default = "default_drop")]
    pub policy_inbound: Action,
    #[serde(default = "default_drop")]
    pub policy_outbound: Action,
    #[serde(default = "default_drop")]
    pub policy_forward: Action,
    #[serde(default)]
    pub allowed_services: Vec<AllowedService>,
    #[serde(default)]
    pub description: String,
}

/// Request to update only a custom zone's policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomZonePolicyUpdate {
    pub policy_inbound: Action,
    pub policy_outbound: Action,
    pub policy_forward: Action,
    #[serde(default)]
    pub allowed_services: Vec<AllowedService>,
}

fn default_drop() -> Action {
    Action::Drop
}

/// Validate a custom zone name: lowercase alphanumeric + hyphens, 1-32 chars,
/// must start with a letter, must not collide with built-in zone names.
#[must_use]
pub fn validate_zone_name(name: &str) -> Result<(), FwError> {
    if name.is_empty() || name.len() > 32 {
        return Err(FwError::Validation(
            "zone name must be 1-32 characters".to_string(),
        ));
    }

    if !name.chars().next().map_or(false, |c| c.is_ascii_lowercase()) {
        return Err(FwError::Validation(
            "zone name must start with a lowercase letter".to_string(),
        ));
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(FwError::Validation(
            "zone name may only contain lowercase letters, digits, and hyphens".to_string(),
        ));
    }

    // Built-in zone names cannot be used.
    const RESERVED: &[&str] = &["wan", "lan", "dmz", "guest", "mgmt", "void"];
    if RESERVED.contains(&name) {
        return Err(FwError::Validation(format!(
            "'{name}' is a reserved zone name"
        )));
    }

    Ok(())
}

/// Validate a VLAN ID for custom zones: 2-4094 (VLAN 0 is WAN, VLAN 1 is void).
#[must_use]
pub fn validate_custom_vlan_id(vlan_id: u16) -> Result<(), FwError> {
    if vlan_id < 2 || vlan_id > 4094 {
        return Err(FwError::Validation(
            "VLAN ID must be between 2 and 4094".to_string(),
        ));
    }
    Ok(())
}

// ── WAN failover / load-balance ─────────────────────────────────────

/// WAN failover/load-balance group configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanGroup {
    pub name: String,
    pub mode: WanMode,
    pub interfaces: Vec<WanMember>,
}

/// WAN group operating mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WanMode {
    Failover,
    LoadBalance,
}

/// A single WAN interface within a WAN group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanMember {
    pub interface: String,
    /// Weight for load balancing (1-100).
    pub weight: u8,
    /// Gateway IP address.
    pub gateway: String,
    /// Priority for failover (lower = higher priority).
    pub priority: u8,
    /// IP address to ping for health checks.
    pub check_target: String,
    pub enabled: bool,
}

// ── Rule action ─────────────────────────────────────────────────────

/// What to do with a matched packet.
///
/// ```
/// use sfgw_fw::Action;
///
/// assert_eq!(Action::Drop.to_string(), "drop");
/// assert_eq!(Action::Accept.to_string(), "accept");
/// assert_eq!(Action::Reject.to_string(), "reject");
/// assert_eq!(Action::Masquerade.to_string(), "masquerade");
///
/// // JSON serialization uses lowercase
/// let json = serde_json::to_string(&Action::Accept).unwrap();
/// assert_eq!(json, r#""accept""#);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Accept,
    Drop,
    Reject,
    Masquerade,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accept => write!(f, "accept"),
            Self::Drop => write!(f, "drop"),
            Self::Reject => write!(f, "reject"),
            Self::Masquerade => write!(f, "masquerade"),
        }
    }
}

// ── Rule detail (stored as JSON in the `rule` column) ───────────────

/// The JSON payload stored in the `rule` column of `firewall_rules`.
///
/// ```
/// use sfgw_fw::{RuleDetail, Action};
///
/// // Minimal rule — defaults to "any" for protocol/source/destination
/// let json = r#"{"action": "accept"}"#;
/// let rule: RuleDetail = serde_json::from_str(json).unwrap();
/// assert_eq!(rule.action, Action::Accept);
/// assert_eq!(rule.protocol, "any");
/// assert_eq!(rule.source, "any");
/// assert!(rule.port.is_none());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDetail {
    pub action: Action,
    #[serde(default = "default_any")]
    pub protocol: String,
    #[serde(default = "default_any")]
    pub source: String,
    #[serde(default = "default_any")]
    pub destination: String,
    #[serde(default)]
    pub port: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
    /// Optional VLAN ID this rule targets.
    #[serde(default)]
    pub vlan: Option<u16>,
    /// Optional rate limit, e.g. "10/second".
    #[serde(default)]
    pub rate_limit: Option<String>,
}

fn default_any() -> String {
    "any".to_string()
}

// ── Firewall rule (full DB row) ─────────────────────────────────────

/// A complete firewall rule as stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: Option<i64>,
    pub chain: String,
    pub priority: i32,
    pub detail: RuleDetail,
    pub enabled: bool,
}

// ── Default policy ──────────────────────────────────────────────────

/// Default chain policies — security-first!
///
/// Defaults to DROP input, DROP forward, ACCEPT output — the only sane
/// default for a security gateway.
///
/// ```
/// use sfgw_fw::{FirewallPolicy, Action};
///
/// let policy = FirewallPolicy::default();
/// assert_eq!(policy.default_input, Action::Drop);
/// assert_eq!(policy.default_forward, Action::Drop);
/// assert_eq!(policy.default_output, Action::Accept);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallPolicy {
    pub default_input: Action,
    pub default_forward: Action,
    pub default_output: Action,
}

impl Default for FirewallPolicy {
    fn default() -> Self {
        Self {
            default_input: Action::Drop,
            default_forward: Action::Drop,
            default_output: Action::Accept,
        }
    }
}

// ── Port forwarding ─────────────────────────────────────────────────

/// A DNAT port-forwarding entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForward {
    pub protocol: String,
    pub external_port: u16,
    pub internal_ip: String,
    pub internal_port: u16,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// WAN interface to bind this port forward to.
    /// `None` = apply on all WAN ports, `Some` = specific WAN interface only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_interface: Option<String>,
}

fn default_true() -> bool {
    true
}

// ── DB row ──────────────────────────────────────────────────────────

/// Raw row from the `firewall_rules` table.
#[derive(Debug, Clone)]
struct DbRow {
    id: i64,
    chain: String,
    priority: i32,
    rule_json: String,
    enabled: bool,
}

// ── DB CRUD ─────────────────────────────────────────────────────────

/// Load all firewall rules from the database, ordered by priority.
pub async fn load_rules(db: &sfgw_db::Db) -> Result<Vec<FirewallRule>, FwError> {
    let conn = db.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, chain, priority, rule, enabled FROM firewall_rules ORDER BY priority ASC, id ASC")
        .context("failed to prepare firewall_rules query")?;

    let rows = stmt
        .query_map([], |row| {
            Ok(DbRow {
                id: row.get(0)?,
                chain: row.get(1)?,
                priority: row.get(2)?,
                rule_json: row.get(3)?,
                enabled: row.get::<_, i32>(4)? != 0,
            })
        })
        .context("failed to query firewall_rules")?;

    let mut rules = Vec::new();
    for row in rows {
        let row = row.context("failed to read firewall_rules row")?;
        let detail: RuleDetail = serde_json::from_str(&row.rule_json)
            .with_context(|| format!("invalid JSON in rule id={}: {}", row.id, row.rule_json))?;
        rules.push(FirewallRule {
            id: Some(row.id),
            chain: row.chain,
            priority: row.priority,
            detail,
            enabled: row.enabled,
        });
    }

    tracing::info!("loaded {} firewall rules from database", rules.len());
    Ok(rules)
}

/// Load only enabled rules.
pub async fn load_enabled_rules(db: &sfgw_db::Db) -> Result<Vec<FirewallRule>, FwError> {
    let all = load_rules(db).await?;
    Ok(all.into_iter().filter(|r| r.enabled).collect())
}

/// Insert a new firewall rule. Returns the new row ID.
pub async fn insert_rule(db: &sfgw_db::Db, rule: &FirewallRule) -> Result<i64, FwError> {
    let json = serde_json::to_string(&rule.detail).context("failed to serialize rule detail")?;
    let enabled_int: i32 = if rule.enabled { 1 } else { 0 };
    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO firewall_rules (chain, priority, rule, enabled) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![rule.chain, rule.priority, json, enabled_int],
    )
    .context("failed to insert firewall rule")?;
    let id = conn.last_insert_rowid();
    tracing::info!("inserted firewall rule id={id}");
    Ok(id)
}

/// Update an existing firewall rule by ID.
pub async fn update_rule(db: &sfgw_db::Db, rule: &FirewallRule) -> Result<(), FwError> {
    let id = rule.id.ok_or(FwError::MissingId)?;
    let json = serde_json::to_string(&rule.detail).context("failed to serialize rule detail")?;
    let enabled_int: i32 = if rule.enabled { 1 } else { 0 };
    let conn = db.lock().await;
    let affected = conn
        .execute(
            "UPDATE firewall_rules SET chain = ?1, priority = ?2, rule = ?3, enabled = ?4 WHERE id = ?5",
            rusqlite::params![rule.chain, rule.priority, json, enabled_int, id],
        )
        .context("failed to update firewall rule")?;
    if affected != 1 {
        return Err(FwError::RuleNotFound(id));
    }
    tracing::info!("updated firewall rule id={id}");
    Ok(())
}

/// Delete a firewall rule by ID.
pub async fn delete_rule(db: &sfgw_db::Db, id: i64) -> Result<(), FwError> {
    let conn = db.lock().await;
    let affected = conn
        .execute(
            "DELETE FROM firewall_rules WHERE id = ?1",
            rusqlite::params![id],
        )
        .context("failed to delete firewall rule")?;
    if affected != 1 {
        return Err(FwError::RuleNotFound(id));
    }
    tracing::info!("deleted firewall rule id={id}");
    Ok(())
}

/// Toggle the enabled state of a rule.
pub async fn toggle_rule(db: &sfgw_db::Db, id: i64, enabled: bool) -> Result<(), FwError> {
    let enabled_int: i32 = if enabled { 1 } else { 0 };
    let conn = db.lock().await;
    let affected = conn
        .execute(
            "UPDATE firewall_rules SET enabled = ?1 WHERE id = ?2",
            rusqlite::params![enabled_int, id],
        )
        .context("failed to toggle firewall rule")?;
    if affected != 1 {
        return Err(FwError::RuleNotFound(id));
    }
    tracing::info!("toggled firewall rule id={id} enabled={enabled}");
    Ok(())
}

/// Load rules, generate iptables config, and atomically apply it.
/// This is the main entry point — call after any rule change.
///
/// Now zone-aware: loads interface zones from the DB and generates
/// zone-based iptables rules instead of hardcoded interface names.
pub async fn apply_rules(db: &sfgw_db::Db) -> Result<(), FwError> {
    let rules = load_enabled_rules(db).await?;
    let zones = load_interface_zones(db).await?;
    let wan_groups = load_wan_groups(db).await?;
    let custom_zones = load_custom_zones(db).await.unwrap_or_default();
    let policy = FirewallPolicy::default();

    let config = if zones.is_empty() {
        // Fallback to legacy generation when no zones are configured.
        iptables::generate_ruleset(&rules, &policy)
    } else {
        iptables::generate_zone_ruleset_with_custom(
            &zones,
            &rules,
            &policy,
            &[],
            &custom_zones,
        )
    };

    iptables::apply_ruleset(&config).await?;

    // Apply WAN routing if groups are configured (non-fatal — don't block startup).
    if !wan_groups.is_empty()
        && let Err(e) = wan::apply_wan_routing(&wan_groups).await
    {
        tracing::error!("WAN routing failed (continuing): {e}");
    }

    tracing::info!("iptables rules applied successfully (zone-aware)");
    Ok(())
}

// ── Zone DB functions ───────────────────────────────────────────────

/// Load interface-to-zone assignments for firewall rule generation.
///
/// Zones are derived from the PVID of each interface joined to the networks
/// table, not from the removed `role` column:
///
/// - Internal interfaces (pvid > 0): zone and vlan_id come from
///   `networks JOIN interfaces ON pvid = vlan_id`.
/// - WAN interfaces (pvid = 0): placed in the WAN zone with `vlan_id: None`.
///
/// For bridged zones (LAN, MGMT, DMZ, GUEST), iptables sees traffic on
/// the bridge interface (e.g. `br-lan`), not on individual switch ports.
/// So we use `br-{zone}` as the interface when a network entry exists.
///
/// For WAN, the raw interface names (eth8, eth9) are used directly since
/// WAN interfaces are not bridged.
///
/// Interfaces whose pvid does not match any network's vlan_id are silently
/// excluded — they have no zone assignment yet (user must configure).
pub async fn load_interface_zones(db: &sfgw_db::Db) -> Result<Vec<ZonePolicy>, FwError> {
    let conn = db.lock().await;

    // ── Internal interfaces (pvid > 0): derive zone from networks JOIN ──

    let mut stmt = conn
        .prepare(
            "SELECT i.name, n.zone, n.vlan_id \
             FROM interfaces i \
             JOIN networks n ON i.pvid = n.vlan_id \
             WHERE i.enabled = 1 AND i.pvid > 0 \
             ORDER BY n.zone, i.name",
        )
        .context("failed to prepare interfaces+networks JOIN query")?;

    // zone_name -> (vlan_id, Vec<iface_name>)
    let mut internal_map: HashMap<String, (u16, Vec<String>)> = HashMap::new();

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u16>(2)?,
            ))
        })
        .context("failed to query interfaces+networks JOIN")?;

    for row in rows {
        let (iface_name, zone_name, vlan_id) = row.context("failed to read JOIN row")?;
        internal_map
            .entry(zone_name)
            .and_modify(|(_, ifaces)| ifaces.push(iface_name.clone()))
            .or_insert_with(|| (vlan_id, vec![iface_name]));
    }

    // ── WAN interfaces (pvid = 0) ──

    let mut wan_stmt = conn
        .prepare("SELECT name FROM interfaces WHERE enabled = 1 AND pvid = 0 ORDER BY name")
        .context("failed to prepare WAN interfaces query")?;

    let wan_rows = wan_stmt
        .query_map([], |row| row.get::<_, String>(0))
        .context("failed to query WAN interfaces")?;

    let mut wan_ifaces: Vec<String> = Vec::new();
    for row in wan_rows {
        wan_ifaces.push(row.context("failed to read WAN interfaces row")?);
    }

    // ── Load enabled networks to determine which zones are bridged ──

    let mut net_stmt = conn
        .prepare("SELECT zone FROM networks WHERE enabled = 1")
        .context("failed to prepare networks query")?;

    let net_rows = net_stmt
        .query_map([], |row| row.get::<_, String>(0))
        .context("failed to query networks")?;

    let mut bridged_zones: HashSet<String> = HashSet::new();
    for row in net_rows {
        let zone = row.context("failed to read networks row")?;
        bridged_zones.insert(zone);
    }

    // ── Build ZonePolicy list ──

    let mut zones: Vec<ZonePolicy> = Vec::new();

    for (zone_name, (vlan_id, ifaces)) in internal_map {
        // For bridged zones, replace individual port interfaces with the bridge.
        let effective_ifaces = if zone_name != "void" && bridged_zones.contains(&zone_name) {
            vec![format!("br-{zone_name}")]
        } else {
            ifaces
        };

        // Skip void zone — VLAN 1 is DROP-only, not a routable zone.
        if zone_name == "void" {
            continue;
        }

        zones.push(ZonePolicy {
            zone: FirewallZone::from_role(&zone_name),
            interfaces: effective_ifaces,
            vlan_id: Some(vlan_id),
        });
    }

    // WAN zone — unbridged, no vlan_id.
    if !wan_ifaces.is_empty() {
        zones.push(ZonePolicy {
            zone: FirewallZone::Wan,
            interfaces: wan_ifaces,
            vlan_id: None,
        });
    }

    tracing::info!(
        "loaded {} zone policies from database (PVID-based)",
        zones.len()
    );
    Ok(zones)
}

/// Load WAN group configuration from the `meta` table (key: `wan_groups`).
pub async fn load_wan_groups(db: &sfgw_db::Db) -> Result<Vec<WanGroup>, FwError> {
    let conn = db.lock().await;
    let mut stmt = conn
        .prepare("SELECT value FROM meta WHERE key = 'wan_groups'")
        .context("failed to prepare meta query for wan_groups")?;

    let result: Option<String> = stmt.query_row([], |row| row.get(0)).ok();

    match result {
        Some(json) => {
            let groups: Vec<WanGroup> = serde_json::from_str(&json)
                .context("failed to parse wan_groups JSON from meta table")?;
            tracing::info!("loaded {} WAN groups from database", groups.len());
            Ok(groups)
        }
        None => Ok(Vec::new()),
    }
}

/// Save WAN group configuration to the `meta` table (key: `wan_groups`).
pub async fn save_wan_groups(db: &sfgw_db::Db, groups: &[WanGroup]) -> Result<(), FwError> {
    let json = serde_json::to_string(groups).context("failed to serialize wan_groups")?;
    let conn = db.lock().await;
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('wan_groups', ?1)",
        rusqlite::params![json],
    )
    .context("failed to save wan_groups to meta table")?;
    tracing::info!("saved {} WAN groups to database", groups.len());
    Ok(())
}

// ── Custom zone DB CRUD ─────────────────────────────────────────────

/// Parse an `Action` from a policy string ("drop", "accept").
fn parse_action(s: &str) -> Action {
    match s.to_lowercase().as_str() {
        "accept" => Action::Accept,
        _ => Action::Drop,
    }
}

/// Serialize an `Action` to a policy string for DB storage.
fn action_to_str(a: &Action) -> &'static str {
    match a {
        Action::Accept => "accept",
        Action::Drop => "drop",
        Action::Reject => "reject",
        Action::Masquerade => "masquerade",
    }
}

/// Load all custom zones from the database.
pub async fn load_custom_zones(db: &sfgw_db::Db) -> Result<Vec<CustomZone>, FwError> {
    let conn = db.lock().await;
    let mut stmt = conn
        .prepare(
            "SELECT id, name, vlan_id, policy_inbound, policy_outbound, \
             policy_forward, allowed_services, description \
             FROM custom_zones ORDER BY name",
        )
        .context("failed to prepare custom_zones query")?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u16>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .context("failed to query custom_zones")?;

    let mut zones = Vec::new();
    for row in rows {
        let (id, name, vlan_id, pol_in, pol_out, pol_fwd, services_json, description) =
            row.context("failed to read custom_zones row")?;

        let allowed_services: Vec<AllowedService> =
            serde_json::from_str(&services_json).unwrap_or_default();

        zones.push(CustomZone {
            id: Some(id),
            name,
            vlan_id,
            policy_inbound: parse_action(&pol_in),
            policy_outbound: parse_action(&pol_out),
            policy_forward: parse_action(&pol_fwd),
            allowed_services,
            description,
        });
    }

    tracing::info!("loaded {} custom zones from database", zones.len());
    Ok(zones)
}

/// Get a single custom zone by ID.
pub async fn get_custom_zone(db: &sfgw_db::Db, id: i64) -> Result<CustomZone, FwError> {
    let conn = db.lock().await;
    let result = conn.query_row(
        "SELECT id, name, vlan_id, policy_inbound, policy_outbound, \
         policy_forward, allowed_services, description \
         FROM custom_zones WHERE id = ?1",
        rusqlite::params![id],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u16>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        },
    );

    match result {
        Ok((id, name, vlan_id, pol_in, pol_out, pol_fwd, services_json, description)) => {
            let allowed_services: Vec<AllowedService> =
                serde_json::from_str(&services_json).unwrap_or_default();
            Ok(CustomZone {
                id: Some(id),
                name,
                vlan_id,
                policy_inbound: parse_action(&pol_in),
                policy_outbound: parse_action(&pol_out),
                policy_forward: parse_action(&pol_fwd),
                allowed_services,
                description,
            })
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Err(FwError::CustomZoneNotFound(id)),
        Err(e) => Err(FwError::Database(e)),
    }
}

/// Insert a new custom zone. Returns the new row ID.
///
/// Validates name, VLAN ID, and checks for conflicts with existing zones.
pub async fn insert_custom_zone(db: &sfgw_db::Db, req: &CustomZoneRequest) -> Result<i64, FwError> {
    validate_zone_name(&req.name)?;
    validate_custom_vlan_id(req.vlan_id)?;

    let services_json =
        serde_json::to_string(&req.allowed_services).context("failed to serialize services")?;

    let conn = db.lock().await;

    // Check VLAN conflict with networks table (built-in zones).
    let vlan_conflict: Option<String> = conn
        .query_row(
            "SELECT zone FROM networks WHERE vlan_id = ?1",
            rusqlite::params![req.vlan_id],
            |row| row.get(0),
        )
        .ok();
    if let Some(existing_zone) = vlan_conflict {
        return Err(FwError::Validation(format!(
            "VLAN {} is already used by built-in zone '{}'",
            req.vlan_id, existing_zone
        )));
    }

    let result = conn.execute(
        "INSERT INTO custom_zones (name, vlan_id, policy_inbound, policy_outbound, \
         policy_forward, allowed_services, description) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            req.name,
            req.vlan_id,
            action_to_str(&req.policy_inbound),
            action_to_str(&req.policy_outbound),
            action_to_str(&req.policy_forward),
            services_json,
            req.description,
        ],
    );

    match result {
        Ok(_) => {
            let id = conn.last_insert_rowid();
            tracing::info!(id, name = %req.name, vlan_id = req.vlan_id, "inserted custom zone");
            Ok(id)
        }
        Err(e) if e.to_string().contains("UNIQUE constraint failed: custom_zones.name") => {
            Err(FwError::CustomZoneNameConflict(req.name.clone()))
        }
        Err(e) if e.to_string().contains("UNIQUE constraint failed: custom_zones.vlan_id")
            || e.to_string().contains("idx_custom_zones_vlan_id") =>
        {
            Err(FwError::CustomZoneVlanConflict(req.vlan_id))
        }
        Err(e) => Err(FwError::Database(e)),
    }
}

/// Update an existing custom zone.
pub async fn update_custom_zone(
    db: &sfgw_db::Db,
    id: i64,
    req: &CustomZoneRequest,
) -> Result<(), FwError> {
    validate_zone_name(&req.name)?;
    validate_custom_vlan_id(req.vlan_id)?;

    let services_json =
        serde_json::to_string(&req.allowed_services).context("failed to serialize services")?;

    let conn = db.lock().await;

    // Check VLAN conflict with networks table (built-in zones).
    let vlan_conflict: Option<String> = conn
        .query_row(
            "SELECT zone FROM networks WHERE vlan_id = ?1",
            rusqlite::params![req.vlan_id],
            |row| row.get(0),
        )
        .ok();
    if let Some(existing_zone) = vlan_conflict {
        return Err(FwError::Validation(format!(
            "VLAN {} is already used by built-in zone '{}'",
            req.vlan_id, existing_zone
        )));
    }

    let result = conn.execute(
        "UPDATE custom_zones SET name = ?1, vlan_id = ?2, policy_inbound = ?3, \
         policy_outbound = ?4, policy_forward = ?5, allowed_services = ?6, \
         description = ?7, updated_at = datetime('now') WHERE id = ?8",
        rusqlite::params![
            req.name,
            req.vlan_id,
            action_to_str(&req.policy_inbound),
            action_to_str(&req.policy_outbound),
            action_to_str(&req.policy_forward),
            services_json,
            req.description,
            id,
        ],
    );

    match result {
        Ok(0) => Err(FwError::CustomZoneNotFound(id)),
        Ok(_) => {
            tracing::info!(id, name = %req.name, "updated custom zone");
            Ok(())
        }
        Err(e) if e.to_string().contains("UNIQUE constraint failed: custom_zones.name") => {
            Err(FwError::CustomZoneNameConflict(req.name.clone()))
        }
        Err(e) if e.to_string().contains("UNIQUE constraint failed: custom_zones.vlan_id")
            || e.to_string().contains("idx_custom_zones_vlan_id") =>
        {
            Err(FwError::CustomZoneVlanConflict(req.vlan_id))
        }
        Err(e) => Err(FwError::Database(e)),
    }
}

/// Update only the policy of a custom zone.
pub async fn update_custom_zone_policy(
    db: &sfgw_db::Db,
    id: i64,
    policy: &CustomZonePolicyUpdate,
) -> Result<(), FwError> {
    let services_json =
        serde_json::to_string(&policy.allowed_services).context("failed to serialize services")?;

    let conn = db.lock().await;
    let affected = conn
        .execute(
            "UPDATE custom_zones SET policy_inbound = ?1, policy_outbound = ?2, \
             policy_forward = ?3, allowed_services = ?4, updated_at = datetime('now') \
             WHERE id = ?5",
            rusqlite::params![
                action_to_str(&policy.policy_inbound),
                action_to_str(&policy.policy_outbound),
                action_to_str(&policy.policy_forward),
                services_json,
                id,
            ],
        )
        .context("failed to update custom zone policy")?;

    if affected == 0 {
        return Err(FwError::CustomZoneNotFound(id));
    }

    tracing::info!(id, "updated custom zone policy");
    Ok(())
}

/// Delete a custom zone by ID.
pub async fn delete_custom_zone(db: &sfgw_db::Db, id: i64) -> Result<(), FwError> {
    let conn = db.lock().await;
    let affected = conn
        .execute(
            "DELETE FROM custom_zones WHERE id = ?1",
            rusqlite::params![id],
        )
        .context("failed to delete custom zone")?;

    if affected == 0 {
        return Err(FwError::CustomZoneNotFound(id));
    }

    tracing::info!(id, "deleted custom zone");
    Ok(())
}

/// Build default IoT zone preset.
pub fn iot_zone_preset(vlan_id: u16) -> CustomZoneRequest {
    CustomZoneRequest {
        name: "iot".to_string(),
        vlan_id,
        policy_inbound: Action::Drop,
        policy_outbound: Action::Accept,
        policy_forward: Action::Drop,
        allowed_services: vec![
            AllowedService {
                protocol: "udp".to_string(),
                port: 53,
                description: Some("DNS".to_string()),
            },
            AllowedService {
                protocol: "udp".to_string(),
                port: 67,
                description: Some("DHCP".to_string()),
            },
        ],
        description: "IoT devices: internet-only, no inter-VLAN access".to_string(),
    }
}

/// Build default VPN zone preset.
pub fn vpn_zone_preset(vlan_id: u16) -> CustomZoneRequest {
    CustomZoneRequest {
        name: "vpn".to_string(),
        vlan_id,
        policy_inbound: Action::Drop,
        policy_outbound: Action::Accept,
        policy_forward: Action::Drop,
        allowed_services: vec![
            AllowedService {
                protocol: "udp".to_string(),
                port: 53,
                description: Some("DNS".to_string()),
            },
        ],
        description: "VPN clients: access to LAN, blocked from MGMT/DMZ".to_string(),
    }
}

// ── First-boot default rules ────────────────────────────────────────

/// Populate the `firewall_rules` table with security-first defaults on
/// first boot (i.e. when the table is empty).
///
/// These rules encode the zone-based security policy:
/// - LAN/MGMT are trusted zones with gateway access
/// - Guest gets internet only, no internal access
/// - DMZ can reach WAN but not LAN/MGMT
/// - WAN is default-deny inbound
/// - NAT masquerade on WAN egress
///
/// Connection tracking (established/related) and ICMP are handled by
/// `iptables::emit_default_rules()` which is always applied regardless of
/// DB content, so they are not duplicated here.
pub async fn create_default_rules(db: &sfgw_db::Db) -> Result<(), FwError> {
    // Only insert defaults when the table is empty (first boot).
    let count: i64 = {
        let conn = db.lock().await;
        conn.query_row("SELECT COUNT(*) FROM firewall_rules", [], |row| row.get(0))
            .context("failed to count firewall_rules")?
    };

    if count > 0 {
        tracing::debug!("firewall_rules table has {count} rules, skipping defaults");
        return Ok(());
    }

    tracing::info!("firewall_rules table is empty, inserting first-boot defaults");

    let defaults = build_default_rules();
    for rule in &defaults {
        insert_rule(db, rule).await?;
    }

    tracing::info!("inserted {} default firewall rules", defaults.len());
    Ok(())
}

/// Build the complete set of first-boot default firewall rules.
#[allow(clippy::vec_init_then_push)]
fn build_default_rules() -> Vec<FirewallRule> {
    let mut rules = Vec::new();

    // ── Forward chain (zone-to-zone policy) ─────────────────────────

    // MGMT → any: full access (management zone is fully trusted).
    rules.push(forward_rule(
        50,
        "iif:@mgmt_ifaces",
        "any",
        Action::Accept,
        Some("MGMT to any"),
    ));

    // LAN → WAN: internet access.
    rules.push(forward_rule(
        100,
        "iif:@lan_ifaces",
        "oif:@wan_ifaces",
        Action::Accept,
        Some("LAN to WAN"),
    ));

    // LAN → Guest: allow (LAN is trusted).
    rules.push(forward_rule(
        110,
        "iif:@lan_ifaces",
        "oif:@guest_ifaces",
        Action::Accept,
        Some("LAN to Guest"),
    ));

    // LAN → DMZ: allow (LAN is trusted).
    rules.push(forward_rule(
        120,
        "iif:@lan_ifaces",
        "oif:@dmz_ifaces",
        Action::Accept,
        Some("LAN to DMZ"),
    ));

    // Guest → WAN: internet only.
    rules.push(forward_rule(
        200,
        "iif:@guest_ifaces",
        "oif:@wan_ifaces",
        Action::Accept,
        Some("Guest to WAN"),
    ));

    // Guest → LAN: blocked.
    rules.push(forward_rule(
        210,
        "iif:@guest_ifaces",
        "oif:@lan_ifaces",
        Action::Drop,
        Some("Guest to LAN blocked"),
    ));

    // Guest → DMZ: blocked.
    rules.push(forward_rule(
        220,
        "iif:@guest_ifaces",
        "oif:@dmz_ifaces",
        Action::Drop,
        Some("Guest to DMZ blocked"),
    ));

    // Guest → MGMT: blocked.
    rules.push(forward_rule(
        230,
        "iif:@guest_ifaces",
        "oif:@mgmt_ifaces",
        Action::Drop,
        Some("Guest to MGMT blocked"),
    ));

    // DMZ → WAN: allow outbound.
    rules.push(forward_rule(
        300,
        "iif:@dmz_ifaces",
        "oif:@wan_ifaces",
        Action::Accept,
        Some("DMZ to WAN"),
    ));

    // DMZ → LAN: blocked.
    rules.push(forward_rule(
        310,
        "iif:@dmz_ifaces",
        "oif:@lan_ifaces",
        Action::Drop,
        Some("DMZ to LAN blocked"),
    ));

    // DMZ → MGMT: blocked.
    rules.push(forward_rule(
        320,
        "iif:@dmz_ifaces",
        "oif:@mgmt_ifaces",
        Action::Drop,
        Some("DMZ to MGMT blocked"),
    ));

    // WAN → any: default deny inbound.
    rules.push(forward_rule(
        400,
        "iif:@wan_ifaces",
        "any",
        Action::Drop,
        Some("default deny inbound"),
    ));

    // ── Input chain (traffic TO the gateway) ────────────────────────

    // SSH from MGMT only (management access).
    rules.push(input_rule(
        31,
        "tcp",
        "iif:@mgmt_ifaces",
        Some("22"),
        Action::Accept,
        Some("SSH from MGMT"),
    ));

    // DNS from LAN (TCP).
    rules.push(input_rule(
        40,
        "tcp",
        "iif:@lan_ifaces",
        Some("53"),
        Action::Accept,
        Some("DNS TCP from LAN"),
    ));

    // DNS from LAN (UDP).
    rules.push(input_rule(
        41,
        "udp",
        "iif:@lan_ifaces",
        Some("53"),
        Action::Accept,
        Some("DNS UDP from LAN"),
    ));

    // DNS from Guest (TCP).
    rules.push(input_rule(
        42,
        "tcp",
        "iif:@guest_ifaces",
        Some("53"),
        Action::Accept,
        Some("DNS TCP from Guest"),
    ));

    // DNS from Guest (UDP).
    rules.push(input_rule(
        43,
        "udp",
        "iif:@guest_ifaces",
        Some("53"),
        Action::Accept,
        Some("DNS UDP from Guest"),
    ));

    // DNS from MGMT (TCP).
    rules.push(input_rule(
        44,
        "tcp",
        "iif:@mgmt_ifaces",
        Some("53"),
        Action::Accept,
        Some("DNS TCP from MGMT"),
    ));

    // DNS from MGMT (UDP).
    rules.push(input_rule(
        45,
        "udp",
        "iif:@mgmt_ifaces",
        Some("53"),
        Action::Accept,
        Some("DNS UDP from MGMT"),
    ));

    // DNS from DMZ (TCP).
    rules.push(input_rule(
        46,
        "tcp",
        "iif:@dmz_ifaces",
        Some("53"),
        Action::Accept,
        Some("DNS TCP from DMZ"),
    ));

    // DNS from DMZ (UDP).
    rules.push(input_rule(
        47,
        "udp",
        "iif:@dmz_ifaces",
        Some("53"),
        Action::Accept,
        Some("DNS UDP from DMZ"),
    ));

    // DHCP from any zone (broadcast-based, must be open).
    rules.push(input_rule(
        50,
        "udp",
        "any",
        Some("67:68"),
        Action::Accept,
        Some("DHCP from any"),
    ));

    // HTTPS from MGMT only (web UI — management zone only).
    rules.push(input_rule(
        60,
        "tcp",
        "iif:@mgmt_ifaces",
        Some("443"),
        Action::Accept,
        Some("HTTPS from MGMT"),
    ));

    // Inform protocol from MGMT only (device adoption).
    rules.push(input_rule(
        70,
        "tcp",
        "iif:@mgmt_ifaces",
        Some("8080"),
        Action::Accept,
        Some("Inform from MGMT"),
    ));

    // Drop all input from WAN (defense-in-depth, policy is DROP anyway).
    rules.push(input_rule(
        900,
        "any",
        "iif:@wan_ifaces",
        None,
        Action::Drop,
        Some("drop all WAN input"),
    ));

    // ── Postrouting chain (NAT) ─────────────────────────────────────

    // Masquerade on WAN egress.
    rules.push(FirewallRule {
        id: None,
        chain: "postrouting".to_string(),
        priority: 100,
        detail: RuleDetail {
            action: Action::Masquerade,
            protocol: "any".to_string(),
            source: "any".to_string(),
            destination: "oif:@wan_ifaces".to_string(),
            port: None,
            comment: Some("NAT masquerade WAN".to_string()),
            vlan: None,
            rate_limit: None,
        },
        enabled: true,
    });

    rules
}

/// Helper: build a forward-chain rule.
fn forward_rule(
    priority: i32,
    source: &str,
    destination: &str,
    action: Action,
    comment: Option<&str>,
) -> FirewallRule {
    FirewallRule {
        id: None,
        chain: "forward".to_string(),
        priority,
        detail: RuleDetail {
            action,
            protocol: "any".to_string(),
            source: source.to_string(),
            destination: destination.to_string(),
            port: None,
            comment: comment.map(|s| s.to_string()),
            vlan: None,
            rate_limit: None,
        },
        enabled: true,
    }
}

/// Helper: build an input-chain rule.
fn input_rule(
    priority: i32,
    protocol: &str,
    source: &str,
    port: Option<&str>,
    action: Action,
    comment: Option<&str>,
) -> FirewallRule {
    FirewallRule {
        id: None,
        chain: "input".to_string(),
        priority,
        detail: RuleDetail {
            action,
            protocol: protocol.to_string(),
            source: source.to_string(),
            destination: "any".to_string(),
            port: port.map(|s| s.to_string()),
            comment: comment.map(|s| s.to_string()),
            vlan: None,
            rate_limit: None,
        },
        enabled: true,
    }
}
