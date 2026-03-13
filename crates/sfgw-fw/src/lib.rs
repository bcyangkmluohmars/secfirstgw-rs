// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! Firewall management — nftables rule generation and CRUD via DB.
//!
//! Security-first defaults: DROP input, DROP forward, ACCEPT output.
//! All rule application is atomic via `nft -f`.
//!
//! Zone-based security model: WAN, LAN, DMZ, MGMT, GUEST.

pub mod nft;
pub mod wan;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

    /// nftables command failed.
    #[error("nft command failed: {0}")]
    NftFailed(String),

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
    /// Parse a zone from the `role` column in the interfaces table.
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
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accept => write!(f, "accept"),
            Self::Drop => write!(f, "drop"),
            Self::Reject => write!(f, "reject"),
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
    #[serde(flatten)]
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

/// Load rules, generate nftables config, and atomically apply it.
/// This is the main entry point — call after any rule change.
///
/// Now zone-aware: loads interface zones from the DB and generates
/// zone-based nftables rules instead of hardcoded interface names.
pub async fn apply_rules(db: &sfgw_db::Db) -> Result<(), FwError> {
    let rules = load_enabled_rules(db).await?;
    let zones = load_interface_zones(db).await?;
    let wan_groups = load_wan_groups(db).await?;
    let policy = FirewallPolicy::default();

    let config = if zones.is_empty() {
        // Fallback to legacy generation when no zones are configured.
        nft::generate_ruleset(&rules, &policy)
    } else {
        nft::generate_zone_ruleset(&zones, &rules, &policy, &[])
    };

    nft::apply_ruleset(&config).await?;

    // Apply WAN routing if groups are configured.
    if !wan_groups.is_empty() {
        wan::apply_wan_routing(&wan_groups).await?;
    }

    tracing::info!("firewall rules applied successfully (zone-aware)");
    Ok(())
}

// ── Zone DB functions ───────────────────────────────────────────────

/// Load interface-to-zone assignments from the `interfaces` table,
/// grouping by the `role` column.
pub async fn load_interface_zones(db: &sfgw_db::Db) -> Result<Vec<ZonePolicy>, FwError> {
    let conn = db.lock().await;
    let mut stmt = conn
        .prepare("SELECT name, role FROM interfaces WHERE enabled = 1 ORDER BY role, name")
        .context("failed to prepare interfaces query")?;

    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .context("failed to query interfaces")?;

    let mut zone_map: HashMap<String, Vec<String>> = HashMap::new();
    for row in rows {
        let (name, role) = row.context("failed to read interfaces row")?;
        zone_map.entry(role).or_default().push(name);
    }

    let zones = zone_map
        .into_iter()
        .map(|(role, interfaces)| ZonePolicy {
            zone: FirewallZone::from_role(&role),
            interfaces,
        })
        .collect();

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
