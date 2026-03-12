// SPDX-License-Identifier: AGPL-3.0-or-later

//! Firewall management — nftables rule generation and CRUD via DB.
//!
//! Security-first defaults: DROP input, DROP forward, ACCEPT output.
//! All rule application is atomic via `nft -f`.

pub mod nft;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ── Zone model ──────────────────────────────────────────────────────

/// Network zone classification for firewall rules.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallZone {
    Wan,
    Lan,
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
            Self::Guest => write!(f, "guest"),
            Self::IoT => write!(f, "iot"),
            Self::Mgmt => write!(f, "mgmt"),
            Self::Vpn => write!(f, "vpn"),
            Self::Custom(name) => write!(f, "{name}"),
        }
    }
}

// ── Rule action ─────────────────────────────────────────────────────

/// What to do with a matched packet.
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
pub async fn load_rules(db: &sfgw_db::Db) -> Result<Vec<FirewallRule>> {
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
pub async fn load_enabled_rules(db: &sfgw_db::Db) -> Result<Vec<FirewallRule>> {
    let all = load_rules(db).await?;
    Ok(all.into_iter().filter(|r| r.enabled).collect())
}

/// Insert a new firewall rule. Returns the new row ID.
pub async fn insert_rule(db: &sfgw_db::Db, rule: &FirewallRule) -> Result<i64> {
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
pub async fn update_rule(db: &sfgw_db::Db, rule: &FirewallRule) -> Result<()> {
    let id = rule.id.context("cannot update rule without id")?;
    let json = serde_json::to_string(&rule.detail).context("failed to serialize rule detail")?;
    let enabled_int: i32 = if rule.enabled { 1 } else { 0 };
    let conn = db.lock().await;
    let affected = conn
        .execute(
            "UPDATE firewall_rules SET chain = ?1, priority = ?2, rule = ?3, enabled = ?4 WHERE id = ?5",
            rusqlite::params![rule.chain, rule.priority, json, enabled_int, id],
        )
        .context("failed to update firewall rule")?;
    anyhow::ensure!(affected == 1, "firewall rule id={id} not found");
    tracing::info!("updated firewall rule id={id}");
    Ok(())
}

/// Delete a firewall rule by ID.
pub async fn delete_rule(db: &sfgw_db::Db, id: i64) -> Result<()> {
    let conn = db.lock().await;
    let affected = conn
        .execute("DELETE FROM firewall_rules WHERE id = ?1", rusqlite::params![id])
        .context("failed to delete firewall rule")?;
    anyhow::ensure!(affected == 1, "firewall rule id={id} not found");
    tracing::info!("deleted firewall rule id={id}");
    Ok(())
}

/// Toggle the enabled state of a rule.
pub async fn toggle_rule(db: &sfgw_db::Db, id: i64, enabled: bool) -> Result<()> {
    let enabled_int: i32 = if enabled { 1 } else { 0 };
    let conn = db.lock().await;
    let affected = conn
        .execute(
            "UPDATE firewall_rules SET enabled = ?1 WHERE id = ?2",
            rusqlite::params![enabled_int, id],
        )
        .context("failed to toggle firewall rule")?;
    anyhow::ensure!(affected == 1, "firewall rule id={id} not found");
    tracing::info!("toggled firewall rule id={id} enabled={enabled}");
    Ok(())
}

/// Load rules, generate nftables config, and atomically apply it.
/// This is the main entry point — call after any rule change.
pub async fn apply_rules(db: &sfgw_db::Db) -> Result<()> {
    let rules = load_enabled_rules(db).await?;
    let policy = FirewallPolicy::default();
    let config = nft::generate_ruleset(&rules, &policy);
    nft::apply_ruleset(&config).await?;
    tracing::info!("firewall rules applied successfully");
    Ok(())
}
