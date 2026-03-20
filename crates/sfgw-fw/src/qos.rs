// SPDX-License-Identifier: AGPL-3.0-or-later

//! Traffic shaping / QoS via `tc` (traffic control) + iptables MARK rules.
//!
//! Uses HTB (Hierarchical Token Bucket) qdiscs with four traffic classes
//! per interface:
//!
//! - **High** (mark 1, class 1:10): VoIP, gaming — low latency, guaranteed bandwidth
//! - **Normal** (mark 2, class 1:20): Web browsing — standard traffic
//! - **Low** (mark 3, class 1:30): Bulk downloads, P2P — best effort
//! - **Default** (mark 0, class 1:40): Unclassified — catch-all
//!
//! QoS rules define match criteria that map packets to classes via iptables
//! mangle table MARK targets. The `tc` HTB qdisc enforces bandwidth limits
//! and priorities per class.
//!
//! For ingress shaping we use an IFB (Intermediate Functional Block) device
//! to redirect incoming traffic through an HTB qdisc, since `tc` cannot
//! directly shape ingress.

use crate::FwError;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ── QoS priority classes ────────────────────────────────────────────

/// Traffic class with associated MARK value and tc class ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QosClass {
    /// VoIP, gaming, interactive — mark 1, class 1:10
    High,
    /// Web, streaming — mark 2, class 1:20
    Normal,
    /// Bulk, P2P, updates — mark 3, class 1:30
    Low,
    /// Unclassified — mark 0, class 1:40
    Default,
}

impl QosClass {
    /// The iptables MARK value for this class.
    pub const fn mark(self) -> u32 {
        match self {
            Self::High => 1,
            Self::Normal => 2,
            Self::Low => 3,
            Self::Default => 0,
        }
    }

    /// The tc class minor ID (e.g. `1:10`).
    pub const fn class_minor(self) -> u16 {
        match self {
            Self::High => 10,
            Self::Normal => 20,
            Self::Low => 30,
            Self::Default => 40,
        }
    }

    /// Map a priority value (1-7) to a QoS class.
    pub fn from_priority(p: u8) -> Self {
        match p {
            1..=2 => Self::High,
            3..=4 => Self::Normal,
            5..=6 => Self::Low,
            _ => Self::Default,
        }
    }

    /// Default bandwidth share (percentage of parent rate).
    pub const fn default_rate_pct(self) -> u8 {
        match self {
            Self::High => 30,
            Self::Normal => 40,
            Self::Low => 20,
            Self::Default => 10,
        }
    }

    /// tc priority (lower = higher priority in HTB).
    pub const fn tc_prio(self) -> u8 {
        match self {
            Self::High => 1,
            Self::Normal => 3,
            Self::Low => 5,
            Self::Default => 7,
        }
    }
}

// ── QoS rule (DB model) ────────────────────────────────────────────

/// A single QoS traffic shaping rule as stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosRule {
    pub id: Option<i64>,
    pub name: String,
    pub interface: String,
    /// `egress` or `ingress`.
    pub direction: String,
    /// Bandwidth limit in kbps for this rule's traffic class.
    pub bandwidth_kbps: u32,
    /// Priority 1 (highest) to 7 (lowest). Maps to QosClass.
    pub priority: u8,
    /// Match protocol: `tcp`, `udp`, `icmp`, or `None` for any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_protocol: Option<String>,
    /// Start of port range to match. `None` = any port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_port_min: Option<u16>,
    /// End of port range. `None` = same as `match_port_min`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_port_max: Option<u16>,
    /// IP address or CIDR to match. `None` = any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_ip: Option<String>,
    /// DSCP value 0-63 to match. `None` = any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_dscp: Option<u8>,
    pub enabled: bool,
}

// ── Input validation ────────────────────────────────────────────────

/// Validate a QoS rule's fields before insertion/update.
fn validate_rule(rule: &QosRule) -> Result<(), FwError> {
    // Name: non-empty, alphanumeric + dashes/underscores
    if rule.name.is_empty() || rule.name.len() > 64 {
        return Err(FwError::Internal(anyhow::anyhow!(
            "QoS rule name must be 1-64 characters"
        )));
    }
    if !rule
        .name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ')
    {
        return Err(FwError::Internal(anyhow::anyhow!(
            "QoS rule name contains invalid characters"
        )));
    }

    // Interface: validate format (alphanumeric + dash)
    validate_interface_name(&rule.interface)?;

    // Direction
    if rule.direction != "egress" && rule.direction != "ingress" {
        return Err(FwError::Internal(anyhow::anyhow!(
            "QoS direction must be 'egress' or 'ingress'"
        )));
    }

    // Bandwidth: 1 kbps to 10 Gbps
    if rule.bandwidth_kbps == 0 || rule.bandwidth_kbps > 10_000_000 {
        return Err(FwError::Internal(anyhow::anyhow!(
            "QoS bandwidth must be 1-10000000 kbps"
        )));
    }

    // Priority: 1-7
    if rule.priority == 0 || rule.priority > 7 {
        return Err(FwError::Internal(anyhow::anyhow!(
            "QoS priority must be 1-7"
        )));
    }

    // Protocol
    if let Some(ref proto) = rule.match_protocol {
        match proto.as_str() {
            "tcp" | "udp" | "icmp" | "icmpv6" => {}
            _ => {
                return Err(FwError::Internal(anyhow::anyhow!(
                    "QoS match_protocol must be tcp, udp, icmp, or icmpv6"
                )));
            }
        }
    }

    // Port range
    if let Some(min) = rule.match_port_min {
        if min == 0 {
            return Err(FwError::Internal(anyhow::anyhow!(
                "QoS port must be 1-65535"
            )));
        }
        if let Some(max) = rule.match_port_max
            && max < min
        {
            return Err(FwError::Internal(anyhow::anyhow!(
                "QoS port range end must be >= start"
            )));
        }
    }

    // IP/CIDR validation
    if let Some(ref ip) = rule.match_ip {
        validate_ip_or_cidr(ip)?;
    }

    // DSCP
    if let Some(dscp) = rule.match_dscp
        && dscp > 63
    {
        return Err(FwError::Internal(anyhow::anyhow!("QoS DSCP must be 0-63")));
    }

    Ok(())
}

/// Validate interface name: letters, digits, dashes only, max 15 chars (Linux limit).
fn validate_interface_name(name: &str) -> Result<(), FwError> {
    if name.is_empty() || name.len() > 15 {
        return Err(FwError::Internal(anyhow::anyhow!(
            "interface name must be 1-15 characters"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
    {
        return Err(FwError::Internal(anyhow::anyhow!(
            "interface name contains invalid characters"
        )));
    }
    Ok(())
}

/// Validate an IP address or CIDR notation string.
fn validate_ip_or_cidr(s: &str) -> Result<(), FwError> {
    if let Some((ip_part, prefix_part)) = s.split_once('/') {
        let ip: IpAddr = ip_part
            .parse()
            .map_err(|_| FwError::Internal(anyhow::anyhow!("invalid IP in CIDR: {s}")))?;
        let prefix: u8 = prefix_part
            .parse()
            .map_err(|_| FwError::Internal(anyhow::anyhow!("invalid prefix in CIDR: {s}")))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(FwError::Internal(anyhow::anyhow!(
                "CIDR prefix {prefix} exceeds max {max}"
            )));
        }
    } else {
        let _: IpAddr = s
            .parse()
            .map_err(|_| FwError::Internal(anyhow::anyhow!("invalid IP address: {s}")))?;
    }
    Ok(())
}

// ── DB CRUD ─────────────────────────────────────────────────────────

/// Load all QoS rules from the database.
pub async fn load_rules(db: &sfgw_db::Db) -> Result<Vec<QosRule>, FwError> {
    let conn = db.lock().await;
    let mut stmt = conn
        .prepare(
            "SELECT id, name, interface, direction, bandwidth_kbps, priority, \
             match_protocol, match_port_min, match_port_max, match_ip, match_dscp, enabled \
             FROM qos_rules ORDER BY priority ASC, id ASC",
        )
        .context("failed to prepare qos_rules query")?;

    let rows = stmt
        .query_map([], |row| {
            Ok(QosRule {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                interface: row.get(2)?,
                direction: row.get(3)?,
                bandwidth_kbps: row.get(4)?,
                priority: row.get(5)?,
                match_protocol: row.get(6)?,
                match_port_min: row.get(7)?,
                match_port_max: row.get(8)?,
                match_ip: row.get(9)?,
                match_dscp: row.get(10)?,
                enabled: row.get::<_, i32>(11)? != 0,
            })
        })
        .context("failed to query qos_rules")?;

    let mut rules = Vec::new();
    for row in rows {
        rules.push(row.context("failed to read qos_rules row")?);
    }

    tracing::info!("loaded {} QoS rules from database", rules.len());
    Ok(rules)
}

/// Load only enabled QoS rules.
pub async fn load_enabled_rules(db: &sfgw_db::Db) -> Result<Vec<QosRule>, FwError> {
    let all = load_rules(db).await?;
    Ok(all.into_iter().filter(|r| r.enabled).collect())
}

/// Insert a new QoS rule. Returns the new row ID.
pub async fn insert_rule(db: &sfgw_db::Db, rule: &QosRule) -> Result<i64, FwError> {
    validate_rule(rule)?;
    let enabled_int: i32 = if rule.enabled { 1 } else { 0 };
    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO qos_rules (name, interface, direction, bandwidth_kbps, priority, \
         match_protocol, match_port_min, match_port_max, match_ip, match_dscp, enabled) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![
            rule.name,
            rule.interface,
            rule.direction,
            rule.bandwidth_kbps,
            rule.priority,
            rule.match_protocol,
            rule.match_port_min,
            rule.match_port_max,
            rule.match_ip,
            rule.match_dscp,
            enabled_int,
        ],
    )
    .context("failed to insert QoS rule")?;
    let id = conn.last_insert_rowid();
    tracing::info!(id, name = %rule.name, "inserted QoS rule");
    Ok(id)
}

/// Update an existing QoS rule by ID.
pub async fn update_rule(db: &sfgw_db::Db, rule: &QosRule) -> Result<(), FwError> {
    let id = rule.id.ok_or(FwError::MissingId)?;
    validate_rule(rule)?;
    let enabled_int: i32 = if rule.enabled { 1 } else { 0 };
    let conn = db.lock().await;
    let affected = conn
        .execute(
            "UPDATE qos_rules SET name = ?1, interface = ?2, direction = ?3, \
             bandwidth_kbps = ?4, priority = ?5, match_protocol = ?6, \
             match_port_min = ?7, match_port_max = ?8, match_ip = ?9, \
             match_dscp = ?10, enabled = ?11 WHERE id = ?12",
            rusqlite::params![
                rule.name,
                rule.interface,
                rule.direction,
                rule.bandwidth_kbps,
                rule.priority,
                rule.match_protocol,
                rule.match_port_min,
                rule.match_port_max,
                rule.match_ip,
                rule.match_dscp,
                enabled_int,
                id,
            ],
        )
        .context("failed to update QoS rule")?;
    if affected != 1 {
        return Err(FwError::Internal(anyhow::anyhow!(
            "QoS rule id={id} not found"
        )));
    }
    tracing::info!(id, name = %rule.name, "updated QoS rule");
    Ok(())
}

/// Delete a QoS rule by ID.
pub async fn delete_rule(db: &sfgw_db::Db, id: i64) -> Result<(), FwError> {
    let conn = db.lock().await;
    let affected = conn
        .execute("DELETE FROM qos_rules WHERE id = ?1", rusqlite::params![id])
        .context("failed to delete QoS rule")?;
    if affected != 1 {
        return Err(FwError::Internal(anyhow::anyhow!(
            "QoS rule id={id} not found"
        )));
    }
    tracing::info!(id, "deleted QoS rule");
    Ok(())
}

// ── tc command generation and application ───────────────────────────

/// Apply all enabled QoS rules from the database.
///
/// For each interface with rules:
/// 1. Clear existing tc qdiscs
/// 2. Set up HTB root qdisc with 4 traffic classes
/// 3. Add tc filters matching on fwmark
/// 4. Add iptables mangle MARK rules for traffic classification
///
/// For ingress rules, an IFB device is created and traffic is redirected.
pub async fn apply_qos(db: &sfgw_db::Db) -> Result<(), FwError> {
    let rules = load_enabled_rules(db).await?;

    if rules.is_empty() {
        tracing::info!("no QoS rules enabled, skipping tc setup");
        return Ok(());
    }

    // Group rules by (interface, direction)
    let mut grouped: std::collections::HashMap<(String, String), Vec<&QosRule>> =
        std::collections::HashMap::new();
    for rule in &rules {
        grouped
            .entry((rule.interface.clone(), rule.direction.clone()))
            .or_default()
            .push(rule);
    }

    // First, clear mangle MARK rules for QoS
    clear_qos_mangle_rules().await?;

    for ((iface, direction), iface_rules) in &grouped {
        let tc_iface = if direction == "ingress" {
            // For ingress, we use an IFB device
            let ifb = format!("ifb-{}", &iface[..iface.len().min(10)]);
            setup_ifb_device(&ifb, iface).await?;
            ifb
        } else {
            iface.clone()
        };

        // Calculate total bandwidth as the max of all rules' bandwidth
        let total_bw_kbps: u32 = iface_rules
            .iter()
            .map(|r| r.bandwidth_kbps)
            .max()
            .unwrap_or(0);

        // Clear and set up HTB on this interface
        clear_qos_for_interface(&tc_iface).await;
        setup_htb_qdisc(&tc_iface, total_bw_kbps).await?;

        // Add iptables mangle MARK rules for each QoS rule
        for rule in iface_rules {
            let class = QosClass::from_priority(rule.priority);
            add_mangle_mark_rule(rule, class.mark(), iface, direction).await?;
        }
    }

    tracing::info!(
        rules = rules.len(),
        "QoS traffic shaping applied successfully"
    );
    Ok(())
}

/// Clear all tc qdiscs on an interface (ignoring errors if none exist).
pub async fn clear_qos_for_interface(iface: &str) {
    use tokio::process::Command;

    // Remove root qdisc (this removes all child classes and filters)
    let _ = Command::new("tc")
        .args(["qdisc", "del", "dev", iface, "root"])
        .output()
        .await;

    // Remove ingress qdisc if any
    let _ = Command::new("tc")
        .args(["qdisc", "del", "dev", iface, "ingress"])
        .output()
        .await;

    tracing::debug!(interface = %iface, "cleared tc qdiscs");
}

/// Set up the HTB root qdisc with 4 traffic classes.
async fn setup_htb_qdisc(iface: &str, total_bw_kbps: u32) -> Result<(), FwError> {
    use tokio::process::Command;

    // Root HTB qdisc with default class 40 (unclassified → Default)
    run_tc_cmd(
        Command::new("tc").args([
            "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "40",
        ]),
        "add root HTB qdisc",
    )
    .await?;

    // Root class: total interface bandwidth
    let rate = format!("{total_bw_kbps}kbit");
    run_tc_cmd(
        Command::new("tc").args([
            "class", "add", "dev", iface, "parent", "1:", "classid", "1:1", "htb", "rate", &rate,
            "ceil", &rate,
        ]),
        "add root HTB class",
    )
    .await?;

    // Add child classes for each traffic tier
    for class in [
        QosClass::High,
        QosClass::Normal,
        QosClass::Low,
        QosClass::Default,
    ] {
        let class_rate_kbps = (total_bw_kbps as u64 * class.default_rate_pct() as u64 / 100) as u32;
        let class_rate_kbps = class_rate_kbps.max(1); // at least 1 kbps
        let class_rate = format!("{class_rate_kbps}kbit");
        let class_ceil = format!("{total_bw_kbps}kbit"); // can burst to full bandwidth
        let classid = format!("1:{}", class.class_minor());
        let prio = class.tc_prio().to_string();

        run_tc_cmd(
            Command::new("tc").args([
                "class",
                "add",
                "dev",
                iface,
                "parent",
                "1:1",
                "classid",
                &classid,
                "htb",
                "rate",
                &class_rate,
                "ceil",
                &class_ceil,
                "prio",
                &prio,
            ]),
            "add HTB child class",
        )
        .await?;

        // Add SFQ (Stochastic Fairness Queueing) leaf for fairness within class
        let sfq_handle = format!("{}:", class.class_minor());
        run_tc_cmd(
            Command::new("tc").args([
                "qdisc",
                "add",
                "dev",
                iface,
                "parent",
                &classid,
                "handle",
                &sfq_handle,
                "sfq",
                "perturb",
                "10",
            ]),
            "add SFQ leaf qdisc",
        )
        .await?;

        // Filter: match fwmark to route to this class
        let mark = class.mark().to_string();
        // Only add fw filter for non-default classes (default is handled by `default 40`)
        if class != QosClass::Default {
            run_tc_cmd(
                Command::new("tc").args([
                    "filter", "add", "dev", iface, "parent", "1:0", "protocol", "ip", "prio",
                    &prio, "handle", &mark, "fw", "classid", &classid,
                ]),
                "add fwmark filter",
            )
            .await?;
        }
    }

    tracing::debug!(
        interface = %iface,
        bandwidth_kbps = total_bw_kbps,
        "HTB qdisc setup complete"
    );
    Ok(())
}

/// Set up an IFB device for ingress shaping and redirect traffic into it.
async fn setup_ifb_device(ifb: &str, real_iface: &str) -> Result<(), FwError> {
    use tokio::process::Command;

    // Load ifb module (ignore error if already loaded)
    let _ = Command::new("modprobe").arg("ifb").output().await;

    // Create IFB device
    let _ = Command::new("ip")
        .args(["link", "add", ifb, "type", "ifb"])
        .output()
        .await;

    // Bring it up
    run_tc_cmd(
        Command::new("ip").args(["link", "set", ifb, "up"]),
        "bring up IFB device",
    )
    .await?;

    // Add ingress qdisc to real interface
    let _ = Command::new("tc")
        .args(["qdisc", "del", "dev", real_iface, "ingress"])
        .output()
        .await;
    run_tc_cmd(
        Command::new("tc").args(["qdisc", "add", "dev", real_iface, "ingress"]),
        "add ingress qdisc",
    )
    .await?;

    // Redirect all ingress traffic to IFB device
    run_tc_cmd(
        Command::new("tc").args([
            "filter", "add", "dev", real_iface, "parent", "ffff:", "protocol", "ip", "u32",
            "match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", ifb,
        ]),
        "redirect ingress to IFB",
    )
    .await?;

    tracing::debug!(ifb = %ifb, interface = %real_iface, "IFB device setup for ingress shaping");
    Ok(())
}

/// Add an iptables mangle MARK rule for a QoS rule.
async fn add_mangle_mark_rule(
    rule: &QosRule,
    mark: u32,
    iface: &str,
    direction: &str,
) -> Result<(), FwError> {
    use tokio::process::Command;

    let mut args: Vec<String> = vec![
        "-t".to_string(),
        "mangle".to_string(),
        "-A".to_string(),
        "POSTROUTING".to_string(),
    ];

    // Interface matching
    if direction == "egress" {
        args.push("-o".to_string());
        args.push(iface.to_string());
    } else {
        args.push("-i".to_string());
        args.push(iface.to_string());
    }

    // Protocol
    if let Some(ref proto) = rule.match_protocol {
        args.push("-p".to_string());
        args.push(proto.clone());
    }

    // Destination port range
    if let Some(port_min) = rule.match_port_min {
        // Port matching requires tcp or udp
        if rule.match_protocol.as_deref() == Some("tcp")
            || rule.match_protocol.as_deref() == Some("udp")
        {
            args.push("--dport".to_string());
            if let Some(port_max) = rule.match_port_max {
                if port_max != port_min {
                    args.push(format!("{port_min}:{port_max}"));
                } else {
                    args.push(port_min.to_string());
                }
            } else {
                args.push(port_min.to_string());
            }
        }
    }

    // IP match (destination for egress, source for ingress)
    if let Some(ref ip) = rule.match_ip {
        if direction == "egress" {
            args.push("-d".to_string());
        } else {
            args.push("-s".to_string());
        }
        args.push(ip.clone());
    }

    // DSCP match
    if let Some(dscp) = rule.match_dscp {
        args.push("-m".to_string());
        args.push("dscp".to_string());
        args.push("--dscp".to_string());
        args.push(dscp.to_string());
    }

    // Set mark
    args.push("-j".to_string());
    args.push("MARK".to_string());
    args.push("--set-mark".to_string());
    args.push(mark.to_string());

    // Add comment for identification
    args.push("-m".to_string());
    args.push("comment".to_string());
    args.push("--comment".to_string());
    args.push(format!("sfgw-qos:{}", rule.name));

    let output = Command::new("iptables")
        .args(&args)
        .output()
        .await
        .context("failed to execute iptables mangle MARK")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FwError::IptablesFailed(format!(
            "iptables mangle MARK failed: {stderr}"
        )));
    }

    tracing::debug!(
        rule_name = %rule.name,
        mark,
        interface = %iface,
        direction,
        "added iptables mangle MARK rule"
    );
    Ok(())
}

/// Clear all iptables mangle rules tagged with sfgw-qos comment.
async fn clear_qos_mangle_rules() -> Result<(), FwError> {
    use tokio::process::Command;

    // List mangle POSTROUTING rules and find sfgw-qos ones
    let output = Command::new("iptables")
        .args(["-t", "mangle", "-L", "POSTROUTING", "--line-numbers", "-n"])
        .output()
        .await
        .context("failed to list mangle rules")?;

    if !output.status.success() {
        // Chain might not exist yet, that's fine
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut rule_nums: Vec<u32> = Vec::new();

    for line in stdout.lines() {
        if line.contains("sfgw-qos:") {
            // Line format: "N    MARK  ..."
            if let Some(num_str) = line.split_whitespace().next()
                && let Ok(num) = num_str.parse::<u32>()
            {
                rule_nums.push(num);
            }
        }
    }

    // Delete in reverse order to preserve line numbers
    rule_nums.sort_unstable();
    rule_nums.reverse();

    for num in rule_nums {
        let _ = Command::new("iptables")
            .args(["-t", "mangle", "-D", "POSTROUTING", &num.to_string()])
            .output()
            .await;
    }

    tracing::debug!("cleared QoS mangle MARK rules");
    Ok(())
}

/// Run a tc/ip command, returning an error on failure.
async fn run_tc_cmd(cmd: &mut tokio::process::Command, context: &str) -> Result<(), FwError> {
    let output = cmd
        .output()
        .await
        .context(format!("failed to execute: {context}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FwError::Internal(anyhow::anyhow!("{context}: {stderr}")));
    }
    Ok(())
}

// ── tc stats parsing ────────────────────────────────────────────────

/// Per-class traffic statistics from `tc -s`.
#[derive(Debug, Clone, Serialize)]
pub struct QosClassStats {
    pub interface: String,
    pub class_id: String,
    pub class_name: String,
    pub sent_bytes: u64,
    pub sent_packets: u64,
    pub dropped_packets: u64,
    pub rate_bps: u64,
}

/// Parsed per-interface QoS statistics.
#[derive(Debug, Clone, Serialize)]
pub struct QosInterfaceStats {
    pub interface: String,
    pub classes: Vec<QosClassStats>,
}

/// Get tc statistics for all interfaces that have HTB qdiscs.
pub async fn get_stats(db: &sfgw_db::Db) -> Result<Vec<QosInterfaceStats>, FwError> {
    let rules = load_rules(db).await?;

    // Collect unique interfaces
    let mut interfaces: std::collections::HashSet<String> = std::collections::HashSet::new();
    for rule in &rules {
        interfaces.insert(rule.interface.clone());
        if rule.direction == "ingress" {
            let ifb = format!("ifb-{}", &rule.interface[..rule.interface.len().min(10)]);
            interfaces.insert(ifb);
        }
    }

    let mut all_stats = Vec::new();
    for iface in interfaces {
        if let Ok(stats) = parse_tc_stats(&iface).await {
            all_stats.push(stats);
        }
    }

    Ok(all_stats)
}

/// Parse `tc -s class show dev <iface>` output.
async fn parse_tc_stats(iface: &str) -> Result<QosInterfaceStats, FwError> {
    use tokio::process::Command;

    let output = Command::new("tc")
        .args(["-s", "class", "show", "dev", iface])
        .output()
        .await
        .context("failed to execute tc -s class")?;

    if !output.status.success() {
        return Err(FwError::Internal(anyhow::anyhow!(
            "tc stats failed for {iface}"
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let classes = parse_tc_class_output(&stdout, iface);

    Ok(QosInterfaceStats {
        interface: iface.to_string(),
        classes,
    })
}

/// Parse tc class output lines into structured stats.
fn parse_tc_class_output(output: &str, iface: &str) -> Vec<QosClassStats> {
    let mut classes = Vec::new();
    let mut current_class_id: Option<String> = None;
    let mut current_bytes: u64 = 0;
    let mut current_packets: u64 = 0;
    let mut current_dropped: u64 = 0;

    for line in output.lines() {
        let line = line.trim();

        // Class header line: "class htb 1:10 parent 1:1 ..."
        if line.starts_with("class htb") {
            // Save previous class if any
            if let Some(ref cid) = current_class_id {
                let class_name = class_id_to_name(cid);
                classes.push(QosClassStats {
                    interface: iface.to_string(),
                    class_id: cid.clone(),
                    class_name,
                    sent_bytes: current_bytes,
                    sent_packets: current_packets,
                    dropped_packets: current_dropped,
                    rate_bps: 0,
                });
            }

            // Extract class ID (e.g. "1:10")
            current_class_id = line.split_whitespace().nth(2).map(|s| s.to_string());
            current_bytes = 0;
            current_packets = 0;
            current_dropped = 0;
        }

        // Stats line: " Sent 12345 bytes 67 pkt (dropped 0, overlimits 0 ...)"
        if line.starts_with("Sent") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                current_bytes = parts[1].parse().unwrap_or(0);
                current_packets = parts[3].parse().unwrap_or(0);
            }
            // Extract dropped count
            if let Some(pos) = line.find("dropped ") {
                let rest = &line[pos + 8..];
                if let Some(end) = rest.find(',') {
                    current_dropped = rest[..end].trim().parse().unwrap_or(0);
                }
            }
        }
    }

    // Save last class
    if let Some(ref cid) = current_class_id {
        let class_name = class_id_to_name(cid);
        classes.push(QosClassStats {
            interface: iface.to_string(),
            class_id: cid.clone(),
            class_name,
            sent_bytes: current_bytes,
            sent_packets: current_packets,
            dropped_packets: current_dropped,
            rate_bps: 0,
        });
    }

    classes
}

/// Map a tc class ID to a human-readable name.
fn class_id_to_name(class_id: &str) -> String {
    match class_id {
        "1:1" => "Root".to_string(),
        "1:10" => "High (VoIP/Gaming)".to_string(),
        "1:20" => "Normal (Web)".to_string(),
        "1:30" => "Low (Bulk/P2P)".to_string(),
        "1:40" => "Default".to_string(),
        other => other.to_string(),
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qos_class_from_priority() {
        assert_eq!(QosClass::from_priority(1), QosClass::High);
        assert_eq!(QosClass::from_priority(2), QosClass::High);
        assert_eq!(QosClass::from_priority(3), QosClass::Normal);
        assert_eq!(QosClass::from_priority(4), QosClass::Normal);
        assert_eq!(QosClass::from_priority(5), QosClass::Low);
        assert_eq!(QosClass::from_priority(6), QosClass::Low);
        assert_eq!(QosClass::from_priority(7), QosClass::Default);
    }

    #[test]
    fn test_qos_class_marks() {
        assert_eq!(QosClass::High.mark(), 1);
        assert_eq!(QosClass::Normal.mark(), 2);
        assert_eq!(QosClass::Low.mark(), 3);
        assert_eq!(QosClass::Default.mark(), 0);
    }

    #[test]
    fn test_qos_class_rates() {
        // Rates should sum to 100%
        let total: u8 = QosClass::High.default_rate_pct()
            + QosClass::Normal.default_rate_pct()
            + QosClass::Low.default_rate_pct()
            + QosClass::Default.default_rate_pct();
        assert_eq!(total, 100);
    }

    #[test]
    fn test_validate_rule_ok() {
        let rule = QosRule {
            id: None,
            name: "voip-traffic".to_string(),
            interface: "eth0".to_string(),
            direction: "egress".to_string(),
            bandwidth_kbps: 10000,
            priority: 1,
            match_protocol: Some("udp".to_string()),
            match_port_min: Some(5060),
            match_port_max: Some(5061),
            match_ip: None,
            match_dscp: Some(46),
            enabled: true,
        };
        assert!(validate_rule(&rule).is_ok());
    }

    #[test]
    fn test_validate_rule_bad_priority() {
        let rule = QosRule {
            id: None,
            name: "test".to_string(),
            interface: "eth0".to_string(),
            direction: "egress".to_string(),
            bandwidth_kbps: 1000,
            priority: 0,
            match_protocol: None,
            match_port_min: None,
            match_port_max: None,
            match_ip: None,
            match_dscp: None,
            enabled: true,
        };
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_rule_bad_direction() {
        let rule = QosRule {
            id: None,
            name: "test".to_string(),
            interface: "eth0".to_string(),
            direction: "both".to_string(),
            bandwidth_kbps: 1000,
            priority: 3,
            match_protocol: None,
            match_port_min: None,
            match_port_max: None,
            match_ip: None,
            match_dscp: None,
            enabled: true,
        };
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_rule_bad_bandwidth() {
        let rule = QosRule {
            id: None,
            name: "test".to_string(),
            interface: "eth0".to_string(),
            direction: "egress".to_string(),
            bandwidth_kbps: 0,
            priority: 3,
            match_protocol: None,
            match_port_min: None,
            match_port_max: None,
            match_ip: None,
            match_dscp: None,
            enabled: true,
        };
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_rule_bad_dscp() {
        let rule = QosRule {
            id: None,
            name: "test".to_string(),
            interface: "eth0".to_string(),
            direction: "egress".to_string(),
            bandwidth_kbps: 1000,
            priority: 3,
            match_protocol: None,
            match_port_min: None,
            match_port_max: None,
            match_ip: None,
            match_dscp: Some(64),
            enabled: true,
        };
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_rule_bad_protocol() {
        let rule = QosRule {
            id: None,
            name: "test".to_string(),
            interface: "eth0".to_string(),
            direction: "egress".to_string(),
            bandwidth_kbps: 1000,
            priority: 3,
            match_protocol: Some("ftp".to_string()),
            match_port_min: None,
            match_port_max: None,
            match_ip: None,
            match_dscp: None,
            enabled: true,
        };
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_rule_port_range_inverted() {
        let rule = QosRule {
            id: None,
            name: "test".to_string(),
            interface: "eth0".to_string(),
            direction: "egress".to_string(),
            bandwidth_kbps: 1000,
            priority: 3,
            match_protocol: Some("tcp".to_string()),
            match_port_min: Some(8080),
            match_port_max: Some(80),
            match_ip: None,
            match_dscp: None,
            enabled: true,
        };
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_interface_name() {
        assert!(validate_interface_name("eth0").is_ok());
        assert!(validate_interface_name("br-lan").is_ok());
        assert!(validate_interface_name("ifb-eth0").is_ok());
        assert!(validate_interface_name("").is_err());
        assert!(validate_interface_name("this_is_way_too_long_iface").is_err());
        assert!(validate_interface_name("eth0;rm -rf /").is_err());
    }

    #[test]
    fn test_validate_ip_or_cidr() {
        assert!(validate_ip_or_cidr("10.0.0.1").is_ok());
        assert!(validate_ip_or_cidr("10.0.0.0/8").is_ok());
        assert!(validate_ip_or_cidr("192.168.1.0/24").is_ok());
        assert!(validate_ip_or_cidr("::1").is_ok());
        assert!(validate_ip_or_cidr("fe80::/10").is_ok());
        assert!(validate_ip_or_cidr("not-an-ip").is_err());
        assert!(validate_ip_or_cidr("10.0.0.0/33").is_err());
    }

    #[test]
    fn test_parse_tc_class_output() {
        let output = r#"class htb 1:1 root rate 100000Kbit ceil 100000Kbit burst 12500b cburst 12500b
 Sent 123456 bytes 789 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
class htb 1:10 parent 1:1 prio 1 rate 30000Kbit ceil 100000Kbit burst 3750b cburst 12500b
 Sent 50000 bytes 100 pkt (dropped 5, overlimits 10 requeues 0)
 backlog 0b 0p requeues 0
class htb 1:20 parent 1:1 prio 3 rate 40000Kbit ceil 100000Kbit burst 5000b cburst 12500b
 Sent 60000 bytes 200 pkt (dropped 2, overlimits 3 requeues 0)
 backlog 0b 0p requeues 0"#;

        let classes = parse_tc_class_output(output, "eth0");
        assert_eq!(classes.len(), 3);

        assert_eq!(classes[0].class_id, "1:1");
        assert_eq!(classes[0].class_name, "Root");
        assert_eq!(classes[0].sent_bytes, 123456);
        assert_eq!(classes[0].sent_packets, 789);
        assert_eq!(classes[0].dropped_packets, 0);

        assert_eq!(classes[1].class_id, "1:10");
        assert_eq!(classes[1].class_name, "High (VoIP/Gaming)");
        assert_eq!(classes[1].sent_bytes, 50000);
        assert_eq!(classes[1].sent_packets, 100);
        assert_eq!(classes[1].dropped_packets, 5);

        assert_eq!(classes[2].class_id, "1:20");
        assert_eq!(classes[2].class_name, "Normal (Web)");
        assert_eq!(classes[2].sent_bytes, 60000);
        assert_eq!(classes[2].dropped_packets, 2);
    }

    #[tokio::test]
    async fn test_qos_crud() {
        let db = sfgw_db::open_in_memory()
            .await
            .expect("open_in_memory should succeed");

        let rule = QosRule {
            id: None,
            name: "test-voip".to_string(),
            interface: "eth0".to_string(),
            direction: "egress".to_string(),
            bandwidth_kbps: 10000,
            priority: 1,
            match_protocol: Some("udp".to_string()),
            match_port_min: Some(5060),
            match_port_max: Some(5061),
            match_ip: None,
            match_dscp: Some(46),
            enabled: true,
        };

        // Insert
        let id = insert_rule(&db, &rule)
            .await
            .expect("insert should succeed");
        assert!(id > 0);

        // Load
        let rules = load_rules(&db).await.expect("load should succeed");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "test-voip");
        assert_eq!(rules[0].bandwidth_kbps, 10000);

        // Update
        let mut updated = rules[0].clone();
        updated.bandwidth_kbps = 20000;
        update_rule(&db, &updated)
            .await
            .expect("update should succeed");

        let rules = load_rules(&db).await.expect("load should succeed");
        assert_eq!(rules[0].bandwidth_kbps, 20000);

        // Delete
        delete_rule(&db, id).await.expect("delete should succeed");
        let rules = load_rules(&db).await.expect("load should succeed");
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn test_qos_load_enabled_only() {
        let db = sfgw_db::open_in_memory()
            .await
            .expect("open_in_memory should succeed");

        let rule1 = QosRule {
            id: None,
            name: "enabled-rule".to_string(),
            interface: "eth0".to_string(),
            direction: "egress".to_string(),
            bandwidth_kbps: 10000,
            priority: 1,
            match_protocol: None,
            match_port_min: None,
            match_port_max: None,
            match_ip: None,
            match_dscp: None,
            enabled: true,
        };
        let rule2 = QosRule {
            id: None,
            name: "disabled-rule".to_string(),
            interface: "eth0".to_string(),
            direction: "egress".to_string(),
            bandwidth_kbps: 5000,
            priority: 5,
            match_protocol: None,
            match_port_min: None,
            match_port_max: None,
            match_ip: None,
            match_dscp: None,
            enabled: false,
        };

        insert_rule(&db, &rule1).await.expect("insert 1");
        insert_rule(&db, &rule2).await.expect("insert 2");

        let all = load_rules(&db).await.expect("load all");
        assert_eq!(all.len(), 2);

        let enabled = load_enabled_rules(&db).await.expect("load enabled");
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].name, "enabled-rule");
    }
}
