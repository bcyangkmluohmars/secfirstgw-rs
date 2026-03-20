// SPDX-License-Identifier: AGPL-3.0-or-later

//! IDS Active Response — firewall integration for automatic threat blocking.
//!
//! Provides functions for the IDS engine to block or rate-limit IPs via the
//! existing `firewall_rules` table and atomic `iptables-restore` application.
//!
//! Rule lifecycle:
//! 1. IDS detects threat -> calls `block_ip()` or `rate_limit_ip()`
//! 2. Rule inserted into `firewall_rules` with high priority (1000+)
//! 3. `apply_rules()` atomically applies all rules via `iptables-restore`
//! 4. Background task calls `cleanup_expired()` every 60s to remove stale rules
//!
//! Expiry is tracked in the rule comment using the format:
//!   `IDS-expires-{unix_timestamp} {reason}`
//! This format passes the iptables comment sanitizer (alphanumeric, spaces, dashes, underscores).

use anyhow::Context;

use crate::{Action, FirewallRule, FwError, RuleDetail};

/// Priority base for IDS rules — above user rules but below zone defaults.
const IDS_PRIORITY_BASE: i32 = 1000;

/// Comment prefix for IDS-generated rules.
const IDS_COMMENT_PREFIX: &str = "IDS-expires-";

/// Sanitize an IDS reason string for safe embedding in iptables comments.
/// Only allows alphanumeric, spaces, dashes, and underscores (matching the
/// iptables comment sanitizer in `iptables/mod.rs`).
fn sanitize_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .take(40) // Leave room for the prefix + timestamp in the 64-char limit
        .collect()
}

/// Build the comment string encoding expiry timestamp and reason.
fn build_ids_comment(expires_epoch: u64, reason: &str) -> String {
    let safe_reason = sanitize_reason(reason);
    format!("{IDS_COMMENT_PREFIX}{expires_epoch} {safe_reason}")
}

/// Parse an IDS comment to extract the expiry timestamp.
/// Returns `None` if the comment is not an IDS rule or has no valid expiry.
fn parse_expiry(comment: &str) -> Option<u64> {
    let rest = comment.strip_prefix(IDS_COMMENT_PREFIX)?;
    // Format: "{timestamp} {reason}" or just "{timestamp}"
    let ts_str = rest.split_once(' ').map_or(rest, |(ts, _)| ts);
    ts_str.parse::<u64>().ok()
}

/// Block an IP address temporarily by inserting a DROP rule with expiry tracking.
///
/// The rule is inserted into the `firewall_rules` table at high priority (1000+)
/// so it takes effect before user-defined rules. After insertion, the full
/// firewall ruleset is atomically re-applied via `iptables-restore`.
///
/// Returns the database row ID of the inserted rule.
#[must_use = "returns the rule ID for tracking"]
pub async fn block_ip(
    db: &sfgw_db::Db,
    ip: &str,
    duration_secs: u64,
    reason: &str,
) -> Result<i64, FwError> {
    // Validate the IP address at the boundary (parse, don't validate)
    let _addr: std::net::IpAddr = ip
        .parse()
        .with_context(|| format!("invalid IP address for IDS block: {ip}"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .with_context(|| "system clock error")?
        .as_secs();
    let expires = now.saturating_add(duration_secs);

    let comment = build_ids_comment(expires, reason);

    // DROP rule on INPUT chain (traffic to the gateway from this IP)
    let input_rule = FirewallRule {
        id: None,
        chain: "input".to_string(),
        priority: IDS_PRIORITY_BASE,
        detail: RuleDetail {
            action: Action::Drop,
            protocol: "any".to_string(),
            source: ip.to_string(),
            destination: "any".to_string(),
            port: None,
            comment: Some(comment.clone()),
            vlan: None,
            rate_limit: None,
        },
        enabled: true,
    };

    // DROP rule on FORWARD chain (traffic through the gateway from this IP)
    let forward_rule = FirewallRule {
        id: None,
        chain: "forward".to_string(),
        priority: IDS_PRIORITY_BASE,
        detail: RuleDetail {
            action: Action::Drop,
            protocol: "any".to_string(),
            source: ip.to_string(),
            destination: "any".to_string(),
            port: None,
            comment: Some(comment),
            vlan: None,
            rate_limit: None,
        },
        enabled: true,
    };

    let input_id = crate::insert_rule(db, &input_rule).await?;
    let _forward_id = crate::insert_rule(db, &forward_rule).await?;

    tracing::warn!(
        ip,
        duration_secs,
        reason,
        input_id,
        "IDS: blocked IP via firewall"
    );

    // Atomically re-apply all rules
    crate::apply_rules(db).await?;

    Ok(input_id)
}

/// Rate-limit an IP address by inserting a rate-limit rule with expiry tracking.
///
/// Inserts a rule that limits packets-per-second from the given IP. The rate
/// limit is applied on the FORWARD chain (transit traffic). After insertion,
/// the full firewall ruleset is atomically re-applied.
///
/// Returns the database row ID of the inserted rule.
#[must_use = "returns the rule ID for tracking"]
pub async fn rate_limit_ip(
    db: &sfgw_db::Db,
    ip: &str,
    pps: u32,
    duration_secs: u64,
    reason: &str,
) -> Result<i64, FwError> {
    // Validate the IP address at the boundary
    let _addr: std::net::IpAddr = ip
        .parse()
        .with_context(|| format!("invalid IP address for IDS rate-limit: {ip}"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .with_context(|| "system clock error")?
        .as_secs();
    let expires = now.saturating_add(duration_secs);

    let comment = build_ids_comment(expires, reason);

    let rule = FirewallRule {
        id: None,
        chain: "forward".to_string(),
        priority: IDS_PRIORITY_BASE + 1,
        detail: RuleDetail {
            action: Action::Drop,
            protocol: "any".to_string(),
            source: ip.to_string(),
            destination: "any".to_string(),
            port: None,
            comment: Some(comment),
            vlan: None,
            rate_limit: Some(format!("{pps}/second")),
        },
        enabled: true,
    };

    let id = crate::insert_rule(db, &rule).await?;

    tracing::warn!(
        ip,
        pps,
        duration_secs,
        reason,
        id,
        "IDS: rate-limited IP via firewall"
    );

    // Atomically re-apply all rules
    crate::apply_rules(db).await?;

    Ok(id)
}

/// Remove all expired IDS rules from the database and re-apply the firewall.
///
/// Scans all firewall rules for IDS-generated comments containing expiry
/// timestamps. Any rule whose expiry has passed is deleted. If any rules
/// were removed, the firewall is atomically re-applied.
///
/// Returns the number of expired rules removed.
pub async fn cleanup_expired(db: &sfgw_db::Db) -> Result<u32, FwError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .with_context(|| "system clock error")?
        .as_secs();

    let all_rules = crate::load_rules(db).await?;
    let mut removed = 0u32;

    for rule in &all_rules {
        let comment = match &rule.detail.comment {
            Some(c) => c,
            None => continue,
        };

        if let Some(expiry) = parse_expiry(comment)
            && now >= expiry
            && let Some(id) = rule.id
        {
            crate::delete_rule(db, id).await?;
            tracing::info!(id, comment, "IDS: removed expired firewall rule");
            removed += 1;
        }
    }

    if removed > 0 {
        tracing::info!(removed, "IDS: re-applying firewall after cleanup");
        crate::apply_rules(db).await?;
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_reason_strips_unsafe_chars() {
        assert_eq!(sanitize_reason("ARP spoof <script>"), "ARP spoof script");
        assert_eq!(sanitize_reason("normal-reason_123"), "normal-reason_123");
    }

    #[test]
    fn build_ids_comment_format() {
        let comment = build_ids_comment(1700000000, "ARP spoof");
        assert_eq!(comment, "IDS-expires-1700000000 ARP spoof");
    }

    #[test]
    fn parse_expiry_valid() {
        assert_eq!(
            parse_expiry("IDS-expires-1700000000 ARP spoof"),
            Some(1700000000)
        );
        assert_eq!(parse_expiry("IDS-expires-1700000000"), Some(1700000000));
    }

    #[test]
    fn parse_expiry_invalid() {
        assert_eq!(parse_expiry("not an IDS rule"), None);
        assert_eq!(parse_expiry("IDS-expires-notanumber reason"), None);
        assert_eq!(parse_expiry(""), None);
    }

    #[test]
    fn sanitize_reason_length_limit() {
        let long = "a".repeat(100);
        assert_eq!(sanitize_reason(&long).len(), 40);
    }
}
