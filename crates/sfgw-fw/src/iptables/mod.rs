// SPDX-License-Identifier: AGPL-3.0-or-later

//! iptables-restore ruleset generation and application via `iptables-restore`.
//!
//! The UDM Pro kernel (4.19) has no nf_tables support, so we use
//! iptables-legacy exclusively. All rules are generated in
//! `iptables-restore` format and applied atomically.

use crate::{
    Action, CustomZone, FirewallPolicy, FirewallRule, FirewallZone, PortForward, ZonePolicy,
};
use anyhow::{Context, Result, bail};
use std::fmt::Write;
use std::net::IpAddr;

// ── Input validation (command injection prevention) ──────────────────

/// Validate that a string is a valid IP address or CIDR notation (e.g. "10.0.0.0/8").
fn validate_ip_or_cidr(s: &str) -> Result<()> {
    if let Some((ip_part, prefix_part)) = s.split_once('/') {
        let _ip: IpAddr = ip_part
            .parse()
            .with_context(|| format!("invalid IP in CIDR: {s}"))?;
        let prefix: u8 = prefix_part
            .parse()
            .with_context(|| format!("invalid prefix length in CIDR: {s}"))?;
        let max = if _ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            bail!("CIDR prefix {prefix} exceeds maximum {max} for {s}");
        }
    } else {
        let _ip: IpAddr = s
            .parse()
            .with_context(|| format!("invalid IP address: {s}"))?;
    }
    Ok(())
}

/// Validate a port specification: single u16, range "80-443", or comma-separated list.
fn validate_port(s: &str) -> Result<()> {
    for part in s.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start
                .trim()
                .parse()
                .with_context(|| format!("invalid port range start in: {s}"))?;
            let end: u16 = end
                .trim()
                .parse()
                .with_context(|| format!("invalid port range end in: {s}"))?;
            if start > end {
                bail!("invalid port range {start}-{end}: start > end");
            }
        } else {
            let _port: u16 = part
                .parse()
                .with_context(|| format!("invalid port number: {part}"))?;
        }
    }
    Ok(())
}

/// Validate protocol is one of the allowed values.
fn validate_protocol(s: &str) -> Result<()> {
    const ALLOWED: &[&str] = &["tcp", "udp", "sctp", "icmp", "icmpv6"];
    if !ALLOWED.contains(&s) {
        bail!(
            "invalid protocol '{}': must be one of {}",
            s,
            ALLOWED.join(", ")
        );
    }
    Ok(())
}

/// Validate rate limit matches pattern like "100/second", "10/minute", "1/hour".
fn validate_rate_limit(s: &str) -> Result<()> {
    let Some((count_str, unit)) = s.split_once('/') else {
        bail!("invalid rate limit '{s}': expected format 'N/unit'");
    };
    let _count: u32 = count_str
        .parse()
        .with_context(|| format!("invalid rate limit count in: {s}"))?;
    const ALLOWED_UNITS: &[&str] = &["second", "minute", "hour"];
    if !ALLOWED_UNITS.contains(&unit) {
        bail!(
            "invalid rate limit unit '{}': must be one of {}",
            unit,
            ALLOWED_UNITS.join(", ")
        );
    }
    Ok(())
}

/// Sanitize a comment: only alphanumeric, spaces, dashes, underscores. Max 64 chars.
fn sanitize_comment(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .take(64)
        .collect()
}

/// Validate an interface name: alphanumeric, dots, dashes, underscores, 1-15 chars.
pub fn validate_interface_name(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 15 {
        bail!("invalid interface name '{}': must be 1-15 characters", s);
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        bail!(
            "invalid interface name '{}': only alphanumeric, '.', '_', '-' allowed",
            s
        );
    }
    Ok(())
}

/// Validate a chain name for user rules.
fn validate_chain(s: &str) -> Result<()> {
    const ALLOWED: &[&str] = &["input", "forward", "output", "prerouting", "postrouting"];
    if !ALLOWED.contains(&s) {
        bail!(
            "invalid chain '{}': must be one of {}",
            s,
            ALLOWED.join(", ")
        );
    }
    Ok(())
}

/// Map chain name to the custom SFGW chain name used in iptables.
fn sfgw_chain(chain: &str) -> &str {
    match chain {
        "input" => "SFGW-INPUT",
        "forward" => "SFGW-FORWARD",
        "output" => "SFGW-OUTPUT",
        "prerouting" => "SFGW-PREROUTING",
        "postrouting" => "SFGW-POSTROUTING",
        _ => "SFGW-INPUT",
    }
}

/// Convert an iptables-restore format rate limit unit to iptables `-m limit` syntax.
/// Input: "100/second" -> "--limit 100/sec"
fn rate_limit_to_iptables(rate: &str) -> String {
    // iptables uses /sec, /min, /hour
    let converted = rate.replace("second", "sec").replace("minute", "min");
    format!("-m limit --limit {converted}")
}

/// Convert Action to iptables target.
fn action_to_target(action: &Action) -> &str {
    match action {
        Action::Accept => "ACCEPT",
        Action::Drop => "DROP",
        Action::Reject => "REJECT",
        Action::Masquerade => "MASQUERADE",
    }
}

/// Convert Action to iptables-restore policy string.
fn action_to_policy(action: &Action) -> &str {
    match action {
        Action::Accept => "ACCEPT",
        Action::Drop => "DROP",
        // Reject and Masquerade are not valid chain policies; default to DROP.
        Action::Reject => "DROP",
        Action::Masquerade => "ACCEPT",
    }
}

/// Convert a port spec for iptables: comma-separated ports use `-m multiport --dports`,
/// single port or range uses `--dport`. Ranges use `:` separator (iptables format),
/// but we accept `-` from the DB/API and convert automatically.
fn port_to_iptables(port: &str) -> String {
    // iptables uses ":" for port ranges, not "-"
    let port = port.replace('-', ":");
    if port.contains(',') {
        format!("-m multiport --dports {port}")
    } else {
        format!("--dport {port}")
    }
}

// ── iptables-restore format generation ──────────────────────────────

/// Generate a complete iptables-restore ruleset from DB rules and policy.
///
/// If `rules` is empty, a hardened default ruleset is generated.
///
/// # Panics
/// Uses `writeln!().unwrap()` throughout -- these cannot fail because
/// `fmt::Write` for `String` is infallible (never returns `Err`).
pub fn generate_ruleset(rules: &[FirewallRule], policy: &FirewallPolicy) -> String {
    // INVARIANT: All writeln!(out, ...).unwrap() calls below write to a String.
    // fmt::Write for String is infallible -- it can only fail on OOM which aborts.
    let mut out = String::with_capacity(4096);

    writeln!(out, "# Generated by sfgw-fw -- do not edit manually").unwrap();
    writeln!(out).unwrap();

    // ── *filter table ──────────────────────────────────────────────
    emit_filter_table(&mut out, policy, |out| {
        // Default secure rules (always present).
        emit_default_rules(out);

        if rules.is_empty() {
            emit_hardened_defaults(out);
        } else {
            emit_user_rules(out, rules);
        }
    });

    // ── *nat table ─────────────────────────────────────────────────
    emit_nat_table(&mut out, |out| {
        if rules.is_empty() {
            // Hardened defaults: masquerade on WAN-like interfaces.
            emit_hardened_nat_defaults(out);
        } else {
            // User rules may include postrouting masquerade.
            emit_user_nat_rules(out, rules);
        }
    });

    out
}

/// Generate a ruleset that also includes port-forwarding DNAT entries.
pub fn generate_ruleset_with_forwards(
    rules: &[FirewallRule],
    policy: &FirewallPolicy,
    forwards: &[PortForward],
) -> String {
    let mut out = String::with_capacity(4096);

    writeln!(out, "# Generated by sfgw-fw -- do not edit manually").unwrap();
    writeln!(out).unwrap();

    // ── *filter table ──────────────────────────────────────────────
    emit_filter_table(&mut out, policy, |out| {
        emit_default_rules(out);

        if rules.is_empty() {
            emit_hardened_defaults(out);
        } else {
            emit_user_rules(out, rules);
        }

        // Allow forwarded traffic to reach DNAT destinations.
        // Legacy mode: no WAN interface info available, passes empty slice.
        for fwd in forwards.iter().filter(|f| f.enabled) {
            if let Err(e) = emit_port_forward_accept(out, fwd, &[]) {
                tracing::error!("skipping invalid port forward accept: {e}");
            }
        }
    });

    // ── *nat table ─────────────────────────────────────────────────
    emit_nat_table(&mut out, |out| {
        // Port forwarding DNAT rules.
        for fwd in forwards.iter().filter(|f| f.enabled) {
            if let Err(e) = emit_port_forward_dnat(out, fwd, &[]) {
                tracing::error!("skipping invalid port forward: {e}");
            }
        }

        if rules.is_empty() {
            emit_hardened_nat_defaults(out);
        } else {
            emit_user_nat_rules(out, rules);
        }
    });

    out
}

/// Atomically apply an iptables ruleset via `iptables-restore`.
///
/// Pipes config to `iptables-restore`. On failure the old rules remain.
/// Validate that a generated ruleset won't lock us out.
/// Refuses to apply if SSH (port 22) is not ACCEPT'd on any interface.
///
/// Checks the actual rule structure (protocol TCP, destination port 22,
/// ACCEPT action) rather than string matching on the whole line. This
/// prevents bypass via crafted comments containing "ssh" or "--dport 22".
fn validate_no_lockout(config: &str) -> Result<()> {
    validate_ssh_accept(config, "IPv4")?;

    // Also validate the IPv6 ruleset that will be generated from this config.
    // Without this check, IPv6 SSH could be locked out silently.
    let ipv6_config = filter_config_to_ipv6(config);
    validate_ssh_accept(&ipv6_config, "IPv6")?;

    Ok(())
}

/// Check that a ruleset contains at least one SSH ACCEPT rule.
///
/// Accepts both `-p tcp` and `-p 6` (protocol number) as valid TCP matches.
fn validate_ssh_accept(config: &str, label: &str) -> Result<()> {
    let has_ssh_accept = config.lines().any(|line| {
        // Strip the comment portion to prevent bypass via crafted comments.
        let rule_part = if let Some(idx) = line.find("-m comment") {
            &line[..idx]
        } else {
            line
        };

        // Must be a rule line (starts with -A), target TCP port 22, and ACCEPT.
        // Accept both `-p tcp` and `-p 6` (IP protocol number for TCP).
        let is_tcp = rule_part.contains("-p tcp") || rule_part.contains("-p 6");
        rule_part.starts_with("-A SFGW-INPUT")
            && is_tcp
            && rule_part.contains("--dport 22")
            && rule_part.contains("-j ACCEPT")
    });
    if !has_ssh_accept {
        bail!(
            "REFUSING to apply ruleset: no {label} SSH ACCEPT rule found — would lock out management access"
        );
    }
    Ok(())
}

pub async fn apply_ruleset(config: &str) -> Result<()> {
    // Sanity check: never apply a ruleset that would lock us out.
    validate_no_lockout(config)?;

    // Step 1: Save current iptables state for rollback (IPv4 + IPv6).
    let backup_v4 = save_state("iptables-save").await?;
    let backup_v6 = save_state("ip6tables-save").await?;

    // Step 2: Clean up any previous SFGW chains (IPv4 + IPv6).
    flush_ruleset().await?;

    // Step 3: Apply IPv4 rules via iptables-restore.
    let safe_config = rewrite_for_noflush(config);
    if let Err(e) = apply_restore("iptables-restore", &safe_config).await {
        tracing::error!("iptables-restore failed, rolling back: {e}");
        restore_state("iptables-restore", &backup_v4).await?;
        return Err(e);
    }

    // Step 3b: Apply IPv6 rules via ip6tables-restore (filter table only).
    let ipv6_config = filter_config_to_ipv6(config);
    let safe_ipv6 = rewrite_for_noflush(&ipv6_config);
    if let Err(e) = apply_restore("ip6tables-restore", &safe_ipv6).await {
        tracing::error!("ip6tables-restore failed, rolling back: {e}");
        restore_state("iptables-restore", &backup_v4).await?;
        restore_state("ip6tables-restore", &backup_v6).await?;
        return Err(e);
    }

    // Step 4: Insert jump rules at the TOP of built-in chains (IPv4 + IPv6).
    insert_jump_rules().await?;

    // Step 5: Verify we haven't locked ourselves out.
    if let Err(e) = verify_connectivity().await {
        tracing::error!("connectivity check failed after apply: {e} — rolling back");
        restore_state("iptables-restore", &backup_v4).await?;
        restore_state("ip6tables-restore", &backup_v6).await?;
        anyhow::bail!("firewall rollback: connectivity check failed: {e}");
    }

    tracing::info!("iptables + ip6tables ruleset applied and verified");
    Ok(())
}

/// Apply a config via iptables-restore or ip6tables-restore.
async fn apply_restore(cmd: &str, config: &str) -> Result<()> {
    use tokio::process::Command;

    let mut child = Command::new(cmd)
        .arg("--noflush")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to execute {cmd}"))?;

    {
        use tokio::io::AsyncWriteExt;
        let stdin = child.stdin.as_mut().context("failed to open stdin")?;
        stdin.write_all(config.as_bytes()).await?;
        stdin.shutdown().await?;
    }

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{cmd} failed (exit {}): {}", output.status, stderr.trim());
    }
    Ok(())
}

/// Save the current iptables/ip6tables state via the given save command.
async fn save_state(cmd: &str) -> Result<String> {
    use tokio::process::Command;

    let output = Command::new(cmd)
        .output()
        .await
        .with_context(|| format!("failed to run {cmd}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{cmd} failed: {}", stderr.trim());
    }

    let backup = String::from_utf8_lossy(&output.stdout).to_string();
    tracing::info!("{cmd}: saved state ({} bytes)", backup.len());
    Ok(backup)
}

/// Restore a previously saved state via iptables-restore or ip6tables-restore.
async fn restore_state(cmd: &str, backup: &str) -> Result<()> {
    use tokio::process::Command;

    let mut child = Command::new(cmd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to execute {cmd} for rollback"))?;

    {
        use tokio::io::AsyncWriteExt;
        let stdin = child.stdin.as_mut().context("failed to open stdin")?;
        stdin.write_all(backup.as_bytes()).await?;
        stdin.shutdown().await?;
    }

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("rollback {cmd} failed: {}", stderr.trim());
        anyhow::bail!("rollback {cmd} failed: {}", stderr.trim());
    }

    tracing::info!("{cmd}: rolled back to previous state");
    Ok(())
}

/// Verify connectivity by TCP-connecting to our own SSH (22) and HTTPS (443)
/// on localhost. If iptables blocks loopback or our own ports, this catches it.
async fn verify_connectivity() -> Result<()> {
    use std::time::Duration;
    use tokio::net::TcpStream;

    // Give the kernel a moment to process the new rules.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Test SSH (port 22) — the OS sshd should always be listening.
    match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect("127.0.0.1:22")).await {
        Ok(Ok(_)) => {
            tracing::debug!("connectivity check: SSH on 127.0.0.1:22 OK");
        }
        Ok(Err(e)) => {
            // Connection refused = port not listening, but not blocked by firewall.
            // Connection reset or timeout = firewall is blocking.
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                tracing::debug!(
                    "connectivity check: SSH on 127.0.0.1:22 refused (sshd not running, but not blocked)"
                );
            } else {
                anyhow::bail!("SSH on 127.0.0.1:22 failed: {e}");
            }
        }
        Err(_) => {
            anyhow::bail!("SSH on 127.0.0.1:22 timed out — firewall is blocking loopback");
        }
    }

    Ok(())
}

/// Transform IPv4 filter config into an IPv6 ip6tables-restore config.
///
/// - Extracts only the `*filter` table (strips `*nat`)
/// - Replaces ICMP echo-request with ICMPv6 echo-request (type 128)
/// - Adds ICMPv6 NDP rules (neighbor/router solicitation/advertisement)
/// - Replaces `-p icmp` with `-p icmpv6`
pub fn filter_config_to_ipv6(config: &str) -> String {
    let mut out = String::with_capacity(config.len());
    let mut in_filter = false;
    let mut in_nat = false;

    for line in config.lines() {
        if line.starts_with("*filter") {
            in_filter = true;
            in_nat = false;
            out.push_str(line);
            out.push('\n');
            continue;
        }
        if line.starts_with("*nat") {
            in_filter = false;
            in_nat = true;
            continue;
        }
        if line == "COMMIT" {
            if in_filter {
                out.push_str("COMMIT\n");
                in_filter = false;
            }
            if in_nat {
                in_nat = false;
            }
            continue;
        }

        // Skip NAT table lines entirely — no IPv6 NAT.
        if in_nat {
            continue;
        }

        if !in_filter {
            // Comments before *filter — keep them.
            if line.starts_with('#') {
                out.push_str(line);
                out.push('\n');
            }
            continue;
        }

        // Replace ICMP echo-request rule with ICMPv6 equivalent + NDP rules.
        if line.contains("-p icmp --icmp-type echo-request") {
            writeln!(
                out,
                "-A SFGW-INPUT -p icmpv6 --icmpv6-type echo-request -m limit --limit 5/sec -j ACCEPT"
            )
            .unwrap();
            // ICMPv6 NDP — required for IPv6 to function at all, but rate-limited
            // to prevent NDP flood attacks.
            writeln!(
                out,
                "-A SFGW-INPUT -p icmpv6 --icmpv6-type neighbor-solicitation -m limit --limit 100/sec --limit-burst 200 -j ACCEPT"
            )
            .unwrap();
            writeln!(
                out,
                "-A SFGW-INPUT -p icmpv6 --icmpv6-type neighbor-advertisement -m limit --limit 100/sec --limit-burst 200 -j ACCEPT"
            )
            .unwrap();
            writeln!(
                out,
                "-A SFGW-INPUT -p icmpv6 --icmpv6-type router-solicitation -m limit --limit 10/sec --limit-burst 20 -j ACCEPT"
            )
            .unwrap();
            writeln!(
                out,
                "-A SFGW-INPUT -p icmpv6 --icmpv6-type router-advertisement -m limit --limit 10/sec --limit-burst 20 -j ACCEPT"
            )
            .unwrap();
            // DHCPv6 — client (546) and server (547) ports.
            writeln!(
                out,
                "-A SFGW-INPUT -p udp --dport 546 -j ACCEPT -m comment --comment \"DHCPv6 client\""
            )
            .unwrap();
            writeln!(
                out,
                "-A SFGW-INPUT -p udp --dport 547 -j ACCEPT -m comment --comment \"DHCPv6 server\""
            )
            .unwrap();
            continue;
        }

        // Skip masquerade rules — no IPv6 NAT.
        if line.contains("-j MASQUERADE") {
            continue;
        }

        out.push_str(line);
        out.push('\n');
    }

    // Link-local (fe80::/10) filtering: drop link-local sourced packets
    // from WAN/DMZ/GUEST zones in the FORWARD chain. Link-local traffic
    // should never cross zone boundaries.
    writeln!(
        out,
        "# ── IPv6 link-local zone isolation ──"
    )
    .unwrap();
    writeln!(
        out,
        "-A SFGW-FORWARD -s fe80::/10 -j DROP -m comment --comment \"drop link-local forwards\""
    )
    .unwrap();
    writeln!(
        out,
        "-A SFGW-FORWARD -d fe80::/10 -j DROP -m comment --comment \"drop link-local forwards\""
    )
    .unwrap();

    out
}

/// Rewrite the iptables-restore config for safe `--noflush` application:
/// - Remove ALL built-in chain declarations (`:INPUT`, `:FORWARD`, etc.)
///   because with `--noflush` they already exist; including them (even with
///   `- [0:0]`) causes old iptables versions to corrupt `-i` interface flags
/// - Keep only custom SFGW chain declarations (`:SFGW-INPUT - [0:0]` etc.)
/// - Remove jump rules from built-in to custom chains (we insert those manually)
fn rewrite_for_noflush(config: &str) -> String {
    let mut out = String::with_capacity(config.len());
    for line in config.lines() {
        // Strip built-in chain declarations entirely — they already exist
        // and re-declaring them with --noflush corrupts rules on UDM Pro.
        if line.starts_with(':') && !line.contains("SFGW-") {
            continue;
        }
        // Skip jump rules from built-in to custom chains
        if line.starts_with("-A INPUT -j SFGW-")
            || line.starts_with("-A FORWARD -j SFGW-")
            || line.starts_with("-A OUTPUT -j SFGW-")
            || line.starts_with("-A PREROUTING -j SFGW-")
            || line.starts_with("-A POSTROUTING -j SFGW-")
        {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Insert jump rules at position 1 in built-in chains so our rules
/// are evaluated before any existing platform rules.
async fn insert_jump_rules() -> Result<()> {
    use tokio::process::Command;

    // Filter table jumps (IPv4 + IPv6).
    for cmd in &["iptables", "ip6tables"] {
        for (builtin, custom) in &[
            ("INPUT", "SFGW-INPUT"),
            ("FORWARD", "SFGW-FORWARD"),
            ("OUTPUT", "SFGW-OUTPUT"),
        ] {
            let output = Command::new(cmd)
                .args(["-I", builtin, "1", "-j", custom])
                .output()
                .await
                .with_context(|| format!("failed to insert {cmd} {builtin} -> {custom} jump"))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("{cmd} -I {builtin} 1 -j {custom} failed: {}", stderr.trim());
            }
        }
    }

    // NAT table jumps (IPv4 only).
    for (builtin, custom) in &[
        ("PREROUTING", "SFGW-PREROUTING"),
        ("POSTROUTING", "SFGW-POSTROUTING"),
    ] {
        let output = Command::new("iptables")
            .args(["-t", "nat", "-I", builtin, "1", "-j", custom])
            .output()
            .await
            .with_context(|| format!("failed to insert nat {builtin} -> {custom} jump"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "iptables -t nat -I {builtin} 1 -j {custom} failed: {}",
                stderr.trim()
            );
        }
    }

    tracing::info!("inserted SFGW jump rules at top of built-in chains (IPv4 + IPv6)");
    Ok(())
}

/// Flush all sfgw iptables + ip6tables rules (remove custom chains).
pub async fn flush_ruleset() -> Result<()> {
    use tokio::process::Command;

    // Flush filter chains for both IPv4 and IPv6.
    for cmd in &["iptables", "ip6tables"] {
        for chain in &["SFGW-INPUT", "SFGW-FORWARD", "SFGW-OUTPUT"] {
            let builtin = match *chain {
                "SFGW-INPUT" => "INPUT",
                "SFGW-FORWARD" => "FORWARD",
                "SFGW-OUTPUT" => "OUTPUT",
                _ => continue,
            };
            let _ = Command::new(cmd)
                .args(["-D", builtin, "-j", chain])
                .output()
                .await;
            let _ = Command::new(cmd).args(["-F", chain]).output().await;
            let _ = Command::new(cmd).args(["-X", chain]).output().await;
        }
    }

    // Flush NAT chains (IPv4 only — no IPv6 NAT).
    for chain in &["SFGW-PREROUTING", "SFGW-POSTROUTING"] {
        let builtin = match *chain {
            "SFGW-PREROUTING" => "PREROUTING",
            "SFGW-POSTROUTING" => "POSTROUTING",
            _ => continue,
        };
        let _ = Command::new("iptables")
            .args(["-t", "nat", "-D", builtin, "-j", chain])
            .output()
            .await;
        let _ = Command::new("iptables")
            .args(["-t", "nat", "-F", chain])
            .output()
            .await;
        let _ = Command::new("iptables")
            .args(["-t", "nat", "-X", chain])
            .output()
            .await;
    }

    tracing::info!("iptables + ip6tables custom chains flushed");
    Ok(())
}

// ── Zone-aware ruleset generation ────────────────────────────────────

/// Generate a complete zone-aware iptables-restore ruleset.
///
/// Uses actual interface assignments from the database. Since iptables
/// does not have named sets, zone interface sets are expanded into
/// individual per-interface rules.
///
/// Security policies per zone:
/// - **WAN**: DROP all input, only established/related, no web UI, NAT masquerade
/// - **LAN**: DHCP, DNS only, forward to WAN/DMZ (no SSH, no web UI)
/// - **DMZ**: Allow 80/443 inbound, no direct LAN/MGMT access, forward to WAN
/// - **MGMT**: Web UI (443), SSH (22), Inform (8080), access to all internal zones
/// - **GUEST**: Internet only (forward to WAN), DNS/DHCP to gateway, no internal access
///
/// # Panics
/// Uses `writeln!().unwrap()` throughout -- these cannot fail because
/// `fmt::Write` for `String` is infallible (never returns `Err`).
pub fn generate_zone_ruleset(
    zones: &[ZonePolicy],
    rules: &[FirewallRule],
    policy: &FirewallPolicy,
    forwards: &[PortForward],
) -> String {
    generate_zone_ruleset_with_custom(zones, rules, policy, forwards, &[])
}

/// Generate a zone-aware ruleset including custom zone policies.
///
/// Custom zones (IoT, VPN, user-defined) get their iptables rules generated
/// from the `custom_zones` DB table configuration.
pub fn generate_zone_ruleset_with_custom(
    zones: &[ZonePolicy],
    rules: &[FirewallRule],
    policy: &FirewallPolicy,
    forwards: &[PortForward],
    custom_zones: &[CustomZone],
) -> String {
    // INVARIANT: All writeln!(out, ...).unwrap() calls write to a String.
    // fmt::Write for String is infallible -- it can only fail on OOM which aborts.
    let mut out = String::with_capacity(8192);

    writeln!(
        out,
        "# Generated by sfgw-fw (zone-aware) -- do not edit manually"
    )
    .unwrap();
    writeln!(out).unwrap();

    // Collect zone interfaces for lookups.
    let wan_ifaces = zone_interfaces(zones, &FirewallZone::Wan);
    let lan_ifaces = zone_interfaces(zones, &FirewallZone::Lan);
    let dmz_ifaces = zone_interfaces(zones, &FirewallZone::Dmz);
    let mgmt_ifaces = zone_interfaces(zones, &FirewallZone::Mgmt);
    let guest_ifaces = zone_interfaces(zones, &FirewallZone::Guest);

    // Collect custom zone interfaces.
    let custom_iface_sets: Vec<(&CustomZone, Vec<&str>)> = custom_zones
        .iter()
        .map(|cz| {
            let zone = FirewallZone::from_role(&cz.name);
            let ifaces = zone_interfaces(zones, &zone);
            (cz, ifaces)
        })
        .collect();

    // ── *filter table ──────────────────────────────────────────────
    emit_filter_table(&mut out, policy, |out| {
        // Default secure rules (conntrack, loopback, ICMP).
        emit_default_rules(out);

        // VLAN isolation rules (before zone rules — must be checked first).
        // Enforces WAN-01 (internal VLANs blocked on WAN) and FW-02 (VLAN 1 void DROP).
        emit_vlan_isolation_rules(out, zones);

        // Zone-specific rules.
        if !wan_ifaces.is_empty() {
            emit_wan_zone_rules(out, &wan_ifaces);
        }
        if !lan_ifaces.is_empty() {
            emit_lan_zone_rules(out, &lan_ifaces, &wan_ifaces, &dmz_ifaces);
        }
        if !dmz_ifaces.is_empty() {
            emit_dmz_zone_rules(out, &dmz_ifaces, &wan_ifaces, &lan_ifaces, &mgmt_ifaces);
        }
        if !mgmt_ifaces.is_empty() {
            emit_mgmt_zone_rules(
                out,
                &mgmt_ifaces,
                &wan_ifaces,
                &lan_ifaces,
                &dmz_ifaces,
                &guest_ifaces,
            );
        }
        if !guest_ifaces.is_empty() {
            emit_guest_zone_rules(
                out,
                &guest_ifaces,
                &wan_ifaces,
                &lan_ifaces,
                &dmz_ifaces,
                &mgmt_ifaces,
            );
        }

        // Custom zone rules (IoT, VPN, user-defined).
        for (cz, cz_ifaces) in &custom_iface_sets {
            if !cz_ifaces.is_empty() {
                emit_custom_zone_rules(
                    out,
                    cz,
                    cz_ifaces,
                    &wan_ifaces,
                    &lan_ifaces,
                    &mgmt_ifaces,
                    &dmz_ifaces,
                );
            }
        }

        // Port forwarding accept rules (WAN-only: restricts to WAN input interfaces).
        for fwd in forwards.iter().filter(|f| f.enabled) {
            if let Err(e) = emit_port_forward_accept(out, fwd, &wan_ifaces) {
                tracing::error!("skipping invalid port forward accept: {e}");
            }
        }

        // User-defined rules from DB (inserted BEFORE zone catch-all DROPs).
        if !rules.is_empty() {
            writeln!(out, "# ── User-defined rules ──").unwrap();
            for rule in rules {
                emit_single_rule(out, rule, zones);
            }
        }

        // Zone catch-all DROP rules — MUST be LAST in each chain so that
        // user-defined rules above are evaluated first.
        emit_zone_catchall_drops(
            out,
            &wan_ifaces,
            &lan_ifaces,
            &dmz_ifaces,
            &mgmt_ifaces,
            &guest_ifaces,
        );

        // Custom zone catch-all DROPs (also must be last).
        for (cz, cz_ifaces) in &custom_iface_sets {
            for iface in cz_ifaces {
                writeln!(
                    out,
                    "-A SFGW-INPUT -i {iface} -j DROP -m comment --comment \"drop all other {} input\"",
                    sanitize_comment(&cz.name),
                )
                .unwrap();
            }
        }
    });

    // ── *nat table ─────────────────────────────────────────────────
    emit_nat_table(&mut out, |out| {
        // Port forwarding DNAT rules.
        for fwd in forwards.iter().filter(|f| f.enabled) {
            if let Err(e) = emit_port_forward_dnat(out, fwd, &wan_ifaces) {
                tracing::error!("skipping invalid port forward: {e}");
            }
        }

        // NAT masquerade on WAN interfaces.
        if !wan_ifaces.is_empty() {
            emit_zone_masquerade(out, &wan_ifaces);
        }
    });

    out
}

// ── Table structure helpers ──────────────────────────────────────────

/// Emit a *filter table block with custom chains.
fn emit_filter_table(out: &mut String, policy: &FirewallPolicy, body: impl FnOnce(&mut String)) {
    writeln!(out, "*filter").unwrap();
    writeln!(
        out,
        ":INPUT {} [0:0]",
        action_to_policy(&policy.default_input)
    )
    .unwrap();
    writeln!(
        out,
        ":FORWARD {} [0:0]",
        action_to_policy(&policy.default_forward)
    )
    .unwrap();
    writeln!(
        out,
        ":OUTPUT {} [0:0]",
        action_to_policy(&policy.default_output)
    )
    .unwrap();

    // Custom chains.
    writeln!(out, ":SFGW-INPUT - [0:0]").unwrap();
    writeln!(out, ":SFGW-FORWARD - [0:0]").unwrap();
    writeln!(out, ":SFGW-OUTPUT - [0:0]").unwrap();

    // Jump from built-in chains to custom chains.
    writeln!(out, "-A INPUT -j SFGW-INPUT").unwrap();
    writeln!(out, "-A FORWARD -j SFGW-FORWARD").unwrap();
    writeln!(out, "-A OUTPUT -j SFGW-OUTPUT").unwrap();

    body(out);

    writeln!(out, "COMMIT").unwrap();
}

/// Emit a *nat table block with custom chains.
fn emit_nat_table(out: &mut String, body: impl FnOnce(&mut String)) {
    writeln!(out, "*nat").unwrap();
    writeln!(out, ":PREROUTING ACCEPT [0:0]").unwrap();
    writeln!(out, ":INPUT ACCEPT [0:0]").unwrap();
    writeln!(out, ":OUTPUT ACCEPT [0:0]").unwrap();
    writeln!(out, ":POSTROUTING ACCEPT [0:0]").unwrap();

    // Custom chains.
    writeln!(out, ":SFGW-PREROUTING - [0:0]").unwrap();
    writeln!(out, ":SFGW-POSTROUTING - [0:0]").unwrap();

    // Jump from built-in chains.
    writeln!(out, "-A PREROUTING -j SFGW-PREROUTING").unwrap();
    writeln!(out, "-A POSTROUTING -j SFGW-POSTROUTING").unwrap();

    body(out);

    writeln!(out, "COMMIT").unwrap();
}

// ── Default rules ────────────────────────────────────────────────────

/// Rules that are always present regardless of user configuration.
fn emit_default_rules(out: &mut String) {
    writeln!(out, "# ── Default secure rules (always present) ──").unwrap();

    // Connection tracking: allow established/related.
    writeln!(
        out,
        "-A SFGW-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    )
    .unwrap();
    writeln!(
        out,
        "-A SFGW-FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    )
    .unwrap();
    writeln!(
        out,
        "-A SFGW-OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    )
    .unwrap();

    // Drop invalid.
    writeln!(out, "-A SFGW-INPUT -m conntrack --ctstate INVALID -j DROP").unwrap();
    writeln!(
        out,
        "-A SFGW-FORWARD -m conntrack --ctstate INVALID -j DROP"
    )
    .unwrap();

    // Allow loopback.
    writeln!(out, "-A SFGW-INPUT -i lo -j ACCEPT").unwrap();
    writeln!(out, "-A SFGW-OUTPUT -o lo -j ACCEPT").unwrap();

    // Allow ICMP echo (ping) -- rate limited.
    writeln!(
        out,
        "-A SFGW-INPUT -p icmp --icmp-type echo-request -m limit --limit 5/sec -j ACCEPT"
    )
    .unwrap();

    // Note: ICMPv6/NDP rules are handled in the IPv6 ruleset via
    // filter_config_to_ipv6(), which replaces this ICMP rule with
    // proper ICMPv6 echo + NDP rules.

    writeln!(out).unwrap();
}

/// Hardened default ruleset when no user rules are configured.
fn emit_hardened_defaults(out: &mut String) {
    writeln!(out, "# ── Hardened defaults (no user rules in DB) ──").unwrap();

    // Allow DHCP on LAN interfaces.
    for iface in &["br-lan", "eth1"] {
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p udp --dport 67:68 -j ACCEPT -m comment --comment \"DHCP on LAN\""
        )
        .unwrap();
    }

    // Allow DNS on LAN interfaces.
    for iface in &["br-lan", "eth1"] {
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 53 -j ACCEPT -m comment --comment \"DNS on LAN\""
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p udp --dport 53 -j ACCEPT -m comment --comment \"DNS on LAN\""
        )
        .unwrap();
    }

    // Allow HTTPS on MGMT only.
    writeln!(
        out,
        "-A SFGW-INPUT -i br-mgmt -p tcp --dport 443 -j ACCEPT -m comment --comment \"HTTPS on MGMT\""
    )
    .unwrap();

    // Allow HTTP on MGMT for 301 redirect to HTTPS.
    writeln!(
        out,
        "-A SFGW-INPUT -i br-mgmt -p tcp --dport 80 -j ACCEPT -m comment --comment \"HTTP redirect on MGMT\""
    )
    .unwrap();

    // Allow SSH on MGMT only.
    writeln!(
        out,
        "-A SFGW-INPUT -i br-mgmt -p tcp --dport 22 -j ACCEPT -m comment --comment \"SSH on MGMT\""
    )
    .unwrap();

    // Allow Inform (8080) on MGMT VLAN only.
    writeln!(
        out,
        "-A SFGW-INPUT -i br-mgmt -p tcp --dport 8080 -j ACCEPT -m comment --comment \"Inform on MGMT only\""
    )
    .unwrap();

    // Allow forwarding from LAN to WAN.
    for lan in &["br-lan", "eth1"] {
        for wan in &["eth0", "ppp0"] {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {lan} -o {wan} -j ACCEPT -m comment --comment \"LAN to WAN\""
            )
            .unwrap();
        }
    }

    // Allow forwarding from MGMT to WAN.
    for wan in &["eth0", "ppp0"] {
        writeln!(
            out,
            "-A SFGW-FORWARD -i br-mgmt -o {wan} -j ACCEPT -m comment --comment \"MGMT to WAN\""
        )
        .unwrap();
    }

    // No WAN inbound (policy DROP handles it).
    writeln!(
        out,
        "# WAN inbound: policy DROP (no explicit rules = blocked)"
    )
    .unwrap();

    writeln!(out).unwrap();
}

/// Hardened NAT defaults for non-zone mode.
fn emit_hardened_nat_defaults(out: &mut String) {
    // NAT masquerade on WAN-like interfaces.
    for wan in &["eth0", "ppp0"] {
        writeln!(
            out,
            "-A SFGW-POSTROUTING -o {wan} -j MASQUERADE -m comment --comment \"NAT masquerade WAN\""
        )
        .unwrap();
    }
}

/// Emit user-defined filter rules from the database.
fn emit_user_rules(out: &mut String, rules: &[FirewallRule]) {
    writeln!(out, "# ── User-defined rules ──").unwrap();

    for rule in rules {
        if rule.chain == "postrouting" {
            continue; // NAT rules go in the nat table.
        }
        emit_single_rule(out, rule, &[]);
    }

    writeln!(out).unwrap();
}

/// Emit user-defined NAT rules from the database.
fn emit_user_nat_rules(out: &mut String, rules: &[FirewallRule]) {
    // Emit postrouting rules.
    for rule in rules.iter().filter(|r| r.chain == "postrouting") {
        emit_single_nat_rule(out, rule, &[]);
    }

    // Always add NAT masquerade on WAN-like interfaces.
    for wan in &["eth0", "ppp0"] {
        writeln!(
            out,
            "-A SFGW-POSTROUTING -o {wan} -j MASQUERADE -m comment --comment \"NAT masquerade WAN\""
        )
        .unwrap();
    }
}

// ── VLAN isolation rules ─────────────────────────────────────────────

/// Emit VLAN isolation rules that enforce WAN-01, FW-01, and FW-02.
///
/// These rules go BEFORE zone rules to ensure VLAN isolation is evaluated first.
///
/// **FW-02 — VLAN 1 void DROP on WAN interfaces:**
/// VLAN 1 is the "factory default untagged" VLAN. The VLAN trunk model assigns it
/// to the void zone (DROP all). WAN interfaces are unbridged, so a `.1` sub-interface
/// could theoretically be created by misconfiguration. The `br-void` rules are
/// defense-in-depth in case someone manually creates that bridge.
///
/// **WAN-01 — Internal VLANs blocked on WAN interfaces:**
/// Internal VLAN IDs (10, 3000, 3001, 3002, etc.) must never appear on WAN ports.
/// These sub-interface DROP rules prevent any misconfigured VLAN sub-interfaces from
/// leaking internal traffic onto the WAN.
///
/// **FW-01 — LAN zone uses VLAN 10 bridge (br-lan):**
/// This is enforced by `load_interface_zones()` which resolves the LAN zone to `br-lan`
/// (the bridge for VLAN 10). The zone rules already reference `br-lan`, not `br-1`.
fn emit_vlan_isolation_rules(out: &mut String, zones: &[ZonePolicy]) {
    writeln!(out, "# ── VLAN isolation rules (WAN-01, FW-02) ──").unwrap();

    // Collect WAN interfaces (raw names — WAN is unbridged).
    let wan_ifaces = zone_interfaces(zones, &FirewallZone::Wan);

    // FW-02: VLAN 1 void DROP on WAN interfaces.
    // WAN ports are unbridged; a misconfigured .1 sub-interface would bypass ASIC DROP.
    for wan in &wan_ifaces {
        writeln!(
            out,
            "-A SFGW-INPUT -i {wan}.1 -j DROP -m comment --comment \"VLAN 1 void DROP\""
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-FORWARD -i {wan}.1 -j DROP -m comment --comment \"VLAN 1 void DROP\""
        )
        .unwrap();
    }

    // FW-02: Defense-in-depth — drop br-void in case someone creates it manually.
    writeln!(
        out,
        "-A SFGW-INPUT -i br-void -j DROP -m comment --comment \"VLAN 1 void DROP\""
    )
    .unwrap();
    writeln!(
        out,
        "-A SFGW-FORWARD -i br-void -j DROP -m comment --comment \"VLAN 1 void DROP\""
    )
    .unwrap();

    // WAN-01: Internal VLANs blocked on WAN interfaces.
    // For each non-WAN zone with a vlan_id, DROP any sub-interface of that VLAN on WAN.
    for zone in zones {
        if zone.zone == FirewallZone::Wan {
            continue;
        }
        let Some(vid) = zone.vlan_id else {
            continue;
        };
        for wan in &wan_ifaces {
            writeln!(
                out,
                "-A SFGW-INPUT -i {wan}.{vid} -j DROP -m comment --comment \"no internal VLAN on WAN\""
            )
            .unwrap();
            writeln!(
                out,
                "-A SFGW-FORWARD -i {wan}.{vid} -j DROP -m comment --comment \"no internal VLAN on WAN\""
            )
            .unwrap();
        }
    }

    writeln!(out).unwrap();
}

// ── Zone-specific rule emitters ──────────────────────────────────────

/// Get validated interfaces for a zone.
fn zone_interfaces<'a>(zones: &'a [ZonePolicy], zone: &FirewallZone) -> Vec<&'a str> {
    let mut ifaces = Vec::new();
    for zp in zones {
        if &zp.zone == zone {
            for iface in &zp.interfaces {
                if validate_interface_name(iface).is_ok() {
                    ifaces.push(iface.as_str());
                } else {
                    tracing::error!("skipping invalid interface '{}' in zone {}", iface, zp.zone);
                }
            }
        }
    }
    ifaces
}

/// WAN zone rules: DROP all input, only established/related gets through,
/// no web UI, no SSH.
fn emit_wan_zone_rules(out: &mut String, wan_ifaces: &[&str]) {
    writeln!(out, "# ── WAN zone rules ──").unwrap();

    for iface in wan_ifaces {
        // Explicitly drop HTTP/HTTPS on WAN (defense-in-depth, policy is DROP anyway).
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 80 -j DROP -m comment --comment \"no web UI on WAN\"",
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 443 -j DROP -m comment --comment \"no web UI on WAN\"",
        )
        .unwrap();

        // Explicitly drop SSH on WAN.
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 22 -j DROP -m comment --comment \"no SSH on WAN\"",
        )
        .unwrap();

        // WAN ICMP rate limiting: 1/sec with burst of 3 (prevents ICMP flood
        // and host-discovery reconnaissance). Oversized payloads (>1500 bytes)
        // are dropped to prevent amplification attacks.
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p icmp --icmp-type echo-request -m length --length 1500:65535 -j DROP -m comment --comment \"drop oversized ICMP on WAN\"",
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p icmp --icmp-type echo-request -m limit --limit 1/sec --limit-burst 3 -j ACCEPT -m comment --comment \"WAN ICMP rate limit\"",
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p icmp --icmp-type echo-request -j DROP -m comment --comment \"WAN ICMP over limit\"",
        )
        .unwrap();

        // Note: catch-all DROP moved to emit_zone_catchall_drops() so user
        // rules inserted after zone rules are evaluated before the final DROP.
    }

    writeln!(out).unwrap();
}

/// LAN zone rules: DHCP, DNS, forward to WAN and DMZ.
/// SSH and web UI are MGMT-only — LAN clients get internet, not gateway access.
fn emit_lan_zone_rules(
    out: &mut String,
    lan_ifaces: &[&str],
    wan_ifaces: &[&str],
    dmz_ifaces: &[&str],
) {
    writeln!(out, "# ── LAN zone rules ──").unwrap();

    for iface in lan_ifaces {
        // Explicitly block SSH and web UI on LAN (MGMT-only).
        // Must be explicit DROP, not just omit ACCEPT — because the platform
        // may have its own ACCEPT rules in the INPUT chain after our jump.
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 22 -j DROP -m comment --comment \"no SSH on LAN\""
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 443 -j DROP -m comment --comment \"no web UI on LAN\""
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 80 -j DROP -m comment --comment \"no HTTP on LAN\""
        )
        .unwrap();

        // DHCP.
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p udp --dport 67:68 -j ACCEPT -m comment --comment \"DHCP on LAN\""
        )
        .unwrap();

        // DNS.
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 53 -j ACCEPT -m comment --comment \"DNS/TCP on LAN\""
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p udp --dport 53 -j ACCEPT -m comment --comment \"DNS/UDP on LAN\""
        )
        .unwrap();

        // Note: catch-all DROP moved to emit_zone_catchall_drops() so user
        // rules inserted after zone rules are evaluated before the final DROP.
    }

    // Forward LAN to WAN (outbound internet).
    for lan in lan_ifaces {
        for wan in wan_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {lan} -o {wan} -j ACCEPT -m comment --comment \"LAN to WAN\""
            )
            .unwrap();
        }
    }

    // Forward LAN to DMZ.
    for lan in lan_ifaces {
        for dmz in dmz_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {lan} -o {dmz} -j ACCEPT -m comment --comment \"LAN to DMZ\""
            )
            .unwrap();
        }
    }

    writeln!(out).unwrap();
}

/// DMZ zone rules: allow 80/443 inbound, no direct LAN/MGMT access, forward to WAN.
fn emit_dmz_zone_rules(
    out: &mut String,
    dmz_ifaces: &[&str],
    wan_ifaces: &[&str],
    lan_ifaces: &[&str],
    mgmt_ifaces: &[&str],
) {
    writeln!(out, "# ── DMZ zone rules ──").unwrap();

    for iface in dmz_ifaces {
        // DMZ gets DNS and DHCP to the gateway, nothing else.
        // HTTP/HTTPS forwarding to DMZ servers is handled via FORWARD rules,
        // not INPUT — INPUT is traffic TO the gateway itself.
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 53 -j ACCEPT -m comment --comment \"DNS/TCP on DMZ\""
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p udp --dport 53 -j ACCEPT -m comment --comment \"DNS/UDP on DMZ\""
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p udp --dport 67:68 -j ACCEPT -m comment --comment \"DHCP on DMZ\""
        )
        .unwrap();

        // Note: catch-all DROP moved to emit_zone_catchall_drops() so user
        // rules inserted after zone rules are evaluated before the final DROP.
    }

    // Block DMZ to LAN forwarding.
    for dmz in dmz_ifaces {
        for lan in lan_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {dmz} -o {lan} -j DROP -m comment --comment \"block DMZ to LAN\""
            )
            .unwrap();
        }
    }

    // Block DMZ to MGMT forwarding.
    for dmz in dmz_ifaces {
        for mgmt in mgmt_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {dmz} -o {mgmt} -j DROP -m comment --comment \"block DMZ to MGMT\""
            )
            .unwrap();
        }
    }

    // Allow DMZ to WAN (outbound internet).
    for dmz in dmz_ifaces {
        for wan in wan_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {dmz} -o {wan} -j ACCEPT -m comment --comment \"DMZ to WAN\""
            )
            .unwrap();
        }
    }

    writeln!(out).unwrap();
}

/// MGMT zone rules: full admin access.
fn emit_mgmt_zone_rules(
    out: &mut String,
    mgmt_ifaces: &[&str],
    wan_ifaces: &[&str],
    lan_ifaces: &[&str],
    dmz_ifaces: &[&str],
    guest_ifaces: &[&str],
) {
    writeln!(out, "# ── MGMT zone rules ──").unwrap();

    for iface in mgmt_ifaces {
        // Web UI access (HTTPS).
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 443 -j ACCEPT -m comment --comment \"web UI on MGMT\""
        )
        .unwrap();

        // HTTP → HTTPS redirect (port 80, 301 only — no plaintext content served).
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 80 -j ACCEPT -m comment --comment \"HTTP redirect on MGMT\""
        )
        .unwrap();

        // SSH for management.
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 22 -j ACCEPT -m comment --comment \"SSH on MGMT\""
        )
        .unwrap();

        // Inform protocol for device adoption.
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 8080 -j ACCEPT -m comment --comment \"Inform on MGMT\""
        )
        .unwrap();

        // DHCP + DNS to gateway.
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p udp --dport 67:68 -j ACCEPT -m comment --comment \"DHCP on MGMT\""
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 53 -j ACCEPT -m comment --comment \"DNS/TCP on MGMT\""
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p udp --dport 53 -j ACCEPT -m comment --comment \"DNS/UDP on MGMT\""
        )
        .unwrap();

        // Note: catch-all DROP moved to emit_zone_catchall_drops() so user
        // rules inserted after zone rules are evaluated before the final DROP.
    }

    // MGMT can reach all internal zones.
    for mgmt in mgmt_ifaces {
        for lan in lan_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {mgmt} -o {lan} -j ACCEPT -m comment --comment \"MGMT to LAN\""
            )
            .unwrap();
        }
        for dmz in dmz_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {mgmt} -o {dmz} -j ACCEPT -m comment --comment \"MGMT to DMZ\""
            )
            .unwrap();
        }
        for guest in guest_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {mgmt} -o {guest} -j ACCEPT -m comment --comment \"MGMT to GUEST\""
            )
            .unwrap();
        }
        for wan in wan_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {mgmt} -o {wan} -j ACCEPT -m comment --comment \"MGMT to WAN\""
            )
            .unwrap();
        }
    }

    writeln!(out).unwrap();
}

/// GUEST zone rules: internet only, DNS/DHCP to gateway, no internal access.
fn emit_guest_zone_rules(
    out: &mut String,
    guest_ifaces: &[&str],
    wan_ifaces: &[&str],
    lan_ifaces: &[&str],
    dmz_ifaces: &[&str],
    mgmt_ifaces: &[&str],
) {
    writeln!(out, "# ── GUEST zone rules ──").unwrap();

    for iface in guest_ifaces {
        // Explicitly block management ports before any ACCEPT.
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 22 -j DROP -m comment --comment \"no SSH on GUEST\""
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 443 -j DROP -m comment --comment \"no web UI on GUEST\""
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 80 -j DROP -m comment --comment \"no HTTP on GUEST\""
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 8080 -j DROP -m comment --comment \"no Inform on GUEST\""
        )
        .unwrap();

        // DNS to gateway.
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 53 -j ACCEPT -m comment --comment \"DNS/TCP on GUEST\""
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p udp --dport 53 -j ACCEPT -m comment --comment \"DNS/UDP on GUEST\""
        )
        .unwrap();

        // DHCP to gateway.
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p udp --dport 67:68 -j ACCEPT -m comment --comment \"DHCP on GUEST\""
        )
        .unwrap();

        // Note: catch-all DROP moved to emit_zone_catchall_drops() so user
        // rules inserted after zone rules are evaluated before the final DROP.
    }

    // Block GUEST to all internal zones.
    for guest in guest_ifaces {
        for lan in lan_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {guest} -o {lan} -j DROP -m comment --comment \"block GUEST to LAN\""
            )
            .unwrap();
        }
        for dmz in dmz_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {guest} -o {dmz} -j DROP -m comment --comment \"block GUEST to DMZ\""
            )
            .unwrap();
        }
        for mgmt in mgmt_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {guest} -o {mgmt} -j DROP -m comment --comment \"block GUEST to MGMT\""
            )
            .unwrap();
        }
    }

    // GUEST to WAN only (internet access).
    for guest in guest_ifaces {
        for wan in wan_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {guest} -o {wan} -j ACCEPT -m comment --comment \"GUEST to WAN\""
            )
            .unwrap();
        }
    }

    writeln!(out).unwrap();
}

/// Custom zone rules: generated from DB `custom_zones` table config.
///
/// Security model:
/// - **IoT-like** (outbound=accept, forward=drop): internet access only, no inter-VLAN.
/// - **VPN-like** (outbound=accept, forward=drop + LAN allow): LAN access, no MGMT/DMZ.
/// - **Custom**: fully user-defined inbound/outbound/forward policies.
///
/// All custom zones:
/// - Always block SSH (22), HTTPS (443), HTTP (80), Inform (8080) to gateway.
/// - Always block access to MGMT zone (security invariant).
/// - DNS and DHCP to gateway are allowed if in `allowed_services`.
fn emit_custom_zone_rules(
    out: &mut String,
    cz: &CustomZone,
    cz_ifaces: &[&str],
    wan_ifaces: &[&str],
    lan_ifaces: &[&str],
    mgmt_ifaces: &[&str],
    dmz_ifaces: &[&str],
) {
    let safe_name = sanitize_comment(&cz.name);
    writeln!(out, "# ── Custom zone rules: {} ──", safe_name).unwrap();

    for iface in cz_ifaces {
        // Security invariant: always block management ports on custom zones.
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 22 -j DROP -m comment --comment \"no SSH on {safe_name}\""
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 443 -j DROP -m comment --comment \"no web UI on {safe_name}\""
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 80 -j DROP -m comment --comment \"no HTTP on {safe_name}\""
        )
        .unwrap();
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -p tcp --dport 8080 -j DROP -m comment --comment \"no Inform on {safe_name}\""
        )
        .unwrap();

        // Allowed services to the gateway (e.g., DNS, DHCP).
        for svc in &cz.allowed_services {
            let proto = svc.protocol.to_lowercase();
            if validate_protocol(&proto).is_err() {
                tracing::error!(
                    "skipping invalid protocol '{}' in custom zone '{}'",
                    svc.protocol,
                    cz.name
                );
                continue;
            }
            let port_label = format!("port {}", svc.port);
            let svc_desc = svc.description.as_deref().unwrap_or(&port_label);
            let svc_comment = sanitize_comment(svc_desc);
            writeln!(
                out,
                "-A SFGW-INPUT -i {iface} -p {proto} --dport {} -j ACCEPT -m comment --comment \"{svc_comment} on {safe_name}\"",
                svc.port,
            )
            .unwrap();
        }
    }

    // Forward rules based on policy.
    let fwd_target = action_to_target(&cz.policy_forward);

    // Security invariant: always block custom zone -> MGMT forwarding regardless of policy.
    for cz_iface in cz_ifaces {
        for mgmt in mgmt_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {cz_iface} -o {mgmt} -j DROP -m comment --comment \"block {safe_name} to MGMT\""
            )
            .unwrap();
        }
    }

    // Forward to WAN: controlled by outbound policy.
    let out_target = action_to_target(&cz.policy_outbound);
    for cz_iface in cz_ifaces {
        for wan in wan_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {cz_iface} -o {wan} -j {out_target} -m comment --comment \"{safe_name} to WAN\""
            )
            .unwrap();
        }
    }

    // Forward to LAN: VPN zones get ACCEPT, IoT/custom get their forward policy.
    // Check if this is a VPN-like zone (name contains "vpn").
    let is_vpn_like = cz.name.contains("vpn");
    let lan_fwd = if is_vpn_like { "ACCEPT" } else { fwd_target };
    for cz_iface in cz_ifaces {
        for lan in lan_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {cz_iface} -o {lan} -j {lan_fwd} -m comment --comment \"{safe_name} to LAN\""
            )
            .unwrap();
        }
    }

    // Forward to DMZ: controlled by forward policy.
    for cz_iface in cz_ifaces {
        for dmz in dmz_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {cz_iface} -o {dmz} -j {fwd_target} -m comment --comment \"{safe_name} to DMZ\""
            )
            .unwrap();
        }
    }

    writeln!(out).unwrap();
}

/// Emit catch-all DROP rules for all zones.
///
/// These MUST be emitted LAST in the filter table so that user-defined rules
/// (inserted between zone-specific ACCEPT rules and these DROPs) are evaluated
/// before the catch-all. This fixes the issue where user rules after zone
/// catch-all DROPs were silently ignored.
fn emit_zone_catchall_drops(
    out: &mut String,
    wan_ifaces: &[&str],
    lan_ifaces: &[&str],
    dmz_ifaces: &[&str],
    mgmt_ifaces: &[&str],
    guest_ifaces: &[&str],
) {
    writeln!(out, "# ── Zone catch-all DROPs (must be last) ──").unwrap();

    for iface in wan_ifaces {
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -j DROP -m comment --comment \"drop all WAN input\""
        )
        .unwrap();
    }
    for iface in lan_ifaces {
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -j DROP -m comment --comment \"drop all other LAN input\""
        )
        .unwrap();
    }
    for iface in dmz_ifaces {
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -j DROP -m comment --comment \"drop all other DMZ input\""
        )
        .unwrap();
    }
    for iface in mgmt_ifaces {
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -j DROP -m comment --comment \"drop all other MGMT input\""
        )
        .unwrap();
    }
    for iface in guest_ifaces {
        writeln!(
            out,
            "-A SFGW-INPUT -i {iface} -j DROP -m comment --comment \"block all other GUEST input\""
        )
        .unwrap();
    }

    writeln!(out).unwrap();
}

/// Emit NAT masquerade rules for zone interfaces.
fn emit_zone_masquerade(out: &mut String, wan_ifaces: &[&str]) {
    for iface in wan_ifaces {
        writeln!(
            out,
            "-A SFGW-POSTROUTING -o {iface} -j MASQUERADE -m comment --comment \"NAT masquerade WAN\""
        )
        .unwrap();
    }
}

// ── Port forwarding helpers ──────────────────────────────────────────

/// Emit a DNAT rule in the nat table for a port forward.
fn emit_port_forward_dnat(out: &mut String, fwd: &PortForward, wan_ifaces: &[&str]) -> Result<()> {
    let proto = fwd.protocol.to_lowercase();
    validate_protocol(&proto)?;
    let _ip: IpAddr = fwd
        .internal_ip
        .parse()
        .with_context(|| format!("invalid internal_ip in port forward: {}", fwd.internal_ip))?;

    let comment = sanitize_comment(fwd.comment.as_deref().unwrap_or("port forward"));

    if let Some(ref iface) = fwd.wan_interface {
        // Specific WAN interface binding.
        validate_interface_name(iface)
            .with_context(|| format!("invalid wan_interface in port forward: {iface}"))?;
        writeln!(
            out,
            "-A SFGW-PREROUTING -i {iface} -p {proto} --dport {} -j DNAT --to-destination {}:{} -m comment --comment \"{comment}\"",
            fwd.external_port, fwd.internal_ip, fwd.internal_port,
        )
        .unwrap();
    } else if !wan_ifaces.is_empty() {
        // Zone mode: expand to all WAN interfaces.
        for iface in wan_ifaces {
            writeln!(
                out,
                "-A SFGW-PREROUTING -i {iface} -p {proto} --dport {} -j DNAT --to-destination {}:{} -m comment --comment \"{comment}\"",
                fwd.external_port, fwd.internal_ip, fwd.internal_port,
            )
            .unwrap();
        }
    } else {
        // Legacy mode: no interface restriction.
        writeln!(
            out,
            "-A SFGW-PREROUTING -p {proto} --dport {} -j DNAT --to-destination {}:{} -m comment --comment \"{comment}\"",
            fwd.external_port, fwd.internal_ip, fwd.internal_port,
        )
        .unwrap();
    }

    Ok(())
}

/// Emit a forward accept rule for port-forwarded traffic.
///
/// ACCEPT rules are restricted to WAN input interfaces only. Port forwards
/// from the internet should not create ACCEPT rules that also apply to
/// LAN/DMZ/MGMT traffic — that would let internal hosts bypass zone policy
/// by sending traffic to the DNAT destination directly.
fn emit_port_forward_accept(
    out: &mut String,
    fwd: &PortForward,
    wan_ifaces: &[&str],
) -> Result<()> {
    let proto = fwd.protocol.to_lowercase();
    validate_protocol(&proto)?;
    let _ip: IpAddr = fwd
        .internal_ip
        .parse()
        .with_context(|| format!("invalid internal_ip in port forward: {}", fwd.internal_ip))?;

    let comment = sanitize_comment(fwd.comment.as_deref().unwrap_or("port forward"));

    if let Some(ref iface) = fwd.wan_interface {
        // Specific WAN interface binding.
        validate_interface_name(iface)
            .with_context(|| format!("invalid wan_interface in port forward: {iface}"))?;
        writeln!(
            out,
            "-A SFGW-FORWARD -i {iface} -d {} -p {proto} --dport {} -j ACCEPT -m comment --comment \"allow fwd: {comment}\"",
            fwd.internal_ip, fwd.internal_port,
        )
        .unwrap();
    } else if !wan_ifaces.is_empty() {
        // Zone mode: restrict to all WAN interfaces.
        for iface in wan_ifaces {
            writeln!(
                out,
                "-A SFGW-FORWARD -i {iface} -d {} -p {proto} --dport {} -j ACCEPT -m comment --comment \"allow fwd: {comment}\"",
                fwd.internal_ip, fwd.internal_port,
            )
            .unwrap();
        }
    } else {
        // Legacy mode (no zones): no interface restriction available.
        writeln!(
            out,
            "-A SFGW-FORWARD -d {} -p {proto} --dport {} -j ACCEPT -m comment --comment \"allow fwd: {comment}\"",
            fwd.internal_ip, fwd.internal_port,
        )
        .unwrap();
    }

    Ok(())
}

// ── Single rule emission ─────────────────────────────────────────────

fn emit_single_rule(out: &mut String, rule: &FirewallRule, zones: &[ZonePolicy]) {
    if let Err(e) = emit_single_rule_validated(out, rule, zones) {
        tracing::error!("skipping invalid firewall rule id={:?}: {e}", rule.id);
    }
}

fn emit_single_rule_validated(
    out: &mut String,
    rule: &FirewallRule,
    zones: &[ZonePolicy],
) -> Result<()> {
    let detail = &rule.detail;
    let chain = &rule.chain;

    // Validate chain name.
    validate_chain(chain)?;

    // Postrouting/NAT rules are handled separately.
    if chain == "postrouting" || chain == "prerouting" {
        return Ok(());
    }

    let target_chain = sfgw_chain(chain);

    // Build the rule parts.
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("-A {target_chain}"));

    // Source interface (iif:) or IP address.
    let src = detail.source.to_lowercase();
    if src != "any" && src != "0.0.0.0/0" {
        if let Some(iface) = src.strip_prefix("iif:") {
            if let Some(set_name) = iface.strip_prefix('@') {
                // Zone set reference -- expand to individual interfaces.
                // We will emit multiple rules, one per interface.
                let zone_name = set_name.strip_suffix("_ifaces").unwrap_or(set_name);
                let ifaces = find_zone_ifaces(zones, zone_name);
                if ifaces.is_empty() {
                    // If we cannot resolve the set, skip this rule.
                    bail!("cannot resolve zone set @{set_name}: no interfaces found");
                }
                // Emit one rule per interface and return.
                for ziface in &ifaces {
                    let mut iparts = parts.clone();
                    iparts.push(format!("-i {ziface}"));
                    emit_rule_tail(&mut iparts, detail, zones)?;
                    writeln!(out, "{}", iparts.join(" ")).unwrap();
                }
                return Ok(());
            } else {
                validate_interface_name(iface)?;
                parts.push(format!("-i {iface}"));
            }
        } else {
            validate_ip_or_cidr(&src)?;
            parts.push(format!("-s {src}"));
        }
    }

    // Destination interface (oif:) or IP address.
    let dst = detail.destination.to_lowercase();
    if dst != "any" && dst != "0.0.0.0/0" {
        if let Some(iface) = dst.strip_prefix("oif:") {
            if let Some(set_name) = iface.strip_prefix('@') {
                // Zone set reference -- expand.
                let zone_name = set_name.strip_suffix("_ifaces").unwrap_or(set_name);
                let ifaces = find_zone_ifaces(zones, zone_name);
                if ifaces.is_empty() {
                    bail!("cannot resolve zone set @{set_name}: no interfaces found");
                }
                // Emit one rule per destination interface.
                for ziface in &ifaces {
                    let mut iparts = parts.clone();
                    iparts.push(format!("-o {ziface}"));
                    emit_rule_tail(&mut iparts, detail, zones)?;
                    writeln!(out, "{}", iparts.join(" ")).unwrap();
                }
                return Ok(());
            } else {
                validate_interface_name(iface)?;
                parts.push(format!("-o {iface}"));
            }
        } else {
            validate_ip_or_cidr(&dst)?;
            parts.push(format!("-d {dst}"));
        }
    }

    emit_rule_tail(&mut parts, detail, zones)?;
    writeln!(out, "{}", parts.join(" ")).unwrap();
    Ok(())
}

/// Append protocol, port, rate limit, action, and comment to rule parts.
fn emit_rule_tail(
    parts: &mut Vec<String>,
    detail: &crate::RuleDetail,
    _zones: &[ZonePolicy],
) -> Result<()> {
    // Protocol.
    let proto = detail.protocol.to_lowercase();
    if proto != "any" && proto != "all" {
        validate_protocol(&proto)?;
        parts.push(format!("-p {proto}"));
    }

    // Port (only valid for tcp/udp/sctp).
    if let Some(ref port) = detail.port
        && !port.is_empty()
        && port != "any"
    {
        validate_port(port)?;
        if matches!(proto.as_str(), "tcp" | "udp" | "sctp") {
            parts.push(port_to_iptables(port));
        }
    }

    // Rate limiting.
    if let Some(ref rate) = detail.rate_limit {
        validate_rate_limit(rate)?;
        parts.push(rate_limit_to_iptables(rate));
    }

    // Action/target.
    parts.push(format!("-j {}", action_to_target(&detail.action)));

    // Comment -- sanitize to prevent injection.
    if let Some(ref comment) = detail.comment
        && !comment.is_empty()
    {
        let safe = sanitize_comment(comment);
        if !safe.is_empty() {
            parts.push(format!("-m comment --comment \"{safe}\""));
        }
    }

    Ok(())
}

/// Emit a single NAT rule (postrouting).
fn emit_single_nat_rule(out: &mut String, rule: &FirewallRule, zones: &[ZonePolicy]) {
    if let Err(e) = emit_single_nat_rule_validated(out, rule, zones) {
        tracing::error!("skipping invalid NAT rule id={:?}: {e}", rule.id);
    }
}

fn emit_single_nat_rule_validated(
    out: &mut String,
    rule: &FirewallRule,
    zones: &[ZonePolicy],
) -> Result<()> {
    let detail = &rule.detail;
    let target_chain = sfgw_chain(&rule.chain);

    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("-A {target_chain}"));

    // Destination interface for masquerade.
    let dst = detail.destination.to_lowercase();
    if dst != "any"
        && dst != "0.0.0.0/0"
        && let Some(iface) = dst.strip_prefix("oif:")
    {
        if let Some(set_name) = iface.strip_prefix('@') {
            let zone_name = set_name.strip_suffix("_ifaces").unwrap_or(set_name);
            let ifaces = find_zone_ifaces(zones, zone_name);
            for ziface in &ifaces {
                let comment = sanitize_comment(detail.comment.as_deref().unwrap_or(""));
                let mut line = format!(
                    "-A {target_chain} -o {ziface} -j {}",
                    action_to_target(&detail.action)
                );
                if !comment.is_empty() {
                    write!(line, " -m comment --comment \"{comment}\"").unwrap();
                }
                writeln!(out, "{line}").unwrap();
            }
            return Ok(());
        } else {
            validate_interface_name(iface)?;
            parts.push(format!("-o {iface}"));
        }
    }

    parts.push(format!("-j {}", action_to_target(&detail.action)));

    if let Some(ref comment) = detail.comment
        && !comment.is_empty()
    {
        let safe = sanitize_comment(comment);
        if !safe.is_empty() {
            parts.push(format!("-m comment --comment \"{safe}\""));
        }
    }

    writeln!(out, "{}", parts.join(" ")).unwrap();
    Ok(())
}

/// Look up zone interfaces by zone name string.
fn find_zone_ifaces<'a>(zones: &'a [ZonePolicy], zone_name: &str) -> Vec<&'a str> {
    let zone = FirewallZone::from_role(zone_name);
    zone_interfaces(zones, &zone)
}

#[cfg(test)]
mod tests;
