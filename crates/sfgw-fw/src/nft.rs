// SPDX-License-Identifier: AGPL-3.0-or-later

//! nftables ruleset generation and atomic application via `nft -f`.

use crate::{Action, FirewallPolicy, FirewallRule, FirewallZone, PortForward, ZonePolicy};
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
    // nftables also accepts comma-separated lists like "80,443,8080"
    // and ranges like "1024-65535"
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

/// Validate a named set reference: alphanumeric + underscore, 1-31 chars.
fn validate_set_name(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 31 {
        bail!("invalid set name '{}': must be 1-31 characters", s);
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        bail!(
            "invalid set name '{}': only alphanumeric and '_' allowed",
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

/// Table name used for all sfgw rules.
const TABLE: &str = "sfgw";

/// Generate a complete nftables ruleset from DB rules and policy.
///
/// If `rules` is empty, a hardened default ruleset is generated.
///
/// # Panics
/// Uses `writeln!().unwrap()` throughout — these cannot fail because
/// `fmt::Write` for `String` is infallible (never returns `Err`).
pub fn generate_ruleset(rules: &[FirewallRule], policy: &FirewallPolicy) -> String {
    // INVARIANT: All writeln!(out, ...).unwrap() calls below write to a String.
    // fmt::Write for String is infallible — it can only fail on OOM which aborts.
    let mut out = String::with_capacity(4096);

    // Flush and recreate — atomic when loaded via `nft -f`.
    writeln!(out, "#!/usr/sbin/nft -f").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "# Generated by sfgw-fw — do not edit manually").unwrap();
    writeln!(out).unwrap();

    // Destroy previous table (ignore if not exists).
    writeln!(out, "table inet {TABLE} {{}}").unwrap();
    writeln!(out, "delete table inet {TABLE}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "table inet {TABLE} {{").unwrap();

    // ── Base chains ─────────────────────────────────────────────────
    emit_chain(&mut out, "input", "filter", "input", &policy.default_input);
    emit_chain(
        &mut out,
        "forward",
        "filter",
        "forward",
        &policy.default_forward,
    );
    emit_chain(
        &mut out,
        "output",
        "filter",
        "output",
        &policy.default_output,
    );

    // NAT chains.
    emit_nat_chains(&mut out);

    writeln!(out).unwrap();

    // Close table definition — rules follow after via `add rule`.
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // ── Default secure rules (always present) ───────────────────────
    emit_default_rules(&mut out);

    if rules.is_empty() {
        // No user rules — emit hardened defaults.
        emit_hardened_defaults(&mut out);
    } else {
        // User rules from DB.
        emit_user_rules(&mut out, rules);
    }

    out
}

/// Generate a ruleset that also includes port-forwarding DNAT entries.
pub fn generate_ruleset_with_forwards(
    rules: &[FirewallRule],
    policy: &FirewallPolicy,
    forwards: &[PortForward],
) -> String {
    let mut out = generate_ruleset(rules, policy);

    if forwards.is_empty() {
        return out;
    }

    // Append DNAT rules after the table definition (add rule syntax).
    writeln!(out).unwrap();
    writeln!(out, "# ── Port forwarding (DNAT) ──").unwrap();
    for fwd in forwards.iter().filter(|f| f.enabled) {
        if let Err(e) = emit_port_forward(&mut out, fwd, None) {
            tracing::error!("skipping invalid port forward: {e}");
        }
    }

    out
}

/// Atomically apply an nftables ruleset.
///
/// Writes config to a temp file, then runs `nft -f <file>`.
/// On failure the old rules remain (nft is transactional).
pub async fn apply_ruleset(config: &str) -> Result<()> {
    use tokio::fs;
    use tokio::process::Command;

    let tmp_path = "/tmp/sfgw-nft.conf";
    fs::write(tmp_path, config)
        .await
        .context("failed to write nftables config to temp file")?;

    let output = Command::new("nft")
        .arg("-f")
        .arg(tmp_path)
        .output()
        .await
        .context("failed to execute nft")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Keep config file for debugging on failure.
        tracing::error!(path = tmp_path, "nft config kept for debugging");
        anyhow::bail!(
            "nft -f failed (exit {}): {}",
            output.status,
            stderr.trim()
        );
    }

    // Clean up temp file on success.
    let _ = fs::remove_file(tmp_path).await;

    tracing::info!("nftables ruleset applied atomically");
    Ok(())
}

/// Flush all sfgw rules (remove the table entirely).
pub async fn flush_ruleset() -> Result<()> {
    use tokio::process::Command;

    let output = Command::new("nft")
        .args(["delete", "table", "inet", TABLE])
        .output()
        .await
        .context("failed to execute nft delete")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Not an error if the table doesn't exist.
        if !stderr.contains("No such file or directory") {
            anyhow::bail!("nft delete table failed: {}", stderr.trim());
        }
    }

    tracing::info!("nftables table {TABLE} flushed");
    Ok(())
}

// ── Zone-aware ruleset generation ────────────────────────────────────

/// Generate a complete zone-aware nftables ruleset.
///
/// Uses actual interface assignments from the database instead of
/// hardcoded interface name patterns.
///
/// Security policies per zone:
/// - **WAN**: DROP all input, only established/related, no web UI, NAT masquerade
/// - **LAN**: Allow web UI (443), DHCP, DNS, forward to WAN/DMZ, no forward to GUEST
/// - **DMZ**: Allow 80/443 inbound, no direct LAN/MGMT access, forward to WAN
/// - **MGMT**: Web UI (443), SSH (22), Inform (8080), access to all internal zones
/// - **GUEST**: Internet only (forward to WAN), DNS/DHCP to gateway, no internal access
/// # Panics
/// Uses `writeln!().unwrap()` throughout — these cannot fail because
/// `fmt::Write` for `String` is infallible (never returns `Err`).
pub fn generate_zone_ruleset(
    zones: &[ZonePolicy],
    rules: &[FirewallRule],
    policy: &FirewallPolicy,
    forwards: &[PortForward],
) -> String {
    // INVARIANT: All writeln!(out, ...).unwrap() calls write to a String.
    // fmt::Write for String is infallible — it can only fail on OOM which aborts.
    let mut out = String::with_capacity(8192);

    writeln!(out, "#!/usr/sbin/nft -f").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "# Generated by sfgw-fw (zone-aware) — do not edit manually"
    )
    .unwrap();
    writeln!(out).unwrap();

    // Destroy previous table (ignore if not exists).
    writeln!(out, "table inet {TABLE} {{}}").unwrap();
    writeln!(out, "delete table inet {TABLE}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "table inet {TABLE} {{").unwrap();

    // ── Interface set definitions ───────────────────────────────────
    emit_zone_defines(&mut out, zones);

    // ── Base chains ─────────────────────────────────────────────────
    emit_chain(&mut out, "input", "filter", "input", &policy.default_input);
    emit_chain(
        &mut out,
        "forward",
        "filter",
        "forward",
        &policy.default_forward,
    );
    emit_chain(
        &mut out,
        "output",
        "filter",
        "output",
        &policy.default_output,
    );
    emit_nat_chains(&mut out);

    writeln!(out).unwrap();

    // Close table definition — chains and sets are defined, rules follow after.
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // ── Rules are emitted AFTER the table block ─────────────────────
    // In nft -f files, `add rule` statements must be outside the table
    // definition block. The table/chains/sets are declared first, then
    // rules are appended via `add rule`.

    // ── Default secure rules (conntrack, loopback, ICMP) ────────────
    emit_default_rules(&mut out);

    // ── Zone-specific rules ─────────────────────────────────────────
    let has_wan = zone_has_interfaces(zones, &FirewallZone::Wan);
    let has_lan = zone_has_interfaces(zones, &FirewallZone::Lan);
    let has_dmz = zone_has_interfaces(zones, &FirewallZone::Dmz);
    let has_mgmt = zone_has_interfaces(zones, &FirewallZone::Mgmt);
    let has_guest = zone_has_interfaces(zones, &FirewallZone::Guest);

    if has_wan {
        emit_wan_zone_rules(&mut out);
    }
    if has_lan {
        emit_lan_zone_rules(&mut out, has_wan, has_dmz);
    }
    if has_dmz {
        emit_dmz_zone_rules(&mut out, has_wan);
    }
    if has_mgmt {
        emit_mgmt_zone_rules(&mut out, has_wan, has_lan, has_dmz, has_guest);
    }
    if has_guest {
        emit_guest_zone_rules(&mut out, has_wan);
    }

    // ── Port forwarding (DNAT) ──────────────────────────────────────
    for fwd in forwards.iter().filter(|f| f.enabled) {
        if let Err(e) = emit_port_forward(&mut out, fwd, Some("iifname @wan_ifaces ")) {
            tracing::error!("skipping invalid port forward: {e}");
        }
    }

    // ── User-defined rules from DB ──────────────────────────────────
    if !rules.is_empty() {
        writeln!(out, "# ── User-defined rules ──").unwrap();
        for rule in rules {
            emit_single_rule(&mut out, rule);
        }
        writeln!(out).unwrap();
    }

    out
}

/// Emit nftables named sets for each zone's interfaces.
fn emit_zone_defines(out: &mut String, zones: &[ZonePolicy]) {
    writeln!(out, "    # ── Zone interface sets ──").unwrap();

    for zp in zones {
        if zp.interfaces.is_empty() {
            continue;
        }
        // Validate every interface name before emitting into nft syntax.
        let mut valid_ifaces = Vec::new();
        for iface in &zp.interfaces {
            if let Err(e) = validate_interface_name(iface) {
                tracing::error!(
                    "skipping invalid interface '{}' in zone {}: {e}",
                    iface,
                    zp.zone
                );
                continue;
            }
            valid_ifaces.push(format!("\"{iface}\""));
        }
        if valid_ifaces.is_empty() {
            continue;
        }
        let set_name = format!("{}_ifaces", zp.zone);
        writeln!(
            out,
            "    set {set_name} {{ type ifname; elements = {{ {} }}; }}",
            valid_ifaces.join(", ")
        )
        .unwrap();
    }
    writeln!(out).unwrap();
}

/// Emit a validated port forward rule. `prefix` is an optional string prepended
/// to the prerouting rule (e.g. "iifname @wan_ifaces " for zone-aware mode).
///
/// If the port forward has a `wan_interface` set, that takes precedence over
/// the zone-level prefix, binding the rule to a specific WAN interface.
fn emit_port_forward(out: &mut String, fwd: &PortForward, prefix: Option<&str>) -> Result<()> {
    let proto = fwd.protocol.to_lowercase();
    validate_protocol(&proto)?;
    // internal_ip must be a valid IP address.
    let _ip: IpAddr = fwd
        .internal_ip
        .parse()
        .with_context(|| format!("invalid internal_ip in port forward: {}", fwd.internal_ip))?;

    // Determine the interface match prefix:
    // - wan_interface on the rule takes precedence (specific WAN binding)
    // - Otherwise fall back to the zone-level prefix (e.g. "@wan_ifaces")
    // - Otherwise no prefix (legacy non-zone mode)
    let effective_prefix: String = if let Some(ref iface) = fwd.wan_interface {
        validate_interface_name(iface)
            .with_context(|| format!("invalid wan_interface in port forward: {iface}"))?;
        format!("iifname \"{iface}\" ")
    } else {
        prefix.unwrap_or("").to_string()
    };

    // external_port and internal_port are u16, inherently safe.
    let comment = sanitize_comment(fwd.comment.as_deref().unwrap_or("port forward"));
    writeln!(
        out,
        "    add rule inet {TABLE} prerouting {effective_prefix}{proto} dport {} dnat to {}:{} comment \"{comment}\"",
        fwd.external_port, fwd.internal_ip, fwd.internal_port,
    )
    .unwrap();
    writeln!(
        out,
        "    add rule inet {TABLE} forward ip daddr {} {proto} dport {} accept comment \"allow fwd: {comment}\"",
        fwd.internal_ip, fwd.internal_port,
    )
    .unwrap();
    Ok(())
}

fn zone_has_interfaces(zones: &[ZonePolicy], zone: &FirewallZone) -> bool {
    zones
        .iter()
        .any(|zp| &zp.zone == zone && !zp.interfaces.is_empty())
}

/// WAN zone rules: DROP all input, only established/related gets through,
/// no web UI, NAT masquerade outbound.
fn emit_wan_zone_rules(out: &mut String) {
    writeln!(out, "    # ── WAN zone rules ──").unwrap();

    // Explicitly drop HTTP/HTTPS on WAN (defense-in-depth, policy is DROP anyway).
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @wan_ifaces tcp dport {{ 80, 443 }} drop comment \"no web UI on WAN\""
    ).unwrap();

    // Explicitly drop SSH on WAN.
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @wan_ifaces tcp dport 22 drop comment \"no SSH on WAN\""
    ).unwrap();

    // NAT masquerade outbound on WAN.
    writeln!(
        out,
        "    add rule inet {TABLE} postrouting oifname @wan_ifaces masquerade comment \"NAT masquerade WAN\""
    ).unwrap();

    writeln!(out).unwrap();
}

/// LAN zone rules: allow web UI, DHCP, DNS, SSH; forward to WAN and DMZ.
fn emit_lan_zone_rules(out: &mut String, has_wan: bool, has_dmz: bool) {
    writeln!(out, "    # ── LAN zone rules ──").unwrap();

    // Web UI access (HTTPS only).
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @lan_ifaces tcp dport 443 accept comment \"web UI on LAN\""
    ).unwrap();

    // SSH for management.
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @lan_ifaces tcp dport 22 accept comment \"SSH on LAN\""
    ).unwrap();

    // DHCP.
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @lan_ifaces udp dport {{ 67, 68 }} accept comment \"DHCP on LAN\""
    ).unwrap();

    // DNS.
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @lan_ifaces tcp dport 53 accept comment \"DNS/TCP on LAN\""
    ).unwrap();
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @lan_ifaces udp dport 53 accept comment \"DNS/UDP on LAN\""
    ).unwrap();

    // Forward LAN to WAN (outbound internet).
    if has_wan {
        writeln!(
            out,
            "    add rule inet {TABLE} forward iifname @lan_ifaces oifname @wan_ifaces accept comment \"LAN to WAN\""
        ).unwrap();
    }

    // Forward LAN to DMZ.
    if has_dmz {
        writeln!(
            out,
            "    add rule inet {TABLE} forward iifname @lan_ifaces oifname @dmz_ifaces accept comment \"LAN to DMZ\""
        ).unwrap();
    }

    writeln!(out).unwrap();
}

/// DMZ zone rules: allow 80/443 inbound, no direct LAN/MGMT access,
/// only established/related back to LAN, forward to WAN.
fn emit_dmz_zone_rules(out: &mut String, has_wan: bool) {
    writeln!(out, "    # ── DMZ zone rules ──").unwrap();

    // Allow public services (HTTP/HTTPS) inbound to DMZ.
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @dmz_ifaces tcp dport {{ 80, 443 }} accept comment \"public services on DMZ\""
    ).unwrap();

    // Block DMZ to LAN forwarding (except established/related handled earlier).
    writeln!(
        out,
        "    add rule inet {TABLE} forward iifname @dmz_ifaces oifname @lan_ifaces drop comment \"block DMZ to LAN\""
    ).unwrap();

    // Block DMZ to MGMT forwarding.
    writeln!(
        out,
        "    add rule inet {TABLE} forward iifname @dmz_ifaces oifname @mgmt_ifaces drop comment \"block DMZ to MGMT\""
    ).unwrap();

    // Allow DMZ to WAN (outbound internet).
    if has_wan {
        writeln!(
            out,
            "    add rule inet {TABLE} forward iifname @dmz_ifaces oifname @wan_ifaces accept comment \"DMZ to WAN\""
        ).unwrap();
    }

    writeln!(out).unwrap();
}

/// MGMT zone rules: full admin access — web UI, SSH, Inform, access to all internal zones.
fn emit_mgmt_zone_rules(
    out: &mut String,
    has_wan: bool,
    has_lan: bool,
    has_dmz: bool,
    has_guest: bool,
) {
    writeln!(out, "    # ── MGMT zone rules ──").unwrap();

    // Web UI access (HTTPS).
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @mgmt_ifaces tcp dport 443 accept comment \"web UI on MGMT\""
    ).unwrap();

    // SSH for management.
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @mgmt_ifaces tcp dport 22 accept comment \"SSH on MGMT\""
    ).unwrap();

    // Inform protocol for device adoption.
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @mgmt_ifaces tcp dport 8080 accept comment \"Inform on MGMT\""
    ).unwrap();

    // DHCP + DNS to gateway.
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @mgmt_ifaces udp dport {{ 67, 68 }} accept comment \"DHCP on MGMT\""
    ).unwrap();
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @mgmt_ifaces tcp dport 53 accept comment \"DNS/TCP on MGMT\""
    ).unwrap();
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @mgmt_ifaces udp dport 53 accept comment \"DNS/UDP on MGMT\""
    ).unwrap();

    // MGMT can reach all internal zones.
    if has_lan {
        writeln!(
            out,
            "    add rule inet {TABLE} forward iifname @mgmt_ifaces oifname @lan_ifaces accept comment \"MGMT to LAN\""
        ).unwrap();
    }
    if has_dmz {
        writeln!(
            out,
            "    add rule inet {TABLE} forward iifname @mgmt_ifaces oifname @dmz_ifaces accept comment \"MGMT to DMZ\""
        ).unwrap();
    }
    if has_guest {
        writeln!(
            out,
            "    add rule inet {TABLE} forward iifname @mgmt_ifaces oifname @guest_ifaces accept comment \"MGMT to GUEST\""
        ).unwrap();
    }
    // MGMT to WAN is optional (configurable), default: allow.
    if has_wan {
        writeln!(
            out,
            "    add rule inet {TABLE} forward iifname @mgmt_ifaces oifname @wan_ifaces accept comment \"MGMT to WAN\""
        ).unwrap();
    }

    writeln!(out).unwrap();
}

/// GUEST zone rules: internet only, DNS/DHCP to gateway, no internal access.
fn emit_guest_zone_rules(out: &mut String, has_wan: bool) {
    writeln!(out, "    # ── GUEST zone rules ──").unwrap();

    // DNS to gateway.
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @guest_ifaces tcp dport 53 accept comment \"DNS/TCP on GUEST\""
    ).unwrap();
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @guest_ifaces udp dport 53 accept comment \"DNS/UDP on GUEST\""
    ).unwrap();

    // DHCP to gateway.
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @guest_ifaces udp dport {{ 67, 68 }} accept comment \"DHCP on GUEST\""
    ).unwrap();

    // Explicitly drop all other input from GUEST (no web UI, no SSH, no Inform).
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname @guest_ifaces drop comment \"block all other GUEST input\""
    ).unwrap();

    // Block GUEST to all internal zones.
    writeln!(
        out,
        "    add rule inet {TABLE} forward iifname @guest_ifaces oifname @lan_ifaces drop comment \"block GUEST to LAN\""
    ).unwrap();
    writeln!(
        out,
        "    add rule inet {TABLE} forward iifname @guest_ifaces oifname @dmz_ifaces drop comment \"block GUEST to DMZ\""
    ).unwrap();
    writeln!(
        out,
        "    add rule inet {TABLE} forward iifname @guest_ifaces oifname @mgmt_ifaces drop comment \"block GUEST to MGMT\""
    ).unwrap();

    // GUEST to WAN only (internet access).
    if has_wan {
        writeln!(
            out,
            "    add rule inet {TABLE} forward iifname @guest_ifaces oifname @wan_ifaces accept comment \"GUEST to WAN\""
        ).unwrap();
    }

    writeln!(out).unwrap();
}

// ── Internal helpers ────────────────────────────────────────────────

fn emit_chain(out: &mut String, name: &str, chain_type: &str, hook: &str, policy: &Action) {
    writeln!(out, "    chain {name} {{").unwrap();
    writeln!(
        out,
        "        type {chain_type} hook {hook} priority 0; policy {policy};"
    )
    .unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();
}

fn emit_nat_chains(out: &mut String) {
    writeln!(out, "    chain prerouting {{").unwrap();
    writeln!(
        out,
        "        type nat hook prerouting priority -100; policy accept;"
    )
    .unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    chain postrouting {{").unwrap();
    writeln!(
        out,
        "        type nat hook postrouting priority 100; policy accept;"
    )
    .unwrap();
    writeln!(out, "    }}").unwrap();
}

/// Rules that are always present regardless of user configuration.
fn emit_default_rules(out: &mut String) {
    writeln!(out, "    # ── Default secure rules (always present) ──").unwrap();

    // Connection tracking: allow established/related.
    writeln!(
        out,
        "    add rule inet {TABLE} input ct state established,related accept"
    )
    .unwrap();
    writeln!(
        out,
        "    add rule inet {TABLE} forward ct state established,related accept"
    )
    .unwrap();
    writeln!(
        out,
        "    add rule inet {TABLE} output ct state established,related accept"
    )
    .unwrap();

    // Drop invalid.
    writeln!(out, "    add rule inet {TABLE} input ct state invalid drop").unwrap();
    writeln!(
        out,
        "    add rule inet {TABLE} forward ct state invalid drop"
    )
    .unwrap();

    // Allow loopback.
    writeln!(out, "    add rule inet {TABLE} input iifname \"lo\" accept").unwrap();
    writeln!(
        out,
        "    add rule inet {TABLE} output oifname \"lo\" accept"
    )
    .unwrap();

    // Allow ICMP echo (ping) — rate limited.
    writeln!(
        out,
        "    add rule inet {TABLE} input icmp type echo-request limit rate 5/second accept"
    )
    .unwrap();
    writeln!(
        out,
        "    add rule inet {TABLE} input icmpv6 type echo-request limit rate 5/second accept"
    )
    .unwrap();
    // Allow essential ICMPv6 (NDP).
    writeln!(
        out,
        "    add rule inet {TABLE} input icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert }} accept"
    )
    .unwrap();

    writeln!(out).unwrap();
}

/// Hardened default ruleset when no user rules are configured.
fn emit_hardened_defaults(out: &mut String) {
    writeln!(out, "    # ── Hardened defaults (no user rules in DB) ──").unwrap();

    // Allow DHCP on LAN interfaces (br-lan*, eth1*, vlan*).
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname {{ \"br-lan*\", \"eth1*\", \"vlan*\" }} udp dport {{ 67, 68 }} accept comment \"DHCP on LAN\""
    ).unwrap();

    // Allow DNS on LAN interfaces.
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname {{ \"br-lan*\", \"eth1*\", \"vlan*\" }} tcp dport 53 accept comment \"DNS on LAN\""
    ).unwrap();
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname {{ \"br-lan*\", \"eth1*\", \"vlan*\" }} udp dport 53 accept comment \"DNS on LAN\""
    ).unwrap();

    // Allow HTTPS on LAN + MGMT.
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname {{ \"br-lan*\", \"eth1*\", \"vlan*\", \"br-mgmt*\" }} tcp dport 443 accept comment \"HTTPS on LAN/MGMT\""
    ).unwrap();

    // Allow Inform (8080) on MGMT VLAN only.
    writeln!(
        out,
        "    add rule inet {TABLE} input iifname \"br-mgmt*\" tcp dport 8080 accept comment \"Inform on MGMT only\""
    ).unwrap();

    // Allow forwarding from LAN to WAN.
    writeln!(
        out,
        "    add rule inet {TABLE} forward iifname {{ \"br-lan*\", \"eth1*\", \"vlan*\" }} oifname {{ \"eth0*\", \"ppp*\", \"wan*\" }} accept comment \"LAN to WAN\""
    ).unwrap();

    // Allow forwarding from MGMT to WAN.
    writeln!(
        out,
        "    add rule inet {TABLE} forward iifname \"br-mgmt*\" oifname {{ \"eth0*\", \"ppp*\", \"wan*\" }} accept comment \"MGMT to WAN\""
    ).unwrap();

    // NAT masquerade on WAN.
    writeln!(
        out,
        "    add rule inet {TABLE} postrouting oifname {{ \"eth0*\", \"ppp*\", \"wan*\" }} masquerade comment \"NAT masquerade WAN\""
    ).unwrap();

    // No WAN inbound (policy DROP handles it).
    writeln!(
        out,
        "    # WAN inbound: policy DROP (no explicit rules = blocked)"
    )
    .unwrap();

    writeln!(out).unwrap();
}

/// Emit user-defined rules from the database.
fn emit_user_rules(out: &mut String, rules: &[FirewallRule]) {
    writeln!(out, "    # ── User-defined rules ──").unwrap();

    for rule in rules {
        emit_single_rule(out, rule);
    }

    // Always add NAT masquerade on WAN (user rules don't replace this).
    writeln!(
        out,
        "    add rule inet {TABLE} postrouting oifname {{ \"eth0*\", \"ppp*\", \"wan*\" }} masquerade comment \"NAT masquerade WAN\""
    ).unwrap();

    writeln!(out).unwrap();
}

fn emit_single_rule(out: &mut String, rule: &FirewallRule) {
    if let Err(e) = emit_single_rule_validated(out, rule) {
        tracing::error!("skipping invalid firewall rule id={:?}: {e}", rule.id);
    }
}

fn emit_single_rule_validated(out: &mut String, rule: &FirewallRule) -> Result<()> {
    let detail = &rule.detail;
    let chain = &rule.chain;

    // Validate chain name.
    validate_chain(chain)?;

    let mut parts: Vec<String> = Vec::new();

    // VLAN matching (vlan is already a u16, safe).
    if let Some(vlan_id) = detail.vlan {
        parts.push(format!("vlan id {vlan_id}"));
    }

    // Source interface (iifname) — must come before protocol in nft syntax.
    let src = detail.source.to_lowercase();
    if src != "any" && src != "0.0.0.0/0" {
        if let Some(iface) = src.strip_prefix("iif:") {
            if let Some(set_name) = iface.strip_prefix('@') {
                validate_set_name(set_name)?;
                parts.push(format!("iifname @{set_name}"));
            } else {
                validate_interface_name(iface)?;
                parts.push(format!("iifname \"{iface}\""));
            }
        } else {
            validate_ip_or_cidr(&src)?;
            parts.push(format!("ip saddr {src}"));
        }
    }

    // Destination interface (oifname) — must come before protocol in nft syntax.
    let dst = detail.destination.to_lowercase();
    if dst != "any" && dst != "0.0.0.0/0" {
        if let Some(iface) = dst.strip_prefix("oif:") {
            if let Some(set_name) = iface.strip_prefix('@') {
                validate_set_name(set_name)?;
                parts.push(format!("oifname @{set_name}"));
            } else {
                validate_interface_name(iface)?;
                parts.push(format!("oifname \"{iface}\""));
            }
        } else {
            validate_ip_or_cidr(&dst)?;
            parts.push(format!("ip daddr {dst}"));
        }
    }

    // Protocol + port — protocol must come right before dport in nft syntax.
    let proto = detail.protocol.to_lowercase();
    if proto != "any" && proto != "all" {
        validate_protocol(&proto)?;
        parts.push(proto.clone());
    }

    // Port (only valid for tcp/udp/sctp).
    if let Some(ref port) = detail.port
        && !port.is_empty()
        && port != "any"
    {
        validate_port(port)?;
        if matches!(proto.as_str(), "tcp" | "udp" | "sctp") {
            parts.push(format!("dport {port}"));
        }
    }

    // Rate limiting.
    if let Some(ref rate) = detail.rate_limit {
        validate_rate_limit(rate)?;
        parts.push(format!("limit rate {rate}"));
    }

    // Action.
    parts.push(detail.action.to_string());

    // Comment — sanitize to prevent injection via nft comment syntax.
    if let Some(ref comment) = detail.comment
        && !comment.is_empty()
    {
        let safe = sanitize_comment(comment);
        if !safe.is_empty() {
            parts.push(format!("comment \"{safe}\""));
        }
    }

    let expr = parts.join(" ");
    writeln!(out, "    add rule inet {TABLE} {chain} {expr}").unwrap();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, FirewallPolicy, FirewallRule, RuleDetail};

    #[test]
    fn default_ruleset_contains_drop_policy() {
        let policy = FirewallPolicy::default();
        let config = generate_ruleset(&[], &policy);
        assert!(
            config.contains("policy drop"),
            "input should default to drop"
        );
        assert!(
            config.contains("policy accept"),
            "output should default to accept"
        );
    }

    #[test]
    fn default_ruleset_has_established_related() {
        let config = generate_ruleset(&[], &FirewallPolicy::default());
        assert!(config.contains("ct state established,related accept"));
    }

    #[test]
    fn default_ruleset_has_loopback() {
        let config = generate_ruleset(&[], &FirewallPolicy::default());
        assert!(config.contains("iifname \"lo\" accept"));
    }

    #[test]
    fn default_ruleset_has_masquerade() {
        let config = generate_ruleset(&[], &FirewallPolicy::default());
        assert!(config.contains("masquerade"));
    }

    #[test]
    fn default_ruleset_allows_dhcp_on_lan() {
        let config = generate_ruleset(&[], &FirewallPolicy::default());
        assert!(config.contains("udp dport { 67, 68 }"));
    }

    #[test]
    fn default_ruleset_allows_inform_on_mgmt_only() {
        let config = generate_ruleset(&[], &FirewallPolicy::default());
        assert!(config.contains("br-mgmt"));
        assert!(config.contains("8080"));
    }

    #[test]
    fn user_rule_generates_nft() {
        let rules = vec![FirewallRule {
            id: Some(1),
            chain: "input".to_string(),
            priority: 0,
            detail: RuleDetail {
                action: Action::Drop,
                protocol: "tcp".to_string(),
                source: "any".to_string(),
                destination: "any".to_string(),
                port: Some("22".to_string()),
                comment: Some("Block SSH from WAN".to_string()),
                vlan: None,
                rate_limit: None,
            },
            enabled: true,
        }];
        let config = generate_ruleset(&rules, &FirewallPolicy::default());
        assert!(config.contains("tcp dport 22 drop"));
        assert!(config.contains("Block SSH from WAN"));
    }

    #[test]
    fn vlan_rule() {
        let rules = vec![FirewallRule {
            id: Some(2),
            chain: "forward".to_string(),
            priority: 10,
            detail: RuleDetail {
                action: Action::Accept,
                protocol: "any".to_string(),
                source: "any".to_string(),
                destination: "any".to_string(),
                port: None,
                comment: Some("Allow VLAN 100 traffic".to_string()),
                vlan: Some(100),
                rate_limit: None,
            },
            enabled: true,
        }];
        let config = generate_ruleset(&rules, &FirewallPolicy::default());
        assert!(config.contains("vlan id 100"));
    }

    #[test]
    fn rate_limited_rule() {
        let rules = vec![FirewallRule {
            id: Some(3),
            chain: "input".to_string(),
            priority: 0,
            detail: RuleDetail {
                action: Action::Accept,
                protocol: "tcp".to_string(),
                source: "any".to_string(),
                destination: "any".to_string(),
                port: Some("443".to_string()),
                comment: Some("HTTPS rate limited".to_string()),
                vlan: None,
                rate_limit: Some("100/second".to_string()),
            },
            enabled: true,
        }];
        let config = generate_ruleset(&rules, &FirewallPolicy::default());
        assert!(config.contains("limit rate 100/second"));
    }

    #[test]
    fn port_forward_generates_dnat() {
        let fwd = vec![PortForward {
            protocol: "tcp".to_string(),
            external_port: 8443,
            internal_ip: "192.168.1.100".to_string(),
            internal_port: 443,
            comment: Some("HTTPS forward".to_string()),
            enabled: true,
            wan_interface: None,
        }];
        let config = generate_ruleset_with_forwards(&[], &FirewallPolicy::default(), &fwd);
        assert!(config.contains("dnat to 192.168.1.100:443"));
        assert!(config.contains("dport 8443"));
    }

    #[test]
    fn interface_source_rule() {
        let rules = vec![FirewallRule {
            id: Some(4),
            chain: "input".to_string(),
            priority: 0,
            detail: RuleDetail {
                action: Action::Accept,
                protocol: "udp".to_string(),
                source: "iif:br-lan".to_string(),
                destination: "any".to_string(),
                port: Some("53".to_string()),
                comment: Some("DNS from LAN".to_string()),
                vlan: None,
                rate_limit: None,
            },
            enabled: true,
        }];
        let config = generate_ruleset(&rules, &FirewallPolicy::default());
        assert!(config.contains("iifname \"br-lan\""));
    }

    #[test]
    fn rule_detail_deserializes_from_db_json() {
        let json = r#"{"action":"drop","protocol":"tcp","source":"any","destination":"any","port":"22","comment":"Block SSH from WAN"}"#;
        let detail: RuleDetail = serde_json::from_str(json).unwrap();
        assert_eq!(detail.action, Action::Drop);
        assert_eq!(detail.protocol, "tcp");
        assert_eq!(detail.port.as_deref(), Some("22"));
        assert!(detail.vlan.is_none());
    }

    // ── Zone-aware ruleset tests ────────────────────────────────────

    fn test_zones() -> Vec<ZonePolicy> {
        vec![
            ZonePolicy {
                zone: FirewallZone::Wan,
                interfaces: vec!["eth0".to_string(), "ppp0".to_string()],
            },
            ZonePolicy {
                zone: FirewallZone::Lan,
                interfaces: vec!["br-lan".to_string(), "eth1".to_string()],
            },
            ZonePolicy {
                zone: FirewallZone::Dmz,
                interfaces: vec!["eth2".to_string()],
            },
            ZonePolicy {
                zone: FirewallZone::Mgmt,
                interfaces: vec!["br-mgmt".to_string()],
            },
            ZonePolicy {
                zone: FirewallZone::Guest,
                interfaces: vec!["br-guest".to_string()],
            },
        ]
    }

    #[test]
    fn zone_ruleset_defines_interface_sets() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(
            config.contains("wan_ifaces"),
            "should define wan_ifaces set"
        );
        assert!(
            config.contains("lan_ifaces"),
            "should define lan_ifaces set"
        );
        assert!(
            config.contains("dmz_ifaces"),
            "should define dmz_ifaces set"
        );
        assert!(config.contains("\"eth0\""), "wan should contain eth0");
        assert!(config.contains("\"br-lan\""), "lan should contain br-lan");
        assert!(config.contains("\"eth2\""), "dmz should contain eth2");
    }

    #[test]
    fn zone_ruleset_wan_blocks_web_ui() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(
            config.contains("iifname @wan_ifaces tcp dport { 80, 443 } drop"),
            "WAN should block web UI ports"
        );
    }

    #[test]
    fn zone_ruleset_wan_blocks_ssh() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(
            config.contains("iifname @wan_ifaces tcp dport 22 drop"),
            "WAN should block SSH"
        );
    }

    #[test]
    fn zone_ruleset_lan_allows_web_ui() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(
            config.contains("iifname @lan_ifaces tcp dport 443 accept"),
            "LAN should allow web UI"
        );
    }

    #[test]
    fn zone_ruleset_lan_allows_dhcp_dns_ssh() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(config.contains("iifname @lan_ifaces udp dport { 67, 68 } accept"));
        assert!(config.contains("iifname @lan_ifaces tcp dport 53 accept"));
        assert!(config.contains("iifname @lan_ifaces udp dport 53 accept"));
        assert!(config.contains("iifname @lan_ifaces tcp dport 22 accept"));
    }

    #[test]
    fn zone_ruleset_lan_forwards_to_wan_and_dmz() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(config.contains("iifname @lan_ifaces oifname @wan_ifaces accept"));
        assert!(config.contains("iifname @lan_ifaces oifname @dmz_ifaces accept"));
    }

    #[test]
    fn zone_ruleset_dmz_no_lan_access() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(
            config.contains("iifname @dmz_ifaces oifname @lan_ifaces drop"),
            "DMZ should not access LAN"
        );
    }

    #[test]
    fn zone_ruleset_dmz_allows_public_services() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(
            config.contains("iifname @dmz_ifaces tcp dport { 80, 443 } accept"),
            "DMZ should allow public HTTP/HTTPS"
        );
    }

    #[test]
    fn zone_ruleset_dmz_forwards_to_wan() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(config.contains("iifname @dmz_ifaces oifname @wan_ifaces accept"));
    }

    #[test]
    fn zone_ruleset_has_masquerade() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(config.contains("oifname @wan_ifaces masquerade"));
    }

    #[test]
    fn zone_ruleset_port_forward_on_wan() {
        let fwd = vec![PortForward {
            protocol: "tcp".to_string(),
            external_port: 8443,
            internal_ip: "192.168.1.100".to_string(),
            internal_port: 443,
            comment: Some("HTTPS forward".to_string()),
            enabled: true,
            wan_interface: None,
        }];
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &fwd);
        assert!(config.contains("iifname @wan_ifaces tcp dport 8443 dnat to 192.168.1.100:443"));
    }

    // ── MGMT zone tests ──

    #[test]
    fn zone_ruleset_mgmt_allows_web_ui_ssh_inform() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(
            config.contains("iifname @mgmt_ifaces tcp dport 443 accept"),
            "MGMT should allow web UI"
        );
        assert!(
            config.contains("iifname @mgmt_ifaces tcp dport 22 accept"),
            "MGMT should allow SSH"
        );
        assert!(
            config.contains("iifname @mgmt_ifaces tcp dport 8080 accept"),
            "MGMT should allow Inform"
        );
    }

    #[test]
    fn zone_ruleset_mgmt_allows_dhcp_dns() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(config.contains("iifname @mgmt_ifaces udp dport { 67, 68 } accept"));
        assert!(config.contains("iifname @mgmt_ifaces tcp dport 53 accept"));
        assert!(config.contains("iifname @mgmt_ifaces udp dport 53 accept"));
    }

    #[test]
    fn zone_ruleset_mgmt_forwards_to_all_internal() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(
            config.contains("iifname @mgmt_ifaces oifname @lan_ifaces accept"),
            "MGMT should reach LAN"
        );
        assert!(
            config.contains("iifname @mgmt_ifaces oifname @dmz_ifaces accept"),
            "MGMT should reach DMZ"
        );
        assert!(
            config.contains("iifname @mgmt_ifaces oifname @guest_ifaces accept"),
            "MGMT should reach GUEST"
        );
        assert!(
            config.contains("iifname @mgmt_ifaces oifname @wan_ifaces accept"),
            "MGMT should reach WAN"
        );
    }

    // ── GUEST zone tests ──

    #[test]
    fn zone_ruleset_guest_allows_dns_dhcp_only() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(
            config.contains("iifname @guest_ifaces tcp dport 53 accept"),
            "GUEST should get DNS"
        );
        assert!(
            config.contains("iifname @guest_ifaces udp dport 53 accept"),
            "GUEST should get DNS"
        );
        assert!(
            config.contains("iifname @guest_ifaces udp dport { 67, 68 } accept"),
            "GUEST should get DHCP"
        );
    }

    #[test]
    fn zone_ruleset_guest_blocks_all_other_input() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(
            config.contains("iifname @guest_ifaces drop comment \"block all other GUEST input\""),
            "GUEST should drop all other input"
        );
    }

    #[test]
    fn zone_ruleset_guest_no_internal_access() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(
            config.contains("iifname @guest_ifaces oifname @lan_ifaces drop"),
            "GUEST to LAN blocked"
        );
        assert!(
            config.contains("iifname @guest_ifaces oifname @dmz_ifaces drop"),
            "GUEST to DMZ blocked"
        );
        assert!(
            config.contains("iifname @guest_ifaces oifname @mgmt_ifaces drop"),
            "GUEST to MGMT blocked"
        );
    }

    #[test]
    fn zone_ruleset_guest_forwards_to_wan_only() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(
            config.contains("iifname @guest_ifaces oifname @wan_ifaces accept"),
            "GUEST should reach WAN"
        );
    }

    #[test]
    fn zone_ruleset_dmz_blocks_mgmt() {
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
        assert!(
            config.contains("iifname @dmz_ifaces oifname @mgmt_ifaces drop"),
            "DMZ to MGMT blocked"
        );
    }

    #[test]
    fn zone_ruleset_includes_user_rules() {
        let rules = vec![FirewallRule {
            id: Some(1),
            chain: "input".to_string(),
            priority: 0,
            detail: RuleDetail {
                action: Action::Accept,
                protocol: "tcp".to_string(),
                source: "any".to_string(),
                destination: "any".to_string(),
                port: Some("8080".to_string()),
                comment: Some("custom service".to_string()),
                vlan: None,
                rate_limit: None,
            },
            enabled: true,
        }];
        let config = generate_zone_ruleset(&test_zones(), &rules, &FirewallPolicy::default(), &[]);
        assert!(config.contains("tcp dport 8080 accept"));
    }

    // ── Input validation tests ────────────────────────────────────

    #[test]
    fn validate_ip_or_cidr_rejects_injection() {
        assert!(validate_ip_or_cidr("10.0.0.1").is_ok());
        assert!(validate_ip_or_cidr("192.168.1.0/24").is_ok());
        assert!(validate_ip_or_cidr("::1").is_ok());
        assert!(validate_ip_or_cidr("fe80::/10").is_ok());
        // Injection attempts
        assert!(validate_ip_or_cidr("10.0.0.1; drop table").is_err());
        assert!(validate_ip_or_cidr("$(whoami)").is_err());
        assert!(validate_ip_or_cidr("10.0.0.1/33").is_err());
        assert!(validate_ip_or_cidr("").is_err());
        assert!(validate_ip_or_cidr("not-an-ip").is_err());
    }

    #[test]
    fn validate_port_rejects_injection() {
        assert!(validate_port("80").is_ok());
        assert!(validate_port("80-443").is_ok());
        assert!(validate_port("80,443,8080").is_ok());
        // Injection attempts
        assert!(validate_port("80; drop").is_err());
        assert!(validate_port("abc").is_err());
        assert!(validate_port("99999").is_err());
        assert!(validate_port("").is_err());
    }

    #[test]
    fn validate_protocol_rejects_injection() {
        assert!(validate_protocol("tcp").is_ok());
        assert!(validate_protocol("udp").is_ok());
        assert!(validate_protocol("icmp").is_ok());
        assert!(validate_protocol("tcp; drop").is_err());
        assert!(validate_protocol("any").is_err()); // "any" handled separately
        assert!(validate_protocol("").is_err());
    }

    #[test]
    fn validate_rate_limit_rejects_injection() {
        assert!(validate_rate_limit("100/second").is_ok());
        assert!(validate_rate_limit("10/minute").is_ok());
        assert!(validate_rate_limit("1/hour").is_ok());
        assert!(validate_rate_limit("100/second; drop").is_err());
        assert!(validate_rate_limit("abc/second").is_err());
        assert!(validate_rate_limit("100/day").is_err());
        assert!(validate_rate_limit("noslash").is_err());
    }

    #[test]
    fn sanitize_comment_strips_dangerous_chars() {
        assert_eq!(sanitize_comment("normal comment"), "normal comment");
        assert_eq!(
            sanitize_comment("has-dash_underscore"),
            "has-dash_underscore"
        );
        // Strips quotes, semicolons, braces
        assert_eq!(
            sanitize_comment("inject\"; drop table"),
            "inject drop table"
        );
        assert_eq!(sanitize_comment("a{b}c"), "abc");
        // Respects max length
        let long = "a".repeat(100);
        assert_eq!(sanitize_comment(&long).len(), 64);
    }

    #[test]
    fn validate_interface_name_rejects_injection() {
        assert!(validate_interface_name("eth0").is_ok());
        assert!(validate_interface_name("br-lan").is_ok());
        assert!(validate_interface_name("wg0").is_ok());
        assert!(validate_interface_name("vlan.100").is_ok());
        // Injection attempts
        assert!(validate_interface_name("eth0; rm -rf /").is_err());
        assert!(validate_interface_name("eth0\"").is_err());
        assert!(validate_interface_name("").is_err());
        assert!(validate_interface_name("a]bcdefghijklmnop").is_err()); // 17 chars with invalid char
        assert!(validate_interface_name("a234567890123456").is_err()); // 16 chars
    }

    #[test]
    fn malicious_rule_source_is_rejected() {
        let rules = vec![FirewallRule {
            id: Some(99),
            chain: "input".to_string(),
            priority: 0,
            detail: RuleDetail {
                action: Action::Drop,
                protocol: "tcp".to_string(),
                source: "10.0.0.1\"; drop table inet sfgw".to_string(),
                destination: "any".to_string(),
                port: Some("22".to_string()),
                comment: None,
                vlan: None,
                rate_limit: None,
            },
            enabled: true,
        }];
        let config = generate_ruleset(&rules, &FirewallPolicy::default());
        // The malicious rule should NOT appear in the output
        assert!(!config.contains("drop table inet sfgw"));
    }

    #[test]
    fn malicious_port_forward_ip_is_rejected() {
        let fwd = vec![PortForward {
            protocol: "tcp".to_string(),
            external_port: 8443,
            internal_ip: "192.168.1.1\"; flush ruleset".to_string(),
            internal_port: 443,
            comment: None,
            enabled: true,
            wan_interface: None,
        }];
        let config = generate_ruleset_with_forwards(&[], &FirewallPolicy::default(), &fwd);
        assert!(!config.contains("flush ruleset"));
    }

    #[test]
    fn malicious_comment_is_sanitized_in_port_forward() {
        let fwd = vec![PortForward {
            protocol: "tcp".to_string(),
            external_port: 8443,
            internal_ip: "192.168.1.100".to_string(),
            internal_port: 443,
            comment: Some("legit\"; flush ruleset; #".to_string()),
            enabled: true,
            wan_interface: None,
        }];
        let config = generate_ruleset_with_forwards(&[], &FirewallPolicy::default(), &fwd);
        assert!(config.contains("dnat to 192.168.1.100:443"));
        // The injection-critical characters (quotes, semicolons, hash) are stripped.
        // The comment is safely enclosed in quotes with no way to escape.
        assert!(!config.contains("\"; flush"));
        assert!(!config.contains("; #"));
        // The sanitized comment should only contain safe chars.
        assert!(config.contains("comment \"legit flush ruleset "));
    }

    // ── WAN interface binding tests ─────────────────────────────────

    #[test]
    fn port_forward_with_wan_interface_generates_iifname() {
        let fwd = vec![PortForward {
            protocol: "tcp".to_string(),
            external_port: 443,
            internal_ip: "192.168.1.100".to_string(),
            internal_port: 443,
            comment: Some("HTTPS on eth0 only".to_string()),
            enabled: true,
            wan_interface: Some("eth0".to_string()),
        }];
        let config = generate_ruleset_with_forwards(&[], &FirewallPolicy::default(), &fwd);
        assert!(
            config.contains("iifname \"eth0\" tcp dport 443 dnat to 192.168.1.100:443"),
            "should bind port forward to specific WAN interface"
        );
    }

    #[test]
    fn port_forward_without_wan_interface_no_iifname_in_legacy() {
        let fwd = vec![PortForward {
            protocol: "tcp".to_string(),
            external_port: 443,
            internal_ip: "192.168.1.100".to_string(),
            internal_port: 443,
            comment: None,
            enabled: true,
            wan_interface: None,
        }];
        let config = generate_ruleset_with_forwards(&[], &FirewallPolicy::default(), &fwd);
        // Legacy mode: the DNAT rule itself should not have an iifname prefix
        assert!(config.contains("tcp dport 443 dnat to 192.168.1.100:443"));
        // The DNAT line specifically should not be interface-scoped
        let dnat_line = config
            .lines()
            .find(|l| l.contains("dnat to 192.168.1.100:443"))
            .unwrap();
        assert!(
            !dnat_line.contains("iifname"),
            "legacy DNAT rule should not have iifname"
        );
    }

    #[test]
    fn port_forward_wan_interface_overrides_zone_prefix() {
        let fwd = vec![PortForward {
            protocol: "tcp".to_string(),
            external_port: 8443,
            internal_ip: "192.168.1.100".to_string(),
            internal_port: 443,
            comment: Some("specific WAN".to_string()),
            enabled: true,
            wan_interface: Some("ppp0".to_string()),
        }];
        let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &fwd);
        // Should use the specific interface, not @wan_ifaces
        assert!(
            config.contains("iifname \"ppp0\" tcp dport 8443 dnat to 192.168.1.100:443"),
            "wan_interface should override zone-level @wan_ifaces prefix"
        );
        assert!(
            !config.contains("@wan_ifaces tcp dport 8443"),
            "should not use @wan_ifaces when wan_interface is set"
        );
    }

    #[test]
    fn port_forward_rejects_invalid_wan_interface() {
        let fwd = vec![PortForward {
            protocol: "tcp".to_string(),
            external_port: 443,
            internal_ip: "192.168.1.100".to_string(),
            internal_port: 443,
            comment: None,
            enabled: true,
            wan_interface: Some("eth0; drop".to_string()),
        }];
        let config = generate_ruleset_with_forwards(&[], &FirewallPolicy::default(), &fwd);
        // The malicious interface name should be rejected; no DNAT rule emitted
        assert!(
            !config.contains("dnat to 192.168.1.100:443"),
            "DNAT rule with invalid interface should not be emitted"
        );
        // The injection payload should not appear in the ruleset
        assert!(
            !config.contains("eth0; drop"),
            "malicious interface name should not appear in ruleset"
        );
    }

    #[test]
    fn port_forward_wan_interface_serde_roundtrip() {
        let fwd = PortForward {
            protocol: "tcp".to_string(),
            external_port: 443,
            internal_ip: "192.168.1.100".to_string(),
            internal_port: 443,
            comment: None,
            enabled: true,
            wan_interface: Some("eth0".to_string()),
        };
        let json = serde_json::to_string(&fwd).unwrap();
        assert!(json.contains("\"wan_interface\":\"eth0\""));

        let parsed: PortForward = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.wan_interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn port_forward_wan_interface_none_omitted_in_json() {
        let fwd = PortForward {
            protocol: "tcp".to_string(),
            external_port: 443,
            internal_ip: "192.168.1.100".to_string(),
            internal_port: 443,
            comment: None,
            enabled: true,
            wan_interface: None,
        };
        let json = serde_json::to_string(&fwd).unwrap();
        assert!(
            !json.contains("wan_interface"),
            "None wan_interface should be omitted from JSON"
        );

        // Deserializing without the field should default to None
        let minimal = r#"{"protocol":"tcp","external_port":443,"internal_ip":"192.168.1.100","internal_port":443,"enabled":true}"#;
        let parsed: PortForward = serde_json::from_str(minimal).unwrap();
        assert!(parsed.wan_interface.is_none());
    }
}
