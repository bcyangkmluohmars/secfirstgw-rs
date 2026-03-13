// SPDX-License-Identifier: AGPL-3.0-or-later

//! WAN failover and load-balancing via Linux policy routing.
//!
//! Each WAN interface gets its own routing table. Health checks
//! run in a background tokio task, removing failed WANs and
//! re-adding them on recovery.

use crate::nft::validate_interface_name;
use crate::{WanGroup, WanMember, WanMode};
use anyhow::{Context, Result};
use std::net::IpAddr;
use tokio::process::Command;

/// Validate a WAN member's fields before using them in commands.
fn validate_wan_member(member: &WanMember) -> Result<()> {
    validate_interface_name(&member.interface)
        .with_context(|| format!("invalid WAN interface name: {}", member.interface))?;
    let _gw: IpAddr = member
        .gateway
        .parse()
        .with_context(|| format!("invalid WAN gateway address: {}", member.gateway))?;
    let _target: IpAddr = member
        .check_target
        .parse()
        .with_context(|| format!("invalid WAN check_target address: {}", member.check_target))?;
    Ok(())
}

/// Base routing table number. WAN interfaces get tables 100, 101, etc.
const RT_TABLE_BASE: u32 = 100;

// ── Public API ──────────────────────────────────────────────────────

/// Apply ip rules and routing tables for all configured WAN groups.
///
/// For each WAN group:
/// - **Failover**: default route via highest-priority (lowest number) healthy member.
/// - **LoadBalance**: ECMP default route with weights.
pub async fn apply_wan_routing(groups: &[WanGroup]) -> Result<()> {
    for group in groups {
        let enabled: Vec<&WanMember> = group.interfaces.iter().filter(|m| m.enabled).collect();

        if enabled.is_empty() {
            tracing::warn!(
                "WAN group '{}' has no enabled members, skipping",
                group.name
            );
            continue;
        }

        // Set up per-interface routing tables.
        for (i, member) in enabled.iter().enumerate() {
            let table_id = RT_TABLE_BASE + i as u32;
            setup_interface_table(member, table_id).await?;
        }

        // Set the default route based on mode.
        match group.mode {
            WanMode::Failover => {
                apply_failover_route(&enabled).await?;
            }
            WanMode::LoadBalance => {
                apply_loadbalance_route(&enabled).await?;
            }
        }

        tracing::info!(
            "WAN group '{}' routing applied ({:?}, {} members)",
            group.name,
            group.mode,
            enabled.len()
        );
    }

    Ok(())
}

/// Check WAN health by pinging the check target through a specific interface.
///
/// Returns `true` if the target is reachable, `false` otherwise.
pub async fn check_wan_health(member: &WanMember) -> Result<bool> {
    validate_interface_name(&member.interface)?;
    let _target: IpAddr = member.check_target.parse().with_context(|| {
        format!(
            "invalid check_target for health check: {}",
            member.check_target
        )
    })?;

    let output = Command::new("ping")
        .args([
            "-I",
            &member.interface,
            "-c",
            "1",
            "-W",
            "2",
            &member.check_target,
        ])
        .output()
        .await
        .with_context(|| {
            format!(
                "failed to execute ping for WAN health check on {}",
                member.interface
            )
        })?;

    Ok(output.status.success())
}

/// Background WAN health monitor loop.
///
/// Periodically checks each WAN member's health and adjusts routing
/// tables on failure or recovery. Spawned as a tokio task.
pub async fn wan_health_monitor(db: sfgw_db::Db) -> Result<()> {
    use std::collections::HashMap;

    let mut health_state: HashMap<String, bool> = HashMap::new();

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        let groups = match crate::load_wan_groups(&db).await {
            Ok(g) => g,
            Err(e) => {
                tracing::error!("failed to load WAN groups for health check: {e}");
                continue;
            }
        };

        for group in &groups {
            let enabled: Vec<&WanMember> = group.interfaces.iter().filter(|m| m.enabled).collect();

            let mut state_changed = false;

            for member in &enabled {
                let healthy = check_wan_health(member).await.unwrap_or(false);
                let prev = health_state.get(&member.interface).copied().unwrap_or(true);

                if healthy != prev {
                    state_changed = true;
                    health_state.insert(member.interface.clone(), healthy);

                    if healthy {
                        tracing::info!(
                            "WAN interface {} recovered (group '{}')",
                            member.interface,
                            group.name
                        );
                    } else {
                        tracing::warn!(
                            "WAN interface {} failed health check (group '{}')",
                            member.interface,
                            group.name
                        );
                    }
                }
            }

            if state_changed {
                // Re-apply routing with only healthy members.
                let healthy_members: Vec<&WanMember> = enabled
                    .iter()
                    .filter(|m| health_state.get(&m.interface).copied().unwrap_or(true))
                    .copied()
                    .collect();

                if healthy_members.is_empty() {
                    tracing::error!("all WAN members in group '{}' are down!", group.name);
                    continue;
                }

                let result = match group.mode {
                    WanMode::Failover => apply_failover_route(&healthy_members).await,
                    WanMode::LoadBalance => apply_loadbalance_route(&healthy_members).await,
                };

                if let Err(e) = result {
                    tracing::error!(
                        "failed to update routing for WAN group '{}': {e}",
                        group.name
                    );
                }
            }
        }
    }
}

// ── Internal helpers ────────────────────────────────────────────────

/// Set up a per-interface routing table with a default route via its gateway.
async fn setup_interface_table(member: &WanMember, table_id: u32) -> Result<()> {
    validate_wan_member(member)?;
    let table_str = table_id.to_string();

    // Add default route in the per-interface table.
    if let Err(e) = run_ip(&[
        "route",
        "replace",
        "default",
        "via",
        &member.gateway,
        "dev",
        &member.interface,
        "table",
        &table_str,
    ])
    .await
    {
        tracing::error!(
            interface = member.interface.as_str(),
            table = table_id,
            "failed to set per-interface default route: {e}"
        );
        return Err(e);
    }

    tracing::debug!(
        "routing table {} configured for {} via {}",
        table_id,
        member.interface,
        member.gateway
    );

    Ok(())
}

/// Apply failover routing: default route via highest-priority (lowest number) member.
async fn apply_failover_route(members: &[&WanMember]) -> Result<()> {
    // Sort by priority (lowest = highest priority).
    let mut sorted: Vec<&&WanMember> = members.iter().collect();
    sorted.sort_by_key(|m| m.priority);

    let primary = sorted
        .first()
        .context("no healthy WAN members for failover")?;

    // Validate the primary member before using in command.
    validate_wan_member(primary)?;

    // Replace default route with the primary WAN.
    run_ip(&[
        "route",
        "replace",
        "default",
        "via",
        &primary.gateway,
        "dev",
        &primary.interface,
    ])
    .await
    .context("failed to set failover default route")?;

    tracing::info!(
        "failover: default route via {} ({}), priority {}",
        primary.gateway,
        primary.interface,
        primary.priority
    );

    Ok(())
}

/// Apply load-balance routing: ECMP default route with weights.
async fn apply_loadbalance_route(members: &[&WanMember]) -> Result<()> {
    // Validate all members before building command.
    for member in members {
        validate_wan_member(member)?;
    }

    // Build nexthop arguments: ip route replace default nexthop via <gw1> dev <if1> weight <w1> ...
    let mut args: Vec<String> = vec![
        "route".to_string(),
        "replace".to_string(),
        "default".to_string(),
    ];

    for member in members {
        args.extend([
            "nexthop".to_string(),
            "via".to_string(),
            member.gateway.clone(),
            "dev".to_string(),
            member.interface.clone(),
            "weight".to_string(),
            member.weight.to_string(),
        ]);
    }

    let str_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_ip(&str_args)
        .await
        .context("failed to set load-balance default route")?;

    let desc: Vec<String> = members
        .iter()
        .map(|m| format!("{}(w={})", m.interface, m.weight))
        .collect();
    tracing::info!("load-balance: default route via {}", desc.join(", "));

    Ok(())
}

/// Run an `ip` command and return its output.
async fn run_ip(args: &[&str]) -> Result<std::process::Output> {
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

/// Generate the `ip` commands that would be executed for a WAN group.
/// Useful for testing without root privileges.
///
/// Validates all member fields before generating commands.
/// Members with invalid fields are skipped with a warning.
pub fn generate_wan_routing_commands(group: &WanGroup) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    let enabled: Vec<&WanMember> = group
        .interfaces
        .iter()
        .filter(|m| m.enabled)
        .filter(|m| {
            if let Err(e) = validate_wan_member(m) {
                tracing::error!("skipping invalid WAN member {}: {e}", m.interface);
                false
            } else {
                true
            }
        })
        .collect();

    // Per-interface table setup.
    for (i, member) in enabled.iter().enumerate() {
        let table_id = RT_TABLE_BASE + i as u32;
        commands.push(vec![
            "ip".to_string(),
            "route".to_string(),
            "replace".to_string(),
            "default".to_string(),
            "via".to_string(),
            member.gateway.clone(),
            "dev".to_string(),
            member.interface.clone(),
            "table".to_string(),
            table_id.to_string(),
        ]);
    }

    // Default route command.
    match group.mode {
        WanMode::Failover => {
            let mut sorted = enabled.clone();
            sorted.sort_by_key(|m| m.priority);
            if let Some(primary) = sorted.first() {
                commands.push(vec![
                    "ip".to_string(),
                    "route".to_string(),
                    "replace".to_string(),
                    "default".to_string(),
                    "via".to_string(),
                    primary.gateway.clone(),
                    "dev".to_string(),
                    primary.interface.clone(),
                ]);
            }
        }
        WanMode::LoadBalance => {
            let mut args = vec![
                "ip".to_string(),
                "route".to_string(),
                "replace".to_string(),
                "default".to_string(),
            ];
            for member in &enabled {
                args.extend([
                    "nexthop".to_string(),
                    "via".to_string(),
                    member.gateway.clone(),
                    "dev".to_string(),
                    member.interface.clone(),
                    "weight".to_string(),
                    member.weight.to_string(),
                ]);
            }
            commands.push(args);
        }
    }

    commands
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WanGroup, WanMember, WanMode};

    fn test_failover_group() -> WanGroup {
        WanGroup {
            name: "wan-failover".to_string(),
            mode: WanMode::Failover,
            interfaces: vec![
                WanMember {
                    interface: "eth0".to_string(),
                    weight: 50,
                    gateway: "10.0.0.1".to_string(),
                    priority: 1,
                    check_target: "8.8.8.8".to_string(),
                    enabled: true,
                },
                WanMember {
                    interface: "ppp0".to_string(),
                    weight: 50,
                    gateway: "10.1.0.1".to_string(),
                    priority: 2,
                    check_target: "1.1.1.1".to_string(),
                    enabled: true,
                },
            ],
        }
    }

    fn test_loadbalance_group() -> WanGroup {
        WanGroup {
            name: "wan-lb".to_string(),
            mode: WanMode::LoadBalance,
            interfaces: vec![
                WanMember {
                    interface: "eth0".to_string(),
                    weight: 70,
                    gateway: "10.0.0.1".to_string(),
                    priority: 1,
                    check_target: "8.8.8.8".to_string(),
                    enabled: true,
                },
                WanMember {
                    interface: "eth1".to_string(),
                    weight: 30,
                    gateway: "10.1.0.1".to_string(),
                    priority: 2,
                    check_target: "1.1.1.1".to_string(),
                    enabled: true,
                },
            ],
        }
    }

    #[test]
    fn failover_routing_commands() {
        let group = test_failover_group();
        let cmds = generate_wan_routing_commands(&group);

        // Should have 2 per-interface table commands + 1 default route.
        assert_eq!(cmds.len(), 3);

        // Per-interface tables.
        assert!(cmds[0].contains(&"table".to_string()));
        assert!(cmds[0].contains(&"100".to_string()));
        assert!(cmds[1].contains(&"table".to_string()));
        assert!(cmds[1].contains(&"101".to_string()));

        // Default route should use eth0 (priority 1, highest).
        let default_cmd = &cmds[2];
        assert!(default_cmd.contains(&"10.0.0.1".to_string()));
        assert!(default_cmd.contains(&"eth0".to_string()));
        assert!(!default_cmd.contains(&"nexthop".to_string()));
    }

    #[test]
    fn failover_selects_lowest_priority_number() {
        let mut group = test_failover_group();
        // Swap priorities so ppp0 becomes primary.
        group.interfaces[0].priority = 10;
        group.interfaces[1].priority = 1;

        let cmds = generate_wan_routing_commands(&group);
        let default_cmd = &cmds[2];
        assert!(
            default_cmd.contains(&"ppp0".to_string()),
            "should select ppp0 with priority 1"
        );
        assert!(default_cmd.contains(&"10.1.0.1".to_string()));
    }

    #[test]
    fn loadbalance_routing_commands() {
        let group = test_loadbalance_group();
        let cmds = generate_wan_routing_commands(&group);

        // 2 per-interface + 1 ECMP default.
        assert_eq!(cmds.len(), 3);

        let default_cmd = &cmds[2];
        // Should contain nexthop for both interfaces.
        let nexthop_count = default_cmd
            .iter()
            .filter(|s| s.as_str() == "nexthop")
            .count();
        assert_eq!(nexthop_count, 2, "should have 2 nexthops");

        // Check weights.
        assert!(
            default_cmd.contains(&"70".to_string()),
            "should have weight 70"
        );
        assert!(
            default_cmd.contains(&"30".to_string()),
            "should have weight 30"
        );
    }

    #[test]
    fn disabled_members_excluded() {
        let mut group = test_failover_group();
        group.interfaces[1].enabled = false;

        let cmds = generate_wan_routing_commands(&group);

        // Only 1 per-interface table + 1 default route.
        assert_eq!(cmds.len(), 2);
        assert!(cmds[0].contains(&"eth0".to_string()));
        assert!(cmds[1].contains(&"eth0".to_string()));
    }

    #[test]
    fn empty_group_produces_no_commands() {
        let group = WanGroup {
            name: "empty".to_string(),
            mode: WanMode::Failover,
            interfaces: vec![],
        };
        let cmds = generate_wan_routing_commands(&group);
        assert!(cmds.is_empty());
    }

    #[test]
    fn all_disabled_produces_no_commands() {
        let mut group = test_failover_group();
        for m in &mut group.interfaces {
            m.enabled = false;
        }
        let cmds = generate_wan_routing_commands(&group);
        assert!(cmds.is_empty());
    }
}
