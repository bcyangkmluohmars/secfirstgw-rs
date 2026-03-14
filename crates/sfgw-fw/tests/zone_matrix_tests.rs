// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests for the sfgw-fw zone matrix security model.
//!
//! These tests verify the complete security model as a whole rather than
//! individual functions. They ensure that the zone matrix enforces the
//! intended isolation properties: GUEST cannot reach LAN, DMZ cannot
//! reach MGMT, WAN exposes no management services, etc.

use sfgw_fw::iptables::generate_zone_ruleset;
use sfgw_fw::wan::generate_wan_routing_commands;
use sfgw_fw::{
    Action, FirewallPolicy, FirewallRule, FirewallZone, PortForward, RuleDetail, WanGroup,
    WanMember, WanMode, ZonePolicy,
};

// ── Helpers ──────────────────────────────────────────────────────────

/// Build the standard five-zone topology used by most tests.
fn standard_zones() -> Vec<ZonePolicy> {
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

/// Generate a zone ruleset with the standard topology, no user rules, no port forwards.
fn standard_ruleset() -> String {
    generate_zone_ruleset(&standard_zones(), &[], &FirewallPolicy::default(), &[])
}

/// Helper: build a simple user rule for testing.
fn make_rule(
    id: i64,
    chain: &str,
    protocol: &str,
    port: Option<&str>,
    action: Action,
    comment: &str,
) -> FirewallRule {
    FirewallRule {
        id: Some(id),
        chain: chain.to_string(),
        priority: 0,
        detail: RuleDetail {
            action,
            protocol: protocol.to_string(),
            source: "any".to_string(),
            destination: "any".to_string(),
            port: port.map(|p| p.to_string()),
            comment: Some(comment.to_string()),
            vlan: None,
            rate_limit: None,
        },
        enabled: true,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Zone Matrix Security Tests
// ═══════════════════════════════════════════════════════════════════════

// ── 1. Default deny ──────────────────────────────────────────────────

#[test]
fn default_deny_input_drop_forward_drop_output_accept() {
    let policy = FirewallPolicy::default();
    assert_eq!(
        policy.default_input,
        Action::Drop,
        "input must default to Drop"
    );
    assert_eq!(
        policy.default_forward,
        Action::Drop,
        "forward must default to Drop"
    );
    assert_eq!(
        policy.default_output,
        Action::Accept,
        "output must default to Accept"
    );

    let config = standard_ruleset();
    // Verify the chain declarations carry the correct policies.
    assert!(
        config.contains(":INPUT DROP [0:0]"),
        "input chain must have policy DROP in generated config"
    );
    assert!(
        config.contains(":FORWARD DROP [0:0]"),
        "forward chain must have policy DROP in generated config"
    );
    assert!(
        config.contains(":OUTPUT ACCEPT [0:0]"),
        "output chain must have policy ACCEPT in generated config"
    );
}

// ── 2. WAN blocks web UI ─────────────────────────────────────────────

#[test]
fn wan_zone_blocks_web_ui_ports_80_443() {
    let config = standard_ruleset();
    // Each WAN interface should have HTTP and HTTPS blocked.
    assert!(
        config.contains("-i eth0 -p tcp --dport 80 -j DROP"),
        "WAN eth0 must explicitly drop HTTP input"
    );
    assert!(
        config.contains("-i eth0 -p tcp --dport 443 -j DROP"),
        "WAN eth0 must explicitly drop HTTPS input"
    );
    assert!(
        config.contains("-i ppp0 -p tcp --dport 80 -j DROP"),
        "WAN ppp0 must explicitly drop HTTP input"
    );
    assert!(
        config.contains("-i ppp0 -p tcp --dport 443 -j DROP"),
        "WAN ppp0 must explicitly drop HTTPS input"
    );
}

// ── 3. WAN blocks SSH ────────────────────────────────────────────────

#[test]
fn wan_zone_blocks_ssh_port_22() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i eth0 -p tcp --dport 22 -j DROP"),
        "WAN eth0 must explicitly drop SSH input"
    );
    assert!(
        config.contains("-i ppp0 -p tcp --dport 22 -j DROP"),
        "WAN ppp0 must explicitly drop SSH input"
    );
}

// ── 4. WAN has NAT masquerade ────────────────────────────────────────

#[test]
fn wan_zone_has_nat_masquerade() {
    let config = standard_ruleset();
    assert!(
        config.contains("-o eth0 -j MASQUERADE"),
        "WAN eth0 must have NAT masquerade in postrouting"
    );
    assert!(
        config.contains("-o ppp0 -j MASQUERADE"),
        "WAN ppp0 must have NAT masquerade in postrouting"
    );
}

// ── 5. LAN: DHCP, DNS only — no SSH, no web UI (MGMT-only) ──────────

#[test]
fn lan_zone_drops_web_ui() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-lan -p tcp --dport 443 -j DROP"),
        "LAN must explicitly DROP HTTPS"
    );
    assert!(
        !config.contains("-i br-lan -p tcp --dport 443 -j ACCEPT"),
        "LAN must NOT ACCEPT HTTPS"
    );
}

#[test]
fn lan_zone_drops_ssh() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-lan -p tcp --dport 22 -j DROP"),
        "LAN must explicitly DROP SSH"
    );
    assert!(
        !config.contains("-i br-lan -p tcp --dport 22 -j ACCEPT"),
        "LAN must NOT ACCEPT SSH"
    );
}

#[test]
fn lan_zone_allows_dhcp_67_68() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-lan -p udp --dport 67:68 -j ACCEPT"),
        "LAN must allow DHCP (67:68)"
    );
}

#[test]
fn lan_zone_allows_dns_53() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-lan -p tcp --dport 53 -j ACCEPT"),
        "LAN must allow DNS/TCP (53)"
    );
    assert!(
        config.contains("-i br-lan -p udp --dport 53 -j ACCEPT"),
        "LAN must allow DNS/UDP (53)"
    );
}

// ── 6. LAN forwards to WAN and DMZ ──────────────────────────────────

#[test]
fn lan_zone_forwards_to_wan() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-lan -o eth0 -j ACCEPT"),
        "LAN must be allowed to forward to WAN eth0"
    );
    assert!(
        config.contains("-i br-lan -o ppp0 -j ACCEPT"),
        "LAN must be allowed to forward to WAN ppp0"
    );
}

#[test]
fn lan_zone_forwards_to_dmz() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-lan -o eth2 -j ACCEPT"),
        "LAN must be allowed to forward to DMZ"
    );
}

// ── 7. LAN does NOT have explicit forward to GUEST ───────────────────

#[test]
fn lan_zone_no_explicit_forward_to_guest() {
    let config = standard_ruleset();
    // There should be no rule allowing LAN->GUEST forwarding.
    // Default deny (forward policy=Drop) handles this isolation.
    assert!(
        !config.contains("-i br-lan -o br-guest -j ACCEPT"),
        "LAN must NOT have an explicit forward-accept to GUEST; default deny handles it"
    );
}

// ── 8. DMZ only gets DNS/DHCP to gateway, catch-all DROP ────────────

#[test]
fn dmz_zone_allows_dns_dhcp_drops_rest() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i eth2 -p tcp --dport 53 -j ACCEPT"),
        "DMZ must allow DNS/TCP"
    );
    assert!(
        config.contains("-i eth2 -p udp --dport 67:68 -j ACCEPT"),
        "DMZ must allow DHCP"
    );
    assert!(
        config.contains("SFGW-INPUT -i eth2 -j DROP"),
        "DMZ must have catch-all DROP"
    );
    assert!(
        !config.contains("-i eth2 -p tcp --dport 443 -j ACCEPT"),
        "DMZ must NOT allow HTTPS to gateway"
    );
}

// ── 9. DMZ blocks forwarding to LAN ──────────────────────────────────

#[test]
fn dmz_zone_blocks_forward_to_lan() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i eth2 -o br-lan -j DROP"),
        "DMZ must explicitly drop forwarding to LAN br-lan"
    );
    assert!(
        config.contains("-i eth2 -o eth1 -j DROP"),
        "DMZ must explicitly drop forwarding to LAN eth1"
    );
}

// ── 10. DMZ blocks forwarding to MGMT ────────────────────────────────

#[test]
fn dmz_zone_blocks_forward_to_mgmt() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i eth2 -o br-mgmt -j DROP"),
        "DMZ must explicitly drop forwarding to MGMT"
    );
}

// ── 11. DMZ forwards to WAN ─────────────────────────────────────────

#[test]
fn dmz_zone_forwards_to_wan() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i eth2 -o eth0 -j ACCEPT"),
        "DMZ must be allowed to forward to WAN eth0"
    );
    assert!(
        config.contains("-i eth2 -o ppp0 -j ACCEPT"),
        "DMZ must be allowed to forward to WAN ppp0"
    );
}

// ── 12. MGMT allows web UI, SSH, Inform, DHCP, DNS ──────────────────

#[test]
fn mgmt_zone_allows_web_ui_443() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-mgmt -p tcp --dport 443 -j ACCEPT"),
        "MGMT must allow HTTPS (443) for web UI"
    );
}

#[test]
fn mgmt_zone_allows_ssh_22() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-mgmt -p tcp --dport 22 -j ACCEPT"),
        "MGMT must allow SSH (22)"
    );
}

#[test]
fn mgmt_zone_allows_inform_8080() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-mgmt -p tcp --dport 8080 -j ACCEPT"),
        "MGMT must allow Inform protocol (8080)"
    );
}

#[test]
fn mgmt_zone_allows_dhcp_and_dns() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-mgmt -p udp --dport 67:68 -j ACCEPT"),
        "MGMT must allow DHCP"
    );
    assert!(
        config.contains("-i br-mgmt -p tcp --dport 53 -j ACCEPT"),
        "MGMT must allow DNS/TCP"
    );
    assert!(
        config.contains("-i br-mgmt -p udp --dport 53 -j ACCEPT"),
        "MGMT must allow DNS/UDP"
    );
}

// ── 13. MGMT forwards to ALL internal zones ──────────────────────────

#[test]
fn mgmt_zone_forwards_to_lan() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-mgmt -o br-lan -j ACCEPT"),
        "MGMT must be allowed to forward to LAN"
    );
}

#[test]
fn mgmt_zone_forwards_to_dmz() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-mgmt -o eth2 -j ACCEPT"),
        "MGMT must be allowed to forward to DMZ"
    );
}

#[test]
fn mgmt_zone_forwards_to_guest() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-mgmt -o br-guest -j ACCEPT"),
        "MGMT must be allowed to forward to GUEST"
    );
}

#[test]
fn mgmt_zone_forwards_to_wan() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-mgmt -o eth0 -j ACCEPT"),
        "MGMT must be allowed to forward to WAN eth0"
    );
    assert!(
        config.contains("-i br-mgmt -o ppp0 -j ACCEPT"),
        "MGMT must be allowed to forward to WAN ppp0"
    );
}

// ── 14. GUEST allows DNS and DHCP to gateway only ────────────────────

#[test]
fn guest_zone_allows_dns_53() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-guest -p tcp --dport 53 -j ACCEPT"),
        "GUEST must allow DNS/TCP (53) to gateway"
    );
    assert!(
        config.contains("-i br-guest -p udp --dport 53 -j ACCEPT"),
        "GUEST must allow DNS/UDP (53) to gateway"
    );
}

#[test]
fn guest_zone_allows_dhcp_67_68() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-guest -p udp --dport 67:68 -j ACCEPT"),
        "GUEST must allow DHCP (67:68) to gateway"
    );
}

// ── 15. GUEST drops all other input ──────────────────────────────────

#[test]
fn guest_zone_drops_all_other_input() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-guest -j DROP -m comment --comment \"block all other GUEST input\""),
        "GUEST must drop all input after DNS/DHCP allows"
    );
}

#[test]
fn guest_zone_does_not_allow_web_ui() {
    let config = standard_ruleset();
    assert!(
        !config.contains("-i br-guest -p tcp --dport 443 -j ACCEPT"),
        "GUEST must NOT be allowed to access the web UI (443)"
    );
}

#[test]
fn guest_zone_does_not_allow_ssh() {
    let config = standard_ruleset();
    assert!(
        !config.contains("-i br-guest -p tcp --dport 22 -j ACCEPT"),
        "GUEST must NOT be allowed to access SSH (22)"
    );
}

#[test]
fn guest_zone_does_not_allow_inform() {
    let config = standard_ruleset();
    assert!(
        !config.contains("-i br-guest -p tcp --dport 8080 -j ACCEPT"),
        "GUEST must NOT be allowed to access Inform (8080)"
    );
}

// ── 16. GUEST blocks forwarding to LAN, DMZ, MGMT ───────────────────

#[test]
fn guest_zone_blocks_forward_to_lan() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-guest -o br-lan -j DROP"),
        "GUEST must explicitly drop forwarding to LAN"
    );
}

#[test]
fn guest_zone_blocks_forward_to_dmz() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-guest -o eth2 -j DROP"),
        "GUEST must explicitly drop forwarding to DMZ"
    );
}

#[test]
fn guest_zone_blocks_forward_to_mgmt() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-guest -o br-mgmt -j DROP"),
        "GUEST must explicitly drop forwarding to MGMT"
    );
}

// ── 17. GUEST can ONLY forward to WAN ────────────────────────────────

#[test]
fn guest_zone_forwards_to_wan() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i br-guest -o eth0 -j ACCEPT"),
        "GUEST must be allowed to forward to WAN eth0"
    );
    assert!(
        config.contains("-i br-guest -o ppp0 -j ACCEPT"),
        "GUEST must be allowed to forward to WAN ppp0"
    );
}

#[test]
fn guest_zone_only_accept_forward_is_wan() {
    let config = standard_ruleset();
    // The only forward-accept rules for GUEST should be to WAN interfaces.
    let guest_forward_accepts: Vec<&str> = config
        .lines()
        .filter(|line| {
            line.contains("-i br-guest") && line.contains("-o ") && line.contains("-j ACCEPT")
        })
        .collect();
    // Should have exactly 2: one for eth0 and one for ppp0.
    assert_eq!(
        guest_forward_accepts.len(),
        2,
        "GUEST should have exactly two forward-accept rules (to WAN interfaces), found: {guest_forward_accepts:?}"
    );
    for line in &guest_forward_accepts {
        assert!(
            line.contains("-o eth0") || line.contains("-o ppp0"),
            "GUEST forward-accept must be to WAN interface, found: {line}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// WAN Failover Tests
// ═══════════════════════════════════════════════════════════════════════

fn test_failover_group() -> WanGroup {
    WanGroup {
        name: "primary-wan".to_string(),
        mode: WanMode::Failover,
        interfaces: vec![
            WanMember {
                interface: "eth0".to_string(),
                weight: 50,
                gateway: "10.0.0.1".to_string(),
                priority: 5,
                check_target: "8.8.8.8".to_string(),
                enabled: true,
            },
            WanMember {
                interface: "ppp0".to_string(),
                weight: 50,
                gateway: "10.1.0.1".to_string(),
                priority: 1,
                check_target: "1.1.1.1".to_string(),
                enabled: true,
            },
            WanMember {
                interface: "eth3".to_string(),
                weight: 50,
                gateway: "10.2.0.1".to_string(),
                priority: 10,
                check_target: "9.9.9.9".to_string(),
                enabled: true,
            },
        ],
    }
}

// ── 18. Failover selects lowest priority number as primary ───────────

#[test]
fn failover_selects_lowest_priority_number_as_primary() {
    let group = test_failover_group();
    let cmds = generate_wan_routing_commands(&group);

    // The last command is the default route; it should use ppp0 (priority=1).
    let default_cmd = cmds.last().expect("should have commands");
    assert!(
        default_cmd.contains(&"ppp0".to_string()),
        "failover must select ppp0 (priority=1) as primary, got: {default_cmd:?}"
    );
    assert!(
        default_cmd.contains(&"10.1.0.1".to_string()),
        "failover must route via ppp0's gateway 10.1.0.1"
    );
    // Must not contain nexthop (that is load-balance syntax).
    assert!(
        !default_cmd.contains(&"nexthop".to_string()),
        "failover default route must not use nexthop syntax"
    );
}

// ── 19. Load balance generates ECMP with weights ─────────────────────

#[test]
fn load_balance_generates_ecmp_with_weights() {
    let group = WanGroup {
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
    };

    let cmds = generate_wan_routing_commands(&group);
    let default_cmd = cmds.last().expect("should have commands");

    // Must contain nexthop entries.
    let nexthop_count = default_cmd
        .iter()
        .filter(|s| s.as_str() == "nexthop")
        .count();
    assert_eq!(nexthop_count, 2, "ECMP must have 2 nexthop entries");

    // Must contain both weights.
    assert!(
        default_cmd.contains(&"70".to_string()),
        "ECMP must contain weight 70"
    );
    assert!(
        default_cmd.contains(&"30".to_string()),
        "ECMP must contain weight 30"
    );

    // Must contain both gateways.
    assert!(default_cmd.contains(&"10.0.0.1".to_string()));
    assert!(default_cmd.contains(&"10.1.0.1".to_string()));
}

// ── 20. Disabled members are excluded ────────────────────────────────

#[test]
fn disabled_members_are_excluded_from_routing() {
    let mut group = test_failover_group();
    // Disable ppp0 (the one with the lowest priority).
    group.interfaces[1].enabled = false;

    let cmds = generate_wan_routing_commands(&group);

    // ppp0 should not appear in any command.
    for cmd in &cmds {
        assert!(
            !cmd.contains(&"ppp0".to_string()),
            "disabled member ppp0 must not appear in routing commands"
        );
    }

    // The default route should now use eth0 (priority=5, next lowest after ppp0).
    let default_cmd = cmds.last().expect("should have commands");
    assert!(
        default_cmd.contains(&"eth0".to_string()),
        "with ppp0 disabled, failover should select eth0 (priority=5)"
    );
}

// ── 21. Empty group produces no commands ─────────────────────────────

#[test]
fn empty_wan_group_produces_no_commands() {
    let group = WanGroup {
        name: "empty".to_string(),
        mode: WanMode::Failover,
        interfaces: vec![],
    };
    let cmds = generate_wan_routing_commands(&group);
    assert!(
        cmds.is_empty(),
        "empty WAN group must produce no routing commands"
    );
}

#[test]
fn all_disabled_wan_group_produces_no_commands() {
    let mut group = test_failover_group();
    for m in &mut group.interfaces {
        m.enabled = false;
    }
    let cmds = generate_wan_routing_commands(&group);
    assert!(
        cmds.is_empty(),
        "WAN group with all members disabled must produce no routing commands"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Ruleset Generation Tests
// ═══════════════════════════════════════════════════════════════════════

// ── 22. Port forwarding generates DNAT on WAN ────────────────────────

#[test]
fn port_forwarding_generates_dnat_on_wan_zone() {
    let forwards = vec![PortForward {
        protocol: "tcp".to_string(),
        external_port: 8443,
        internal_ip: "192.168.1.100".to_string(),
        internal_port: 443,
        comment: Some("HTTPS forward to webserver".to_string()),
        enabled: true,
        wan_interface: None,
    }];

    let config = generate_zone_ruleset(
        &standard_zones(),
        &[],
        &FirewallPolicy::default(),
        &forwards,
    );

    // DNAT must be scoped to each WAN interface.
    assert!(
        config.contains("-i eth0 -p tcp --dport 8443 -j DNAT --to-destination 192.168.1.100:443"),
        "port forward DNAT must be scoped to WAN interface eth0"
    );
    assert!(
        config.contains("-i ppp0 -p tcp --dport 8443 -j DNAT --to-destination 192.168.1.100:443"),
        "port forward DNAT must be scoped to WAN interface ppp0"
    );

    // Must also allow the forwarded traffic in the forward chain.
    assert!(
        config.contains("-d 192.168.1.100 -p tcp --dport 443 -j ACCEPT"),
        "port forward must have a matching forward accept rule"
    );
}

#[test]
fn disabled_port_forward_not_in_ruleset() {
    let forwards = vec![PortForward {
        protocol: "tcp".to_string(),
        external_port: 2222,
        internal_ip: "192.168.1.50".to_string(),
        internal_port: 22,
        comment: Some("SSH forward (disabled)".to_string()),
        enabled: false,
        wan_interface: None,
    }];

    let config = generate_zone_ruleset(
        &standard_zones(),
        &[],
        &FirewallPolicy::default(),
        &forwards,
    );

    assert!(
        !config.contains("--dport 2222"),
        "disabled port forward must not appear in ruleset"
    );
}

// ── 23. User rules appear in zone ruleset ────────────────────────────

#[test]
fn user_rules_appear_in_zone_ruleset() {
    let rules = vec![
        make_rule(
            1,
            "input",
            "tcp",
            Some("9090"),
            Action::Accept,
            "prometheus",
        ),
        make_rule(2, "forward", "udp", Some("5060"), Action::Drop, "block SIP"),
    ];

    let config = generate_zone_ruleset(&standard_zones(), &rules, &FirewallPolicy::default(), &[]);

    assert!(
        config.contains("-p tcp --dport 9090 -j ACCEPT"),
        "user rule for port 9090 must appear in zone ruleset"
    );
    assert!(
        config.contains("-p udp --dport 5060 -j DROP"),
        "user rule dropping SIP must appear in zone ruleset"
    );
    assert!(
        config.contains("User-defined rules"),
        "zone ruleset must have a user-defined rules section"
    );
}

// ── 24. Rate limited rules generate correct syntax ───────────────────

#[test]
fn rate_limited_rules_generate_correct_iptables_syntax() {
    let rules = vec![FirewallRule {
        id: Some(1),
        chain: "input".to_string(),
        priority: 0,
        detail: RuleDetail {
            action: Action::Accept,
            protocol: "tcp".to_string(),
            source: "any".to_string(),
            destination: "any".to_string(),
            port: Some("443".to_string()),
            comment: Some("rate limited HTTPS".to_string()),
            vlan: None,
            rate_limit: Some("50/second".to_string()),
        },
        enabled: true,
    }];

    let config = generate_zone_ruleset(&standard_zones(), &rules, &FirewallPolicy::default(), &[]);

    assert!(
        config.contains("-m limit --limit 50/sec"),
        "rate limited rule must generate '-m limit --limit <value>' syntax"
    );
    assert!(
        config.contains("-p tcp --dport 443 -m limit --limit 50/sec -j ACCEPT"),
        "rate limit must appear before the action"
    );
}

// ── 26. Zone interfaces are expanded into individual rules ───────────

#[test]
fn zone_interfaces_expanded_into_individual_rules() {
    let config = standard_ruleset();

    // WAN has two interfaces; each should have its own rules.
    assert!(
        config.contains("-i eth0 -p tcp --dport 22 -j DROP"),
        "WAN eth0 should have SSH drop rule"
    );
    assert!(
        config.contains("-i ppp0 -p tcp --dport 22 -j DROP"),
        "WAN ppp0 should have SSH drop rule"
    );

    // LAN should explicitly DROP SSH and web UI (MGMT-only).
    assert!(
        config.contains("-i br-lan -p tcp --dport 443 -j DROP"),
        "LAN br-lan must DROP web UI"
    );
    assert!(
        config.contains("-i eth1 -p tcp --dport 443 -j DROP"),
        "LAN eth1 must DROP web UI"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Cross-cutting Security Invariant Tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn no_zone_except_mgmt_allows_ssh_input() {
    let config = standard_ruleset();
    // SSH accept rules should only appear for MGMT zone interfaces.
    let ssh_accept_lines: Vec<&str> = config
        .lines()
        .filter(|line| line.contains("--dport 22") && line.contains("-j ACCEPT"))
        .collect();

    for line in &ssh_accept_lines {
        assert!(
            line.contains("-i br-mgmt"),
            "SSH accept must only appear for MGMT interfaces, found: {line}"
        );
    }
}

#[test]
fn no_zone_except_mgmt_allows_inform_8080() {
    let config = standard_ruleset();
    let inform_accept_lines: Vec<&str> = config
        .lines()
        .filter(|line| line.contains("--dport 8080") && line.contains("-j ACCEPT"))
        .collect();

    for line in &inform_accept_lines {
        assert!(
            line.contains("-i br-mgmt"),
            "Inform (8080) accept must only appear for MGMT, found: {line}"
        );
    }
}

#[test]
fn wan_has_no_accept_input_rules() {
    let config = standard_ruleset();
    // WAN interfaces should have no input accept rules (only drop rules).
    let wan_input_accepts: Vec<&str> = config
        .lines()
        .filter(|line| {
            (line.contains("-i eth0") || line.contains("-i ppp0"))
                && line.contains("SFGW-INPUT")
                && line.contains("-j ACCEPT")
        })
        .collect();

    assert!(
        wan_input_accepts.is_empty(),
        "WAN must have no input accept rules, found: {wan_input_accepts:?}"
    );
}

#[test]
fn guest_drop_rule_appears_after_dns_dhcp_allows() {
    let config = standard_ruleset();
    // The catch-all drop rule for GUEST input must come after the DNS/DHCP allows.
    let guest_dns_pos = config
        .find("-i br-guest -p tcp --dport 53 -j ACCEPT")
        .expect("GUEST DNS allow must exist");
    let guest_dhcp_pos = config
        .find("-i br-guest -p udp --dport 67:68 -j ACCEPT")
        .expect("GUEST DHCP allow must exist");
    let guest_drop_pos = config
        .find("-i br-guest -j DROP -m comment --comment \"block all other GUEST input\"")
        .expect("GUEST catch-all drop must exist");

    assert!(
        guest_drop_pos > guest_dns_pos,
        "GUEST drop must come after DNS allow"
    );
    assert!(
        guest_drop_pos > guest_dhcp_pos,
        "GUEST drop must come after DHCP allow"
    );
}

#[test]
fn guest_forward_drops_appear_before_wan_accept() {
    let config = standard_ruleset();
    let guest_lan_drop = config
        .find("-i br-guest -o br-lan -j DROP")
        .expect("GUEST->LAN drop must exist");
    let guest_wan_accept = config
        .find("-i br-guest -o eth0 -j ACCEPT")
        .expect("GUEST->WAN accept must exist");

    assert!(
        guest_lan_drop < guest_wan_accept,
        "GUEST->LAN drop must appear before GUEST->WAN accept"
    );
}

#[test]
fn dmz_forward_drops_appear_before_wan_accept() {
    let config = standard_ruleset();
    let dmz_lan_drop = config
        .find("-i eth2 -o br-lan -j DROP")
        .expect("DMZ->LAN drop must exist");
    let dmz_wan_accept = config
        .find("-i eth2 -o eth0 -j ACCEPT")
        .expect("DMZ->WAN accept must exist");

    assert!(
        dmz_lan_drop < dmz_wan_accept,
        "DMZ->LAN drop must appear before DMZ->WAN accept"
    );
}

#[test]
fn conntrack_established_related_present_in_all_chains() {
    let config = standard_ruleset();
    assert!(
        config.contains("-A SFGW-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"),
        "input chain must accept established/related"
    );
    assert!(
        config.contains("-A SFGW-FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"),
        "forward chain must accept established/related"
    );
    assert!(
        config.contains("-A SFGW-OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"),
        "output chain must accept established/related"
    );
}

#[test]
fn invalid_packets_dropped_in_input_and_forward() {
    let config = standard_ruleset();
    assert!(
        config.contains("-A SFGW-INPUT -m conntrack --ctstate INVALID -j DROP"),
        "input chain must drop invalid packets"
    );
    assert!(
        config.contains("-A SFGW-FORWARD -m conntrack --ctstate INVALID -j DROP"),
        "forward chain must drop invalid packets"
    );
}

#[test]
fn loopback_accepted() {
    let config = standard_ruleset();
    assert!(
        config.contains("-i lo -j ACCEPT"),
        "loopback input must be accepted"
    );
    assert!(
        config.contains("-o lo -j ACCEPT"),
        "loopback output must be accepted"
    );
}

#[test]
fn ipv6_filter_config_has_icmpv6_ndp_rules() {
    let config = standard_ruleset();
    let ipv6 = sfgw_fw::iptables::filter_config_to_ipv6(&config);
    assert!(
        ipv6.contains("--icmpv6-type neighbor-solicitation"),
        "IPv6 config must have NDP neighbor solicitation"
    );
    assert!(
        ipv6.contains("--icmpv6-type router-advertisement"),
        "IPv6 config must have NDP router advertisement"
    );
    assert!(
        ipv6.contains("--icmpv6-type echo-request"),
        "IPv6 config must have ICMPv6 echo-request"
    );
    assert!(
        !ipv6.contains("-p icmp "),
        "IPv6 config must not contain IPv4 ICMP rules"
    );
    assert!(
        !ipv6.contains("*nat"),
        "IPv6 config must not contain NAT table"
    );
}

// ── FirewallZone::from_role parsing ──────────────────────────────────

#[test]
fn firewall_zone_from_role_case_insensitive() {
    assert_eq!(FirewallZone::from_role("WAN"), FirewallZone::Wan);
    assert_eq!(FirewallZone::from_role("wan"), FirewallZone::Wan);
    assert_eq!(FirewallZone::from_role("Wan"), FirewallZone::Wan);
    assert_eq!(FirewallZone::from_role("LAN"), FirewallZone::Lan);
    assert_eq!(FirewallZone::from_role("dmz"), FirewallZone::Dmz);
    assert_eq!(FirewallZone::from_role("GUEST"), FirewallZone::Guest);
    assert_eq!(FirewallZone::from_role("IoT"), FirewallZone::IoT);
    assert_eq!(FirewallZone::from_role("mgmt"), FirewallZone::Mgmt);
    assert_eq!(FirewallZone::from_role("vpn"), FirewallZone::Vpn);
}

#[test]
fn firewall_zone_from_role_custom() {
    match FirewallZone::from_role("honeypot") {
        FirewallZone::Custom(name) => assert_eq!(name, "honeypot"),
        other => panic!("expected Custom(\"honeypot\"), got {other:?}"),
    }
}

// ── Empty zone sets do not produce rules for that zone ───────────────

#[test]
fn zone_with_no_interfaces_produces_no_rules() {
    let zones = vec![
        ZonePolicy {
            zone: FirewallZone::Wan,
            interfaces: vec!["eth0".to_string()],
        },
        ZonePolicy {
            zone: FirewallZone::Lan,
            interfaces: vec!["br-lan".to_string()],
        },
        // GUEST zone has no interfaces assigned.
        ZonePolicy {
            zone: FirewallZone::Guest,
            interfaces: vec![],
        },
    ];

    let config = generate_zone_ruleset(&zones, &[], &FirewallPolicy::default(), &[]);

    // GUEST rules should not appear since no interfaces are assigned.
    assert!(
        !config.contains("br-guest"),
        "GUEST zone with no interfaces must not generate any rules"
    );
    // But WAN and LAN should still work.
    assert!(config.contains("-i eth0"));
    assert!(config.contains("-i br-lan"));
}

// ── iptables-restore format structure ────────────────────────────────

#[test]
fn ruleset_has_proper_iptables_restore_structure() {
    let config = standard_ruleset();

    // Must have *filter table.
    assert!(config.contains("*filter"), "must have *filter table");

    // Must have *nat table.
    assert!(config.contains("*nat"), "must have *nat table");

    // Must have COMMIT for each table.
    let commit_count = config.matches("COMMIT").count();
    assert_eq!(
        commit_count, 2,
        "must have exactly 2 COMMIT statements (filter and nat)"
    );

    // Must have custom chain declarations.
    assert!(
        config.contains(":SFGW-INPUT - [0:0]"),
        "must declare custom input chain"
    );
    assert!(
        config.contains(":SFGW-FORWARD - [0:0]"),
        "must declare custom forward chain"
    );

    // Must have jumps from built-in to custom chains.
    assert!(
        config.contains("-A INPUT -j SFGW-INPUT"),
        "must jump to custom input chain"
    );
    assert!(
        config.contains("-A FORWARD -j SFGW-FORWARD"),
        "must jump to custom forward chain"
    );
}
