// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests for the sfgw-fw zone matrix security model.
//!
//! These tests verify the complete security model as a whole rather than
//! individual functions. They ensure that the zone matrix enforces the
//! intended isolation properties: GUEST cannot reach LAN, DMZ cannot
//! reach MGMT, WAN exposes no management services, etc.

use sfgw_fw::nft::{generate_ruleset, generate_ruleset_with_forwards, generate_zone_ruleset};
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
    assert_eq!(policy.default_input, Action::Drop, "input must default to Drop");
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
        config.contains("chain input {\n        type filter hook input priority 0; policy drop;"),
        "input chain must have policy drop in generated config"
    );
    assert!(
        config.contains(
            "chain forward {\n        type filter hook forward priority 0; policy drop;"
        ),
        "forward chain must have policy drop in generated config"
    );
    assert!(
        config.contains(
            "chain output {\n        type filter hook output priority 0; policy accept;"
        ),
        "output chain must have policy accept in generated config"
    );
}

// ── 2. WAN blocks web UI ─────────────────────────────────────────────

#[test]
fn wan_zone_blocks_web_ui_ports_80_443() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @wan_ifaces tcp dport { 80, 443 } drop"),
        "WAN must explicitly drop HTTP/HTTPS input"
    );
}

// ── 3. WAN blocks SSH ────────────────────────────────────────────────

#[test]
fn wan_zone_blocks_ssh_port_22() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @wan_ifaces tcp dport 22 drop"),
        "WAN must explicitly drop SSH input"
    );
}

// ── 4. WAN has NAT masquerade ────────────────────────────────────────

#[test]
fn wan_zone_has_nat_masquerade() {
    let config = standard_ruleset();
    assert!(
        config.contains("oifname @wan_ifaces masquerade"),
        "WAN must have NAT masquerade in postrouting"
    );
}

// ── 5. LAN allows web UI, SSH, DHCP, DNS ─────────────────────────────

#[test]
fn lan_zone_allows_web_ui_443() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @lan_ifaces tcp dport 443 accept"),
        "LAN must allow HTTPS (443) for web UI"
    );
}

#[test]
fn lan_zone_allows_ssh_22() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @lan_ifaces tcp dport 22 accept"),
        "LAN must allow SSH (22)"
    );
}

#[test]
fn lan_zone_allows_dhcp_67_68() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @lan_ifaces udp dport { 67, 68 } accept"),
        "LAN must allow DHCP (67/68)"
    );
}

#[test]
fn lan_zone_allows_dns_53() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @lan_ifaces tcp dport 53 accept"),
        "LAN must allow DNS/TCP (53)"
    );
    assert!(
        config.contains("iifname @lan_ifaces udp dport 53 accept"),
        "LAN must allow DNS/UDP (53)"
    );
}

// ── 6. LAN forwards to WAN and DMZ ──────────────────────────────────

#[test]
fn lan_zone_forwards_to_wan() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @lan_ifaces oifname @wan_ifaces accept"),
        "LAN must be allowed to forward to WAN"
    );
}

#[test]
fn lan_zone_forwards_to_dmz() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @lan_ifaces oifname @dmz_ifaces accept"),
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
        !config.contains("iifname @lan_ifaces oifname @guest_ifaces accept"),
        "LAN must NOT have an explicit forward-accept to GUEST; default deny handles it"
    );
}

// ── 8. DMZ allows inbound HTTP/HTTPS ─────────────────────────────────

#[test]
fn dmz_zone_allows_inbound_http_https() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @dmz_ifaces tcp dport { 80, 443 } accept"),
        "DMZ must allow inbound HTTP (80) and HTTPS (443)"
    );
}

// ── 9. DMZ blocks forwarding to LAN ──────────────────────────────────

#[test]
fn dmz_zone_blocks_forward_to_lan() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @dmz_ifaces oifname @lan_ifaces drop"),
        "DMZ must explicitly drop forwarding to LAN"
    );
}

// ── 10. DMZ blocks forwarding to MGMT ────────────────────────────────

#[test]
fn dmz_zone_blocks_forward_to_mgmt() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @dmz_ifaces oifname @mgmt_ifaces drop"),
        "DMZ must explicitly drop forwarding to MGMT"
    );
}

// ── 11. DMZ forwards to WAN ─────────────────────────────────────────

#[test]
fn dmz_zone_forwards_to_wan() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @dmz_ifaces oifname @wan_ifaces accept"),
        "DMZ must be allowed to forward to WAN"
    );
}

// ── 12. MGMT allows web UI, SSH, Inform, DHCP, DNS ──────────────────

#[test]
fn mgmt_zone_allows_web_ui_443() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @mgmt_ifaces tcp dport 443 accept"),
        "MGMT must allow HTTPS (443) for web UI"
    );
}

#[test]
fn mgmt_zone_allows_ssh_22() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @mgmt_ifaces tcp dport 22 accept"),
        "MGMT must allow SSH (22)"
    );
}

#[test]
fn mgmt_zone_allows_inform_8080() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @mgmt_ifaces tcp dport 8080 accept"),
        "MGMT must allow Inform protocol (8080)"
    );
}

#[test]
fn mgmt_zone_allows_dhcp_and_dns() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @mgmt_ifaces udp dport { 67, 68 } accept"),
        "MGMT must allow DHCP"
    );
    assert!(
        config.contains("iifname @mgmt_ifaces tcp dport 53 accept"),
        "MGMT must allow DNS/TCP"
    );
    assert!(
        config.contains("iifname @mgmt_ifaces udp dport 53 accept"),
        "MGMT must allow DNS/UDP"
    );
}

// ── 13. MGMT forwards to ALL internal zones ──────────────────────────

#[test]
fn mgmt_zone_forwards_to_lan() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @mgmt_ifaces oifname @lan_ifaces accept"),
        "MGMT must be allowed to forward to LAN"
    );
}

#[test]
fn mgmt_zone_forwards_to_dmz() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @mgmt_ifaces oifname @dmz_ifaces accept"),
        "MGMT must be allowed to forward to DMZ"
    );
}

#[test]
fn mgmt_zone_forwards_to_guest() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @mgmt_ifaces oifname @guest_ifaces accept"),
        "MGMT must be allowed to forward to GUEST"
    );
}

#[test]
fn mgmt_zone_forwards_to_wan() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @mgmt_ifaces oifname @wan_ifaces accept"),
        "MGMT must be allowed to forward to WAN"
    );
}

// ── 14. GUEST allows DNS and DHCP to gateway only ────────────────────

#[test]
fn guest_zone_allows_dns_53() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @guest_ifaces tcp dport 53 accept"),
        "GUEST must allow DNS/TCP (53) to gateway"
    );
    assert!(
        config.contains("iifname @guest_ifaces udp dport 53 accept"),
        "GUEST must allow DNS/UDP (53) to gateway"
    );
}

#[test]
fn guest_zone_allows_dhcp_67_68() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @guest_ifaces udp dport { 67, 68 } accept"),
        "GUEST must allow DHCP (67/68) to gateway"
    );
}

// ── 15. GUEST drops all other input ──────────────────────────────────

#[test]
fn guest_zone_drops_all_other_input() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @guest_ifaces drop comment \"block all other GUEST input\""),
        "GUEST must drop all input after DNS/DHCP allows"
    );
}

#[test]
fn guest_zone_does_not_allow_web_ui() {
    let config = standard_ruleset();
    // Verify there is no rule allowing GUEST to reach port 443 on the gateway.
    assert!(
        !config.contains("iifname @guest_ifaces tcp dport 443 accept"),
        "GUEST must NOT be allowed to access the web UI (443)"
    );
}

#[test]
fn guest_zone_does_not_allow_ssh() {
    let config = standard_ruleset();
    assert!(
        !config.contains("iifname @guest_ifaces tcp dport 22 accept"),
        "GUEST must NOT be allowed to access SSH (22)"
    );
}

#[test]
fn guest_zone_does_not_allow_inform() {
    let config = standard_ruleset();
    assert!(
        !config.contains("iifname @guest_ifaces tcp dport 8080 accept"),
        "GUEST must NOT be allowed to access Inform (8080)"
    );
}

// ── 16. GUEST blocks forwarding to LAN, DMZ, MGMT ───────────────────

#[test]
fn guest_zone_blocks_forward_to_lan() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @guest_ifaces oifname @lan_ifaces drop"),
        "GUEST must explicitly drop forwarding to LAN"
    );
}

#[test]
fn guest_zone_blocks_forward_to_dmz() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @guest_ifaces oifname @dmz_ifaces drop"),
        "GUEST must explicitly drop forwarding to DMZ"
    );
}

#[test]
fn guest_zone_blocks_forward_to_mgmt() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @guest_ifaces oifname @mgmt_ifaces drop"),
        "GUEST must explicitly drop forwarding to MGMT"
    );
}

// ── 17. GUEST can ONLY forward to WAN ────────────────────────────────

#[test]
fn guest_zone_forwards_to_wan() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname @guest_ifaces oifname @wan_ifaces accept"),
        "GUEST must be allowed to forward to WAN (internet access)"
    );
}

#[test]
fn guest_zone_only_accept_forward_is_wan() {
    let config = standard_ruleset();
    // The only forward-accept rule for GUEST should be to WAN.
    // Count all forward accept rules that originate from GUEST.
    let guest_forward_accepts: Vec<&str> = config
        .lines()
        .filter(|line| {
            line.contains("iifname @guest_ifaces")
                && line.contains("oifname")
                && line.contains("accept")
        })
        .collect();
    assert_eq!(
        guest_forward_accepts.len(),
        1,
        "GUEST should have exactly one forward-accept rule (to WAN), found: {guest_forward_accepts:?}"
    );
    assert!(
        guest_forward_accepts[0].contains("@wan_ifaces"),
        "the single GUEST forward-accept must be to WAN"
    );
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
    }];

    let config = generate_zone_ruleset(
        &standard_zones(),
        &[],
        &FirewallPolicy::default(),
        &forwards,
    );

    // DNAT must be scoped to WAN interfaces.
    assert!(
        config.contains("iifname @wan_ifaces tcp dport 8443 dnat to 192.168.1.100:443"),
        "port forward DNAT must be scoped to WAN interfaces"
    );

    // Must also allow the forwarded traffic in the forward chain.
    assert!(
        config.contains("ip daddr 192.168.1.100 tcp dport 443 accept"),
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
    }];

    let config = generate_zone_ruleset(
        &standard_zones(),
        &[],
        &FirewallPolicy::default(),
        &forwards,
    );

    assert!(
        !config.contains("dport 2222"),
        "disabled port forward must not appear in ruleset"
    );
}

// ── 23. User rules appear in zone ruleset ────────────────────────────

#[test]
fn user_rules_appear_in_zone_ruleset() {
    let rules = vec![
        make_rule(1, "input", "tcp", Some("9090"), Action::Accept, "prometheus"),
        make_rule(2, "forward", "udp", Some("5060"), Action::Drop, "block SIP"),
    ];

    let config = generate_zone_ruleset(
        &standard_zones(),
        &rules,
        &FirewallPolicy::default(),
        &[],
    );

    assert!(
        config.contains("tcp dport 9090 accept"),
        "user rule for port 9090 must appear in zone ruleset"
    );
    assert!(
        config.contains("udp dport 5060 drop"),
        "user rule dropping SIP must appear in zone ruleset"
    );
    assert!(
        config.contains("User-defined rules"),
        "zone ruleset must have a user-defined rules section"
    );
}

// ── 24. VLAN rules generate correct syntax ───────────────────────────

#[test]
fn vlan_rules_generate_correct_nft_syntax() {
    let rules = vec![FirewallRule {
        id: Some(1),
        chain: "forward".to_string(),
        priority: 10,
        detail: RuleDetail {
            action: Action::Accept,
            protocol: "any".to_string(),
            source: "any".to_string(),
            destination: "any".to_string(),
            port: None,
            comment: Some("allow VLAN 200 traffic".to_string()),
            vlan: Some(200),
            rate_limit: None,
        },
        enabled: true,
    }];

    let config = generate_zone_ruleset(
        &standard_zones(),
        &rules,
        &FirewallPolicy::default(),
        &[],
    );

    assert!(
        config.contains("vlan id 200 accept"),
        "VLAN rule must generate 'vlan id <id>' syntax"
    );
}

// ── 25. Rate limited rules generate correct syntax ───────────────────

#[test]
fn rate_limited_rules_generate_correct_nft_syntax() {
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

    let config = generate_zone_ruleset(
        &standard_zones(),
        &rules,
        &FirewallPolicy::default(),
        &[],
    );

    assert!(
        config.contains("limit rate 50/second"),
        "rate limited rule must generate 'limit rate <value>' syntax"
    );
    assert!(
        config.contains("tcp dport 443 limit rate 50/second accept"),
        "rate limit must appear before the action"
    );
}

// ── 26. Zone interface sets are properly defined ─────────────────────

#[test]
fn zone_interface_sets_are_properly_defined() {
    let config = standard_ruleset();

    // Each zone should have a named set with its interfaces.
    assert!(
        config.contains("set wan_ifaces { type ifname; elements = { \"eth0\", \"ppp0\" }; }"),
        "wan_ifaces set must contain eth0 and ppp0"
    );
    assert!(
        config.contains("set guest_ifaces { type ifname; elements = { \"br-guest\" }; }"),
        "guest_ifaces set must contain br-guest"
    );
    assert!(
        config.contains("set mgmt_ifaces { type ifname; elements = { \"br-mgmt\" }; }"),
        "mgmt_ifaces set must contain br-mgmt"
    );
    assert!(
        config.contains("set dmz_ifaces { type ifname; elements = { \"eth2\" }; }"),
        "dmz_ifaces set must contain eth2"
    );
}

#[test]
fn zone_interface_set_with_multiple_interfaces() {
    let config = standard_ruleset();
    // LAN has two interfaces; verify both are in the set.
    // The order may vary, so check for both.
    let lan_set_line = config
        .lines()
        .find(|l| l.contains("set lan_ifaces"))
        .expect("must have lan_ifaces set");
    assert!(
        lan_set_line.contains("\"br-lan\"") && lan_set_line.contains("\"eth1\""),
        "lan_ifaces set must contain both br-lan and eth1, got: {lan_set_line}"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Cross-cutting Security Invariant Tests
// ═══════════════════════════════════════════════════════════════════════
// These tests verify security properties that span the entire zone matrix.

#[test]
fn no_zone_except_lan_and_mgmt_allows_ssh_input() {
    let config = standard_ruleset();
    // SSH accept rules should only appear for LAN and MGMT zones.
    let ssh_accept_lines: Vec<&str> = config
        .lines()
        .filter(|line| line.contains("dport 22") && line.contains("accept"))
        .collect();

    for line in &ssh_accept_lines {
        assert!(
            line.contains("@lan_ifaces") || line.contains("@mgmt_ifaces"),
            "SSH accept must only appear for LAN or MGMT, found: {line}"
        );
    }
}

#[test]
fn no_zone_except_mgmt_allows_inform_8080() {
    let config = standard_ruleset();
    let inform_accept_lines: Vec<&str> = config
        .lines()
        .filter(|line| line.contains("dport 8080") && line.contains("accept"))
        .collect();

    for line in &inform_accept_lines {
        assert!(
            line.contains("@mgmt_ifaces"),
            "Inform (8080) accept must only appear for MGMT, found: {line}"
        );
    }
}

#[test]
fn wan_has_no_accept_input_rules() {
    let config = standard_ruleset();
    // WAN should have no input accept rules (only drop rules).
    let wan_input_accepts: Vec<&str> = config
        .lines()
        .filter(|line| {
            line.contains("iifname @wan_ifaces")
                && line.contains("input")
                && line.contains("accept")
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
        .find("iifname @guest_ifaces tcp dport 53 accept")
        .expect("GUEST DNS allow must exist");
    let guest_dhcp_pos = config
        .find("iifname @guest_ifaces udp dport { 67, 68 } accept")
        .expect("GUEST DHCP allow must exist");
    let guest_drop_pos = config
        .find("iifname @guest_ifaces drop comment \"block all other GUEST input\"")
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
    // The explicit drop rules for GUEST->LAN/DMZ/MGMT must appear before
    // the GUEST->WAN accept, ensuring isolation even if order matters.
    let guest_lan_drop = config
        .find("iifname @guest_ifaces oifname @lan_ifaces drop")
        .expect("GUEST->LAN drop must exist");
    let guest_wan_accept = config
        .find("iifname @guest_ifaces oifname @wan_ifaces accept")
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
        .find("iifname @dmz_ifaces oifname @lan_ifaces drop")
        .expect("DMZ->LAN drop must exist");
    let dmz_wan_accept = config
        .find("iifname @dmz_ifaces oifname @wan_ifaces accept")
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
        config.contains("add rule inet sfgw input ct state established,related accept"),
        "input chain must accept established/related"
    );
    assert!(
        config.contains("add rule inet sfgw forward ct state established,related accept"),
        "forward chain must accept established/related"
    );
    assert!(
        config.contains("add rule inet sfgw output ct state established,related accept"),
        "output chain must accept established/related"
    );
}

#[test]
fn invalid_packets_dropped_in_input_and_forward() {
    let config = standard_ruleset();
    assert!(
        config.contains("add rule inet sfgw input ct state invalid drop"),
        "input chain must drop invalid packets"
    );
    assert!(
        config.contains("add rule inet sfgw forward ct state invalid drop"),
        "forward chain must drop invalid packets"
    );
}

#[test]
fn loopback_accepted() {
    let config = standard_ruleset();
    assert!(
        config.contains("iifname \"lo\" accept"),
        "loopback input must be accepted"
    );
    assert!(
        config.contains("oifname \"lo\" accept"),
        "loopback output must be accepted"
    );
}

#[test]
fn icmpv6_ndp_accepted() {
    let config = standard_ruleset();
    assert!(
        config.contains("nd-neighbor-solicit"),
        "NDP neighbor solicitation must be accepted"
    );
    assert!(
        config.contains("nd-router-advert"),
        "NDP router advertisement must be accepted"
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
        !config.contains("@guest_ifaces"),
        "GUEST zone with no interfaces must not generate any rules"
    );
    // But WAN and LAN should still work.
    assert!(config.contains("@wan_ifaces"));
    assert!(config.contains("@lan_ifaces"));
}

// ── Table atomicity ──────────────────────────────────────────────────

#[test]
fn ruleset_destroys_and_recreates_table_atomically() {
    let config = standard_ruleset();
    // Must flush the old table before creating the new one.
    let create_pos = config
        .find("table inet sfgw {}")
        .expect("must create empty table first");
    let delete_pos = config
        .find("delete table inet sfgw")
        .expect("must delete the empty table");
    let open_pos = config
        .rfind("table inet sfgw {")
        .expect("must open final table block");

    assert!(
        create_pos < delete_pos,
        "empty table creation must precede deletion"
    );
    assert!(
        delete_pos < open_pos,
        "deletion must precede final table definition"
    );
}

// ── NAT chain declarations ───────────────────────────────────────────

#[test]
fn nat_chains_present_with_correct_hooks() {
    let config = standard_ruleset();
    assert!(
        config.contains("chain prerouting {"),
        "prerouting NAT chain must exist"
    );
    assert!(
        config.contains("type nat hook prerouting priority -100; policy accept;"),
        "prerouting chain must be nat type with priority -100"
    );
    assert!(
        config.contains("chain postrouting {"),
        "postrouting NAT chain must exist"
    );
    assert!(
        config.contains("type nat hook postrouting priority 100; policy accept;"),
        "postrouting chain must be nat type with priority 100"
    );
}

// ── Multiple port forwards ───────────────────────────────────────────

#[test]
fn multiple_port_forwards_all_appear_scoped_to_wan() {
    let forwards = vec![
        PortForward {
            protocol: "tcp".to_string(),
            external_port: 80,
            internal_ip: "192.168.1.10".to_string(),
            internal_port: 80,
            comment: Some("HTTP forward".to_string()),
            enabled: true,
        },
        PortForward {
            protocol: "tcp".to_string(),
            external_port: 443,
            internal_ip: "192.168.1.10".to_string(),
            internal_port: 443,
            comment: Some("HTTPS forward".to_string()),
            enabled: true,
        },
        PortForward {
            protocol: "udp".to_string(),
            external_port: 51820,
            internal_ip: "192.168.1.20".to_string(),
            internal_port: 51820,
            comment: Some("WireGuard forward".to_string()),
            enabled: true,
        },
    ];

    let config = generate_zone_ruleset(
        &standard_zones(),
        &[],
        &FirewallPolicy::default(),
        &forwards,
    );

    assert!(config.contains("iifname @wan_ifaces tcp dport 80 dnat to 192.168.1.10:80"));
    assert!(config.contains("iifname @wan_ifaces tcp dport 443 dnat to 192.168.1.10:443"));
    assert!(config.contains("iifname @wan_ifaces udp dport 51820 dnat to 192.168.1.20:51820"));
}

// ── Legacy (non-zone) ruleset ────────────────────────────────────────

#[test]
fn legacy_ruleset_still_enforces_default_deny() {
    let policy = FirewallPolicy::default();
    let config = generate_ruleset(&[], &policy);
    assert!(config.contains("policy drop"), "legacy ruleset must default deny");
    assert!(config.contains("masquerade"), "legacy ruleset must have NAT");
    assert!(
        config.contains("ct state established,related accept"),
        "legacy ruleset must allow established/related"
    );
}

#[test]
fn legacy_ruleset_with_port_forwards_generates_dnat() {
    let forwards = vec![PortForward {
        protocol: "tcp".to_string(),
        external_port: 2222,
        internal_ip: "192.168.1.50".to_string(),
        internal_port: 22,
        comment: Some("SSH forward".to_string()),
        enabled: true,
    }];
    let config = generate_ruleset_with_forwards(&[], &FirewallPolicy::default(), &forwards);
    assert!(
        config.contains("dnat to 192.168.1.50:22"),
        "legacy port forward must generate DNAT"
    );
    assert!(
        config.contains("dport 2222"),
        "legacy port forward must reference external port"
    );
}

// ── VLAN + rate limit combined rule ──────────────────────────────────

#[test]
fn combined_vlan_and_rate_limit_rule() {
    let rules = vec![FirewallRule {
        id: Some(1),
        chain: "forward".to_string(),
        priority: 5,
        detail: RuleDetail {
            action: Action::Accept,
            protocol: "tcp".to_string(),
            source: "any".to_string(),
            destination: "any".to_string(),
            port: Some("443".to_string()),
            comment: Some("VLAN 100 HTTPS rate limited".to_string()),
            vlan: Some(100),
            rate_limit: Some("200/second".to_string()),
        },
        enabled: true,
    }];

    let config = generate_zone_ruleset(
        &standard_zones(),
        &rules,
        &FirewallPolicy::default(),
        &[],
    );

    // Must contain all components in the correct order.
    let rule_line = config
        .lines()
        .find(|l| l.contains("vlan id 100"))
        .expect("must have VLAN 100 rule");
    assert!(
        rule_line.contains("vlan id 100"),
        "must have VLAN match"
    );
    assert!(
        rule_line.contains("tcp dport 443"),
        "must have port match"
    );
    assert!(
        rule_line.contains("limit rate 200/second"),
        "must have rate limit"
    );
    assert!(
        rule_line.contains("accept"),
        "must have accept action"
    );
}

// ── Source/destination interface rules ────────────────────────────────

#[test]
fn source_interface_rule_generates_iifname() {
    let rules = vec![FirewallRule {
        id: Some(1),
        chain: "input".to_string(),
        priority: 0,
        detail: RuleDetail {
            action: Action::Accept,
            protocol: "tcp".to_string(),
            source: "iif:br-lan".to_string(),
            destination: "any".to_string(),
            port: Some("8080".to_string()),
            comment: Some("custom from LAN".to_string()),
            vlan: None,
            rate_limit: None,
        },
        enabled: true,
    }];

    let config = generate_zone_ruleset(
        &standard_zones(),
        &rules,
        &FirewallPolicy::default(),
        &[],
    );
    assert!(
        config.contains("iifname \"br-lan\""),
        "iif: prefix must generate iifname match"
    );
}

#[test]
fn destination_interface_rule_generates_oifname() {
    let rules = vec![FirewallRule {
        id: Some(1),
        chain: "forward".to_string(),
        priority: 0,
        detail: RuleDetail {
            action: Action::Drop,
            protocol: "any".to_string(),
            source: "any".to_string(),
            destination: "oif:eth0".to_string(),
            port: None,
            comment: Some("block to WAN".to_string()),
            vlan: None,
            rate_limit: None,
        },
        enabled: true,
    }];

    let config = generate_zone_ruleset(
        &standard_zones(),
        &rules,
        &FirewallPolicy::default(),
        &[],
    );
    assert!(
        config.contains("oifname \"eth0\""),
        "oif: prefix must generate oifname match"
    );
}

// ── IP source/destination rules ──────────────────────────────────────

#[test]
fn ip_source_rule_generates_saddr() {
    let rules = vec![FirewallRule {
        id: Some(1),
        chain: "input".to_string(),
        priority: 0,
        detail: RuleDetail {
            action: Action::Drop,
            protocol: "any".to_string(),
            source: "10.99.0.0/16".to_string(),
            destination: "any".to_string(),
            port: None,
            comment: Some("block bad subnet".to_string()),
            vlan: None,
            rate_limit: None,
        },
        enabled: true,
    }];

    let config = generate_ruleset(&rules, &FirewallPolicy::default());
    assert!(
        config.contains("ip saddr 10.99.0.0/16 drop"),
        "IP source must generate 'ip saddr' match"
    );
}

#[test]
fn ip_destination_rule_generates_daddr() {
    let rules = vec![FirewallRule {
        id: Some(1),
        chain: "forward".to_string(),
        priority: 0,
        detail: RuleDetail {
            action: Action::Accept,
            protocol: "tcp".to_string(),
            source: "any".to_string(),
            destination: "192.168.1.100".to_string(),
            port: Some("443".to_string()),
            comment: Some("allow to server".to_string()),
            vlan: None,
            rate_limit: None,
        },
        enabled: true,
    }];

    let config = generate_ruleset(&rules, &FirewallPolicy::default());
    assert!(
        config.contains("ip daddr 192.168.1.100"),
        "IP destination must generate 'ip daddr' match"
    );
}

// ── WAN failover: priority ordering with 3 members ───────────────────

#[test]
fn failover_three_members_selects_correct_primary() {
    // eth3 has priority 10, eth0 has priority 5, ppp0 has priority 1
    // ppp0 should be selected.
    let group = test_failover_group();
    let cmds = generate_wan_routing_commands(&group);
    let default_cmd = cmds.last().expect("must have default route");
    assert!(
        default_cmd.contains(&"ppp0".to_string()),
        "with three members, failover must select ppp0 (priority=1)"
    );
}

#[test]
fn failover_with_only_highest_priority_disabled_falls_back() {
    let mut group = test_failover_group();
    // Disable ppp0 (priority=1), so eth0 (priority=5) should be next.
    group.interfaces[1].enabled = false;
    let cmds = generate_wan_routing_commands(&group);
    let default_cmd = cmds.last().expect("must have default route");
    assert!(
        default_cmd.contains(&"eth0".to_string()),
        "with ppp0 disabled, must fall back to eth0 (priority=5)"
    );
    assert!(
        !default_cmd.contains(&"eth3".to_string()),
        "eth3 (priority=10) must not be primary when eth0 (priority=5) is available"
    );
}

// ── Load balance: per-interface table setup ──────────────────────────

#[test]
fn load_balance_per_interface_tables_use_sequential_ids() {
    let group = WanGroup {
        name: "lb".to_string(),
        mode: WanMode::LoadBalance,
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
                interface: "eth1".to_string(),
                weight: 50,
                gateway: "10.1.0.1".to_string(),
                priority: 2,
                check_target: "1.1.1.1".to_string(),
                enabled: true,
            },
        ],
    };

    let cmds = generate_wan_routing_commands(&group);
    // First two commands are per-interface table setup.
    assert!(cmds[0].contains(&"100".to_string()), "first table must be 100");
    assert!(cmds[1].contains(&"101".to_string()), "second table must be 101");
}
