use super::*;
use crate::{Action, AllowedService, CustomZone, FirewallPolicy, FirewallRule, RuleDetail};

#[test]
fn default_ruleset_contains_drop_policy() {
    let policy = FirewallPolicy::default();
    let config = generate_ruleset(&[], &policy);
    assert!(
        config.contains(":INPUT DROP"),
        "input should default to drop"
    );
    assert!(
        config.contains(":OUTPUT ACCEPT"),
        "output should default to accept"
    );
}

#[test]
fn default_ruleset_has_established_related() {
    let config = generate_ruleset(&[], &FirewallPolicy::default());
    assert!(config.contains("-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"));
}

#[test]
fn default_ruleset_has_loopback() {
    let config = generate_ruleset(&[], &FirewallPolicy::default());
    assert!(config.contains("-i lo -j ACCEPT"));
}

#[test]
fn default_ruleset_has_masquerade() {
    let config = generate_ruleset(&[], &FirewallPolicy::default());
    assert!(config.contains("MASQUERADE"));
}

#[test]
fn default_ruleset_allows_dhcp_on_lan() {
    let config = generate_ruleset(&[], &FirewallPolicy::default());
    assert!(config.contains("--dport 67:68"));
}

#[test]
fn default_ruleset_allows_inform_on_mgmt_only() {
    let config = generate_ruleset(&[], &FirewallPolicy::default());
    assert!(config.contains("br-mgmt"));
    assert!(config.contains("8080"));
}

#[test]
fn user_rule_generates_iptables() {
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
    assert!(config.contains("-p tcp --dport 22 -j DROP"));
    assert!(config.contains("Block SSH from WAN"));
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
    assert!(config.contains("-m limit --limit 100/sec"));
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
    assert!(config.contains("--to-destination 192.168.1.100:443"));
    assert!(config.contains("--dport 8443"));
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
    assert!(config.contains("-i br-lan"));
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
            vlan_id: None,
        },
        ZonePolicy {
            zone: FirewallZone::Lan,
            interfaces: vec!["br-lan".to_string(), "eth1".to_string()],
            vlan_id: Some(10),
        },
        ZonePolicy {
            zone: FirewallZone::Dmz,
            interfaces: vec!["eth2".to_string()],
            vlan_id: Some(3002),
        },
        ZonePolicy {
            zone: FirewallZone::Mgmt,
            interfaces: vec!["br-mgmt".to_string()],
            vlan_id: Some(3000),
        },
        ZonePolicy {
            zone: FirewallZone::Guest,
            interfaces: vec!["br-guest".to_string()],
            vlan_id: Some(3001),
        },
    ]
}

#[test]
fn zone_ruleset_wan_blocks_web_ui() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    // Each WAN interface should have port 80 and 443 blocked.
    assert!(
        config.contains("-i eth0 -p tcp --dport 80 -j DROP"),
        "WAN eth0 should block HTTP"
    );
    assert!(
        config.contains("-i eth0 -p tcp --dport 443 -j DROP"),
        "WAN eth0 should block HTTPS"
    );
    assert!(
        config.contains("-i ppp0 -p tcp --dport 80 -j DROP"),
        "WAN ppp0 should block HTTP"
    );
    assert!(
        config.contains("-i ppp0 -p tcp --dport 443 -j DROP"),
        "WAN ppp0 should block HTTPS"
    );
}

#[test]
fn zone_ruleset_wan_blocks_ssh() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    assert!(
        config.contains("-i eth0 -p tcp --dport 22 -j DROP"),
        "WAN eth0 should block SSH"
    );
    assert!(
        config.contains("-i ppp0 -p tcp --dport 22 -j DROP"),
        "WAN ppp0 should block SSH"
    );
}

#[test]
fn zone_ruleset_lan_explicitly_drops_ssh_and_web() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    // LAN must explicitly DROP SSH, HTTPS, HTTP — not just omit ACCEPT.
    // Platform may have its own ACCEPT rules after our chain.
    assert!(
        config.contains("-i br-lan -p tcp --dport 22 -j DROP"),
        "LAN must explicitly DROP SSH"
    );
    assert!(
        config.contains("-i br-lan -p tcp --dport 443 -j DROP"),
        "LAN must explicitly DROP HTTPS"
    );
    assert!(
        config.contains("-i br-lan -p tcp --dport 80 -j DROP"),
        "LAN must explicitly DROP HTTP"
    );
    // Must NOT have ACCEPT for these ports.
    assert!(
        !config.contains("-i br-lan -p tcp --dport 443 -j ACCEPT"),
        "LAN must NOT ACCEPT HTTPS"
    );
    assert!(
        !config.contains("-i br-lan -p tcp --dport 22 -j ACCEPT"),
        "LAN must NOT ACCEPT SSH"
    );
}

#[test]
fn zone_ruleset_lan_allows_dhcp_dns() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    assert!(config.contains("-i br-lan -p udp --dport 67:68 -j ACCEPT"));
    assert!(config.contains("-i br-lan -p tcp --dport 53 -j ACCEPT"));
    assert!(config.contains("-i br-lan -p udp --dport 53 -j ACCEPT"));
}

#[test]
fn zone_ruleset_lan_forwards_to_wan_and_dmz() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    assert!(config.contains("-i br-lan -o eth0 -j ACCEPT"));
    assert!(config.contains("-i br-lan -o ppp0 -j ACCEPT"));
    assert!(config.contains("-i br-lan -o eth2 -j ACCEPT"));
}

#[test]
fn zone_ruleset_dmz_no_lan_access() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    assert!(
        config.contains("-i eth2 -o br-lan -j DROP"),
        "DMZ should not access LAN"
    );
}

#[test]
fn zone_ruleset_dmz_allows_dns_dhcp_only() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    // DMZ gets DNS and DHCP to the gateway, but no HTTP/HTTPS/SSH INPUT.
    assert!(
        config.contains("-i eth2 -p tcp --dport 53 -j ACCEPT"),
        "DMZ should allow DNS/TCP"
    );
    assert!(
        config.contains("-i eth2 -p udp --dport 67:68 -j ACCEPT"),
        "DMZ should allow DHCP"
    );
    assert!(
        config.contains("SFGW-INPUT -i eth2 -j DROP"),
        "DMZ should have catch-all DROP"
    );
    assert!(
        !config.contains("-i eth2 -p tcp --dport 80 -j ACCEPT"),
        "DMZ must NOT allow HTTP to gateway"
    );
    assert!(
        !config.contains("-i eth2 -p tcp --dport 443 -j ACCEPT"),
        "DMZ must NOT allow HTTPS to gateway"
    );
}

#[test]
fn zone_ruleset_dmz_forwards_to_wan() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    assert!(config.contains("-i eth2 -o eth0 -j ACCEPT"));
}

#[test]
fn zone_ruleset_has_masquerade() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    assert!(config.contains("-o eth0 -j MASQUERADE"));
    assert!(config.contains("-o ppp0 -j MASQUERADE"));
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
    // In zone mode, DNAT should be scoped to each WAN interface.
    assert!(
        config.contains("-i eth0 -p tcp --dport 8443 -j DNAT --to-destination 192.168.1.100:443")
    );
    assert!(
        config.contains("-i ppp0 -p tcp --dport 8443 -j DNAT --to-destination 192.168.1.100:443")
    );
}

// ── MGMT zone tests ──

#[test]
fn zone_ruleset_mgmt_allows_web_ui_ssh_inform() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    assert!(
        config.contains("-i br-mgmt -p tcp --dport 443 -j ACCEPT"),
        "MGMT should allow web UI"
    );
    assert!(
        config.contains("-i br-mgmt -p tcp --dport 22 -j ACCEPT"),
        "MGMT should allow SSH"
    );
    assert!(
        config.contains("-i br-mgmt -p tcp --dport 8080 -j ACCEPT"),
        "MGMT should allow Inform"
    );
}

#[test]
fn zone_ruleset_mgmt_allows_dhcp_dns() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    assert!(config.contains("-i br-mgmt -p udp --dport 67:68 -j ACCEPT"));
    assert!(config.contains("-i br-mgmt -p tcp --dport 53 -j ACCEPT"));
    assert!(config.contains("-i br-mgmt -p udp --dport 53 -j ACCEPT"));
}

#[test]
fn zone_ruleset_mgmt_forwards_to_all_internal() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    assert!(
        config.contains("-i br-mgmt -o br-lan -j ACCEPT"),
        "MGMT should reach LAN"
    );
    assert!(
        config.contains("-i br-mgmt -o eth2 -j ACCEPT"),
        "MGMT should reach DMZ"
    );
    assert!(
        config.contains("-i br-mgmt -o br-guest -j ACCEPT"),
        "MGMT should reach GUEST"
    );
    assert!(
        config.contains("-i br-mgmt -o eth0 -j ACCEPT"),
        "MGMT should reach WAN"
    );
}

// ── GUEST zone tests ──

#[test]
fn zone_ruleset_guest_allows_dns_dhcp_only() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    assert!(
        config.contains("-i br-guest -p tcp --dport 53 -j ACCEPT"),
        "GUEST should get DNS"
    );
    assert!(
        config.contains("-i br-guest -p udp --dport 53 -j ACCEPT"),
        "GUEST should get DNS"
    );
    assert!(
        config.contains("-i br-guest -p udp --dport 67:68 -j ACCEPT"),
        "GUEST should get DHCP"
    );
}

#[test]
fn zone_ruleset_guest_blocks_all_other_input() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    assert!(
        config.contains("-i br-guest -j DROP -m comment --comment \"block all other GUEST input\""),
        "GUEST should drop all other input"
    );
}

#[test]
fn zone_ruleset_guest_no_internal_access() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    assert!(
        config.contains("-i br-guest -o br-lan -j DROP"),
        "GUEST to LAN blocked"
    );
    assert!(
        config.contains("-i br-guest -o eth2 -j DROP"),
        "GUEST to DMZ blocked"
    );
    assert!(
        config.contains("-i br-guest -o br-mgmt -j DROP"),
        "GUEST to MGMT blocked"
    );
}

#[test]
fn zone_ruleset_guest_forwards_to_wan_only() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    assert!(
        config.contains("-i br-guest -o eth0 -j ACCEPT"),
        "GUEST should reach WAN eth0"
    );
    assert!(
        config.contains("-i br-guest -o ppp0 -j ACCEPT"),
        "GUEST should reach WAN ppp0"
    );
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
    assert!(config.contains("--to-destination 192.168.1.100:443"));
    // The injection-critical characters are stripped.
    assert!(!config.contains("\"; flush"));
    assert!(!config.contains("; #"));
    // The sanitized comment should only contain safe chars.
    assert!(config.contains("\"legit flush ruleset "));
}

// ── WAN interface binding tests ─────────────────────────────────

#[test]
fn port_forward_with_wan_interface_generates_iface() {
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
        config.contains("-i eth0 -p tcp --dport 443 -j DNAT --to-destination 192.168.1.100:443"),
        "should bind port forward to specific WAN interface"
    );
}

#[test]
fn port_forward_without_wan_interface_no_iface_in_legacy() {
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
    // Legacy mode: the DNAT rule itself should not have an -i prefix
    assert!(config.contains("-p tcp --dport 443 -j DNAT --to-destination 192.168.1.100:443"));
    // The DNAT line specifically should not be interface-scoped
    let dnat_line = config
        .lines()
        .find(|l| l.contains("--to-destination 192.168.1.100:443"))
        .unwrap();
    assert!(
        !dnat_line.contains("-i "),
        "legacy DNAT rule should not have -i interface"
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
    // Should use the specific interface, not expand to all WAN interfaces.
    assert!(
        config.contains("-i ppp0 -p tcp --dport 8443 -j DNAT --to-destination 192.168.1.100:443"),
        "wan_interface should override zone-level WAN interface expansion"
    );
    // Should NOT have eth0 DNAT for port 8443 (only ppp0).
    assert!(
        !config.contains("-i eth0 -p tcp --dport 8443"),
        "should not use eth0 when wan_interface is set to ppp0"
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
        !config.contains("--to-destination 192.168.1.100:443"),
        "DNAT rule with invalid interface should not be emitted"
    );
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

// ── iptables-restore format tests ────────────────────────────────

#[test]
fn ruleset_has_filter_table_structure() {
    let config = generate_ruleset(&[], &FirewallPolicy::default());
    assert!(config.contains("*filter"), "must have *filter table");
    assert!(config.contains("COMMIT"), "must have COMMIT");
    assert!(
        config.contains(":SFGW-INPUT - [0:0]"),
        "must declare custom input chain"
    );
    assert!(
        config.contains(":SFGW-FORWARD - [0:0]"),
        "must declare custom forward chain"
    );
    assert!(
        config.contains("-A INPUT -j SFGW-INPUT"),
        "must jump to custom input chain"
    );
    assert!(
        config.contains("-A FORWARD -j SFGW-FORWARD"),
        "must jump to custom forward chain"
    );
}

#[test]
fn ruleset_has_nat_table_structure() {
    let config = generate_ruleset(&[], &FirewallPolicy::default());
    assert!(config.contains("*nat"), "must have *nat table");
    assert!(
        config.contains(":SFGW-PREROUTING - [0:0]"),
        "must declare custom prerouting chain"
    );
    assert!(
        config.contains(":SFGW-POSTROUTING - [0:0]"),
        "must declare custom postrouting chain"
    );
}

#[test]
fn zone_ruleset_dmz_blocks_mgmt() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    assert!(
        config.contains("-i eth2 -o br-mgmt -j DROP"),
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
    assert!(config.contains("-p tcp --dport 8080 -j ACCEPT"));
}

/// Simulate the real UDM Pro config: only WAN, LAN, MGMT zones + DB default rules.
/// Print the full ruleset to verify rule ordering.
#[test]
fn debug_udm_ruleset_with_db_rules() {
    use crate::FirewallZone;

    let zones = vec![
        ZonePolicy {
            zone: FirewallZone::Wan,
            interfaces: vec!["eth4".to_string()],
            vlan_id: None,
        },
        ZonePolicy {
            zone: FirewallZone::Lan,
            interfaces: vec!["br-lan".to_string()],
            vlan_id: Some(10),
        },
        ZonePolicy {
            zone: FirewallZone::Mgmt,
            interfaces: vec!["br-mgmt".to_string()],
            vlan_id: Some(3000),
        },
    ];

    // Simulate DB default rules (subset — the ones that resolve with 3 zones)
    let rules = vec![
        FirewallRule {
            id: Some(1),
            chain: "forward".into(),
            priority: 50,
            detail: RuleDetail {
                action: Action::Accept,
                protocol: "any".into(),
                source: "iif:@mgmt_ifaces".into(),
                destination: "any".into(),
                port: None,
                comment: Some("MGMT to any".into()),
                vlan: None,
                rate_limit: None,
            },
            enabled: true,
        },
        FirewallRule {
            id: Some(2),
            chain: "forward".into(),
            priority: 100,
            detail: RuleDetail {
                action: Action::Accept,
                protocol: "any".into(),
                source: "iif:@lan_ifaces".into(),
                destination: "oif:@wan_ifaces".into(),
                port: None,
                comment: Some("LAN to WAN".into()),
                vlan: None,
                rate_limit: None,
            },
            enabled: true,
        },
        FirewallRule {
            id: Some(3),
            chain: "forward".into(),
            priority: 400,
            detail: RuleDetail {
                action: Action::Drop,
                protocol: "any".into(),
                source: "iif:@wan_ifaces".into(),
                destination: "any".into(),
                port: None,
                comment: Some("default deny inbound".into()),
                vlan: None,
                rate_limit: None,
            },
            enabled: true,
        },
        FirewallRule {
            id: Some(4),
            chain: "input".into(),
            priority: 31,
            detail: RuleDetail {
                action: Action::Accept,
                protocol: "tcp".into(),
                source: "iif:@mgmt_ifaces".into(),
                destination: "any".into(),
                port: Some("22".into()),
                comment: Some("SSH from MGMT".into()),
                vlan: None,
                rate_limit: None,
            },
            enabled: true,
        },
        FirewallRule {
            id: Some(6),
            chain: "input".into(),
            priority: 60,
            detail: RuleDetail {
                action: Action::Accept,
                protocol: "tcp".into(),
                source: "iif:@mgmt_ifaces".into(),
                destination: "any".into(),
                port: Some("443".into()),
                comment: Some("HTTPS from MGMT".into()),
                vlan: None,
                rate_limit: None,
            },
            enabled: true,
        },
        FirewallRule {
            id: Some(7),
            chain: "input".into(),
            priority: 900,
            detail: RuleDetail {
                action: Action::Drop,
                protocol: "any".into(),
                source: "iif:@wan_ifaces".into(),
                destination: "any".into(),
                port: None,
                comment: Some("drop all WAN input".into()),
                vlan: None,
                rate_limit: None,
            },
            enabled: true,
        },
    ];

    let config = generate_zone_ruleset(&zones, &rules, &FirewallPolicy::default(), &[]);

    // MUST have SSH accept on br-mgmt
    assert!(
        config.contains("-i br-mgmt") && config.contains("--dport 22") && config.contains("ACCEPT"),
        "MGMT SSH must be allowed"
    );
    // MUST have HTTPS accept on br-mgmt
    assert!(
        config.contains("-A SFGW-INPUT -i br-mgmt -p tcp --dport 443 -j ACCEPT"),
        "MGMT HTTPS must be allowed"
    );
}

// ── VLAN isolation tests (WAN-01, FW-01, FW-02) ──────────────────────

/// FW-02: VLAN 1 DROP rules appear on all WAN interfaces and br-void.
#[test]
fn test_vlan1_void_drop_rules() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);

    // eth0.1 and ppp0.1 are the WAN VLAN 1 sub-interfaces.
    assert!(
        config
            .contains("-A SFGW-INPUT -i eth0.1 -j DROP -m comment --comment \"VLAN 1 void DROP\""),
        "VLAN 1 DROP missing on eth0 INPUT"
    );
    assert!(
        config.contains(
            "-A SFGW-FORWARD -i eth0.1 -j DROP -m comment --comment \"VLAN 1 void DROP\""
        ),
        "VLAN 1 DROP missing on eth0 FORWARD"
    );
    assert!(
        config
            .contains("-A SFGW-INPUT -i ppp0.1 -j DROP -m comment --comment \"VLAN 1 void DROP\""),
        "VLAN 1 DROP missing on ppp0 INPUT"
    );
    assert!(
        config.contains(
            "-A SFGW-FORWARD -i ppp0.1 -j DROP -m comment --comment \"VLAN 1 void DROP\""
        ),
        "VLAN 1 DROP missing on ppp0 FORWARD"
    );

    // br-void defense-in-depth.
    assert!(
        config
            .contains("-A SFGW-INPUT -i br-void -j DROP -m comment --comment \"VLAN 1 void DROP\""),
        "VLAN 1 void DROP missing for br-void INPUT"
    );
    assert!(
        config.contains(
            "-A SFGW-FORWARD -i br-void -j DROP -m comment --comment \"VLAN 1 void DROP\""
        ),
        "VLAN 1 void DROP missing for br-void FORWARD"
    );
}

/// WAN-01: Internal VLAN IDs are DROPped on WAN interfaces.
#[test]
fn test_internal_vlans_blocked_on_wan() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);

    // VLAN 10 (LAN) must not appear on eth0 or ppp0.
    assert!(
        config.contains(
            "-A SFGW-INPUT -i eth0.10 -j DROP -m comment --comment \"no internal VLAN on WAN\""
        ),
        "LAN VLAN 10 not blocked on eth0 INPUT"
    );
    assert!(
        config.contains(
            "-A SFGW-FORWARD -i eth0.10 -j DROP -m comment --comment \"no internal VLAN on WAN\""
        ),
        "LAN VLAN 10 not blocked on eth0 FORWARD"
    );
    assert!(
        config.contains(
            "-A SFGW-INPUT -i ppp0.10 -j DROP -m comment --comment \"no internal VLAN on WAN\""
        ),
        "LAN VLAN 10 not blocked on ppp0 INPUT"
    );

    // VLAN 3000 (MGMT) must be blocked on WAN.
    assert!(
        config.contains(
            "-A SFGW-INPUT -i eth0.3000 -j DROP -m comment --comment \"no internal VLAN on WAN\""
        ),
        "MGMT VLAN 3000 not blocked on eth0"
    );

    // VLAN 3001 (GUEST) must be blocked on WAN.
    assert!(
        config.contains(
            "-A SFGW-INPUT -i eth0.3001 -j DROP -m comment --comment \"no internal VLAN on WAN\""
        ),
        "GUEST VLAN 3001 not blocked on eth0"
    );

    // VLAN 3002 (DMZ) must be blocked on WAN.
    assert!(
        config.contains(
            "-A SFGW-INPUT -i eth0.3002 -j DROP -m comment --comment \"no internal VLAN on WAN\""
        ),
        "DMZ VLAN 3002 not blocked on eth0"
    );
}

/// FW-01: LAN zone rules reference br-lan (VLAN 10 bridge), not any VLAN 1 interface.
#[test]
fn test_lan_zone_uses_vlan10_bridge() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);

    // LAN rules reference br-lan.
    assert!(
        config.contains("-i br-lan"),
        "LAN zone must reference br-lan"
    );

    // No VLAN 1 bridge reference in LAN rules.
    assert!(
        !config.contains("-i br-1 "),
        "LAN zone must NOT reference br-1 (VLAN 1 bridge)"
    );
    assert!(
        !config.contains("-i br-void ")
            || config.contains("-j DROP -m comment --comment \"VLAN 1 void DROP\""),
        "br-void may only appear in DROP rules"
    );

    // The VLAN 10 DHCP/DNS rules are on br-lan.
    assert!(
        config.contains("-A SFGW-INPUT -i br-lan -p udp --dport 67:68 -j ACCEPT"),
        "DHCP must be on br-lan"
    );
    assert!(
        config.contains("-A SFGW-INPUT -i br-lan -p tcp --dport 53 -j ACCEPT"),
        "DNS/TCP must be on br-lan"
    );
}

/// ZonePolicy.vlan_id is populated correctly for each zone type.
#[test]
fn test_zone_policy_has_vlan_id() {
    let zones = test_zones();

    let wan = zones
        .iter()
        .find(|z| z.zone == crate::FirewallZone::Wan)
        .unwrap();
    assert_eq!(wan.vlan_id, None, "WAN zone must have vlan_id: None");

    let lan = zones
        .iter()
        .find(|z| z.zone == crate::FirewallZone::Lan)
        .unwrap();
    assert_eq!(
        lan.vlan_id,
        Some(10),
        "LAN zone must have vlan_id: Some(10)"
    );

    let mgmt = zones
        .iter()
        .find(|z| z.zone == crate::FirewallZone::Mgmt)
        .unwrap();
    assert_eq!(
        mgmt.vlan_id,
        Some(3000),
        "MGMT zone must have vlan_id: Some(3000)"
    );

    let guest = zones
        .iter()
        .find(|z| z.zone == crate::FirewallZone::Guest)
        .unwrap();
    assert_eq!(
        guest.vlan_id,
        Some(3001),
        "GUEST zone must have vlan_id: Some(3001)"
    );

    let dmz = zones
        .iter()
        .find(|z| z.zone == crate::FirewallZone::Dmz)
        .unwrap();
    assert_eq!(
        dmz.vlan_id,
        Some(3002),
        "DMZ zone must have vlan_id: Some(3002)"
    );
}

// ── Issue fix tests ──────────────────────────────────────────────

/// Issue 1: User-defined rules MUST appear BEFORE zone catch-all DROPs.
/// Previously, user rules were emitted after each zone's catch-all DROP,
/// meaning they were silently ignored by iptables.
#[test]
fn user_rules_appear_before_zone_catchall_drops() {
    let rules = vec![FirewallRule {
        id: Some(1),
        chain: "input".to_string(),
        priority: 500,
        detail: RuleDetail {
            action: Action::Accept,
            protocol: "tcp".to_string(),
            source: "any".to_string(),
            destination: "any".to_string(),
            port: Some("9090".to_string()),
            comment: Some("custom service".to_string()),
            vlan: None,
            rate_limit: None,
        },
        enabled: true,
    }];
    let config = generate_zone_ruleset(&test_zones(), &rules, &FirewallPolicy::default(), &[]);

    let user_rule_pos = config
        .find("--dport 9090 -j ACCEPT")
        .expect("user rule must be present in output");
    let catchall_drop_pos = config
        .find("drop all WAN input")
        .expect("WAN catch-all DROP must be present");

    assert!(
        user_rule_pos < catchall_drop_pos,
        "user-defined rules must appear BEFORE zone catch-all DROPs.\n\
         User rule at byte {user_rule_pos}, catch-all DROP at byte {catchall_drop_pos}"
    );

    // Also verify all zone catch-all DROPs are after user rules.
    let lan_drop_pos = config
        .find("drop all other LAN input")
        .expect("LAN catch-all DROP must be present");
    assert!(
        user_rule_pos < lan_drop_pos,
        "user rule must appear before LAN catch-all DROP"
    );
}

/// Issue 1: Zone catch-all DROPs section header must exist and be last.
#[test]
fn zone_catchall_drops_section_exists() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);
    assert!(
        config.contains("Zone catch-all DROPs (must be last)"),
        "catch-all DROP section must have identifying comment"
    );
}

/// Issue 2: validate_no_lockout must NOT be bypassable via crafted comments.
/// A rule that DROPs SSH but has a comment containing "--dport 22 -j ACCEPT"
/// previously passed validation. Now it must fail.
#[test]
fn validate_no_lockout_rejects_comment_bypass() {
    // Craft a malicious ruleset: DROP SSH, but comment tricks the old validator.
    let config = r#"*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:SFGW-INPUT - [0:0]
-A INPUT -j SFGW-INPUT
-A SFGW-INPUT -i lo -j ACCEPT
-A SFGW-INPUT -p tcp --dport 22 -j DROP -m comment --comment "fake --dport 22 -j ACCEPT in comment"
COMMIT
"#;

    let result = validate_no_lockout(config);
    assert!(
        result.is_err(),
        "validate_no_lockout must reject a ruleset where the only SSH rule is DROP with a crafted comment"
    );
}

/// Issue 2: validate_no_lockout must PASS when a real SSH ACCEPT rule exists.
#[test]
fn validate_no_lockout_passes_real_ssh_accept() {
    let config = r#"*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:SFGW-INPUT - [0:0]
-A INPUT -j SFGW-INPUT
-A SFGW-INPUT -i lo -j ACCEPT
-A SFGW-INPUT -i br-mgmt -p tcp --dport 22 -j ACCEPT -m comment --comment "SSH on MGMT"
COMMIT
"#;

    let result = validate_no_lockout(config);
    assert!(
        result.is_ok(),
        "validate_no_lockout must pass when real SSH ACCEPT exists: {result:?}"
    );
}

/// Issue 2: validate_no_lockout must reject a ruleset with NO SSH rules at all.
#[test]
fn validate_no_lockout_rejects_no_ssh_rules() {
    let config = r#"*filter
:INPUT DROP [0:0]
:SFGW-INPUT - [0:0]
-A INPUT -j SFGW-INPUT
-A SFGW-INPUT -i lo -j ACCEPT
COMMIT
"#;

    let result = validate_no_lockout(config);
    assert!(
        result.is_err(),
        "validate_no_lockout must reject a ruleset with no SSH rules at all"
    );
}

/// Issue 3: Port forward ACCEPT rules must include WAN input interface restriction.
#[test]
fn port_forward_accept_restricted_to_wan_in_zone_mode() {
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

    // The ACCEPT rule in FORWARD chain must have -i <wan_iface> restriction.
    let accept_lines: Vec<&str> = config
        .lines()
        .filter(|l| l.contains("allow fwd:") && l.contains("-j ACCEPT"))
        .collect();

    assert!(
        !accept_lines.is_empty(),
        "port forward ACCEPT rules must exist"
    );

    for line in &accept_lines {
        assert!(
            line.contains("-i eth0") || line.contains("-i ppp0"),
            "port forward ACCEPT rule must be restricted to WAN interface: {line}"
        );
    }
}

/// Issue 3: Port forward with specific wan_interface uses that interface in ACCEPT.
#[test]
fn port_forward_accept_uses_specific_wan_interface() {
    let fwd = vec![PortForward {
        protocol: "tcp".to_string(),
        external_port: 443,
        internal_ip: "192.168.1.100".to_string(),
        internal_port: 443,
        comment: Some("HTTPS on ppp0 only".to_string()),
        enabled: true,
        wan_interface: Some("ppp0".to_string()),
    }];
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &fwd);

    let accept_lines: Vec<&str> = config
        .lines()
        .filter(|l| l.contains("allow fwd:") && l.contains("-j ACCEPT"))
        .collect();

    assert_eq!(
        accept_lines.len(),
        1,
        "specific wan_interface should produce exactly 1 ACCEPT rule, got: {accept_lines:?}"
    );
    assert!(
        accept_lines[0].contains("-i ppp0"),
        "ACCEPT rule should use ppp0: {}",
        accept_lines[0]
    );
    assert!(
        !accept_lines[0].contains("-i eth0"),
        "ACCEPT rule should NOT use eth0 when wan_interface is ppp0"
    );
}

/// Issue 3: Legacy mode (no zones) still generates ACCEPT without interface.
#[test]
fn port_forward_accept_legacy_no_interface() {
    let fwd = vec![PortForward {
        protocol: "tcp".to_string(),
        external_port: 8443,
        internal_ip: "192.168.1.100".to_string(),
        internal_port: 443,
        comment: None,
        enabled: true,
        wan_interface: None,
    }];
    let config = generate_ruleset_with_forwards(&[], &FirewallPolicy::default(), &fwd);

    let accept_line = config
        .lines()
        .find(|l| l.contains("allow fwd:") && l.contains("-j ACCEPT"))
        .expect("port forward ACCEPT rule must exist in legacy mode");

    // Legacy mode has no WAN interface info, so no -i restriction.
    assert!(
        !accept_line.contains("-i "),
        "legacy mode should not have -i restriction: {accept_line}"
    );
}

/// VLAN isolation rules appear BEFORE zone-specific rules in the generated ruleset.
#[test]
fn test_vlan_isolation_rules_appear_before_zone_rules() {
    let config = generate_zone_ruleset(&test_zones(), &[], &FirewallPolicy::default(), &[]);

    let void_drop_pos = config
        .find("VLAN 1 void DROP")
        .expect("VLAN 1 void DROP must be present");
    let wan_zone_rules_pos = config
        .find("WAN zone rules")
        .expect("WAN zone rules section must be present");

    assert!(
        void_drop_pos < wan_zone_rules_pos,
        "VLAN isolation rules must appear before WAN zone rules"
    );
}

// ── Custom zone tests ──────────────────────────────────────────────

fn iot_custom_zone() -> CustomZone {
    CustomZone {
        id: Some(1),
        name: "iot".to_string(),
        vlan_id: 40,
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
        description: "IoT devices".to_string(),
    }
}

fn vpn_custom_zone() -> CustomZone {
    CustomZone {
        id: Some(2),
        name: "vpn".to_string(),
        vlan_id: 50,
        policy_inbound: Action::Drop,
        policy_outbound: Action::Accept,
        policy_forward: Action::Drop,
        allowed_services: vec![AllowedService {
            protocol: "udp".to_string(),
            port: 53,
            description: Some("DNS".to_string()),
        }],
        description: "VPN clients".to_string(),
    }
}

fn zones_with_custom() -> Vec<ZonePolicy> {
    vec![
        ZonePolicy {
            zone: FirewallZone::Wan,
            interfaces: vec!["eth8".to_string()],
            vlan_id: None,
        },
        ZonePolicy {
            zone: FirewallZone::Lan,
            interfaces: vec!["br-lan".to_string()],
            vlan_id: Some(10),
        },
        ZonePolicy {
            zone: FirewallZone::Mgmt,
            interfaces: vec!["br-mgmt".to_string()],
            vlan_id: Some(99),
        },
        ZonePolicy {
            zone: FirewallZone::IoT,
            interfaces: vec!["br-iot".to_string()],
            vlan_id: Some(40),
        },
        ZonePolicy {
            zone: FirewallZone::Vpn,
            interfaces: vec!["br-vpn".to_string()],
            vlan_id: Some(50),
        },
    ]
}

#[test]
fn custom_zone_iot_blocks_management_ports() {
    let zones = zones_with_custom();
    let custom = vec![iot_custom_zone()];
    let config = generate_zone_ruleset_with_custom(
        &zones,
        &[],
        &FirewallPolicy::default(),
        &[],
        &custom,
    );

    // IoT zone must block SSH, HTTPS, HTTP, Inform to gateway.
    assert!(
        config.contains("-A SFGW-INPUT -i br-iot -p tcp --dport 22 -j DROP"),
        "IoT must block SSH: {config}"
    );
    assert!(
        config.contains("-A SFGW-INPUT -i br-iot -p tcp --dport 443 -j DROP"),
        "IoT must block HTTPS"
    );
    assert!(
        config.contains("-A SFGW-INPUT -i br-iot -p tcp --dport 80 -j DROP"),
        "IoT must block HTTP"
    );
    assert!(
        config.contains("-A SFGW-INPUT -i br-iot -p tcp --dport 8080 -j DROP"),
        "IoT must block Inform"
    );
}

#[test]
fn custom_zone_iot_allows_dns_dhcp() {
    let zones = zones_with_custom();
    let custom = vec![iot_custom_zone()];
    let config = generate_zone_ruleset_with_custom(
        &zones,
        &[],
        &FirewallPolicy::default(),
        &[],
        &custom,
    );

    assert!(
        config.contains("-A SFGW-INPUT -i br-iot -p udp --dport 53 -j ACCEPT"),
        "IoT must allow DNS"
    );
    assert!(
        config.contains("-A SFGW-INPUT -i br-iot -p udp --dport 67 -j ACCEPT"),
        "IoT must allow DHCP"
    );
}

#[test]
fn custom_zone_iot_allows_outbound_blocks_inter_vlan() {
    let zones = zones_with_custom();
    let custom = vec![iot_custom_zone()];
    let config = generate_zone_ruleset_with_custom(
        &zones,
        &[],
        &FirewallPolicy::default(),
        &[],
        &custom,
    );

    // IoT outbound (to WAN) = ACCEPT.
    assert!(
        config.contains("-A SFGW-FORWARD -i br-iot -o eth8 -j ACCEPT"),
        "IoT must allow outbound to WAN"
    );

    // IoT to MGMT = always DROP (security invariant).
    assert!(
        config.contains("-A SFGW-FORWARD -i br-iot -o br-mgmt -j DROP"),
        "IoT must block access to MGMT"
    );

    // IoT to LAN = DROP (forward policy is drop).
    assert!(
        config.contains("-A SFGW-FORWARD -i br-iot -o br-lan -j DROP"),
        "IoT must block access to LAN"
    );
}

#[test]
fn custom_zone_vpn_allows_lan_access() {
    let zones = zones_with_custom();
    let custom = vec![vpn_custom_zone()];
    let config = generate_zone_ruleset_with_custom(
        &zones,
        &[],
        &FirewallPolicy::default(),
        &[],
        &custom,
    );

    // VPN to LAN = ACCEPT (VPN-like zone gets LAN access).
    assert!(
        config.contains("-A SFGW-FORWARD -i br-vpn -o br-lan -j ACCEPT"),
        "VPN must allow access to LAN: {config}"
    );

    // VPN to MGMT = always DROP.
    assert!(
        config.contains("-A SFGW-FORWARD -i br-vpn -o br-mgmt -j DROP"),
        "VPN must block access to MGMT"
    );

    // VPN to WAN = ACCEPT (outbound policy).
    assert!(
        config.contains("-A SFGW-FORWARD -i br-vpn -o eth8 -j ACCEPT"),
        "VPN must allow outbound to WAN"
    );
}

#[test]
fn custom_zone_catchall_drop_present() {
    let zones = zones_with_custom();
    let custom = vec![iot_custom_zone()];
    let config = generate_zone_ruleset_with_custom(
        &zones,
        &[],
        &FirewallPolicy::default(),
        &[],
        &custom,
    );

    assert!(
        config.contains("-A SFGW-INPUT -i br-iot -j DROP"),
        "Custom zone must have catch-all DROP"
    );
}

#[test]
fn custom_zone_mgmt_blocked_regardless_of_policy() {
    // Even with forward=accept, MGMT must be blocked.
    let zones = zones_with_custom();
    let mut permissive = iot_custom_zone();
    permissive.policy_forward = Action::Accept;
    let custom = vec![permissive];
    let config = generate_zone_ruleset_with_custom(
        &zones,
        &[],
        &FirewallPolicy::default(),
        &[],
        &custom,
    );

    assert!(
        config.contains("-A SFGW-FORWARD -i br-iot -o br-mgmt -j DROP"),
        "MGMT must ALWAYS be blocked from custom zones, even with permissive forward policy"
    );
}
