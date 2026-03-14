use super::*;
use crate::{Action, FirewallPolicy, FirewallRule, RuleDetail};

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
        },
        ZonePolicy {
            zone: FirewallZone::Lan,
            interfaces: vec!["br-lan".to_string()],
        },
        ZonePolicy {
            zone: FirewallZone::Mgmt,
            interfaces: vec!["br-mgmt".to_string()],
        },
    ];

    // Simulate DB default rules (subset — the ones that resolve with 3 zones)
    let rules = vec![
        FirewallRule { id: Some(1), chain: "forward".into(), priority: 50,
            detail: RuleDetail { action: Action::Accept, protocol: "any".into(), source: "iif:@mgmt_ifaces".into(), destination: "any".into(), port: None, comment: Some("MGMT to any".into()), vlan: None, rate_limit: None }, enabled: true },
        FirewallRule { id: Some(2), chain: "forward".into(), priority: 100,
            detail: RuleDetail { action: Action::Accept, protocol: "any".into(), source: "iif:@lan_ifaces".into(), destination: "oif:@wan_ifaces".into(), port: None, comment: Some("LAN to WAN".into()), vlan: None, rate_limit: None }, enabled: true },
        FirewallRule { id: Some(3), chain: "forward".into(), priority: 400,
            detail: RuleDetail { action: Action::Drop, protocol: "any".into(), source: "iif:@wan_ifaces".into(), destination: "any".into(), port: None, comment: Some("default deny inbound".into()), vlan: None, rate_limit: None }, enabled: true },
        FirewallRule { id: Some(4), chain: "input".into(), priority: 31,
            detail: RuleDetail { action: Action::Accept, protocol: "tcp".into(), source: "iif:@mgmt_ifaces".into(), destination: "any".into(), port: Some("22".into()), comment: Some("SSH from MGMT".into()), vlan: None, rate_limit: None }, enabled: true },
        FirewallRule { id: Some(6), chain: "input".into(), priority: 60,
            detail: RuleDetail { action: Action::Accept, protocol: "tcp".into(), source: "iif:@mgmt_ifaces".into(), destination: "any".into(), port: Some("443".into()), comment: Some("HTTPS from MGMT".into()), vlan: None, rate_limit: None }, enabled: true },
        FirewallRule { id: Some(7), chain: "input".into(), priority: 900,
            detail: RuleDetail { action: Action::Drop, protocol: "any".into(), source: "iif:@wan_ifaces".into(), destination: "any".into(), port: None, comment: Some("drop all WAN input".into()), vlan: None, rate_limit: None }, enabled: true },
    ];

    let config = generate_zone_ruleset(&zones, &rules, &FirewallPolicy::default(), &[]);
    eprintln!("\n=== GENERATED UDM RULESET ===\n{config}\n=== END ===\n");

    // MUST have SSH accept on br-mgmt
    assert!(config.contains("-i br-mgmt") && config.contains("--dport 22") && config.contains("ACCEPT"),
        "MGMT SSH must be allowed");
    // MUST have HTTPS accept on br-mgmt
    assert!(config.contains("-A SFGW-INPUT -i br-mgmt -p tcp --dport 443 -j ACCEPT"),
        "MGMT HTTPS must be allowed");
}
