// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests for sfgw-ids intrusion detection monitors.
//!
//! Tests cover ARP spoofing detection, DHCP rogue server detection,
//! DNS unauthorized server detection, VLAN hopping detection, and
//! the alert correlation engine (Collector).

use std::net::{IpAddr, Ipv4Addr};

use chrono::Utc;
use sfgw_ids::arp::{ArpBinding, ArpMonitor, format_mac};
use sfgw_ids::collector::Collector;
use sfgw_ids::dhcp::DhcpMonitor;
use sfgw_ids::dns::DnsMonitor;
use sfgw_ids::vlan::VlanMonitor;
use sfgw_ids::{IdsEvent, ResponseAction, Severity};

// ---------------------------------------------------------------------------
// Helper constants
// ---------------------------------------------------------------------------

const IFACE_ETH0: &str = "eth0";
const IFACE_ETH1: &str = "eth1";

/// A known gateway MAC.
const GW_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01];
/// A known client MAC.
const CLIENT_MAC_A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
/// A second client MAC.
const CLIENT_MAC_B: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x66];
/// An attacker MAC.
const ATTACKER_MAC: [u8; 6] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
/// Our DHCP server MAC.
const OUR_DHCP_MAC: [u8; 6] = [0x02, 0x42, 0xAC, 0x11, 0x00, 0x02];
/// Rogue DHCP server MAC.
const ROGUE_DHCP_MAC: [u8; 6] = [0xBA, 0xAD, 0xCA, 0xFE, 0x00, 0x01];

const GW_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
const CLIENT_IP_A: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);

/// Broadcast MAC.
const BROADCAST_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
/// Zero MAC (used in ARP requests for target).
const ZERO_MAC: [u8; 6] = [0x00; 6];

// ---------------------------------------------------------------------------
// Frame builder helpers
// ---------------------------------------------------------------------------

/// Build a raw Ethernet + ARP frame (42 bytes).
///
/// `opcode`: 1 = request, 2 = reply
fn build_arp_frame(
    eth_dst: &[u8; 6],
    eth_src: &[u8; 6],
    opcode: u16,
    sender_mac: &[u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: &[u8; 6],
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);

    // Ethernet header (14 bytes)
    frame.extend_from_slice(eth_dst); // dst MAC
    frame.extend_from_slice(eth_src); // src MAC
    frame.extend_from_slice(&0x0806u16.to_be_bytes()); // EtherType ARP

    // ARP payload (28 bytes)
    frame.extend_from_slice(&0x0001u16.to_be_bytes()); // hw type: Ethernet
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // proto type: IPv4
    frame.push(6); // hw addr len
    frame.push(4); // proto addr len
    frame.extend_from_slice(&opcode.to_be_bytes()); // opcode
    frame.extend_from_slice(sender_mac); // sender MAC
    frame.extend_from_slice(&sender_ip.octets()); // sender IP
    frame.extend_from_slice(target_mac); // target MAC
    frame.extend_from_slice(&target_ip.octets()); // target IP

    assert_eq!(frame.len(), 42);
    frame
}

/// Build a gratuitous ARP (sender IP == target IP, broadcast dest).
/// Uses opcode=1 (request) so it does not trigger the unsolicited reply detector
/// before the flood counter has a chance to exceed the threshold.
fn build_garp_frame(sender_mac: &[u8; 6], ip: Ipv4Addr) -> Vec<u8> {
    build_arp_frame(
        &BROADCAST_MAC,
        sender_mac,
        1, // request — gratuitous ARP announcements are commonly sent as requests
        sender_mac,
        ip,
        &ZERO_MAC,
        ip, // sender_ip == target_ip => gratuitous
    )
}

/// Build an 802.1Q-tagged Ethernet frame with a given VLAN and inner EtherType.
/// Returns: dst(6) + src(6) + 0x8100(2) + TCI(2) + inner_ethertype(2) + payload
fn build_vlan_frame(
    dst: &[u8; 6],
    src: &[u8; 6],
    vlan_id: u16,
    inner_ethertype: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(dst);
    frame.extend_from_slice(src);
    frame.extend_from_slice(&0x8100u16.to_be_bytes()); // 802.1Q
    let tci = vlan_id & 0x0FFF; // priority 0, DEI 0
    frame.extend_from_slice(&tci.to_be_bytes());
    frame.extend_from_slice(&inner_ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Build a double-tagged (QinQ) frame.
fn build_double_tagged_frame(
    dst: &[u8; 6],
    src: &[u8; 6],
    outer_vlan: u16,
    inner_vlan: u16,
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(dst);
    frame.extend_from_slice(src);
    // Outer tag
    frame.extend_from_slice(&0x8100u16.to_be_bytes());
    frame.extend_from_slice(&(outer_vlan & 0x0FFF).to_be_bytes());
    // Inner tag
    frame.extend_from_slice(&0x8100u16.to_be_bytes());
    frame.extend_from_slice(&(inner_vlan & 0x0FFF).to_be_bytes());
    // Some inner EtherType (IPv4) + minimal padding
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&[0u8; 46]); // pad to minimum
    frame
}

/// Build a DTP frame (multicast dest 01:00:0C:CC:CC:CC).
fn build_dtp_frame(src: &[u8; 6]) -> Vec<u8> {
    let dtp_dst: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC];
    let mut frame = Vec::new();
    frame.extend_from_slice(&dtp_dst);
    frame.extend_from_slice(src);
    frame.extend_from_slice(&0x2004u16.to_be_bytes()); // DTP SNAP EtherType
    frame.extend_from_slice(&[0u8; 32]); // DTP payload stub
    frame
}

/// Build a normal untagged Ethernet frame (not ARP, not 802.1Q).
fn build_plain_ethernet_frame(
    dst: &[u8; 6],
    src: &[u8; 6],
    ethertype: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(dst);
    frame.extend_from_slice(src);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Build a minimal valid DHCP frame (Ethernet + IPv4 + UDP + DHCP).
///
/// `msg_type`: 1=DISCOVER, 2=OFFER, 5=ACK
/// `server_mac`: placed in Ethernet src
/// `client_mac_chaddr`: placed in DHCP chaddr field
/// `server_ip`: placed in DHCP siaddr field and IPv4 src
/// `your_ip`: placed in DHCP yiaddr field
fn build_dhcp_frame(
    server_mac: &[u8; 6],
    client_mac_chaddr: &[u8; 6],
    server_ip: Ipv4Addr,
    your_ip: Ipv4Addr,
    msg_type: u8,
) -> Vec<u8> {
    let mut frame = Vec::new();

    // --- Ethernet header (14 bytes) ---
    frame.extend_from_slice(&BROADCAST_MAC); // dst (broadcast for DHCP)
    frame.extend_from_slice(server_mac); // src
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType IPv4

    // --- IPv4 header (20 bytes) ---
    let ip_start = frame.len();
    frame.push(0x45); // version 4, IHL 5 (20 bytes)
    frame.push(0x00); // DSCP/ECN
    // Total length: IP(20) + UDP(8) + DHCP(240) + options(4) = 272
    let ip_total_len: u16 = 20 + 8 + 240 + 4;
    frame.extend_from_slice(&ip_total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]); // identification
    frame.extend_from_slice(&[0x00, 0x00]); // flags + fragment offset
    frame.push(64); // TTL
    frame.push(17); // protocol: UDP
    frame.extend_from_slice(&[0x00, 0x00]); // checksum (zeroed, not validated in parser)
    frame.extend_from_slice(&server_ip.octets()); // src IP
    frame.extend_from_slice(&Ipv4Addr::BROADCAST.octets()); // dst IP
    assert_eq!(frame.len() - ip_start, 20);

    // --- UDP header (8 bytes) ---
    // For server->client messages (OFFER/ACK): src=67, dst=68
    // For client->server messages (DISCOVER): src=68, dst=67
    let (src_port, dst_port) = if msg_type == 1 {
        (68u16, 67u16) // client -> server
    } else {
        (67u16, 68u16) // server -> client
    };
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    let udp_len: u16 = 8 + 240 + 4;
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]); // checksum (zeroed)

    // --- DHCP payload (240 bytes fixed + options) ---
    let dhcp_start = frame.len();
    // op: 1=BOOTREQUEST, 2=BOOTREPLY
    frame.push(if msg_type == 1 { 1 } else { 2 });
    frame.push(1); // htype: Ethernet
    frame.push(6); // hlen: 6
    frame.push(0); // hops
    frame.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]); // xid
    frame.extend_from_slice(&[0x00, 0x00]); // secs
    frame.extend_from_slice(&[0x00, 0x00]); // flags
    frame.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets()); // ciaddr
    frame.extend_from_slice(&your_ip.octets()); // yiaddr
    frame.extend_from_slice(&server_ip.octets()); // siaddr
    frame.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets()); // giaddr

    // chaddr: 16 bytes (6 MAC + 10 padding)
    frame.extend_from_slice(client_mac_chaddr);
    frame.extend_from_slice(&[0u8; 10]);

    // sname: 64 bytes
    frame.extend_from_slice(&[0u8; 64]);
    // file: 128 bytes
    frame.extend_from_slice(&[0u8; 128]);

    // Magic cookie
    frame.extend_from_slice(&[99, 130, 83, 99]);

    assert_eq!(frame.len() - dhcp_start, 240);

    // DHCP options: option 53 (message type) + end
    frame.push(53); // option code
    frame.push(1); // length
    frame.push(msg_type); // value
    frame.push(255); // end option

    frame
}

/// Build a minimal DNS frame (Ethernet + IPv4 + UDP + DNS).
///
/// `is_response`: if true, sets QR bit in DNS flags
/// `src_ip` / `dst_ip`: IPv4 addresses for IP header
/// `query_name`: optional domain name to encode in the question section
fn build_dns_frame(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    is_response: bool,
    query_name: Option<&str>,
) -> Vec<u8> {
    // Build DNS payload first so we know its length
    let mut dns_payload = Vec::new();

    // DNS header (12 bytes)
    dns_payload.extend_from_slice(&[0x00, 0x01]); // Transaction ID
    let flags: u16 = if is_response { 0x8000 } else { 0x0100 }; // QR bit + RD
    dns_payload.extend_from_slice(&flags.to_be_bytes());
    let qdcount: u16 = if query_name.is_some() { 1 } else { 0 };
    dns_payload.extend_from_slice(&qdcount.to_be_bytes()); // QDCOUNT
    dns_payload.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    dns_payload.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    dns_payload.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    // Question section
    if let Some(name) = query_name {
        for label in name.split('.') {
            dns_payload.push(label.len() as u8);
            dns_payload.extend_from_slice(label.as_bytes());
        }
        dns_payload.push(0); // root label
        dns_payload.extend_from_slice(&[0x00, 0x01]); // QTYPE: A
        dns_payload.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN
    }

    let mut frame = Vec::new();

    // --- Ethernet header ---
    frame.extend_from_slice(dst_mac);
    frame.extend_from_slice(src_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    // --- IPv4 header (20 bytes) ---
    let ip_total_len: u16 = 20 + 8 + dns_payload.len() as u16;
    frame.push(0x45); // version + IHL
    frame.push(0x00);
    frame.extend_from_slice(&ip_total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]); // identification
    frame.extend_from_slice(&[0x00, 0x00]); // flags
    frame.push(64); // TTL
    frame.push(17); // UDP
    frame.extend_from_slice(&[0x00, 0x00]); // checksum
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());

    // --- UDP header (8 bytes) ---
    let (src_port, dst_port) = if is_response {
        (53u16, 12345u16) // response from DNS server
    } else {
        (12345u16, 53u16) // query to DNS server
    };
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    let udp_len: u16 = 8 + dns_payload.len() as u16;
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]); // checksum

    // --- DNS payload ---
    frame.extend_from_slice(&dns_payload);

    frame
}

/// Create a test IdsEvent with the given parameters.
fn make_event(
    detector: &'static str,
    severity: Severity,
    interface: &str,
    mac: Option<&str>,
    ip: Option<&str>,
) -> IdsEvent {
    IdsEvent {
        timestamp: Utc::now(),
        severity,
        detector,
        source_mac: mac.map(String::from),
        source_ip: ip.map(String::from),
        interface: interface.to_string(),
        vlan: None,
        description: format!("Test event from {} on {}", detector, interface),
    }
}

// ===========================================================================
// ARP Spoofing Detection Tests
// ===========================================================================

/// Test 1: Normal ARP request produces no event.
#[test]
fn arp_normal_request_no_event() {
    let mut monitor = ArpMonitor::new(10);

    // ARP Request: "Who has 192.168.1.1? Tell 192.168.1.100"
    let frame = build_arp_frame(
        &BROADCAST_MAC,
        &CLIENT_MAC_A,
        1, // request
        &CLIENT_MAC_A,
        CLIENT_IP_A,
        &ZERO_MAC,
        GW_IP,
    );

    let result = monitor
        .process_arp_packet(&frame, IFACE_ETH0)
        .expect("process_arp_packet should not error");

    assert!(
        result.is_none(),
        "Normal ARP request should not trigger an event"
    );
}

/// Test 2: Normal ARP reply (after a request for that IP) produces no event.
#[test]
fn arp_normal_reply_after_request_no_event() {
    let mut monitor = ArpMonitor::new(10);

    // First send a request for the gateway IP so it is tracked as pending
    let request = build_arp_frame(
        &BROADCAST_MAC,
        &CLIENT_MAC_A,
        1, // request
        &CLIENT_MAC_A,
        CLIENT_IP_A,
        &ZERO_MAC,
        GW_IP,
    );
    let _ = monitor.process_arp_packet(&request, IFACE_ETH0);

    // Now send a reply from the gateway (IP matches pending request)
    let reply = build_arp_frame(
        &CLIENT_MAC_A,
        &GW_MAC,
        2, // reply
        &GW_MAC,
        GW_IP,
        &CLIENT_MAC_A,
        CLIENT_IP_A,
    );

    let result = monitor
        .process_arp_packet(&reply, IFACE_ETH0)
        .expect("process_arp_packet should not error");

    assert!(
        result.is_none(),
        "ARP reply after a matching request should not trigger an event"
    );
}

/// Test 3: Gateway impersonation — ARP from wrong MAC claiming gateway IP.
#[test]
fn arp_gateway_impersonation_critical_event() {
    let mut monitor = ArpMonitor::new(10);

    // Register gateway binding
    monitor.update_bindings(vec![ArpBinding {
        ip: GW_IP,
        mac: GW_MAC,
        interface: IFACE_ETH0.to_string(),
        vlan: None,
        is_gateway: true,
    }]);

    // Attacker sends ARP reply claiming to be the gateway
    let frame = build_arp_frame(
        &BROADCAST_MAC,
        &ATTACKER_MAC,
        2, // reply
        &ATTACKER_MAC,
        GW_IP, // claims gateway IP
        &CLIENT_MAC_A,
        CLIENT_IP_A,
    );

    let result = monitor
        .process_arp_packet(&frame, IFACE_ETH0)
        .expect("process_arp_packet should not error");

    let event = result.expect("Gateway impersonation should produce an event");
    assert_eq!(event.severity, Severity::Critical);
    assert_eq!(event.detector, "arp");
    assert!(
        event.description.contains("Gateway impersonation"),
        "Description should mention gateway impersonation, got: {}",
        event.description
    );
    assert_eq!(
        event.source_mac.as_deref(),
        Some(&*format_mac(&ATTACKER_MAC))
    );
}

/// Test 4: IP/MAC binding change detected.
#[test]
fn arp_binding_change_warning() {
    let mut monitor = ArpMonitor::new(10);

    // Register a non-gateway binding for CLIENT_IP_A -> CLIENT_MAC_A
    monitor.update_bindings(vec![ArpBinding {
        ip: CLIENT_IP_A,
        mac: CLIENT_MAC_A,
        interface: IFACE_ETH0.to_string(),
        vlan: Some(10),
        is_gateway: false,
    }]);

    // A different MAC claims the same IP
    let frame = build_arp_frame(
        &BROADCAST_MAC,
        &CLIENT_MAC_B,
        2,
        &CLIENT_MAC_B,
        CLIENT_IP_A,
        &ZERO_MAC,
        GW_IP,
    );

    // Need a pending request so the unsolicited reply check doesn't fire first
    // Actually, binding change check runs before unsolicited reply check in the code
    let result = monitor
        .process_arp_packet(&frame, IFACE_ETH0)
        .expect("should not error");

    let event = result.expect("Binding change should produce an event");
    assert_eq!(event.severity, Severity::Warning);
    assert!(
        event.description.contains("binding change"),
        "Description should mention binding change, got: {}",
        event.description
    );
    // Should include the VLAN from the binding
    assert_eq!(event.vlan, Some(10));
}

/// Test 5: Gratuitous ARP flood detection (above threshold).
#[test]
fn arp_garp_flood_warning() {
    let mut monitor = ArpMonitor::new(2); // Low threshold: 2 GARPs/s

    let ip = Ipv4Addr::new(192, 168, 1, 50);

    // Send enough gratuitous ARPs to exceed the threshold.
    // Threshold check: entry.0 > garp_threshold * elapsed.max(1)
    // With elapsed ~= 1s, need > 2*1 = 2, so need 3 GARPs.
    let mut event = None;
    for _ in 0..5 {
        let frame = build_garp_frame(&ATTACKER_MAC, ip);
        let result = monitor
            .process_arp_packet(&frame, IFACE_ETH0)
            .expect("should not error");
        if result.is_some() {
            event = result;
            break;
        }
    }

    let event = event.expect("GARP flood should produce a warning event");
    assert_eq!(event.severity, Severity::Warning);
    assert!(
        event.description.contains("Gratuitous ARP flood"),
        "Description should mention GARP flood, got: {}",
        event.description
    );
}

/// Test 6: Unsolicited ARP reply (no prior request) triggers a warning.
#[test]
fn arp_unsolicited_reply_warning() {
    let mut monitor = ArpMonitor::new(10);

    let sender_ip = Ipv4Addr::new(10, 0, 0, 50);

    // Send a reply without any prior request for sender_ip
    let frame = build_arp_frame(
        &CLIENT_MAC_A,
        &ATTACKER_MAC,
        2, // reply
        &ATTACKER_MAC,
        sender_ip,
        &CLIENT_MAC_A,
        CLIENT_IP_A,
    );

    let result = monitor
        .process_arp_packet(&frame, IFACE_ETH0)
        .expect("should not error");

    let event = result.expect("Unsolicited reply should produce an event");
    assert_eq!(event.severity, Severity::Warning);
    assert!(
        event.description.contains("Unsolicited ARP reply"),
        "Description should mention unsolicited, got: {}",
        event.description
    );
}

/// Test 7: Duplicate IP detection — two different MACs claim the same IP.
#[test]
fn arp_duplicate_ip_warning() {
    let mut monitor = ArpMonitor::new(10);

    let shared_ip = Ipv4Addr::new(10, 0, 0, 99);

    // First ARP request from MAC A for shared_ip (also registers it as pending)
    let frame_a = build_arp_frame(
        &BROADCAST_MAC,
        &CLIENT_MAC_A,
        1, // request
        &CLIENT_MAC_A,
        shared_ip,
        &ZERO_MAC,
        GW_IP,
    );
    let result_a = monitor
        .process_arp_packet(&frame_a, IFACE_ETH0)
        .expect("should not error");
    assert!(result_a.is_none(), "First ARP from MAC A should be fine");

    // Second ARP request from MAC B for the same shared_ip
    let frame_b = build_arp_frame(
        &BROADCAST_MAC,
        &CLIENT_MAC_B,
        1, // request
        &CLIENT_MAC_B,
        shared_ip,
        &ZERO_MAC,
        GW_IP,
    );
    let result_b = monitor
        .process_arp_packet(&frame_b, IFACE_ETH0)
        .expect("should not error");

    let event = result_b.expect("Duplicate IP should produce an event");
    assert_eq!(event.severity, Severity::Warning);
    assert!(
        event.description.contains("Duplicate IP"),
        "Description should mention duplicate IP, got: {}",
        event.description
    );
}

// ===========================================================================
// DHCP Detection Tests
// ===========================================================================

/// Test 8: Rogue DHCP server detection — OFFER from unknown MAC.
#[test]
fn dhcp_rogue_server_offer_critical() {
    let mut monitor = DhcpMonitor::new(vec![OUR_DHCP_MAC], 50);

    let rogue_ip = Ipv4Addr::new(192, 168, 1, 254);
    let offered_ip = Ipv4Addr::new(192, 168, 1, 200);

    // DHCP OFFER from a rogue server
    let frame = build_dhcp_frame(
        &ROGUE_DHCP_MAC,
        &CLIENT_MAC_A,
        rogue_ip,
        offered_ip,
        2, // OFFER
    );

    let result = monitor
        .process_dhcp_packet(&frame, IFACE_ETH0)
        .expect("should not error");

    let event = result.expect("Rogue DHCP OFFER should produce an event");
    assert_eq!(event.severity, Severity::Critical);
    assert_eq!(event.detector, "dhcp");
    assert!(
        event.description.contains("Rogue DHCP server"),
        "Description should mention rogue server, got: {}",
        event.description
    );
    assert!(
        event.description.contains("OFFER"),
        "Description should mention OFFER, got: {}",
        event.description
    );
}

/// Test 9: Valid DHCP ACK from our server produces no event.
#[test]
fn dhcp_valid_ack_no_event() {
    let mut monitor = DhcpMonitor::new(vec![OUR_DHCP_MAC], 50);

    let our_ip = Ipv4Addr::new(192, 168, 1, 1);
    let assigned_ip = Ipv4Addr::new(192, 168, 1, 100);

    // DHCP ACK from our server
    let frame = build_dhcp_frame(
        &OUR_DHCP_MAC,
        &CLIENT_MAC_A,
        our_ip,
        assigned_ip,
        5, // ACK
    );

    let result = monitor
        .process_dhcp_packet(&frame, IFACE_ETH0)
        .expect("should not error");

    assert!(
        result.is_none(),
        "Valid DHCP ACK from our server should not trigger an event"
    );
}

// ===========================================================================
// VLAN Hopping Detection Tests
// ===========================================================================

/// Test 10: DTP packet detection.
#[test]
fn vlan_dtp_packet_critical() {
    let mut monitor = VlanMonitor::new();

    let frame = build_dtp_frame(&ATTACKER_MAC);

    let result = monitor
        .process_frame(&frame, IFACE_ETH0)
        .expect("should not error");

    let event = result.expect("DTP packet should produce a critical event");
    assert_eq!(event.severity, Severity::Critical);
    assert_eq!(event.detector, "vlan");
    assert!(
        event.description.contains("DTP"),
        "Description should mention DTP, got: {}",
        event.description
    );
}

/// Test 11: 802.1Q double-tagging detection.
#[test]
fn vlan_double_tagging_critical() {
    let mut monitor = VlanMonitor::new();

    let frame = build_double_tagged_frame(&BROADCAST_MAC, &ATTACKER_MAC, 10, 20);

    let result = monitor
        .process_frame(&frame, IFACE_ETH0)
        .expect("should not error");

    let event = result.expect("Double-tagged frame should produce a critical event");
    assert_eq!(event.severity, Severity::Critical);
    assert_eq!(event.detector, "vlan");
    assert!(
        event.description.contains("double-tagging"),
        "Description should mention double-tagging, got: {}",
        event.description
    );
    assert_eq!(event.vlan, Some(10)); // outer VLAN
}

/// Test 12: VLAN out of configured range.
#[test]
fn vlan_out_of_range_warning() {
    let mut monitor = VlanMonitor::new();
    monitor.set_vlan_range(10, 100);

    // Frame with VLAN 200 (outside 10-100)
    let frame = build_vlan_frame(
        &BROADCAST_MAC,
        &CLIENT_MAC_A,
        200,
        0x0800, // inner EtherType IPv4
        &[0u8; 46],
    );

    let result = monitor
        .process_frame(&frame, IFACE_ETH0)
        .expect("should not error");

    let event = result.expect("VLAN out of range should produce a warning");
    assert_eq!(event.severity, Severity::Warning);
    assert!(
        event.description.contains("out of range"),
        "Description should mention out of range, got: {}",
        event.description
    );
    assert_eq!(event.vlan, Some(200));
}

/// Test 13: Unexpected VLAN on access port.
#[test]
fn vlan_unexpected_on_access_port_warning() {
    let mut monitor = VlanMonitor::new();
    monitor.set_vlan_range(1, 4094);
    // eth0 is an access port that should only see VLAN 10
    monitor.set_port_vlans(IFACE_ETH0.to_string(), vec![10]);

    // Frame with VLAN 20 on eth0 (not allowed)
    let frame = build_vlan_frame(&BROADCAST_MAC, &CLIENT_MAC_A, 20, 0x0800, &[0u8; 46]);

    let result = monitor
        .process_frame(&frame, IFACE_ETH0)
        .expect("should not error");

    let event = result.expect("Unexpected VLAN should produce a warning");
    assert_eq!(event.severity, Severity::Warning);
    assert!(
        event.description.contains("Unexpected VLAN"),
        "Description should mention unexpected VLAN, got: {}",
        event.description
    );
}

/// Test 14: MAC on wrong VLAN.
#[test]
fn vlan_mac_on_wrong_vlan_warning() {
    let mut monitor = VlanMonitor::new();
    monitor.set_vlan_range(1, 4094);

    // First frame: CLIENT_MAC_A on VLAN 10 (learns it)
    let frame1 = build_vlan_frame(&BROADCAST_MAC, &CLIENT_MAC_A, 10, 0x0800, &[0u8; 46]);
    let result1 = monitor
        .process_frame(&frame1, IFACE_ETH0)
        .expect("should not error");
    assert!(
        result1.is_none(),
        "First frame should be learned without event"
    );

    // Second frame: same MAC on VLAN 20 (wrong VLAN)
    let frame2 = build_vlan_frame(&BROADCAST_MAC, &CLIENT_MAC_A, 20, 0x0800, &[0u8; 46]);
    let result2 = monitor
        .process_frame(&frame2, IFACE_ETH0)
        .expect("should not error");

    let event = result2.expect("MAC on wrong VLAN should produce a warning");
    assert_eq!(event.severity, Severity::Warning);
    assert!(
        event.description.contains("wrong VLAN"),
        "Description should mention wrong VLAN, got: {}",
        event.description
    );
}

/// Test 15: Normal untagged frame produces no event.
#[test]
fn vlan_normal_untagged_no_event() {
    let mut monitor = VlanMonitor::new();

    // Plain IPv4 frame (EtherType 0x0800, no 802.1Q tag)
    let frame = build_plain_ethernet_frame(
        &BROADCAST_MAC,
        &CLIENT_MAC_A,
        0x0800, // IPv4, not 802.1Q
        &[0u8; 46],
    );

    let result = monitor
        .process_frame(&frame, IFACE_ETH0)
        .expect("should not error");

    assert!(
        result.is_none(),
        "Normal untagged frame should not trigger an event"
    );
}

// ===========================================================================
// DNS Detection Tests
// ===========================================================================

/// Test: Unauthorized DNS server response detection.
#[test]
fn dns_unauthorized_server_critical() {
    let authorized_ip = Ipv4Addr::new(192, 168, 1, 1);
    let rogue_ip = Ipv4Addr::new(10, 99, 99, 99);
    let client_ip = Ipv4Addr::new(192, 168, 1, 100);

    let mut monitor = DnsMonitor::new(vec![IpAddr::V4(authorized_ip)]);

    // DNS response from unauthorized server
    let frame = build_dns_frame(
        &ATTACKER_MAC,
        &CLIENT_MAC_A,
        rogue_ip,  // src: rogue DNS server
        client_ip, // dst: client
        true,      // is_response
        Some("example.com"),
    );

    let result = monitor
        .process_dns_packet(&frame, IFACE_ETH0)
        .expect("should not error");

    let event = result.expect("Unauthorized DNS response should produce an event");
    assert_eq!(event.severity, Severity::Critical);
    assert_eq!(event.detector, "dns");
    assert!(
        event.description.contains("Unauthorized DNS response"),
        "Description should mention unauthorized, got: {}",
        event.description
    );
}

/// Test: Authorized DNS server response produces no event.
#[test]
fn dns_authorized_server_no_event() {
    let authorized_ip = Ipv4Addr::new(192, 168, 1, 1);
    let client_ip = Ipv4Addr::new(192, 168, 1, 100);

    let mut monitor = DnsMonitor::new(vec![IpAddr::V4(authorized_ip)]);

    // DNS response from authorized server
    let frame = build_dns_frame(
        &GW_MAC,
        &CLIENT_MAC_A,
        authorized_ip, // src: our DNS server
        client_ip,     // dst: client
        true,          // is_response
        Some("example.com"),
    );

    let result = monitor
        .process_dns_packet(&frame, IFACE_ETH0)
        .expect("should not error");

    assert!(
        result.is_none(),
        "Authorized DNS response should not trigger an event"
    );
}

// ===========================================================================
// Alert Correlation (Collector) Tests
// ===========================================================================

/// Test 16: Same MAC on multiple interfaces triggers BlockMac.
#[test]
fn collector_same_mac_multiple_interfaces_block() {
    let mut collector = Collector::new(60);
    let mac_str = format_mac(&ATTACKER_MAC);

    // Event from eth0
    let event1 = make_event("arp", Severity::Warning, IFACE_ETH0, Some(&mac_str), None);
    let _ = collector.ingest(event1).expect("ingest should not error");

    // Event from eth1 with the same MAC
    let event2 = make_event("arp", Severity::Warning, IFACE_ETH1, Some(&mac_str), None);
    let result = collector.ingest(event2).expect("ingest should not error");

    let action = result.expect("Same MAC on multiple interfaces should trigger a response");
    match action {
        ResponseAction::BlockMac {
            ref mac,
            duration_secs,
        } => {
            assert_eq!(mac, &mac_str);
            assert_eq!(duration_secs, 600);
        }
        other => panic!("Expected BlockMac action, got: {:?}", other),
    }
}

/// Test 17: Multiple warnings from different detectors for same MAC triggers IsolatePort.
#[test]
fn collector_multi_detector_warnings_isolate() {
    let mut collector = Collector::new(60);
    let mac_str = format_mac(&CLIENT_MAC_A);

    // Warning from ARP detector on eth0
    let event1 = make_event("arp", Severity::Warning, IFACE_ETH0, Some(&mac_str), None);
    let _ = collector.ingest(event1).expect("ingest should not error");

    // Warning from VLAN detector on eth0 (same interface, different detector)
    let event2 = make_event("vlan", Severity::Warning, IFACE_ETH0, Some(&mac_str), None);
    let result = collector.ingest(event2).expect("ingest should not error");

    let action = result.expect("Warnings from different detectors should trigger escalation");
    match action {
        ResponseAction::IsolatePort {
            ref interface,
            ref mac,
        } => {
            assert_eq!(interface, IFACE_ETH0);
            assert_eq!(mac, &mac_str);
        }
        other => panic!("Expected IsolatePort action, got: {:?}", other),
    }
}

/// Test 18: ARP + DNS events from same IP triggers RateLimit.
#[test]
fn collector_arp_dns_same_ip_ratelimit() {
    let mut collector = Collector::new(60);
    let ip_str = "192.168.1.50";

    // ARP event with a source IP
    let event1 = make_event("arp", Severity::Warning, IFACE_ETH0, None, Some(ip_str));
    let _ = collector.ingest(event1).expect("ingest should not error");

    // DNS event with the same source IP
    let event2 = make_event("dns", Severity::Warning, IFACE_ETH0, None, Some(ip_str));
    let result = collector.ingest(event2).expect("ingest should not error");

    let action = result.expect("ARP + DNS from same IP should trigger RateLimit");
    match action {
        ResponseAction::RateLimit { ref ip, pps } => {
            assert_eq!(ip, ip_str);
            assert_eq!(pps, 10);
        }
        other => panic!("Expected RateLimit action, got: {:?}", other),
    }
}

/// Test 19: Timeline returns events in chronological order.
#[test]
fn collector_timeline_ordering() {
    let mut collector = Collector::new(60);

    let event1 = make_event("arp", Severity::Info, IFACE_ETH0, None, Some("10.0.0.1"));
    let event2 = make_event("dns", Severity::Warning, IFACE_ETH0, None, Some("10.0.0.2"));
    let event3 = make_event(
        "vlan",
        Severity::Critical,
        IFACE_ETH0,
        None,
        Some("10.0.0.3"),
    );

    let _ = collector.ingest(event1).expect("ingest should not error");
    let _ = collector.ingest(event2).expect("ingest should not error");
    let _ = collector.ingest(event3).expect("ingest should not error");

    let timeline = collector.timeline(10);
    assert_eq!(timeline.len(), 3);

    // Events should be in insertion (chronological) order
    assert_eq!(timeline[0].detector, "arp");
    assert_eq!(timeline[1].detector, "dns");
    assert_eq!(timeline[2].detector, "vlan");

    // Timestamps should be non-decreasing
    assert!(timeline[0].timestamp <= timeline[1].timestamp);
    assert!(timeline[1].timestamp <= timeline[2].timestamp);
}

/// Test: Timeline with last_n less than total events returns the tail.
#[test]
fn collector_timeline_last_n() {
    let mut collector = Collector::new(60);

    for i in 0..5 {
        let event = make_event(
            "arp",
            Severity::Info,
            IFACE_ETH0,
            None,
            Some(&format!("10.0.0.{}", i)),
        );
        let _ = collector.ingest(event).expect("ingest should not error");
    }

    let timeline = collector.timeline(2);
    assert_eq!(timeline.len(), 2);
    // Should be the last 2 events
    assert_eq!(timeline[0].source_ip.as_deref(), Some("10.0.0.3"));
    assert_eq!(timeline[1].source_ip.as_deref(), Some("10.0.0.4"));
}

/// Test 20: Single event on one interface returns no escalation.
#[test]
fn collector_single_event_no_escalation() {
    let mut collector = Collector::new(60);

    let event = make_event(
        "arp",
        Severity::Warning,
        IFACE_ETH0,
        Some(&format_mac(&CLIENT_MAC_A)),
        Some("192.168.1.100"),
    );

    let result = collector.ingest(event).expect("ingest should not error");
    assert!(
        result.is_none(),
        "A single event should not trigger escalation"
    );
}

/// Test: Correlate method detects multi-interface MAC presence.
#[test]
fn collector_correlate_multi_interface() {
    let mut collector = Collector::new(60);
    let mac_str = format_mac(&ATTACKER_MAC);

    let event1 = make_event("arp", Severity::Warning, IFACE_ETH0, Some(&mac_str), None);
    let event2 = make_event("arp", Severity::Warning, IFACE_ETH1, Some(&mac_str), None);

    // Ingest both (the second will trigger BlockMac via ingest, but correlate
    // should also find it)
    let _ = collector.ingest(event1).expect("ingest should not error");
    let _ = collector.ingest(event2).expect("ingest should not error");

    let actions = collector.correlate();
    assert!(
        !actions.is_empty(),
        "correlate() should return actions for multi-interface MAC"
    );

    let has_block = actions
        .iter()
        .any(|a| matches!(a, ResponseAction::BlockMac { mac, .. } if mac == &mac_str));
    assert!(
        has_block,
        "correlate() should include BlockMac for the attacker MAC"
    );
}

/// Test: format_mac produces the expected colon-separated hex string.
#[test]
fn format_mac_correctness() {
    let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    assert_eq!(format_mac(&mac), "aa:bb:cc:dd:ee:ff");

    let zero = [0x00; 6];
    assert_eq!(format_mac(&zero), "00:00:00:00:00:00");
}
