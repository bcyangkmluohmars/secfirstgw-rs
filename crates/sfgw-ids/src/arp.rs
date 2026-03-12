// SPDX-License-Identifier: AGPL-3.0-or-later

//! ARP Spoofing Detection
//!
//! Monitors ARP traffic via raw sockets (AF_PACKET) on all interfaces.
//!
//! Detects:
//! - Gratuitous ARP floods (rate > threshold per source MAC)
//! - IP/MAC binding changes (known IP suddenly has different MAC)
//! - Gateway impersonation (someone claims to be the gateway MAC/IP)
//! - ARP responses without prior request (unsolicited replies)
//! - Duplicate IP detection (two MACs claiming same IP)

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};
use chrono::Utc;
use nix::sys::socket::{self, AddressFamily, SockFlag, SockType};

use super::{IdsEvent, Severity};

/// ARP hardware type: Ethernet
const ARP_HW_ETHER: u16 = 1;
/// ARP protocol type: IPv4
const ARP_PROTO_IPV4: u16 = 0x0800;
/// ARP opcode: request
const ARP_OP_REQUEST: u16 = 1;
/// ARP opcode: reply
const ARP_OP_REPLY: u16 = 2;
/// Minimum ARP packet length (excluding Ethernet header)
const ARP_PACKET_LEN: usize = 28;
/// Ethernet header length
const ETH_HEADER_LEN: usize = 14;
/// EtherType ARP
const ETH_P_ARP: u16 = 0x0806;

/// Known IP-MAC binding from DHCP leases + static config
#[derive(Debug, Clone)]
pub struct ArpBinding {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub interface: String,
    pub vlan: Option<u16>,
    pub is_gateway: bool,
}

/// Parsed ARP packet fields
#[derive(Debug)]
struct ArpPacket {
    opcode: u16,
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    #[allow(dead_code)]
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
}

/// ARP monitor state per interface
pub struct ArpMonitor {
    /// Known bindings (from DHCP leases + static)
    bindings: Vec<ArpBinding>,
    /// Gratuitous ARP counter per MAC: (count, window_start)
    garp_counter: HashMap<[u8; 6], (u64, chrono::DateTime<Utc>)>,
    /// Max gratuitous ARPs per second before alert
    garp_threshold: u64,
    /// Recently seen ARP requests (target_ip -> timestamp) for unsolicited reply detection
    pending_requests: HashMap<Ipv4Addr, chrono::DateTime<Utc>>,
    /// IP -> MAC mapping for duplicate IP detection
    ip_mac_seen: HashMap<Ipv4Addr, [u8; 6]>,
}

impl ArpMonitor {
    pub fn new(garp_threshold: u64) -> Self {
        Self {
            bindings: Vec::new(),
            garp_counter: HashMap::new(),
            garp_threshold,
            pending_requests: HashMap::new(),
            ip_mac_seen: HashMap::new(),
        }
    }

    /// Process a raw ARP packet (Ethernet frame), return event if suspicious.
    ///
    /// `packet` is a full Ethernet frame starting with the 14-byte Ethernet header.
    pub fn process_arp_packet(
        &mut self,
        packet: &[u8],
        interface: &str,
    ) -> Result<Option<IdsEvent>> {
        let arp = match parse_arp_from_frame(packet) {
            Some(a) => a,
            None => return Ok(None),
        };

        let now = Utc::now();

        // Track ARP requests for unsolicited reply detection
        if arp.opcode == ARP_OP_REQUEST {
            self.pending_requests.insert(arp.target_ip, now);
            // Prune old entries (older than 5 seconds)
            self.pending_requests
                .retain(|_, ts| (now - *ts).num_seconds() < 5);
        }

        // --- Detection 1: Gratuitous ARP flood ---
        if is_gratuitous(&arp) {
            let entry = self
                .garp_counter
                .entry(arp.sender_mac)
                .or_insert((0, now));

            let elapsed = (now - entry.1).num_seconds().max(1) as u64;
            if elapsed > 10 {
                // Reset window
                *entry = (1, now);
            } else {
                entry.0 += 1;
            }

            if entry.0 > self.garp_threshold * elapsed.max(1) {
                return Ok(Some(IdsEvent {
                    timestamp: now,
                    severity: Severity::Warning,
                    detector: "arp",
                    source_mac: Some(format_mac(&arp.sender_mac)),
                    source_ip: Some(arp.sender_ip.to_string()),
                    interface: interface.to_string(),
                    vlan: None,
                    description: format!(
                        "Gratuitous ARP flood: {} sent {} GARPs in {}s (threshold: {}/s)",
                        format_mac(&arp.sender_mac),
                        entry.0,
                        elapsed,
                        self.garp_threshold
                    ),
                }));
            }
        }

        // --- Detection 2: Gateway impersonation ---
        for binding in &self.bindings {
            if binding.is_gateway
                && arp.sender_ip == binding.ip
                && arp.sender_mac != binding.mac
            {
                return Ok(Some(IdsEvent {
                    timestamp: now,
                    severity: Severity::Critical,
                    detector: "arp",
                    source_mac: Some(format_mac(&arp.sender_mac)),
                    source_ip: Some(arp.sender_ip.to_string()),
                    interface: interface.to_string(),
                    vlan: None,
                    description: format!(
                        "Gateway impersonation: {} claims gateway IP {} (real MAC: {})",
                        format_mac(&arp.sender_mac),
                        binding.ip,
                        format_mac(&binding.mac)
                    ),
                }));
            }
        }

        // --- Detection 3: IP/MAC binding change ---
        for binding in &self.bindings {
            if arp.sender_ip == binding.ip && arp.sender_mac != binding.mac {
                return Ok(Some(IdsEvent {
                    timestamp: now,
                    severity: Severity::Warning,
                    detector: "arp",
                    source_mac: Some(format_mac(&arp.sender_mac)),
                    source_ip: Some(arp.sender_ip.to_string()),
                    interface: interface.to_string(),
                    vlan: binding.vlan,
                    description: format!(
                        "ARP binding change: IP {} moved from {} to {}",
                        arp.sender_ip,
                        format_mac(&binding.mac),
                        format_mac(&arp.sender_mac)
                    ),
                }));
            }
        }

        // --- Detection 4: Unsolicited ARP reply ---
        if arp.opcode == ARP_OP_REPLY {
            if !self.pending_requests.contains_key(&arp.sender_ip) {
                return Ok(Some(IdsEvent {
                    timestamp: now,
                    severity: Severity::Warning,
                    detector: "arp",
                    source_mac: Some(format_mac(&arp.sender_mac)),
                    source_ip: Some(arp.sender_ip.to_string()),
                    interface: interface.to_string(),
                    vlan: None,
                    description: format!(
                        "Unsolicited ARP reply: {} ({}) sent reply without prior request",
                        format_mac(&arp.sender_mac),
                        arp.sender_ip
                    ),
                }));
            }
        }

        // --- Detection 5: Duplicate IP (two MACs claiming same IP) ---
        if let Some(prev_mac) = self.ip_mac_seen.get(&arp.sender_ip) {
            if *prev_mac != arp.sender_mac {
                let event = IdsEvent {
                    timestamp: now,
                    severity: Severity::Warning,
                    detector: "arp",
                    source_mac: Some(format_mac(&arp.sender_mac)),
                    source_ip: Some(arp.sender_ip.to_string()),
                    interface: interface.to_string(),
                    vlan: None,
                    description: format!(
                        "Duplicate IP: {} claimed by both {} and {}",
                        arp.sender_ip,
                        format_mac(prev_mac),
                        format_mac(&arp.sender_mac)
                    ),
                };
                self.ip_mac_seen.insert(arp.sender_ip, arp.sender_mac);
                return Ok(Some(event));
            }
        }
        self.ip_mac_seen.insert(arp.sender_ip, arp.sender_mac);

        Ok(None)
    }

    /// Update known bindings from DHCP lease database
    pub fn update_bindings(&mut self, bindings: Vec<ArpBinding>) {
        self.bindings = bindings;
    }
}

/// Parse ARP packet from a full Ethernet frame.
fn parse_arp_from_frame(frame: &[u8]) -> Option<ArpPacket> {
    if frame.len() < ETH_HEADER_LEN + ARP_PACKET_LEN {
        return None;
    }

    // Verify EtherType is ARP
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETH_P_ARP {
        return None;
    }

    let arp = &frame[ETH_HEADER_LEN..];
    parse_arp_raw(arp)
}

/// Parse the raw 28-byte ARP payload.
fn parse_arp_raw(data: &[u8]) -> Option<ArpPacket> {
    if data.len() < ARP_PACKET_LEN {
        return None;
    }

    let hw_type = u16::from_be_bytes([data[0], data[1]]);
    let proto_type = u16::from_be_bytes([data[2], data[3]]);
    let hw_len = data[4];
    let proto_len = data[5];

    // Only handle Ethernet + IPv4
    if hw_type != ARP_HW_ETHER || proto_type != ARP_PROTO_IPV4 || hw_len != 6 || proto_len != 4 {
        return None;
    }

    let opcode = u16::from_be_bytes([data[6], data[7]]);

    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&data[8..14]);

    let sender_ip = Ipv4Addr::new(data[14], data[15], data[16], data[17]);

    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&data[18..24]);

    let target_ip = Ipv4Addr::new(data[24], data[25], data[26], data[27]);

    Some(ArpPacket {
        opcode,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    })
}

/// Check if an ARP packet is gratuitous (sender IP == target IP).
fn is_gratuitous(arp: &ArpPacket) -> bool {
    arp.sender_ip == arp.target_ip
}

/// Format a MAC address as colon-separated hex.
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Open an AF_PACKET raw socket for ARP traffic.
fn open_arp_socket() -> Result<std::os::fd::OwnedFd> {
    use nix::sys::socket::SockProtocol;

    // ETH_P_ARP in network byte order
    let proto = SockProtocol::EthAll; // We filter by EtherType ourselves

    let fd = socket::socket(
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        Some(proto),
    )
    .context("failed to create AF_PACKET socket for ARP monitoring")?;

    Ok(fd)
}

/// Start passive ARP monitoring on all interfaces via AF_PACKET.
pub async fn start_monitor(
    db: sfgw_db::Db,
    event_tx: tokio::sync::mpsc::Sender<IdsEvent>,
) -> Result<()> {
    tracing::info!("ARP monitor starting");

    let fd = open_arp_socket()?;
    let raw_fd = fd.as_raw_fd();

    let mut monitor = ArpMonitor::new(10); // 10 GARPs/s threshold

    // Load initial bindings from DB
    if let Ok(bindings) = load_bindings_from_db(&db).await {
        monitor.update_bindings(bindings);
    }

    let mut buf = [0u8; 2048];
    loop {
        // Use tokio::task::spawn_blocking to avoid blocking the async runtime
        let n = tokio::task::spawn_blocking(move || {
            // Safety: raw_fd is valid for the lifetime of `fd` above
            // We use nix recv directly
            nix::sys::socket::recv(raw_fd, &mut buf, nix::sys::socket::MsgFlags::empty())
        })
        .await?;

        let n = match n {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("ARP socket recv error: {e}");
                continue;
            }
        };

        if n < ETH_HEADER_LEN + ARP_PACKET_LEN {
            continue;
        }

        // Check EtherType == ARP
        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
        if ethertype != ETH_P_ARP {
            continue;
        }

        match monitor.process_arp_packet(&buf[..n], "eth0") {
            Ok(Some(event)) => {
                if event_tx.send(event).await.is_err() {
                    tracing::warn!("ARP monitor: event channel closed");
                    break;
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::debug!("ARP packet parse error: {e}");
            }
        }
    }

    Ok(())
}

/// Load ARP bindings from the DHCP lease database.
async fn load_bindings_from_db(db: &sfgw_db::Db) -> Result<Vec<ArpBinding>> {
    let conn = db.lock().await;
    let mut stmt = conn.prepare(
        "SELECT mac, ip FROM devices WHERE ip IS NOT NULL AND adopted = 1",
    )?;
    let bindings = stmt
        .query_map([], |row| {
            let mac_str: String = row.get(0)?;
            let ip_str: String = row.get(1)?;
            Ok((mac_str, ip_str))
        })?
        .filter_map(|r| r.ok())
        .filter_map(|(mac_str, ip_str)| {
            let mac = parse_mac(&mac_str)?;
            let ip: Ipv4Addr = ip_str.parse().ok()?;
            Some(ArpBinding {
                ip,
                mac,
                interface: String::new(),
                vlan: None,
                is_gateway: false,
            })
        })
        .collect();
    Ok(bindings)
}

/// Parse a colon-separated MAC address string.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}
