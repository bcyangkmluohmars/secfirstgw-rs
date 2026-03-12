// SPDX-License-Identifier: AGPL-3.0-or-later

//! DHCP Snooping / Spoofing Detection
//!
//! We ARE the DHCP server — any other DHCP Offer on the network is rogue.
//!
//! Detects:
//! - Rogue DHCP servers (DHCP Offer from unknown source)
//! - DHCP starvation attacks (excessive DHCP Discover from spoofed MACs)
//! - DHCP spoofing (forged ACK/NAK from unauthorized server)
//!
//! Builds a trusted binding table from valid DHCP ACKs for ARP correlation.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};
use chrono::Utc;

use super::arp::{format_mac, ArpBinding};
use super::{IdsEvent, Severity};

/// DHCP message types (option 53)
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_ACK: u8 = 5;

/// DHCP magic cookie
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Ethernet header length
const ETH_HEADER_LEN: usize = 14;
/// Minimum IPv4 header length
const IP_HEADER_LEN: usize = 20;
/// UDP header length
const UDP_HEADER_LEN: usize = 8;
/// Minimum DHCP payload (up to magic cookie + 1 option byte)
const DHCP_MIN_LEN: usize = 240;

/// UDP port for DHCP server
const DHCP_SERVER_PORT: u16 = 67;
/// UDP port for DHCP client
const DHCP_CLIENT_PORT: u16 = 68;

/// EtherType IPv4
const ETH_P_IP: u16 = 0x0800;

/// A DHCP binding learned from a valid DHCP ACK.
#[derive(Debug, Clone)]
pub struct DhcpBinding {
    pub client_mac: [u8; 6],
    pub assigned_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub timestamp: chrono::DateTime<Utc>,
}

pub struct DhcpMonitor {
    /// Our own DHCP server MAC addresses (per interface)
    our_macs: Vec<[u8; 6]>,
    /// DHCP Discover rate per source MAC: (count, window_start)
    discover_rate: HashMap<[u8; 6], (u64, chrono::DateTime<Utc>)>,
    /// Max discovers per second per MAC before starvation alert
    starvation_threshold: u64,
    /// Trusted bindings from valid DHCP ACKs
    trusted_bindings: Vec<DhcpBinding>,
}

impl DhcpMonitor {
    pub fn new(our_macs: Vec<[u8; 6]>, starvation_threshold: u64) -> Self {
        Self {
            our_macs,
            discover_rate: HashMap::new(),
            starvation_threshold,
            trusted_bindings: Vec::new(),
        }
    }

    /// Export current trusted bindings for ARP monitor correlation.
    pub fn export_bindings(&self) -> Vec<ArpBinding> {
        self.trusted_bindings
            .iter()
            .map(|b| ArpBinding {
                ip: b.assigned_ip,
                mac: b.client_mac,
                interface: String::new(),
                vlan: None,
                is_gateway: false,
            })
            .collect()
    }

    /// Process a raw Ethernet frame containing a potential DHCP packet.
    /// Returns an event if a rogue server or starvation is detected.
    pub fn process_dhcp_packet(
        &mut self,
        packet: &[u8],
        interface: &str,
    ) -> Result<Option<IdsEvent>> {
        let dhcp = match parse_dhcp_from_frame(packet) {
            Some(d) => d,
            None => return Ok(None),
        };

        let now = Utc::now();

        match dhcp.msg_type {
            // --- Rogue DHCP server detection ---
            DHCP_OFFER | DHCP_ACK => {
                let from_us = self.our_macs.iter().any(|m| *m == dhcp.server_mac);
                if !from_us {
                    return Ok(Some(IdsEvent {
                        timestamp: now,
                        severity: Severity::Critical,
                        detector: "dhcp",
                        source_mac: Some(format_mac(&dhcp.server_mac)),
                        source_ip: Some(dhcp.server_ip.to_string()),
                        interface: interface.to_string(),
                        vlan: None,
                        description: format!(
                            "Rogue DHCP server: {} ({}) sent {} — not our server",
                            format_mac(&dhcp.server_mac),
                            dhcp.server_ip,
                            if dhcp.msg_type == DHCP_OFFER {
                                "OFFER"
                            } else {
                                "ACK"
                            }
                        ),
                    }));
                }

                // Valid ACK from our server — record binding
                if dhcp.msg_type == DHCP_ACK {
                    self.trusted_bindings.push(DhcpBinding {
                        client_mac: dhcp.client_mac,
                        assigned_ip: dhcp.your_ip,
                        server_ip: dhcp.server_ip,
                        timestamp: now,
                    });
                    // Cap binding table size
                    if self.trusted_bindings.len() > 10_000 {
                        self.trusted_bindings.drain(..5_000);
                    }
                }
            }

            // --- DHCP starvation detection ---
            DHCP_DISCOVER => {
                let entry = self
                    .discover_rate
                    .entry(dhcp.client_mac)
                    .or_insert((0, now));

                let elapsed = (now - entry.1).num_seconds().max(1) as u64;
                if elapsed > 10 {
                    *entry = (1, now);
                } else {
                    entry.0 += 1;
                }

                // Check for rapid DISCOVERs from many different MACs (starvation pattern)
                // A single source sending many DISCOVERs with different chaddr values
                let total_discovers: u64 = self.discover_rate.values().map(|(c, _)| c).sum();
                let active_macs = self
                    .discover_rate
                    .iter()
                    .filter(|(_, (_, ts))| (now - *ts).num_seconds() < 10)
                    .count() as u64;

                if active_macs > self.starvation_threshold {
                    // Prune old entries
                    self.discover_rate
                        .retain(|_, (_, ts)| (now - *ts).num_seconds() < 30);

                    return Ok(Some(IdsEvent {
                        timestamp: now,
                        severity: Severity::Critical,
                        detector: "dhcp",
                        source_mac: Some(format_mac(&dhcp.client_mac)),
                        source_ip: None,
                        interface: interface.to_string(),
                        vlan: None,
                        description: format!(
                            "DHCP starvation attack: {} unique MACs sending DISCOVERs in 10s window \
                             (threshold: {}, total: {})",
                            active_macs, self.starvation_threshold, total_discovers
                        ),
                    }));
                }
            }

            _ => {}
        }

        Ok(None)
    }
}

/// Parsed DHCP packet fields we care about.
#[derive(Debug)]
struct DhcpParsed {
    msg_type: u8,
    client_mac: [u8; 6],
    your_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    server_mac: [u8; 6], // from Ethernet header
}

/// Parse a DHCP packet from a full Ethernet frame.
fn parse_dhcp_from_frame(frame: &[u8]) -> Option<DhcpParsed> {
    if frame.len() < ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + DHCP_MIN_LEN {
        return None;
    }

    // Check EtherType
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETH_P_IP {
        return None;
    }

    // Extract source MAC from Ethernet header
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);

    let ip_start = ETH_HEADER_LEN;
    let ip_header = &frame[ip_start..];

    // IPv4 header: check protocol == UDP (17)
    let ip_version = (ip_header[0] >> 4) & 0x0F;
    if ip_version != 4 {
        return None;
    }
    let ip_hdr_len = ((ip_header[0] & 0x0F) as usize) * 4;
    if ip_hdr_len < IP_HEADER_LEN {
        return None;
    }
    let protocol = ip_header[9];
    if protocol != 17 {
        // Not UDP
        return None;
    }

    let udp_start = ip_start + ip_hdr_len;
    if frame.len() < udp_start + UDP_HEADER_LEN {
        return None;
    }
    let udp = &frame[udp_start..];

    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);

    // DHCP: server port 67, client port 68
    if !((src_port == DHCP_SERVER_PORT && dst_port == DHCP_CLIENT_PORT)
        || (src_port == DHCP_CLIENT_PORT && dst_port == DHCP_SERVER_PORT))
    {
        return None;
    }

    let dhcp_start = udp_start + UDP_HEADER_LEN;
    if frame.len() < dhcp_start + DHCP_MIN_LEN {
        return None;
    }
    let dhcp = &frame[dhcp_start..];

    // DHCP fields:
    // [0]    op (1=request, 2=reply)
    // [1]    htype (1=ethernet)
    // [2]    hlen (6)
    // [3]    hops
    // [4..8] xid
    // [12..16] ciaddr
    // [16..20] yiaddr (your IP)
    // [20..24] siaddr (server IP)
    // [24..28] giaddr
    // [28..34] chaddr (client MAC, first 6 bytes)
    // [236..240] magic cookie
    // [240+]  options

    let htype = dhcp[1];
    let hlen = dhcp[2];
    if htype != 1 || hlen != 6 {
        return None;
    }

    let your_ip = Ipv4Addr::new(dhcp[16], dhcp[17], dhcp[18], dhcp[19]);
    let server_ip = Ipv4Addr::new(dhcp[20], dhcp[21], dhcp[22], dhcp[23]);

    let mut client_mac = [0u8; 6];
    client_mac.copy_from_slice(&dhcp[28..34]);

    // Verify magic cookie
    if dhcp[236..240] != DHCP_MAGIC_COOKIE {
        return None;
    }

    // Parse options to find message type (option 53)
    let msg_type = parse_dhcp_option_53(&dhcp[240..])?;

    // For server-originated messages, use the Ethernet source MAC
    let server_mac = src_mac;

    Some(DhcpParsed {
        msg_type,
        client_mac,
        your_ip,
        server_ip,
        server_mac,
    })
}

/// Parse DHCP options to find option 53 (message type).
fn parse_dhcp_option_53(options: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i < options.len() {
        let option_code = options[i];
        if option_code == 255 {
            // End option
            break;
        }
        if option_code == 0 {
            // Padding
            i += 1;
            continue;
        }
        if i + 1 >= options.len() {
            break;
        }
        let option_len = options[i + 1] as usize;
        if option_code == 53 && option_len == 1 && i + 2 < options.len() {
            return Some(options[i + 2]);
        }
        i += 2 + option_len;
    }
    None
}

/// Start passive DHCP monitoring on all interfaces via AF_PACKET.
pub async fn start_monitor(
    db: sfgw_db::Db,
    event_tx: tokio::sync::mpsc::Sender<IdsEvent>,
) -> Result<()> {
    tracing::info!("DHCP monitor starting");

    let fd = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Packet,
        nix::sys::socket::SockType::Raw,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        Some(nix::sys::socket::SockProtocol::EthAll),
    )
    .context("failed to create AF_PACKET socket for DHCP monitoring")?;

    let raw_fd = fd.as_raw_fd();

    // Load our own MAC addresses from the DB
    let our_macs = load_our_macs(&db).await.unwrap_or_default();
    let mut monitor = DhcpMonitor::new(our_macs, 50); // 50 unique MACs in 10s = starvation

    let mut buf = [0u8; 4096];
    loop {
        let n = tokio::task::spawn_blocking(move || {
            nix::sys::socket::recv(raw_fd, &mut buf, nix::sys::socket::MsgFlags::empty())
        })
        .await?;

        let n = match n {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("DHCP socket recv error: {e}");
                continue;
            }
        };

        if n < ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN {
            continue;
        }

        // Quick check: EtherType must be IPv4
        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
        if ethertype != ETH_P_IP {
            continue;
        }

        match monitor.process_dhcp_packet(&buf[..n], "eth0") {
            Ok(Some(event)) => {
                if event_tx.send(event).await.is_err() {
                    tracing::warn!("DHCP monitor: event channel closed");
                    break;
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::debug!("DHCP packet parse error: {e}");
            }
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}

/// Load our own MAC addresses from the interfaces table.
async fn load_our_macs(db: &sfgw_db::Db) -> Result<Vec<[u8; 6]>> {
    let conn = db.lock().await;
    let mut stmt = conn.prepare("SELECT mac FROM interfaces WHERE role IN ('lan', 'wan')")?;
    let macs: Vec<[u8; 6]> = stmt
        .query_map([], |row| {
            let mac_str: String = row.get(0)?;
            Ok(mac_str)
        })?
        .filter_map(|r| r.ok())
        .filter_map(|s| parse_mac_str(&s))
        .collect();
    Ok(macs)
}

fn parse_mac_str(s: &str) -> Option<[u8; 6]> {
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
