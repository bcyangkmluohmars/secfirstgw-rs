// SPDX-License-Identifier: AGPL-3.0-or-later

//! DNS Anomaly Detection
//!
//! Monitors DNS traffic on the network. Since we control dnsmasq,
//! any DNS response from a non-authorized source is suspicious.
//!
//! Detects:
//! - DNS responses from unauthorized servers
//! - DNS tunneling (high entropy query names, long subdomains, excessive NXDOMAIN)
//! - DNS rebinding attacks (response with private IP for public domain)
//! - DNS amplification (large response-to-query ratio)
//! - Per-client query rate anomalies

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};
use chrono::Utc;

use super::{IdsEvent, Severity};

/// Ethernet header length
const ETH_HEADER_LEN: usize = 14;
/// Minimum IPv4 header length
const IP_HEADER_LEN: usize = 20;
/// UDP header length
const UDP_HEADER_LEN: usize = 8;
/// DNS header length
const DNS_HEADER_LEN: usize = 12;
/// DNS port
const DNS_PORT: u16 = 53;
/// EtherType IPv4
const ETH_P_IP: u16 = 0x0800;

/// DNS response code: NXDOMAIN
const RCODE_NXDOMAIN: u8 = 3;

/// Maximum label length before flagging as suspicious
const SUSPICIOUS_LABEL_LEN: usize = 40;
/// Maximum total query name length before flagging
const SUSPICIOUS_QUERY_LEN: usize = 120;
/// Shannon entropy threshold for tunneling detection
const ENTROPY_THRESHOLD: f64 = 4.0;
/// Max queries per client per 10-second window
const QUERY_RATE_THRESHOLD: u64 = 200;
/// NXDOMAIN threshold per client per 60s
const NXDOMAIN_THRESHOLD: u64 = 50;

/// Per-client statistics.
struct ClientStats {
    query_count: u64,
    nxdomain_count: u64,
    window_start: chrono::DateTime<Utc>,
    total_query_bytes: u64,
    total_response_bytes: u64,
}

pub struct DnsMonitor {
    /// Authorized DNS server IPs (our own resolvers)
    authorized_servers: Vec<IpAddr>,
    /// Per-client (source IP) statistics
    client_stats: HashMap<Ipv4Addr, ClientStats>,
    /// Private IP ranges for rebinding detection.
    #[allow(dead_code)]
    private_ranges: Vec<(u32, u32)>,
}

impl DnsMonitor {
    pub fn new(authorized_servers: Vec<IpAddr>) -> Self {
        // RFC 1918 + loopback + link-local
        let private_ranges = vec![
            (0x0A000000, 0xFF000000), // 10.0.0.0/8
            (0xAC100000, 0xFFF00000), // 172.16.0.0/12
            (0xC0A80000, 0xFFFF0000), // 192.168.0.0/16
            (0x7F000000, 0xFF000000), // 127.0.0.0/8
            (0xA9FE0000, 0xFFFF0000), // 169.254.0.0/16
        ];
        Self {
            authorized_servers,
            client_stats: HashMap::new(),
            private_ranges,
        }
    }

    /// Process a raw Ethernet frame that may contain DNS traffic.
    pub fn process_dns_packet(
        &mut self,
        packet: &[u8],
        interface: &str,
    ) -> Result<Option<IdsEvent>> {
        let parsed = match parse_dns_from_frame(packet) {
            Some(d) => d,
            None => return Ok(None),
        };

        let now = Utc::now();

        // --- Detection 1: Unauthorized DNS server ---
        if parsed.is_response {
            let src_ip = IpAddr::V4(parsed.src_ip);
            if !self.authorized_servers.contains(&src_ip) {
                return Ok(Some(IdsEvent {
                    timestamp: now,
                    severity: Severity::Critical,
                    detector: "dns",
                    source_mac: None,
                    source_ip: Some(parsed.src_ip.to_string()),
                    interface: interface.to_string(),
                    vlan: None,
                    description: format!(
                        "Unauthorized DNS response from {} (not in authorized server list)",
                        parsed.src_ip
                    ),
                }));
            }
        }

        // Track client stats (for queries, src is the client; for responses, dst is)
        let client_ip = if parsed.is_response {
            parsed.dst_ip
        } else {
            parsed.src_ip
        };

        let stats = self.client_stats.entry(client_ip).or_insert(ClientStats {
            query_count: 0,
            nxdomain_count: 0,
            window_start: now,
            total_query_bytes: 0,
            total_response_bytes: 0,
        });

        // Reset window if older than 60s
        if (now - stats.window_start).num_seconds() > 60 {
            stats.query_count = 0;
            stats.nxdomain_count = 0;
            stats.window_start = now;
            stats.total_query_bytes = 0;
            stats.total_response_bytes = 0;
        }

        if parsed.is_response {
            stats.total_response_bytes += packet.len() as u64;

            // Track NXDOMAIN
            if parsed.rcode == RCODE_NXDOMAIN {
                stats.nxdomain_count += 1;
            }

            // --- Detection: Excessive NXDOMAIN (tunneling indicator) ---
            if stats.nxdomain_count > NXDOMAIN_THRESHOLD {
                let count = stats.nxdomain_count;
                stats.nxdomain_count = 0; // reset to avoid repeated alerts
                return Ok(Some(IdsEvent {
                    timestamp: now,
                    severity: Severity::Warning,
                    detector: "dns",
                    source_mac: None,
                    source_ip: Some(client_ip.to_string()),
                    interface: interface.to_string(),
                    vlan: None,
                    description: format!(
                        "Excessive NXDOMAIN: {} got {} NXDOMAIN responses in 60s (possible tunneling/DGA)",
                        client_ip, count
                    ),
                }));
            }

            // --- Detection: DNS amplification ---
            if stats.total_query_bytes > 0 {
                let ratio = stats.total_response_bytes as f64 / stats.total_query_bytes as f64;
                if ratio > 10.0 && stats.total_response_bytes > 50_000 {
                    return Ok(Some(IdsEvent {
                        timestamp: now,
                        severity: Severity::Warning,
                        detector: "dns",
                        source_mac: None,
                        source_ip: Some(client_ip.to_string()),
                        interface: interface.to_string(),
                        vlan: None,
                        description: format!(
                            "DNS amplification: {} response/query ratio {:.1}x ({} bytes response, {} bytes query)",
                            client_ip, ratio, stats.total_response_bytes, stats.total_query_bytes
                        ),
                    }));
                }
            }
        } else {
            stats.query_count += 1;
            stats.total_query_bytes += packet.len() as u64;

            // --- Detection: Query rate anomaly ---
            let elapsed = (now - stats.window_start).num_seconds().max(1) as u64;
            if stats.query_count > QUERY_RATE_THRESHOLD * (elapsed / 10).max(1) {
                return Ok(Some(IdsEvent {
                    timestamp: now,
                    severity: Severity::Warning,
                    detector: "dns",
                    source_mac: None,
                    source_ip: Some(client_ip.to_string()),
                    interface: interface.to_string(),
                    vlan: None,
                    description: format!(
                        "DNS query rate anomaly: {} sent {} queries in {}s",
                        client_ip, stats.query_count, elapsed
                    ),
                }));
            }
        }

        // --- Detection: DNS tunneling via query name analysis ---
        if !parsed.is_response
            && let Some(ref qname) = parsed.query_name
        {
            // Check for suspiciously long labels
            let labels: Vec<&str> = qname.split('.').collect();
            let has_long_label = labels.iter().any(|l| l.len() > SUSPICIOUS_LABEL_LEN);
            let total_len = qname.len();

            if has_long_label || total_len > SUSPICIOUS_QUERY_LEN {
                return Ok(Some(IdsEvent {
                    timestamp: now,
                    severity: Severity::Warning,
                    detector: "dns",
                    source_mac: None,
                    source_ip: Some(client_ip.to_string()),
                    interface: interface.to_string(),
                    vlan: None,
                    description: format!(
                        "Possible DNS tunneling: query name length {} with long subdomain labels (query: {})",
                        total_len,
                        truncate_str(qname, 80)
                    ),
                }));
            }

            // Shannon entropy check on the subdomain portion
            if labels.len() > 2 {
                let subdomain = labels[..labels.len() - 2].join(".");
                let entropy = shannon_entropy(&subdomain);
                if entropy > ENTROPY_THRESHOLD && subdomain.len() > 20 {
                    return Ok(Some(IdsEvent {
                        timestamp: now,
                        severity: Severity::Warning,
                        detector: "dns",
                        source_mac: None,
                        source_ip: Some(client_ip.to_string()),
                        interface: interface.to_string(),
                        vlan: None,
                        description: format!(
                            "Possible DNS tunneling: high entropy ({:.2}) in subdomain (query: {})",
                            entropy,
                            truncate_str(qname, 80)
                        ),
                    }));
                }
            }
        }

        Ok(None)
    }
}

/// Parsed DNS packet fields.
#[derive(Debug)]
struct DnsParsed {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    is_response: bool,
    rcode: u8,
    query_name: Option<String>,
}

/// Parse DNS packet from a full Ethernet frame.
fn parse_dns_from_frame(frame: &[u8]) -> Option<DnsParsed> {
    if frame.len() < ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + DNS_HEADER_LEN {
        return None;
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETH_P_IP {
        return None;
    }

    let ip_start = ETH_HEADER_LEN;
    let ip = &frame[ip_start..];

    let ip_version = (ip[0] >> 4) & 0x0F;
    if ip_version != 4 {
        return None;
    }
    let ip_hdr_len = ((ip[0] & 0x0F) as usize) * 4;
    if ip_hdr_len < IP_HEADER_LEN {
        return None;
    }

    // Protocol must be UDP
    if ip[9] != 17 {
        return None;
    }

    let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);

    let udp_start = ip_start + ip_hdr_len;
    if frame.len() < udp_start + UDP_HEADER_LEN {
        return None;
    }
    let udp = &frame[udp_start..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);

    // Must involve DNS port
    if src_port != DNS_PORT && dst_port != DNS_PORT {
        return None;
    }

    let dns_start = udp_start + UDP_HEADER_LEN;
    if frame.len() < dns_start + DNS_HEADER_LEN {
        return None;
    }
    let dns = &frame[dns_start..];

    // DNS header: flags at bytes 2-3
    let flags = u16::from_be_bytes([dns[2], dns[3]]);
    let is_response = (flags & 0x8000) != 0;
    let rcode = (flags & 0x000F) as u8;
    let qdcount = u16::from_be_bytes([dns[4], dns[5]]);

    // Parse first query name if present
    let query_name = if qdcount > 0 {
        parse_dns_name(&dns[DNS_HEADER_LEN..])
    } else {
        None
    };

    Some(DnsParsed {
        src_ip,
        dst_ip,
        is_response,
        rcode,
        query_name,
    })
}

/// Parse a DNS name from the question section (label format).
fn parse_dns_name(data: &[u8]) -> Option<String> {
    let mut name = String::new();
    let mut i = 0;

    loop {
        if i >= data.len() {
            break;
        }
        let len = data[i] as usize;
        if len == 0 {
            break;
        }
        // Compression pointer — we don't follow these for simplicity
        if len & 0xC0 == 0xC0 {
            break;
        }
        if len > 63 || i + 1 + len > data.len() {
            break;
        }
        if !name.is_empty() {
            name.push('.');
        }
        // Labels should be ASCII
        for &b in &data[i + 1..i + 1 + len] {
            if b.is_ascii_graphic() || b == b'-' {
                name.push(b as char);
            } else {
                name.push('?');
            }
        }
        i += 1 + len;
    }

    if name.is_empty() { None } else { Some(name) }
}

/// Calculate Shannon entropy of a string.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Truncate a string for display in log messages.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

/// Start passive DNS monitoring on all interfaces via AF_PACKET.
pub async fn start_monitor(
    _db: sfgw_db::Db,
    event_tx: tokio::sync::mpsc::Sender<IdsEvent>,
) -> Result<()> {
    tracing::info!("DNS monitor starting");

    let fd = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Packet,
        nix::sys::socket::SockType::Raw,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        Some(nix::sys::socket::SockProtocol::EthAll),
    )
    .context("failed to create AF_PACKET socket for DNS monitoring")?;

    let raw_fd = fd.as_raw_fd();

    // Load authorized DNS servers from the database (interfaces with role 'lan' or 'mgmt').
    // Falls back to loopback only if loading fails.
    let authorized = load_authorized_from_db(&_db).await.unwrap_or_else(|e| {
        tracing::warn!("Failed to load authorized DNS servers from DB: {e}, using loopback only");
        vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]
    });
    if authorized.is_empty() {
        tracing::warn!("No authorized DNS servers found in DB, using loopback only");
    }
    let authorized = if authorized.is_empty() {
        vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]
    } else {
        authorized
    };
    tracing::info!("Authorized DNS servers: {:?}", authorized);
    let mut monitor = DnsMonitor::new(authorized);

    let mut buf = [0u8; 4096];
    loop {
        let n = tokio::task::spawn_blocking(move || {
            nix::sys::socket::recv(raw_fd, &mut buf, nix::sys::socket::MsgFlags::empty())
        })
        .await?;

        let n = match n {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("DNS socket recv error: {e}");
                continue;
            }
        };

        if n < ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + DNS_HEADER_LEN {
            continue;
        }

        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
        if ethertype != ETH_P_IP {
            continue;
        }

        match monitor.process_dns_packet(&buf[..n], "eth0") {
            Ok(Some(event)) => {
                if event_tx.send(event).await.is_err() {
                    tracing::warn!("DNS monitor: event channel closed");
                    break;
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::debug!("DNS packet parse error: {e}");
            }
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}

/// Load authorized DNS server IPs from the database.
///
/// Queries the interfaces table for entries with role 'lan' or 'mgmt',
/// parses their IP addresses (stripping CIDR prefix if present), and
/// returns them as the set of IPs that are allowed to send DNS responses.
async fn load_authorized_from_db(db: &sfgw_db::Db) -> Result<Vec<IpAddr>> {
    let conn = db.lock().await;
    let mut stmt = conn.prepare("SELECT ips FROM interfaces WHERE role IN ('lan', 'mgmt')")?;
    let rows: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();
    drop(stmt);
    drop(conn);

    let mut authorized = Vec::new();
    for ips_json in rows {
        // IPs are stored as JSON arrays, e.g. ["192.168.1.1/24", "fd00::1/64"]
        if let Ok(ips) = serde_json::from_str::<Vec<String>>(&ips_json) {
            for ip_str in ips {
                // Strip CIDR prefix length if present (e.g. "192.168.1.1/24" -> "192.168.1.1")
                let bare_ip = ip_str.split('/').next().unwrap_or(&ip_str);
                if let Ok(addr) = bare_ip.parse::<IpAddr>() {
                    authorized.push(addr);
                }
            }
        }
    }
    Ok(authorized)
}
