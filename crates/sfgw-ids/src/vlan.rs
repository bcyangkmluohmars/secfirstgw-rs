// SPDX-License-Identifier: AGPL-3.0-or-later

//! VLAN Hopping Detection
//!
//! Detects:
//! - 802.1Q double-tagging (frame with two VLAN tags)
//! - DTP negotiation attempts (Dynamic Trunking Protocol — should never appear)
//! - Traffic from unexpected VLANs on access ports
//! - MAC appearing on wrong VLAN (moved without re-auth)

use std::collections::HashMap;
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};
use chrono::Utc;

use super::arp::format_mac;
use super::{IdsEvent, Severity};

/// 802.1Q EtherType
const ETH_P_8021Q: u16 = 0x8100;
/// 802.1AD (QinQ outer tag) EtherType
const ETH_P_8021AD: u16 = 0x88A8;
/// DTP (Dynamic Trunking Protocol) multicast destination MAC
const DTP_DEST_MAC: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC];
/// DTP EtherType (Cisco SNAP)
const ETH_P_DTP_SNAP: u16 = 0x2004;
/// Ethernet header length
const ETH_HEADER_LEN: usize = 14;

/// Configured VLAN range considered valid.
#[derive(Debug, Clone)]
pub struct VlanConfig {
    pub min_vlan: u16,
    pub max_vlan: u16,
}

impl Default for VlanConfig {
    fn default() -> Self {
        Self {
            min_vlan: 1,
            max_vlan: 4094,
        }
    }
}

pub struct VlanMonitor {
    /// Expected VLAN assignments per port/interface
    port_vlan_map: HashMap<String, Vec<u16>>,
    /// Known MAC-to-VLAN bindings
    mac_vlan_map: HashMap<[u8; 6], u16>,
    /// Valid VLAN range
    vlan_config: VlanConfig,
}

impl VlanMonitor {
    pub fn new() -> Self {
        Self {
            port_vlan_map: HashMap::new(),
            mac_vlan_map: HashMap::new(),
            vlan_config: VlanConfig::default(),
        }
    }

    /// Configure the valid VLAN range for this monitor.
    pub fn set_vlan_range(&mut self, min: u16, max: u16) {
        self.vlan_config.min_vlan = min;
        self.vlan_config.max_vlan = max;
    }

    /// Set expected VLANs for an interface (access port config).
    pub fn set_port_vlans(&mut self, interface: String, vlans: Vec<u16>) {
        self.port_vlan_map.insert(interface, vlans);
    }

    /// Check raw ethernet frame for VLAN anomalies.
    pub fn process_frame(
        &mut self,
        frame: &[u8],
        interface: &str,
    ) -> Result<Option<IdsEvent>> {
        if frame.len() < ETH_HEADER_LEN {
            return Ok(None);
        }

        let now = Utc::now();

        // Extract destination and source MAC
        let mut dst_mac = [0u8; 6];
        dst_mac.copy_from_slice(&frame[0..6]);
        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&frame[6..12]);

        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

        // --- Detection 1: DTP packets (should never appear on access ports) ---
        if dst_mac == DTP_DEST_MAC || ethertype == ETH_P_DTP_SNAP {
            return Ok(Some(IdsEvent {
                timestamp: now,
                severity: Severity::Critical,
                detector: "vlan",
                source_mac: Some(format_mac(&src_mac)),
                source_ip: None,
                interface: interface.to_string(),
                vlan: None,
                description: format!(
                    "DTP packet detected from {} on {} — possible VLAN hopping attempt (DTP should be disabled)",
                    format_mac(&src_mac),
                    interface
                ),
            }));
        }

        // --- Detection 2: 802.1Q double-tagging ---
        if ethertype == ETH_P_8021Q || ethertype == ETH_P_8021AD {
            if frame.len() < ETH_HEADER_LEN + 4 {
                return Ok(None);
            }

            // First VLAN tag
            let vlan_tci = u16::from_be_bytes([frame[14], frame[15]]);
            let outer_vlan = vlan_tci & 0x0FFF;
            let inner_ethertype = u16::from_be_bytes([frame[16], frame[17]]);

            // Check for double-tagging (another 802.1Q tag inside)
            if inner_ethertype == ETH_P_8021Q || inner_ethertype == ETH_P_8021AD {
                if frame.len() < ETH_HEADER_LEN + 8 {
                    return Ok(None);
                }
                let inner_tci = u16::from_be_bytes([frame[18], frame[19]]);
                let inner_vlan = inner_tci & 0x0FFF;

                return Ok(Some(IdsEvent {
                    timestamp: now,
                    severity: Severity::Critical,
                    detector: "vlan",
                    source_mac: Some(format_mac(&src_mac)),
                    source_ip: None,
                    interface: interface.to_string(),
                    vlan: Some(outer_vlan),
                    description: format!(
                        "802.1Q double-tagging attack: {} sent frame with outer VLAN {} inner VLAN {} on {}",
                        format_mac(&src_mac),
                        outer_vlan,
                        inner_vlan,
                        interface
                    ),
                }));
            }

            // --- Detection 3: VLAN tag outside configured range ---
            if outer_vlan < self.vlan_config.min_vlan || outer_vlan > self.vlan_config.max_vlan {
                return Ok(Some(IdsEvent {
                    timestamp: now,
                    severity: Severity::Warning,
                    detector: "vlan",
                    source_mac: Some(format_mac(&src_mac)),
                    source_ip: None,
                    interface: interface.to_string(),
                    vlan: Some(outer_vlan),
                    description: format!(
                        "VLAN tag out of range: {} sent frame with VLAN {} (valid range: {}-{})",
                        format_mac(&src_mac),
                        outer_vlan,
                        self.vlan_config.min_vlan,
                        self.vlan_config.max_vlan
                    ),
                }));
            }

            // --- Detection 4: Unexpected VLAN on access port ---
            if let Some(allowed) = self.port_vlan_map.get(interface) {
                if !allowed.contains(&outer_vlan) {
                    return Ok(Some(IdsEvent {
                        timestamp: now,
                        severity: Severity::Warning,
                        detector: "vlan",
                        source_mac: Some(format_mac(&src_mac)),
                        source_ip: None,
                        interface: interface.to_string(),
                        vlan: Some(outer_vlan),
                        description: format!(
                            "Unexpected VLAN: {} sent frame with VLAN {} on {} (allowed: {:?})",
                            format_mac(&src_mac),
                            outer_vlan,
                            interface,
                            allowed
                        ),
                    }));
                }
            }

            // --- Detection 5: MAC on wrong VLAN ---
            if let Some(expected_vlan) = self.mac_vlan_map.get(&src_mac) {
                if *expected_vlan != outer_vlan {
                    return Ok(Some(IdsEvent {
                        timestamp: now,
                        severity: Severity::Warning,
                        detector: "vlan",
                        source_mac: Some(format_mac(&src_mac)),
                        source_ip: None,
                        interface: interface.to_string(),
                        vlan: Some(outer_vlan),
                        description: format!(
                            "MAC on wrong VLAN: {} expected on VLAN {} but seen on VLAN {}",
                            format_mac(&src_mac),
                            expected_vlan,
                            outer_vlan
                        ),
                    }));
                }
            } else {
                // First time seeing this MAC — record its VLAN
                self.mac_vlan_map.insert(src_mac, outer_vlan);
            }
        }

        Ok(None)
    }
}

/// Start passive VLAN monitoring on all interfaces via AF_PACKET.
pub async fn start_monitor(
    _db: sfgw_db::Db,
    event_tx: tokio::sync::mpsc::Sender<IdsEvent>,
) -> Result<()> {
    tracing::info!("VLAN monitor starting");

    let fd = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Packet,
        nix::sys::socket::SockType::Raw,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        Some(nix::sys::socket::SockProtocol::EthAll),
    )
    .context("failed to create AF_PACKET socket for VLAN monitoring")?;

    let raw_fd = fd.as_raw_fd();
    let mut monitor = VlanMonitor::new();

    let mut buf = [0u8; 2048];
    loop {
        let n = tokio::task::spawn_blocking(move || {
            nix::sys::socket::recv(raw_fd, &mut buf, nix::sys::socket::MsgFlags::empty())
        })
        .await?;

        let n = match n {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("VLAN socket recv error: {e}");
                continue;
            }
        };

        if n < ETH_HEADER_LEN {
            continue;
        }

        match monitor.process_frame(&buf[..n], "eth0") {
            Ok(Some(event)) => {
                if event_tx.send(event).await.is_err() {
                    tracing::warn!("VLAN monitor: event channel closed");
                    break;
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::debug!("VLAN frame parse error: {e}");
            }
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}
