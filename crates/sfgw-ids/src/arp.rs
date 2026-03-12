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

use anyhow::Result;
use super::{IdsEvent, Severity};

/// Known IP-MAC binding from DHCP leases + static config
#[derive(Debug, Clone)]
pub struct ArpBinding {
    pub ip: std::net::Ipv4Addr,
    pub mac: [u8; 6],
    pub interface: String,
    pub vlan: Option<u16>,
    pub is_gateway: bool,
}

/// ARP monitor state per interface
pub struct ArpMonitor {
    /// Known bindings (from DHCP leases + static)
    bindings: Vec<ArpBinding>,
    /// Gratuitous ARP counter per MAC (for rate limiting detection)
    garp_counter: std::collections::HashMap<[u8; 6], (u64, chrono::DateTime<chrono::Utc>)>,
    /// Max gratuitous ARPs per second before alert
    garp_threshold: u64,
}

impl ArpMonitor {
    pub fn new(garp_threshold: u64) -> Self {
        todo!()
    }

    /// Process a raw ARP packet, return event if suspicious
    pub fn process_arp_packet(&mut self, packet: &[u8], interface: &str) -> Result<Option<IdsEvent>> {
        todo!()
    }

    /// Update known bindings from DHCP lease database
    pub fn update_bindings(&mut self, bindings: Vec<ArpBinding>) {
        todo!()
    }
}

/// Start passive ARP monitoring on all interfaces via AF_PACKET
pub async fn start_monitor(db: &sfgw_db::Db) -> Result<()> {
    todo!()
}
