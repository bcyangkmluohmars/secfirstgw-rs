// SPDX-License-Identifier: AGPL-3.0-or-later

//! DHCP Spoofing Detection
//!
//! We ARE the DHCP server — any other DHCP Offer on the network is rogue.
//!
//! Detects:
//! - Rogue DHCP servers (DHCP Offer from unknown source)
//! - DHCP starvation attacks (excessive DHCP Discover from spoofed MACs)
//! - DHCP Option injection (malicious options in rogue responses)

use anyhow::Result;
use super::{IdsEvent, Severity};

pub struct DhcpMonitor {
    /// Our own DHCP server MAC addresses (per interface)
    our_macs: Vec<[u8; 6]>,
    /// DHCP Discover rate per source MAC
    discover_rate: std::collections::HashMap<[u8; 6], (u64, chrono::DateTime<chrono::Utc>)>,
    /// Max discovers per second per MAC before starvation alert
    starvation_threshold: u64,
}

impl DhcpMonitor {
    pub fn new(our_macs: Vec<[u8; 6]>, starvation_threshold: u64) -> Self {
        todo!()
    }

    /// Process a DHCP packet, return event if rogue server or starvation detected
    pub fn process_dhcp_packet(&mut self, packet: &[u8], interface: &str) -> Result<Option<IdsEvent>> {
        todo!()
    }
}

pub async fn start_monitor(db: &sfgw_db::Db) -> Result<()> {
    todo!()
}
