// SPDX-License-Identifier: AGPL-3.0-or-later

//! DNS Spoofing Detection
//!
//! Monitors DNS responses on the network. Since we control dnsmasq,
//! any DNS response from a non-authorized source is suspicious.
//!
//! Detects:
//! - DNS responses from unauthorized servers
//! - DNS response for queries we didn't forward (race condition spoofing)
//! - NXDOMAIN hijacking

use anyhow::Result;
use super::IdsEvent;

pub struct DnsMonitor {
    /// Authorized DNS server IPs (our own resolvers)
    authorized_servers: Vec<std::net::IpAddr>,
}

impl DnsMonitor {
    pub fn new(authorized_servers: Vec<std::net::IpAddr>) -> Self {
        todo!()
    }

    pub fn process_dns_packet(&mut self, packet: &[u8], interface: &str) -> Result<Option<IdsEvent>> {
        todo!()
    }
}

pub async fn start_monitor(db: &sfgw_db::Db) -> Result<()> {
    todo!()
}
