// SPDX-License-Identifier: AGPL-3.0-or-later

//! VLAN Hopping Detection
//!
//! Detects:
//! - 802.1Q double-tagging (frame with two VLAN tags)
//! - DTP negotiation attempts (Dynamic Trunking Protocol — should never appear)
//! - Traffic from unexpected VLANs on access ports
//! - MAC appearing on wrong VLAN (moved without re-auth)

use anyhow::Result;
use super::IdsEvent;

pub struct VlanMonitor {
    /// Expected VLAN assignments per port/interface
    port_vlan_map: std::collections::HashMap<String, Vec<u16>>,
    /// Known MAC-to-VLAN bindings
    mac_vlan_map: std::collections::HashMap<[u8; 6], u16>,
}

impl VlanMonitor {
    pub fn new() -> Self {
        todo!()
    }

    /// Check raw ethernet frame for VLAN anomalies
    pub fn process_frame(&mut self, frame: &[u8], interface: &str) -> Result<Option<IdsEvent>> {
        todo!()
    }
}

pub async fn start_monitor(db: &sfgw_db::Db) -> Result<()> {
    todo!()
}
