// SPDX-License-Identifier: AGPL-3.0-or-later

//! Event collector — receives IDS events from remote nodes (switches, APs)
//!
//! Remote nodes run sfgw-ids in Switch/AP role and push events to the
//! gateway controller via authenticated API endpoint.
//! The collector correlates events across nodes for cross-network detection.
//!
//! Example: MAC appears on two switches simultaneously → likely spoofing.

use anyhow::Result;
use super::{IdsEvent, ResponseAction};

pub struct EventCollector {
    /// Recent events indexed by source MAC for correlation
    recent_by_mac: std::collections::HashMap<String, Vec<IdsEvent>>,
    /// Time window for correlation (default: 30s)
    correlation_window_secs: u64,
}

impl EventCollector {
    pub fn new(correlation_window_secs: u64) -> Self {
        todo!()
    }

    /// Ingest event from local detector or remote node
    pub fn ingest(&mut self, event: IdsEvent) -> Result<Option<ResponseAction>> {
        todo!()
    }

    /// Correlate recent events — detect cross-node patterns
    pub fn correlate(&self) -> Vec<ResponseAction> {
        todo!()
    }
}
