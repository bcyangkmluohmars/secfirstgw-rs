// SPDX-License-Identifier: AGPL-3.0-or-later

//! Event Collector — receives IDS events from remote nodes (switches, APs)
//!
//! Remote nodes run sfgw-ids in Switch/AP role and push events to the
//! gateway controller via authenticated API endpoint.
//! The collector correlates events across nodes for cross-network detection.
//!
//! Correlation patterns:
//! - Same MAC seen on multiple switches simultaneously (MAC spoofing)
//! - ARP spoofing on switch + DNS anomaly on gateway (coordinated attack)
//! - Multiple low-severity events from different nodes = elevated severity
//! - Timeline tracking for forensic analysis

use std::collections::HashMap;

use chrono::Utc;
use anyhow::Result;

use super::{IdsEvent, ResponseAction, Severity};

/// Maximum events to keep in the correlation window per source.
const MAX_EVENTS_PER_SOURCE: usize = 100;
/// Maximum total events in the collector before pruning.
const MAX_TOTAL_EVENTS: usize = 10_000;

pub struct Collector {
    /// Recent events indexed by source MAC for correlation.
    recent_by_mac: HashMap<String, Vec<IdsEvent>>,
    /// Recent events indexed by source IP for correlation.
    recent_by_ip: HashMap<String, Vec<IdsEvent>>,
    /// Recent events indexed by detector type for cross-detector correlation.
    recent_by_detector: HashMap<String, Vec<IdsEvent>>,
    /// All recent events in chronological order (timeline for forensics).
    timeline: Vec<IdsEvent>,
    /// Time window for correlation (in seconds).
    correlation_window_secs: u64,
    /// Total event count (for pruning).
    total_events: usize,
}

impl Collector {
    pub fn new(correlation_window_secs: u64) -> Self {
        Self {
            recent_by_mac: HashMap::new(),
            recent_by_ip: HashMap::new(),
            recent_by_detector: HashMap::new(),
            timeline: Vec::new(),
            correlation_window_secs,
            total_events: 0,
        }
    }

    /// Ingest an event from a local detector or remote node.
    /// Returns a response action if correlation reveals a higher-severity pattern.
    pub fn ingest(&mut self, event: IdsEvent) -> Result<Option<ResponseAction>> {
        let now = Utc::now();

        // Index by source MAC
        if let Some(ref mac) = event.source_mac {
            let entries = self
                .recent_by_mac
                .entry(mac.clone())
                .or_insert_with(Vec::new);
            entries.push(event.clone());
            if entries.len() > MAX_EVENTS_PER_SOURCE {
                entries.drain(..entries.len() - MAX_EVENTS_PER_SOURCE);
            }
        }

        // Index by source IP
        if let Some(ref ip) = event.source_ip {
            let entries = self
                .recent_by_ip
                .entry(ip.clone())
                .or_insert_with(Vec::new);
            entries.push(event.clone());
            if entries.len() > MAX_EVENTS_PER_SOURCE {
                entries.drain(..entries.len() - MAX_EVENTS_PER_SOURCE);
            }
        }

        // Index by detector
        let entries = self
            .recent_by_detector
            .entry(event.detector.to_string())
            .or_insert_with(Vec::new);
        entries.push(event.clone());
        if entries.len() > MAX_EVENTS_PER_SOURCE * 10 {
            entries.drain(..entries.len() - MAX_EVENTS_PER_SOURCE * 10);
        }

        // Add to timeline
        self.timeline.push(event.clone());
        self.total_events += 1;

        // Prune if too many events
        if self.total_events > MAX_TOTAL_EVENTS {
            self.prune(now);
        }

        // --- Correlation: check if this event triggers escalation ---

        // Pattern 1: Same MAC on multiple interfaces (MAC spoofing/movement)
        if let Some(ref mac) = event.source_mac {
            if let Some(events) = self.recent_by_mac.get(mac.as_str()) {
                let recent: Vec<&IdsEvent> = events
                    .iter()
                    .filter(|e| (now - e.timestamp).num_seconds() < self.correlation_window_secs as i64)
                    .collect();

                // Check if same MAC seen on different interfaces
                let interfaces: Vec<&str> = recent
                    .iter()
                    .map(|e| e.interface.as_str())
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();

                if interfaces.len() > 1 {
                    return Ok(Some(ResponseAction::BlockMac {
                        mac: mac.clone(),
                        duration_secs: 600,
                    }));
                }
            }
        }

        // Pattern 2: Multiple low-severity events from different detectors = escalation
        if event.severity == Severity::Warning {
            if let Some(ref mac) = event.source_mac {
                if let Some(events) = self.recent_by_mac.get(mac.as_str()) {
                    let recent_warnings: Vec<&IdsEvent> = events
                        .iter()
                        .filter(|e| {
                            e.severity == Severity::Warning
                                && (now - e.timestamp).num_seconds()
                                    < self.correlation_window_secs as i64
                        })
                        .collect();

                    // Different detectors flagging the same MAC = coordinated attack
                    let detectors: std::collections::HashSet<&str> = recent_warnings
                        .iter()
                        .map(|e| e.detector)
                        .collect();

                    if detectors.len() >= 2 {
                        return Ok(Some(ResponseAction::IsolatePort {
                            interface: event.interface.clone(),
                            mac: mac.clone(),
                        }));
                    }

                    // Many warnings from same detector = escalate
                    if recent_warnings.len() >= 5 {
                        return Ok(Some(ResponseAction::BlockMac {
                            mac: mac.clone(),
                            duration_secs: 300,
                        }));
                    }
                }
            }
        }

        // Pattern 3: ARP spoofing + DNS anomaly from same source (coordinated)
        if let Some(ref ip) = event.source_ip {
            if let Some(events) = self.recent_by_ip.get(ip.as_str()) {
                let recent: Vec<&IdsEvent> = events
                    .iter()
                    .filter(|e| (now - e.timestamp).num_seconds() < self.correlation_window_secs as i64)
                    .collect();

                let has_arp = recent.iter().any(|e| e.detector == "arp");
                let has_dns = recent.iter().any(|e| e.detector == "dns");

                if has_arp && has_dns {
                    return Ok(Some(ResponseAction::RateLimit {
                        ip: ip.clone(),
                        pps: 10, // Very aggressive rate limit for coordinated attack
                    }));
                }
            }
        }

        Ok(None)
    }

    /// Correlate recent events — detect cross-node patterns.
    /// Returns a list of response actions for detected patterns.
    pub fn correlate(&self) -> Vec<ResponseAction> {
        let now = Utc::now();
        let mut actions = Vec::new();

        // Scan all MACs for multi-interface presence
        for (mac, events) in &self.recent_by_mac {
            let recent: Vec<&IdsEvent> = events
                .iter()
                .filter(|e| (now - e.timestamp).num_seconds() < self.correlation_window_secs as i64)
                .collect();

            if recent.is_empty() {
                continue;
            }

            let interfaces: std::collections::HashSet<&str> =
                recent.iter().map(|e| e.interface.as_str()).collect();

            if interfaces.len() > 1 {
                actions.push(ResponseAction::BlockMac {
                    mac: mac.clone(),
                    duration_secs: 600,
                });
            }

            // Check for severity escalation
            let warning_count = recent
                .iter()
                .filter(|e| e.severity == Severity::Warning)
                .count();
            let detectors: std::collections::HashSet<&str> =
                recent.iter().map(|e| e.detector).collect();

            if warning_count >= 3 && detectors.len() >= 2 {
                actions.push(ResponseAction::IsolatePort {
                    interface: recent.last().map(|e| e.interface.clone()).unwrap_or_default(),
                    mac: mac.clone(),
                });
            }
        }

        actions
    }

    /// Get the event timeline for forensic analysis.
    pub fn timeline(&self, last_n: usize) -> &[IdsEvent] {
        let start = self.timeline.len().saturating_sub(last_n);
        &self.timeline[start..]
    }

    /// Prune old events outside the correlation window.
    fn prune(&mut self, now: chrono::DateTime<Utc>) {
        let cutoff = self.correlation_window_secs as i64 * 2; // Keep 2x window for context

        self.recent_by_mac.retain(|_, events| {
            events.retain(|e| (now - e.timestamp).num_seconds() < cutoff);
            !events.is_empty()
        });

        self.recent_by_ip.retain(|_, events| {
            events.retain(|e| (now - e.timestamp).num_seconds() < cutoff);
            !events.is_empty()
        });

        self.recent_by_detector.retain(|_, events| {
            events.retain(|e| (now - e.timestamp).num_seconds() < cutoff);
            !events.is_empty()
        });

        self.timeline
            .retain(|e| (now - e.timestamp).num_seconds() < cutoff);

        self.total_events = self.timeline.len();
    }
}
