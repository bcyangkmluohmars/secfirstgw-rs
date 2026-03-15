# Requirements: secfirstgw-rs

**Defined:** 2026-03-15
**Core Value:** Security first — default deny, zero trust, minimal attack surface

## v0.1.0 Requirements

Requirements for VLAN Trunk Model milestone. Each maps to roadmap phases.

### Data Model

- [x] **DATA-01**: VLAN 1 is void — all traffic on VLAN 1 is DROPped by firewall
- [x] **DATA-02**: LAN zone defaults to VLAN 10 (not VLAN 1)
- [x] **DATA-03**: Each zone owns one or more VLANs (zone → N VLANs relationship)
- [x] **DATA-04**: Each port has exactly one PVID (untagged VLAN) determining its primary zone
- [x] **DATA-05**: Each port can carry additional tagged VLANs from any zone
- [x] **DATA-06**: New/unconfigured ports default to PVID 10 (LAN) — lockout prevention
- [x] **DATA-07**: DB migration from role-per-interface to PVID + tagged VLAN list model

### Switch ASIC (hardware addon)

- [ ] **ASIC-01**: swconfig VLAN programming driven by per-port PVID + tagged VLAN config (only when board detected)
- [ ] **ASIC-02**: MGMT port PVID set to MGMT VLAN (3000), tagged VLANs configurable
- [ ] **ASIC-03**: Void VLAN 1 programmed on switch with no bridge attachment

### WAN Isolation

- [ ] **WAN-01**: WAN ports cannot receive internal VLANs (10, 3000, 3001, etc.)
- [ ] **WAN-02**: Internal ports cannot receive WAN provider VLANs
- [ ] **WAN-03**: Provider VLAN config (e.g. VLAN 7 Telekom) stays in WAN config only

### Firewall

- [ ] **FW-01**: Firewall rules updated for new VLAN ID scheme (VLAN 10 = LAN, not VLAN 1)
- [ ] **FW-02**: VLAN 1 catch-all DROP rule on all chains (void VLAN enforcement)

### API

- [ ] **API-01**: Port config endpoint: GET/PUT per-port PVID + tagged VLAN list
- [ ] **API-02**: Zone endpoint returns associated VLANs
- [ ] **API-03**: Interfaces endpoint reflects PVID and tagged VLANs instead of role

### Web UI

- [ ] **UI-01**: Port click opens VLAN config: set PVID, checklist of tagged VLANs
- [ ] **UI-02**: Switch panel shows colored dots per port for tagged VLANs (zone colors)
- [ ] **UI-03**: Port primary color = PVID zone color, secondary dots = tagged zones
- [ ] **UI-04**: Device-specific switch visualization as addon when board detected, generic fallback
- [ ] **UI-05**: Disabled/void ports (PVID 1) shown as dark/inactive

## v0.2.0 Requirements

Deferred to future release.

### Custom Zones

- **ZONE-01**: User can create custom zones (IoT, VPN, Custom)
- **ZONE-02**: Custom zone gets own firewall chain with configurable policies

### Advanced Networking

- **NET-01**: Port bonding / LACP
- **NET-02**: DDNS client for WAN IP updates
- **NET-03**: Traffic shaping / QoS

## Out of Scope

| Feature | Reason |
|---------|--------|
| DPI / packet inspection | CPU budget on embedded hardware |
| UPnP / NAT-PMP | Security risk, defer with disabled-by-default |
| Firmware OTA updates | Separate milestone |
| HA failover | Separate milestone, high complexity |
| Q-in-Q / provider bridging | Edge case, not needed for target users |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| DATA-01 | Phase 1 | ✓ Done |
| DATA-02 | Phase 1 | ✓ Done |
| DATA-03 | Phase 1 | ✓ Done |
| DATA-04 | Phase 1 | ✓ Done |
| DATA-05 | Phase 1 | ✓ Done |
| DATA-06 | Phase 1 | ✓ Done |
| DATA-07 | Phase 1 | ✓ Done |
| ASIC-01 | Phase 2 | Pending |
| ASIC-02 | Phase 2 | Pending |
| ASIC-03 | Phase 2 | Pending |
| WAN-01 | Phase 3 | Pending |
| WAN-02 | Phase 3 | Pending |
| WAN-03 | Phase 3 | Pending |
| FW-01 | Phase 3 | Pending |
| FW-02 | Phase 3 | Pending |
| API-01 | Phase 4 | Pending |
| API-02 | Phase 4 | Pending |
| API-03 | Phase 4 | Pending |
| UI-01 | Phase 5 | Pending |
| UI-02 | Phase 5 | Pending |
| UI-03 | Phase 5 | Pending |
| UI-04 | Phase 5 | Pending |
| UI-05 | Phase 5 | Pending |

**Coverage:**
- v0.1.0 requirements: 23 total
- Mapped to phases: 23
- Unmapped: 0

---
*Requirements defined: 2026-03-15*
*Last updated: 2026-03-15 — Phase 1 complete*
