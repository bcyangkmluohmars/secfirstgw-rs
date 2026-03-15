# Roadmap: secfirstgw-rs — v0.1.0 VLAN Trunk Model

## Overview

Replace the broken single-role port model with a proper VLAN trunk model where zones own VLANs and VLANs land on ports. Work flows in strict dependency order: data model and DB migration first, then switch ASIC programming, then firewall and WAN enforcement, then API exposure, then web UI visualization.

## Milestones

- [x] **v0.0.3 Foundation** — Phases pre-GSD (shipped 2026-03-14)
- [ ] **v0.1.0 VLAN Trunk Model** — Phases 1-5 (in progress)

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Data Model** — DB migration to PVID + tagged VLAN list, void VLAN 1, LAN VLAN 10 defaults
- [ ] **Phase 2: Switch ASIC** — swconfig programming driven by per-port config (UDM Pro hardware addon)
- [ ] **Phase 3: Network Enforcement** — WAN isolation + firewall rules updated for new VLAN ID scheme
- [ ] **Phase 4: API** — REST endpoints exposing PVID, tagged VLANs, and zone→VLAN relationships
- [ ] **Phase 5: Web UI** — Switch visualization with port VLAN config, colored zone dots, board-specific layout

## Phase Details

### Phase 1: Data Model

**Goal**: The internal representation of ports, zones, and VLANs correctly reflects the trunk model — zones own VLANs, ports have one untagged PVID and a list of tagged VLANs, and VLAN 1 is void by definition
**Depends on**: Nothing (first phase)
**Requirements**: DATA-01, DATA-02, DATA-03, DATA-04, DATA-05, DATA-06, DATA-07
**Success Criteria** (what must be TRUE):
  1. The `interfaces` DB table has no `role` column — replaced by `pvid` (integer) and `tagged_vlans` (JSON array)
  2. VLAN 1 exists in the DB as a defined void VLAN with no bridge attachment
  3. The LAN zone is associated with VLAN 10 in the `networks` table (not VLAN 1)
  4. Any interface with no explicit config has pvid=10 (LAN zone) after migration
  5. The DB migration runs successfully on an existing v0.0.3 database without data loss to non-role fields
**Plans:** 2 plans

Plans:
- [ ] 01-01-PLAN.md — DB migration 005: role-to-PVID schema change, void VLAN 1, LAN VLAN 10
- [ ] 01-02-PLAN.md — Rust code updates: sfgw-net structs/queries/seeding, switch.rs, sfgw-api handlers

---

### Phase 2: Switch ASIC

**Goal**: The RTL8370B switch ASIC on UDM Pro is programmed according to per-port PVID and tagged VLAN config from the DB — not hardcoded to "all VLANs on all ports"
**Depends on**: Phase 1
**Requirements**: ASIC-01, ASIC-02, ASIC-03
**Success Criteria** (what must be TRUE):
  1. On a UDM Pro, swconfig reflects the PVID and tagged VLAN list for each port (verifiable via `swconfig dev switch0 show`)
  2. The MGMT port (eth7) has pvid=3000 in hardware with no LAN VLANs forwarded on it
  3. VLAN 1 is programmed on the switch with no bridge interface attached — traffic on it goes nowhere
  4. On VM or Docker (no board detected), switch ASIC code does not run and no error is produced
**Plans**: TBD

Plans:
- [ ] 02-01: TBD

---

### Phase 3: Network Enforcement

**Goal**: Firewall and routing enforce the VLAN separation — WAN ports cannot bleed into internal VLANs, internal ports cannot receive provider VLANs, and VLAN 1 is DROPped everywhere
**Depends on**: Phase 1
**Requirements**: WAN-01, WAN-02, WAN-03, FW-01, FW-02
**Success Criteria** (what must be TRUE):
  1. A packet tagged with an internal VLAN ID (10, 3000, 3001) cannot arrive on a WAN interface — iptables DROP rule in place and verifiable
  2. A packet tagged with a provider VLAN (e.g. VLAN 7 for Telekom) cannot enter on a LAN port
  3. Any packet on VLAN 1 is DROPped by a catch-all rule before reaching any chain (verifiable via `iptables -L`)
  4. LAN zone rules reference VLAN 10 (br-lan.10 or equivalent), not VLAN 1
**Plans**: TBD

Plans:
- [ ] 03-01: TBD

---

### Phase 4: API

**Goal**: The REST API exposes the new PVID/tagged VLAN model so clients can read and write per-port config and query zone-to-VLAN associations
**Depends on**: Phase 1, Phase 2, Phase 3
**Requirements**: API-01, API-02, API-03
**Success Criteria** (what must be TRUE):
  1. `GET /api/ports/{id}` returns `pvid` and `tagged_vlans` fields (no `role` field)
  2. `PUT /api/ports/{id}` with a new PVID and tagged VLAN list persists to DB and triggers switch/firewall reconfiguration
  3. `GET /api/zones/{id}` returns the list of VLAN IDs owned by that zone
  4. `GET /api/interfaces` returns `pvid` and `tagged_vlans` per interface — role field absent from response
**Plans**: TBD

Plans:
- [ ] 04-01: TBD

---

### Phase 5: Web UI

**Goal**: The switch panel shows each port's zone membership visually and lets the user reconfigure port VLAN assignment through a click interaction — with hardware-specific layout on UDM Pro and a generic fallback elsewhere
**Depends on**: Phase 4
**Requirements**: UI-01, UI-02, UI-03, UI-04, UI-05
**Success Criteria** (what must be TRUE):
  1. Clicking a port opens a config panel showing the current PVID (primary zone) and a checklist of additional VLANs the port carries
  2. Each port shows colored dots representing its tagged zones — primary color reflects PVID zone, secondary dots reflect tagged zones
  3. Ports with pvid=1 (void) are visually distinct — dark/inactive appearance distinguishable from active ports at a glance
  4. On a UDM Pro, the switch panel renders the actual UDM Pro port layout (board-specific addon); on VM/Docker it renders a generic port grid
  5. Saving a port config through the UI causes the switch and firewall to reconfigure without a full page reload
**Plans**: TBD

Plans:
- [ ] 05-01: TBD

---

## Progress

**Execution Order:** 1 → 2 → 3 → 4 → 5

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Data Model | 0/2 | Planned | - |
| 2. Switch ASIC | 0/? | Not started | - |
| 3. Network Enforcement | 0/? | Not started | - |
| 4. API | 0/? | Not started | - |
| 5. Web UI | 0/? | Not started | - |

---
*Roadmap created: 2026-03-15 for milestone v0.1.0*
