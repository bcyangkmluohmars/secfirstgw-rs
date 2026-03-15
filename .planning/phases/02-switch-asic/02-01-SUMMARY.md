---
phase: 02-switch-asic
plan: 01
subsystem: network
tags: [switch, vlan, swconfig, asic, rtl8370b, pvid, trunk]

# Dependency graph
requires:
  - phase: 01-data-model
    provides: "interfaces table with pvid + tagged_vlans columns; void VLAN 1 in networks table"

provides:
  - "compute_vlan_port_map(): per-port PVID + tagged_vlans → per-VLAN port membership BTreeMap"
  - "format_port_string(): PortMember list → swconfig port string"
  - "iface_to_switch_port(): ethN → switch port number mapping"
  - "load_port_vlan_config(): DB query for pvid > 0 interfaces"
  - "setup_switch_vlans(): async, DB-driven, programs each VLAN and each port's PVID"
  - "Stale VLAN cleanup covering 1-100 and 3000-3100 ranges"
  - "VLAN 1 always programmed as catch-all sink with all ports tagged"

affects:
  - 02-switch-asic
  - 03-firewall
  - phase-integration-testing

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Per-port VLAN inversion: port config (pvid + tagged_vlans) → per-VLAN port membership map"
    - "VLAN 1 as void catch-all: always programmed on ASIC, never has a Linux bridge"
    - "WAN port exclusion: pvid=0 signals 'not an internal VLAN port', excluded at SQL level"
    - "Positional ethN → port N mapping for switch port identification"

key-files:
  created: []
  modified:
    - crates/sfgw-net/src/switch.rs

key-decisions:
  - "setup_switch_vlans is now async (reads DB); caller in setup_networks updated accordingly"
  - "WAN port exclusion done at SQL level (WHERE pvid > 0) not in Rust logic"
  - "VLAN 1 built via map.entry(1).or_insert_with() to handle edge case where pvid=1 exists"
  - "Stale cleanup covers 3000-3100 range in addition to 1-100 for zone VLAN cleanup"
  - "build_port_string() replaced entirely by format_port_string() which is membership-driven"

patterns-established:
  - "BTreeMap<u16, Vec<PortMember>> as the canonical VLAN→ports structure throughout switch programming"
  - "PortMember { port: u8, tagged: bool } as the atomic unit of VLAN membership"
  - "compute_vlan_port_map() as the pure function tested in isolation (no swconfig calls)"

# Metrics
duration: 18min
completed: 2026-03-15
---

# Phase 2 Plan 01: Switch ASIC VLAN Programming Rewrite Summary

**Switch ASIC programming rewritten from hardcoded zone-based model to per-port PVID + tagged_vlans DB-driven model with VLAN 1 catch-all sink and full MGMT port isolation**

## Performance

- **Duration:** ~18 min
- **Started:** 2026-03-15T12:02:37Z
- **Completed:** 2026-03-15T12:20:00Z
- **Tasks:** 2 (both implemented in one atomic switch.rs rewrite)
- **Files modified:** 1

## Accomplishments

- `compute_vlan_port_map()` correctly inverts per-port config: each port only appears in VLANs its pvid/tagged_vlans configure it for
- MGMT port (eth7 / switch port 7) with pvid=3000 appears only in VLAN 3000 (untagged) and VLAN 1 (catch-all tagged) — never in VLAN 10
- VLAN 1 always programmed on the ASIC with all ports tagged as a void catch-all sink; no Linux bridge created for it (setup_bridges skips void zone — existing behavior unchanged)
- WAN ports excluded at SQL level (WHERE pvid > 0), never appear in any VLAN membership
- Stale VLAN cleanup extended to cover 3000–3100 range in addition to 1–100
- All 75 tests pass (11 new tests added, 5 old build_port_string tests removed)

## Task Commits

1. **Tasks 1 + 2: Per-port VLAN computation, ASIC programming, stale cleanup, VLAN 1 bridge exclusion** - `6e29466` (feat)

## Files Created/Modified

- `crates/sfgw-net/src/switch.rs` — Full rewrite: added PortVlanConfig, PortMember, load_port_vlan_config(), iface_to_switch_port(), compute_vlan_port_map(), format_port_string(); rewrote setup_switch_vlans() to be async and DB-driven; removed build_port_string(); extended stale cleanup to 3000-3100 range; added 11 unit + integration tests

## Decisions Made

- `setup_switch_vlans` made async to read from DB directly. Caller `setup_networks` updated: `setup_switch_vlans(sw, &networks)?` → `setup_switch_vlans(sw, db).await?`
- WAN port exclusion at SQL level (`WHERE pvid > 0`) is cleaner than filtering in Rust and aligns with Phase 1 decision that pvid=0 means "not an internal VLAN port"
- VLAN 1 entry uses `map.entry(1).or_insert_with()` instead of contains_key + insert (clippy map_entry lint)
- Tasks 1 and 2 committed together since both modify only switch.rs and form one cohesive logical unit — splitting would have left the code in an invalid intermediate state

## Deviations from Plan

None — plan executed exactly as written. The tasks were logically combined into one commit (both tasks were in the same file and formed a single coherent rewrite), which is a packaging choice not a deviation.

## Issues Encountered

- One clippy warning from new code (map_entry pattern for VLAN 1 insertion) — fixed immediately before commit

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Phase 2 switch ASIC requirements fully implemented:
  - ASIC-01: per-port VLAN programming from DB config
  - ASIC-02: MGMT port isolation (port 7 only in VLAN 3000 + VLAN 1)
  - ASIC-03: VLAN 1 as void catch-all sink on ASIC, no bridge
- Blocker from STATE.md resolved: "switch.rs currently hardcodes all VLANs on all ports"
- Ready for Phase 3 (firewall) — iptables-legacy only on UDM Pro kernel 4.19

## Self-Check: PASSED

- switch.rs: FOUND
- 02-01-SUMMARY.md: FOUND
- commit 6e29466: FOUND

---
*Phase: 02-switch-asic*
*Completed: 2026-03-15*
