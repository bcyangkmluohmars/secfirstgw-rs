---
phase: 03-network-enforcement
plan: 01
subsystem: firewall
tags: [iptables, vlan, zone-model, pvid, sfgw-fw]

# Dependency graph
requires:
  - phase: 01-data-model
    provides: "networks table with vlan_id + zone columns, interfaces table with pvid (role column removed in migration 005)"
  - phase: 02-switch-asic
    provides: "ASIC enforces VLAN isolation at hardware level; WAN-02/WAN-03 enforcement is hardware-level complement to FW rules"
provides:
  - "load_interface_zones() using PVID + networks JOIN (runtime crash fix)"
  - "ZonePolicy.vlan_id field for dynamic VLAN isolation rule generation"
  - "VLAN isolation iptables rules (WAN-01, FW-01, FW-02) in SFGW-INPUT/SFGW-FORWARD"
affects:
  - 03-network-enforcement (future plans)
  - sfgw-fw iptables rule generation

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "PVID-based zone derivation: JOIN interfaces ON pvid = networks.vlan_id"
    - "VLAN isolation rules before zone rules in iptables chain order"
    - "Dynamic internal VLAN DROP on WAN derived from ZonePolicy.vlan_id"

key-files:
  created: []
  modified:
    - crates/sfgw-fw/src/lib.rs
    - crates/sfgw-fw/src/iptables/mod.rs
    - crates/sfgw-fw/src/iptables/tests.rs
    - crates/sfgw-fw/tests/zone_matrix_tests.rs
    - crates/sfgw-fw/src/nft.rs

key-decisions:
  - "ZonePolicy.vlan_id: Option<u16> added so iptables emitter can derive internal VLAN DROP rules without re-querying DB"
  - "void zone (VLAN 1) excluded from routable zone list in load_interface_zones() — DROP-only, never bridged"
  - "VLAN isolation rules placed BEFORE zone rules in generate_zone_ruleset() — isolation must be checked first"
  - "br-void DROP rules added as defense-in-depth regardless of WAN interface presence"
  - "WAN-02/WAN-03 left to switch ASIC hardware enforcement (Phase 2) + existing zone DROP policy as defense-in-depth"

patterns-established:
  - "VLAN isolation: emit_vlan_isolation_rules(out, zones) called after emit_default_rules, before zone emitters"
  - "Zone lookup pattern: zone_interfaces(zones, &FirewallZone::Wan) for WAN ifaces in isolation rules"

# Metrics
duration: 18min
completed: 2026-03-15
---

# Phase 3 Plan 01: Network Enforcement — PVID Zone Resolution + VLAN Isolation Summary

**Fixed runtime crash (role column removed) by rewriting load_interface_zones() to PVID+JOIN, added VLAN isolation iptables rules enforcing WAN-01/FW-01/FW-02**

## Performance

- **Duration:** ~18 min
- **Started:** 2026-03-15T00:05:37Z
- **Completed:** 2026-03-15T00:23:37Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Fixed runtime crash: `load_interface_zones()` no longer queries the removed `role` column — now uses `JOIN networks ON pvid = vlan_id`
- Added `vlan_id: Option<u16>` to `ZonePolicy` struct, populated from the networks table for internal zones and `None` for WAN
- Implemented `emit_vlan_isolation_rules()` enforcing WAN-01 (internal VLANs blocked on WAN) and FW-02 (VLAN 1 void DROP); FW-01 confirmed by test (LAN zone uses br-lan, not br-1)
- Zero compile warnings, zero test failures across workspace (121+ tests pass)

## Task Commits

1. **Task 1: Rewrite load_interface_zones() to use PVID + networks JOIN** - `5cb4780` (feat)
2. **Task 2: Add VLAN isolation rules to iptables generation** - `640ca64` (feat)

## Files Created/Modified

- `/run/media/kevin/KioxiaNVMe/sec/secfirstgw-rs/crates/sfgw-fw/src/lib.rs` - Rewrote `load_interface_zones()` with PVID JOIN; added `vlan_id` to `ZonePolicy`
- `/run/media/kevin/KioxiaNVMe/sec/secfirstgw-rs/crates/sfgw-fw/src/iptables/mod.rs` - Added `emit_vlan_isolation_rules()` and call site in `generate_zone_ruleset()`
- `/run/media/kevin/KioxiaNVMe/sec/secfirstgw-rs/crates/sfgw-fw/src/iptables/tests.rs` - Added 5 new VLAN isolation tests + updated ZonePolicy literals
- `/run/media/kevin/KioxiaNVMe/sec/secfirstgw-rs/crates/sfgw-fw/tests/zone_matrix_tests.rs` - Updated ZonePolicy literals with vlan_id
- `/run/media/kevin/KioxiaNVMe/sec/secfirstgw-rs/crates/sfgw-fw/src/nft.rs` - Updated ZonePolicy literals with vlan_id

## Decisions Made

- `ZonePolicy.vlan_id: Option<u16>` added so the iptables emitter can derive internal VLAN DROP rules dynamically without re-querying the DB
- `void` zone excluded from the routable zone list — VLAN 1 is DROP-only and never bridged
- VLAN isolation rules placed before zone rules in the filter chain so they are evaluated first
- `br-void` DROP rules always emitted as defense-in-depth regardless of WAN interface presence
- WAN-02/WAN-03 (provider VLANs on internal interfaces) left to switch ASIC (Phase 2) + existing zone DROP policy

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Updated ZonePolicy construction in nft.rs and zone_matrix_tests.rs**
- **Found during:** Task 1 (adding vlan_id field to ZonePolicy)
- **Issue:** Adding a new non-optional field to a struct breaks all existing construction sites — build fails
- **Fix:** Added `vlan_id: None` (WAN) or `vlan_id: Some(vid)` to all ZonePolicy literals in nft.rs, zone_matrix_tests.rs, and both test files
- **Files modified:** `crates/sfgw-fw/src/nft.rs`, `crates/sfgw-fw/tests/zone_matrix_tests.rs`
- **Verification:** `cargo build -p sfgw-fw` clean, all tests pass
- **Committed in:** `5cb4780` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking — struct field propagation)
**Impact on plan:** Required to compile. No scope creep.

## Issues Encountered

None — plan executed as specified.

## Self-Check

- [x] `crates/sfgw-fw/src/lib.rs` exists with `pvid = n.vlan_id` JOIN pattern
- [x] `crates/sfgw-fw/src/iptables/mod.rs` contains `emit_vlan_isolation_rules`
- [x] Commits `5cb4780` and `640ca64` exist in git log
- [x] `cargo test -p sfgw-fw` — 59 + 58 + 4 = 121 tests, 0 failures
- [x] `grep -c '"role"' crates/sfgw-fw/src/lib.rs` returns 0 SQL role references

## Self-Check: PASSED

## Next Phase Readiness

- Firewall crate is now fully consistent with the PVID-based data model from Phase 1
- VLAN isolation enforcement is in place: WAN-01, FW-01, FW-02 enforced by iptables
- Phase 3 Plan 02 can proceed (if applicable) — no blockers from this plan

---
*Phase: 03-network-enforcement*
*Completed: 2026-03-15*
