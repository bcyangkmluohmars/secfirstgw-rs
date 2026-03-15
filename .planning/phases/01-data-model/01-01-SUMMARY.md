---
phase: 01-data-model
plan: 01
subsystem: database
tags: [sqlite, rusqlite, migration, vlan, pvid, schema]

# Dependency graph
requires: []
provides:
  - "Migration 005 SQL: interfaces rebuilt with pvid/tagged_vlans, role/vlan_id removed"
  - "VLAN 1 void entry in networks (disabled, no subnet, no bridge)"
  - "LAN network updated to vlan_id=10"
  - "6 upgrade-path tests proving migration correctness"
affects:
  - "02-data-model (plan 02)"
  - "02-switch-asic"
  - "03-firewall"
  - "04-api"

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "SQLite rename-create-copy-drop pattern for schema changes (no DROP COLUMN pre-3.35)"
    - "Upgrade-path tests: run migrations 001-004 manually, insert pre-migration data, apply target migration, verify"
    - "setup_pre_005 helper isolates upgrade-path test state"

key-files:
  created:
    - "crates/sfgw-db/migrations/005_vlan_trunk_model.sql"
  modified:
    - "crates/sfgw-db/src/lib.rs"

key-decisions:
  - "WAN ports get pvid=0 to signal they are outside the internal VLAN numbering space"
  - "VLAN 1 is permanently void (disabled, DROP all) — LAN is VLAN 10, not untagged"
  - "New/unconfigured ports default to pvid=10 to prevent lockout on fresh installs"
  - "SQLite rename-create-copy-drop used instead of ALTER TABLE DROP COLUMN for pre-3.35 compatibility"

patterns-established:
  - "Upgrade-path test pattern: setup_pre_005 helper runs migrations 001-004 then sets version to 4, allowing targeted migration testing"

# Metrics
duration: 2min
completed: 2026-03-15
---

# Phase 1 Plan 1: VLAN Trunk Model Data Migration Summary

**SQLite migration 005 that drops role/vlan_id from interfaces, adds pvid (AUTOINCREMENT=10) and tagged_vlans, inserts VLAN 1 void row, and moves LAN to VLAN 10 — with 6 upgrade-path tests**

## Performance

- **Duration:** ~2 min
- **Started:** 2026-03-15T04:12:24Z
- **Completed:** 2026-03-15T04:14:12Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Migration 005 SQL created using rename-create-copy-drop pattern for SQLite pre-3.35 compatibility
- Role-to-PVID mapping: lan→10, mgmt→3000, guest→3001, dmz→3002, wan→0, other→10
- VLAN 1 void entry inserted (disabled, 0.0.0.0/32, no DHCP, no bridge)
- LAN network updated to vlan_id=10 (safe: only updates NULL or 1)
- 6 new tests cover: pvid column exists, role column gone, void VLAN 1 present, LAN upgrade path, field preservation, WAN gets pvid=0
- All 12 tests pass (6 original + 6 new), clean build with zero warnings

## Task Commits

Each task was committed atomically:

1. **Task 1: Create migration 005 SQL** - `5289282` (feat)
2. **Task 2: Register migration and update sfgw-db tests** - `cf83270` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `crates/sfgw-db/migrations/005_vlan_trunk_model.sql` - Complete migration: drop role/vlan_id, add pvid/tagged_vlans, void VLAN 1, LAN VLAN 10
- `crates/sfgw-db/src/lib.rs` - Migration 005 registered, schema version updated to 5, 6 new tests added

## Decisions Made

- WAN ports get pvid=0: signals "not an internal VLAN port" — WAN is a completely separate world from internal VLAN numbering
- VLAN 1 is permanently void (disabled, no subnet): prevents accidental forwarding of untagged frames from misconfigured switches
- Default pvid=10 (not 0, not 1): prevents lockout on fresh installs where interfaces aren't yet assigned
- SQLite rename-create-copy-drop: required because ALTER TABLE DROP COLUMN is not available in SQLite < 3.35 (UDM Pro kernel 4.19 ships an older SQLite)

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Migration 005 is the foundation of v0.1.0. Schema is correct and tested.
- Plan 02 (if any) can proceed immediately.
- Phase 2 (switch ASIC) can read pvid/tagged_vlans from interfaces table.
- Phase 3 (firewall) can read void VLAN 1 and create DROP rules for it.
- Concern carried forward: switch.rs currently hardcodes "all VLANs on all ports" — full rewrite required in Phase 2.

---
*Phase: 01-data-model*
*Completed: 2026-03-15*
