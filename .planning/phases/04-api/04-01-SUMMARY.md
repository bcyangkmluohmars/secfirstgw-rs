---
phase: 04-api
plan: 01
subsystem: api
tags: [axum, rest, vlan, pvid, zones, switch-asic, iptables]

# Dependency graph
requires:
  - phase: 03-network-enforcement
    provides: PVID-based zone resolution and VLAN isolation iptables rules
  - phase: 02-switch-asic
    provides: setup_networks and SwitchLayout for hardware ASIC programming
  - phase: 01-data-model
    provides: interfaces table with pvid/tagged_vlans columns, networks table with vlan_id

provides:
  - GET /api/v1/ports/{name} — per-port PVID/tagged-VLAN read endpoint (no role field)
  - PUT /api/v1/ports/{name} — per-port VLAN config write with live ASIC+FW reconfiguration
  - GET /api/v1/zones — list all network zones with vlan_id
  - GET /api/v1/zones/{zone} — single zone with vlan_id and associated interface names
  - pub async fn reconfigure_networks(db) in sfgw-net/switch.rs

affects:
  - 05-web-ui (consumes these endpoints for port and zone configuration UI)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - DB lock released before calling reconfigure_networks (avoids deadlock on async DB access)
    - Reconfig failures logged but do not fail the 200 response (DB is source of truth)
    - Port name validation (path traversal rejection) before DB query as defense-in-depth
    - Zone-interface association via pvid JOIN (same vlan_id as zone's vlan_id)

key-files:
  created: []
  modified:
    - crates/sfgw-net/src/switch.rs
    - crates/sfgw-api/src/lib.rs

key-decisions:
  - "Port PUT releases DB lock before reconfigure_networks/apply_rules — both acquire their own locks"
  - "Reconfig failure on port update returns 200 — DB is source of truth, ASIC syncs on next boot"
  - "is_valid_port_name() rejects dot/slash/backslash — defense-in-depth even with parameterized SQL"
  - "Zone interface association uses pvid = vlan_id match (same model as PVID zone resolution in Phase 3)"

patterns-established:
  - "Port/zone endpoints return no role field — role is a user management concept, not a network concept"
  - "reconfigure_networks detects board at call time (same 5-line pattern as detect_interfaces_for_platform)"

# Metrics
duration: 18min
completed: 2026-03-15
---

# Phase 4 Plan 1: Port and Zone API Endpoints Summary

**Port GET/PUT and zone GET endpoints with live ASIC+firewall reconfiguration on pvid/tagged_vlans changes**

## Performance

- **Duration:** ~18 min
- **Started:** 2026-03-15T05:48:06Z
- **Completed:** 2026-03-15T06:06:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Added `pub async fn reconfigure_networks(db)` to `sfgw-net/switch.rs` — detects board at call time and delegates to `setup_networks`, callable from API layer without needing a `SwitchLayout` argument
- Added GET/PUT `/api/v1/ports/{name}` with port name path-traversal validation, pvid/tagged_vlans validation identical to `interface_update`, and post-write switch+firewall reconfiguration
- Added GET `/api/v1/zones` and GET `/api/v1/zones/{zone}` exposing VLAN IDs and zone-interface associations via pvid matching
- Registered all four routes behind auth + E2EE middleware in `protected_routes`
- Added 7 unit tests covering query shape, update persistence, pvid validation, zone vlan_id correctness, and zone-interface association

## Task Commits

1. **Task 1 + Task 2: Port/zone handlers + integration tests** - `03a9bf4` (feat)

**Plan metadata:** (docs commit — next)

## Files Created/Modified

- `crates/sfgw-net/src/switch.rs` — Added `reconfigure_networks` public function
- `crates/sfgw-api/src/lib.rs` — Port GET/PUT handlers, zone list/get handlers, route registrations, 7 unit tests

## Decisions Made

- Port PUT releases the DB lock in a block before calling `reconfigure_networks` and `apply_rules` — both functions acquire their own DB lock internally, so holding the outer lock would deadlock on the async mutex
- Reconfiguration failure returns 200 (not 500) — the DB write succeeded and is the source of truth; the ASIC and firewall will be brought into sync on the next boot or explicit apply
- `is_valid_port_name()` rejects `.`, `/`, `\` before the DB query — defense-in-depth per CLAUDE.md, even though parameterized SQL makes injection impossible
- Zone-interface association uses `WHERE pvid = vlan_id` — consistent with how Phase 3 resolves zones from PVID

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Port and zone endpoints are ready for Phase 5 (Web UI) consumption
- The web UI can read per-port VLAN config and write it with immediate live effect
- Zone page can show which interfaces belong to each zone
- No blockers

## Self-Check: PASSED

- `crates/sfgw-net/src/switch.rs` — FOUND
- `crates/sfgw-api/src/lib.rs` — FOUND
- Commit `03a9bf4` — FOUND

---
*Phase: 04-api*
*Completed: 2026-03-15*
