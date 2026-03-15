---
phase: 05-web-ui
plan: 02
subsystem: web-ui
tags: [react, typescript, vlan, pvid, port-config, modal, zones, tailwind]

# Dependency graph
requires:
  - phase: 05-01
    provides: pvid/tagged_vlans in NetworkInterface, vlanToZone map, pvid2Zone(), zone API data
  - phase: 04-api
    provides: PUT /api/v1/ports/{name}, GET /api/v1/zones

provides:
  - Port config panel (Modal size=lg) opened on physical port click in both switch panel variants
  - PVID radio selector built from live zone API data
  - Tagged VLAN checkbox list (excludes PVID zone, void, WAN)
  - api.updatePort() integration — live apply without page reload

affects:
  - web/src/pages/Interfaces.tsx — port click routing, new config panel, state management

# Tech tracking
tech-stack:
  added: []
  patterns:
    - isPhysicalPort() — routes clicks: physical→config panel, bridge/VLAN sub-interface→old edit modal
    - pvidOptions[] built from zones API — WAN sentinel (pvid=0) first, void last, zones by vlan_id
    - taggedDisabled flag — WAN/void ports cannot carry tagged VLANs, section visually dimmed
    - await load() after save — live switch panel refresh with no page reload

key-files:
  created: []
  modified:
    - web/src/pages/Interfaces.tsx

key-decisions:
  - "Physical port routing: isPhysicalPort() = !startsWith('br-') && !includes('.') — bridges and VLAN sub-interfaces keep old edit modal"
  - "pvidOptions includes WAN (pvid=0) sentinel at top — consistent with pvid2Zone() model from Plan 01"
  - "taggedOptions filters out void, WAN, and the current PVID zone — prevents invalid/redundant selections"
  - "taggedDisabled for pvid=0 and pvid=1 — WAN ports exist outside internal VLAN numbering; void ports carry nothing"

# Metrics
duration: ~8min (checkpoint pending)
completed: 2026-03-15
---

# Phase 5 Plan 2: Port Config Panel Summary

**Interactive port config panel with PVID radio selector and tagged VLAN checklist — live apply via PUT /api/v1/ports/{name}**

## Status

CHECKPOINT PENDING — Task 1 complete and committed. Task 2 (human verification) awaiting user confirmation.

## Performance

- **Duration:** ~8 min (checkpoint pending)
- **Started:** 2026-03-15
- **Tasks:** 1/2 complete
- **Files modified:** 1

## Accomplishments

### Task 1 (Complete)

- Added `configPort`, `configPvid`, `configTagged`, `saving` state for port config panel
- Added `openPortConfig()` — uses pvid/tagged_vlans from NetworkInterface directly (no extra API call on load); falls back to `api.getPort()` if missing
- Added `handlePortClick()` — routes physical ports to config panel, bridges/VLAN sub-interfaces to old edit modal
- Added `toggleTaggedVlan()` — checkbox toggle helper for tagged VLAN list
- Added `handleSavePortConfig()` — calls `api.updatePort()`, shows toast, closes panel, calls `load()` for live refresh
- Built `pvidOptions[]` from zones API: WAN sentinel (pvid=0) at top, then zones sorted by vlan_id, void last
- Config panel Modal (size=lg) with 4 sections: port info bar, PVID radio list, tagged VLAN checklist, Save/Cancel buttons
- `taggedDisabled` flag dims and disables tagged VLAN section for WAN (pvid=0) and void (pvid=1) ports
- Wired `handlePortClick()` into both `renderDeviceSwitch` and `renderGenericSwitch` port buttons
- TypeScript clean (`tsc --noEmit` zero output), production build passes (371KB, 1.77s)

## Task Commits

1. **Task 1: Port config panel with PVID selector and tagged VLAN checklist** — `c5eee48`

## Files Created/Modified

- `web/src/pages/Interfaces.tsx` — port click routing, new config panel state + handlers + JSX, old edit modal preserved for bridges/VLANs

## Decisions Made

- `isPhysicalPort()` defined as `!name.startsWith('br-') && !name.includes('.')` — correctly identifies eth0, eth1 etc. as physical; br-lan, eth0.100 go to old modal
- `openPortConfig()` prefers iface.pvid/tagged_vlans from the already-loaded interfaces list — avoids extra API round-trip on every port click. Falls back to `api.getPort()` only if somehow missing
- PVID selector when changed also strips the newly-selected VLAN from `configTagged` — prevents a VLAN from being both PVID and tagged simultaneously
- Tagged options exclude WAN zone by name in addition to the void filter — WAN has no vlan_id but defensive check added

## Deviations from Plan

None — plan executed exactly as written.

## User Setup Required

None.

## Self-Check: PARTIAL (checkpoint pending)

- `web/src/pages/Interfaces.tsx` — FOUND
- Commit `c5eee48` (Task 1) — FOUND
- `npx tsc --noEmit` — PASS (no output)
- `npm run build` — PASS (371KB, 1.77s)
- `handlePortClick` in Interfaces.tsx — present (routes physical vs bridge/VLAN)
- `openPortConfig` in Interfaces.tsx — present
- `api.updatePort` call in handleSavePortConfig — present
- `await load()` after save — present

Full self-check pending Task 2 human verification.

---
*Phase: 05-web-ui*
*Completed: 2026-03-15 (checkpoint pending)*
