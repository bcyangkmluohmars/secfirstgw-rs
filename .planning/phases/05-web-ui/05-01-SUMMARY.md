---
phase: 05-web-ui
plan: 01
subsystem: web-ui
tags: [react, typescript, vlan, pvid, zones, switch-panel, tailwind]

# Dependency graph
requires:
  - phase: 04-api
    provides: GET /api/v1/ports/{name}, GET /api/v1/zones, GET/PUT /api/v1/ports/{name}

provides:
  - api.ts exports PortConfig, ZoneInfo types and getPort/updatePort/getZones/getZone methods
  - Switch panel colored by PVID zone (primary) with tagged VLAN dots
  - Void ports (pvid=1) dark/inactive with VOID label
  - NetworkInterface type updated to include pvid and tagged_vlans fields

affects:
  - web/src/pages/Interfaces.tsx — switch panel visual model
  - web/src/api.ts — TypeScript types and client methods

# Tech tracking
tech-stack:
  added: []
  patterns:
    - vlanToZone map (vlan_id → ZoneInfo) built from api.getZones() for O(1) PVID lookup
    - pvid2Zone() resolver — 0=wan, 1=void, N=zone by vlan_id match
    - Tagged VLAN dots max-3 with +N overflow counter

key-files:
  created: []
  modified:
    - web/src/api.ts
    - web/src/pages/Interfaces.tsx

key-decisions:
  - "NetworkInterface type updated to include pvid and tagged_vlans — /api/v1/interfaces already returns them, no per-port API calls needed"
  - "Zone cards section still groups by role field — switch panel uses pvid exclusively"
  - "pvid=1 signals void (DROP-all VLAN 1) — rendered dark/inactive with VOID label, not same as link-down"
  - "pvid=0 signals WAN — no tagged VLAN dots, keep existing WAN red styling"

# Metrics
duration: 3min
completed: 2026-03-15
---

# Phase 5 Plan 1: Switch Panel PVID Visualization Summary

**PVID-based switch panel coloring with tagged VLAN dots using Zone API for runtime color resolution**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-03-15T06:21:20Z
- **Completed:** 2026-03-15T06:24:30Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Added `PortConfig` and `ZoneInfo` TypeScript interfaces to `api.ts` matching Phase 4 API responses
- Updated `NetworkInterface` to include `pvid: number` and `tagged_vlans: number[]` (already returned by `/api/v1/interfaces`)
- Added `api.getPort()`, `api.updatePort()`, `api.getZones()`, `api.getZone()` client methods
- Rewrote switch panel zone resolution from role-field to PVID-based: `pvid2Zone()` maps pvid → zone name via `vlanToZone` lookup
- Void ports (pvid=1) render dark navy with VOID label — intentionally disabled appearance distinct from link-down
- WAN ports (pvid=0) remain red with no tagged VLAN dots
- Tagged VLAN dots (w-1.5 h-1.5 colored dots) rendered per-port for each tagged VLAN, skipping PVID, max 3 shown + "+N" counter
- Zone legend now driven by `api.getZones()` data, always includes void indicator
- Both `renderDeviceSwitch` (UDM Pro board) and `renderGenericSwitch` (generic grid) updated
- Zone cards section below switch panel still groups by role field (unchanged)
- TypeScript compiles clean, production build succeeds (366KB bundle)

## Task Commits

1. **Task 1: Add PortConfig/ZoneInfo types and API methods** — `ce27088`
2. **Task 2: Rewrite switch panel with PVID zone coloring and tagged VLAN dots** — `4627cf4`

## Files Created/Modified

- `web/src/api.ts` — Added PortConfig, ZoneInfo, updated NetworkInterface, added 4 API methods
- `web/src/pages/Interfaces.tsx` — Complete switch panel rewrite with PVID model, zone API integration

## Decisions Made

- Used option (a) from the plan: updated `NetworkInterface` to include `pvid` and `tagged_vlans` — the `/api/v1/interfaces` endpoint already returns them (confirmed in `lib.rs` line 984). No per-port API calls needed on load.
- Zone cards section (`sortedZones.map(...)`) continues using `iface.role` for grouping — the plan explicitly allows this. Only the switch panel buttons use PVID-based resolution.
- `pvid === 1` is the void sentinel value — rendered with `bg-navy-950 border-navy-800/20 opacity-60` + VOID label. Opacity 60 vs 50 for "link down" to distinguish intentionally-disabled from broken.
- `pvid === 0` is the WAN sentinel — no tagged dots since WAN lives outside internal VLAN numbering.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None.

## Next Phase Readiness

- Switch panel now shows multi-VLAN trunk configuration visually
- Tagged VLAN assignments are visible at a glance per port
- Void ports clearly distinct from active or link-down ports
- Phase 5 plan 01 ready; next plan can build on this visual foundation

## Self-Check: PASSED

- `web/src/api.ts` — FOUND
- `web/src/pages/Interfaces.tsx` — FOUND
- Commit `ce27088` (Task 1) — FOUND
- Commit `4627cf4` (Task 2) — FOUND
- `npx tsc --noEmit` — PASS (no output = no errors)
- `npm run build` — PASS (built in 1.80s)
- `api.getZones` in Interfaces.tsx — FOUND (line 73)
- `pvid` in Interfaces.tsx — FOUND (multiple)
- `tagged_vlans` in Interfaces.tsx — FOUND
- `void` handling in Interfaces.tsx — FOUND (pvid === 1 → 'void' zone)

---
*Phase: 05-web-ui*
*Completed: 2026-03-15*
