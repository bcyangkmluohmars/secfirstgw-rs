# State

## Current Position

Phase: Not started (defining requirements)
Plan: —
Status: Defining requirements
Last activity: 2026-03-15 — Milestone v0.1.0 started

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-15)

**Core value:** Security first — default deny, zero trust, minimal attack surface
**Current focus:** VLAN Trunk Model

## Accumulated Context

- UDM Pro board detection centralized in sfgw-hal (board_id ea15, reads /proc/ubnthal/board key=value format)
- switch.rs already configures all VLANs on all LAN ports (hardcoded) — needs to become per-port configurable
- interfaces table has `role` column — needs migration to PVID-based model
- networks table has zone/vlan_id/subnet/gateway — this is the zone→VLAN mapping
- WAN config is separate (wan table, WAN page in UI) — must stay isolated from internal VLANs
- Toast context was causing 429 retry loops (fixed with useMemo on context value)
- Frontend uses React + TypeScript + Tailwind, components in web/src/components/ui
