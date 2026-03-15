# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-15)

**Core value:** Security first — default deny, zero trust, minimal attack surface
**Current focus:** Phase 1 — Data Model (v0.1.0 VLAN Trunk Model)

## Current Position

Phase: 1 of 5 (Data Model)
Plan: 1 of 2 in current phase
Status: In progress — plan 01 complete, plan 02 pending
Last activity: 2026-03-15 — Plan 01-01 complete (migration 005, 12/12 tests passing)

Progress: [█░░░░░░░░░] 10%

## Performance Metrics

**Velocity:**
- Total plans completed: 1
- Average duration: ~2 min
- Total execution time: ~2 min

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01-data-model | 1 | ~2 min | ~2 min |

**Recent Trend:**
- Last 5 plans: 01-01 (2 min)
- Trend: —

*Updated after each plan completion*

## Accumulated Context

### Decisions

Decisions logged in PROJECT.md Key Decisions table. Key decisions for current work:

- VLAN 1 = void (DROP all), LAN = VLAN 10 — safest defaults, avoids industry "untagged mess"
- Per-port PVID + tagged VLAN list replaces single `role` field in interfaces table
- WAN ports completely isolated from internal VLAN numbering space — two separate worlds
- Switch ASIC config (swconfig) is a hardware addon: runs only when UDM Pro board detected at startup
- New/unconfigured ports default to pvid=10 (LAN) — prevents lockout on fresh installs
- [01-01] WAN pvid=0 signals "not an internal VLAN port" — value chosen to be obviously invalid in VLAN range
- [01-01] SQLite rename-create-copy-drop used for DROP COLUMN compat with SQLite < 3.35

### Pending Todos

None.

### Blockers/Concerns

- switch.rs currently hardcodes "all VLANs on all ports" — full rewrite required in Phase 2
- iptables-legacy only on UDM Pro kernel 4.19 — no nf_tables, all FW work in Phase 3 must use iptables

## Session Continuity

Last session: 2026-03-15
Stopped at: Completed 01-01-PLAN.md — ready for 01-02-PLAN.md
Resume file: None
