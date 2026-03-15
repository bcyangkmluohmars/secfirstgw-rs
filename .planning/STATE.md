# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-15)

**Core value:** Security first — default deny, zero trust, minimal attack surface
**Current focus:** Phase 1 — Data Model (v0.1.0 VLAN Trunk Model)

## Current Position

Phase: 1 of 5 (Data Model)
Plan: 0 of ? in current phase
Status: Ready to plan
Last activity: 2026-03-15 — Roadmap created, 5 phases defined for v0.1.0

Progress: [░░░░░░░░░░] 0%

## Performance Metrics

**Velocity:**
- Total plans completed: 0
- Average duration: —
- Total execution time: —

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| - | - | - | - |

**Recent Trend:**
- Last 5 plans: —
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

### Pending Todos

None yet.

### Blockers/Concerns

- DB migration must preserve non-role fields in existing v0.0.3 `interfaces` table — validate before writing migration
- switch.rs currently hardcodes "all VLANs on all ports" — full rewrite required in Phase 2
- iptables-legacy only on UDM Pro kernel 4.19 — no nf_tables, all FW work in Phase 3 must use iptables

## Session Continuity

Last session: 2026-03-15
Stopped at: Roadmap created — ready to run /gsd:plan-phase 1
Resume file: None
