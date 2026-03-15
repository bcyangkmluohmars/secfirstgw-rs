# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-15)

**Core value:** Security first — default deny, zero trust, minimal attack surface
**Current focus:** Phase 3 — Network Enforcement (v0.1.0 VLAN Trunk Model)

## Current Position

Phase: 2 of 5 (Switch ASIC)
Plan: 1 of 1 in current phase — PHASE COMPLETE
Status: Phase 02 complete — all plans done
Last activity: 2026-03-15 — Plan 02-01 complete (switch ASIC rewritten to per-port PVID model, 75 tests pass)

Progress: [████░░░░░░] 40%

## Performance Metrics

**Velocity:**
- Total plans completed: 3
- Average duration: ~9.3 min
- Total execution time: ~28 min

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01-data-model | 2 | ~11 min | ~5.5 min |
| 02-switch-asic | 1 | ~18 min | ~18 min |

**Recent Trend:**
- Last 5 plans: 01-01 (2 min), 01-02 (9 min), 02-01 (18 min)
- Trend: increasing (larger plans)

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
- [01-02] Network seeding guard counts non-void networks: migration 005 always seeds void, so COUNT(*)==0 never fires post-migration
- [01-02] Void VLAN 1 owned by migration 005, not configure() defaults — migration uses INSERT OR IGNORE
- [01-02] interface_delete identifies VLAN sub-interfaces by dot in name (not vlan_id IS NOT NULL)
- [01-02] wan.rs set_wan_config sets pvid=0; remove_wan_config reverts pvid=10
- [02-01] setup_switch_vlans is now async (reads DB directly); WAN excluded at SQL level (WHERE pvid > 0)
- [02-01] VLAN 1 catch-all sink always programmed on ASIC; no Linux bridge (setup_bridges skips void)
- [02-01] Stale cleanup covers 3000-3100 range (zone VLANs) in addition to 1-100

### Pending Todos

None.

### Blockers/Concerns

- iptables-legacy only on UDM Pro kernel 4.19 — no nf_tables, all FW work in Phase 3 must use iptables

## Session Continuity

Last session: 2026-03-15
Stopped at: Completed 02-01-PLAN.md — Phase 02 complete, ready for Phase 03
Resume file: None
