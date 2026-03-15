# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-15)

**Core value:** Security first — default deny, zero trust, minimal attack surface
**Current focus:** Phase 3 — Network Enforcement (v0.1.0 VLAN Trunk Model)

## Current Position

Phase: 3 of 5 (Network Enforcement)
Plan: 1 of ? in current phase — PLAN COMPLETE
Status: Phase 03 plan 01 complete — firewall crash fixed, VLAN isolation rules added
Last activity: 2026-03-15 — Plan 03-01 complete (PVID-based zone resolution, VLAN isolation iptables rules)

Progress: [█████░░░░░] 50%

## Performance Metrics

**Velocity:**
- Total plans completed: 4
- Average duration: ~11.5 min
- Total execution time: ~46 min

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01-data-model | 2 | ~11 min | ~5.5 min |
| 02-switch-asic | 1 | ~18 min | ~18 min |
| 03-network-enforcement | 1 | ~18 min | ~18 min |

**Recent Trend:**
- Last 5 plans: 01-01 (2 min), 01-02 (9 min), 02-01 (18 min), 03-01 (18 min)
- Trend: stabilizing at ~18 min for firewall/ASIC plans

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
- [03-01] ZonePolicy.vlan_id: Option<u16> added so iptables emitter derives VLAN DROP rules without re-querying DB
- [03-01] void zone excluded from routable zone list in load_interface_zones() — DROP-only, never bridged
- [03-01] VLAN isolation rules placed before zone rules in generate_zone_ruleset() — isolation checked first
- [03-01] WAN-02/WAN-03 left to switch ASIC hardware enforcement (Phase 2) + zone DROP as defense-in-depth

### Pending Todos

None.

### Blockers/Concerns

- iptables-legacy only on UDM Pro kernel 4.19 — no nf_tables, all FW work in Phase 3 must use iptables

## Session Continuity

Last session: 2026-03-15
Stopped at: Completed 03-01-PLAN.md — PVID zone resolution fixed, VLAN isolation rules enforced
Resume file: None
