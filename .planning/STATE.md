# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-15)

**Core value:** Security first — default deny, zero trust, minimal attack surface
**Current focus:** Phase 5 — Web UI (v0.1.0 VLAN Trunk Model)

## Current Position

Phase: 5 of 5 (Web UI)
Plan: 2 of ? in current phase — CHECKPOINT (human-verify)
Status: Phase 05 plan 02 Task 1 complete — port config panel built, awaiting human verification (Task 2)
Last activity: 2026-03-15 — Plan 05-02 Task 1 complete (port config panel with PVID selector + tagged VLAN checklist)

Progress: [███████░░░] 70%

## Performance Metrics

**Velocity:**
- Total plans completed: 6
- Average duration: ~11 min
- Total execution time: ~67 min

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01-data-model | 2 | ~11 min | ~5.5 min |
| 02-switch-asic | 1 | ~18 min | ~18 min |
| 03-network-enforcement | 1 | ~18 min | ~18 min |
| 04-api | 1 | ~18 min | ~18 min |
| 05-web-ui | 1 | ~3 min | ~3 min |

**Recent Trend:**
- Last 5 plans: 01-02 (9 min), 02-01 (18 min), 03-01 (18 min), 04-01 (18 min), 05-01 (3 min)
- Trend: UI work significantly faster than backend; /api/v1/interfaces already returned pvid/tagged_vlans so no extra API work needed

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
- [Phase 04-api]: Port PUT releases DB lock before reconfigure — both reconfig fns acquire their own lock
- [Phase 04-api]: Port update reconfig failure returns 200 — DB is source of truth, ASIC syncs on next boot
- [Phase 04-api]: Zone-interface association uses pvid = vlan_id match (consistent with Phase 3 PVID zone resolution)
- [05-01] NetworkInterface updated to include pvid/tagged_vlans — /api/v1/interfaces already returns them, no per-port calls needed
- [05-01] Switch panel uses pvid exclusively for zone resolution; zone cards section still groups by role field
- [05-02] isPhysicalPort() routes clicks: physical→config panel, bridge/VLAN sub-interface→old edit modal
- [05-02] pvidOptions includes WAN sentinel (pvid=0) at top; taggedDisabled for WAN/void ports

### Pending Todos

None.

### Blockers/Concerns

- iptables-legacy only on UDM Pro kernel 4.19 — no nf_tables, all FW work in Phase 3 must use iptables

## Session Continuity

Last session: 2026-03-15
Stopped at: 05-02-PLAN.md Task 2 checkpoint (human-verify) — port config panel built, awaiting user verification
Resume file: None
