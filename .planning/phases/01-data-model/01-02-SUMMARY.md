---
phase: 01-data-model
plan: 02
subsystem: network
tags: [rust, sfgw-net, sfgw-api, sfgw-cli, pvid, tagged-vlans, vlan, interface-model]

# Dependency graph
requires:
  - "01-01 (migration 005 adds pvid/tagged_vlans columns)"
provides:
  - "InterfaceInfo struct with pvid:u16 + tagged_vlans:Vec<u16>"
  - "configure() writes pvid/tagged_vlans to DB"
  - "list_interfaces() reads pvid/tagged_vlans from DB"
  - "API endpoints return pvid/tagged_vlans in JSON"
  - "switch.rs uses VLAN 10 for LAN, skips void zone"
affects:
  - "02-switch-asic (reads pvid/tagged_vlans per-interface from DB)"
  - "03-firewall (reads void VLAN 1, creates DROP rules)"
  - "04-api (pvid/tagged_vlans exposed to frontend)"

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "pvid=0 sentinel: signals WAN port (outside internal VLAN numbering space)"
    - "Non-void count guard: migration always seeds void, seeding guard checks zone != void"
    - "Zone-driven tagging: build_port_string uses zone param not VLAN number to drive port behavior"

key-files:
  created: []
  modified:
    - "crates/sfgw-net/src/lib.rs"
    - "crates/sfgw-net/src/switch.rs"
    - "crates/sfgw-net/src/wan.rs"
    - "crates/sfgw-api/src/lib.rs"
    - "crates/sfgw-cli/src/main.rs"

key-decisions:
  - "Network seeding guard changed to count non-void networks: migration 005 always inserts void, so COUNT(*)==0 never fires post-migration"
  - "Void VLAN 1 removed from configure() defaults: migration handles it via INSERT OR IGNORE, no double-insert needed"
  - "interface_delete() identifies VLAN sub-interfaces by dot in name, not vlan_id IS NOT NULL (column removed)"
  - "wan.rs set_wan_config sets pvid=0 (not role=wan); remove_wan_config reverts pvid to 10 (LAN default)"

patterns-established:
  - "guess_pvid() returns u16 PVID values: 0 for non-VLAN-port types (loopback/VPN/container/WAN), 10 for LAN"
  - "guess_tagged_vlans() always returns [] — tagged VLANs never auto-detected, always user-configured"
  - "build_port_string(vlan_id, zone, sw) uses zone for tagging policy, not VLAN number"

# Metrics
duration: 9min
completed: 2026-03-15
---

# Phase 1 Plan 2: Rust Code Update for PVID + Tagged VLAN Trunk Model Summary

**Replace role-based InterfaceInfo with pvid:u16 + tagged_vlans:Vec<u16> across sfgw-net, sfgw-api, and sfgw-cli — all SQL queries, struct fields, and API handlers updated to match migration 005 schema**

## Performance

- **Duration:** ~9 min
- **Started:** 2026-03-15T04:16:35Z
- **Completed:** 2026-03-15T04:25:54Z
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments

- InterfaceInfo.role removed; pvid:u16 and tagged_vlans:Vec<u16> added with full doc comments
- configure() upserts pvid/tagged_vlans (only on first discovery, never overwritten)
- list_interfaces() reads pvid/tagged_vlans via i32→u16 clamping and JSON parse
- detect_interfaces_for_platform() assigns pvid=0 (WAN), pvid=3000 (MGMT), pvid=10 (LAN)
- guess_role() replaced by guess_pvid() returning u16 + guess_tagged_vlans() always returning []
- WAN auto-creation loop: pvid==0 replaces role=="wan"
- Network seeding guard: counts non-void networks (migration always seeds void, COUNT(*) is always >=1)
- LAN default changed to vlan_id=Some(10); void removed from configure() defaults (migration owns it)
- switch.rs: LAN uses n.vlan_id.unwrap_or(10), void zone skipped in switch and bridge setup
- build_port_string() takes zone: &str instead of checking vlan_id==1
- API interfaces_handler: returns pvid/tagged_vlans JSON (no role/vlan_id)
- API interface_update: accepts pvid (0 or 1-4094) and tagged_vlans with validation
- API interface_create_vlan: INSERT with pvid/tagged_vlans, removed role param
- API interface_delete: identifies VLAN sub-interfaces by dot in name
- sfgw-cli: displays pvid or "WAN" label instead of role string
- wan.rs: set_wan_config sets pvid=0; remove_wan_config reverts pvid=10
- Full workspace builds with zero errors, zero warnings
- All 69 sfgw-net tests pass, all workspace tests pass

## Task Commits

1. **Task 1: Update sfgw-net InterfaceInfo, configure(), list_interfaces(), seeding** - `f767dfa` (feat)
2. **Task 2: Update sfgw-net switch.rs for VLAN 10 LAN** - `7eef431` (feat)
3. **Task 3: Update sfgw-api handlers and sfgw-cli for PVID model** - `2b6af1c` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `crates/sfgw-net/src/lib.rs` - InterfaceInfo pvid/tagged_vlans, configure, list_interfaces, guess_pvid, seeding, all tests updated
- `crates/sfgw-net/src/switch.rs` - VLAN 10 LAN, void zone skipped, build_port_string zone param
- `crates/sfgw-net/src/wan.rs` - pvid=0 on WAN config save, pvid=10 revert on remove
- `crates/sfgw-api/src/lib.rs` - interfaces_handler, interface_update, interface_create_vlan, interface_delete updated
- `crates/sfgw-cli/src/main.rs` - display pvid/WAN instead of role

## Decisions Made

- Network seeding guard counts non-void networks: `migration 005` always inserts the void entry via `INSERT OR IGNORE`, so `COUNT(*) FROM networks` is always at least 1 after migrations. The seeding trigger changed to `COUNT(*) FROM networks WHERE zone != 'void'` so configure() correctly seeds LAN/MGMT/Guest/DMZ on fresh installs.
- Void VLAN 1 removed from configure() defaults: migration 005 owns the void entry. Having it in configure() defaults would cause a duplicate-key conflict.
- interface_delete identifies VLAN sub-interfaces by dot in name (e.g. "eth0.10") rather than `vlan_id IS NOT NULL` — the vlan_id column no longer exists in the interfaces table.
- wan.rs WAN marking updated: set_wan_config now sets pvid=0, remove_wan_config reverts to pvid=10 (LAN default).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] wan.rs still referenced role column**
- **Found during:** Task 1 (cargo test failure)
- **Issue:** wan.rs `set_wan_config` executed `UPDATE interfaces SET role = 'wan'` and `remove_wan_config` used `role = 'lan'` — both failed at runtime because the role column was removed in migration 005
- **Fix:** `set_wan_config` now sets `pvid = 0`; `remove_wan_config` now reverts `pvid = 10 WHERE pvid = 0`
- **Files modified:** `crates/sfgw-net/src/wan.rs`
- **Commit:** included in f767dfa

**2. [Rule 1 - Bug] Network seeding guard never fired post-migration-005**
- **Found during:** Task 1 (test failures for test_default_networks_seeded_on_empty_db)
- **Issue:** Migration 005 inserts a void row into networks via `INSERT OR IGNORE`, so `COUNT(*) FROM networks` is always 1 after migrations. The configure() guard `if network_count == 0` never fired, meaning LAN/MGMT/Guest/DMZ were never seeded on fresh installs.
- **Fix:** Changed guard to `COUNT(*) FROM networks WHERE zone != 'void'`; removed void from configure() defaults (migration handles it)
- **Files modified:** `crates/sfgw-net/src/lib.rs`
- **Commit:** included in f767dfa

**3. [Rule 3 - Blocking] sfgw-cli referenced iface.role preventing workspace build**
- **Found during:** Task 3 (cargo build failure)
- **Issue:** `crates/sfgw-cli/src/main.rs:258` referenced `iface.role` which no longer exists on InterfaceInfo
- **Fix:** Display `pvid=N` or "WAN" (for pvid=0) in the interfaces listing
- **Files modified:** `crates/sfgw-cli/src/main.rs`
- **Commit:** 2b6af1c

## Issues Encountered

None beyond the deviations above.

## User Setup Required

None.

## Next Phase Readiness

- All Rust code now matches migration 005 schema.
- InterfaceInfo.pvid and tagged_vlans are the canonical interface data model.
- Phase 2 (switch ASIC) can read per-interface pvid/tagged_vlans and program the hardware switch accordingly.
- Phase 3 (firewall) can read void VLAN 1 from networks and create DROP rules.
- Concern from Plan 01 remains: switch.rs hardcodes "all VLANs on all ports" — full per-port PVID rewrite required in Phase 2 (ASIC-01/02/03).

---
*Phase: 01-data-model*
*Completed: 2026-03-15*
