---
phase: 01-data-model
verified: 2026-03-15T04:29:17Z
status: passed
score: 15/15 must-haves verified
re_verification: false
---

# Phase 1: Data Model Verification Report

**Phase Goal:** The internal representation of ports, zones, and VLANs correctly reflects the trunk model — zones own VLANs, ports have one untagged PVID and a list of tagged VLANs, and VLAN 1 is void by definition
**Verified:** 2026-03-15T04:29:17Z
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|---------|
| 1 | interfaces table has `pvid` (INTEGER NOT NULL DEFAULT 10) and `tagged_vlans` (TEXT NOT NULL DEFAULT '[]') columns | VERIFIED | `005_vlan_trunk_model.sql` lines 28-29; `test_migration_005_interfaces_has_pvid_column` passes |
| 2 | interfaces table has no `role` column after migration | VERIFIED | Migration drops `interfaces_old`; `test_migration_005_interfaces_no_role_column` confirms `SELECT role FROM interfaces` errors |
| 3 | networks table has VLAN 1 void entry (`zone='void'`, `enabled=0`, no bridge) | VERIFIED | Migration SQL line 55-56 `INSERT OR IGNORE … zone='void', vlan_id=1, enabled=0`; `test_migration_005_void_vlan_exists` passes; `setup_bridges` explicitly skips void zone |
| 4 | LAN network row has `vlan_id=10` (not NULL or 1) | VERIFIED | Migration SQL line 61 `UPDATE networks SET vlan_id = 10 WHERE zone = 'lan' AND (vlan_id IS NULL OR vlan_id = 1)`; `test_migration_005_lan_vlan_10` passes; seeding defaults `Some(10)` for LAN |
| 5 | Existing v0.0.3 interface rows preserve name, mac, ips, mtu, is_up, enabled, config after migration | VERIFIED | `test_migration_005_preserves_non_role_fields` verifies all 7 non-role fields survive rename-create-copy-drop |
| 6 | Existing `role='lan'` interfaces get `pvid=10`, `role='wan'` get `pvid=0` | VERIFIED | CASE expression in migration SQL; `test_migration_005_lan_vlan_10` (pvid=10) and `test_migration_005_wan_gets_pvid_zero` (pvid=0) pass |
| 7 | Schema version is 5 after migration | VERIFIED | `test_schema_version` and `test_idempotent_migrations_on_same_db` both assert version "5" and pass |
| 8 | `InterfaceInfo` struct has `pvid: u16` and `tagged_vlans: Vec<u16>` (no `role` field) | VERIFIED | `sfgw-net/src/lib.rs` lines 65-67; no `role` field anywhere in sfgw-net source |
| 9 | `configure()` inserts with `pvid`/`tagged_vlans`, only on first discovery | VERIFIED | `lib.rs` lines 92-98: INSERT with pvid/tagged_vlans, ON CONFLICT only updates mac/ips/mtu/is_up |
| 10 | New/unconfigured ports get `pvid=10` by default; WAN ports get `pvid=0` | VERIFIED | `guess_pvid()` returns 0 for loopback/VPN/WAN-like, 10 for everything else; seeding defaults to pvid=10 |
| 11 | Default network seeding uses `vlan_id=10` for LAN (not NULL); includes void VLAN 1 (via migration, not seeding) | VERIFIED | Seeding array uses `Some(10)` for LAN; guard checks `zone != 'void'` count; migration owns void entry |
| 12 | `list_interfaces()` returns `pvid` and `tagged_vlans` from DB | VERIFIED | `lib.rs` line 251: `SELECT name, mac, ips, mtu, is_up, pvid, tagged_vlans FROM interfaces`; `test_list_interfaces_after_insert` verifies |
| 13 | API `interfaces_handler` returns `pvid` and `tagged_vlans` in JSON (no `role`/`vlan_id` for interfaces) | VERIFIED | `sfgw-api/src/lib.rs` line 976: SELECT query uses pvid/tagged_vlans; JSON output fields `pvid` and `tagged_vlans` at lines 998-999; all `role` references in API are for `users` table only |
| 14 | API `interface_update` accepts `pvid` (0 or 1-4094) and `tagged_vlans` with validation | VERIFIED | `lib.rs` lines 1111-1141: pvid validation allows 0 or 1-4094; tagged_vlans validates each element is 1-4094 |
| 15 | `switch.rs` uses VLAN 10 for LAN (not VLAN 1); void zone is skipped in switch and bridge setup | VERIFIED | `switch.rs` line 192: `"lan" => n.vlan_id.unwrap_or(10)`; void skip guards at lines 250 and 402; `build_port_string` takes `zone: &str` parameter |

**Score:** 15/15 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/sfgw-db/migrations/005_vlan_trunk_model.sql` | SQL migration: drop role/vlan_id, add pvid/tagged_vlans, void VLAN 1, LAN VLAN 10 | VERIFIED | 62 lines; complete 3-step migration with comment header and role→PVID mapping rationale |
| `crates/sfgw-db/src/lib.rs` | Migration registered, schema version 5, 6 new tests | VERIFIED | Migration at line 144-146; version "5" asserted in 2 tests; 6 migration-specific tests present; `setup_pre_005` helper established |
| `crates/sfgw-net/src/lib.rs` | InterfaceInfo with pvid/tagged_vlans, configure(), list_interfaces(), seeding | VERIFIED | All fields and queries updated; `guess_pvid()` and `guess_tagged_vlans()` implemented; non-void seeding guard correct |
| `crates/sfgw-net/src/switch.rs` | LAN uses VLAN 10, void zone skipped, build_port_string takes zone param | VERIFIED | All three changes confirmed in code; switch tests updated to `build_port_string(10, "lan", &sw)` |
| `crates/sfgw-api/src/lib.rs` | API handlers return pvid/tagged_vlans, accept pvid/tagged_vlans in updates | VERIFIED | interfaces_handler, interface_update, interface_create_vlan all updated; no interface-related `role` references |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `crates/sfgw-db/src/lib.rs` | `crates/sfgw-db/migrations/005_vlan_trunk_model.sql` | `include_str!("../migrations/005_vlan_trunk_model.sql")` at line 144 | WIRED | Pattern `include_str!.*005_vlan_trunk_model` present |
| `crates/sfgw-net/src/lib.rs` | Migration 005 schema | SQL queries use `pvid` and `tagged_vlans` columns | WIRED | `SELECT … pvid, tagged_vlans FROM interfaces` (line 251); `INSERT … pvid, tagged_vlans` (line 92) |
| `crates/sfgw-api/src/lib.rs` | `crates/sfgw-net/src/lib.rs` | API reads `InterfaceInfo` with pvid/tagged_vlans; API SQL mirrors net struct | WIRED | API SELECT at line 976 matches struct fields; `pvid` and `tagged_vlans` in JSON output |
| `crates/sfgw-net/src/switch.rs` | Migration 005 schema | Bridge setup reads `networks` table where LAN is VLAN 10 | WIRED | `load_enabled_networks` queries `networks` table; `n.vlan_id.unwrap_or(10)` for LAN; void zone skipped |
| `crates/sfgw-net/src/wan.rs` | Migration 005 schema | `set_wan_config` sets `pvid=0`; `remove_wan_config` reverts `pvid=10` | WIRED | `UPDATE interfaces SET pvid = 0` (line 488); `UPDATE interfaces SET pvid = 10 WHERE pvid = 0` (line 543) |
| `crates/sfgw-cli/src/main.rs` | `sfgw-net::InterfaceInfo` | Displays `pvid` field (no `role`) | WIRED | Lines 254-263: displays `pvid_str` as "WAN" or "pvid=N" |

---

### Requirements Coverage

| Requirement | Status | Evidence |
|-------------|--------|---------|
| DATA-01: VLAN 1 is void — all traffic DROPped | SATISFIED | VLAN 1 row in networks with `zone='void'`, `enabled=0`; void zone skipped in bridge setup; firewall DROP rules are Phase 3 scope |
| DATA-02: LAN zone defaults to VLAN 10 | SATISFIED | Migration updates existing LAN rows to vlan_id=10; seeding uses `Some(10)`; switch uses `n.vlan_id.unwrap_or(10)` |
| DATA-03: Zone → VLAN relationship in networks table | SATISFIED | `networks` table maps zone to vlan_id; multiple zones each own their VLAN |
| DATA-04: Each port has exactly one PVID | SATISFIED | `interfaces.pvid` is `INTEGER NOT NULL DEFAULT 10`; configure() only sets on first discovery |
| DATA-05: Each port can carry additional tagged VLANs | SATISFIED | `interfaces.tagged_vlans TEXT NOT NULL DEFAULT '[]'`; `InterfaceInfo.tagged_vlans: Vec<u16>`; API accepts/validates tagged_vlans array |
| DATA-06: New/unconfigured ports default to PVID 10 | SATISFIED | `DEFAULT 10` in schema; `guess_pvid()` returns 10 for non-WAN physical interfaces |
| DATA-07: DB migration from role-per-interface to PVID + tagged VLAN model | SATISFIED | Migration 005 complete: rename-create-copy-drop, role→PVID mapping, void VLAN 1, LAN VLAN 10; 6 upgrade-path tests pass |

---

### Anti-Patterns Found

None. No TODOs, FIXMEs, placeholders, or stub implementations found in the modified files.

---

### Test Results

| Test Suite | Tests | Pass | Fail |
|------------|-------|------|------|
| `cargo test -p sfgw-db` | 12 unit + 2 doctests | 14 | 0 |
| `cargo test -p sfgw-net` | 69 unit + 3 doctests | 72 | 0 |
| `cargo build` (full workspace) | — | Clean | 0 warnings |

---

### Human Verification Required

None. All observable truths are verifiable from the codebase and test results. The firewall DROP rules for VLAN 1 traffic are explicitly Phase 3 scope (DATA-01 only requires the void entry to exist, which it does).

---

## Gaps Summary

No gaps. All 15 must-haves from both plans are verified against the actual codebase.

The phase fully achieves its goal: ports have `pvid` (untagged VLAN) and `tagged_vlans` (trunk list), zones own VLANs via the `networks` table, VLAN 1 is void by definition (disabled, no bridge, no DHCP), and LAN is VLAN 10 throughout the stack — in the migration SQL, the Rust struct, the configure/list queries, the switch setup, and the API handlers.

---

_Verified: 2026-03-15T04:29:17Z_
_Verifier: Claude (gsd-verifier)_
