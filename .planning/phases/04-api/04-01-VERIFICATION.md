---
phase: 04-api
verified: 2026-03-15T06:30:00Z
status: passed
score: 5/5 must-haves verified
re_verification: false
---

# Phase 4: Port and Zone API Endpoints — Verification Report

**Phase Goal:** The REST API exposes the new PVID/tagged VLAN model so clients can read and write per-port config and query zone-to-VLAN associations
**Verified:** 2026-03-15T06:30:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | GET /api/v1/ports/{name} returns pvid and tagged_vlans for a specific port | VERIFIED | `port_get_handler` at lib.rs:2343 — SQL selects pvid, tagged_vlans; JSON response includes both fields; no role field |
| 2 | PUT /api/v1/ports/{name} persists pvid/tagged_vlans and triggers switch+firewall reconfiguration | VERIFIED | `port_update_handler` at lib.rs:2416 — validates, writes to DB, calls `sfgw_net::switch::reconfigure_networks` then `sfgw_fw::apply_rules` at lines 2531–2535 |
| 3 | GET /api/v1/zones returns all zones with their VLAN IDs | VERIFIED | `zones_list_handler` at lib.rs:2548 — queries `vlan_id` from networks table, returns `{ "zones": [...] }` |
| 4 | GET /api/v1/zones/{zone} returns a specific zone with its VLAN IDs | VERIFIED | `zone_get_handler` at lib.rs:2584 — queries zone by name, returns vlan_id + interfaces list; 404 on miss |
| 5 | GET /api/v1/interfaces returns pvid and tagged_vlans per interface with no role field | VERIFIED | `interfaces_handler` at lib.rs:978 — SQL selects pvid, tagged_vlans; JSON response at lines 1006–1007; no role key anywhere in port/interface response JSON |

**Score:** 5/5 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/sfgw-api/src/lib.rs` | Port config endpoints (GET/PUT) and zone endpoints (GET list + GET by zone) | VERIFIED | All four handlers implemented and substantive; routes registered at lines 174–180 behind auth + E2EE middleware |
| `crates/sfgw-net/src/switch.rs` | Public reconfigure function callable from API layer | VERIFIED | `pub async fn reconfigure_networks(db: &sfgw_db::Db)` at line 95 — detects board, calls `setup_networks`; fully implemented |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `lib.rs port_update_handler` | `sfgw_net::switch::reconfigure_networks` | async call after DB write | WIRED | lib.rs:2531 — `sfgw_net::switch::reconfigure_networks(&db).await` called after the DB lock is explicitly dropped |
| `lib.rs port_update_handler` | `sfgw_fw::apply_rules` | async call after switch reconfig | WIRED | lib.rs:2534 — `sfgw_fw::apply_rules(&db).await` called sequentially after switch reconfig |

### Requirements Coverage

| Requirement | Status | Blocking Issue |
|-------------|--------|----------------|
| API-01: Port config endpoint GET/PUT per-port PVID + tagged VLAN list | SATISFIED | GET and PUT handlers implemented at /api/v1/ports/{name} |
| API-02: Zone endpoint returns associated VLANs | SATISFIED | GET /api/v1/zones and GET /api/v1/zones/{zone} return vlan_id and interface association |
| API-03: Interfaces endpoint reflects PVID and tagged VLANs instead of role | SATISFIED | interfaces_handler returns pvid and tagged_vlans; no role field in response JSON |

### Anti-Patterns Found

None in phase 4 code. One unrelated pre-existing comment match ("placeholder") in the session handler at lib.rs:584, which is outside this phase's scope.

### Human Verification Required

#### 1. Live reconfiguration round-trip on hardware

**Test:** PUT /api/v1/ports/eth0 with {"pvid": 20, "tagged_vlans": [30]}, then check `swconfig dev switch0 vlan 20 get ports` on a UDM Pro
**Expected:** Port 0 appears untagged in VLAN 20; CPU port tagged
**Why human:** Requires physical UDM Pro hardware with a running binary

#### 2. Firewall rules regenerated after port update

**Test:** PUT /api/v1/ports/eth1 changing pvid, then `iptables -L` to verify the zone-based rules reflect the new assignment
**Expected:** iptables rules reference the new zone for eth1
**Why human:** Requires a running environment with iptables and sfgw_fw wired in

### Test Coverage

7 unit tests in `crates/sfgw-api/src/lib.rs` (lines 2690–2882):
- `test_port_get_query_shape` — verifies pvid=10, tagged_vlans=[20,30] round-trip
- `test_port_update_persists_vlan_config` — verifies UPDATE sets pvid=3001, tagged=[10,20]
- `test_port_update_rejects_invalid_pvid_high` — pvid=5000 rejected
- `test_port_update_rejects_invalid_pvid_negative` — pvid=-1 rejected
- `test_zones_query_returns_vlan_id` — void zone vlan_id=1, lan zone vlan_id=10
- `test_zone_get_returns_associated_interfaces` — eth1/eth2 in LAN zone, eth3 excluded
- `test_is_valid_port_name` — path traversal rejection confirmed

Commit `03a9bf4` (feat(04-api)) verified in git log.

### Gaps Summary

No gaps. All five observable truths are verified, both required artifacts are substantive and wired, all three requirements are satisfied, and no blocker anti-patterns are present.

---

_Verified: 2026-03-15T06:30:00Z_
_Verifier: Claude (gsd-verifier)_
