---
phase: 03-network-enforcement
plan: 01
verified: 2026-03-15T05:13:38Z
status: passed
score: 5/5 must-haves verified
re_verification: false
---

# Phase 3 Plan 01: Network Enforcement Verification Report

**Phase Goal:** Firewall and routing enforce the VLAN separation — WAN ports cannot bleed into internal VLANs, internal ports cannot receive provider VLANs, and VLAN 1 is DROPped everywhere
**Verified:** 2026-03-15T05:13:38Z
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `load_interface_zones()` derives zone from pvid via networks table JOIN (not from removed role column) | VERIFIED | `lib.rs:488`: `JOIN networks n ON i.pvid = n.vlan_id`; zero SQL references to `role` column |
| 2 | WAN interfaces (pvid=0) appear in WAN zone without relying on role column | VERIFIED | `lib.rs:517-528`: separate `SELECT name FROM interfaces WHERE enabled = 1 AND pvid = 0` query; WAN zone built with `vlan_id: None` |
| 3 | VLAN 1 tagged packets are DROPped in INPUT and FORWARD chains before any other rule | VERIFIED | `iptables/mod.rs:1033-1058`: `emit_vlan_isolation_rules()` emits `{wan}.1 -j DROP` on INPUT+FORWARD for all WAN ifaces, plus `br-void -j DROP`; called at line 710 before zone rules; test `test_vlan1_void_drop_rules` passes |
| 4 | Internal VLAN IDs (10, 3000, 3001, 3002) are DROPped on WAN interfaces | VERIFIED | `iptables/mod.rs:1060-1081`: iterates non-WAN zones with `vlan_id`, emits `{wan}.{vid} -j DROP` on INPUT+FORWARD; test `test_internal_vlans_blocked_on_wan` passes, covering VLANs 10, 3000, 3001, 3002 |
| 5 | LAN zone rules reference br-lan (bridge for VLAN 10 zone), not VLAN 1 | VERIFIED | `lib.rs:553-554`: bridged zones use `br-{zone_name}`, so zone=lan becomes `br-lan`; test `test_lan_zone_uses_vlan10_bridge` asserts `br-lan` present and `br-1` absent from LAN rules |

**Score:** 5/5 truths verified

---

### Required Artifacts

| Artifact | Expected | Level 1: Exists | Level 2: Substantive | Level 3: Wired | Status |
|----------|----------|-----------------|----------------------|----------------|--------|
| `crates/sfgw-fw/src/lib.rs` | PVID-based `load_interface_zones()`, `ZonePolicy.vlan_id` field | Yes | Contains `networks.vlan_id`, JOIN query, `vlan_id: Option<u16>` field | Called from `apply_rules()` at line 437 | VERIFIED |
| `crates/sfgw-fw/src/iptables/mod.rs` | VLAN isolation rules, `emit_vlan_isolation_rules()` | Yes | 1084-line file with full `emit_vlan_isolation_rules()` impl and "VLAN 1 void" pattern | Called from `generate_zone_ruleset()` at line 710 | VERIFIED |

---

### Key Link Verification

| From | To | Via | Status | Evidence |
|------|----|-----|--------|----------|
| `lib.rs` | `interfaces.pvid + networks.zone` | SQL JOIN on `pvid = vlan_id` | WIRED | `lib.rs:488`: `JOIN networks n ON i.pvid = n.vlan_id` |
| `iptables/mod.rs` | SFGW-INPUT/SFGW-FORWARD chains | `emit_vlan_isolation_rules()` | WIRED | Defined at line 1027, called at line 710 inside `generate_zone_ruleset()` |

---

### Requirements Coverage

| Requirement | Status | Implementation Evidence |
|-------------|--------|------------------------|
| WAN-01 (internal VLANs blocked on WAN) | SATISFIED | `emit_vlan_isolation_rules()` drops `{wan}.{vid}` for each internal zone's vlan_id on all WAN interfaces; covers VLANs 10, 3000, 3001, 3002+ dynamically |
| WAN-02 (internal ports cannot receive provider VLANs) | SATISFIED (hardware) | Enforced by switch ASIC PVID model from Phase 2; existing zone rules (`WAN -> any = DROP`) provide iptables defense-in-depth. As documented in PLAN, no additional iptables rules are needed. |
| WAN-03 (provider VLAN config stays in WAN config only) | SATISFIED (hardware) | Enforced at data model level (Phase 1/2): provider VLANs are only in WAN interface pvid configuration, not in networks table |
| FW-01 (firewall rules use VLAN 10 for LAN, not VLAN 1) | SATISFIED | `load_interface_zones()` resolves `zone=lan` to `br-lan` (VLAN 10 bridge); test `test_lan_zone_uses_vlan10_bridge` verifies no `br-1` appears in LAN rules |
| FW-02 (VLAN 1 catch-all DROP on all chains) | SATISFIED | `emit_vlan_isolation_rules()` drops `{wan}.1` on INPUT+FORWARD for each WAN iface, plus unconditional `br-void -j DROP` on both chains; test `test_vlan1_void_drop_rules` verifies all six DROP rules |

---

### Anti-Patterns Found

None. No TODO/FIXME/placeholder comments in modified files. No empty implementations. No stub returns. Zero compile warnings.

---

### Human Verification Required

None. All success criteria are verifiable through code inspection and automated tests.

---

## Verification Summary

All five observable truths from the PLAN frontmatter are fully verified. The phase achieved its goal:

**Firewall VLAN separation is enforced at multiple layers:**

1. **Code correctness**: `load_interface_zones()` no longer references the removed `role` column — the runtime crash is fixed. Zone derivation uses PVID JOIN.

2. **WAN-01 (iptables)**: Every internal VLAN ID (derived dynamically from `ZonePolicy.vlan_id`) generates DROP rules for `.{vid}` sub-interfaces on all WAN interfaces in both SFGW-INPUT and SFGW-FORWARD. The PLAN's success criteria list of VLANs 10, 3000, 3001, 3002 are all covered by the test fixture and verified by `test_internal_vlans_blocked_on_wan`.

3. **FW-02 (iptables)**: VLAN 1 DROP rules are emitted for `{wan}.1` (all WAN interfaces) and `br-void` in both INPUT and FORWARD chains, placed before any zone rules. Test `test_vlan_isolation_rules_appear_before_zone_rules` verifies ordering.

4. **FW-01**: LAN zone resolves to `br-lan` (VLAN 10 bridge), not `br-1` or any VLAN 1 reference. Confirmed by test.

5. **Build integrity**: Zero warnings, 5 new VLAN isolation tests + 1 ordering test added, 62 total tests pass (58 unit + 4 doctests).

6. **Git commits**: Both claimed commits exist — `5cb4780` (Task 1) and `640ca64` (Task 2).

**Note on WAN-02/WAN-03**: These are correctly handled at the hardware level (switch ASIC PVID enforcement from Phase 2). The existing zone DROP policy provides iptables defense-in-depth. This is the documented design decision, not a gap.

---

_Verified: 2026-03-15T05:13:38Z_
_Verifier: Claude (gsd-verifier)_
