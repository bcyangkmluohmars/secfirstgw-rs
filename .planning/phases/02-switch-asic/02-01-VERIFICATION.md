---
phase: 02-switch-asic
verified: 2026-03-15T04:49:20Z
status: passed
score: 5/5 must-haves verified
re_verification: false
---

# Phase 2: Switch ASIC VLAN Programming Verification Report

**Phase Goal:** The RTL8370B switch ASIC on UDM Pro is programmed according to per-port PVID and tagged VLAN config from the DB — not hardcoded to "all VLANs on all ports"
**Verified:** 2026-03-15T04:49:20Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| #   | Truth                                                                                                        | Status     | Evidence                                                                                                                          |
|-----|--------------------------------------------------------------------------------------------------------------|------------|-----------------------------------------------------------------------------------------------------------------------------------|
| 1   | Each switch port only carries VLANs it is configured for (via pvid + tagged_vlans from DB), not all VLANs   | VERIFIED   | `compute_vlan_port_map` inverts per-port config; port only enters a VLAN via its pvid (untagged) or tagged_vlans (tagged). Tests: `test_compute_vlan_port_map_default_udm_pro`, `test_compute_vlan_port_map_trunk_port` |
| 2   | MGMT port (eth7 / switch port 7) has pvid=3000 and does not carry LAN VLAN 10 untagged                      | VERIFIED   | `test_mgmt_port_not_in_lan_vlan` asserts port 7 absent from VLAN 10 entirely; port 7 untagged in VLAN 3000 only. `test_compute_vlan_port_map_default_udm_pro` double-checks both tagged and untagged absence |
| 3   | VLAN 1 is programmed on the switch ASIC with all LAN ports tagged, but no Linux bridge is created for it    | VERIFIED   | `compute_vlan_port_map` always inserts VLAN 1 with all ports tagged (lines 241-255). `setup_bridges` skips `zone == "void"` at line 489 — no br-void created. `test_compute_vlan_port_map_vlan1_always_present` confirms VLAN 1 always present |
| 4   | On VM or Docker (switch=None), setup_switch_vlans is never called and no error occurs                        | VERIFIED   | `setup_networks` guard at line 106: `if let Some(sw) = switch { setup_switch_vlans(sw, db).await?; }` — when switch is None the block is skipped entirely. `test_setup_switch_vlans_produces_correct_commands` exercises the data path without swconfig |
| 5   | Ports with pvid=0 (WAN) are excluded from VLAN membership computation entirely                               | VERIFIED   | SQL query: `SELECT name, pvid, tagged_vlans FROM interfaces WHERE pvid > 0` (line 150). Integration test inserts eth8/eth9 with pvid=0 and asserts they are absent from port_configs (8 ports returned, not 10) |

**Score:** 5/5 truths verified

### Required Artifacts

| Artifact                              | Expected                                                         | Status     | Details                                                                  |
|---------------------------------------|------------------------------------------------------------------|------------|--------------------------------------------------------------------------|
| `crates/sfgw-net/src/switch.rs`       | Per-port VLAN computation, ASIC programming, VLAN 1 sink         | VERIFIED   | 1001 lines. All required functions present and substantive: `compute_vlan_port_map`, `format_port_string`, `iface_to_switch_port`, `load_port_vlan_config`, `setup_switch_vlans`. 11 unit + integration tests in the module. No stubs, no TODOs. |

### Key Link Verification

| From                          | To                       | Via                          | Status  | Details                                                                                        |
|-------------------------------|--------------------------|------------------------------|---------|------------------------------------------------------------------------------------------------|
| `crates/sfgw-net/src/switch.rs` | `interfaces` DB table  | SQL query for pvid + tagged_vlans | WIRED | Line 150: `SELECT name, pvid, tagged_vlans FROM interfaces WHERE pvid > 0` — exact pattern match |
| `compute_vlan_port_map`       | `swconfig_set_vlan_ports` | BTreeMap iteration           | WIRED   | Lines 393-397: iterates `vlan_map`, calls `swconfig_set_vlan_ports` for each entry             |
| `setup_switch_vlans`          | `swconfig_set_pvid`       | per-port PVID loop           | WIRED   | Lines 400-410: loops `port_configs`, calls `swconfig_set_pvid` with `pvid` for each port       |

### Requirements Coverage

| Requirement | Description                                                                   | Status      | Evidence                                                                                              |
|-------------|-------------------------------------------------------------------------------|-------------|-------------------------------------------------------------------------------------------------------|
| ASIC-01     | swconfig VLAN programming driven by per-port PVID + tagged VLAN config       | SATISFIED   | `setup_switch_vlans` reads DB via `load_port_vlan_config`, computes map, programs each VLAN and each port's PVID |
| ASIC-02     | MGMT port PVID set to MGMT VLAN (3000), tagged VLANs configurable            | SATISFIED   | MGMT port (port 7) programmed with pvid=3000 from DB; its tagged_vlans are honoured by `compute_vlan_port_map`. `swconfig_set_pvid` called for every port including port 7 |
| ASIC-03     | Void VLAN 1 programmed on switch with no bridge attachment                    | SATISFIED   | VLAN 1 always in `compute_vlan_port_map` output with all ports tagged. `setup_bridges` skips `zone == "void"` so no br-void is created |

### Anti-Patterns Found

None. No TODOs, FIXMEs, placeholders, `return null`, empty handlers, or console.log-only implementations found in switch.rs.

### Human Verification Required

The following items cannot be verified programmatically and require a live UDM Pro with the binary deployed:

#### 1. swconfig output matches computed VLAN map

**Test:** Deploy the binary on a UDM Pro. After startup, run `swconfig dev switch0 show`.
**Expected:** Each VLAN entry lists only the ports assigned to it (e.g. VLAN 10 shows ports 0 1 2 3 4 5 6 8t 9t, not all 10 ports). VLAN 3000 shows port 7 8t 9t only. VLAN 1 shows all ports tagged.
**Why human:** swconfig is a kernel module tool that does not exist in the build/test environment. The code path that calls it is exercised at unit-test level via pure logic (compute_vlan_port_map), but the actual ASIC register write is not testable without hardware.

#### 2. MGMT port eth7 isolation confirmed on wire

**Test:** With MGMT pvid=3000 and LAN pvid=10, plug a device into eth7 and verify it does NOT receive DHCP from the LAN DHCP server (br-lan). Verify it receives DHCP from the MGMT DHCP server (br-mgmt) if configured.
**Expected:** No LAN traffic reaches eth7. MGMT zone is isolated.
**Why human:** Requires physical switch + wired test device.

#### 3. VLAN 1 traffic goes nowhere

**Test:** Force a frame tagged as VLAN 1 into the switch (e.g. via a vlan-aware NIC or `ip link add link ethX type vlan id 1`). Verify it is not bridged to any Linux interface.
**Expected:** The frame arrives at the CPU port tagged VLAN 1 but there is no br-void to deliver it to; it is dropped.
**Why human:** Requires hardware or a traffic generator capable of injecting tagged VLAN 1 frames.

## Gaps Summary

None. All automated checks pass. The implementation is substantive, fully wired, and comprehensively tested (75/75 tests pass, full workspace builds clean with zero warnings).

---

_Verified: 2026-03-15T04:49:20Z_
_Verifier: Claude (gsd-verifier)_
