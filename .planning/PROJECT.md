# secfirstgw-rs

## What This Is

A security-first gateway firmware written in Rust. Single binary replacing bloated gateway stacks (Ubiquiti UniFi OS, etc.) on bare metal (UDM Pro, SE, USG), VM, or Docker. 12 MB RAM vs. their 1.8 GB. Firewall, routing, VPN, DNS/DHCP, IDS, NAS, web UI — all in one process.

## Core Value

Every design decision prioritizes security. Default deny, zero trust, no hardcoded credentials, encrypted everything, minimal attack surface.

## Requirements

### Validated

<!-- Shipped and confirmed working on UDM Pro. -->

- ✓ Dual-stack firewall (nftables + iptables-legacy) with zone model and catch-all DROP — v0.0.3
- ✓ Interface management, VLAN creation, bridge configuration — v0.0.3
- ✓ Auto-detection of Ubiquiti hardware (board ID → port roles, switch layout) — v0.0.3
- ✓ Web UI + API (axum, TLS 1.3, E2EE, rate limiting, security headers) — v0.0.3
- ✓ DNS/DHCP via dnsmasq config generation — v0.0.3
- ✓ Switchable personality system (7 personalities) — v0.0.3
- ✓ Auth (Argon2id, sessions, E2EE envelope) — v0.0.3
- ✓ SQLite database, encrypted at rest — v0.0.3
- ✓ WAN failover/load balancing with health checks — v0.0.3
- ✓ Centralized board detection in sfgw-hal — v0.0.3

### Active

<!-- Current milestone: v0.1.0 VLAN Trunk Model -->

- [ ] Proper VLAN trunk model: zones own VLANs, VLANs land on ports
- [ ] VLAN 1 = void (all DROP), LAN defaults to VLAN 10
- [ ] Port config: PVID (untagged) + tagged VLAN list per port
- [ ] WAN ports isolated from internal VLAN system
- [ ] UI: port click → VLAN checklist, colored dots for tagged VLANs
- [ ] Device-specific switch visualization (UDM Pro port layout)

### Out of Scope

- Real-time packet inspection / DPI — too much CPU for embedded, use IDS pattern matching instead
- Custom zones (IoT, VPN, Custom) — deferred, need trunk model first
- UPnP/NAT-PMP — security risk, deferred, disabled by default
- Firmware OTA updates — deferred to later milestone
- HA (active/passive failover) — deferred, complex

## Context

- **Platform**: Runs on UDM Pro (ARM64, kernel 4.19 — NO nf_tables, iptables-legacy only), VMs, Docker
- **Switch ASIC**: RTL8370B on UDM Pro, configured via swconfig. Currently hardcoded "all VLANs on all ports" — needs to become configurable
- **Current VLAN model (broken)**: 1 port = 1 zone role. Doesn't support trunk ports (AP/switch connected needing multiple VLANs)
- **Target VLAN model**: Zone → has N VLANs → VLANs land on N ports (tagged or untagged/PVID). Two separate worlds: WAN ports (provider VLANs) vs LAN ports (internal VLANs)
- **DB schema**: `interfaces` table has `role` column that needs to become PVID-based. `networks` table has zone/vlan_id/subnet/gateway
- **Crate structure**: sfgw-hal (board detection), sfgw-net (interface + switch config), sfgw-fw (firewall), sfgw-api (web API), sfgw-db (SQLite)

## Constraints

- **Kernel**: UDM Pro kernel 4.19 has no nf_tables — iptables-legacy only
- **RAM**: Must stay under 15 MB total RSS on UDM Pro
- **No unsafe**: `#![deny(unsafe_code)]` in every crate
- **No println**: Use tracing exclusively
- **Parameterized SQL**: No string interpolation in queries, ever
- **Dual-stack**: All network code must handle IPv4 + IPv6

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| VLAN 1 = void (all DROP) | New ports start isolated — safest default | — Pending |
| LAN defaults to VLAN 10 (not 1) | VLAN 1 is industry-standard "untagged mess", avoid it | — Pending |
| WAN ports completely separated from internal VLANs | Provider VLANs (e.g. 7 for Telekom) must not collide with internal | — Pending |
| Zone = firewall/routing concept, not port property | Ports carry VLANs; zones own VLANs; bridges connect them | — Pending |
| Per-port PVID + tagged VLAN list | Replaces single "role" field, supports trunk ports properly | — Pending |

---
*Last updated: 2026-03-15 after milestone v0.1.0 start*
