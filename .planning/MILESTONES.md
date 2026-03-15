# Milestones

## v0.2.0 (2026-03-15) — VLAN Trunk Model + LCM Display

**What shipped:**
- VLAN trunk model: per-port PVID + tagged VLANs, VLAN 1 = void (all DROP), LAN = VLAN 10
- DB migration (role → pvid/tagged_vlans), switch ASIC programming from DB
- WAN isolation from internal VLAN space (pvid=0 sentinel)
- Firewall VLAN isolation rules (iptables-legacy)
- REST API for port config (GET/PUT with live reconfig) and zone endpoints
- Web UI switch panel with PVID-based zone coloring and tagged VLAN dots
- Port config panel with PVID selector + tagged VLAN checklist (partial — awaiting verification)
- Native LCM display driver for UDM Pro (replaces ulcmd daemon entirely)
- MCU init sequence, live system stats push (CPU/mem/fan/uptime) every 3s
- Board-specific LCM configs (UDM Pro verified, UDM SE + UDM prepared)
- ulcmd masked and stopped alongside other UniFi services
- systemd deployment improvements, WAN DHCP fixes, DNS fixes
- CI fixes (cargo fmt + clippy nightly)

**Last phase:** 5 (Web UI — partially complete, plans 05-01 done, 05-02 at checkpoint)

## v0.0.3 (2026-03-14) — Foundation

**What shipped:**
- Dual-stack firewall (nftables + iptables-legacy) with zone model
- Catch-all DROP on all zones, bridge interfaces
- Interface management, VLAN creation, bridge config
- Ubiquiti hardware auto-detection (UDM Pro, SE, USG)
- Web UI + API (axum, TLS 1.3, E2EE, rate limiting)
- DNS/DHCP via dnsmasq config generation
- Switchable personality system (7 personalities)
- Auth (Argon2id, sessions, E2EE envelope)
- SQLite database, encrypted at rest
- WAN failover/load balancing with presets (Telekom VDSL, etc.)
- Centralized board detection in sfgw-hal
- Device-specific switch visualization in UI

**Last phase:** 0 (pre-GSD, manual development)

## v0.0.2

- E2EE API layer (X25519 + ML-KEM-1024)
- MGMT zone and port
- Switch ASIC VLAN programming
- DNS/DHCP on br-lan + br-mgmt

## v0.0.1

- Initial prototype
- nftables firewall, basic web UI, WireGuard VPN
