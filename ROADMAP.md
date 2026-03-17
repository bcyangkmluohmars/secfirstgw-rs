# Roadmap

Current version: **v0.3.0**

## Status

### Working

- **Firewall** — nftables (modern kernels) + iptables-legacy (UDM Pro / kernel 4.19). Dual-stack IPv4/IPv6. Zone model with catch-all DROP on all zones. Port forwards. NAT masquerade. Atomic ruleset application with SSH lockout rollback.
- **Networking** — Interface management, VLAN trunk model (per-port PVID + tagged VLANs), bridge configuration. Auto-detection of Ubiquiti hardware (UDM Pro, SE, USG). Switch ASIC VLAN programming via swconfig driven by DB config. VLAN 1 = void sink (all DROP). WAN ports isolated from internal VLAN space (PVID 0).
- **Web UI + API** — axum, TLS 1.3 only. E2EE (X25519 + ML-KEM-1024, AES-256-GCM). Session binding (IP + fingerprint). Rate limiting on every endpoint. Security headers (HSTS, CSP, X-Frame-Options, etc.). User management.
- **DNS/DHCP** — dnsmasq config generation. DHCP ranges, static leases, DNS overrides. DNSSEC validation.
- **Personality** — 7 switchable personalities for error messages, honeypot, IDS alerts. Switchable via web UI settings.
- **Database** — SQLite, encrypted at rest, parameterized queries, migrations.
- **Auth** — Argon2id password hashing, session tokens, E2EE envelope middleware.
- **Display (LCM)** — Native serial driver for UDM Pro front panel (direct STM32F2 MCU communication via `/dev/ttyACM0`, replaces ulcmd). Live system stats (CPU, memory, fan RPM, uptime) pushed every 3s. Board-specific configs (UDM Pro verified, UDM SE + UDM prepared).
- **UniFi Inform** — Full TNBU binary protocol (AES-128-CBC unadopted, AES-128-GCM adopted). 5-phase adoption flow: passive validation → SSH fingerprint → authkey delivery via inform response → system_cfg with SSH hardening (custom user, ubnt disabled, iptables gateway-only) → post-adoption SSH verification with 3-attempt retry and IDS alerting. Snappy/zlib decompression with bomb protection. Per-IP rate limiting. DB protection against adopted record overwrite on service restart. Live device stats (port table, PoE, CPU/mem). Web UI with adopt/ignore/remove and per-port switch config. Tested end-to-end on USW-Flex. See [docs/inform-adoption-flow.md](docs/inform-adoption-flow.md).
- **Deploy** — clean-and-install.sh for production (masks all UniFi services including ulcmd). dev-deploy.sh for rapid iteration on UDM Pro (rsync + on-device build + restart with SSH lockout protection).

### Untested
- **VPN** — WireGuard tunnels via boringtun. Peer management, config generation. Multi-core.
- **IDS** — ARP/DHCP/DNS/VLAN anomaly detection framework with alert correlation.
- **Display (HD44780/Framebuffer)** — HD44780 LCD fallback, framebuffer touchscreen abstraction (untested without UDM Pro LCM hardware).

### In Progress

- **Honeypot** — Module written (`sfgw-personality::honeypot`), not yet wired into service lifecycle. Troll TCP listener on port 28082.
- **Forward-secret logging** — Framework exists, daily key rotation not yet integrated.
- **NAS** — SMB (ksmbd) + NFS interface stubs. Not yet functional.
- **Encrypted storage** — LUKS2 integration started, not complete.

### Planned

- **Web UI polish** — Dashboard, firewall rule editor drag-and-drop, VPN config download, real-time IDS event feed.
- **IDS active response** — Auto-block on detection threshold (notify sfgw-fw to insert DROP rules).
- **Honeypot integration** — Wire honeypot connections into IDS event pipeline for correlation.
- **Custom zones** — IoT, VPN, Custom zone types with configurable policies.
- **WAN Failover/Load-Balancing Improvements**
  - Health-Check erweitern — HTTP-Check, DNS-Resolve-Check (nicht nur ICMP Ping)
  - Hysterese / Flap-Detection (Interface flapped 10x in 1 Min → nicht sofort re-route)
  - Sticky-Sessions (bei Failover bestehende Connections nicht brechen)
  - Per-Zone WAN-Pinning ("DMZ immer über eth8, LAN über switch0")
  - Web UI — WAN-Bereich mit Failover/LB-Konfiguration, Health-Check-Status, Interface-Prioritäten
- **DDNS** — Dynamic DNS client for WAN IP updates.
- **UPnP/NAT-PMP** — Optional, disabled by default.
- **Traffic shaping** — QoS via tc/nftables.
- **Multi-site VPN** — Site-to-site WireGuard with auto-failover.
- **Firmware updates** — OTA update mechanism with rollback.
- **Backup/Restore** — Configuration export/import.
- **HA (High Availability)** — Active/passive failover between two gateways.

### Known Issues

- User-defined firewall rules after zone catch-all DROPs are silently ignored (rules need priority reordering)
- `validate_no_lockout` can be bypassed via rule comments containing "ssh"
- Port forward ACCEPT rules lack input interface restriction (should be WAN-only)
- IoT/VPN/Custom zones have no default rules yet
- Personality setting is not persisted across restarts (resets to "kevin")

## Version History

### v0.3.0 (2026-03-17)

- **sfgw-inform crate** — Complete UniFi Inform protocol implementation
- TNBU binary packet parsing/serialization (40-byte header, AES IV, flags bitfield)
- AES-128-CBC decryption/encryption (PKCS7, default key = MD5("ubnt"))
- AES-128-GCM decryption/encryption (16-byte nonce, 40-byte header AAD, 16-byte tag)
- Snappy + zlib decompression with 10 MiB bomb protection
- Per-IP rate limiting (soft + hard thresholds, MAC tracking, IDS integration)
- SSH provisioning: factory creds → hardware fingerprint from EEPROM → validate → generate authkey + SSH creds
- Authkey delivery via Inform response mgmt_cfg (no mca-ctrl, no SSH config push)
- system_cfg generation: SSH hardening (custom user, ubnt disabled, iptables gateway-only, syslog forwarding)
- cfgversion hash tracking for config change detection
- Post-adoption SSH verification (3-attempt retry, IDS critical alert on exhaustion)
- Two-phase key resolution with DB fallback (handles service restarts, adoption transitions)
- DB protection: check for existing Adopted/Adopting records before creating Pending (prevents overwrite on restart)
- Inform JSON payload parsing (30+ fields: port_table, sys_stats, PoE, FDB, etc.)
- Per-port switch config model (PVID, tagged VLANs, PoE mode, egress rate limit, isolation)
- Device state machine: Pending → Adopting → Adopted, plus Ignored and Phantom states
- IDS events: phantom device detection, inform flood, SSH provisioning failure, config delivery failure
- API endpoints: inform settings, device list, adopt, ignore, remove, port config GET/PUT
- Web UI page: device list with state badges, adopt/ignore/remove actions, live stats, port config editor
- Full protocol documentation: [docs/inform-adoption-flow.md](docs/inform-adoption-flow.md)
- Tested end-to-end on real USW-Flex hardware (36s from click to verified adoption)
- IDS `log_event()` public API for cross-crate security event logging
- dnsmasq `reload_by_pid_file()` for config reload without process handle

### v0.2.0 (2026-03-15)

- VLAN trunk model: per-port PVID + tagged VLANs replacing single role field
- VLAN 1 = void sink (all DROP, never bridged), LAN = VLAN 10
- WAN ports isolated from internal VLAN space (PVID 0 sentinel)
- DB migration (role → pvid/tagged_vlans) with SQLite compat
- Switch ASIC programming driven by per-port DB config
- Firewall VLAN isolation rules (iptables-legacy)
- REST API for port config (GET/PUT with live switch+firewall reconfig)
- Zone endpoints (list + detail with VLAN associations)
- Web UI switch panel with PVID-based zone coloring and tagged VLAN dots
- Port config panel with PVID selector + tagged VLAN checklist
- Native LCM display driver for UDM Pro (replaces ulcmd entirely)
- MCU init sequence, live system stats push (CPU/mem/fan/uptime)
- ulcmd masked and stopped alongside other UniFi services
- WAN DHCP fixes, DNS fixes
- SSE event stream for live log viewing in web UI

### v0.0.3 (2026-03-14)

- Switchable personality system (7 personalities)
- Security headers middleware
- iptables-legacy backend for UDM Pro
- Dual-stack IPv6 firewall
- Catch-all DROP on all zones
- Bridge interface fix (br-lan/br-mgmt instead of individual ports)
- DMZ INPUT hardening (DNS/DHCP only, no HTTP/HTTPS)

### v0.0.2

- E2EE API layer (X25519 + ML-KEM-1024)
- MGMT zone and port
- Switch ASIC VLAN programming
- DNS/DHCP on br-lan + br-mgmt

### v0.0.1

- Initial prototype
- nftables firewall, basic web UI, WireGuard VPN
