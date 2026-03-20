# Roadmap

Current version: **v0.4.0**

## Status

### Working

- **Firewall** — nftables (modern kernels) + iptables-legacy (UDM Pro / kernel 4.19). Dual-stack IPv4/IPv6. Zone model with catch-all DROP on all zones. Port forwards. NAT masquerade. Atomic ruleset application with SSH lockout rollback.
- **Networking** — Interface management, VLAN trunk model (per-port PVID + tagged VLANs), bridge configuration. Auto-detection of Ubiquiti hardware (UDM Pro, SE, USG). Switch ASIC VLAN programming via swconfig driven by DB config. VLAN 1 = void sink (all DROP). WAN ports isolated from internal VLAN space (PVID 0).
- **Web UI + API** — axum, TLS 1.3 only. E2EE (X25519 + ML-KEM-1024, AES-256-GCM). Session binding (IP + fingerprint). Rate limiting on every endpoint. Security headers (HSTS, CSP, X-Frame-Options, etc.). User management.
- **DNS/DHCP** — dnsmasq config generation. DHCP ranges, static leases, DNS overrides. DNSSEC validation.
- **Personality** — 7 switchable personalities for error messages, honeypot, IDS alerts. Switchable via web UI settings. Persisted across restarts via DB meta table.
- **Database** — SQLite, encrypted at rest, parameterized queries, migrations.
- **Auth** — Argon2id password hashing, session tokens, E2EE envelope middleware.
- **IDS Active Response** — Auto-block on detection threshold. Atomic iptables-restore rule insertion via `sfgw-fw::ids_response`. Rate limiting and timed expiry with background cleanup task.
- **Honeypot** — Troll TCP listener on port 28082, wired into service lifecycle. Connections logged as IDS events. Enable/disable via API + Web UI.
- **Backup/Restore** — JSON configuration export/import. Secrets excluded. Atomic restore with SQLite savepoint. Download/upload via Settings UI.
- **DDNS** — Dynamic DNS client supporting DynDNS2, DuckDNS, and Cloudflare. Background update loop with IP change detection. Per-config intervals. Full CRUD API + Web UI page.
- **Custom Zones** — IoT, VPN, and user-defined zone types with configurable inbound/outbound/forward policies. Allowed service lists. MGMT always blocked from custom zones (security invariant). Zone presets. DB-backed with iptables rule generation.
- **Traffic Shaping (QoS)** — HTB qdisc per interface with 4 priority classes (High/Normal/Low/Default). iptables mangle MARK rules. IFB device for ingress shaping. SFQ leaf qdiscs. Match by protocol, port, IP/CIDR, DSCP. Live tc stats. API + Web UI.
- **WAN Failover/Load-Balancing** — Extended health checks (HTTP probe, DNS resolve, ICMP). Hysteresis/flap detection with configurable threshold and sliding window. Sticky sessions via CONNMARK. Per-zone WAN pinning via fwmark + ip rule. Flap event log. Web UI with health config, flap log viewer.
- **Display (LCM)** — Native serial driver for UDM Pro front panel (direct STM32F2 MCU communication via `/dev/ttyACM0`, replaces ulcmd). Live system stats (CPU, memory, fan RPM, uptime) pushed every 3s. Board-specific configs (UDM Pro verified, UDM SE + UDM prepared).
- **UniFi Inform** — Full TNBU binary protocol (AES-128-CBC unadopted, AES-128-GCM adopted). 5-phase adoption flow: passive validation → SSH fingerprint → authkey delivery via inform response → system_cfg with SSH hardening (custom user, ubnt disabled, iptables gateway-only) → post-adoption SSH verification with 3-attempt retry and IDS alerting. Snappy/zlib decompression with bomb protection. Per-IP rate limiting. DB protection against adopted record overwrite on service restart. Live device stats (port table, PoE, CPU/mem). Web UI with adopt/ignore/remove and per-port switch config. Tested end-to-end on USW-Flex and UAP-AC-Pro. See [docs/inform-adoption-flow.md](docs/inform-adoption-flow.md).
- **WiFi Management** — Wireless network CRUD (create/update/delete SSIDs). WPA2/WPA3 with PSK. Per-SSID VLAN tagging. Per-radio band selection (2.4 GHz, 5 GHz, both). Guest network and L2 isolation flags. AP system_cfg generation with full VLAN bridging: vconfig VLAN creation, per-VLAN bridges (br0.{vid}) with eth0.{vid} uplink + ath radio ports, netconf entries for automatic interface bring-up. Tested end-to-end on UAP-AC-Pro (WPA2 auth + DHCP on VLAN 10).
- **Deploy** — clean-and-install.sh for production (masks all UniFi services including ulcmd). dev-deploy.sh for rapid iteration on UDM Pro (rsync + on-device build + restart with SSH lockout protection).

### Untested
- **VPN** — WireGuard tunnels via boringtun. Peer management, config generation with download + QR code. Multi-core.
- **IDS** — ARP/DHCP/DNS/VLAN anomaly detection framework with alert correlation.
- **Display (HD44780/Framebuffer)** — HD44780 LCD fallback, framebuffer touchscreen abstraction (untested without UDM Pro LCM hardware).

- **WiFi Advanced** — Channel selection, TX power, bandwidth (HT20/HT40/VHT80), fast roaming (802.11r), band steering. Per-radio config in system_cfg. Multi-SSID per radio (VAP): up to 4 SSIDs per radio, correct ath0/ath1/ath10/ath11 naming, dynamic bridge port enumeration. VAP capacity indicator in Web UI.
- **IDS Event Feed** — Real-time SSE event page with severity/category/time filters, stats cards, top source IPs, expandable rows, JSON export.
- **Firmware Updates (OTA)** — Update check via configurable URL (GitHub releases default, HTTPS enforced). Mandatory SHA-256 verified download, atomic binary swap via rename(2), auto-rollback. Background periodic check. Web UI with release notes, channel selector.
- **UPnP/NAT-PMP** — UPnP IGD (SSDP + SOAP) and NAT-PMP (RFC 6886) servers. iptables DNAT mappings with TTL expiry. LAN-only binding, disabled by default, per-IP quotas, port range limits.
- **IPSec VPN** — IKEv2 via strongSwan (swanctl.conf generation). Site-to-site and roadwarrior modes. PSK and certificate auth. AES-256-GCM + SHA-384 + ECP384 defaults. Web UI with WireGuard/IPSec tab switcher.
- **SQLCipher** — Database encrypted at rest via SQLCipher (AES-256). Key derived from hardware fingerprint (board serial + CPU ID + MAC) via HKDF-SHA256. Key zeroized after PRAGMA, never on disk. Automatic plain-to-encrypted migration on first start.
- **Forward-secret logging** — HKDF ratchet with daily key rotation. AES-256-GCM encrypted log files. Export deletes key (forward secrecy). Destroy marks day permanently unrecoverable. Midnight auto-rotation task. API + Web UI with encrypted archive tab.
- **Multi-site VPN** — Site-to-site WireGuard mesh with auto-failover via handshake age monitoring. Full-mesh or hub-and-spoke topology. Background health monitor. Route failover to backup peers. PSK quantum-resistance. Web UI sites tab.
- **Dashboard** — Enhanced with security overview, VPN status, device health, DHCP clients, traffic table, 5s auto-refresh.

### In Progress

- **NAS** — SMB (ksmbd) + NFS interface stubs. Not yet functional.
- **Encrypted storage** — LUKS2 integration started, not complete.

### Planned

- **Web UI polish** — Firewall rule editor drag-and-drop.
- **HA (High Availability)** — Active/passive failover between two gateways.

### Known Issues

- ~~User-defined firewall rules after zone catch-all DROPs are silently ignored~~ (fixed: catch-all DROPs moved to end of chain)
- ~~`validate_no_lockout` can be bypassed via rule comments containing "ssh"~~ (fixed: checks rule structure, strips comments before matching)
- ~~Port forward ACCEPT rules lack input interface restriction~~ (fixed: restricted to WAN interfaces in zone mode)
- ~~IoT/VPN/Custom zones have no default rules yet~~ (fixed: custom zones with configurable policies + IoT/VPN presets)
- ~~Personality setting is not persisted across restarts (resets to "kevin")~~ (fixed: DB-backed via meta table)

## Version History

### v0.4.0 (2026-03-20)

- **SQLCipher** — AES-256 database encryption at rest, hardware-bound key derivation (HKDF-SHA256 from board serial + CPU ID + MAC), automatic plain-to-encrypted migration, vendored OpenSSL for UDM Pro
- **Forward-secret logging** — HKDF ratchet with daily key rotation, AES-256-GCM encrypted log files, export deletes key, destroy marks permanently unrecoverable, midnight auto-rotation, API + Web UI encrypted archive tab
- **Multi-site VPN** — Site-to-site WireGuard mesh with auto-failover via handshake age monitoring, full-mesh or hub-and-spoke topology, background health monitor, PSK quantum-resistance, Web UI sites tab
- **IPSec VPN** — IKEv2 via strongSwan swanctl.conf generation, site-to-site + roadwarrior modes, PSK + certificate auth, AES-256-GCM + SHA-384 + ECP384 defaults, Web UI tab switcher
- **Custom Zones** — IoT/VPN/user-defined zones with configurable inbound/outbound/forward policies, allowed service lists, MGMT always blocked (security invariant), zone presets, iptables rule generation
- **Traffic Shaping (QoS)** — HTB qdisc with 4 priority classes, iptables mangle MARK, IFB ingress shaping, SFQ leaf qdiscs, match by protocol/port/IP/DSCP, live tc stats, API + Web UI
- **WAN Failover/Load-Balancing** — HTTP/DNS/ICMP health probes, flap detection with sliding window, sticky sessions via CONNMARK, per-zone WAN pinning via fwmark + ip rule, flap event log
- **WiFi Advanced** — Channel selection, TX power, bandwidth (HT20/HT40/VHT80), 802.11r fast roaming, band steering, multi-SSID per radio (VAP) with correct ath naming, VAP capacity indicator
- **UPnP/NAT-PMP** — UPnP IGD (SSDP + SOAP) and NAT-PMP (RFC 6886), iptables DNAT with TTL expiry, LAN-only, disabled by default, per-IP quotas
- **Firmware Updates (OTA)** — Update check via configurable HTTPS URL, mandatory SHA-256 verification, atomic binary swap, auto-rollback, background periodic check, Web UI with release notes
- **DDNS** — DynDNS2/DuckDNS/Cloudflare with background IP change detection, per-config intervals, Cloudflare zone_id hex validation
- **IDS Event Feed** — Real-time SSE with severity/category/time filters, stats cards, top source IPs, JSON export
- **Dashboard** — Security overview, VPN status, device health, DHCP clients, traffic table, 5s auto-refresh
- **IDS Active Response** — Auto-block on threshold, atomic iptables-restore, rate limiting + timed expiry
- sec: Firmware SHA-256 now mandatory (no install without checksum)
- sec: update_url enforced HTTPS-only
- sec: Cloudflare zone_id hex-validated against URL path manipulation
- fix: rustls CryptoProvider panic on startup (0.23+ requires explicit provider)
- fix: Devices page shows "UniFi Inform" badge for adopted devices, no action buttons
- fix: Stale dnsmasq orphan process blocking restart (startup cleanup)
- DB migrations 007-015 (DDNS, WAN health, QoS, custom zones, wireless advanced, UPnP, firmware, log keys, site mesh)

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
- Tested end-to-end on real USW-Flex and UAP-AC-Pro hardware (36s from click to verified adoption)
- **Wireless network management** — DB schema, CRUD API, Web UI page
- AP system_cfg generation: per-radio WLAN config (aaa.N + wireless.N), WPA2/WPA3 PSK, SSID hiding, guest/L2 isolation
- VLAN-tagged WLAN support: vconfig VLAN creation, per-VLAN bridge (br0.{vid}) with eth0.{vid} uplink + ath radio ports
- Automatic VLAN interface bring-up via netconf entries (br0.{vid} + eth0.{vid} with up=enabled)
- Device-type dispatch (AP vs Switch) for system_cfg template selection
- ssh-key patch for 1024-bit RSA host keys (older UAP-AC-Pro/LR firmware with Dropbear)
- ssh-diag diagnostic tool for device SSH debugging
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
