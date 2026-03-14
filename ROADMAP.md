# Roadmap

Current version: **v0.0.3**

## Status

### Working

- **Firewall** — nftables (modern kernels) + iptables-legacy (UDM Pro / kernel 4.19). Dual-stack IPv4/IPv6. Zone model with catch-all DROP on all zones. Port forwards. NAT masquerade. Atomic ruleset application with SSH lockout rollback.
- **Networking** — Interface management, VLAN creation, bridge configuration. Auto-detection of Ubiquiti hardware (UDM Pro, SE, USG). Switch ASIC VLAN programming via swconfig.
- **VPN** — WireGuard tunnels via boringtun. Peer management, config generation. Multi-core.
- **Web UI + API** — axum, TLS 1.3 only. E2EE (X25519 + ML-KEM-1024, AES-256-GCM). Session binding (IP + fingerprint). Rate limiting on every endpoint. Security headers (HSTS, CSP, X-Frame-Options, etc.). User management.
- **DNS/DHCP** — dnsmasq config generation. DHCP ranges, static leases, DNS overrides. DNSSEC validation.
- **Device Adoption** — mTLS CA, Inform protocol handling, device approval/rejection workflow.
- **IDS** — ARP/DHCP/DNS/VLAN anomaly detection framework with alert correlation.
- **Personality** — 7 switchable personalities for error messages, honeypot, IDS alerts. Switchable via web UI settings.
- **Display** — HD44780 LCD driver (UDM Pro front panel via ulcmd), framebuffer touchscreen abstraction.
- **Database** — SQLite, encrypted at rest, parameterized queries, migrations.
- **Auth** — Argon2id password hashing, session tokens, E2EE envelope middleware.
- **Deploy** — dev-deploy.sh for rapid iteration on UDM Pro (rsync + on-device build + restart with SSH lockout protection).

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
