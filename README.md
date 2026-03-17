# secfirstgw-rs

> If you know, you know. If you don't — the firewall will let you know.

A security-focused gateway firmware, written in Rust. Runs on bare metal, VM, or Docker.

**Coming soon.**

## Why?

Because 180+ services, Java, MongoDB without auth, hardcoded credentials, and single-core VPN at 30 MB/s in 2026 is not acceptable.

**11 MB RAM** on a UDM Pro. Their stack uses 1.8 GB.

## What?

A single Rust binary replacing bloated gateway stacks:

- **Firewall & Router** — iptables-legacy (UDM Pro / kernel 4.19) + nftables (modern kernels), dual-stack IPv4/IPv6
- **Network Controller** — device adoption, provisioning, monitoring
- **UniFi Inform** — TNBU protocol, AES-128-CBC/GCM, SSH fingerprint verification, system_cfg hardening
- **Multi-Core VPN** — WireGuard (boringtun) across all cores
- **DNS & DHCP** — dnsmasq config generation
- **Encrypted Storage** — LUKS2 FDE with hardware-bound key derivation
- **Forward-Secret Logs** — daily key rotation, old keys deleted after export
- **NAS** — SMB (ksmbd) + NFS
- **Web UI + API** — axum-based, TLS 1.3 only, E2EE API layer, security headers, rate limiting
- **IDS/IPS** — ARP/DHCP/DNS/VLAN anomaly detection with alert correlation
- **Personality** — switchable error message styles (because security doesn't have to be boring)

## Platforms

| Platform | Networking | Storage | Display |
|----------|-----------|---------|---------|
| Bare Metal (ARM64) | Hardware switch ASICs | LUKS2 on HDD | LCM (UDM Pro native serial) / HD44780 LCD / Framebuffer |
| VM | virtio-net / e1000 | LUKS2 on vdisk | No |
| Docker | macvlan / host | Volume mount | No |

## Zone Model

Every switch port has a **PVID** (Port VLAN ID) that determines its untagged zone, plus optional tagged VLANs for trunk membership. WAN ports (PVID 0) are completely separated from the internal VLAN space. VLAN 1 is a void sink — all traffic dropped, never bridged. Traffic uses bridge interfaces (`br-lan`, `br-mgmt`, etc.) — never individual switch ports. Default firewall policies enforce strict isolation with catch-all DROP on every zone.

| Zone | Purpose |
|------|---------|
| **WAN** | Uplink(s) to internet. Multiple WAN ports supported with failover/load-balance. |
| **LAN** | Trusted internal network. DNS, DHCP. No direct gateway admin access. |
| **DMZ** | Public-facing services. Isolated from LAN/MGMT. DNS/DHCP only to gateway. |
| **MGMT** | Admin management. Web UI, SSH, device adoption (Inform). |
| **GUEST** | Untrusted clients. Internet only, no internal access. |

### Default Zone-to-Zone Forwarding Matrix

```
From \ To   |  WAN     LAN     DMZ     MGMT    GUEST
────────────┼──────────────────────────────────────────
WAN         |   -      DROP    DROP    DROP    DROP
LAN         |   ✓      ✓       ✓       ✓      DROP
DMZ         |   ✓      DROP    ✓       DROP    DROP
MGMT        |  opt     ✓       ✓       ✓       ✓
GUEST       |   ✓      DROP    DROP    DROP    DROP
```

### Per-Zone Input Rules (to Gateway)

Every zone ends with a catch-all DROP — nothing gets through unless explicitly allowed.

| Service          | WAN  | LAN  | DMZ  | MGMT | GUEST |
|------------------|------|------|------|------|-------|
| Web UI (443)     | -    | -    | -    | ✓    | -     |
| SSH (22)         | -    | -    | -    | ✓    | -     |
| DNS (53)         | -    | ✓    | ✓    | ✓    | ✓     |
| DHCP (67/68)     | -    | ✓    | ✓    | ✓    | ✓     |
| Inform (8080)    | -    | -    | -    | ✓    | -     |
| Port Forwards    | ✓    | -    | -    | -    | -     |
| Ping (ICMP)      | rate | ✓    | rate | ✓    | rate  |
| **Catch-all**    | DROP | DROP | DROP | DROP | DROP  |

### WAN Failover / Load Balancing

Multiple interfaces can be assigned the WAN zone. Supported modes:

- **Failover** — active/standby with health checks (ping gateway). Automatic switchover on failure.
- **Load Balance** — weighted round-robin across healthy WANs via policy routing.

### IPv6

All filter rules are dual-stack — IPv4 (iptables) and IPv6 (ip6tables) with identical policies. IPv6 additionally permits ICMPv6 neighbor discovery (NDP types 133-136) required for IPv6 to function.

## First-Boot Defaults

secfirstgw ships with zero-config defaults. On first boot, everything works out of the box:

### Hardware Auto-Detection

On Ubiquiti hardware, the board ID (`/proc/ubnthal/board`) is used to auto-assign port roles:

| Board | Device | WAN Ports | MGMT Port |
|-------|--------|-----------|-----------|
| `ea15` | UDM Pro | eth8 (RJ45), eth9 (SFP+) | eth7 |
| `ea22` | UDM SE | eth8 (RJ45), eth9 (SFP+) | eth7 |
| `ea21` | UDM | eth4, eth5 | - |
| `e610` | USG 3P | eth0 | - |
| `e612` | USG Pro 4 | eth0, eth2 | - |

UDM Pro / SE port layout:
```
Port 1-7 (eth0-eth6)  → LAN (PVID 10, untagged)
Port 8   (eth7)       → MGMT (PVID 3000, untagged, 10.0.0.0/24)
Port 9   (eth8)       → WAN1 (PVID 0, outside VLAN space)
Port 10  (eth9)       → WAN2 (PVID 0, outside VLAN space)
Port 11  (eth10)      → LAN (PVID 10, SFP+)
```

VLAN 1 is a catch-all void — all switch ports are tagged members, but no bridge is created. Any unclassified traffic lands in VLAN 1 and is dropped.

### Default Networks

| Network | VLAN | Subnet | DHCP Pool | Status |
|---------|------|--------|-----------|--------|
| Void | 1 | - | - | Sink (all DROP) |
| LAN | 10 | 192.168.1.0/24 | .100-.254 | Active |
| WAN1 | - | DHCP (eth8) | - | Active |
| WAN2 | - | DHCP (eth9) | - | Active |
| Management | 3000 | 10.0.0.0/24 | .100-.254 | Active |
| Guest | 3001 | 192.168.3.0/24 | .100-.254 | Active |
| DMZ | 3002 | 172.16.0.0/24 | .100-.254 | Active |

### Default Firewall Policy

Rules are auto-created on first boot:

- **NAT**: Masquerade on all WAN interfaces (IPv4 only)
- **LAN**: DNS/DHCP to gateway, full internet access, can reach Guest/DMZ. No SSH/Web UI.
- **Guest**: DNS/DHCP to gateway, internet only, all internal traffic blocked
- **DMZ**: DNS/DHCP to gateway, internet access, LAN/MGMT access blocked. No HTTP/HTTPS to gateway.
- **MGMT**: Full access — Web UI, SSH, Inform, DNS/DHCP, internet
- **WAN inbound**: Default deny (except established/related + port forwards)
- **All zones**: Catch-all DROP at end — no traffic leaks through to platform services

### Default DNS/DHCP

- DNS forwarding to WAN gateway + 1.1.1.1 + 9.9.9.9
- DHCP on LAN: 192.168.1.100-254, 12h lease, domain `lan`
- DNSSEC validation (requires dnsmasq compiled with --enable-dnssec; disabled on stock UDM Pro)
- DNS rebind protection enabled

## Personality

secfirstgw has attitude. Error messages, rate-limit responses, honeypot replies, and IDS alerts come with personality — switchable at runtime via the web UI settings.

| Personality | Style |
|-------------|-------|
| **kevin** (default) | German/English street slang, zero filter |
| **corporate** | "authentication required" |
| **pirate** | "ye be no crew of mine!" |
| **zen** | "the gate remains closed to those who do not know the way" |
| **bofh** | "your credentials were lost in a tragic boating accident" |
| **unreal-tournament** | "DENIED!" / "GODLIKE!" |
| **gaming-legends** | "YOU SHALL NOT PASS!" / "all your base are belong to us" |

Open source — add your own personality and submit a PR.

## Platform Notes

### UDM Pro Baseline Load Average

The UDM Pro kernel (4.19) has several I2C hardware monitoring drivers compiled in as builtins (not loadable modules). These poll continuously and cannot be disabled from userspace:

| Driver | Device | Function |
|--------|--------|----------|
| `adt7475` | `4-002e` | Temperature sensors, fan RPM, PWM control |
| `pca953x` | `0-0028` | GPIO expander (LEDs) |
| `pca954x` | `0-0071` | I2C bus multiplexer |
| `rtc-s35390a` | `1-0030` | Real-time clock |
| `dummy` | `1-0031` to `1-0037` | Unused I2C addresses (still polled) |

Additionally, the Annapurna Labs Ethernet switch driver (`al_mod_eth`) runs a permanent link detection loop across all ports in uninterruptible sleep (D-state), which the kernel counts as load.

This results in a **baseline load average of ~1.0-1.2** even when the system is completely idle (0% CPU usage). These are kernel threads in I/O wait — not actual CPU utilization.

The web UI accounts for this by using core-relative thresholds for load average coloring (warn at `cores`, error at `2x cores`) and displaying actual CPU utilization (delta-sampled from `/proc/stat`) separately from load average.

## Security First

Every design decision prioritizes security:

- No hardcoded keys or credentials
- No unauthenticated databases
- No trusted proxy headers (`X-Forwarded-For` is untrusted input — always socket peer)
- Encrypted at rest, encrypted in transit, encrypted in logs
- Minimal attack surface: one binary, one process, one language
- E2EE API layer: hybrid X25519 + ML-KEM-1024 (FIPS 203) key exchange, HKDF-SHA256, AES-256-GCM
- Security headers: HSTS, CSP, X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy
- Catch-all DROP on all firewall zones — no platform ports leak through
- Dual-stack IPv4/IPv6 firewall — no IPv6 bypass
- Rate limiting on every endpoint

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                      sfgw-cli                         │  ← Single binary entry point
├──────────┬──────────┬──────────┬─────────────────────┤
│ sfgw-fw  │ sfgw-net │ sfgw-vpn │      sfgw-api       │  ← Core services
├──────────┼──────────┼──────────┼─────────────────────┤
│ sfgw-dns │sfgw-adopt│ sfgw-nas │    sfgw-display     │  ← Peripheral services
├──────────┼──────────┴──────────┼─────────────────────┤
│sfgw-inform│  sfgw-personality  │   sfgw-controller   │  ← Protocol & orchestration
├──────────┼─────────────────────┼─────────────────────┤
│ sfgw-ids │     sfgw-crypto     │      sfgw-log       │  ← Detection & foundation
├──────────┴─────────────────────┴─────────────────────┤
│                sfgw-db  │  sfgw-hal                   │  ← Storage & hardware
│   bare_metal   │    vm    │    docker                 │     (compile-time or runtime)
└──────────────────────────────────────────────────────┘
```

## License

AGPL-3.0-or-later — [LICENSE](LICENSE)

Contributions require a [CLA](https://gist.github.com/CLAassistant/bd1ea8ec8aa0357414e8) to enable dual-licensing.
Commercial licenses available for organizations that cannot comply with AGPL.
