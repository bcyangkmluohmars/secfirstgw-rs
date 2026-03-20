<p align="center">
  <h1 align="center">secfirstgw-rs</h1>
  <p align="center">
    <strong>A security-first gateway firmware, written in Rust.</strong>
    <br />
    One binary. 11 MB RAM. Zero trust.
  </p>
  <p align="center">
    <a href="#quickstart"><strong>Quickstart</strong></a> · 
    <a href="docs/ARCHITECTURE.md"><strong>Architecture</strong></a> · 
    <a href="docs/SECURITY.md"><strong>Security Policy</strong></a> · 
    <a href="CONTRIBUTING.md"><strong>Contributing</strong></a>
  </p>
</p>

---

## Why Does This Exist?

We audited commercial gateway firmware. What we found was unacceptable.

180+ services running. Java. MongoDB without authentication. Hardcoded credentials baked into firmware images. Single-core VPN topping out at 30 MB/s on hardware capable of gigabit. 1.8 GB of RAM consumed before a single packet is routed. Exposed database ports on the management network. `X-Forwarded-For` trusted as gospel. Path traversal defenses that amount to `replace("../", "")`. Security patches that lag months behind disclosure.

This is not a theoretical concern. These are findings from real firmware running on real networks protecting real businesses.

**secfirstgw-rs** is the answer: a single static Rust binary that replaces the entire stack. 57,000 lines of Rust. 11 MB of RAM on a UDM Pro. No JVM. No databases listening on the network. No message brokers. No hardcoded anything. Every secret encrypted in memory. Every firewall zone ending with `DROP`.

If you know, you know. If you don't — the firewall will let you know.

## Features

### Firewall & Router

- **nftables** on modern kernels, **iptables-legacy** on older platforms (UDM Pro / kernel 4.19)
- **Dual-stack IPv4/IPv6** with identical policies — no IPv6 bypass
- **Zone-based security model**: WAN, LAN, DMZ, MGMT, GUEST, plus custom zones (IoT, VPN, user-defined)
- **Atomic ruleset application** via `iptables-restore` with SSH lockout rollback
- **Catch-all DROP** on every zone — nothing gets through unless explicitly allowed
- **NAT masquerade**, port forwarding, UPnP/NAT-PMP (disabled by default, LAN-only)
- **Traffic shaping (QoS)** — HTB with 4 priority classes, match by protocol/port/IP/DSCP

### WAN Failover & Load Balancing

- Multiple WAN interfaces with automatic failover
- HTTP probe, DNS resolve, and ICMP health checks
- Hysteresis and flap detection with configurable thresholds
- Sticky sessions via CONNMARK, per-zone WAN pinning
- Weighted round-robin load balancing across healthy WANs

### VPN

- **WireGuard** via [boringtun](https://github.com/cloudflare/boringtun) — multi-core, userspace
- **IPSec** via strongSwan (IKEv2, PSK + certificate auth, AES-256-GCM)
- Peer management with config generation, download, and QR code

### DNS & DHCP

- dnsmasq config generation with DHCP ranges, static leases, DNS overrides
- DNSSEC validation
- DNS rebind protection
- Per-zone DNS/DHCP policies

### Network Controller

- **UniFi Inform protocol** — full TNBU binary implementation (AES-128-CBC/GCM)
- Device adoption with SSH fingerprint verification and post-adoption hardening
- WiFi management: WPA2/WPA3, VLAN-tagged SSIDs, per-radio band selection
- Per-port switch config: PVID, tagged VLANs, PoE, egress rate limiting
- Tested end-to-end on real USW-Flex and UAP-AC-Pro hardware

### Intrusion Detection (IDS/IPS)

- ARP spoofing, DHCP starvation, DNS tunneling, VLAN hopping detection
- Alert correlation engine across all managed devices
- Auto-response: port isolation, MAC block, rate limiting
- Honeypot TCP listener with personality-flavored responses

### Security Architecture

- **E2EE API layer**: hybrid X25519 + ML-KEM-1024 (FIPS 203) key exchange, AES-256-GCM
- **Post-quantum cryptography**: hybrid classical + PQ for key exchange and firmware signing
- **In-memory encryption**: all secrets in `SecureBox<T>` — encrypted, mlock'd, zeroized on drop
- **TLS 1.3 only** — two cipher suites, no fallback, no negotiation
- **Encrypted database**: SQLite with SQLCipher (AES-256), hardware-bound key derivation
- **Forward-secret logs**: daily key rotation, old keys deleted after export
- **Session binding**: tokens bound to TLS session + IP + device fingerprint + envelope key
- No hardcoded keys. No unauthenticated databases. No trusted proxy headers.

### Display

- Native serial driver for UDM Pro front panel LCD (direct STM32F2 MCU communication)
- HD44780 LCD and framebuffer touchscreen abstraction
- Live system stats: CPU, memory, fan RPM, uptime — pushed every 3 seconds

### Extras

- **Personality system** — 7 switchable styles for error messages, honeypot, and IDS alerts
- **DDNS client** — DynDNS2, DuckDNS, Cloudflare with IP change detection
- **Backup/Restore** — JSON config export/import, secrets excluded, atomic restore
- **OTA firmware updates** — SHA-256 verified, atomic binary swap, auto-rollback on failure

## Personality

secfirstgw has attitude. Error messages, rate-limit responses, honeypot replies, and IDS alerts come with personality — switchable at runtime.

| Personality | 401 Unauthorized |
|-------------|-----------------|
| **kevin** (default) | "log dich ein junge!" |
| **corporate** | "authentication required" |
| **pirate** | "ye be no crew of mine!" |
| **zen** | "the gate remains closed to those who do not know the way" |
| **bofh** | "your credentials were lost in a tragic boating accident" |
| **unreal-tournament** | "DENIED!" |
| **gaming-legends** | "YOU SHALL NOT PASS!" |

[Add your own and submit a PR.](CONTRIBUTING.md)

## Zone Model

Every switch port has a PVID (Port VLAN ID) determining its zone. WAN ports are completely separated from the internal VLAN space. VLAN 1 is a void sink — all traffic dropped, never bridged.

```
From \ To   |  WAN     LAN     DMZ     MGMT    GUEST
────────────┼──────────────────────────────────────────
WAN         |   -      DROP    DROP    DROP    DROP
LAN         |   ✓      ✓       ✓       ✓      DROP
DMZ         |   ✓      DROP    ✓       DROP    DROP
MGMT        |  opt     ✓       ✓       ✓       ✓
GUEST       |   ✓      DROP    DROP    DROP    DROP
```

Services accessible per zone:

| Service | WAN | LAN | DMZ | MGMT | GUEST |
|---------|-----|-----|-----|------|-------|
| Web UI (443) | - | - | - | ✓ | - |
| SSH (22) | - | - | - | ✓ | - |
| DNS (53) | - | ✓ | ✓ | ✓ | ✓ |
| DHCP (67/68) | - | ✓ | ✓ | ✓ | ✓ |
| Inform (8080) | - | - | - | ✓ | - |
| **Catch-all** | DROP | DROP | DROP | DROP | DROP |

For the complete security architecture, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Supported Platforms

| Platform | Networking | Storage | Display | Status |
|----------|-----------|---------|---------|--------|
| **UDM Pro** (aarch64) | Hardware switch ASICs | LUKS2 on HDD | Native LCM serial | ✅ Verified |
| **UDM SE** (aarch64) | Hardware switch ASICs | LUKS2 on HDD | Native LCM serial | Prepared |
| VM (QEMU/KVM) | virtio-net / e1000 | LUKS2 on vdisk | - | Untested |
| Docker | macvlan / host | Volume mount | - | Untested |
| Bare metal (x86_64) | Standard NICs | LUKS2 | - | Untested |

See [HARDWARE.md](HARDWARE.md) for detailed hardware support and community testing info.

## Quickstart

### One-Liner Install (UDM Pro / Bare Metal)

SSH into your gateway device and run:

```bash
curl -fsSL https://raw.githubusercontent.com/bcyangkmluohmars/secfirstgw-rs/main/scripts/clean-and-install.sh | bash -
```

The install script will:
1. Detect your architecture and platform
2. Back up existing UniFi config (if present)
3. Download and verify the latest release (SHA-256)
4. Install the binary and systemd service
5. Mask conflicting UniFi services
6. Start secfirstgw and verify SSH connectivity

**After install:** Open `https://<device-ip>` from a device on the MGMT network to complete setup.

### Build from Source

```bash
# Prerequisites: Rust stable toolchain, Node.js (for web UI)
git clone https://github.com/bcyangkmluohmars/secfirstgw-rs.git
cd secfirstgw-rs

# Development build
make build

# Run tests
make test

# Cross-compile for ARM64 (UDM Pro)
make aarch64

# Build distribution tarballs for both architectures
make dist
```

### Docker

```bash
docker compose up --build
```

For detailed setup instructions, see [docs/QUICKSTART.md](docs/QUICKSTART.md).

## Architecture

secfirstgw-rs is a Cargo workspace with 16 crates, each with a single responsibility:

```
┌──────────────────────────────────────────────────────────┐
│                       sfgw-cli                           │  ← Single binary entry point
├──────────┬──────────┬──────────┬─────────────────────────┤
│ sfgw-fw  │ sfgw-net │ sfgw-vpn │      sfgw-api           │  ← Core services
├──────────┼──────────┼──────────┼─────────────────────────┤
│ sfgw-dns │sfgw-adopt│ sfgw-nas │    sfgw-display         │  ← Peripheral services
├──────────┼──────────┴──────────┼─────────────────────────┤
│sfgw-inform│ sfgw-personality   │   sfgw-controller       │  ← Protocol & orchestration
├──────────┼─────────────────────┼─────────────────────────┤
│ sfgw-ids │    sfgw-crypto      │      sfgw-log           │  ← Detection & foundation
├──────────┴─────────────────────┴─────────────────────────┤
│              sfgw-db   │   sfgw-hal                       │  ← Storage & hardware
└──────────────────────────────────────────────────────────┘
```

| Crate | Purpose |
|-------|---------|
| `sfgw-cli` | Binary entry point, arg parsing, service orchestration |
| `sfgw-fw` | Firewall rules (nftables/iptables), zone matrix, QoS, WAN failover |
| `sfgw-net` | Interface management, VLANs, routing, switch ASIC, WiFi |
| `sfgw-vpn` | WireGuard (boringtun) + IPSec (strongSwan) |
| `sfgw-dns` | dnsmasq config generation, DHCP/DNS |
| `sfgw-api` | axum HTTP API, TLS 1.3, E2EE middleware, auth, rate limiting |
| `sfgw-db` | SQLite + SQLCipher, migrations, encrypted storage |
| `sfgw-crypto` | SecureBox, hybrid PQ crypto, key derivation |
| `sfgw-adopt` | Device adoption, mTLS CA, certificate management |
| `sfgw-inform` | UniFi TNBU protocol, Inform handler, system_cfg |
| `sfgw-ids` | ARP/DHCP/DNS/VLAN anomaly detection, alert correlation |
| `sfgw-log` | Forward-secret log encryption |
| `sfgw-hal` | Hardware abstraction, Ubiquiti board detection |
| `sfgw-display` | LCM serial, HD44780, framebuffer |
| `sfgw-nas` | SMB (ksmbd) + NFS |
| `sfgw-personality` | Switchable error message personalities |
| `sfgw-controller` | High-level service lifecycle orchestration |

For the full architectural deep dive, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Network Attack Surface Comparison

```
Typical gateway stack:                secfirstgw-rs:
──────────────────────                ──────────────
Database   :27017/:5432 (often no auth) — (SQLite = embedded, no port)
Cache      :6379                        — (in-memory, no port)
Msg Broker :5672 + :15672               — (tokio channels, no broker)
App Server :8443 + :8080                  :443 (TLS 1.3 only)
Reverse Proxy :80 → redirect              :80 → 301 to :443
Device Mgmt   :8080                       :8080 (Inform, MGMT VLAN only)
SSH           :22                        — (not installed on managed devices)
──────────────────────                ──────────────
12+ open ports                        2-3 ports total
```

## How It Compares

| Capability | secfirstgw-rs | Typical Commercial |
|-----------|---------------|-------------------|
| RAM usage | **11 MB** | 1.8 GB+ |
| Open network ports | **2-3** | 12+ |
| VPN throughput | Multi-core WireGuard | Single-core, 30 MB/s |
| Database | Embedded SQLite (no port) | MongoDB/PostgreSQL (network-exposed) |
| Encryption at rest | LUKS2 + SQLCipher + SecureBox | Varies |
| Post-quantum crypto | X25519 + ML-KEM-1024 | None |
| API encryption | E2EE envelope inside TLS | TLS only |
| Source code | **Fully open (AGPL-3.0)** | Proprietary |
| Hardcoded credentials | **None** | [Redacted] |
| IPv6 firewall | Identical to IPv4 | Often incomplete |
| Firmware verification | Ed25519 + ML-DSA-65 | Varies |

We do not name specific vendors in this comparison. The numbers speak for themselves. If you've audited commercial gateway firmware, you already know.

## Project Status

**Current version: v0.3.0** — See [ROADMAP.md](ROADMAP.md) for detailed status.

**Working:** Firewall (nftables + iptables-legacy), zone model, dual-stack IPv4/IPv6, Web UI + API (axum, TLS 1.3, E2EE), DNS/DHCP, UniFi Inform adoption, WiFi management, IDS active response, honeypot, QoS, WAN failover, DDNS, backup/restore, OTA updates, UPnP/NAT-PMP, IPSec, LCM display, SQLCipher, personality system.

**In progress:** Forward-secret logging, NAS (SMB/NFS), LUKS2 integration.

**Planned:** Multi-site VPN, HA (active/passive failover), advanced WiFi (multi-SSID VAP, 802.11r).

## Contributing

We welcome contributions — especially personalities, IDS signatures, platform support, and tests.

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [CLAUDE.md](CLAUDE.md) (yes, the coding directives apply to humans too).

**We will never accept:**
- Telemetry or phone-home functionality
- Closed-source dependencies
- Weakening of any security guarantee for convenience
- `TrustAllCerts` or equivalent in any form

## Security

**Found a vulnerability?** Do NOT open a public issue. See [docs/SECURITY.md](docs/SECURITY.md) for responsible disclosure.

We respond within 48 hours. We credit researchers. We will never mark a valid finding as "Informational."

## License

**AGPL-3.0-or-later** — [LICENSE](LICENSE)

The entire source code is public. We don't obfuscate. We don't hide. Transparency is the strongest security argument there is.

Contributions require a [CLA](https://gist.github.com/CLAassistant/bd1ea8ec8aa0357414e8) to enable dual-licensing. Commercial licenses available for organizations that cannot comply with AGPL.

---

<p align="center">
  <sub>57,000 lines of Rust · 16 crates · 1 binary · 11 MB RAM · Zero trust</sub>
</p>
