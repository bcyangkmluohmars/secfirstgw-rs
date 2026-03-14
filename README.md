# secfirstgw-rs

> If you know, you know. If you don't — the firewall will let you know.

A security-focused gateway firmware, written in Rust. Runs on bare metal, VM, or Docker.

**Coming soon.**

## Why?

Because 180+ services, Java, MongoDB without auth, hardcoded credentials, and single-core VPN at 30 MB/s in 2026 is not acceptable.

## What?

A single Rust binary replacing bloated gateway stacks:

- **Firewall & Router** — nftables via netlink, stateful packet inspection
- **Network Controller** — device adoption, provisioning, monitoring
- **Multi-Core VPN** — WireGuard (boringtun) across all cores
- **DNS & DHCP** — dnsmasq config generation
- **Encrypted Storage** — LUKS2 FDE with hardware-bound key derivation
- **Forward-Secret Logs** — daily key rotation, old keys deleted after export
- **NAS** — SMB (ksmbd) + NFS
- **Web UI + API** — axum-based, minimal attack surface

## Platforms

| Platform | Networking | Storage | LCD |
|----------|-----------|---------|-----|
| Bare Metal (ARM64) | Hardware switch ASICs | LUKS2 on HDD | Yes |
| VM | virtio-net / e1000 | LUKS2 on vdisk | No |
| Docker | macvlan / host | Volume mount | No |

## Zone Model

Every interface is assigned a zone. Default firewall policies enforce strict isolation:

| Zone | Purpose |
|------|---------|
| **WAN** | Uplink(s) to internet. Multiple WAN ports supported with failover/load-balance. |
| **LAN** | Trusted internal network. Full access to services and web UI. |
| **DMZ** | Public-facing services. Isolated from LAN. |
| **MGMT** | Admin management. Web UI, SSH, device adoption (Inform). |
| **GUEST** | Untrusted clients. Internet only, no internal access. |

### Default Zone-to-Zone Forwarding Matrix

```
From \ To   │  WAN     LAN     DMZ     MGMT    GUEST
────────────┼──────────────────────────────────────────
WAN         │   -      DROP    DROP    DROP    DROP
LAN         │   ✓      ✓       ✓       ✓      DROP
DMZ         │   ✓      DROP    ✓       DROP    DROP
MGMT        │  opt     ✓       ✓       ✓       ✓
GUEST       │   ✓      DROP    DROP    DROP    DROP
```

### Per-Zone Input Rules (to Gateway)

| Service          | WAN  | LAN  | DMZ  | MGMT | GUEST |
|------------------|------|------|------|------|-------|
| Web UI (443)     | -    | -    | -    | ✓    | -     |
| SSH (22)         | -    | ✓    | -    | ✓    | -     |
| DNS (53)         | -    | ✓    | -    | ✓    | ✓     |
| DHCP (67/68)     | -    | ✓    | -    | ✓    | ✓     |
| Inform (8080)    | -    | -    | -    | ✓    | -     |
| Port Forwards    | ✓    | -    | -    | -    | -     |
| Ping (ICMP)      | rate | ✓    | rate | ✓    | rate  |

### WAN Failover / Load Balancing

Multiple interfaces can be assigned the WAN zone. Supported modes:

- **Failover** — active/standby with health checks (ping gateway). Automatic switchover on failure.
- **Load Balance** — weighted round-robin across healthy WANs via policy routing.

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
Port 1-7 (eth0-eth6)  → LAN (switch0, untagged VLAN 1)
Port 8   (eth7)       → MGMT (PVID 3000, untagged, 10.0.0.0/24)
Port 9   (eth8)       → WAN1 (RJ45)
Port 10  (eth9)       → WAN2 (SFP+)
Port 11  (eth10)      → LAN (SFP+)
```

### Default Networks

| Network | VLAN | Subnet | DHCP Pool | Status |
|---------|------|--------|-----------|--------|
| LAN | 1 (untagged) | 192.168.1.0/24 | .100-.254 | Active |
| WAN1 | - | DHCP (eth8) | - | Active |
| WAN2 | - | DHCP (eth9) | - | Active |
| Management | 3000 | 10.0.0.0/24 | .100-.254 | Active |
| Guest | 3001 | 192.168.3.0/24 | .100-.254 | Prepared |
| DMZ | 3002 | 172.16.0.0/24 | .100-.254 | Prepared |

Prepared networks are pre-configured but disabled. Enable them via the web UI to create the VLANs, bridges, and firewall rules automatically.

### Default Firewall Policy

31 rules are auto-created on first boot:

- **NAT**: Masquerade on all WAN interfaces
- **LAN**: Full internet access, can reach Guest/DMZ
- **Guest**: Internet only, all internal traffic blocked
- **DMZ**: Internet only, LAN/MGMT access blocked
- **MGMT**: Full access to everything
- **WAN inbound**: Default deny (except established/related)
- **Input**: Web UI (HTTPS) from MGMT only, SSH from LAN/MGMT, DNS/DHCP from all internal zones

### Default DNS/DHCP

- DNS forwarding to WAN gateway + 1.1.1.1 + 9.9.9.9
- DHCP on LAN: 192.168.1.100-254, 12h lease, domain `lan`
- DNSSEC validation enabled
- DNS rebind protection enabled

## Security First

Every design decision prioritizes security:

- No hardcoded keys or credentials
- No unauthenticated databases
- No trusted proxy headers without validation
- Encrypted at rest, encrypted in transit, encrypted in logs
- Minimal attack surface: one binary, one process, one language
- E2EE API layer: hybrid X25519 + ML-KEM-1024 (FIPS 203) key exchange, HKDF-SHA256, AES-256-GCM

## Architecture

```
┌─────────────────────────────────────────────┐
│                 sfgw-cli                     │  ← Single binary entry point
├──────────┬──────────┬──────────┬────────────┤
│ sfgw-fw  │ sfgw-net │ sfgw-vpn │  sfgw-api  │  ← Core services
├──────────┼──────────┼──────────┼────────────┤
│ sfgw-dns │sfgw-adopt│ sfgw-nas │  sfgw-lcd  │  ← Peripheral services
├──────────┴──────────┴──────────┴────────────┤
│ sfgw-crypto  │  sfgw-db  │  sfgw-log        │  ← Foundation
├──────────────┴───────────┴──────────────────┤
│              sfgw-hal                        │  ← Hardware abstraction
│    bare_metal  │    vm    │    docker        │     (compile-time or runtime)
└──────────────────────────────────────────────┘
```

## License

AGPL-3.0-or-later — [LICENSE](LICENSE)

Contributions require a [CLA](https://gist.github.com/CLAassistant/bd1ea8ec8aa0357414e8) to enable dual-licensing.
Commercial licenses available for organizations that cannot comply with AGPL.
