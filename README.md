# secfirstgw-rs

> If you know, you know.

A security-focused gateway firmware, written in Rust. Runs on bare metal, VM, or Docker.

**Coming soon.**

## Why?

Because 180+ services, Java, MongoDB without auth, hardcoded credentials, and single-core VPN at 30 MB/s in 2026 is not acceptable.

## What?

A single Rust binary replacing bloated gateway stacks:

- **Firewall & Router** — nftables via netlink, stateful packet inspection
- **Network Controller** — device adoption, provisioning, monitoring
- **Multi-Core VPN** — WireGuard (boringtun) + OpenVPN across all cores
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
| Web UI (443)     | -    | ✓    | -    | ✓    | -     |
| SSH (22)         | -    | -    | -    | ✓    | -     |
| DNS (53)         | -    | ✓    | -    | ✓    | ✓     |
| DHCP (67/68)     | -    | ✓    | -    | ✓    | ✓     |
| Inform (8080)    | -    | -    | -    | ✓    | -     |
| Port Forwards    | ✓    | -    | -    | -    | -     |
| Ping (ICMP)      | rate | ✓    | rate | ✓    | rate  |

### WAN Failover / Load Balancing

Multiple interfaces can be assigned the WAN zone. Supported modes:

- **Failover** — active/standby with health checks (ping gateway). Automatic switchover on failure.
- **Load Balance** — weighted round-robin across healthy WANs via policy routing.

## Security First

Every design decision prioritizes security:

- No hardcoded keys or credentials
- No unauthenticated databases
- No trusted proxy headers without validation
- Encrypted at rest, encrypted in transit, encrypted in logs
- Minimal attack surface: one binary, one process, one language
- E2EE API layer: X25519 ECDH + HKDF + AES-256-GCM envelope encryption

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

Contributions require a [CLA](CLA.md) to enable dual-licensing.
Commercial licenses available for organizations that cannot comply with AGPL.
