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

## Security First

Every design decision prioritizes security:

- No hardcoded keys or credentials
- No unauthenticated databases
- No trusted proxy headers without validation
- Encrypted at rest, encrypted in transit, encrypted in logs
- Minimal attack surface: one binary, one process, one language

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
