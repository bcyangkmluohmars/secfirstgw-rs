# Supported Hardware

## Verified

| Device | Board ID | Arch | RAM | Status | Notes |
|--------|----------|------|-----|--------|-------|
| UDM Pro | `ea15` | aarch64 | 4 GB | ✅ Tested | Full port detection, 10 MB RSS, dual WAN, switch0, LCD |

## Planned

| Device | Board ID | Arch | RAM | Status |
|--------|----------|------|-----|--------|
| UDM SE | `ea22` | aarch64 | 4 GB | Untested |
| UDM | `ea21` | aarch64 | 2 GB | Untested |
| USG 3P | `e610` | mips64 | 512 MB | Untested |
| USG Pro 4 | `e612` | mips64 | 2 GB | Untested |

## Generic Platforms

| Platform | Arch | Status | Notes |
|----------|------|--------|-------|
| VM (QEMU/KVM) | x86_64 / aarch64 | Untested | virtio-net, LUKS2 on vdisk |
| Docker | any | Untested | macvlan or host networking |
| Bare metal (x86) | x86_64 | Untested | Standard NICs via ethtool detection |

## Community Testing

Tested secfirstgw-rs on hardware not listed here? Open an issue or PR with:

- Device model and board ID (`cat /proc/ubnthal/board` on Ubiquiti devices)
- RAM and architecture (`uname -m`, `free -h`)
- Which interfaces were detected and assigned
- Any issues encountered

## Hardware Detection

secfirstgw-rs auto-detects Ubiquiti hardware via `/proc/ubnthal/board` and assigns port roles accordingly. On non-Ubiquiti hardware, interfaces are detected via netlink and can be assigned manually through the web UI or config file.
