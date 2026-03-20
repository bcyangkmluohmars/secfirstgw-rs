# Architecture

> Every design decision in secfirstgw-rs answers one question: "What happens if an attacker controls this input?"

## Overview

secfirstgw-rs compiles to a single static binary (`sfgw`) that replaces the entire gateway software stack. There is no JVM, no database server, no message broker, no reverse proxy — just one process managing the network.

```
┌──────────────────────────────────────────────────────────┐
│                       sfgw-cli                           │  Binary entry point
├──────────┬──────────┬──────────┬─────────────────────────┤
│ sfgw-fw  │ sfgw-net │ sfgw-vpn │      sfgw-api           │  Core services
├──────────┼──────────┼──────────┼─────────────────────────┤
│ sfgw-dns │sfgw-adopt│ sfgw-nas │    sfgw-display         │  Peripheral services
├──────────┼──────────┴──────────┼─────────────────────────┤
│sfgw-inform│ sfgw-personality   │   sfgw-controller       │  Protocol & orchestration
├──────────┼─────────────────────┼─────────────────────────┤
│ sfgw-ids │    sfgw-crypto      │      sfgw-log           │  Detection & foundation
├──────────┴─────────────────────┴─────────────────────────┤
│              sfgw-db   │   sfgw-hal                       │  Storage & hardware
└──────────────────────────────────────────────────────────┘
```

All inter-crate communication happens through Rust function calls and tokio channels. There are no network sockets between internal components.

## Zone Model

secfirstgw-rs enforces network segmentation through a zone-based firewall model. Every physical port and VLAN is assigned to exactly one zone. Traffic between zones is controlled by an explicit forwarding matrix with **default deny**.

### Core Zones

| Zone | Purpose | Access to Gateway |
|------|---------|-------------------|
| **WAN** | Internet uplink(s). Multiple ports supported with failover/load-balance. | Port forwards only |
| **LAN** | Trusted internal network. Standard clients. | DNS, DHCP |
| **DMZ** | Public-facing services. Isolated from LAN and MGMT. | DNS, DHCP only |
| **MGMT** | Administrator management. The only zone with Web UI, SSH, and Inform access. | Full |
| **GUEST** | Untrusted clients. Internet only, no internal access. | DNS, DHCP |

Custom zones (IoT, VPN, user-defined) can be created with configurable inbound/outbound/forward policies. MGMT access is always blocked from custom zones — this is a security invariant enforced in code.

### Zone-to-Zone Forwarding Matrix

```
From \ To   |  WAN     LAN     DMZ     MGMT    GUEST
────────────┼──────────────────────────────────────────
WAN         |   -      DROP    DROP    DROP    DROP
LAN         |   ✓      ✓       ✓       ✓      DROP
DMZ         |   ✓      DROP    ✓       DROP    DROP
MGMT        |  opt     ✓       ✓       ✓       ✓
GUEST       |   ✓      DROP    DROP    DROP    DROP
```

**Key principles:**
- WAN inbound is always DROP (except established/related and explicit port forwards)
- Guest can reach the internet but nothing else
- DMZ can reach the internet and itself, but never LAN or MGMT
- Only MGMT has full access (Web UI, SSH, device adoption)
- Every chain ends with a catch-all DROP — no traffic leaks to platform services

### Per-Zone Input Rules (Traffic to the Gateway Itself)

| Service | WAN | LAN | DMZ | MGMT | GUEST |
|---------|-----|-----|-----|------|-------|
| Web UI (443) | - | - | - | ✓ | - |
| SSH (22) | - | - | - | ✓ | - |
| DNS (53) | - | ✓ | ✓ | ✓ | ✓ |
| DHCP (67/68) | - | ✓ | ✓ | ✓ | ✓ |
| Inform (8080) | - | - | - | ✓ | - |
| Port Forwards | ✓ | - | - | - | - |
| Ping (ICMP) | rate-limited | ✓ | rate-limited | ✓ | rate-limited |
| **Catch-all** | **DROP** | **DROP** | **DROP** | **DROP** | **DROP** |

### VLAN Architecture

The zone model is implemented through VLANs on the switch ASIC:

- Every switch port has a **PVID** (Port VLAN ID) that determines its untagged zone
- Ports can additionally carry **tagged VLANs** for trunk membership
- WAN ports use PVID 0 — completely separated from the internal VLAN space
- **VLAN 1 is a void sink** — all switch ports are tagged members, but no bridge is created. Any unclassified traffic lands in VLAN 1 and is silently dropped
- Traffic always flows through bridge interfaces (`br-lan`, `br-mgmt`, etc.), never individual switch ports

**Default VLAN assignments (UDM Pro):**

| VLAN | Zone | Subnet | Purpose |
|------|------|--------|---------|
| 1 | Void | - | Catch-all sink (all DROP) |
| 10 | LAN | 192.168.1.0/24 | Trusted clients |
| 3000 | MGMT | 10.0.0.0/24 | Administration |
| 3001 | GUEST | 192.168.3.0/24 | Untrusted clients |
| 3002 | DMZ | 172.16.0.0/24 | Public services |
| - | WAN1 | DHCP | Internet uplink (RJ45) |
| - | WAN2 | DHCP | Internet uplink (SFP+) |

### IPv6

All filter rules are dual-stack. IPv4 (`iptables`) and IPv6 (`ip6tables`) policies are identical. IPv6 additionally permits ICMPv6 neighbor discovery (NDP types 133-136) required for IPv6 to function.

There is no "IPv6 is handled separately" or "we'll add IPv6 later." Every rule, every zone, every policy works on both stacks from day one.

## Firewall Implementation

### Atomic Application

All firewall rules are applied atomically via `iptables-restore`. Rules are generated in memory, written as a complete ruleset, and loaded in a single kernel call. There is no window where rules are partially applied.

### SSH Lockout Prevention

Before applying any ruleset, `validate_no_lockout()` verifies that SSH access from the current management session will not be blocked. If validation fails, the ruleset is rejected before application. The dev-deploy script additionally implements a watchdog timer: if the new binary fails to start within a timeout, the previous binary is restored and SSH access is guaranteed.

### IDS Active Response

When the IDS detects a threat exceeding the configured threshold, it calls into `sfgw-fw::ids_response` to insert blocking rules. These rules are:
- Applied atomically (no partial state)
- Rate-limited (one rule application per source IP per interval)
- Time-limited (auto-expire with background cleanup task)

## Cryptographic Architecture

### Transport: TLS 1.3 Only

- **No TLS 1.2 fallback**. No negotiation. No legacy cipher suites.
- Two cipher suites: `TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256`
- If a client cannot do TLS 1.3, it does not get in.

### Application: E2EE Envelope

Every API request to a protected endpoint is wrapped in an additional encryption layer on top of TLS:

```
Client                                    Gateway
  |                                          |
  |<-------- TLS 1.3 (X25519+ML-KEM) ------>|  Layer 1: Transport
  |                                          |
  |  { "envelope": {                         |
  |      "v": 1,                             |
  |      "eph_pub": "...",                   |  Layer 2: E2EE
  |      "nonce": "...",                     |  (AES-256-GCM)
  |      "ciphertext": "base64...",          |
  |      "tag": "..."                        |
  |  } }                                     |
  |                                          |
```

- Ephemeral key per session via Hybrid ECDH (X25519 + ML-KEM-1024)
- Even with broken TLS (compromised CA, corporate MITM inspection, Heartbleed-class bug): the attacker sees only encrypted envelopes
- No replay: ephemeral key per request
- CSRF protection is inherent — the E2EE envelope provides equivalent guarantees

### Session Security

Session tokens are bound to four factors:
1. **TLS Session ID** — different TLS tunnel = token invalid
2. **Client IP** — IP change = token invalid
3. **Device Fingerprint** — browser/screen/timezone hash
4. **E2EE Envelope Key** — different key = token invalid

A stolen token is worthless without replicating the exact client state. Replicating the client state requires network access — which you don't have.

### In-Memory Security: SecureBox

Every secret in secfirstgw lives in a `SecureBox<T>`:

| Protection | What It Prevents |
|-----------|-----------------|
| AES-256-GCM encryption with ephemeral key | Cold boot attacks, DMA attacks |
| `mlock()` | Secrets written to swap |
| `madvise(MADV_DONTDUMP)` | Secrets in core dumps |
| `zeroize` on Drop | Remnants in freed heap |
| Guard pages | Buffer overflow → SIGSEGV, not key leak |
| `mprotect(PROT_NONE)` when idle | Readable only during active use |

`gdb attach` + heap search = nothing. Memory dump = ciphertext. Cold boot = ciphertext.

### Post-Quantum Cryptography

Hybrid approach — both classical and post-quantum algorithms must be broken:

| Purpose | Classical | Post-Quantum |
|---------|-----------|-------------|
| Key Exchange | X25519 | ML-KEM-1024 (FIPS 203) |
| Firmware Signing | Ed25519 | ML-DSA-65 (FIPS 204) |
| Config Signing | Ed25519 | ML-DSA-65 (FIPS 204) |

This protects against harvest-now-decrypt-later attacks. Device adoption keys live for years — they must survive quantum computers.

### Disk Security

- **LUKS2 Full Disk Encryption** for HDD storage
- Key derivation from hardware-bound values (board serial + CPU ID + MAC) via HKDF-SHA256
- Slot 0: auto-unlock (board-bound) — seamless boot without passphrase
- Slot 1: user passphrase (recovery)
- HDD physically removable → steal it, get nothing

### Database Encryption

- SQLite encrypted at rest via SQLCipher (AES-256)
- Key derived from hardware fingerprint via HKDF-SHA256
- Key zeroized immediately after PRAGMA, never touches disk
- Automatic plain-to-encrypted migration on first start

### Log Security

- Forward-secret encryption with daily key rotation
- Old keys deleted after export — past logs are permanently unreadable
- Even with root access, an attacker cannot read historical logs

## Threat Model

### What We Defend Against

| Threat | Mitigation |
|--------|-----------|
| Remote exploitation | 2-3 open ports (vs 12+), minimal attack surface |
| TLS compromise | E2EE envelope provides second encryption layer |
| Session hijacking | Token bound to TLS session + IP + fingerprint + E2EE key |
| Memory forensics | SecureBox: encrypted + mlock'd + zeroized on drop |
| Disk theft | LUKS2 FDE with hardware-bound keys |
| Swap forensics | All secrets mlock'd — never written to swap |
| Database compromise | SQLCipher encryption, hardware-bound key |
| IPv6 bypass | Identical dual-stack policies |
| Config replay | Monotone sequence numbers on device configs |
| Firmware downgrade | Version must strictly increase, dual-signed |
| Lateral movement | Managed devices have zero open ports |
| IDS evasion | Distributed sensors — switches/APs report independently |
| Root compromise on gateway | See below |

### Even Root Is Not Enough

The ultimate test: an attacker has SSH root access on the gateway.

| Attack | Result |
|--------|--------|
| Read keys from RAM | Encrypted + mlock'd. Only ciphertext. |
| Dump database | SQLCipher encrypted at rest. |
| Read config secrets | SecureBox, only ciphertext in memory. |
| Forge session tokens | Bound to TLS session + IP + fingerprint + envelope key. |
| Modify firmware | Code-signed (Ed25519 + ML-DSA-65). Won't boot. |
| Take over switches/APs | mTLS with pinned gateway cert. Rejected. |
| Sniff API traffic | E2EE envelope inside TLS. Two layers. |
| Disable IDS | Switches/APs report independently. |
| Delete logs | Forward-secret encrypted, already exported, old keys deleted. |
| Install backdoor | Next signed firmware update overwrites it. |

### What We Do NOT Defend Against

- Physical access to the running device with unlocked screen
- Compromise of the build pipeline (supply chain attack)
- Zero-day in the Linux kernel itself
- Nation-state adversaries with custom silicon — though we make it expensive

## Device Adoption Protocol

secfirstgw implements the UniFi Inform protocol for managing Ubiquiti switches and access points. The adoption flow prioritizes security over convenience:

1. **Discovery** — Device sends Inform packet (AES-128-CBC with default key). Gateway validates OUI, source IP, and model code. Failed validation = Phantom device + IDS event.
2. **Pending** — Device appears in admin UI. No auto-adopt. Admin must explicitly click "Adopt."
3. **SSH Fingerprint Verification** — Gateway connects to device via SSH, verifies hardware fingerprint from EEPROM. If fingerprint doesn't match expectations, adoption is rejected.
4. **Key Exchange** — Unique authkey delivered to device via Inform response (`mgmt_cfg`). SSH is never used for key delivery.
5. **Hardening** — `system_cfg` pushed: custom SSH user created, `ubnt` default user disabled, iptables restricted to gateway-only access, syslog forwarding enabled.
6. **Post-Adoption Verification** — Gateway SSH-connects to verify hardening was applied. Three attempts with IDS critical alert on exhaustion.

After adoption, all communication switches to AES-128-GCM with the per-device authkey. The default key is never used again.

Full protocol documentation: [inform-adoption-flow.md](inform-adoption-flow.md)

## Hardware Auto-Detection

On Ubiquiti hardware, `sfgw-hal` reads `/proc/ubnthal/board` to determine the device model and auto-assign port roles:

| Board ID | Device | WAN Ports | MGMT Port | LAN Ports |
|----------|--------|-----------|-----------|-----------|
| `ea15` | UDM Pro | eth8, eth9 (SFP+) | eth7 | eth0-eth6, eth10 (SFP+) |
| `ea22` | UDM SE | eth8, eth9 (SFP+) | eth7 | eth0-eth6 |
| `ea21` | UDM | eth4, eth5 | - | eth0-eth3 |
| `e610` | USG 3P | eth0 | - | eth1-eth2 |
| `e612` | USG Pro 4 | eth0, eth2 | - | eth1, eth3 |

On non-Ubiquiti hardware, interfaces are detected via netlink and can be assigned through the web UI.

## Build Targets

The project cross-compiles to static musl binaries for deployment on embedded hardware:

- `make aarch64` — ARM64 (UDM Pro, UDM SE, generic ARM routers)
- `make x86_64` — x86_64 (VMs, bare metal x86 appliances)
- `make dist` — Distribution tarballs for both architectures

The web UI (React + TypeScript) is built and embedded in the distribution tarball. The binary serves the UI directly — no reverse proxy needed.

## Why Open Source

The entire source code is public.

We don't obfuscate. We don't hide. Security through obscurity is not security. When you have no hardcoded keys, no default passwords, and no shortcuts, transparency is the strongest argument there is.

Find something. We'll wait.
