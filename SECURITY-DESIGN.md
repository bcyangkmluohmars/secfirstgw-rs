# Security Design Philosophy

> "lass mich in ruhe und geh dich ficken" — Every layer, to every attacker.

secfirstgw-rs is designed so that **every attack vector ends at a wall**. Not because a WAF blocks it, not because an IPS catches it — because the attack surface simply does not exist.

## Even Root is Useless

The ultimate test: an attacker has SSH root access on the gateway. What now?

| Attack | Result |
|--------|--------|
| Read keys from RAM | Encrypted + mlock'd. Only ciphertext. |
| Dump database | SQLite encrypted at rest. |
| Read config secrets | SecureBox<T>, only ciphertext in memory. |
| Forge session tokens | Bound to TLS session + IP + device fingerprint + envelope key. |
| Modify firmware | Code-signed (Ed25519 + ML-DSA-65). Won't boot. |
| Take over switches/APs | mTLS with pinned gateway cert. Rejected. |
| Sniff API traffic | E2EE envelope inside TLS. Two layers. |
| Disable IDS | Switches/APs report independently. Gateway is just the collector. |
| Delete logs | Forward-secret encrypted, already exported, old keys deleted. |
| Install backdoor | Next signed firmware update overwrites it. |
| Lateral movement | Switches/APs have zero open ports. Nowhere to go. |

**Root access = checkmate anyway.**

## Defense Layers

### Network Attack Surface

Typical enterprise gateway firmware exposes 12+ ports — databases, message brokers, management services, all listening. secfirstgw has a different approach:

```
Typical gateway stack:                secfirstgw-rs:
──────────────────────                ──────────────
Database   :27017/:5432 (often no auth) — (SQLite = embedded, no port)
Cache      :6379                        — (in-memory in binary)
Msg Broker :5672 + :15672               — (tokio channels, no broker)
App Server :8443 + :8080                sfgw-api :443 (HTTPS only)
Reverse Proxy :80 → redirect            :80 → 301 to :443
Device Mgmt   :8080                     :8080 (Adoption, MGMT VLAN only)
SSH           :22                       — (not installed)
──────────────────────                ──────────────
12+ open ports                        2-3 ports total
```

Port binding:
- **WAN**: `:443` only (API/UI, optionally disabled for remote management)
- **LAN**: `:443` + `:80→301`
- **MGMT VLAN**: `:443` + `:80→301` + `:8080` (Inform/Adoption) — **only** interface with Inform
- **Guest/IoT VLANs**: nothing

### Transport Security

- **TLS 1.3 only** — no 1.2 fallback, no legacy, no negotiation
- Two cipher suites: `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`
- **SMB3 only** — no SMB1/SMB2
- If you can't do TLS 1.3, you don't get in.

### API Double Encryption (E2EE Envelope)

```
Client                                    Gateway
  │                                          │
  │◄──────── TLS 1.3 (X25519+ML-KEM) ──────►│  Layer 1: Transport
  │                                          │
  │  { "envelope": {                         │
  │      "v": 1,                             │
  │      "eph_pub": "...",                   │  Layer 2: E2EE
  │      "nonce": "...",                     │  (AES-256-GCM)
  │      "ciphertext": "base64...",          │
  │      "tag": "..."                        │
  │  } }                                     │
  │                                          │
```

- Ephemeral key per session via Hybrid ECDH + ML-KEM
- Even with broken TLS (compromised CA, corporate inspection, Heartbleed-class bug): attacker sees only encrypted envelopes
- No replay: ephemeral key per request

### Session Security

Session tokens are bound to:
- **TLS Session ID** — different tunnel = token invalid
- **Client IP** — IP changes = token invalid
- **Device Fingerprint** — browser, screen, timezone hash
- **E2EE Envelope Key** — different key = token invalid

Stolen token is worthless without exact client state. Replicating client state requires network access — which you don't have (2 ports, mTLS, E2EE).

### Post-Quantum Cryptography

Hybrid approach — both must be broken:

| Purpose | Classical | Post-Quantum |
|---------|-----------|-------------|
| Key Exchange (Adoption/TLS) | X25519 | ML-KEM-1024 (FIPS 203) |
| Firmware Signing | Ed25519 | ML-DSA-65 (FIPS 204) |
| Config Signing | Ed25519 | ML-DSA-65 (FIPS 204) |

Protection against harvest-now-decrypt-later. Adoption keys live for years on devices — they must survive quantum computers.

### In-Memory Security

Every secret lives in `SecureBox<T>`:
- **zeroize on Drop** — no remnants in freed heap
- **mlock()** — never written to swap, ever
- **Guard pages** — buffer overflow → SIGSEGV, not key leak
- **RAM encryption** — ephemeral key in CPU register only
- **mprotect(PROT_NONE)** — unreadable when not actively used

`gdb attach` + heap search = nothing. Memory dump = ciphertext. Cold boot = ciphertext. DMA attack = ciphertext.

### Disk Security

- **LUKS2 Full Disk Encryption** on HDD
- Key derivation from board-bound values (serial + GUID from eMMC/NAND)
- LUKS Slot 0: auto-unlock (board-bound), Slot 1: user passphrase (recovery)
- HDD physically removable → steal it, get nothing

### Log Security

- **Forward-secret encryption** — daily key rotation
- Old keys deleted after export
- Even with root access: past logs are unreadable, keys are gone
- Optional: wipe-on-tamper if HDD removed without clean shutdown

### Managed Devices (Switches/APs)

- **Zero open ports** — no SSH, no HTTP, no SNMP, no telnet
- Not disabled — not compiled in. Code doesn't exist in binary.
- Communication: outbound TLS only, to gateway
- Config/firmware push over existing mTLS session
- Recovery: factory reset button → re-enter adoption mode
- No default SSH credentials. No SSH daemon. Period.

### Device Adoption Protocol

- **No default key** — every device gets unique secret at adoption
- **Manual approval** — admin must confirm in UI (no auto-adopt)
- **Mutual TLS** — device has client cert signed by gateway CA
- **Certificate pinning** — device accepts only the gateway CA pinned at adoption
- **Hybrid PQ key exchange** — X25519 + ML-KEM-1024
- **Monotone sequence numbers** — no config replay, no firmware downgrade
- **Signed configs** — device verifies signature before applying
- **Signed firmware** — Ed25519 + ML-DSA-65, version must strictly increase

### Distributed IDS

Every device in the network is an IDS sensor:
- **Gateway**: full packet inspection on all interfaces + correlation engine
- **Switches**: local ARP/DHCP/DNS/VLAN monitoring on every port
- **APs**: deauth floods, evil twin, rogue AP detection

Switches see intra-VLAN traffic that never reaches the gateway. All events reported to gateway collector for cross-node correlation. Alerting via Telegram + webhook.

Auto-response: port isolation, MAC block, rate limiting.

Even if the gateway IDS is disabled (root compromise), switches and APs continue reporting independently.

## Open Source as Security

The entire source code is public: [github.com/bcyangkmluohmars/secfirstgw-rs](https://github.com/bcyangkmluohmars/secfirstgw-rs)

GLHF.

We don't obfuscate. We don't hide. Find something. We'll wait.

Open source is not a risk when you have nothing to hide — no hardcoded keys, no default passwords, no shortcuts. Transparency is the strongest security argument there is.
