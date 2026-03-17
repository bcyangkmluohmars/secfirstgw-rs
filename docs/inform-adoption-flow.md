# UniFi Inform Adoption Flow

Complete documentation of the secfirstgw-rs device adoption protocol, from first contact to verified hardened state.

## Overview

secfirstgw-rs implements a UniFi-compatible Inform protocol for managing Ubiquiti network devices (switches, APs). The adoption flow uses a combination of the TNBU binary protocol (port 8080) and SSH to bring a factory-default device under management.

**Key design principle**: The authkey is delivered via the Inform response (`mgmt_cfg`), never via SSH/mca-ctrl. SSH is only used for fingerprint verification (pre-adoption) and config verification (post-adoption).

## Protocol: TNBU Packet Format

All Inform communication uses the TNBU binary packet format:

```
Offset  Size  Field
0       4     Magic: "TNBU" (0x54 0x4E 0x42 0x55)
4       4     Packet version (always 0)
8       6     Hardware MAC address
14      2     Flags (bitfield)
16      16    AES Initialization Vector
32      4     Data version (always 1)
36      4     Data length (encrypted payload size)
40      N     Encrypted payload
```

### Flags Bitfield

| Bit | Hex  | Meaning            |
|-----|------|--------------------|
| 0   | 0x01 | Encrypted          |
| 1   | 0x02 | zlib compressed    |
| 2   | 0x04 | Snappy compressed  |
| 3   | 0x08 | AES-128-GCM mode   |

Common flag combinations:
- `0x01` (1) — AES-128-CBC, no compression (factory default)
- `0x05` (5) — AES-128-CBC + Snappy
- `0x09` (9) — AES-128-GCM, no compression
- `0x0D` (13) — AES-128-GCM + Snappy (adopted devices)

### Encryption Modes

| State      | Mode        | Key                          | Nonce    |
|------------|-------------|------------------------------|----------|
| Unadopted  | AES-128-CBC | `MD5("ubnt")` = `ba86f2bb...`| 16-byte IV, PKCS7 padding |
| Adopted    | AES-128-GCM | Per-device authkey (16 bytes)| Full 16-byte IV as nonce  |

GCM mode uses the 40-byte TNBU header as Additional Authenticated Data (AAD). The GCM auth tag (16 bytes) is appended to the ciphertext. The `data_length` field includes the tag.

The 16-byte GCM nonce matches Java's `GCMParameterSpec(128, iv)` used by UniFi firmware (`mcad`).

## Device States

```
                           ┌──────────┐
                           │ PHANTOM  │ ← passive validation failed
                           └──────────┘
                                 │ (re-validates on next inform)
                                 ▼
┌─────────────┐  inform   ┌──────────┐  admin    ┌──────────┐  SSH ok   ┌──────────┐
│ Factory     │ ────────► │ PENDING  │ ────────► │ ADOPTING │ ────────► │ ADOPTED  │
│ Default     │           │          │  "adopt"  │          │           │          │
└─────────────┘           ├──────────┤           └──────────┘           └──────────┘
                          │ IGNORED  │ ← admin clicked "ignore"
                          └──────────┘
```

- **Pending** — Passed passive validation (OUI check, IP match, model recognition). Visible in UI, waiting for admin decision.
- **Ignored** — Admin chose to ignore. Still accepts informs silently, separate UI tab.
- **Adopting** — Admin clicked "Adopt". SSH fingerprint verification in progress.
- **Adopted** — Verified, authkey exchanged, system_cfg provisioned, SSH-verified.
- **Phantom** — Failed passive validation. Logged as IDS security event. Not shown in main device list.

## Complete Adoption Flow

### Phase 1: Discovery (Passive)

```
Device                          Gateway (port 8080)
  │                                │
  │  POST /inform [TNBU, CBC]     │
  │ ─────────────────────────────► │
  │                                │ 1. Parse TNBU header
  │                                │ 2. Decrypt AES-128-CBC with default key
  │                                │ 3. Decompress (if flagged)
  │                                │ 4. Parse JSON payload
  │                                │ 5. Passive validation:
  │                                │    - MAC OUI = Ubiquiti?
  │                                │    - Source IP = claimed IP?
  │                                │    - Model code known?
  │                                │ 6. Store as PENDING in DB
  │  TNBU response: noop(30)      │
  │ ◄───────────────────────────── │
  │                                │
  │  (repeats every 30s)           │
```

**Passive validation** (Stufe 1) runs on every new device. If validation fails, the device is stored as PHANTOM and an IDS event is logged. The device still receives a `noop` response (no information leakage to attacker).

**Source files**: `handler.rs:validate_inform()`, `payload.rs:is_ubiquiti_oui()`

### Phase 2: SSH Fingerprint Verification

When the admin clicks "Adopt" in the UI:

```
Gateway                             Device (SSH port 22)
  │                                    │
  │  SSH connect (ubnt/ubnt)           │
  │ ──────────────────────────────────►│
  │                                    │
  │  cat /proc/ubnthal/system.info     │
  │ ──────────────────────────────────►│
  │                                    │
  │  cpuid=1617657f                    │
  │  serialno=ac8ba9a8a5e1            │
  │  device.hashid=...                 │
  │  systemid=...                      │
  │  boardrevision=...                 │
  │  vendorid=...                      │
  │ ◄──────────────────────────────────│
  │                                    │
  │  Validate fingerprint              │
  │  Generate authkey (CSPRNG, 16 bytes → 32 hex)
  │  Generate SSH user (sfgw_XXYYZZ)  │
  │  Generate SSH password (24 chars)  │
  │  Hash password (SHA-512 crypt)     │
  │                                    │
  │  SSH disconnect                    │
  │ ──────────────────────────────────►│
  │                                    │
  │  Store in DB:                      │
  │    state = Adopted                 │
  │    authkey = <generated>           │
  │    ssh_username = sfgw_a8a5e1      │
  │    ssh_password = <generated>      │
  │    ssh_password_hash = $6$...      │
  │    fingerprint = {cpuid, serial, ...}
```

**Critical**: SSH is ONLY used to read the hardware fingerprint. Nothing is written to the device via SSH. No `mca-ctrl`, no config changes, no `set-inform`. The authkey is delivered exclusively through the Inform response in the next phase.

**SSH credentials**: Factory default `ubnt/ubnt`. If these don't work (device already provisioned), adoption fails and stays in Adopting state (retryable after factory reset).

**Source files**: `provision.rs:provision_device()`

### Phase 3: Authkey Delivery via Inform

The device continues sending CBC-encrypted informs. The handler detects it's Adopted but still on CBC:

```
Device                          Gateway
  │                                │
  │  POST /inform [CBC, default key]│
  │ ─────────────────────────────► │
  │                                │ State = Adopted, flags = CBC
  │                                │ → deliver authkey via mgmt_cfg
  │                                │
  │  setparam response:            │
  │  {                             │
  │    "_type": "setparam",        │
  │    "interval": 10,             │
  │    "mgmt_cfg": "               │
  │      capability=notif,...      │
  │      cfgversion=0000000000000000│ ← zero: system_cfg not sent yet
  │      led_enabled=true          │
  │      stun_url=stun://10.0.0.1:3478/
  │      mgmt_url=https://10.0.0.1:8443/...
  │      authkey=<32 hex chars>    │ ← the per-device key
  │      use_aes_gcm=true          │
  │      report_crash=true         │
  │    "                           │
  │  }                             │
  │ ◄───────────────────────────── │
  │                                │
  │  mcad stores authkey in        │
  │  /var/etc/persistent/cfg/mgmt  │
  │  Switches to GCM mode          │
```

**cfgversion = `0000000000000000`**: This sentinel value prevents the GCM branch from falsely thinking the system_cfg was already applied. When the device re-informs with GCM and reports this cfgversion, the handler knows system_cfg still needs to be delivered.

**mcad behavior**: The `mcad` daemon (on the device) parses the `mgmt_cfg`, stores the authkey in `/var/etc/persistent/cfg/mgmt`, sets `use_aes_gcm=true`, and immediately switches to GCM encryption for subsequent informs. The authkey is stored UPPERCASE on the device.

**Source files**: `handler.rs` (CBC branch of Adopted state), `system_cfg.rs:generate_mgmt_cfg()`

### Phase 4: System Config Delivery (GCM)

The device now sends GCM-encrypted informs with the new authkey:

```
Device                          Gateway
  │                                │
  │  POST /inform [GCM+Snappy, authkey]
  │ ─────────────────────────────► │
  │                                │ Decrypt with authkey (GCM, 40-byte header AAD)
  │                                │ Decompress (Snappy)
  │                                │ Parse JSON
  │                                │ device.cfgversion = "0000000000000000"
  │                                │ expected_cfgversion = "ce7a440e8e4e6ef6"
  │                                │ → mismatch → deliver system_cfg
  │                                │
  │  setparam response:            │
  │  {                             │
  │    "_type": "setparam",        │
  │    "interval": 10,             │
  │    "mgmt_cfg": "...",          │ ← cfgversion=ce7a440e8e4e6ef6
  │    "system_cfg": "             │
  │      bridge.status=disabled    │
  │      dhcpc.1.devname=eth0      │
  │      ...                       │
  │      iptables.1.cmd=-A INPUT -s 10.0.0.1 -p tcp --dport 22 -j ACCEPT
  │      iptables.2.cmd=-A INPUT -p tcp --dport 22 -j DROP
  │      ...                       │
  │      unifi.key=<authkey>       │
  │      users.1.name=sfgw_a8a5e1 │
  │      users.1.password=$6$...   │ ← SHA-512 crypt hash
  │      users.2.name=ubnt         │
  │      users.2.shell=/bin/false  │ ← factory user disabled
  │      ...                       │
  │    "                           │
  │  }                             │
  │ ◄───────────────────────────── │
  │                                │
  │  Device applies system_cfg:    │
  │  - Writes /tmp/system.cfg      │
  │  - Runs apply-config            │
  │  - Creates new SSH user         │
  │  - Disables ubnt user           │
  │  - Applies iptables rules       │
  │  - Stores cfgversion            │
```

**system_cfg contents** (key security hardening):

| Section | What it does |
|---------|-------------|
| `iptables.1` | ACCEPT SSH from gateway IP (10.0.0.1) only |
| `iptables.2` | DROP SSH from everything else |
| `users.1` | Custom SSH user (`sfgw_XXYYZZ`) with SHA-512 password |
| `users.2` | Factory `ubnt` user disabled (`shell=/bin/false`) |
| `unifi.key` | Authkey stored in device running config |
| `sshd` | SSH enabled on eth0 with password auth |
| `syslog.remote` | Syslog forwarded to gateway |
| `ntpclient` | NTP pointing to gateway + ubnt fallback |
| `httpd` | Local web UI disabled |

**cfgversion**: A 16-hex-char hash of the system_cfg content (`DefaultHasher`). The device stores this and reports it back in subsequent informs. When it matches our expected value, we know the device applied the config.

**Source files**: `handler.rs` (GCM branch of Adopted state), `system_cfg.rs:generate_system_cfg()`

### Phase 5: SSH Verification

When the device reports a matching cfgversion, the handler spawns async SSH verification:

```
Gateway                             Device
  │                                    │
  │  (3 second delay)                  │
  │                                    │
  │  SSH connect with provisioned creds│
  │  (sfgw_a8a5e1 / <password>)       │
  │ ──────────────────────────────────►│
  │                                    │
  │  cat /tmp/system.cfg               │
  │ ──────────────────────────────────►│
  │                                    │
  │  (full config content)             │
  │ ◄──────────────────────────────────│
  │                                    │
  │  Verify:                           │
  │  ✓ unifi.key matches authkey       │
  │  ✓ users.1.name = sfgw_a8a5e1     │
  │  ✓ users.2.shell = /bin/false      │
  │  ✓ iptables ACCEPT from 10.0.0.1  │
  │  ✓ iptables DROP from rest         │
  │                                    │
  │  SSH disconnect                    │
  │ ──────────────────────────────────►│
  │                                    │
  │  Mark config_applied = true        │
  │  config_delivery_attempts = 0      │
  │  → ADOPTION COMPLETE               │
```

**Retry logic**: If SSH verification fails:
- `config_applied = false`, `config_delivery_attempts += 1`
- Next inform → system_cfg re-delivered
- After 3 failed attempts → IDS critical event, admin intervention required
- Handler returns `noop(60)` until admin resets the counter

**Source files**: `provision.rs:verify_config_applied()`, `handler.rs` (cfgversion match branch)

## Real-World Adoption Timeline

Captured from a live USW-Flex (ac:8b:a9:a8:a5:e1) adoption on 2026-03-17:

```
T+0.0s   adoption initiated — spawning SSH provisioning
T+0.0s   starting SSH provisioning (ip=10.0.0.212)
T+0.7s   hardware fingerprint verified (serial=ac8ba9a8a5e1, cpuid=1617657f)
T+0.7s   device provisioning complete — adopted, authkey will be delivered
T+3.5s   inform received (CBC, default=false)
T+3.5s   adopted device still on CBC — delivering mgmt_cfg with authkey
T+3.9s   inform received (CBC) → delivering system_cfg (cfgversion=ce7a440e8e4e6ef6)
T+33.1s  inform received (GCM+Snappy) → device reported matching cfgversion
T+36.1s  starting post-adoption SSH verification
T+36.7s  SSH verification passed — system_cfg confirmed on device
T+36.7s  config verified via SSH — adoption complete
```

**Total time: ~36 seconds** from admin click to fully verified adoption.

## Decryption Key Resolution

The handler uses a two-phase key resolution to handle transition states:

1. **Primary key**: Check in-memory device cache for authkey. If found, use it. Otherwise, use default key.
2. **Fallback key**: If primary fails, try the other:
   - If authkey was primary → fall back to default key
   - If default was primary → check DB for authkey (provisioning may have just completed)

This handles edge cases:
- Device adopted in DB but in-memory cache not yet updated
- Device factory-reset but still using old authkey temporarily
- Service restart where in-memory cache is empty

### DB Protection

Before creating a new Pending record for an unknown device, the handler checks the database for existing Adopted/Adopting records. If found, the record is restored to memory instead of being overwritten. This prevents service restarts from destroying adoption state.

## Encryption Details

### AES-128-CBC (Unadopted)

- Key: `MD5("ubnt")` = `ba86f2bbe107c7c57eb5f2690775c712`
- IV: Random 16 bytes (from TNBU header)
- Padding: PKCS7
- **INTEROP ONLY**: MD5 and CBC are required for compatibility with stock firmware

### AES-128-GCM (Adopted)

- Key: Per-device authkey (16 bytes, generated via `ring::rand::SystemRandom`)
- Nonce: Full 16-byte IV from TNBU header (matches Java `GCMParameterSpec(128, iv)`)
- AAD: 40-byte TNBU packet header (from wire, not reconstructed)
- Tag: 16 bytes, appended to ciphertext
- Tag size in `data_length`: Yes, `data_length = ciphertext_len + 16`

### Compression

Applied AFTER encryption (decrypt first, then decompress):
- **Snappy**: Used by most adopted devices (flags `0x0D`)
- **zlib**: Alternative compression (flags `0x0B`)
- Decompression bomb protection: 10 MiB maximum decompressed size

## Config Formats

### mgmt_cfg

Newline-separated key=value string. Stored on device at `/var/etc/persistent/cfg/mgmt`. Persists across reboots and (partially) across factory resets.

Notable: `use_aes_gcm=true` persists across factory reset. The authkey may or may not persist depending on firmware version.

### system_cfg

Newline-separated key=value string. Written to `/tmp/system.cfg` on the device. Applied via `apply-config`. Does NOT persist across factory reset (it's in `/tmp/`).

No comments, no blank lines. `mcad` rejects malformed content.

## Error Recovery

| Scenario | What happens |
|----------|-------------|
| SSH auth fails during adoption | Device stays in Adopting. Retryable after factory reset. |
| Device doesn't switch to GCM | CBC branch keeps re-delivering mgmt_cfg with authkey every inform cycle. |
| cfgversion never matches | system_cfg re-delivered up to 3 times, then IDS alert. |
| SSH verification fails | config_delivery_attempts incremented, system_cfg re-sent. After 3 failures: IDS critical event. |
| Service restart during adoption | DB record preserved. In-memory cache restored from DB on next inform. |
| Device factory reset after adoption | Device reverts to CBC with default key. If authkey persists in DB, re-adoption is automatic. |

## Source File Map

| File | Responsibility |
|------|---------------|
| `handler.rs` | Main inform request handler. Decryption, JSON parsing, state machine, response building. |
| `crypto.rs` | AES-128-CBC and AES-128-GCM encrypt/decrypt. Default key derivation. Authkey generation. |
| `packet.rs` | TNBU binary packet parsing and serialization. |
| `codec.rs` | Snappy and zlib decompression with bomb protection. |
| `payload.rs` | Inform JSON payload and response structs. Model name lookup. OUI validation. |
| `provision.rs` | SSH-based provisioning (fingerprint read) and post-adoption verification. |
| `system_cfg.rs` | `mgmt_cfg` and `system_cfg` generation. cfgversion hashing. |
| `state.rs` | Device state machine, UbntDevice struct, hardware fingerprint. |
| `rate.rs` | Per-IP rate limiting with soft/hard thresholds and MAC tracking. |
