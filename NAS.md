# secfirstNAS — Architecture & Planning

## Overview

Repurpose Ubiquiti UNVR 4-Bay hardware as a combined NAS + NVR appliance running under the secfirst security architecture. Monorepo with secfirstgw — shared crates, separate binary.

## Target Hardware

### Ubiquiti uNVR 4-Bay (~270€ + VAT) — KMU Entry
- CPU: ARM Cortex A57 Quad-Core (64-bit, AES Crypto Extensions)
- RAM: 4 GB
- Flash: 32 GB (OS)
- Storage: 4x SATA 3.5" Hot-Swap Bays
- Network: 1x RJ45 1GbE, 1x SFP+ 10GbE
- No display, single LED
- ZFS ARC limit: 1-1.5 GB

### Ubiquiti UNAS-4 (~450€ + VAT) — KMU Pro
- CPU: ARM Cortex A57 Quad-Core (64-bit, AES Crypto Extensions)
- RAM: 8 GB
- Flash: 32 GB (OS)
- Storage: 4x SATA 3.5" Hot-Swap Bays + 2x NVMe M.2
- Network: 1x RJ45 1GbE, 2x SFP+ 10GbE
- M.2 slots usable as ZFS SLOG (write log) + L2ARC (read cache) → massive IO boost
- ZFS ARC limit: 4-5 GB
- Same SoC, double RAM, NVMe cache = significantly better NAS performance

### Ubiquiti UNVRP 16-Bay (~4500€ + VAT) — Enterprise
- CPU: Marvell CN10208 (Octeon 10, 8x ARM Neoverse N2)
- RAM: 32 GB
- Storage: 16x SATA Hot-Swap Bays
- Network: 1x RJ45 1GbE (mgmt), 2x SFP28 25GbE
- Dual hot-swappable PSU
- 3U Rackmount
- Up to 300x 4K or 500x 1080p cameras
- RAIDZ2/RAIDZ3 viable with 16 bays
- ZFS ARC: 16+ GB

### Hardware Detection
Same binary for all targets. `sfgw-hal` auto-detects hardware at boot:
- uNVR → 4-bay mode, conservative RAM tuning
- UNAS-4 → 4-bay + NVMe cache mode, more RAM for ARC
- UNVRP → 16-bay enterprise mode, full ZFS features

## Architecture

### Monorepo Strategy

Both `secfirstgw` and `secfirstnas` live in the same Cargo workspace. Shared crates, two separate binaries. Split into separate repos later if needed.

### Shared Crates (from secfirstgw)

- `sfgw-crypto` — Encryption at rest, SecureBox, PQ crypto
- `sfgw-nas` — SMB3/NFS core (existing, 843 LoC)
- `sfgw-api` — axum Web UI base, auth, E2EE middleware
- `sfgw-db` — SQLite, user/auth management
- `sfgw-hal` — Hardware detection (extend for uNVR identification)
- `sfgw-inform` — Device adoption (reuse for UniFi cameras)
- `sfgw-net` — Network basics

### New Crates

- `sfnas-nvr` — NVR functionality
  - RTSP stream ingestion from adopted UniFi cameras
  - Recording: continuous + motion-triggered
  - Retention management (FIFO when disk full, configurable per camera)
  - Playback: timeline, seek, export clips
  - Motion detection (lightweight, on-device)
  
- `sfnas-storage` — Storage management
  - Unified storage stack: Btrfs → dm-crypt (HW crypto) → MD RAID (HW parity) → SATA
  - MD RAID levels: RAID0, RAID1, RAID5, RAID10
  - HW parity acceleration via Annapurna Labs DMA engine (al_dma_drv) for RAID5
  - HW crypto acceleration via Annapurna Labs SSM engine for dm-crypt/LUKS
  - Btrfs (single mode on top of MD): snapshots, checksumming, LZ4 compression
  - Disk health monitoring (SMART)
  - Scrub scheduling (both MD and Btrfs)
  - Bay management: power control, presence detection, activity LEDs via I2C GPIO
  
- `sfnas-share` — File sharing
  - SMB3 share management
  - User permissions / ACLs
  - Quotas (per user, per share)
  - Suitable for SME / KMU use
  
- `sfnas-cli` — Binary entry point
  - Hardware profile detection (uNVR auto-detect)
  - Service orchestration for NAS + NVR

### Web UI: Setup Wizard

Visual, hardware-aware setup. Not a form — feels like touching the device.

**Step 0: Hardware Discovery**
- Auto-detect which bays are populated
- SMART query each disk: model, capacity, health, temperature, bad sectors
- Show warnings for unhealthy disks
- Display uNVR front-view image with bay status (empty/populated/warning)

**Step 1: Device Mode**
- "NAS only" / "NVR only" / "NAS + NVR"
- Determines which services start and UI layout

**Step 2: Bay Assignment (visual)**
- Interactive image of uNVR front panel, 4 bays clickable
- User assigns each populated bay: 🟦 NAS or 🟥 NVR
- Empty/missing bays greyed out
- Each bay shows disk info on hover/tap (model, size, health)

**Step 3: RAID Configuration**
- Based on bay assignments, show only valid RAID options:
  - 4x same role → RAID5 (default, best capacity) / RAID10 (best performance) / RAID0 (no redundancy, warning)
  - 3x same role → RAID5 (default) / RAID1 (less capacity, more safety)
  - 2x NAS + 2x NVR → Mirror + Mirror
  - 3+1 split → RAID5 + Single (with warning)
  - 2 bays total → RAID1 (only option with redundancy)
  - 1 bay → Single disk (prominent no-redundancy warning)
- Default for 4-bay NAS: RAID5 (75% capacity, HW parity acceleration)
- Default for 4-bay NVR: RAID10 (best write performance for continuous recording)

**Step 4: Summary & Confirm**
- Visual recap of assignment + RAID level
- "This will erase all data on selected disks" warning
- Format & initialize

### Hot-Plug & Live Monitoring

- **udev events** via `tokio-udev` — no polling, kernel pushes disk insert/remove events
- Real-time bay status pushed to UI via WebSocket
- The setup wizard front-view image doubles as a **live dashboard**:
  - Disk removed → bay turns red, MD RAID degraded notification
  - Disk inserted → bay shows new disk info, offer rebuild/replace
  - New disk in empty bay → offer pool expansion
- SMART monitoring continuous — proactive warnings before failure
- AHCI hot-plug confirmed on actual hardware (SSS flag set, verified via dmesg)
- Bay presence detection via PCA9575 I2C GPIO (gpio-484..487)

### Storage Layout

Unified storage stack across all hardware tiers:

```
┌─────────────────────────────┐
│  Btrfs (single mode)        │  Snapshots, checksums, LZ4 compression
├─────────────────────────────┤
│  dm-crypt / LUKS            │  HW crypto via AL SSM engine (PCI 00:04.0)
├─────────────────────────────┤
│  MD RAID (0/1/5/10)         │  HW parity via AL DMA engine (PCI 00:05.0)
├────────┬────────┬───────────┤
│ Bay 0  │ Bay 1  │ Bay 2 ... │  AHCI / SATA III 6 Gbps
└────────┴────────┴───────────┘
```

One stack, all RAID levels. `sfnas-storage` wraps `mdadm` + `cryptsetup` + `mkfs.btrfs`. Setup wizard hides the complexity — user picks bays and RAID level, we build the stack.

**Hardware acceleration (uNVR SoC — Annapurna Labs Alpine V2):**
- **Parity (RAID5):** `al_dma_drv` → Linux async_xor/async_pq framework → MD RAID5 offload
- **Crypto (dm-crypt):** `al-ssm-pcie` → hardware AES acceleration for LUKS
- Both confirmed present on dev device (PCI 00:04.0 crypto, 00:05.0 RAID/DMA)

**RAID options by disk count:**

| Disks | RAID0 | RAID1 | RAID5 | RAID10 |
|-------|-------|-------|-------|--------|
| 1 | Single (warning) | — | — | — |
| 2 | ✓ | ✓ (default) | — | — |
| 3 | ✓ | ✓ | ✓ (default) | — |
| 4 | ✓ | ✓ | ✓ (default NAS) | ✓ (default NVR) |

**Capacity with 4x 3TB disks:**
- RAID5: 9 TB usable (75%) — best for NAS
- RAID10: 6 TB usable (50%) — best for NVR write performance
- RAID1: 3 TB usable (25%) — maximum redundancy
- RAID0: 12 TB usable (100%) — no redundancy (prominent warning)

**MD RAID5 write hole mitigation:**
- `--write-journal` on a partition on the eMMC (32 GB has ~15 GB free)
- Or dedicated journal on NVMe (UNAS-4)
- Write-intent bitmap as minimum fallback

**Btrfs (single mode on top of MD):**
- Snapshots: NAS shares versioning, ransomware rollback
- Checksumming: bitrot detection on consumer SATA drives
- Compression: LZ4 (negligible CPU on A57)
- Subvolumes: separate NAS/NVR data areas
- Scrubs: scheduled nightly, low priority (both MD scrub + Btrfs scrub)

**Encryption:**
- dm-crypt/LUKS between MD RAID and Btrfs
- Key management via sfgw-crypto (SecureBox, key derivation)
- HW AES via SoC crypto engine — near-zero CPU overhead

**Tiered tuning by hardware:**

| Hardware | RAID levels | Extras |
|----------|-------------|--------|
| uNVR (4 GB, 4 bays) | RAID0/1/5/10 | HW parity + HW crypto, journal on eMMC |
| UNAS-4 (8 GB, 4 bays + NVMe) | RAID0/1/5/10 | HW parity + HW crypto, journal on NVMe, NVMe read cache |
| UNVRP (32 GB, 16 bays) | RAID0/1/5/6/10 | RAID6 viable with 16 bays, dedicated journal disk |

**Mixed mode (NAS + NVR) on 4 bays:**
- 2+2: Two separate MD arrays (e.g. RAID1 + RAID1)
- 3+1: RAID5 + Single (with warning on single disk)
- Separate Btrfs subvolumes per role on each array

**Disk lifecycle operations (all via mdadm):**
- Add disk to existing array → `mdadm --grow`
- Replace failed disk → `mdadm --replace` / `--add` (hot-spare rebuild)
- Expand array → `mdadm --grow --raid-devices=N`
- Bay power control → GPIO gpio-480..483 (PCA9575 I2C)

### NVR Camera Flow

1. Camera sends Inform → sfgw-inform adopts (same flow as APs/switches)
2. Camera provisioned with RTSP credentials + stream config
3. sfnas-nvr connects to camera RTSP stream
4. Records to subvolume/dataset `pool/nvr/<camera-mac>/`
5. Retention policy manages disk usage per camera
6. Web UI: live view, playback timeline, clip export

### Web UI

Extend existing secfirstgw Web UI (React + TypeScript):
- Dashboard: disk health, camera grid, share overview
- Storage: pool status, disk SMART, scrub history
- Cameras: live view, playback, motion events, retention settings
- Shares: create/manage SMB shares, users, quotas
- Same E2EE architecture as secfirstgw UI

### Authentication & User Management

**Local Users (always available)**
- Built-in user/group management
- For small installations without directory services

**MS365 OAuth / Entra ID**
- SSO via standard OIDC flow
- Token-based, no password stored on device
- User auto-provisioning on first login

**Active Directory Sync**
- LDAP(S) against on-prem AD or Entra ID
- User + group sync (scheduled + on-demand)
- Group → share permission mapping
- Kerberos auth for seamless SMB access from domain-joined machines

Setup wizard offers all three, user picks what fits. Can combine (local admin + AD for regular users).

### Security (inherited from secfirstgw)

- All data encrypted at rest (dm-crypt/LUKS with HW crypto acceleration + sfgw-crypto key management)
- Zero-trust: no cloud dependency, no call-home
- Camera streams encrypted in transit (RTSP over TLS where supported)
- SMB3 with mandatory signing + encryption
- Web UI with E2EE envelope (same as secfirstgw)
- User auth through sfgw-db

### Performance Considerations

- ARM A57 with Crypto Extensions + dedicated SoC crypto engine → near-zero CPU overhead for encryption
- HW parity engine → RAID5 parity calculations offloaded from CPU
- **uNVR (4 GB):** MD RAID + dm-crypt + Btrfs ~100-200 MB overhead, leaves ~3.8 GB for NVR buffering + OS + services
- **UNAS-4 (8 GB):** Same stack + NVMe cache for read/write acceleration
- **UNVRP (32 GB):** Same stack + ample headroom, RAID6 double parity viable
- 10G SFP+: more than enough for multiple HD camera streams + SMB
- Scrubs: schedule at night, low priority (MD scrub + Btrfs scrub)
- NVR writes are sequential (append-only recordings) — ideal for RAID5 sequential parity writes

### Deployment

**Option 1: USB Boot (easiest, reversible)**
- Some uNVR revisions have an internal USB header on the board
- Flash secfirstNAS to USB stick, plug in, device boots from USB
- Original eMMC firmware untouched — pull USB stick to revert
- Community confirmed: people already run USB-NVMe adapters off this header
- "Open lid, insert USB, close lid, power on" — zero risk deployment

**Option 2: eMMC Flash (permanent)**
- Write secfirstNAS image directly to 32GB eMMC via UART shell
- Replaces original firmware
- Recovery via TFTP if needed

**Option 3: UART/Serial Console (always available)**
- 4-pin header on board (present on all revisions)
- 115200 baud serial console
- Fallback for debugging, initial flash, recovery

**Note:** USB header not confirmed on all hardware revisions. UART 4-pin header is always present.

### Open Questions

- [ ] uNVR boot process: does it prefer USB over eMMC? (boot order)
- [ ] Which uNVR hardware revisions have the USB header?
- [x] ~~uNVR SATA controller~~: AHCI confirmed, SSS flag set, hot-plug works. 2x controllers, 4 ports each.
- [x] ~~ZFS vs alternatives~~ → **Decided:** Unified stack: MD RAID (all levels, HW parity for RAID5) + dm-crypt (HW crypto) + Btrfs (single mode). No ZFS needed.
- [ ] Camera RTSP: do all UniFi cameras use standard RTSP or proprietary extensions?
- [ ] SMB implementation: Samba recommended (AD/Kerberos-ready), pure-Rust libs not mature enough
- [ ] Should NVR recordings be browsable as SMB shares? (camera footage as files)
- [ ] udev event reliability on this SoC for hot-plug detection

## Competitive Positioning

This device at 270€ replaces:
- Synology DS423 (~500€) for NAS
- Ubiquiti NVR (~270€) for camera recording
- Combined: one device, one binary, one UI, full encryption, no cloud

## Timeline

TBD — depends on secfirstgw stabilization. Agent task when ready.
