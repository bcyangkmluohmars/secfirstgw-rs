---
name: NAS unified storage stack decision
description: All tiers use MD RAID + dm-crypt (HW crypto) + Btrfs. HW parity acceleration for RAID5. No ZFS.
type: project
---

Unified storage stack across all hardware tiers:
Btrfs (single mode) → dm-crypt/LUKS (HW crypto) → MD RAID (0/1/5/10, HW parity for 5) → SATA

**Why:**
- Annapurna Labs SoC has dedicated parity DMA engine (PCI 00:05.0, al_dma_drv) that accelerates MD RAID5 via async_xor
- Dedicated crypto engine (PCI 00:04.0, al-ssm-pcie) accelerates dm-crypt
- ZFS ignores both HW accelerators (does RAIDZ + encryption in software)
- MD RAID supports all levels (0/1/5/10) with same tooling (mdadm)
- Btrfs on top (single mode, no Btrfs RAID) provides snapshots, checksums, compression
- Minimal RAM overhead (~100-200 MB) vs ZFS ARC (1+ GB minimum)

**How to apply:** `sfnas-storage` wraps mdadm + cryptsetup + mkfs.btrfs. Setup wizard picks RAID level based on disk count and role (NAS default=RAID5, NVR default=RAID10). RAID5 write hole mitigated with --write-journal on eMMC partition. Same stack for uNVR, UNAS-4, UNVRP — only tuning differs.
