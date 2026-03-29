# UNVR — Network & Hardware Architecture

## Hardware Topology

```
                                    ┌──────────────────────────────────┐
                                    │   Annapurna Labs Alpine V2       │
                                    │   4× Cortex-A57, 4GB RAM         │
                                    │                                   │
  ┌──────────┐   1GbE direct       │  ┌───────────┐  ┌───────────┐   │
  │ RJ45     ├─────────────────────────┤ 1G MAC 0  │  │ 10G MAC 0 ├───────── SFP+ (unused)
  │ (eth0)   │   PCI 00:01.0       │  │  (eth0)   │  │  (eth1)   │   │      (eth1)
  └──────────┘                      │  └───────────┘  └───────────┘   │
                                    │                                   │
                                    │  ┌─────────┐  ┌─────────┐       │
                                    │  │ Crypto   │  │ DMA     │       │
                                    │  │ (al_ssm) │  │ (al_dma)│       │
                                    │  │ 00:04.0  │  │ 00:05.0 │       │
                                    │  └─────────┘  └─────────┘       │
                                    │                                   │
                                    │  ┌─────────────────────────────┐ │
                                    │  │  2× AHCI SATA Controllers   │ │
                                    │  │  00:08.0 (ata1,ata3)        │ │
                                    │  │  00:09.0 (ata5,ata7)        │ │
                                    │  └──────┬──────┬──────┬──────┘ │
                                    │         │      │      │     │   │
                                    └─────────┼──────┼──────┼─────┼───┘
                                              │      │      │     │
                                    ┌─────────┴──────┴──────┴─────┴───┐
                                    │         4× SATA III 6 Gbps       │
                                    │  ┌──────┐┌──────┐┌──────┐┌──────┐│
                                    │  │Bay 1 ││Bay 2 ││Bay 3 ││Bay 4 ││
                                    │  │ata7  ││ata5  ││ata1  ││ata3  ││
                                    │  │host6 ││host4 ││host0 ││host2 ││
                                    │  └──────┘└──────┘└──────┘└──────┘│
                                    └──────────────────────────────────┘
```

## Network Layout

```
                    ┌─────────────────────┐
                    │   Core Network      │
                    │   10.0.0.0/24       │
                    │   (Management VLAN) │
                    └─────────┬───────────┘
                              │
                    ┌─────────┴───────────┐
                    │  eth0 — 1GbE RJ45   │
                    │  10.0.0.118 (DHCP)  │
                    │  PCI 00:01.0        │
                    ├─────────────────────┤
                    │  eth1 — 10G SFP+    │
                    │  (not connected)    │
                    │  PCI 00:02.0        │
                    └─────────────────────┘
```

**No VLANs, no bridges, no routing.** The UNVR is a storage appliance — single flat network connection. All traffic (SMB, Web UI, SSH, rsync) goes through `eth0`.

## Physical Port Mapping

| Port | Interface | PCI Device | MAC | Speed | Status |
|------|-----------|------------|-----|-------|--------|
| RJ45 | eth0 | 00:01.0 (1G MAC) | e4:38:83:74:5c:41 | 1 GbE | UP, 10.0.0.118/24 |
| SFP+ | eth1 | 00:02.0 (10G MAC) | e4:38:83:74:5c:42 | 10 GbE | DOWN (unused) |

## Storage Layout

```
┌─────────────────────────────────────────────────────────┐
│  Btrfs (compress=zstd, noatime, space_cache=v2)         │
│  Mounted: /mnt/md-0                                      │
├─────────────────────────────────────────────────────────┤
│  MD RAID5 (md0) — 5.5 TB usable                         │
│  3× member disks, 512K chunk, bitmap enabled             │
├───────────────┬───────────────┬─────────────────────────┤
│  /dev/sda     │  /dev/sdb     │  /dev/sdc               │
│  WD30EFRX-68E │  WD30EFRX-68E │  HUS724030ALA640        │
│  3.0 TB HDD   │  3.0 TB HDD   │  3.0 TB HDD             │
│  Bay 3 (ata1) │  Bay 4 (ata3) │  Bay 2 (ata5)           │
└───────────────┴───────────────┴─────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  /dev/sde — INTEL SSDSC2BB12 (120 GB SSD) — Bay 1      │
│  Partitioned: sde1 (512K) + sde2 (1G) + sde3 (110G)    │
│  Not in RAID — standalone / spare                        │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  /dev/sdd — 29 GB eMMC (boot via USB xHCI, PCI 01:00)  │
│  sdd1: /boot (128M, ext4, ro)                            │
│  sdd2: / (2G, ext4, rootfs)                              │
│  sdd3: /data (4G, ext4, config+DB)                       │
│  sdd4: /var/log (4G, ext4)                               │
│  sdd5: (3G, unused/recovery)                             │
└─────────────────────────────────────────────────────────┘
```

## Bay-to-SATA Mapping

| Bay | SATA Controller | ATA Link | SCSI Host | Disk | Model |
|-----|----------------|----------|-----------|------|-------|
| 1 | 00:09.0 | ata7 | host6 | /dev/sde | Intel SSD 120GB |
| 2 | 00:09.0 | ata5 | host4 | /dev/sdc | Hitachi 3TB |
| 3 | 00:08.0 | ata1 | host0 | /dev/sda | WD Red 3TB |
| 4 | 00:08.0 | ata3 | host2 | /dev/sdb | WD Red 3TB |

## LED Control

```
┌─────────────────────────────────────────────────────┐
│  SGPO Controller (gpiochip8) — White Activity LEDs  │
│  ┌──────┬──────┬──────┬──────┐                      │
│  │Pin 22│Pin 20│Pin 16│Pin 18│                      │
│  │Bay 1 │Bay 2 │Bay 3 │Bay 4 │                      │
│  └──────┴──────┴──────┴──────┘                      │
│                                                      │
│  PCA9575 (gpiochip1, I2C 0x21) — Red Fault LEDs    │
│  ┌──────┬──────┬──────┬──────┐                      │
│  │Pin 12│Pin 13│Pin 14│Pin 15│                      │
│  │Bay 1 │Bay 2 │Bay 3 │Bay 4 │                      │
│  └──────┴──────┴──────┴──────┘                      │
│                                                      │
│  Modes: Off | Normal (W) | Active (W blink 2Hz)    │
│         SmartWarning (R blink) | Degraded (R)       │
│         Identify (W+R alternate)                     │
└─────────────────────────────────────────────────────┘
```

## Thermal / Fan Control

```
ADT7475 HWMON (I2C 0x2e)
├── Fan 1: ~2800 RPM (PWM 80/255 = 31%)
├── Fan 2: ~2773 RPM
├── Fan 3: ~2755 RPM
├── Fan 4: not populated
├── Temp 1: 43°C (board)
├── Temp 2: 42°C (board)
└── Temp 3: 32°C (board)

HDD Temperatures (via SMART):
├── sda (Bay 3): 37°C
└── sdb (Bay 4): 36°C

Profiles: silent | balanced (default) | performance | full
```

## I2C Bus Map

| Bus | Address | Device | Function |
|-----|---------|--------|----------|
| 0 | 0x20 | PCA9575 | GPIO expander (misc) |
| 0 | 0x21 | PCA9575 | Bay LEDs (pins 12-15), Power (0-3), Presence (4-7) |
| 0 | 0x29 | PCA9575 | GPIO expander (misc) |
| 0 | 0x71 | PCA9546 | I2C mux (4 channels) |
| 4 | 0x2e | ADT7475 | Fan control + temperature sensors |

## SoC PCI Device Map

| PCI Addr | Device | Driver | Function |
|----------|--------|--------|----------|
| 00:01.0 | 1G MAC | al_eth | RJ45 Ethernet (eth0) |
| 00:02.0 | 10G SFP+ MAC | al_eth | SFP+ Ethernet (eth1, unused) |
| 00:04.0 | Crypto Engine | al_ssm | AES/SHA HW acceleration |
| 00:05.0 | DMA/RAID Engine | al_dma | XOR/PQ for RAID5/6 |
| 00:08.0 | AHCI SATA #1 | ahci | Bay 3 (ata1) + Bay 4 (ata3) |
| 00:09.0 | AHCI SATA #2 | ahci | Bay 1 (ata7) + Bay 2 (ata5) |
| 01:00.0 | USB 3.0 xHCI | xhci_hcd | eMMC boot (ASMedia ASM3042) |

## GPIO Chips

| Chip | Controller | Lines | Function |
|------|-----------|-------|----------|
| gpiochip0 | PCA9575 (0x20) | 16 | Misc GPIO |
| gpiochip1 | PCA9575 (0x21) | 16 | Bay LEDs + Power + Presence |
| gpiochip2-4 | PL061 | 8 each | SoC GPIO |
| gpiochip5 | PL061 GPIO3 | 8 | ulogo_blue (pin 7) |
| gpiochip6 | PL061 GPIO4 | 8 | ulogo_white (pin 5) |
| gpiochip7 | PL061 | 8 | SoC GPIO |
| gpiochip8 | SGPO (fd8b4000) | 32 | SATA activity LEDs |

## Services

| Port | Protocol | Service |
|------|----------|---------|
| 22 | TCP | SSH |
| 80 | TCP | HTTP → HTTPS redirect |
| 443 | TCP | HTTPS (Web UI + API, TLS 1.3) |
| 445 | TCP | SMB3 (Samba, encrypted) |
| 873 | TCP | rsync |

## Firewall (nftables)

```
table inet filter — policy DROP
├── input: lo accept, established accept, ICMP, SSH(22), HTTP(80),
│          HTTPS(443), SMB(445), rsync(873), log+drop rest
├── forward: DROP (NAS does not route)
└── output: ACCEPT
```
