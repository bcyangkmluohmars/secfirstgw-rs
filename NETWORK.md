# UDM Pro — Network Architecture

## Hardware Topology

```
                                    ┌─────────────────────────────────┐
                                    │   Annapurna Labs Alpine V2      │
                                    │   4× Cortex-A57, 4GB RAM        │
                                    │                                  │
  ┌──────────┐   10GbE direct       │  ┌───────────┐  ┌───────────┐  │
  │ WAN SFP+ ├─────────────────────────┤ 10G MAC 0 │  │ 10G MAC 1 ├──────── LAN SFP+
  │ (eth9)   │   PCI 00:00.0        │  │  (eth9)   │  │  (eth10)  │  │      (eth10)
  └──────────┘                       │  └───────────┘  └───────────┘  │
                                    │                                  │
  ┌──────────┐   1GbE direct        │  ┌───────────┐  ┌───────────┐  │
  │ WAN RJ45 ├─────────────────────────┤ 1G MAC 0  │  │ 1G MAC 1  ├──────┐
  │ (eth8)   │   PCI 00:01.0        │  │  (eth8)   │  │ (switch0) │  │   │
  └──────────┘                       │  └───────────┘  └─────┬─────┘  │   │
                                    │                        │         │   │
                                    │  ┌─────────┐  ┌───────┐         │   │
                                    │  │ Crypto   │  │ DMA   │         │   │
                                    │  │ (al_ssm) │  │(al_dma│         │   │
                                    │  │ 00:04.0  │  │00:05.0│         │   │
                                    │  └─────────┘  └───────┘         │   │
                                    │                                  │   │
                                    │  ┌─────────┐                     │   │
                                    │  │  SATA    │ ← HDD Bay (1×)    │   │
                                    │  │ 00:08.0  │                     │   │
                                    │  └─────────┘                     │   │
                                    └──────────────────────────────────┘   │
                                                                           │
                                         1 GbE Uplink (BOTTLENECK)         │
                                                                           │
                                    ┌──────────────────────────────────┐   │
                                    │     RTL8370MB 8-Port GbE Switch  │   │
                                    │     (SMI via eth8 MDIO bus)      ├───┘
                                    │                                  │
                                    │  ┌────┬────┬────┬────┬────┬────┬────┬────┐
                                    │  │ P0 │ P1 │ P2 │ P3 │ P4 │ P5 │ P6 │ P7 │
                                    └──┴────┴────┴────┴────┴────┴────┴────┴────┘
                                       │    │    │    │    │    │    │    │
                                      eth0 eth1 eth2 eth3 eth4 eth5 eth6 eth7
                                       │    │    │    │    │    │    │    │
                                    ───────────── RJ45 LAN Ports ────────────
```

## VLAN / Bridge Layout

```
┌─────────────────────────────────────────────────────────────────┐
│                         switch0                                  │
│                    (al_eth, PCI 00:03.0)                         │
│                                                                  │
│  VLAN 10 ──── switch0.10 ──┬── br-lan ──── 192.168.1.0/24      │
│                             └── eth10 (LAN SFP+)                 │
│                                                                  │
│  VLAN 3000 ── switch0.3000 ── br-mgmt ── 10.0.0.0/24           │
│                                                                  │
│  VLAN 3001 ── switch0.3001 ── br-guest ── 192.168.3.0/24       │
│                                                                  │
│  VLAN 3002 ── switch0.3002 ── br-dmz ──── 172.16.0.0/24        │
└─────────────────────────────────────────────────────────────────┘

WAN:  eth8 (RJ45 1GbE) ── direct to SoC, no switch
      eth9 (SFP+ 10GbE) ── direct to SoC, no switch
```

## Zones & Subnets

| Zone | Bridge | Subnet | VLAN | Switch Ports | Description |
|------|--------|--------|------|-------------|-------------|
| LAN | br-lan | 192.168.1.0/24 | 10 | switch0.10 + eth10 (SFP+) | Primary network |
| Management | br-mgmt | 10.0.0.0/24 | 3000 | switch0.3000 | Device management (APs, switches, NAS) |
| Guest | br-guest | 192.168.3.0/24 | 3001 | switch0.3001 | Guest WiFi / isolated |
| DMZ | br-dmz | 172.16.0.0/24 | 3002 | switch0.3002 | Exposed services |

## Physical Port Mapping

| Port | Interface | PCI Device | MAC | Connection | Speed |
|------|-----------|------------|-----|------------|-------|
| WAN RJ45 | eth8 | 00:01.0 (1G MAC) | 74:ac:b9:14:46:41 | Direct to SoC | 1 GbE |
| WAN SFP+ | eth9 | 00:00.0 (10G MAC) | 74:ac:b9:14:46:42 | Direct to SoC | 10 GbE |
| LAN SFP+ | eth10 | 00:02.0 (10G MAC) | 74:ac:b9:14:46:43 | Direct to SoC | 10 GbE |
| LAN 1 | eth0@switch0 | via 00:03.0 | 74:ac:b9:14:46:39 | RTL8370MB Port 0 | 1 GbE |
| LAN 2 | eth1@switch0 | via 00:03.0 | 74:ac:b9:14:46:3a | RTL8370MB Port 1 | 1 GbE |
| LAN 3 | eth2@switch0 | via 00:03.0 | 74:ac:b9:14:46:3b | RTL8370MB Port 2 | 1 GbE |
| LAN 4 | eth3@switch0 | via 00:03.0 | 74:ac:b9:14:46:3c | RTL8370MB Port 3 | 1 GbE |
| LAN 5 | eth4@switch0 | via 00:03.0 | 74:ac:b9:14:46:3d | RTL8370MB Port 4 | 1 GbE |
| LAN 6 | eth5@switch0 | via 00:03.0 | 74:ac:b9:14:46:3e | RTL8370MB Port 5 | 1 GbE |
| LAN 7 | eth6@switch0 | via 00:03.0 | 74:ac:b9:14:46:3f | RTL8370MB Port 6 | 1 GbE |
| LAN 8 | eth7@switch0 | via 00:03.0 | 74:ac:b9:14:46:40 | RTL8370MB Port 7 | 1 GbE |

## Bandwidth Bottleneck

```
                    10 GbE          10 GbE
  WAN SFP+ ─────── SoC ─────────── LAN SFP+     ← Full 10G throughput
  WAN RJ45 ─────── SoC                           ← Full 1G throughput

  LAN Ports ─── RTL8370MB ──[1GbE uplink]── SoC  ← ALL 8 ports share 1 GbE to CPU
```

**Impact:**
- WAN SFP+ ↔ LAN SFP+: **10 Gbit/s** (direct, no switch)
- WAN RJ45 ↔ LAN SFP+: **1 Gbit/s** (direct, no switch)
- LAN RJ45 (any) ↔ WAN: **1 Gbit/s shared** across all 8 ports
- LAN RJ45 ↔ LAN RJ45 (same VLAN): **1 Gbit/s** per port (switch-internal, no CPU)
- LAN RJ45 ↔ LAN RJ45 (different VLAN): **1 Gbit/s shared** (routed through CPU)

**Recommendation:** Use SFP+ for uplinks to core switches. RJ45 ports for management devices, APs, cameras — not high-throughput clients.

## Kernel Driver Stack

```
┌──────────────────────────────────────────┐
│           Linux Network Stack             │
│  (bridge, vlan, netfilter, routing)       │
├──────────┬──────────┬────────────────────┤
│ eth8     │ eth9     │ switch0            │
│ eth10    │          │ └─ eth0..eth7      │
├──────────┴──────────┴────────────────────┤
│              al_eth.ko                    │
│  (Annapurna Labs Ethernet HAL)           │
│  - 4× MAC instances (2× 1G, 2× 10G)    │
│  - RTL8370MB switch mgmt via I2C         │
│  - VLAN port isolation via HAL registers │
├──────────────────────────────────────────┤
│         Internal PCIe Bus                 │
│  pcie-al-internal.c (SMCC snoop config)  │
└──────────────────────────────────────────┘
```

## SoC PCI Device Map

| PCI Addr | Device | Driver | Function |
|----------|--------|--------|----------|
| 00:00.0 | 10G SFP+ MAC #1 | al_eth | WAN SFP+ (eth9) |
| 00:01.0 | 1G MAC #1 | al_eth | WAN RJ45 (eth8) |
| 00:02.0 | 10G SFP+ MAC #2 | al_eth | LAN SFP+ (eth10) |
| 00:03.0 | 1G MAC #2 | al_eth | Switch uplink → RTL8370MB (switch0) |
| 00:04.0 | Crypto Engine | al_ssm | AES/SHA HW acceleration |
| 00:05.0 | DMA/RAID Engine | al_dma | XOR/PQ for RAID5/6 |
| 00:08.0 | SATA Controller | ahci | HDD Bay (1×) |
| 01:00.0 | USB 3.0 xHCI | xhci_hcd | eMMC boot via ASMedia |
