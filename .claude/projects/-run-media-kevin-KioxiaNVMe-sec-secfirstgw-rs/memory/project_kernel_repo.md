---
name: Kernel 6.12 port needs own GitHub repo
description: The Alpine V2 kernel port (pcie-al-internal, al_eth, al_dma, al_ssm, al_sgpo, snoop quirk) should be published as a standalone repo. Same SoC used in UDM-Pro.
type: project
---

The Linux 6.12 kernel port for Annapurna Labs Alpine V2 should be published as a GitHub repo (e.g. `secfirst/linux-alpine-v2`).

**Why:**
- Original work not available anywhere else
- Same SoC (AL-314) used in UDM-Pro (10.0.0.1) which is the next target
- Community benefit — QNAP, Synology, MikroTik devices use the same SoC
- Proper patch management for upstream submission potential

**What to publish:**
- Kernel patches against vanilla 6.12.77 (pcie-al-internal, pcie-al dbi fix, snoop quirk)
- Out-of-tree modules (al_eth, al_dma, al_ssm, al_sgpo)
- Device tree sources (UNVR, later UDM-Pro)
- Defconfigs
- Build instructions + Docker setup
- ANALYSIS.md with reverse-engineering findings

**UDM-Pro differences from UNVR:**
- Same SoC, same pcie-al-internal driver
- Different peripherals: WiFi (QCA9984), Ethernet switch, different bay layout
- Different device tree needed
- secfirstgw already runs on it (at 10.0.0.1)

**How to apply:** Create patches with `git format-patch`, publish repo, reference from secfirstgw-rs and secfirstnas-rs.
