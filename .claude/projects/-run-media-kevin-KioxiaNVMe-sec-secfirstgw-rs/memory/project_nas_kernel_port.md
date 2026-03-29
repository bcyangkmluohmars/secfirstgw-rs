---
name: NAS kernel 6.12 port — complete patch list
description: All kernel patches, driver changes, DTS modifications, and config changes for Linux 6.12 on Ubiquiti UNVR (Alpine V2)
type: project
---

## secfirstNAS Kernel 6.12.77 Port — Complete Patch List

### 1. New Driver: `pcie-al-internal.c`
**File:** `drivers/pci/controller/pcie-al-internal.c` (NEW)
**Purpose:** Internal PCIe host controller for Annapurna Labs Alpine V2 SoC
**What it does:**
- Replaces `pci-host-ecam-generic` for the internal PCIe bus
- Compatible: `annapurna-labs,alpine-internal-pcie`
- Sets `PCI_PROBE_ONLY` — prevents BAR reassignment (preserves U-Boot config)
- Bus notifier on `BUS_NOTIFY_BIND_DRIVER` configures per-device:
  - SMCC Sub-Master snoop (offset 0x110, 0x130, 0x150, 0x170) — bits 0+1
  - APP_CONTROL register (offset 0x220) — lower 16 bits = 0x03FF
- Reverse-engineered from stock 4.19 firmware via vmlinux-to-elf + disassembly
**Why:** Without this, TX DMA (Ethernet) and IDENTIFY (SATA) fail due to missing cache coherency configuration

### 2. Patched Driver: `pcie-al.c` (External PCIe)
**File:** `drivers/pci/controller/dwc/pcie-al.c`
**Changes:**
- Pre-set `pci->dbi_base = devm_ioremap(dev, controller_res->start + 0x10000, 0x10000)`
- Prevents DWC framework resource conflict (controller and DBI share same base on Alpine V2)
**Why:** Without this, the external PCIe (xHCI USB for eMMC boot) fails to probe

### 3. PCI Quirk: `quirk_al_alpine_snoop_enable` (backup/fallback)
**File:** `drivers/pci/quirks.c`
**What:** DECLARE_PCI_FIXUP_FINAL for vendor 0x1c36 — sets SMCC snoop on all sub-masters
**Note:** With pcie-al-internal.c, this quirk is redundant but harmless as defense-in-depth

### 4. Out-of-tree Module: `al_eth.ko` (Ethernet)
**Location:** `secfirstnas-rs/kernel/modules/al_eth/`
**Ported from:** delroth/al_eth-standalone (kernel 5.5) → kernel 6.12
**Key changes from 5.5 original:**
- Added C22 MDIO `read`/`write` callbacks (6.12 splits C22/C45)
- `ndo_do_ioctl` → `ndo_eth_ioctl`
- `strlcpy` → `strscpy`
- `u64_stats_fetch_begin_irq` → `u64_stats_fetch_begin`
- `kzfree` → `kfree_sensitive`
- Ethtool: `get/set_settings` → `get/set_link_ksettings`
- Ethtool: `get/set_coalesce` — added `kernel_ethtool_coalesce` + `netlink_ext_ack` params
- Ethtool: `get/set_rxfh` → uses `ethtool_rxfh_param` struct
- Ethtool: `ethtool_eee` → `ethtool_keee`
- Ethtool: added `supported_coalesce_params`
- `phydev->advertising` — bitfield ops → `linkmode_*()` API
- HAL files (al_hal_*): UNCHANGED (pure register access, no kernel API deps)

### 5. Custom Device Tree: `alpine-v2-ubnt-unvr.dts`
**Location:** `secfirstnas-rs/kernel/dts/alpine-v2-ubnt-unvr.dts`
**Key additions over mainline alpine-v2.dtsi:**
- `pci@fbc00000`: compatible = `annapurna-labs,alpine-internal-pcie` + `dma-coherent`
- `msix@fbe00000`: added `interrupt-controller` + `#interrupt-cells` (needed for of_irq_init)
- External PCIe: `pcie@fd800000` with `amazon,al-alpine-v2-pcie`, reg = controller(64K) + config/ECAM(1MB at 0xfb600000)
- `chosen`: `linux,pci-probe-only = <1>` + `iommu.passthrough=1` in bootargs
- All UNVR peripherals: I2C (PCA9546 mux, 3x PCA9575), GPIO, LEDs, HDD power control, SATA LEDs, Reset button, Watchdog, RTC, Thermal, SPI flash partitions

### 6. Kernel Config: `unvr_defconfig`
**Key additions over default arm64:**
- `CONFIG_ARCH_ALPINE=y`
- `CONFIG_PCIE_AL=y` (external PCIe, DWC-based)
- `CONFIG_PCIE_AL_INTERNAL=y` (internal PCIe, our new driver)
- `CONFIG_PCI_HOST_GENERIC=y` (fallback)
- `CONFIG_ALPINE_MSI=y` (MSI-X interrupt controller)
- `CONFIG_SATA_AHCI=y`
- `CONFIG_MD` + RAID 0/1/5/10 as modules
- `CONFIG_DM_CRYPT=m`
- `CONFIG_BTRFS_FS=m`
- `CONFIG_ZONE_DMA32=y`
- Full ARM64 crypto acceleration
- I2C DesignWare, PCA953x GPIO, PL061 GPIO
- Marvell PHY drivers
- xHCI USB

### 7. U-Boot Configuration
**Saved env:**
```
bootcmd_secfirst=usb start; ext4load usb 0 0x04078000 alpine-v2-ubnt-unvr.dtb; ext4load usb 0 0x08000004 uImage; fdt addr 0x04078000; bootm 0x08000004 - 0x04078000
bootcmd=run bootcmd_secfirst
```
**U-Boot env (mtd1):** `rootfs=PARTLABEL=rootfs`, `bootargsextra=boot=local rw`
**Recovery:** Hold reset button during power-on → telnet → restore factory firmware

### 8. Build Infrastructure
- `kernel/Dockerfile` — Debian Bookworm cross-compile container
- Docker-based build: `make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-`
- uImage wrapper via `mkimage`
- al_eth built as out-of-tree module against built kernel tree

### Key Discoveries
1. **AXI Sub-Master Snoop** — Internal PCI devices need SMCC registers configured for cache-coherent DMA. Without it, DMA reads return stale cache data.
2. **APP_CONTROL Register** (0x220) — Must have lower 16 bits set to 0x03FF. Discovered via firmware disassembly.
3. **DBI base offset** — On Alpine V2, DWC DBI registers are at controller_base + 0x10000, not at controller_base.
4. **ECAM for external PCIe** — At 0xfb600000 (1MB), not at 0xfd810000 (64K). The 64K region is DBI, not ECAM.
5. **MSI-X init** — Needs `interrupt-controller` property on the msix node for `of_irq_init()` to process it.
6. **`linux,pci-probe-only`** — Must be in `/chosen` node (not PCI node) and must be `= <1>` (u32, not boolean).
7. **Bootargs source** — U-Boot's `setenv bootargs` in bootcmd overrides DTB chosen/bootargs. Put args in DTB or remove setenv from bootcmd.
