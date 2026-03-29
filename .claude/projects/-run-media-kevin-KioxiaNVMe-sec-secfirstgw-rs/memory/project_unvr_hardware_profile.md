---
name: uNVR hardware profile
description: Complete hardware mapping of uNVR dev device — SoC, GPIO bay control, LEDs, fans, boot layout, PCI, network. Updated with all kernel 6.12 findings.
type: project
---

## uNVR Hardware Profile — Board ID `ea1a`

**SoC:** Annapurna Labs Alpine V2 (AL-314), 4x Cortex-A57, AES/SHA/CRC32 crypto extensions
**RAM:** 4040 MB, no swap
**Device IP:** 10.0.0.118 (DHCP)

### Boot
- 32 GB eMMC via ASMedia ASM3042 USB 3.0 xHCI (PCIe external port 0)
- U-Boot on SPI flash (mtd0-6), custom bootcmd_secfirst saved in env
- Alpine Linux 3.21 rootfs on ext4

### Storage
- 2x AHCI controllers (PCI 00:08.0, 00:09.0), 4 SATA-III ports each = 8 total, 4 physical bays
- AHCI hot-plug confirmed (SSS flag set)
- Tested: 3x 3TB HDD + 1x 120GB Intel DC SSD — RAID5 working, 57 MB/s write, 204 MB/s read

### HW Acceleration Engines
- **Ethernet** (PCI 00:01.0, 00:02.0): al_eth driver, 1GbE + 10GbE
- **DMA/RAID** (PCI 00:05.0): al_dma driver, 4 channels, XOR+PQ for RAID5/6 HW parity
- **Crypto** (PCI 00:04.0): al_ssm driver, AES-XTS/CBC priority 400 (beats ARM CE at 300)
- All engines need AXI SMCC snoop + APP_CONTROL configured by pcie-al-internal driver

### Fan Control (ADT7475 HWMON)
- 3x fans connected (Fan 4 not populated)
- Fan 1-3: ~2600 RPM idle (31% PWM), max ~8600 RPM (100% PWM)
- PWM control: `/sys/class/hwmon/hwmon0/pwm{1,2,3}` (0-255)
- RPM readback: `/sys/class/hwmon/hwmon0/fan{1,2,3}_input`
- Temperature sensors: 3 channels (38°C/37°C/34°C idle)
  - `/sys/class/hwmon/hwmon0/temp{1,2,3}_input` (millidegrees)
- Fan profiles planned: silence/balanced/performance based on HDD+CPU temp

### GPIO / Bay Control (PCA9575 I2C expander at 0x21 = gpiochip1)
- Lines 0-3: HDD Power (output) — **DANGER: toggles eMMC power too, do not blind-toggle!**
- Lines 4-7: HDD Present (input, active-low) — working, tested all 4 slots
- Lines 12-15: HDD Fault LED (output) — GPIO works but LED not confirmed visually
- gpiochip0 (PCA9575 at 0x20): misc GPIO, some outputs some inputs

### LEDs
- ulogo_blue: gpiochip5 (PL061 GPIO3 Pin 7) — working, trigger support
- ulogo_white: gpiochip6 (PL061 GPIO4 Pin 5) — working, trigger support (heartbeat, default-on, disk-activity)
- SATA Activity LEDs: SGPO controller at 0xfd8b0000 — needs al_sgpo driver (building)
  - Pins: 16 (slot 3), 18 (slot 4), 20 (slot 2), 22 (slot 1)
- HDD Fault LEDs: PCA9575 gpiochip1 lines 12-15 — GPIO toggleable, LED visibility unconfirmed

### Bluetooth
- CSR Bluetooth Dongle (USB 0a12:0001) on internal USB header
- **STATUS: OFF** — antenna physically removed, kernel support disabled

### Network
- eth0: 1GbE RJ45 (al_eth, Marvell/RTL PHY via C22 MDIO)
- eth1: 10G SFP+ (al_eth, SerDes)

### PCI (Internal Bus — pcie-al-internal driver)
- 00:01.0: Ethernet 1GbE (al_eth)
- 00:02.0: Ethernet 10GbE (al_eth)
- 00:04.0: Crypto Engine (al_ssm)
- 00:05.0: DMA/RAID Engine (al_dma)
- 00:08.0: AHCI SATA Controller 0
- 00:09.0: AHCI SATA Controller 1

### PCI (External Bus — pcie-al DWC driver)
- 01:00.0: ASMedia ASM3042 xHCI (eMMC USB bridge)

### Other
- RTC: S35390A on I2C bus 1
- Watchdog: SP805 (fd88c000)
- Serial: ttyS0 at 115200 baud (UART console)
- SPI Flash: 7 MTD partitions (u-boot, env, factory, eeprom, recovery, config)
- Thermal: Annapurna Labs thermal sensor (CPU, ~52°C under load)
