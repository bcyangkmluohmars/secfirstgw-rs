---
name: UNVR HDD Bay LED mapping
description: Verified GPIO-to-LED mapping for all 4 HDD bays — white (SGPO) and red/orange (PCA9575). Tested 2026-03-21.
type: project
---

## UNVR HDD Bay LED Mapping (verified)

| Slot | White (Activity) | Red (Fault) |
|------|------------------|-------------|
| 1    | SGPO gpiochip8 pin 22 | PCA gpiochip1 pin 12 |
| 2    | SGPO gpiochip8 pin 20 | PCA gpiochip1 pin 13 |
| 3    | SGPO gpiochip8 pin 16 | PCA gpiochip1 pin 14 |
| 4    | SGPO gpiochip8 pin 18 | PCA gpiochip1 pin 15 |

### SGPO (Serial GPIO Output) — white activity LEDs
- Driver: `al_sgpo.ko` (custom, out-of-tree)
- Chip: `gpiochip8 [fd8b4000.sgpo]` (32 lines, 4 groups)
- Only even pins 16,18,20,22 drive LEDs; odd pins 17,19,21,23 are unused
- Control: `gpioset 8 <pin>=1` (on) / `gpioset 8 <pin>=0` (off)

### PCA9575 — red/orange fault LEDs
- Driver: `pca953x` (mainline, built-in)
- Chip: `gpiochip1 [0-0021]` (16 lines, I2C addr 0x21)
- Lines 12-15 are fault LEDs
- Lines 0-3 are HDD power (**DANGER: do not toggle blindly, controls eMMC power too**)
- Lines 4-7 are presence detect (active-low: 0=present)
- Control: `gpioset 1 <pin>=1` (on) / `gpioset 1 <pin>=0` (off)

### ulogo LEDs (front panel)
- White: `gpiochip6` (PL061 GPIO4 pin 5) — `/sys/class/leds/ulogo_white/`
- Blue: `gpiochip5` (PL061 GPIO3 pin 7) — `/sys/class/leds/ulogo_blue/`
- Triggers: none, heartbeat, default-on, disk-activity, timer

### Usage in sfnas-storage Bay code
```rust
// White = disk OK / activity indicator
// Red = fault / SMART warning / rebuild
// Both = critical error
```

**Why:** Need this mapping for the sfnas-storage Bay struct to control LEDs based on disk health, RAID status, and I/O activity.

**How to apply:** Update `crates/sfnas-storage/src/bay.rs` with correct GPIO chip numbers and pin mappings. Use libgpiod chardev API (`/dev/gpiochipN`) instead of legacy sysfs.
