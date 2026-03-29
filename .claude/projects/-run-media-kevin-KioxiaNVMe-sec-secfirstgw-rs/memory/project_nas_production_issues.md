---
name: NAS production issues backlog
description: All known issues that need fixing before secfirstNAS is production-ready. Collected 2026-03-21.
type: project
---

## secfirstNAS Production Issues Backlog

### Critical (breaks functionality)
1. **smartctl timeout on removed disk** — API hangs 30+ seconds when disk is removed, UI shows "NetworkError". Fix: run smartctl with `timeout 5` wrapper, catch errors gracefully
2. **UI crashes on disk removal** — "Failed to load storage data" / "NetworkError". Frontend must handle API timeouts and show degraded state instead of crashing
3. **RAID not auto-assembled after reboot** — Arrays=0 after boot. Need: `mdadm --detail --scan >> /etc/mdadm.conf` and `mdadm --assemble --scan` in init script
4. **No auto-mount** — RAID + Btrfs not mounted after boot. Need fstab entries or init script mount

### Important (broken features)
5. **Bay N/A in Storage page** — Disk API doesn't include bay-to-disk mapping. Need to call `Bay::map_to_disk()` and add `bay: Option<u8>` to disk API response
6. **Serial "Unknown"** — SMART serial not parsed. The `smartctl` output has serial at a different line than expected. Fix `extract_smart_value` to check "Serial Number" field
7. **Logs show dmesg** — syslogd not auto-started. Add `syslogd` to OpenRC boot runlevel in image
8. **No live disk/bay updates** — UI polls every 10s but doesn't reflect hot-plug instantly. Consider: reduce poll to 3s for bays, or add WebSocket for bay events via udev
9. **syslogd not in image** — Must auto-start. Add to init script or OpenRC

### Nice to have (polish)
10. **Deploy script bash vs sh** — Step 6 fails on Alpine (no bash). Already partially fixed but verify
11. **HTTPS** — Currently HTTP on 8080. Need self-signed TLS on 443 (copy from sfgw-api)
12. **E2EE** — No envelope encryption on API. Copy X25519+AES-GCM layer from sfgw
13. **Fan profile not persistent** — Resets to balanced on reboot. Save to `/data/config/fan_profile`
14. **Bay LED state not persistent** — LEDs set in init script but mode not saved
15. **Firmware update via UI** — Upload endpoint exists but no actual flash logic
16. **Bay slot ordering wrong in CLI** — Slots map to wrong physical positions (verified LED test showed different order than code assumed)

### Already fixed
- ✅ °C Unicode display
- ✅ eMMC filtered from disk list (fbc00000 filter)
- ✅ Temperatures in dashboard (HWMON + HDD SMART)
- ✅ Network shows active interface (eth0 not eth1)
- ✅ Uptime decimal overflow
- ✅ Deploy script stops service before SCP
- ✅ Deploy script uses sh not bash
- ✅ Deploy script restarts service after deploy
- ✅ OpenRC init script for secfirstnas
- ✅ Module auto-load config
- ✅ Bay LEDs (white + red, all 4 slots)
- ✅ SGPO driver for SATA LEDs
- ✅ Fan control (PWM, RPM readback)

**How to apply:** Fix items 1-9 together in next sprint, build new image, test as complete unit.
