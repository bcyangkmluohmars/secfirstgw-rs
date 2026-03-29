---
name: NAS MVP goal — replace Synology Rackstation
description: First goal is replacing Kevin's Synology with uNVR running secfirstNAS. Only needs SMB shares + rsync (backup sync from Frankfurt).
type: project
---

MVP goal: Replace Kevin's Synology Rackstation with secfirstNAS on uNVR.

Required features for MVP:
1. SMB shares (via Samba)
2. rsync for backup sync from Frankfurt server

NVR/camera features come later. SMB + rsync is the first milestone.

**Why:** Kevin has the uNVR sitting around for 1-2 years, originally wanted to sell it. If secfirstNAS can replace the Synology, it's proof the product works.

**How to apply:** Prioritize sfnas-storage (MD RAID setup) + sfnas-share (Samba) + rsync in base image. NVR is a later phase.
