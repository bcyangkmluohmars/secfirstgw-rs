---
name: Be careful with rm -rf
description: User warned about careless rm -rf usage, especially with Docker volume mounts where host paths are exposed
type: feedback
---

Be extra careful with `rm -rf` commands, especially in Docker contexts with volume mounts.

**Why:** Volume mounts map host paths into containers. A wrong path in `rm -rf` inside a container can destroy host data. The user explicitly warned about this.

**How to apply:** Always double-check paths before any `rm -rf`. Prefer targeted deletion over wildcards. When cleaning Docker-created files, verify the mount path is correct and isolated. Ask before running destructive commands on host filesystem.
