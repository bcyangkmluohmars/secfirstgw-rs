#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# dev-deploy.sh — Cross-compile in Docker, push binary to UDM Pro, restart.
#
# Usage:
#   ./scripts/dev-deploy.sh              # default: root@10.0.0.1
#   ./scripts/dev-deploy.sh 10.0.0.1     # custom IP

set -euo pipefail

TARGET="${1:-10.0.0.1}"
USER="root"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

# Colors
if [ -t 1 ]; then
    G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m' R='\033[0;31m' N='\033[0m'
else
    G='' Y='' C='' R='' N=''
fi

log()  { echo -e "${G}[dev]${N} $*"; }
warn() { echo -e "${Y}[dev]${N} $*"; }
err()  { echo -e "${R}[dev]${N} $*" >&2; exit 1; }

# ─── Cross-compile in Docker ────────────────────────────────────────────────

log "Cross-compiling for aarch64-musl in Docker..."

docker build -f "${PROJECT_DIR}/Dockerfile.cross" -o "${PROJECT_DIR}/out" "${PROJECT_DIR}" 2>&1 \
    | while IFS= read -r line; do
        # Show only cargo compile lines and the final result
        case "$line" in
            *Compiling*|*Finished*|*error*|*warning*sfgw*) echo "  $line" ;;
        esac
    done

[ -f "${PROJECT_DIR}/out/sfgw" ] || err "Build failed — no binary produced"
log "Build complete: $(ls -lh "${PROJECT_DIR}/out/sfgw" | awk '{print $5}') static binary"

# ─── Push binary to device ──────────────────────────────────────────────────

log "Deploying to ${C}${USER}@${TARGET}${N}..."

ssh "${USER}@${TARGET}" "rc-service sfgw stop 2>/dev/null || true; sleep 1"
scp -q "${PROJECT_DIR}/out/sfgw" "${USER}@${TARGET}:/usr/local/bin/sfgw"
ssh "${USER}@${TARGET}" "chmod 0755 /usr/local/bin/sfgw"

log "Binary deployed."

# ─── Copy web assets (pre-built locally) ─────────────────────────────────────

if [ -d "${PROJECT_DIR}/web/dist" ]; then
    log "Syncing pre-built web assets..."
    ssh "${USER}@${TARGET}" "mkdir -p /usr/local/share/sfgw/web"
    tar -cf - -C "${PROJECT_DIR}/web/dist" . | ssh "${USER}@${TARGET}" "tar -xf - -C /usr/local/share/sfgw/web"
else
    warn "No web/dist/ found locally. Run 'cd web && npm run build' first."
    warn "Continuing without web UI update."
fi

# ─── Restart sfgw service ───────────────────────────────────────────────────

log "Restarting sfgw service..."

ssh "${USER}@${TARGET}" bash <<'REMOTE_RESTART'
set -euo pipefail

# Configure adt7475 hardware-autonomous fan control (UDM Pro)
HW="/sys/class/hwmon/hwmon0"
if [ -f "$HW/name" ] && [ "$(cat "$HW/name")" = "adt7475" ]; then
    echo 2 > "$HW/pwm2_auto_channels_temp"
    echo 45000 > "$HW/temp2_auto_point1_temp"
    echo 75000 > "$HW/temp2_auto_point2_temp"
    echo 64 > "$HW/pwm2_auto_point1_pwm"
    echo 255 > "$HW/pwm2_auto_point2_pwm"
    echo 2 > "$HW/pwm2_enable"
    echo "Fan: adt7475 autonomous mode (45-75°C ramp)"
fi

rc-service sfgw start
sleep 2

if rc-service sfgw status | grep -q "started"; then
    PID=$(pgrep -f '/usr/local/bin/sfgw' || true)
    if [ -n "$PID" ]; then
        MEM=$(awk '/VmRSS/{printf "%.1f MB", $2/1024}' /proc/$PID/status 2>/dev/null || echo "? MB")
        echo "sfgw running — PID $PID, $MEM RAM"
    else
        echo "sfgw service started"
    fi

    # Verify SSH still works after firewall rules applied.
    sleep 3
    SSH_OK=0
    for i in 1 2 3; do
        if (echo > /dev/tcp/127.0.0.1/22) 2>/dev/null; then
            SSH_OK=1
            break
        fi
        sleep 1
    done

    if [ "$SSH_OK" -eq 1 ]; then
        echo "SSH connectivity check passed."
    else
        echo "SSH BLOCKED — firewall lockout detected! Stopping service..."
        rc-service sfgw stop 2>/dev/null || true
        # Flush SFGW chains to restore connectivity (IPv4 + IPv6).
        for ipt in iptables ip6tables; do
            for chain in SFGW-INPUT SFGW-FORWARD SFGW-OUTPUT; do
                bc="${chain#SFGW-}"
                $ipt -D "$bc" -j "$chain" 2>/dev/null || true
                $ipt -F "$chain" 2>/dev/null || true
                $ipt -X "$chain" 2>/dev/null || true
            done
        done
        for chain in SFGW-PREROUTING SFGW-POSTROUTING; do
            bc="${chain#SFGW-}"
            iptables -t nat -D "$bc" -j "$chain" 2>/dev/null || true
            iptables -t nat -F "$chain" 2>/dev/null || true
            iptables -t nat -X "$chain" 2>/dev/null || true
        done
        echo "SFGW chains flushed. SSH restored. Check /var/log/sfgw/sfgw.log"
        exit 1
    fi
else
    echo "FAILED — sfgw service not started"
    tail -20 /var/log/sfgw/sfgw.log 2>/dev/null || tail -20 /var/log/sfgw/sfgw.err 2>/dev/null
    exit 1
fi
REMOTE_RESTART

echo ""
echo -e "${G}Done!${N} https://${TARGET}:443"
echo -e "Logs: ssh ${USER}@${TARGET} tail -f /var/log/sfgw/sfgw.log"
