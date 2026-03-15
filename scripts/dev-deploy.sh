#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# dev-deploy.sh — Fast dev loop: rsync source to UDM Pro, build on-device,
#                 install to /usr/local/bin, restart systemd service.
#
# Usage:
#   ./scripts/dev-deploy.sh              # default: root@10.0.0.1
#   ./scripts/dev-deploy.sh 10.0.0.1     # custom IP

set -euo pipefail

TARGET="${1:-10.0.0.1}"
USER="root"
REMOTE_SRC="/data/sfgw-src"
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

# ─── Rsync source to UDM ─────────────────────────────────────────────────────

log "Syncing source to ${C}${USER}@${TARGET}:${REMOTE_SRC}${N}..."

tar -cf - -C "${PROJECT_DIR}" \
    --exclude='target' \
    --exclude='web/node_modules' \
    --exclude='web/dist' \
    --exclude='.git' \
    --exclude='dist' \
    . | ssh "${USER}@${TARGET}" "mkdir -p ${REMOTE_SRC} && tar -xf - -C ${REMOTE_SRC}"

log "Sync complete."

# ─── Build on device ─────────────────────────────────────────────────────────

log "Building on ${C}${TARGET}${N} (release)..."

# shellcheck disable=SC2087
ssh "${USER}@${TARGET}" bash <<'REMOTE_BUILD'
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

cd /data/sfgw-src
cargo build --release --bin sfgw 2>&1

# Stop service before overwriting binary ("text file busy")
systemctl stop sfgw.service 2>/dev/null || true
sleep 1

# Install binary to persistent location
cp target/release/sfgw /usr/local/bin/sfgw
chmod 0755 /usr/local/bin/sfgw

echo "BUILD_OK"
REMOTE_BUILD

log "Build complete."

# ─── Copy web assets (pre-built locally) ──────────────────────────────────────
# Must happen BEFORE service restart — sfgw start rebuilds the network stack
# and the SSH connection may drop during that window.

if [ -d "${PROJECT_DIR}/web/dist" ]; then
    log "Syncing pre-built web assets..."
    ssh "${USER}@${TARGET}" "mkdir -p /usr/local/share/sfgw/web"
    tar -cf - -C "${PROJECT_DIR}/web/dist" . | ssh "${USER}@${TARGET}" "tar -xf - -C /usr/local/share/sfgw/web"
else
    warn "No web/dist/ found locally. Run 'cd web && npm run build' first."
    warn "Continuing without web UI update."
fi

# ─── Restart sfgw service ────────────────────────────────────────────────────

log "Restarting sfgw service..."

ssh "${USER}@${TARGET}" bash <<'REMOTE_RESTART'
set -euo pipefail

systemctl start sfgw.service
sleep 2

if systemctl is-active sfgw.service >/dev/null 2>&1; then
    PID=$(pgrep -f '/usr/local/bin/sfgw start' || true)
    if [ -n "$PID" ]; then
        MEM=$(ps -o rss= -p $PID | awk '{printf "%.1f MB", $1/1024}')
        echo "sfgw running — PID $PID, $MEM RAM (systemd)"
    else
        echo "sfgw service active"
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
        systemctl stop sfgw.service 2>/dev/null || true
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
        echo "SFGW chains flushed. SSH restored. Check /data/sfgw/sfgw.log"
        exit 1
    fi
else
    echo "FAILED — sfgw service not active"
    tail -20 /data/sfgw/sfgw.log
    exit 1
fi
REMOTE_RESTART

echo ""
echo -e "${G}Done!${N} https://${TARGET}:443"
echo -e "Logs: ssh ${USER}@${TARGET} tail -f /data/sfgw/sfgw.log"
