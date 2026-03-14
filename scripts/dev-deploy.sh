#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# dev-deploy.sh — Fast dev loop: rsync source to UDM Pro, build on-device, restart
#
# Usage:
#   ./scripts/dev-deploy.sh              # default: root@192.168.1.1
#   ./scripts/dev-deploy.sh 10.0.0.1     # custom IP
#   SFGW_PORT=9443 ./scripts/dev-deploy.sh  # custom listen port

set -euo pipefail

TARGET="${1:-192.168.1.1}"
USER="root"
REMOTE_SRC="/data/sfgw-src"
REMOTE_BIN="/tmp/sfgw"
SFGW_PORT="${SFGW_PORT:-8443}"
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

# Use tar+ssh pipe — works without rsync on target
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

# Build release binary
cargo build --release --bin sfgw 2>&1

# Stop running sfgw before copying (binary may be "text file busy")
pkill -f '/tmp/sfgw start' 2>/dev/null || true
sleep 1

# Copy binary to /tmp (not persistent across reboot)
cp target/release/sfgw /tmp/sfgw
chmod +x /tmp/sfgw

echo "BUILD_OK"
REMOTE_BUILD

log "Build complete."

# ─── Copy web assets (pre-built locally) ──────────────────────────────────────

if [ -d "${PROJECT_DIR}/web/dist" ]; then
    log "Syncing pre-built web assets..."
    tar -cf - -C "${PROJECT_DIR}/web/dist" . | ssh "${USER}@${TARGET}" "mkdir -p /tmp/sfgw-web && tar -xf - -C /tmp/sfgw-web"
else
    warn "No web/dist/ found locally. Run 'cd web && npm run build' first."
    warn "Continuing without web UI update."
fi

# ─── Restart sfgw ─────────────────────────────────────────────────────────────

log "Restarting sfgw on port ${C}${SFGW_PORT}${N}..."

ssh "${USER}@${TARGET}" bash <<REMOTE_RESTART
set -euo pipefail

# Kill existing sfgw
pkill -f '/tmp/sfgw start' 2>/dev/null || true
sleep 1

# Stop platform dnsmasq instances that would block sfgw ports.
# NOTE: Do NOT kill ubios-udapi-server — it manages networking/routing.
# Instead, remove the config files that ubios uses to spawn dnsmasq.
# Without configs, respawned dnsmasq instances fail immediately.
rm -f /run/dnsmasq.dns.conf.d/*.conf 2>/dev/null || true
rm -f /run/dnsmasq.dhcp.conf.d/*.conf 2>/dev/null || true
[ -x /etc/init.d/dnsmasq ] && /etc/init.d/dnsmasq stop 2>/dev/null || true
killall -q dnsmasq 2>/dev/null || true
sleep 1
# Ensure log directory exists
mkdir -p /var/log/sfgw

# Start fresh
export SFGW_DB_PATH=/data/sfgw/sfgw.db
export SFGW_LISTEN_ADDR="[::]:${SFGW_PORT}"
export SFGW_WEB_DIR=/tmp/sfgw-web
export RUST_LOG=sfgw=debug

nohup /tmp/sfgw start > /tmp/sfgw.log 2>&1 &

sleep 2

if pgrep -f '/tmp/sfgw start' >/dev/null; then
    PID=\$(pgrep -f '/tmp/sfgw start')
    MEM=\$(ps -o rss= -p \$PID | awk '{printf "%.1f MB", \$1/1024}')
    echo -e "sfgw running — PID \$PID, \$MEM RAM, port ${SFGW_PORT}"
else
    echo "FAILED — check /tmp/sfgw.log"
    tail -20 /tmp/sfgw.log
    exit 1
fi
REMOTE_RESTART

echo ""
echo -e "${G}Done!${N} https://${TARGET}:${SFGW_PORT}"
echo -e "Logs: ssh ${USER}@${TARGET} tail -f /tmp/sfgw.log"
