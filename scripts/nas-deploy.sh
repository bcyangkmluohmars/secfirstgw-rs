#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# nas-deploy.sh — Cross-compile secfirstNAS and deploy EVERYTHING to UNVR (Alpine aarch64).
#
# Deploys:
#   1. secfirstnas binary      → /usr/local/bin/secfirstnas
#   2. web-nas static files    → /data/www/
#   3. kernel modules          → /lib/modules/6.12.77/extra/
#   4. module auto-load config → /lib/modules-load.d/secfirstnas.conf
#   5. LED default state       → ulogo white default-on
#   6. Samba defaults           (if not already configured)
#   7. depmod -a
#
# Usage:
#   ./scripts/nas-deploy.sh              # default: root@10.0.0.118
#   ./scripts/nas-deploy.sh 10.0.0.118   # custom IP

set -euo pipefail

TARGET="${1:-10.0.0.118}"
USER="root"
REMOTE_BIN="/usr/local/bin/secfirstnas"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
DOCKER_IMAGE="sfnas-builder"
DOCKERFILE="${SCRIPT_DIR}/nas-build.Dockerfile"
TRIPLE="aarch64-unknown-linux-musl"
LOCAL_BIN="${PROJECT_DIR}/target/${TRIPLE}/release/secfirstnas"

# Kernel module source paths (pre-built, do not rebuild)
KMOD_DIR="/run/media/kevin/KioxiaNVMe/sec/secfirstnas-rs/kernel/build"
KMOD_ROOTFS="${KMOD_DIR}/rootfs/lib/modules/6.12.77/extra"
KVER="6.12.77"
REMOTE_KMOD_DIR="/lib/modules/${KVER}/extra"

# Web UI
WEBNAS_DIR="${PROJECT_DIR}/web-nas"
WEBNAS_DIST="${WEBNAS_DIR}/dist"
REMOTE_WWW="/data/www"

# Colors
if [ -t 1 ]; then
    G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m' R='\033[0;31m' N='\033[0m'
else
    G='' Y='' C='' R='' N=''
fi

log()  { echo -e "${G}[nas]${N} $*"; }
warn() { echo -e "${Y}[nas]${N} $*"; }
err()  { echo -e "${R}[nas]${N} $*" >&2; exit 1; }

# ─── Step 1: Cross-compile binary in Docker ──────────────────────────────────

log "Step 1/7: Building secfirstnas for ${C}${TRIPLE}${N} (static musl)..."

docker build \
    -f "${DOCKERFILE}" \
    -t "${DOCKER_IMAGE}" \
    "${PROJECT_DIR}"

# Extract the binary from the Docker image
log "Extracting binary..."
mkdir -p "$(dirname "${LOCAL_BIN}")"
CONTAINER_ID=$(docker create "${DOCKER_IMAGE}")
docker cp "${CONTAINER_ID}:/build/target/${TRIPLE}/release/secfirstnas" "${LOCAL_BIN}"
docker rm "${CONTAINER_ID}" >/dev/null

if [ ! -f "${LOCAL_BIN}" ]; then
    err "Build failed — binary not found at ${LOCAL_BIN}"
fi

SIZE=$(du -h "${LOCAL_BIN}" | cut -f1)
log "Binary: ${C}${LOCAL_BIN}${N} (${SIZE})"

# ─── Step 2: Build web UI ────────────────────────────────────────────────────

log "Step 2/7: Building web-nas UI..."

if [ ! -f "${WEBNAS_DIR}/package.json" ]; then
    err "web-nas/package.json not found"
fi

(cd "${WEBNAS_DIR}" && npm install --silent && npm run build)

if [ ! -f "${WEBNAS_DIST}/index.html" ]; then
    err "web-nas build failed — dist/index.html not found"
fi

log "Web UI built: $(du -sh "${WEBNAS_DIST}" | cut -f1)"

# ─── Step 3: Deploy binary ───────────────────────────────────────────────────

log "Step 3/7: Deploying binary to ${C}${USER}@${TARGET}:${REMOTE_BIN}${N}..."

# Stop service and kill any remaining process before overwriting binary
ssh "${USER}@${TARGET}" "rc-service secfirstnas stop 2>/dev/null; pkill -9 secfirstnas 2>/dev/null; sleep 1; rm -f ${REMOTE_BIN}"

scp -q "${LOCAL_BIN}" "${USER}@${TARGET}:${REMOTE_BIN}"
ssh "${USER}@${TARGET}" "chmod 0755 ${REMOTE_BIN}"

# ─── Step 4: Deploy web UI ───────────────────────────────────────────────────

log "Step 4/7: Deploying web UI to ${C}${REMOTE_WWW}${N}..."

ssh "${USER}@${TARGET}" "mkdir -p ${REMOTE_WWW}"
scp -q -r "${WEBNAS_DIST}/"* "${USER}@${TARGET}:${REMOTE_WWW}/"

# ─── Step 5: Deploy kernel modules ───────────────────────────────────────────

log "Step 5/7: Deploying kernel modules to ${C}${REMOTE_KMOD_DIR}${N}..."

# Collect all kernel modules (al_eth, al_dma, al_ssm from rootfs; al_sgpo from build dir)
TMPMOD=$(mktemp -d)
trap "rm -rf ${TMPMOD}" EXIT

if [ -d "${KMOD_ROOTFS}" ]; then
    cp "${KMOD_ROOTFS}/"*.ko "${TMPMOD}/" 2>/dev/null || true
fi
# al_sgpo is built separately and lives in the build root
if [ -f "${KMOD_DIR}/al_sgpo.ko" ]; then
    cp "${KMOD_DIR}/al_sgpo.ko" "${TMPMOD}/"
fi

NMOD=$(ls "${TMPMOD}/"*.ko 2>/dev/null | wc -l)
if [ "${NMOD}" -eq 0 ]; then
    warn "No kernel modules found to deploy — skipping"
else
    ssh "${USER}@${TARGET}" "mkdir -p ${REMOTE_KMOD_DIR}"
    scp -q "${TMPMOD}/"*.ko "${USER}@${TARGET}:${REMOTE_KMOD_DIR}/"
    log "Deployed ${NMOD} kernel module(s): $(ls "${TMPMOD}/"*.ko | xargs -I{} basename {} | tr '\n' ' ')"
fi

# ─── Step 6: Module auto-loading + LED + Samba defaults ──────────────────────

log "Step 6/7: Configuring module auto-load, LED, and Samba defaults..."

ssh "${USER}@${TARGET}" sh -s <<'REMOTE_SETUP'
set -e

# --- Module auto-loading ---
# Alpine uses /lib/modules-load.d/, NOT /etc/modules-load.d/
mkdir -p /lib/modules-load.d
cat > /lib/modules-load.d/secfirstnas.conf <<'EOF'
# secfirstNAS kernel modules — loaded at boot
al_dma
al_ssm
al_eth
al_sgpo
EOF

# --- LED default state: ulogo white = default-on ---
# The UNVR has an addressable LED ring controlled via /sys/class/leds/
# Set the U-Logo LED to white (default-on trigger)
for led_path in /sys/class/leds/white:*/trigger; do
    if [ -f "$led_path" ]; then
        echo "default-on" > "$led_path" 2>/dev/null || true
    fi
done

# Also handle ulogo specifically if it exists
if [ -d /sys/class/leds/ulogo ]; then
    echo "default-on" > /sys/class/leds/ulogo/trigger 2>/dev/null || true
    echo 255 > /sys/class/leds/ulogo/brightness 2>/dev/null || true
fi

# Fallback: set all white LEDs to max brightness
for br_path in /sys/class/leds/white:*/brightness; do
    if [ -f "$br_path" ]; then
        echo 255 > "$br_path" 2>/dev/null || true
    fi
done

# --- Samba defaults (only if not already configured) ---
if [ ! -f /etc/samba/smb.conf ]; then
    mkdir -p /etc/samba
    cat > /etc/samba/smb.conf <<'SMBEOF'
[global]
   workgroup = WORKGROUP
   server string = SecFirstNAS
   server role = standalone server
   log file = /var/log/samba/log.%m
   max log size = 1000
   logging = file

   # Security
   map to guest = Bad User
   usershare allow guests = yes
   security = user
   passdb backend = tdbsam

   # SMB3 minimum — no legacy protocols
   server min protocol = SMB3
   server max protocol = SMB3

   # Performance
   socket options = TCP_NODELAY IPTOS_LOWDELAY
   read raw = yes
   write raw = yes
   use sendfile = yes
   aio read size = 16384
   aio write size = 16384

   # Disable printing
   load printers = no
   printing = bsd
   printcap name = /dev/null
   disable spoolss = yes

   # File creation
   create mask = 0664
   directory mask = 0775
SMBEOF
    echo "[samba] Created default smb.conf"
else
    echo "[samba] smb.conf already exists — skipping"
fi

mkdir -p /var/log/samba
REMOTE_SETUP

# ─── Step 7: Deploy init script ──────────────────────────────────────────────

log "Step 7/9: Deploying init script + firewall..."

INITD_SCRIPT="${SCRIPT_DIR}/secfirstnas.initd"
if [ -f "${INITD_SCRIPT}" ]; then
    scp -q "${INITD_SCRIPT}" "${USER}@${TARGET}:/etc/init.d/secfirstnas"
    ssh "${USER}@${TARGET}" "chmod 0755 /etc/init.d/secfirstnas; rc-update add secfirstnas default 2>/dev/null || true"
    log "Init script deployed (RAID auto-assembly + auto-mount)"
else
    warn "Init script not found at ${INITD_SCRIPT} — skipping"
fi

# Deploy firewall rules
FW_RULES="${SCRIPT_DIR}/nas-firewall.nft"
if [ -f "${FW_RULES}" ]; then
    ssh "${USER}@${TARGET}" "mkdir -p /etc/nftables.d"
    scp -q "${FW_RULES}" "${USER}@${TARGET}:/etc/nftables.d/secfirstnas.nft"
    log "Firewall rules deployed (default DROP, ports 22/80/443/445/873)"
else
    warn "Firewall rules not found at ${FW_RULES} — skipping"
fi

# ─── Step 8: depmod + verify ─────────────────────────────────────────────────

log "Step 8/8: Running depmod and printing status..."

ssh "${USER}@${TARGET}" sh -s <<REMOTE_STATUS
set -e

# Run depmod for kernel module dependency resolution
depmod -a ${KVER} 2>/dev/null || depmod -a 2>/dev/null || echo "[warn] depmod not available"

# Restart secfirstnas service
rc-service secfirstnas start 2>/dev/null || echo "[warn] could not start secfirstnas service"

echo ""
echo "============================================"
echo "  secfirstNAS Deployment Summary"
echo "============================================"
echo ""

# Binary version
echo -n "  Binary:   "
${REMOTE_BIN} --version 2>/dev/null || echo "installed (version check unavailable)"

# Web UI
echo -n "  Web UI:   "
if [ -f ${REMOTE_WWW}/index.html ]; then
    echo "${REMOTE_WWW}/"
else
    echo "NOT FOUND"
fi

# Kernel modules
echo -n "  Modules:  "
ls ${REMOTE_KMOD_DIR}/*.ko 2>/dev/null | wc -l | tr -d ' '
echo -n " module(s) in ${REMOTE_KMOD_DIR}/"
echo ""

# Module auto-load
echo -n "  Autoload: "
if [ -f /lib/modules-load.d/secfirstnas.conf ]; then
    echo "/lib/modules-load.d/secfirstnas.conf"
else
    echo "NOT CONFIGURED"
fi

# Samba
echo -n "  Samba:    "
if [ -f /etc/samba/smb.conf ]; then
    echo "/etc/samba/smb.conf"
else
    echo "NOT CONFIGURED"
fi

# LEDs
echo -n "  LEDs:     "
led_count=0
for t in /sys/class/leds/white:*/trigger /sys/class/leds/ulogo/trigger; do
    [ -f "\$t" ] && led_count=\$((led_count + 1))
done
echo "\${led_count} LED(s) configured"

echo ""
echo "============================================"
REMOTE_STATUS

echo ""
log "${G}Deployment complete!${N}"
echo -e "  ssh ${USER}@${TARGET} secfirstnas status"
echo -e "  http://${TARGET}:8080/"
