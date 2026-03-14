#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# secfirstgw-rs — Clean Install Script for ARM Routers (UDM Pro, etc.)
#
# Usage (one-liner from SSH):
#   curl -fsSL https://raw.githubusercontent.com/bcyangkmluohmars/secfirstgw-rs/main/scripts/clean-and-install.sh | bash -
#
# What this script does:
#   1. Detects architecture (aarch64 / x86_64)
#   2. Downloads the latest secfirstgw release from GitHub
#   3. Verifies SHA256 checksum
#   4. Installs binary + web assets
#   5. Installs required system packages (dnsmasq, nftables, wireguard-tools)
#   6. Creates systemd service (or init script if no systemd)
#   7. Backs up existing UniFi config (if present)
#   8. Starts secfirstgw
#
# Requirements:
#   - Root access (SSH)
#   - Internet connectivity
#   - curl or wget
#
# The script is idempotent — safe to re-run for upgrades.

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────

REPO="bcyangkmluohmars/secfirstgw-rs"
INSTALL_DIR="/usr/local"
BIN_DIR="${INSTALL_DIR}/bin"
WEB_DIR="${INSTALL_DIR}/share/sfgw/web"
DATA_DIR="/data/sfgw"
DB_PATH="${DATA_DIR}/sfgw.db"
SERVICE_NAME="sfgw"
LISTEN_ADDR="[::]:443"

# Colors (if terminal supports them)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' NC=''
fi

# ─── Helpers ──────────────────────────────────────────────────────────────────

log()  { echo -e "${GREEN}[sfgw]${NC} $*"; }
warn() { echo -e "${YELLOW}[sfgw]${NC} $*" >&2; }
err()  { echo -e "${RED}[sfgw]${NC} $*" >&2; exit 1; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "This script must be run as root."
    fi
}

detect_arch() {
    local arch
    arch="$(uname -m)"
    case "${arch}" in
        aarch64|arm64) echo "aarch64" ;;
        x86_64|amd64)  echo "x86_64" ;;
        *)             err "Unsupported architecture: ${arch}" ;;
    esac
}

detect_platform() {
    if [ -e "/dev/ubnthal" ]; then
        echo "ubiquiti"
    elif [ -e "/.dockerenv" ]; then
        echo "docker"
    else
        echo "generic"
    fi
}

# Download helper — works with curl or wget
fetch() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "${dest}" "${url}"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "${dest}" "${url}"
    else
        err "Neither curl nor wget found. Install one and retry."
    fi
}

# Get latest release tag from GitHub API
get_latest_version() {
    local url="https://api.github.com/repos/${REPO}/releases/latest"
    local tmp
    tmp="$(mktemp)"
    fetch "${url}" "${tmp}"
    grep '"tag_name"' "${tmp}" | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
    rm -f "${tmp}"
}

# ─── Pre-flight Checks ───────────────────────────────────────────────────────

preflight() {
    require_root

    log "Detecting system..."
    ARCH="$(detect_arch)"
    PLATFORM="$(detect_platform)"
    log "  Architecture: ${CYAN}${ARCH}${NC}"
    log "  Platform:     ${CYAN}${PLATFORM}${NC}"
    log "  Kernel:       ${CYAN}$(uname -r)${NC}"

    # Safety: refuse to run from a cloned dev repo
    local script_dir
    script_dir="$(cd "$(dirname "$0")" && pwd)"
    if [ -f "${script_dir}/../.sfgw-dev" ] || [ -f "${script_dir}/../Cargo.toml" ]; then
        err "Refusing to run from a development checkout." \
            "\n  For development, use: docker compose up --build" \
            "\n  This script is meant for: curl ... | bash  (on target hardware)"
    fi

    # Safety: refuse to run in Docker
    if [ "${PLATFORM}" = "docker" ]; then
        err "Running inside Docker — use docker compose instead."
    fi

    # Safety: refuse to run on desktop/laptop/workstation systems
    if [ "${PLATFORM}" = "generic" ] && [ "${SFGW_FORCE:-}" != "1" ]; then
        if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ] || \
           [ -d "/usr/share/xsessions" ] || [ -d "/usr/share/wayland-sessions" ] || \
           command -v gdm >/dev/null 2>&1 || command -v sddm >/dev/null 2>&1 || \
           command -v lightdm >/dev/null 2>&1; then
            err "This looks like a desktop/workstation — refusing to install." \
                "\n  This script is for dedicated gateway hardware (UDM Pro, bare-metal routers, VMs)." \
                "\n  It will modify firewall rules, DNS, and system services." \
                "\n  For development, use: docker compose up --build" \
                "\n\n  To override (you know what you're doing): SFGW_FORCE=1 $0"
        fi
        log "Generic server detected — proceeding with install"
    fi

    if [ "${PLATFORM}" = "ubiquiti" ]; then
        log "  Ubiquiti hardware detected — will preserve kernel modules"
        # Check if UniFi is running
        if pgrep -f "unifi-os" >/dev/null 2>&1 || pgrep -f "java.*unifi" >/dev/null 2>&1; then
            warn "UniFi controller is running. It will be stopped."
            echo ""
            echo -e "  ${YELLOW}This will replace UniFi OS with secfirstgw.${NC}"
            echo -e "  ${YELLOW}A backup of the current config will be saved to /data/unifi-backup/.${NC}"
            echo ""
            read -rp "  Continue? [y/N] " confirm
            if [ "${confirm}" != "y" ] && [ "${confirm}" != "Y" ]; then
                log "Aborted."
                exit 0
            fi
        fi
    fi
}

# ─── Backup Existing Config ──────────────────────────────────────────────────

backup_existing() {
    if [ "${PLATFORM}" = "ubiquiti" ]; then
        local backup_dir="/data/unifi-backup/$(date +%Y%m%d-%H%M%S)"
        log "Backing up UniFi config to ${backup_dir}..."
        mkdir -p "${backup_dir}"

        # Save network config
        if [ -d "/data/unifi" ]; then
            cp -a /data/unifi "${backup_dir}/unifi" 2>/dev/null || true
        fi

        # Save current firewall rules
        iptables-save > "${backup_dir}/iptables-backup.conf" 2>/dev/null || true

        # Save interface config
        ip -j addr > "${backup_dir}/ip-addr.json" 2>/dev/null || true
        ip -j route > "${backup_dir}/ip-route.json" 2>/dev/null || true

        log "Backup complete: ${backup_dir}"
    fi

    # Back up existing sfgw data if upgrading
    if [ -f "${DB_PATH}" ]; then
        local db_backup="${DB_PATH}.bak.$(date +%Y%m%d-%H%M%S)"
        log "Backing up existing database to ${db_backup}..."
        cp "${DB_PATH}" "${db_backup}"
    fi
}

# ─── Install System Dependencies ─────────────────────────────────────────────

install_deps() {
    log "Checking system dependencies..."

    local missing=()
    command -v dnsmasq  >/dev/null 2>&1 || missing+=(dnsmasq)
    command -v iptables >/dev/null 2>&1 || missing+=(iptables)
    command -v wg       >/dev/null 2>&1 || missing+=(wireguard-tools)
    command -v ip       >/dev/null 2>&1 || missing+=(iproute2)

    if [ ${#missing[@]} -eq 0 ]; then
        log "All dependencies present."
        return 0
    fi

    log "Installing: ${missing[*]}"

    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y --no-install-recommends "${missing[@]}"
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache "${missing[@]}"
    elif command -v opkg >/dev/null 2>&1; then
        opkg update
        opkg install "${missing[@]}"
    else
        warn "Could not detect package manager. Please install manually: ${missing[*]}"
    fi
}

# ─── Download + Install Binary ────────────────────────────────────────────────

install_binary() {
    log "Fetching latest release..."
    local version
    version="$(get_latest_version)"
    if [ -z "${version}" ]; then
        err "Could not determine latest version from GitHub."
    fi
    log "Latest version: ${CYAN}${version}${NC}"

    local tarball="secfirstgw-${version#v}-${ARCH}-linux.tar.gz"
    local url="https://github.com/${REPO}/releases/download/${version}/${tarball}"
    local checksum_url="https://github.com/${REPO}/releases/download/${version}/SHA256SUMS"

    local tmp_dir
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "${tmp_dir}"' EXIT

    log "Downloading ${tarball}..."
    fetch "${url}" "${tmp_dir}/${tarball}"
    fetch "${checksum_url}" "${tmp_dir}/SHA256SUMS"

    # Verify checksum
    log "Verifying SHA256 checksum..."
    (cd "${tmp_dir}" && grep "${tarball}" SHA256SUMS | sha256sum -c -) || \
        err "Checksum verification failed! Aborting."

    # Extract
    log "Installing..."
    tar -xzf "${tmp_dir}/${tarball}" -C "${tmp_dir}"

    # Install binary
    install -m 0755 "${tmp_dir}/sfgw" "${BIN_DIR}/sfgw"

    # Install web assets
    mkdir -p "${WEB_DIR}"
    if [ -d "${tmp_dir}/dist" ]; then
        rm -rf "${WEB_DIR:?}/"*
        cp -a "${tmp_dir}/dist/"* "${WEB_DIR}/"
    fi

    # Create data directory
    mkdir -p "${DATA_DIR}"
    chmod 0700 "${DATA_DIR}"

    log "Installed ${CYAN}sfgw${NC} ${version} to ${BIN_DIR}/sfgw"
}

# ─── Stop Competing Services ─────────────────────────────────────────────────

stop_existing() {
    if [ "${PLATFORM}" = "ubiquiti" ]; then
        log "Stopping UniFi services..."

        # Stop UniFi OS services — we're taking over
        systemctl stop unifi-core 2>/dev/null || true
        systemctl disable unifi-core 2>/dev/null || true
        systemctl stop unifi 2>/dev/null || true
        systemctl disable unifi 2>/dev/null || true

        # Stop ubios-udapi-server — this is the process supervisor that
        # respawns dnsmasq and other platform services on UDM/USG.
        # Must be stopped BEFORE killing dnsmasq, otherwise it restarts them.
        # WARNING: This temporarily breaks network connectivity until sfgw
        # takes over. Only acceptable during full install (not dev-deploy).
        if pgrep -f "ubios-udapi-server" >/dev/null 2>&1; then
            log "Stopping ubios-udapi-server (service supervisor)..."
            warn "Network connectivity will be temporarily interrupted."
            killall ubios-udapi-server 2>/dev/null || true
            sleep 1
        fi

        # Stop dnsmasq — try init script first (clean shutdown), then killall
        if [ -x /etc/init.d/dnsmasq ]; then
            /etc/init.d/dnsmasq stop 2>/dev/null || true
        fi
        systemctl stop dnsmasq 2>/dev/null || true
        systemctl disable dnsmasq 2>/dev/null || true
        killall -q dnsmasq 2>/dev/null || true
        sleep 1

        # Verify no dnsmasq left
        if pgrep dnsmasq >/dev/null 2>&1; then
            warn "dnsmasq still running — sending SIGKILL..."
            killall -q -KILL dnsmasq 2>/dev/null || true
            sleep 1
        fi

        log "All platform services stopped."
    else
        # Generic: stop system dnsmasq if present
        if [ -x /etc/init.d/dnsmasq ]; then
            /etc/init.d/dnsmasq stop 2>/dev/null || true
        fi
        systemctl stop dnsmasq 2>/dev/null || true
        systemctl disable dnsmasq 2>/dev/null || true
    fi

    # Stop existing sfgw if upgrading
    if systemctl is-active "${SERVICE_NAME}" >/dev/null 2>&1; then
        log "Stopping existing sfgw..."
        systemctl stop "${SERVICE_NAME}"
    fi
}

# ─── Install Service ─────────────────────────────────────────────────────────

install_service() {
    if command -v systemctl >/dev/null 2>&1; then
        install_systemd_service
    else
        install_init_script
    fi
}

install_systemd_service() {
    log "Installing systemd service..."

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<'UNIT'
[Unit]
Description=secfirstgw — Security First Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sfgw
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=no
ProtectSystem=strict
ReadWritePaths=/data/sfgw /tmp /run
PrivateTmp=yes

# Network capabilities (required for firewall, routing, VPN)
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_MODULE

# Environment
Environment=SFGW_DB_PATH=/data/sfgw/sfgw.db
Environment=SFGW_LISTEN_ADDR=[::]:443
Environment=SFGW_WEB_DIR=/usr/local/share/sfgw/web
Environment=RUST_LOG=sfgw=info

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"
    log "Systemd service installed and enabled."
}

install_init_script() {
    log "No systemd found — installing init script..."

    cat > "/etc/init.d/${SERVICE_NAME}" <<'INIT'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          sfgw
# Required-Start:    $network
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       secfirstgw — Security First Gateway
### END INIT INFO

DAEMON=/usr/local/bin/sfgw
PIDFILE=/var/run/sfgw.pid
export SFGW_DB_PATH=/data/sfgw/sfgw.db
export SFGW_LISTEN_ADDR=[::]:443
export SFGW_WEB_DIR=/usr/local/share/sfgw/web
export RUST_LOG=sfgw=info

case "$1" in
    start)
        echo "Starting sfgw..."
        start-stop-daemon -S -b -m -p "$PIDFILE" -x "$DAEMON"
        ;;
    stop)
        echo "Stopping sfgw..."
        start-stop-daemon -K -p "$PIDFILE" 2>/dev/null
        rm -f "$PIDFILE"
        ;;
    restart)
        $0 stop; $0 start
        ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        exit 1
        ;;
esac
INIT

    chmod +x "/etc/init.d/${SERVICE_NAME}"
    log "Init script installed."
}

# ─── Enable IP Forwarding ────────────────────────────────────────────────────

enable_forwarding() {
    log "Enabling IP forwarding..."

    # Persistent
    cat > /etc/sysctl.d/99-sfgw.conf <<SYSCTL
# secfirstgw — IP forwarding (gateway mode)
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
SYSCTL

    # Apply now
    sysctl -p /etc/sysctl.d/99-sfgw.conf >/dev/null 2>&1 || true
}

# ─── Start ────────────────────────────────────────────────────────────────────

start_service() {
    log "Starting secfirstgw..."

    if command -v systemctl >/dev/null 2>&1; then
        systemctl start "${SERVICE_NAME}"
    else
        /etc/init.d/${SERVICE_NAME} start
    fi

    # Wait for it to come up
    sleep 2

    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active "${SERVICE_NAME}" >/dev/null 2>&1; then
            log "${GREEN}secfirstgw is running!${NC}"
        else
            warn "Service may not have started correctly. Check: journalctl -u sfgw"
        fi
    fi
}

# ─── Post-start SSH connectivity check ────────────────────────────────

verify_ssh_alive() {
    log "Verifying SSH is still reachable after firewall apply..."

    # Give sfgw a moment to apply firewall rules.
    sleep 3

    # Try a TCP connect to our own SSH port.
    # If the firewall locked us out, this will fail.
    local ok=0
    for attempt in 1 2 3; do
        if (echo > /dev/tcp/127.0.0.1/22) 2>/dev/null; then
            ok=1
            break
        fi
        sleep 1
    done

    if [ "${ok}" -eq 1 ]; then
        log "SSH connectivity check passed."
    else
        err "SSH connectivity check FAILED — firewall may have locked out SSH!" \
            "\n  Emergency rollback: stopping sfgw and restoring previous iptables." \
            "\n  Run 'iptables-restore < /data/unifi-backup/*/iptables-backup.conf' to restore."

        # Stop sfgw so its firewall rules are no longer active.
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
        else
            /etc/init.d/${SERVICE_NAME} stop 2>/dev/null || true
        fi

        # Flush SFGW chains to restore connectivity (IPv4 + IPv6).
        for ipt in iptables ip6tables; do
            for chain in SFGW-INPUT SFGW-FORWARD SFGW-OUTPUT; do
                builtin_chain="${chain#SFGW-}"
                ${ipt} -D "${builtin_chain}" -j "${chain}" 2>/dev/null || true
                ${ipt} -F "${chain}" 2>/dev/null || true
                ${ipt} -X "${chain}" 2>/dev/null || true
            done
        done
        for chain in SFGW-PREROUTING SFGW-POSTROUTING; do
            builtin_chain="${chain#SFGW-}"
            iptables -t nat -D "${builtin_chain}" -j "${chain}" 2>/dev/null || true
            iptables -t nat -F "${chain}" 2>/dev/null || true
            iptables -t nat -X "${chain}" 2>/dev/null || true
        done

        warn "SFGW chains flushed. SSH should be restored."
        exit 1
    fi
}

# ─── Summary ─────────────────────────────────────────────────────────────────

print_summary() {
    local ip
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || echo '<this-device-ip>')"

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  secfirstgw installed successfully!                      ${GREEN}║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC}                                                          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Web UI:    ${CYAN}https://${ip}${NC}                    ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Binary:    /usr/local/bin/sfgw                           ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Data:      /data/sfgw/                                   ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Logs:      journalctl -u sfgw -f                         ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Open the Web UI to complete initial setup.               ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                          ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    echo ""
    echo -e "${CYAN}  ┌──────────────────────────────────────┐${NC}"
    echo -e "${CYAN}  │  secfirstgw — Security First Gateway │${NC}"
    echo -e "${CYAN}  │  Clean Install                       │${NC}"
    echo -e "${CYAN}  └──────────────────────────────────────┘${NC}"
    echo ""

    preflight
    backup_existing
    stop_existing
    install_deps
    install_binary
    enable_forwarding
    install_service
    start_service
    verify_ssh_alive
    print_summary
}

main "$@"
