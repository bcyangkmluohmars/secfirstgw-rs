# Quickstart Guide

Get secfirstgw-rs running on your gateway hardware in under 10 minutes.

## Prerequisites

- A supported device (see [HARDWARE.md](../HARDWARE.md)) or a Linux VM/server
- Root SSH access to the device
- Internet connectivity (for download)

## Option 1: Install from Release (Recommended)

### One-Liner Install

SSH into your gateway device and run:

```bash
curl -fsSL https://raw.githubusercontent.com/bcyangkmluohmars/secfirstgw-rs/main/scripts/clean-and-install.sh | bash -
```

The script is idempotent — safe to re-run for upgrades.

### What the Install Script Does

1. **Detects** your architecture (aarch64 / x86_64) and platform (Ubiquiti / generic)
2. **Safety checks** — refuses to run on desktops, Docker containers, or dev checkouts
3. **Backs up** existing UniFi config to `/data/unifi-backup/` (if present)
4. **Downloads** the latest release from GitHub
5. **Verifies** SHA-256 checksum
6. **Installs** binary to `/usr/local/bin/sfgw` and web UI to `/usr/local/share/sfgw/web/`
7. **Installs** system dependencies (dnsmasq, iptables, wireguard-tools, iproute2)
8. **Masks** all conflicting UniFi services (persistent across reboot)
9. **Enables** IP forwarding (IPv4 + IPv6)
10. **Configures** hardware fan control (on Ubiquiti devices)
11. **Creates** systemd service (or init script if no systemd)
12. **Starts** secfirstgw
13. **Verifies** SSH connectivity after firewall rules are applied — auto-rollback if SSH is locked out

### After Installation

1. Connect a device to the **MGMT port** (Port 8 / eth7 on UDM Pro)
2. The MGMT network defaults to `10.0.0.0/24` — your device will get a DHCP address
3. Open `https://10.0.0.1` in your browser
4. Accept the self-signed certificate (a proper TLS cert is generated on first boot)
5. Create your admin account
6. You're in.

### Default Network Layout (UDM Pro)

After installation, the following networks are active:

| Port(s) | Zone | Subnet | Purpose |
|---------|------|--------|---------|
| 1-7 (eth0-eth6) | LAN | 192.168.1.0/24 | Trusted clients |
| 8 (eth7) | MGMT | 10.0.0.0/24 | Admin management |
| 9 (eth8) | WAN1 | DHCP | Internet (RJ45) |
| 10 (eth9) | WAN2 | DHCP | Internet (SFP+) |
| 11 (eth10) | LAN | 192.168.1.0/24 | LAN (SFP+) |

**MGMT is the only zone with access to the Web UI, SSH, and device adoption.** LAN, DMZ, and Guest users cannot access the gateway admin interface.

## Option 2: Build from Source

### Requirements

- Rust stable toolchain (edition 2024)
- Node.js 18+ and npm (for the web UI)
- For cross-compilation: `aarch64-unknown-linux-musl` or `x86_64-unknown-linux-musl` target

### Clone and Build

```bash
git clone https://github.com/bcyangkmluohmars/secfirstgw-rs.git
cd secfirstgw-rs

# Install musl cross-compilation target (for ARM64)
rustup target add aarch64-unknown-linux-musl

# Build everything (debug, native arch)
make build

# Run tests
make test

# Lint
make clippy

# Build release for ARM64 (includes web UI)
make aarch64

# Build release for x86_64
make x86_64

# Build distribution tarballs for both
make dist
```

### Deploy to Device

For development iteration on a UDM Pro on the MGMT network:

```bash
scripts/dev-deploy.sh 10.0.0.1
```

This script:
- Cross-compiles for aarch64
- Rsyncs the binary to the device
- Builds on-device (if needed)
- Restarts the service with SSH lockout protection

For production deployment, use the clean-and-install script or the distribution tarball from `make dist`.

## Option 3: Docker

```bash
git clone https://github.com/bcyangkmluohmars/secfirstgw-rs.git
cd secfirstgw-rs
docker compose up --build
```

Docker mode uses macvlan or host networking. Some features (switch ASIC programming, hardware display, LUKS2) are not available in Docker.

## First Steps After Setup

### 1. Verify Firewall Rules

Check that the zone-based firewall is active:

```bash
sfgw firewall status
```

All zones should show catch-all DROP rules at the end of each chain.

### 2. Connect Devices to the Right Zones

- **Workstations, phones, trusted devices** → LAN ports (1-7)
- **Admin laptop** → MGMT port (8) — this is the only port with Web UI access
- **Internet uplink** → WAN port (9 for RJ45, 10 for SFP+)
- **Public-facing servers** → Create and assign a DMZ VLAN
- **Guest WiFi, untrusted devices** → Create and assign a Guest VLAN

### 3. Adopt Network Devices

If you have Ubiquiti switches or access points:

1. Ensure the device is on the MGMT VLAN (or factory-default, broadcasting Inform)
2. Open the Web UI → Devices
3. The device will appear as "Pending"
4. Click "Adopt"
5. secfirstgw will verify the device via SSH, exchange keys, and harden its configuration
6. Adoption takes about 36 seconds (tested on USW-Flex and UAP-AC-Pro)

### 4. Set Up DNS/DHCP

DNS and DHCP are pre-configured for all zones. Customize via Web UI → Settings → DNS/DHCP:

- Static leases
- DNS overrides
- Upstream DNS servers (default: WAN gateway + 1.1.1.1 + 9.9.9.9)

### 5. Configure VPN (Optional)

WireGuard VPN can be configured via Web UI → VPN:

- Create peers with config generation + QR code
- Multi-core — uses all available CPU cores

### 6. Set Your Personality

Web UI → Settings → Personality. Pick your style. The default is "kevin" — adjust accordingly.

## File Locations

| Path | Purpose |
|------|---------|
| `/usr/local/bin/sfgw` | Binary |
| `/usr/local/share/sfgw/web/` | Web UI assets |
| `/data/sfgw/sfgw.db` | Database (SQLCipher encrypted) |
| `/data/sfgw/sfgw.log` | Log file |
| `/data/unifi-backup/` | Pre-install UniFi config backup |

## Service Management

```bash
# Status
systemctl status sfgw

# Logs (live)
journalctl -u sfgw -f

# Restart
systemctl restart sfgw

# Stop
systemctl stop sfgw
```

## Troubleshooting

### Web UI Not Accessible

1. Ensure you're connected to the **MGMT** port/VLAN (not LAN)
2. The Web UI is only accessible from MGMT — this is by design
3. Check that the service is running: `systemctl status sfgw`

### SSH Locked Out After Install

The install script has automatic rollback if SSH is locked out. If you somehow still lose access:

1. Connect via serial console (UART)
2. Stop the service: `systemctl stop sfgw`
3. Flush firewall rules: `iptables -F && ip6tables -F`
4. SSH should be restored

### Device Not Appearing for Adoption

1. The device must be on the MGMT VLAN or reachable on port 8080
2. Ensure the device is factory-default (or set its Inform URL to `http://10.0.0.1:8080/inform`)
3. Check the IDS events — if the device fails passive validation, it will be logged as a Phantom device

### Reverting to UniFi

```bash
systemctl stop sfgw
systemctl disable sfgw

# Unmask UniFi services
for svc in udapi-server unifi-core unifi; do
    systemctl unmask "$svc"
done

# Restore backup
cp -a /data/unifi-backup/latest/unifi /data/unifi

systemctl start udapi-server
```

## Next Steps

- [Architecture deep dive](ARCHITECTURE.md) — zone model, threat model, crypto design
- [Security policy](SECURITY.md) — responsible disclosure
- [Contributing](../CONTRIBUTING.md) — how to contribute
- [Roadmap](../ROADMAP.md) — what's coming next
