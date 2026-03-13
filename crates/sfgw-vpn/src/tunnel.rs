// SPDX-License-Identifier: AGPL-3.0-or-later

//! WireGuard tunnel lifecycle management.
//!
//! Creates, starts, stops, and manages WireGuard tunnels.
//! Uses boringtun for userspace WireGuard implementation.
//! Falls back to kernel WireGuard tools if available.

use anyhow::{bail, Context, Result};
use tracing::{info, warn};

use crate::db::{self, TunnelRow};
use crate::{
    CreateTunnelRequest, TunnelConfig, TunnelStatus, VpnTunnel,
};

/// Create a new WireGuard tunnel, generate keys, and persist to DB.
///
/// Returns the created tunnel (with generated public key, private key redacted).
pub async fn create_tunnel(
    db: &sfgw_db::Db,
    request: &CreateTunnelRequest,
) -> Result<VpnTunnel> {
    let name = &request.name;

    // Validate interface name (kernel limit: 15 chars, alphanumeric + limited special)
    if name.len() > 15 || name.is_empty() {
        bail!("interface name must be 1-15 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("interface name must be alphanumeric, dash, or underscore");
    }

    // Validate addresses
    validate_tunnel_address(&request.address)?;
    if let Some(ref v6) = request.address_v6 {
        validate_tunnel_address(v6)?;
    }

    // Check for name collision
    if db::get_tunnel_by_name(db, name).await?.is_some() {
        bail!("tunnel '{}' already exists", name);
    }

    let keypair = crate::keys::generate_keypair()?;
    let public_key = keypair.public_key;

    let config = TunnelConfig {
        listen_port: request.listen_port,
        private_key: keypair.private_key,
        public_key: public_key.clone(),
        address: request.address.clone(),
        address_v6: request.address_v6.clone(),
        dns: request.dns.clone(),
        mtu: request.mtu.unwrap_or(1420),
        zone: request.zone.clone(),
    };

    let config_json = config.to_db_json()?;
    let id = db::insert_tunnel(db, name, "wireguard", &config_json).await?;

    info!(tunnel = name, "created WireGuard tunnel");

    Ok(VpnTunnel {
        id,
        name: name.to_string(),
        tunnel_type: crate::TunnelType::WireGuard,
        enabled: false,
        listen_port: request.listen_port,
        public_key,
        address: request.address.clone(),
        address_v6: request.address_v6.clone(),
        dns: request.dns.clone(),
        mtu: request.mtu.unwrap_or(1420),
        zone: request.zone.clone(),
    })
}

/// Start a WireGuard tunnel using boringtun userspace or kernel WireGuard.
///
/// Creates a TUN interface, configures addresses, and starts the packet loop.
pub async fn start_tunnel(db: &sfgw_db::Db, tunnel_id: i64) -> Result<()> {
    let row = db::get_tunnel_by_id(db, tunnel_id)
        .await?
        .context("tunnel not found")?;

    if row.enabled != 0 {
        bail!("tunnel '{}' is already running", row.name);
    }

    let config = TunnelConfig::from_db_json(&row.config)?;

    // Load peers from the database
    let peer_rows = db::list_peers(db, tunnel_id).await?;
    let wg_peers: Vec<_> = peer_rows
        .iter()
        .filter(|p| p.enabled)
        .map(crate::peer::peer_row_to_wg_peer)
        .collect();

    // Try kernel WireGuard first, fall back to boringtun userspace
    match start_kernel_wg(&row.name, &config, &wg_peers).await {
        Ok(()) => {
            info!(tunnel = row.name, "started WireGuard tunnel (kernel)");
        }
        Err(kernel_err) => {
            warn!(
                tunnel = row.name,
                "kernel WireGuard unavailable ({kernel_err}), using boringtun userspace"
            );
            start_userspace_wg(&row.name, &config, &wg_peers).await?;
            info!(tunnel = row.name, "started WireGuard tunnel (boringtun userspace)");
        }
    }

    db::set_tunnel_enabled(db, row.id, true).await?;
    Ok(())
}

/// Stop a WireGuard tunnel.
pub async fn stop_tunnel(db: &sfgw_db::Db, tunnel_id: i64) -> Result<()> {
    let row = db::get_tunnel_by_id(db, tunnel_id)
        .await?
        .context("tunnel not found")?;

    // Bring down and delete the interface (warn if commands fail unexpectedly)
    if let Err(e) = run_cmd("ip", &["link", "set", "down", "dev", &row.name]).await {
        warn!(tunnel = row.name.as_str(), "failed to bring interface down: {e}");
    }
    if let Err(e) = run_cmd("ip", &["link", "delete", "dev", &row.name]).await {
        warn!(tunnel = row.name.as_str(), "failed to delete interface: {e}");
    }

    db::set_tunnel_enabled(db, row.id, false).await?;

    info!(tunnel = row.name, "WireGuard tunnel stopped");
    Ok(())
}

/// Delete a tunnel entirely (stops it first if running).
pub async fn delete_tunnel(db: &sfgw_db::Db, tunnel_id: i64) -> Result<()> {
    let row = db::get_tunnel_by_id(db, tunnel_id)
        .await?
        .context("tunnel not found")?;

    // Best-effort stop
    if row.enabled != 0 {
        if let Err(e) = stop_tunnel(db, tunnel_id).await {
            warn!(tunnel = row.name.as_str(), "failed to stop tunnel during delete: {e}");
        }
    }

    // Peers are cascade-deleted by FK constraint
    db::delete_tunnel(db, row.id).await?;
    info!(tunnel = row.name, "WireGuard tunnel deleted");
    Ok(())
}

/// Query live status of a tunnel interface.
pub async fn get_status(name: &str) -> Result<TunnelStatus> {
    let is_up = check_interface_up(name).await;

    if !is_up {
        return Ok(TunnelStatus {
            name: name.to_string(),
            is_up: false,
            rx_bytes: 0,
            tx_bytes: 0,
            peers: Vec::new(),
        });
    }

    // Try `wg show` for kernel WireGuard stats
    let output = tokio::process::Command::new("wg")
        .args(["show", name, "dump"])
        .output()
        .await;

    let (mut total_rx, mut total_tx) = (0u64, 0u64);
    let mut peers = Vec::new();

    if let Ok(output) = output {
        if output.status.success() {
            let dump = String::from_utf8_lossy(&output.stdout);
            for line in dump.lines().skip(1) {
                let fields: Vec<&str> = line.split('\t').collect();
                if fields.len() >= 7 {
                    let rx: u64 = fields[6].parse().unwrap_or(0);
                    let tx: u64 = fields[5].parse().unwrap_or(0);
                    let last_handshake: u64 = fields[4].parse().unwrap_or(0);

                    total_rx += rx;
                    total_tx += tx;

                    peers.push(crate::PeerStatus {
                        public_key: fields[0].to_string(),
                        endpoint: if fields[2] == "(none)" {
                            None
                        } else {
                            Some(fields[2].to_string())
                        },
                        last_handshake_secs: last_handshake,
                        rx_bytes: rx,
                        tx_bytes: tx,
                    });
                }
            }
        }
    }

    // If no wg stats, try reading from /sys for TUN interface
    if peers.is_empty() {
        total_rx = read_sys_bytes(name, "rx_bytes");
        total_tx = read_sys_bytes(name, "tx_bytes");
    }

    Ok(TunnelStatus {
        name: name.to_string(),
        is_up: true,
        rx_bytes: total_rx,
        tx_bytes: total_tx,
        peers,
    })
}

/// List all tunnels from DB.
pub async fn list_tunnels(db: &sfgw_db::Db) -> Result<Vec<VpnTunnel>> {
    let rows = db::list_tunnels(db).await?;
    let mut tunnels = Vec::with_capacity(rows.len());

    for row in rows {
        match tunnel_from_row(row) {
            Ok(t) => tunnels.push(t),
            Err(e) => warn!("skipping corrupt tunnel row: {e}"),
        }
    }

    Ok(tunnels)
}

/// Get a single tunnel by ID.
pub async fn get_tunnel_by_id(db: &sfgw_db::Db, id: i64) -> Result<Option<VpnTunnel>> {
    let row = db::get_tunnel_by_id(db, id).await?;
    match row {
        Some(r) => Ok(Some(tunnel_from_row(r)?)),
        None => Ok(None),
    }
}

/// Get a single tunnel by name.
pub async fn get_tunnel(db: &sfgw_db::Db, name: &str) -> Result<Option<VpnTunnel>> {
    let row = db::get_tunnel_by_name(db, name).await?;
    match row {
        Some(r) => Ok(Some(tunnel_from_row(r)?)),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Kernel WireGuard (primary path if kernel module is loaded)
// ---------------------------------------------------------------------------

async fn start_kernel_wg(
    name: &str,
    config: &TunnelConfig,
    peers: &[crate::WgPeer],
) -> Result<()> {
    // Create WireGuard interface
    run_cmd("ip", &["link", "add", "dev", name, "type", "wireguard"])
        .await
        .context("kernel WireGuard module not available")?;

    // Set private key via temp file (avoids CLI exposure)
    {
        let mut key_b64 = crate::keys::private_key_to_base64(&config.private_key)?;
        let result = set_private_key(name, &key_b64).await;
        use zeroize::Zeroize;
        key_b64.zeroize();
        result?;
    }

    // Set listen port
    run_cmd(
        "wg",
        &["set", name, "listen-port", &config.listen_port.to_string()],
    )
    .await
    .context("failed to set listen port")?;

    // Add IPv4 address
    run_cmd("ip", &["address", "add", &config.address, "dev", name])
        .await
        .context("failed to set IPv4 address")?;

    // Add IPv6 address (dual-stack)
    if let Some(ref v6) = config.address_v6 {
        run_cmd("ip", &["-6", "address", "add", v6, "dev", name])
            .await
            .context("failed to set IPv6 address")?;
    }

    // Set MTU
    run_cmd(
        "ip",
        &["link", "set", "mtu", &config.mtu.to_string(), "dev", name],
    )
    .await
    .context("failed to set MTU")?;

    // Configure peers
    for peer in peers {
        apply_peer_to_kernel(name, peer).await?;
    }

    // Bring interface up
    run_cmd("ip", &["link", "set", "up", "dev", name])
        .await
        .context("failed to bring interface up")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Boringtun userspace WireGuard (fallback)
// ---------------------------------------------------------------------------

async fn start_userspace_wg(
    name: &str,
    config: &TunnelConfig,
    peers: &[crate::WgPeer],
) -> Result<()> {
    // Create TUN interface
    let tun_fd = crate::userspace::create_tun_device(name)?;

    // Set addresses using ip command (TUN interfaces support this)
    run_cmd("ip", &["address", "add", &config.address, "dev", name])
        .await
        .context("failed to set IPv4 address on TUN")?;

    if let Some(ref v6) = config.address_v6 {
        run_cmd("ip", &["-6", "address", "add", v6, "dev", name])
            .await
            .context("failed to set IPv6 address on TUN")?;
    }

    run_cmd(
        "ip",
        &["link", "set", "mtu", &config.mtu.to_string(), "dev", name],
    )
    .await
    .context("failed to set MTU on TUN")?;

    run_cmd("ip", &["link", "set", "up", "dev", name])
        .await
        .context("failed to bring TUN interface up")?;

    // Start the boringtun packet loop as a background task
    let private_key = config.private_key.open()?;
    let listen_port = config.listen_port;

    let peer_configs: Vec<_> = peers
        .iter()
        .map(|p| crate::userspace::PeerConfig {
            public_key: p.public_key.clone(),
            preshared_key: p.preshared_key.clone(),
            endpoint: p.endpoint.clone(),
            persistent_keepalive: p.persistent_keepalive,
            allowed_ips: p.allowed_ips.clone(),
        })
        .collect();

    crate::userspace::spawn_tunnel_task(
        name.to_string(),
        tun_fd,
        private_key,
        listen_port,
        peer_configs,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn tunnel_from_row(row: TunnelRow) -> Result<VpnTunnel> {
    let config = TunnelConfig::from_db_json(&row.config)?;

    Ok(VpnTunnel {
        id: row.id,
        name: row.name,
        tunnel_type: crate::TunnelType::WireGuard,
        enabled: row.enabled != 0,
        listen_port: config.listen_port,
        public_key: config.public_key,
        address: config.address,
        address_v6: config.address_v6,
        dns: config.dns,
        mtu: config.mtu,
        zone: config.zone,
    })
}

/// Validate a tunnel address (e.g., "10.0.0.1/24" or "fd00::1/64").
/// Accepts addresses with host bits set (standard for WireGuard interface addresses).
fn validate_tunnel_address(addr: &str) -> Result<()> {
    match addr.split_once('/') {
        Some((ip, prefix)) => {
            ip.parse::<std::net::IpAddr>()
                .map_err(|_| anyhow::anyhow!("invalid tunnel address/CIDR: {addr}"))?;
            prefix
                .parse::<u8>()
                .map_err(|_| anyhow::anyhow!("invalid prefix length in: {addr}"))?;
        }
        None => {
            addr.parse::<std::net::IpAddr>()
                .map_err(|_| anyhow::anyhow!("invalid tunnel address: {addr}"))?;
        }
    }
    Ok(())
}

/// Set the private key on a WG interface using a temp file.
async fn set_private_key(iface: &str, private_key_b64: &str) -> Result<()> {
    let tmp_dir = std::env::temp_dir();
    let key_path = tmp_dir.join(format!(".wg-key-{}-{}", iface, std::process::id()));

    tokio::fs::write(&key_path, private_key_b64.as_bytes())
        .await
        .context("failed to write temp key file")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(&key_path, perms).await?;
    }

    let result = run_cmd(
        "wg",
        &[
            "set",
            iface,
            "private-key",
            &key_path.to_string_lossy(),
        ],
    )
    .await;

    let _ = tokio::fs::remove_file(&key_path).await;
    result.context("failed to set private key on interface")?;
    Ok(())
}

/// Apply a single peer configuration to a live kernel WG interface.
async fn apply_peer_to_kernel(iface: &str, peer: &crate::WgPeer) -> Result<()> {
    let mut args = vec![
        "set".to_string(),
        iface.to_string(),
        "peer".to_string(),
        peer.public_key.clone(),
    ];

    if !peer.allowed_ips.is_empty() {
        args.push("allowed-ips".to_string());
        args.push(peer.allowed_ips.join(","));
    }

    if let Some(ref ep) = peer.endpoint {
        args.push("endpoint".to_string());
        args.push(ep.clone());
    }

    if let Some(ka) = peer.persistent_keepalive {
        args.push("persistent-keepalive".to_string());
        args.push(ka.to_string());
    }

    // For PSK, pipe through stdin
    if let Some(ref psk) = peer.preshared_key {
        use tokio::io::AsyncWriteExt;
        args.insert(4, "preshared-key".to_string());
        args.insert(5, "/dev/stdin".to_string());

        let mut child = tokio::process::Command::new("wg")
            .args(args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("failed to spawn wg set for peer")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(psk.as_bytes()).await?;
        }

        let out = child.wait_with_output().await?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!("wg set peer failed: {stderr}");
        }
    } else {
        let str_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        run_cmd("wg", &str_args).await.context("failed to configure peer")?;
    }

    tracing::debug!(iface, peer = peer.public_key, "peer configured");
    Ok(())
}

/// Check whether a network interface is UP.
async fn check_interface_up(name: &str) -> bool {
    let output = tokio::process::Command::new("ip")
        .args(["link", "show", name])
        .output()
        .await;

    match output {
        Ok(o) if o.status.success() => {
            let out = String::from_utf8_lossy(&o.stdout);
            out.contains("UP") || out.contains("state UP")
        }
        _ => false,
    }
}

/// Read bytes counter from /sys/class/net for a TUN interface.
fn read_sys_bytes(iface: &str, counter: &str) -> u64 {
    let path = format!("/sys/class/net/{iface}/statistics/{counter}");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Run a command, returning Ok(()) on success or an error with stderr.
async fn run_cmd(prog: &str, args: &[&str]) -> Result<()> {
    tracing::debug!(cmd = prog, ?args, "executing");

    let output = tokio::process::Command::new(prog)
        .args(args)
        .output()
        .await
        .with_context(|| format!("failed to execute {prog}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{prog} failed (exit {}): {stderr}", output.status);
    }

    Ok(())
}
