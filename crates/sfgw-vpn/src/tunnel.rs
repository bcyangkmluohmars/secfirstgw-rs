// SPDX-License-Identifier: AGPL-3.0-or-later

//! WireGuard tunnel lifecycle management.
//!
//! Creates, starts, stops, and manages WireGuard tunnels.
//! Uses kernel WireGuard tools (`ip`, `wg`) via `tokio::process::Command`.
//! TODO: boringtun userspace fallback when kernel module is unavailable.

use anyhow::{bail, Context, Result};
use tokio::process::Command;
use tracing::{debug, info, warn};
use zeroize::Zeroize;

use crate::db::{self, TunnelRow};
use crate::{TunnelConfig, TunnelStatus, VpnTunnel, WgPeer, WgPeerStatus};

/// Create a new WireGuard tunnel, generate keys, and persist to DB.
///
/// Returns the created tunnel (with generated public key, private key redacted).
pub async fn create_tunnel(
    db: &sfgw_db::Db,
    name: &str,
    listen_port: u16,
    address: &str,
    dns: Option<&str>,
    mtu: Option<u16>,
) -> Result<VpnTunnel> {
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

    // Check for name collision
    if db::get_tunnel_by_name(db, name).await?.is_some() {
        bail!("tunnel '{}' already exists", name);
    }

    let keypair = crate::keys::generate_keypair()?;
    let public_key = keypair.public_key;

    let config = TunnelConfig {
        listen_port,
        private_key: keypair.private_key,
        public_key: public_key.clone(),
        address: address.to_string(),
        dns: dns.map(String::from),
        mtu: mtu.unwrap_or(1420),
        peers: Vec::new(),
    };

    let config_json = config.to_db_json()?;

    let id = db::insert_tunnel(db, name, "wireguard", &config_json).await?;

    info!(tunnel = name, "created WireGuard tunnel");

    Ok(VpnTunnel {
        id,
        name: name.to_string(),
        tunnel_type: crate::TunnelType::WireGuard,
        enabled: false,
        listen_port,
        public_key,
        address: address.to_string(),
        dns: dns.map(String::from),
        mtu: mtu.unwrap_or(1420),
        peers: Vec::new(),
    })
}

/// Start a WireGuard tunnel: create interface, set address, configure peers.
pub async fn start_tunnel(db: &sfgw_db::Db, name: &str) -> Result<()> {
    let row = db::get_tunnel_by_name(db, name)
        .await?
        .context("tunnel not found")?;

    let config = TunnelConfig::from_db_json(&row.config)?;

    // 1. Create WireGuard interface
    run_cmd("ip", &["link", "add", "dev", name, "type", "wireguard"])
        .await
        .context("failed to create WG interface — is the wireguard kernel module loaded?")?;

    // 2. Set private key via wg (pipe through stdin to avoid CLI exposure)
    //    Temporarily decrypt the SecureBox to get the base64 key.
    {
        let mut key_b64 = crate::keys::private_key_to_base64(&config.private_key)?;
        let result = set_private_key(name, &key_b64).await;
        key_b64.zeroize();
        result?;
    }

    // 3. Set listen port
    run_cmd(
        "wg",
        &[
            "set",
            name,
            "listen-port",
            &config.listen_port.to_string(),
        ],
    )
    .await
    .context("failed to set listen port")?;

    // 4. Add address
    run_cmd("ip", &["address", "add", &config.address, "dev", name])
        .await
        .context("failed to set address")?;

    // 5. Set MTU
    run_cmd(
        "ip",
        &["link", "set", "mtu", &config.mtu.to_string(), "dev", name],
    )
    .await
    .context("failed to set MTU")?;

    // 6. Configure peers
    for peer in &config.peers {
        apply_peer(name, peer).await?;
    }

    // 7. Bring interface up
    run_cmd("ip", &["link", "set", "up", "dev", name])
        .await
        .context("failed to bring interface up")?;

    // 8. Mark enabled in DB
    db::set_tunnel_enabled(db, row.id, true).await?;

    info!(tunnel = name, "WireGuard tunnel started");
    Ok(())
}

/// Stop a WireGuard tunnel: tear down the interface.
pub async fn stop_tunnel(db: &sfgw_db::Db, name: &str) -> Result<()> {
    let row = db::get_tunnel_by_name(db, name)
        .await?
        .context("tunnel not found")?;

    // Bring down and delete the interface (ignore errors if already gone)
    let _ = run_cmd("ip", &["link", "set", "down", "dev", name]).await;
    let _ = run_cmd("ip", &["link", "delete", "dev", name]).await;

    db::set_tunnel_enabled(db, row.id, false).await?;

    info!(tunnel = name, "WireGuard tunnel stopped");
    Ok(())
}

/// Delete a tunnel entirely (stops it first if running).
pub async fn delete_tunnel(db: &sfgw_db::Db, name: &str) -> Result<()> {
    // Best-effort stop
    let _ = stop_tunnel(db, name).await;

    let row = db::get_tunnel_by_name(db, name)
        .await?
        .context("tunnel not found")?;

    db::delete_tunnel(db, row.id).await?;
    info!(tunnel = name, "WireGuard tunnel deleted");
    Ok(())
}

/// Add a peer to an existing tunnel. Updates both DB config and live interface.
pub async fn add_peer(
    db: &sfgw_db::Db,
    tunnel_name: &str,
    peer: WgPeer,
) -> Result<()> {
    let row = db::get_tunnel_by_name(db, tunnel_name)
        .await?
        .context("tunnel not found")?;

    let mut config = TunnelConfig::from_db_json(&row.config)?;

    // Check for duplicate public key
    if config
        .peers
        .iter()
        .any(|p| p.public_key == peer.public_key)
    {
        bail!("peer with public key already exists in this tunnel");
    }

    // If interface is up, apply peer live
    if row.enabled != 0 {
        apply_peer(tunnel_name, &peer).await?;
    }

    config.peers.push(peer);

    let config_json = config.to_db_json()?;
    db::update_tunnel_config(db, row.id, &config_json).await?;

    info!(tunnel = tunnel_name, "peer added");
    Ok(())
}

/// Remove a peer by public key from a tunnel.
pub async fn remove_peer(
    db: &sfgw_db::Db,
    tunnel_name: &str,
    peer_public_key: &str,
) -> Result<()> {
    let row = db::get_tunnel_by_name(db, tunnel_name)
        .await?
        .context("tunnel not found")?;

    let mut config = TunnelConfig::from_db_json(&row.config)?;

    let before = config.peers.len();
    config.peers.retain(|p| p.public_key != peer_public_key);
    if config.peers.len() == before {
        bail!("peer not found in tunnel");
    }

    // If interface is up, remove peer live
    if row.enabled != 0 {
        let _ = run_cmd(
            "wg",
            &["set", tunnel_name, "peer", peer_public_key, "remove"],
        )
        .await;
    }

    let config_json = config.to_db_json()?;
    db::update_tunnel_config(db, row.id, &config_json).await?;

    info!(tunnel = tunnel_name, "peer removed");
    Ok(())
}

/// Query live status of a tunnel interface.
pub async fn get_status(name: &str) -> Result<TunnelStatus> {
    // Check if interface exists
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

    // Parse `wg show <name> dump` for peer stats
    let output = Command::new("wg")
        .args(["show", name, "dump"])
        .output()
        .await
        .context("failed to run wg show")?;

    if !output.status.success() {
        warn!(tunnel = name, "wg show failed — interface may not be WG");
        return Ok(TunnelStatus {
            name: name.to_string(),
            is_up: true,
            rx_bytes: 0,
            tx_bytes: 0,
            peers: Vec::new(),
        });
    }

    let dump = String::from_utf8_lossy(&output.stdout);
    let mut peers = Vec::new();
    let mut total_rx: u64 = 0;
    let mut total_tx: u64 = 0;

    // First line is the interface itself; subsequent lines are peers.
    // Format: public_key\tpreshared_key\tendpoint\tallowed_ips\tlatest_handshake\ttx\trx\tkeepalive
    for line in dump.lines().skip(1) {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() >= 7 {
            let rx: u64 = fields[6].parse().unwrap_or(0);
            let tx: u64 = fields[5].parse().unwrap_or(0);
            let last_handshake: u64 = fields[4].parse().unwrap_or(0);

            total_rx += rx;
            total_tx += tx;

            peers.push(WgPeerStatus {
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

    Ok(TunnelStatus {
        name: name.to_string(),
        is_up: true,
        rx_bytes: total_rx,
        tx_bytes: total_tx,
        peers,
    })
}

/// List all tunnels from DB with their live status.
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

/// Get a single tunnel by name.
pub async fn get_tunnel(db: &sfgw_db::Db, name: &str) -> Result<Option<VpnTunnel>> {
    let row = db::get_tunnel_by_name(db, name).await?;
    match row {
        Some(r) => Ok(Some(tunnel_from_row(r)?)),
        None => Ok(None),
    }
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
        dns: config.dns,
        mtu: config.mtu,
        peers: config.peers,
    })
}

/// Set the private key on a WG interface using stdin (avoids CLI exposure).
async fn set_private_key(iface: &str, private_key_b64: &str) -> Result<()> {
    // Write the key to a temp file with restrictive permissions, pass to wg
    // This avoids putting the key in process arguments visible in /proc.
    let tmp_dir = std::env::temp_dir();
    let key_path = tmp_dir.join(format!(".wg-key-{}-{}", iface, std::process::id()));

    // Write key with 0600 permissions
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

    // Always clean up key file
    let _ = tokio::fs::remove_file(&key_path).await;

    result.context("failed to set private key on interface")?;
    Ok(())
}

/// Apply a single peer configuration to a live WG interface.
async fn apply_peer(iface: &str, peer: &WgPeer) -> Result<()> {
    let mut args = vec![
        "set".to_string(),
        iface.to_string(),
        "peer".to_string(),
        peer.public_key.clone(),
    ];

    if peer.preshared_key.is_some() {
        // PSK will be piped through stdin below
        args.extend(["preshared-key".to_string(), "/dev/stdin".to_string()]);
    }

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
    if peer.preshared_key.is_some() {
        use tokio::io::AsyncWriteExt;
        let psk = peer.preshared_key.as_ref().unwrap();
        let mut child = Command::new("wg")
            .args(
                args.iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>(),
            )
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("failed to spawn wg set for peer")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(psk.as_bytes()).await?;
            // drop closes stdin
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

    debug!(iface = iface, peer = peer.public_key, "peer configured");
    Ok(())
}

/// Check whether a network interface is UP.
async fn check_interface_up(name: &str) -> bool {
    let output = Command::new("ip")
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

/// Run a command, returning Ok(()) on success or an error with stderr.
async fn run_cmd(prog: &str, args: &[&str]) -> Result<()> {
    debug!(cmd = prog, ?args, "executing");

    let output = Command::new(prog)
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
