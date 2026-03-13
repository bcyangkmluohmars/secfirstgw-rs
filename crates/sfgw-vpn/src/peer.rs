// SPDX-License-Identifier: AGPL-3.0-or-later

//! Peer management — add, remove, list peers with server-generated keypairs.
//!
//! Each peer gets a unique X25519 keypair generated server-side.
//! The private key is stored encrypted in the DB and is only revealed
//! when generating a downloadable client config.

use anyhow::{bail, Context, Result};
use tracing::info;
use zeroize::Zeroize;

use crate::db::{self, PeerRow};
use crate::{
    CreatePeerRequest, RoutingMode, TunnelConfig, VpnPeer, WgPeer,
};

/// Add a new peer to a tunnel. Generates a unique keypair and preshared key.
///
/// Returns the created peer (private key NOT included in the response).
pub async fn add_peer(
    db_handle: &sfgw_db::Db,
    tunnel_id: i64,
    request: &CreatePeerRequest,
) -> Result<VpnPeer> {
    // Load the tunnel to validate it exists and get its config
    let tunnel_row = db::get_tunnel_by_id(db_handle, tunnel_id)
        .await?
        .context("tunnel not found")?;

    let tunnel_config = TunnelConfig::from_db_json(&tunnel_row.config)?;

    // Generate a unique keypair for this peer
    let keypair = crate::keys::generate_keypair()?;
    let public_key = keypair.public_key.clone();
    let mut private_key_b64 = crate::keys::private_key_to_base64(&keypair.private_key)?;

    // Generate a preshared key for quantum resistance
    let preshared_key = crate::keys::generate_preshared_key();

    // Determine peer address (auto-assign if not provided)
    let address = match &request.address {
        Some(addr) => {
            validate_cidr(addr)?;
            addr.clone()
        }
        None => auto_assign_address(db_handle, tunnel_id, &tunnel_config.address).await?,
    };

    // Determine IPv6 address if tunnel has IPv6
    let address_v6 = match (&request.address_v6, &tunnel_config.address_v6) {
        (Some(addr), _) => {
            validate_cidr(addr)?;
            Some(addr.clone())
        }
        (None, Some(tunnel_v6)) => {
            Some(auto_assign_address_v6(db_handle, tunnel_id, tunnel_v6).await?)
        }
        (None, None) => None,
    };

    // Build allowed IPs based on routing mode
    let allowed_ips = build_allowed_ips(&request.routing_mode, &request.allowed_ips, &address, address_v6.as_deref());

    let allowed_ips_json = serde_json::to_string(&allowed_ips)?;
    let routing_mode_str = request.routing_mode.to_string();
    let dns = request.dns.as_deref().or(tunnel_config.dns.as_deref());

    let peer_id = db::insert_peer(
        db_handle,
        tunnel_id,
        request.name.as_deref(),
        &public_key,
        &private_key_b64,
        Some(&preshared_key),
        &address,
        address_v6.as_deref(),
        &allowed_ips_json,
        request.endpoint.as_deref(),
        request.persistent_keepalive,
        &routing_mode_str,
        dns,
    )
    .await?;

    // Zeroize the plaintext private key
    private_key_b64.zeroize();

    info!(tunnel_id, peer_id, peer_name = ?request.name, "peer added");

    // Fetch the created peer to get the created_at timestamp
    let row = db::get_peer_by_id(db_handle, peer_id)
        .await?
        .context("peer just created but not found")?;

    Ok(peer_from_row(&row))
}

/// Remove a peer from a tunnel.
pub async fn remove_peer(
    db_handle: &sfgw_db::Db,
    tunnel_id: i64,
    peer_id: i64,
) -> Result<()> {
    // Verify the peer belongs to this tunnel
    let _peer = db::get_peer(db_handle, tunnel_id, peer_id)
        .await?
        .context("peer not found in this tunnel")?;

    db::delete_peer(db_handle, peer_id).await?;
    info!(tunnel_id, peer_id, "peer removed");
    Ok(())
}

/// List all peers for a tunnel (no private keys in output).
pub async fn list_peers(db_handle: &sfgw_db::Db, tunnel_id: i64) -> Result<Vec<VpnPeer>> {
    let rows = db::list_peers(db_handle, tunnel_id).await?;
    Ok(rows.iter().map(peer_from_row).collect())
}

/// Get a single peer by ID (no private key in output).
pub async fn get_peer(
    db_handle: &sfgw_db::Db,
    tunnel_id: i64,
    peer_id: i64,
) -> Result<Option<VpnPeer>> {
    let row = db::get_peer(db_handle, tunnel_id, peer_id).await?;
    Ok(row.as_ref().map(peer_from_row))
}

/// Generate a downloadable WireGuard client config for a peer.
///
/// This temporarily decrypts the peer's private key to include it in the config.
/// The config is in standard wg-quick format.
pub async fn generate_client_config(
    db_handle: &sfgw_db::Db,
    tunnel_id: i64,
    peer_id: i64,
    server_endpoint: &str,
) -> Result<String> {
    let tunnel_row = db::get_tunnel_by_id(db_handle, tunnel_id)
        .await?
        .context("tunnel not found")?;

    let tunnel_config = TunnelConfig::from_db_json(&tunnel_row.config)?;

    let peer_row = db::get_peer(db_handle, tunnel_id, peer_id)
        .await?
        .context("peer not found")?;

    let routing_mode = RoutingMode::from_str_lossy(&peer_row.routing_mode);
    let allowed_ips: Vec<String> = serde_json::from_str(&peer_row.allowed_ips_json)
        .unwrap_or_default();

    // Build the client's allowed IPs (what traffic goes through the VPN)
    let client_allowed_ips = match routing_mode {
        RoutingMode::Full => vec![
            "0.0.0.0/0".to_string(),
            "::/0".to_string(),
        ],
        RoutingMode::Split => {
            if allowed_ips.is_empty() {
                // Default: route the tunnel subnet
                let mut ips = vec![tunnel_config.address.clone()];
                if let Some(ref v6) = tunnel_config.address_v6 {
                    ips.push(v6.clone());
                }
                ips
            } else {
                allowed_ips
            }
        }
    };

    // Build the client address line (combine v4 + v6)
    let mut peer_address = peer_row.address.clone();
    if let Some(ref v6) = peer_row.address_v6 {
        peer_address = format!("{}, {}", peer_address, v6);
    }

    let dns = peer_row
        .dns
        .as_deref()
        .or(tunnel_config.dns.as_deref());

    let config = crate::config::generate_peer_config(
        &peer_row.private_key_enc,
        &peer_address,
        dns,
        tunnel_config.mtu,
        &tunnel_config.public_key,
        server_endpoint,
        &client_allowed_ips,
        peer_row.preshared_key.as_deref(),
        peer_row.persistent_keepalive.map(|v| v as u16),
    );

    Ok(config)
}

/// Convert a PeerRow to the WgPeer format used for applying to the WireGuard interface.
pub fn peer_row_to_wg_peer(row: &PeerRow) -> WgPeer {
    let allowed_ips: Vec<String> = serde_json::from_str(&row.allowed_ips_json)
        .unwrap_or_default();

    // Server-side allowed IPs: the peer's assigned address(es)
    let mut server_allowed_ips = vec![ensure_host_cidr(&row.address)];
    if let Some(ref v6) = row.address_v6 {
        server_allowed_ips.push(ensure_host_cidr(v6));
    }
    // Also include any additional allowed IPs from the peer config
    for ip in &allowed_ips {
        if !server_allowed_ips.contains(ip) {
            server_allowed_ips.push(ip.clone());
        }
    }

    WgPeer {
        public_key: row.public_key.clone(),
        preshared_key: row.preshared_key.clone(),
        allowed_ips: server_allowed_ips,
        endpoint: row.endpoint.clone(),
        persistent_keepalive: row.persistent_keepalive.map(|v| v as u16),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert a DB row to a VpnPeer (no private key).
fn peer_from_row(row: &PeerRow) -> VpnPeer {
    let allowed_ips: Vec<String> = serde_json::from_str(&row.allowed_ips_json)
        .unwrap_or_default();

    VpnPeer {
        id: row.id,
        tunnel_id: row.tunnel_id,
        name: row.name.clone(),
        public_key: row.public_key.clone(),
        address: row.address.clone(),
        address_v6: row.address_v6.clone(),
        allowed_ips,
        endpoint: row.endpoint.clone(),
        persistent_keepalive: row.persistent_keepalive.map(|v| v as u16),
        routing_mode: RoutingMode::from_str_lossy(&row.routing_mode),
        dns: row.dns.clone(),
        enabled: row.enabled,
        created_at: row.created_at.clone(),
    }
}

/// Validate that a string is a valid CIDR address.
fn validate_cidr(addr: &str) -> Result<()> {
    // Accept CIDR notation (possibly with host bits set, e.g. 10.0.0.1/24)
    if let Some((ip_part, prefix_part)) = addr.split_once('/') {
        ip_part
            .parse::<std::net::IpAddr>()
            .map_err(|_| anyhow::anyhow!("invalid IP in CIDR: {}", addr))?;
        prefix_part
            .parse::<u8>()
            .map_err(|_| anyhow::anyhow!("invalid prefix length in CIDR: {}", addr))?;
        return Ok(());
    }
    // Bare IP without prefix
    addr.parse::<std::net::IpAddr>()
        .map_err(|_| anyhow::anyhow!("invalid address/CIDR: {}", addr))?;
    Ok(())
}

/// Ensure an address has a host CIDR suffix (/32 for v4, /128 for v6).
fn ensure_host_cidr(addr: &str) -> String {
    if addr.contains('/') {
        return addr.to_string();
    }
    if addr.contains(':') {
        format!("{}/128", addr)
    } else {
        format!("{}/32", addr)
    }
}

/// Auto-assign the next available IPv4 address in the tunnel's subnet.
///
/// Handles addresses with host bits set (e.g., "10.0.0.1/24") by truncating
/// to the network address before iterating hosts.
async fn auto_assign_address(
    db_handle: &sfgw_db::Db,
    tunnel_id: i64,
    tunnel_address: &str,
) -> Result<String> {
    // Parse IP and prefix separately to handle host-bits-set addresses
    let (ip_str, prefix_str) = tunnel_address
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("tunnel address missing CIDR prefix: {tunnel_address}"))?;

    let ip: std::net::Ipv4Addr = ip_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid tunnel IPv4 address: {e}"))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid prefix length: {e}"))?;

    let used = db::used_addresses(db_handle, tunnel_id).await?;

    // Calculate subnet range from IP and prefix
    let ip_u32 = u32::from(ip);
    let mask = if prefix >= 32 { u32::MAX } else { u32::MAX << (32 - prefix) };
    let network_addr = ip_u32 & mask;
    let broadcast_addr = network_addr | !mask;

    // Iterate host addresses in the subnet, skipping network, broadcast, and gateway
    let mut addr = network_addr + 1;
    while addr < broadcast_addr {
        let candidate_ip = std::net::Ipv4Addr::from(addr);
        if candidate_ip != ip {
            let candidate = format!("{}/32", candidate_ip);
            let candidate_bare = candidate_ip.to_string();
            if !used.iter().any(|u| u.starts_with(&candidate_bare)) {
                return Ok(candidate);
            }
        }
        addr += 1;
    }

    bail!("no available addresses in subnet {}", tunnel_address);
}

/// Auto-assign the next available IPv6 address in the tunnel's subnet.
async fn auto_assign_address_v6(
    db_handle: &sfgw_db::Db,
    tunnel_id: i64,
    tunnel_address_v6: &str,
) -> Result<String> {
    let (ip_str, prefix_str) = tunnel_address_v6
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("tunnel IPv6 address missing prefix: {tunnel_address_v6}"))?;

    let ip: std::net::Ipv6Addr = ip_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid tunnel IPv6 address: {e}"))?;
    let _prefix: u8 = prefix_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid prefix length: {e}"))?;

    // Use the tunnel's own IP as the base for assignment
    let gateway_u128 = u128::from(ip);

    let used = db::used_addresses(db_handle, tunnel_id).await?;

    // Start from gateway + 2 (skip network and gateway)
    for offset in 2u128..=254 {
        let candidate_ip = std::net::Ipv6Addr::from(gateway_u128 + offset);
        let candidate = format!("{}/128", candidate_ip);
        let candidate_bare = candidate_ip.to_string();
        if !used.iter().any(|u| u.contains(&candidate_bare)) {
            return Ok(candidate);
        }
    }

    bail!("no available IPv6 addresses in subnet {}", tunnel_address_v6);
}

/// Build the allowed IPs list based on routing mode.
///
/// For full tunnel: 0.0.0.0/0, ::/0
/// For split tunnel: the peer's own address + any extra subnets
fn build_allowed_ips(
    mode: &RoutingMode,
    extra_ips: &[String],
    peer_address: &str,
    peer_address_v6: Option<&str>,
) -> Vec<String> {
    match mode {
        RoutingMode::Full => {
            vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
        }
        RoutingMode::Split => {
            let mut ips = vec![ensure_host_cidr(peer_address)];
            if let Some(v6) = peer_address_v6 {
                ips.push(ensure_host_cidr(v6));
            }
            for ip in extra_ips {
                if !ips.contains(ip) {
                    ips.push(ip.clone());
                }
            }
            ips
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ensure_host_cidr() {
        assert_eq!(ensure_host_cidr("10.0.0.2"), "10.0.0.2/32");
        assert_eq!(ensure_host_cidr("10.0.0.2/32"), "10.0.0.2/32");
        assert_eq!(ensure_host_cidr("10.0.0.0/24"), "10.0.0.0/24");
        assert_eq!(ensure_host_cidr("fd00::2"), "fd00::2/128");
        assert_eq!(ensure_host_cidr("fd00::2/128"), "fd00::2/128");
    }

    #[test]
    fn test_build_allowed_ips_full() {
        let ips = build_allowed_ips(
            &RoutingMode::Full,
            &[],
            "10.0.0.2/32",
            Some("fd00::2/128"),
        );
        assert_eq!(ips, vec!["0.0.0.0/0", "::/0"]);
    }

    #[test]
    fn test_build_allowed_ips_split() {
        let ips = build_allowed_ips(
            &RoutingMode::Split,
            &["192.168.1.0/24".to_string()],
            "10.0.0.2/32",
            Some("fd00::2/128"),
        );
        assert_eq!(
            ips,
            vec!["10.0.0.2/32", "fd00::2/128", "192.168.1.0/24"]
        );
    }

    #[test]
    fn test_validate_cidr() {
        assert!(validate_cidr("10.0.0.1/24").is_ok());
        assert!(validate_cidr("10.0.0.1/32").is_ok());
        assert!(validate_cidr("fd00::1/64").is_ok());
        assert!(validate_cidr("10.0.0.1").is_ok());
        assert!(validate_cidr("not-an-ip").is_err());
    }

    #[test]
    fn test_routing_mode_from_str() {
        assert_eq!(RoutingMode::from_str_lossy("full"), RoutingMode::Full);
        assert_eq!(RoutingMode::from_str_lossy("split"), RoutingMode::Split);
        assert_eq!(RoutingMode::from_str_lossy("unknown"), RoutingMode::Split);
    }
}
