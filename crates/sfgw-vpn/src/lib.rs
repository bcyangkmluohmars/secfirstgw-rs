// SPDX-License-Identifier: AGPL-3.0-or-later

//! sfgw-vpn — WireGuard VPN tunnel management for secfirstgw.
//!
//! Provides multi-tunnel WireGuard support with:
//! - Curve25519 key generation and management
//! - Tunnel lifecycle (create, start, stop, delete)
//! - Peer management (add, remove)
//! - Config file generation/parsing (wg-quick format)
//! - QR code data for mobile peer provisioning
//!
//! # Security
//!
//! - Private keys are NEVER logged or returned in API responses
//! - Preshared keys provide additional quantum-resistance
//! - Key material is passed to `wg` via temp files (0600), not CLI args
//! - TODO: Wrap private keys in SecureBox for encrypted in-memory storage

use serde::{Deserialize, Serialize};

pub mod config;
pub mod db;
pub mod keys;
pub mod tunnel;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// Supported VPN tunnel types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelType {
    WireGuard,
}

impl std::fmt::Display for TunnelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelType::WireGuard => write!(f, "wireguard"),
        }
    }
}

/// A VPN tunnel as presented to callers.
///
/// **Note**: `private_key` is intentionally NOT included here.
/// Only the `public_key` is exposed. The private key lives only in DB config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnTunnel {
    pub id: i64,
    pub name: String,
    pub tunnel_type: TunnelType,
    pub enabled: bool,
    pub listen_port: u16,
    /// Public key for this tunnel (safe to share with peers).
    pub public_key: String,
    pub address: String,
    pub dns: Option<String>,
    pub mtu: u16,
    pub peers: Vec<WgPeer>,
}

/// A WireGuard peer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgPeer {
    pub public_key: String,
    /// Preshared key for additional quantum resistance. Optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u16>,
}

/// Full tunnel configuration as stored in the DB `config` JSON column.
///
/// **Contains private key** — must NEVER be serialized to API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub listen_port: u16,
    /// Base64-encoded Curve25519 private key. NEVER log or expose.
    /// TODO: Replace with SecureBox<String> for encrypted in-memory storage.
    pub private_key: String,
    /// Base64-encoded public key (derived from private_key).
    pub public_key: String,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<String>,
    pub mtu: u16,
    #[serde(default)]
    pub peers: Vec<WgPeer>,
}

/// Live status of a tunnel interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub name: String,
    pub is_up: bool,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub peers: Vec<WgPeerStatus>,
}

/// Live status of a single peer on a tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgPeerStatus {
    pub public_key: String,
    pub endpoint: Option<String>,
    /// Seconds since epoch of the last successful handshake (0 = never).
    pub last_handshake_secs: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

// ---------------------------------------------------------------------------
// Service entry point
// ---------------------------------------------------------------------------

/// Initialize the VPN service.
///
/// Currently ensures the DB schema is ready. Tunnels marked `enabled` in the
/// database could be auto-started here in the future.
pub async fn start(db: &sfgw_db::Db) -> anyhow::Result<()> {
    let tunnels = tunnel::list_tunnels(db).await?;
    let enabled_count = tunnels.iter().filter(|t| t.enabled).count();

    tracing::info!(
        total = tunnels.len(),
        enabled = enabled_count,
        "VPN service ready (WireGuard multi-tunnel)"
    );

    Ok(())
}
