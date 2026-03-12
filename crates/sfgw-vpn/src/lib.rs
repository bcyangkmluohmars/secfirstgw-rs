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
//! - Private keys are wrapped in `SecureBox<Vec<u8>>` — encrypted in memory
//!   with an ephemeral AES-256-GCM key, mlock'd, excluded from core dumps
//! - Preshared keys provide additional quantum-resistance
//! - Key material is passed to `wg` via temp files (0600), not CLI args

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sfgw_crypto::secure_mem::SecureBox;

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

/// Full tunnel configuration with the private key in a `SecureBox`.
///
/// This is the runtime representation. The private key is encrypted in memory
/// and only decrypted when needed (e.g., to write a WireGuard config or pass
/// to `wg set`).
///
/// **Contains private key** — must NEVER be serialized to API responses.
/// Use [`TunnelConfig::to_db_config`] / [`TunnelConfig::from_db_config`]
/// for database (de)serialization.
pub struct TunnelConfig {
    pub listen_port: u16,
    /// Curve25519 private key in a SecureBox. NEVER log or expose.
    pub private_key: SecureBox<Vec<u8>>,
    /// Base64-encoded public key (derived from private_key).
    pub public_key: String,
    pub address: String,
    pub dns: Option<String>,
    pub mtu: u16,
    pub peers: Vec<WgPeer>,
}

/// Serializable tunnel config for database storage.
///
/// The private key is stored as base64 in the DB. This struct is only used
/// at the DB boundary — private keys are immediately wrapped in SecureBox
/// when loading, and only unwrapped for serialization when saving.
#[derive(Serialize, Deserialize)]
pub(crate) struct DbTunnelConfig {
    pub listen_port: u16,
    /// Base64-encoded Curve25519 private key.
    pub private_key: String,
    /// Base64-encoded public key.
    pub public_key: String,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<String>,
    pub mtu: u16,
    #[serde(default)]
    pub peers: Vec<WgPeer>,
}

impl TunnelConfig {
    /// Serialize this config to JSON for DB storage.
    ///
    /// Temporarily decrypts the private key to produce the base64 string,
    /// then zeroizes the intermediate.
    pub(crate) fn to_db_json(&self) -> Result<String> {
        let private_key_b64 = keys::private_key_to_base64(&self.private_key)?;
        let mut db_config = DbTunnelConfig {
            listen_port: self.listen_port,
            private_key: private_key_b64,
            public_key: self.public_key.clone(),
            address: self.address.clone(),
            dns: self.dns.clone(),
            mtu: self.mtu,
            peers: self.peers.clone(),
        };

        let json = serde_json::to_string(&db_config)
            .map_err(|e| anyhow::anyhow!("failed to serialize tunnel config: {e}"))?;

        // Zeroize the plaintext base64 key that was in the DbTunnelConfig
        use zeroize::Zeroize;
        db_config.private_key.zeroize();

        Ok(json)
    }

    /// Deserialize a DB JSON config string into a `TunnelConfig`.
    ///
    /// The private key is immediately wrapped in SecureBox upon loading.
    pub(crate) fn from_db_json(json: &str) -> Result<Self> {
        use zeroize::Zeroize;

        let mut db_config: DbTunnelConfig = serde_json::from_str(json)
            .map_err(|e| anyhow::anyhow!("corrupt tunnel config in DB: {e}"))?;

        let secure_key = keys::wrap_private_key(&db_config.private_key)?;

        // Zeroize the plaintext base64 key immediately
        db_config.private_key.zeroize();

        Ok(TunnelConfig {
            listen_port: db_config.listen_port,
            private_key: secure_key,
            public_key: db_config.public_key,
            address: db_config.address,
            dns: db_config.dns,
            mtu: db_config.mtu,
            peers: db_config.peers,
        })
    }
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
