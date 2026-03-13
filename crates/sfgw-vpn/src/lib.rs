// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! sfgw-vpn — WireGuard VPN tunnel management for secfirstgw.
//!
//! Provides multi-tunnel WireGuard support using boringtun userspace:
//! - Curve25519 key generation and management
//! - Tunnel lifecycle (create, start, stop, delete)
//! - Peer management with server-generated keypairs (add, remove, list)
//! - Config file generation (wg-quick format) for client provisioning
//! - Split/full tunnel routing per peer
//! - Dual-stack IPv4 + IPv6 support
//!
//! # Security
//!
//! - Private keys are NEVER logged or returned in API responses
//! - Private keys are wrapped in `SecureBox<Vec<u8>>` — encrypted in memory
//!   with an ephemeral AES-256-GCM key, mlock'd, excluded from core dumps
//! - Preshared keys provide additional quantum-resistance
//! - All peers get unique server-generated X25519 keypairs

use serde::{Deserialize, Serialize};
use sfgw_crypto::secure_mem::SecureBox;

pub mod config;
pub mod db;
pub mod keys;
pub mod peer;
pub mod tunnel;
pub mod userspace;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// VPN-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum VpnError {
    #[error("tunnel not found: {0}")]
    TunnelNotFound(String),

    #[error("peer not found: {0}")]
    PeerNotFound(String),

    #[error("tunnel '{0}' already exists")]
    TunnelExists(String),

    #[error("duplicate peer public key in tunnel")]
    DuplicatePeer,

    #[error("invalid interface name: {0}")]
    InvalidName(String),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("tunnel is not running")]
    TunnelNotRunning,

    #[error("tunnel is already running")]
    TunnelAlreadyRunning,

    #[error(transparent)]
    Db(#[from] anyhow::Error),
}

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

/// Per-peer routing mode: full tunnel or split tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    /// Route all traffic through the VPN (0.0.0.0/0, ::/0).
    Full,
    /// Route only specified subnets through the VPN.
    Split,
}

impl std::fmt::Display for RoutingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingMode::Full => write!(f, "full"),
            RoutingMode::Split => write!(f, "split"),
        }
    }
}

impl RoutingMode {
    /// Parse from a string, defaulting to Split for unknown values.
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "full" => Self::Full,
            _ => Self::Split,
        }
    }
}

/// A VPN tunnel as presented to callers (no private key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnTunnel {
    pub id: i64,
    pub name: String,
    pub tunnel_type: TunnelType,
    pub enabled: bool,
    pub listen_port: u16,
    /// Public key for this tunnel (safe to share with peers).
    pub public_key: String,
    /// IPv4 address/CIDR for the tunnel interface.
    pub address: String,
    /// IPv6 address/CIDR for the tunnel interface (dual-stack).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_v6: Option<String>,
    pub dns: Option<String>,
    pub mtu: u16,
    /// Firewall zone for this tunnel's traffic.
    pub zone: String,
}

/// A VPN peer as presented to callers (no private key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnPeer {
    pub id: i64,
    pub tunnel_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Public key for this peer (safe to share).
    pub public_key: String,
    /// IPv4 VPN address assigned to this peer.
    pub address: String,
    /// IPv6 VPN address assigned to this peer (dual-stack).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_v6: Option<String>,
    pub allowed_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u16>,
    pub routing_mode: RoutingMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

/// A WireGuard peer configuration (server-side view for applying to interface).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgPeer {
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u16>,
}

/// Request body for creating a new tunnel.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateTunnelRequest {
    pub name: String,
    pub listen_port: u16,
    /// IPv4 address/CIDR (e.g., "10.0.0.1/24").
    pub address: String,
    /// IPv6 address/CIDR (e.g., "fd00::1/64"). Optional for dual-stack.
    #[serde(default)]
    pub address_v6: Option<String>,
    #[serde(default)]
    pub dns: Option<String>,
    #[serde(default)]
    pub mtu: Option<u16>,
    /// Firewall zone for VPN traffic. Defaults to "vpn".
    #[serde(default = "default_zone")]
    pub zone: String,
}

fn default_zone() -> String {
    "vpn".to_string()
}

/// Request body for adding a new peer to a tunnel.
#[derive(Debug, Clone, Deserialize)]
pub struct CreatePeerRequest {
    /// Human-readable name for this peer.
    #[serde(default)]
    pub name: Option<String>,
    /// IPv4 address to assign (e.g., "10.0.0.2/32"). Auto-assigned if omitted.
    #[serde(default)]
    pub address: Option<String>,
    /// IPv6 address to assign (e.g., "fd00::2/128"). Auto-assigned if omitted.
    #[serde(default)]
    pub address_v6: Option<String>,
    /// Additional allowed IPs for split tunnel mode.
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Peer's public endpoint (optional, for site-to-site).
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
    /// Routing mode: "full" or "split" (default: "split").
    #[serde(default = "default_routing_mode")]
    pub routing_mode: RoutingMode,
    /// DNS servers for this peer (overrides tunnel DNS).
    #[serde(default)]
    pub dns: Option<String>,
}

fn default_routing_mode() -> RoutingMode {
    RoutingMode::Split
}

/// Full tunnel configuration with the private key in a `SecureBox`.
///
/// This is the runtime representation used internally.
/// **Contains private key** — must NEVER be serialized to API responses.
pub struct TunnelConfig {
    pub listen_port: u16,
    /// Curve25519 private key in a SecureBox. NEVER log or expose.
    pub private_key: SecureBox<Vec<u8>>,
    /// Base64-encoded public key (derived from private_key).
    pub public_key: String,
    pub address: String,
    pub address_v6: Option<String>,
    pub dns: Option<String>,
    pub mtu: u16,
    pub zone: String,
}

/// Serializable tunnel config for database storage.
///
/// The private key is stored as base64 in the DB. Only used at the DB boundary.
#[derive(Serialize, Deserialize)]
pub(crate) struct DbTunnelConfig {
    pub listen_port: u16,
    pub private_key: String,
    pub public_key: String,
    pub address: String,
    #[serde(default)]
    pub address_v6: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<String>,
    pub mtu: u16,
    #[serde(default = "default_zone")]
    pub zone: String,
}

impl TunnelConfig {
    /// Serialize this config to JSON for DB storage.
    pub(crate) fn to_db_json(&self) -> anyhow::Result<String> {
        let private_key_b64 = keys::private_key_to_base64(&self.private_key)?;
        let mut db_config = DbTunnelConfig {
            listen_port: self.listen_port,
            private_key: private_key_b64,
            public_key: self.public_key.clone(),
            address: self.address.clone(),
            address_v6: self.address_v6.clone(),
            dns: self.dns.clone(),
            mtu: self.mtu,
            zone: self.zone.clone(),
        };

        let json = serde_json::to_string(&db_config)
            .map_err(|e| anyhow::anyhow!("failed to serialize tunnel config: {e}"))?;

        use zeroize::Zeroize;
        db_config.private_key.zeroize();

        Ok(json)
    }

    /// Deserialize a DB JSON config string into a `TunnelConfig`.
    pub(crate) fn from_db_json(json: &str) -> anyhow::Result<Self> {
        use zeroize::Zeroize;

        let mut db_config: DbTunnelConfig = serde_json::from_str(json)
            .map_err(|e| anyhow::anyhow!("corrupt tunnel config in DB: {e}"))?;

        let secure_key = keys::wrap_private_key(&db_config.private_key)?;
        db_config.private_key.zeroize();

        Ok(TunnelConfig {
            listen_port: db_config.listen_port,
            private_key: secure_key,
            public_key: db_config.public_key,
            address: db_config.address,
            address_v6: db_config.address_v6,
            dns: db_config.dns,
            mtu: db_config.mtu,
            zone: db_config.zone,
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
    pub peers: Vec<PeerStatus>,
}

/// Live status of a single peer on a tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
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
/// Ensures the DB schema is ready and logs tunnel count.
pub async fn start(db: &sfgw_db::Db) -> Result<(), VpnError> {
    let tunnels = tunnel::list_tunnels(db).await?;
    let enabled_count = tunnels.iter().filter(|t| t.enabled).count();

    tracing::info!(
        total = tunnels.len(),
        enabled = enabled_count,
        "VPN service ready (WireGuard userspace via boringtun)"
    );

    Ok(())
}
