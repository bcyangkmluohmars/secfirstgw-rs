// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! sfgw-vpn — VPN tunnel management for secfirstgw.
//!
//! Provides multi-tunnel VPN support:
//! - **WireGuard** via boringtun userspace: Curve25519 key generation,
//!   peer management, wg-quick config generation, QR provisioning
//! - **IPsec/IKEv2** via strongSwan: swanctl config generation,
//!   certificate and PSK auth, roadwarrior and site-to-site modes
//! - Tunnel lifecycle (create, start, stop, delete)
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
//! - IPsec uses modern cipher suites only (no 3DES, no SHA-1, no DH<16)
//! - PSK material stored in `SecureBox` — never hardcoded

use serde::{Deserialize, Serialize};
use sfgw_crypto::secure_mem::SecureBox;

pub mod config;
pub mod db;
pub mod ipsec;
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

    #[error("invalid IPsec configuration: {0}")]
    InvalidIpsecConfig(String),

    #[error("strongSwan error: {0}")]
    StrongSwan(String),

    #[error("swanctl config injection attempt: {0}")]
    ConfigInjection(String),

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
    /// IPsec/IKEv2 via strongSwan.
    #[serde(rename = "ipsec")]
    IPsec,
}

impl std::fmt::Display for TunnelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelType::WireGuard => write!(f, "wireguard"),
            TunnelType::IPsec => write!(f, "ipsec"),
        }
    }
}

impl TunnelType {
    /// Parse from a database/string representation.
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "ipsec" => Self::IPsec,
            _ => Self::WireGuard,
        }
    }
}

// ---------------------------------------------------------------------------
// IPsec-specific data model
// ---------------------------------------------------------------------------

/// IPsec authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpsecAuthMethod {
    /// X.509 certificate-based (preferred, uses sfgw-adopt CA).
    Certificate,
    /// Pre-shared key (fallback for legacy clients).
    Psk,
    /// EAP-MSCHAPv2 (for Windows/macOS/iOS native clients).
    #[serde(rename = "eap-mschapv2")]
    EapMschapv2,
}

impl std::fmt::Display for IpsecAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpsecAuthMethod::Certificate => write!(f, "certificate"),
            IpsecAuthMethod::Psk => write!(f, "psk"),
            IpsecAuthMethod::EapMschapv2 => write!(f, "eap-mschapv2"),
        }
    }
}

impl IpsecAuthMethod {
    /// Parse from a string representation.
    pub fn parse(s: &str) -> Result<Self, VpnError> {
        match s.to_lowercase().as_str() {
            "certificate" | "cert" => Ok(Self::Certificate),
            "psk" => Ok(Self::Psk),
            "eap-mschapv2" | "eap_mschapv2" | "eapmschapv2" => Ok(Self::EapMschapv2),
            other => Err(VpnError::InvalidIpsecConfig(format!(
                "unknown auth method: {other}"
            ))),
        }
    }
}

/// IPsec connection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpsecMode {
    /// Remote access / roadwarrior (server assigns virtual IP).
    RoadWarrior,
    /// Site-to-site tunnel (fixed subnets on both ends).
    SiteToSite,
}

impl std::fmt::Display for IpsecMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpsecMode::RoadWarrior => write!(f, "roadwarrior"),
            IpsecMode::SiteToSite => write!(f, "site-to-site"),
        }
    }
}

impl IpsecMode {
    /// Parse from a string representation.
    pub fn parse(s: &str) -> Result<Self, VpnError> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "roadwarrior" | "road-warrior" => Ok(Self::RoadWarrior),
            "site-to-site" | "sitetosite" | "s2s" => Ok(Self::SiteToSite),
            other => Err(VpnError::InvalidIpsecConfig(format!(
                "unknown IPsec mode: {other}"
            ))),
        }
    }
}

/// Request body for creating a new IPsec tunnel.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateIpsecTunnelRequest {
    pub name: String,
    pub mode: IpsecMode,
    pub auth_method: IpsecAuthMethod,
    /// IKE identity, e.g. "gateway.secfirstgw.local".
    #[serde(default)]
    pub local_id: Option<String>,
    /// IKE port override (default 500/4500 for NAT-T).
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Local bind address, default %any.
    #[serde(default)]
    pub local_addrs: Option<String>,
    /// Virtual IP pool for roadwarrior, e.g. "10.10.0.0/24".
    #[serde(default)]
    pub pool_v4: Option<String>,
    /// Virtual IPv6 pool for roadwarrior, e.g. "fd10::0/112".
    #[serde(default)]
    pub pool_v6: Option<String>,
    /// Local traffic selectors for site-to-site.
    #[serde(default)]
    pub local_ts: Option<Vec<String>>,
    /// Remote traffic selectors for site-to-site.
    #[serde(default)]
    pub remote_ts: Option<Vec<String>>,
    /// DNS servers to push to clients.
    #[serde(default)]
    pub dns: Option<String>,
    /// Firewall zone for this tunnel's traffic.
    #[serde(default = "default_zone")]
    pub zone: String,
}

/// IPsec DB config — serialized to JSON in the `config` column.
///
/// Public for integration test access; not intended for external API consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsecDbConfig {
    pub mode: String,
    pub auth_method: String,
    pub local_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_addrs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_v4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_v6: Option<String>,
    #[serde(default)]
    pub local_ts: Vec<String>,
    #[serde(default)]
    pub remote_ts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<String>,
    #[serde(default = "default_zone")]
    pub zone: String,
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
    /// WAN interface to bind this tunnel to (None = all interfaces).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,
    /// Peers belonging to this tunnel.
    #[serde(default)]
    pub peers: Vec<VpnPeer>,
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
    /// WAN interface to bind to (None = all interfaces).
    #[serde(default)]
    pub bind_interface: Option<String>,
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
    /// WAN interface to bind to (None = all interfaces).
    pub bind_interface: Option<String>,
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
    /// WAN interface to bind to (None = all interfaces).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,
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
            bind_interface: self.bind_interface.clone(),
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
            bind_interface: db_config.bind_interface,
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
    let wg_count = tunnels
        .iter()
        .filter(|t| t.tunnel_type == TunnelType::WireGuard)
        .count();
    let ipsec_count = tunnels
        .iter()
        .filter(|t| t.tunnel_type == TunnelType::IPsec)
        .count();

    tracing::info!(
        total = tunnels.len(),
        enabled = enabled_count,
        wireguard = wg_count,
        ipsec = ipsec_count,
        "VPN service ready (WireGuard + IPsec/IKEv2)"
    );

    Ok(())
}
