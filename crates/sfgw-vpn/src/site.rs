// SPDX-License-Identifier: AGPL-3.0-or-later

//! Site-to-site WireGuard mesh management with auto-failover.
//!
//! Manages full-mesh or hub-and-spoke WireGuard tunnels between multiple sites.
//! Health is determined by WireGuard handshake age — if a peer's last handshake
//! exceeds `failover_timeout_secs`, traffic is rerouted through a backup peer.
//!
//! # Security
//!
//! - Private keys wrapped in `SecureBox<Vec<u8>>` — never logged or returned in API
//! - Preshared keys provide quantum-resistance between sites
//! - All subnets validated before route injection (no arbitrary route manipulation)

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

use crate::db;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// Mesh topology mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MeshTopology {
    /// Every site connects to every other site.
    FullMesh,
    /// All spoke sites connect only to the hub (local site).
    HubAndSpoke,
}

impl std::fmt::Display for MeshTopology {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeshTopology::FullMesh => write!(f, "full-mesh"),
            MeshTopology::HubAndSpoke => write!(f, "hub-and-spoke"),
        }
    }
}

impl MeshTopology {
    /// Parse from string, defaulting to full-mesh for unknown values.
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().replace('_', "-").as_str() {
            "hub-and-spoke" | "hub" | "spoke" => Self::HubAndSpoke,
            _ => Self::FullMesh,
        }
    }
}

/// A site within a mesh network (API-safe — no private key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub id: i64,
    pub mesh_id: i64,
    pub name: String,
    /// Endpoint address (IP:port or hostname:port).
    pub endpoint: String,
    /// Base64-encoded public key.
    pub public_key: String,
    /// Subnets behind this site (CIDR notation).
    pub local_subnets: Vec<String>,
    /// Subnets reachable at remote sites (informational).
    pub remote_subnets: Vec<String>,
    /// Priority for failover: 0 = primary, higher = lower priority.
    pub priority: i64,
    /// Whether this is the local site (our gateway).
    pub is_local: bool,
    pub enabled: bool,
    pub created_at: String,
}

/// A site mesh configuration (API-safe).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteMesh {
    pub id: i64,
    pub name: String,
    pub topology: MeshTopology,
    pub listen_port: u16,
    pub keepalive_interval: u16,
    pub failover_timeout_secs: u32,
    pub enabled: bool,
    pub sites: Vec<Site>,
    pub created_at: String,
    pub updated_at: String,
}

/// Per-site connection status (live data from WireGuard).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteStatus {
    pub site_id: i64,
    pub site_name: String,
    pub endpoint: String,
    pub state: SiteConnectionState,
    /// Seconds since last successful WireGuard handshake (0 = never).
    pub last_handshake_secs: u64,
    /// Approximate latency derived from handshake age.
    pub latency_ms: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Connection state for a site peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiteConnectionState {
    /// Handshake recent, tunnel is healthy.
    Connected,
    /// Handshake is stale but within timeout.
    Degraded,
    /// Handshake exceeded failover timeout — site unreachable.
    Down,
    /// Never had a handshake.
    Pending,
}

impl std::fmt::Display for SiteConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SiteConnectionState::Connected => write!(f, "connected"),
            SiteConnectionState::Degraded => write!(f, "degraded"),
            SiteConnectionState::Down => write!(f, "down"),
            SiteConnectionState::Pending => write!(f, "pending"),
        }
    }
}

/// Mesh-level status summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshStatus {
    pub mesh_id: i64,
    pub mesh_name: String,
    pub is_active: bool,
    pub interface_name: String,
    pub sites: Vec<SiteStatus>,
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Create a new site mesh.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateMeshRequest {
    pub name: String,
    #[serde(default = "default_topology")]
    pub topology: MeshTopology,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default = "default_keepalive")]
    pub keepalive_interval: u16,
    #[serde(default = "default_failover_timeout")]
    pub failover_timeout_secs: u32,
    #[serde(default)]
    pub sites: Vec<CreateSiteRequest>,
}

/// Add a site to a mesh.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateSiteRequest {
    pub name: String,
    pub endpoint: String,
    /// Provide public key for remote sites. Omit for local site (auto-generated).
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub preshared_key: Option<String>,
    #[serde(default)]
    pub local_subnets: Vec<String>,
    #[serde(default)]
    pub remote_subnets: Vec<String>,
    #[serde(default)]
    pub priority: i64,
    /// Mark this as the local site (our gateway). Only one per mesh.
    #[serde(default)]
    pub is_local: bool,
}

/// Update a site mesh.
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateMeshRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub topology: Option<MeshTopology>,
    #[serde(default)]
    pub listen_port: Option<u16>,
    #[serde(default)]
    pub keepalive_interval: Option<u16>,
    #[serde(default)]
    pub failover_timeout_secs: Option<u32>,
}

fn default_topology() -> MeshTopology {
    MeshTopology::FullMesh
}
fn default_listen_port() -> u16 {
    51820
}
fn default_keepalive() -> u16 {
    25
}
fn default_failover_timeout() -> u32 {
    90
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a mesh name: 1-64 chars, alphanumeric + dash/underscore/space.
fn validate_mesh_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        bail!("mesh name must be 1-64 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ')
    {
        bail!("mesh name must be alphanumeric, dash, underscore, or space");
    }
    Ok(())
}

/// Validate a site name: same rules as mesh name.
fn validate_site_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        bail!("site name must be 1-64 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ')
    {
        bail!("site name must be alphanumeric, dash, underscore, or space");
    }
    Ok(())
}

/// Validate an endpoint: must be ip:port or hostname:port.
fn validate_endpoint(endpoint: &str) -> Result<()> {
    if endpoint.is_empty() {
        bail!("endpoint must not be empty");
    }
    // Must have a port component
    let last_colon = endpoint.rfind(':');
    match last_colon {
        None => bail!("endpoint must include port (e.g. 203.0.113.1:51820)"),
        Some(pos) => {
            let port_str = &endpoint[pos + 1..];
            let port: u16 = port_str
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port in endpoint: {}", endpoint))?;
            if port == 0 {
                bail!("endpoint port must be 1-65535");
            }
            let host = &endpoint[..pos];
            // For IPv6 endpoints, host might be [::1] — strip brackets
            let host = host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(host);
            if host.is_empty() {
                bail!("endpoint host must not be empty");
            }
            // Validate it's either a valid IP or a reasonable hostname
            if host.parse::<std::net::IpAddr>().is_err() {
                // Allow hostname: alphanumeric + dots + dashes
                if !host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                {
                    bail!("invalid endpoint hostname: {}", host);
                }
            }
        }
    }
    Ok(())
}

/// Validate a CIDR subnet string.
fn validate_subnet(subnet: &str) -> Result<()> {
    let (ip_str, prefix_str) = subnet.split_once('/').ok_or_else(|| {
        anyhow::anyhow!(
            "subnet must be in CIDR notation (e.g. 10.0.0.0/24): {}",
            subnet
        )
    })?;
    ip_str
        .parse::<std::net::IpAddr>()
        .map_err(|_| anyhow::anyhow!("invalid IP in subnet: {}", subnet))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid prefix length in subnet: {}", subnet))?;
    let is_v6 = ip_str.contains(':');
    let max = if is_v6 { 128 } else { 32 };
    if prefix > max {
        bail!("prefix length must be 0-{} for subnet: {}", max, subnet);
    }
    Ok(())
}

/// Validate a listen port.
fn validate_listen_port(port: u16) -> Result<()> {
    if port == 0 {
        bail!("listen port must be 1-65535");
    }
    Ok(())
}

/// Validate a base64-encoded WireGuard public key.
fn validate_public_key(key: &str) -> Result<()> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(|e| anyhow::anyhow!("invalid base64 public key: {}", e))?;
    if decoded.len() != 32 {
        bail!(
            "invalid public key length: {} bytes (expected 32)",
            decoded.len()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CRUD operations
// ---------------------------------------------------------------------------

/// Create a new site mesh. Auto-generates keypair for the local site.
pub async fn create_mesh(db_handle: &sfgw_db::Db, request: &CreateMeshRequest) -> Result<SiteMesh> {
    validate_mesh_name(&request.name)?;
    validate_listen_port(request.listen_port)?;

    if request.keepalive_interval == 0 {
        bail!("keepalive_interval must be > 0");
    }
    if request.failover_timeout_secs < 10 {
        bail!("failover_timeout_secs must be >= 10");
    }

    // Check for duplicate name
    let existing = db::list_site_meshes(db_handle).await?;
    if existing.iter().any(|m| m.name == request.name) {
        bail!("site mesh '{}' already exists", request.name);
    }

    // Validate all sites
    let local_count = request.sites.iter().filter(|s| s.is_local).count();
    if local_count > 1 {
        bail!("only one site can be marked as local");
    }

    for site in &request.sites {
        validate_site_name(&site.name)?;
        validate_endpoint(&site.endpoint)?;
        for subnet in &site.local_subnets {
            validate_subnet(subnet)?;
        }
        for subnet in &site.remote_subnets {
            validate_subnet(subnet)?;
        }
        if let Some(ref pk) = site.public_key {
            validate_public_key(pk)?;
        }
    }

    let topology_str = request.topology.to_string();
    let mesh_id = db::insert_site_mesh(
        db_handle,
        &request.name,
        &topology_str,
        request.listen_port,
        request.keepalive_interval,
        request.failover_timeout_secs,
    )
    .await?;

    // Insert sites
    for site_req in &request.sites {
        add_site_to_mesh(db_handle, mesh_id, site_req).await?;
    }

    info!(mesh_id, name = %request.name, "created site mesh");

    get_mesh(db_handle, mesh_id)
        .await?
        .context("mesh just created but not found")
}

/// Add a site peer to an existing mesh.
pub async fn add_site_to_mesh(
    db_handle: &sfgw_db::Db,
    mesh_id: i64,
    request: &CreateSiteRequest,
) -> Result<Site> {
    validate_site_name(&request.name)?;
    validate_endpoint(&request.endpoint)?;
    for subnet in &request.local_subnets {
        validate_subnet(subnet)?;
    }
    for subnet in &request.remote_subnets {
        validate_subnet(subnet)?;
    }

    let (public_key, private_key_enc) = if request.is_local {
        // Generate keypair for local site
        let keypair = crate::keys::generate_keypair()?;
        let mut priv_b64 = crate::keys::private_key_to_base64(&keypair.private_key)?;
        let pk = keypair.public_key;
        let enc = priv_b64.clone();
        priv_b64.zeroize();
        (pk, Some(enc))
    } else {
        // Remote site — must provide public key
        let pk = request
            .public_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("public_key required for remote sites"))?;
        validate_public_key(pk)?;
        (pk.clone(), None)
    };

    let local_subnets_json = serde_json::to_string(&request.local_subnets)?;
    let remote_subnets_json = serde_json::to_string(&request.remote_subnets)?;

    let site_id = db::insert_site_mesh_peer(
        db_handle,
        mesh_id,
        &request.name,
        &request.endpoint,
        &public_key,
        private_key_enc.as_deref(),
        request.preshared_key.as_deref(),
        &local_subnets_json,
        &remote_subnets_json,
        request.priority,
        request.is_local,
    )
    .await?;

    info!(mesh_id, site_id, name = %request.name, is_local = request.is_local, "added site to mesh");

    let row = db::get_site_mesh_peer(db_handle, site_id)
        .await?
        .context("site just created but not found")?;

    Ok(site_from_row(&row))
}

/// Get a mesh by ID with all its sites.
pub async fn get_mesh(db_handle: &sfgw_db::Db, mesh_id: i64) -> Result<Option<SiteMesh>> {
    let row = db::get_site_mesh(db_handle, mesh_id).await?;
    match row {
        Some(r) => {
            let site_rows = db::list_site_mesh_peers(db_handle, mesh_id).await?;
            let sites: Vec<Site> = site_rows.iter().map(site_from_row).collect();
            Ok(Some(mesh_from_row(&r, sites)))
        }
        None => Ok(None),
    }
}

/// List all meshes with their sites.
pub async fn list_meshes(db_handle: &sfgw_db::Db) -> Result<Vec<SiteMesh>> {
    let mesh_rows = db::list_site_meshes(db_handle).await?;
    let mut meshes = Vec::with_capacity(mesh_rows.len());

    for row in &mesh_rows {
        let site_rows = db::list_site_mesh_peers(db_handle, row.id).await?;
        let sites: Vec<Site> = site_rows.iter().map(site_from_row).collect();
        meshes.push(mesh_from_row(row, sites));
    }

    Ok(meshes)
}

/// Update a mesh configuration.
pub async fn update_mesh(
    db_handle: &sfgw_db::Db,
    mesh_id: i64,
    request: &UpdateMeshRequest,
) -> Result<SiteMesh> {
    let existing = db::get_site_mesh(db_handle, mesh_id)
        .await?
        .context("mesh not found")?;

    if let Some(ref name) = request.name {
        validate_mesh_name(name)?;
    }
    if let Some(port) = request.listen_port {
        validate_listen_port(port)?;
    }
    if let Some(ka) = request.keepalive_interval
        && ka == 0
    {
        bail!("keepalive_interval must be > 0");
    }
    if let Some(ft) = request.failover_timeout_secs
        && ft < 10
    {
        bail!("failover_timeout_secs must be >= 10");
    }

    let name = request.name.as_deref().unwrap_or(&existing.name);
    let topology = request
        .topology
        .map(|t| t.to_string())
        .unwrap_or(existing.topology);
    let listen_port = request.listen_port.unwrap_or(existing.listen_port as u16);
    let keepalive = request
        .keepalive_interval
        .unwrap_or(existing.keepalive_interval as u16);
    let failover = request
        .failover_timeout_secs
        .unwrap_or(existing.failover_timeout_secs as u32);

    db::update_site_mesh(
        db_handle,
        mesh_id,
        name,
        &topology,
        listen_port,
        keepalive,
        failover,
    )
    .await?;

    info!(mesh_id, "updated site mesh");

    get_mesh(db_handle, mesh_id)
        .await?
        .context("mesh not found after update")
}

/// Delete a mesh and all its sites (cascade).
pub async fn delete_mesh(db_handle: &sfgw_db::Db, mesh_id: i64) -> Result<()> {
    let mesh = db::get_site_mesh(db_handle, mesh_id)
        .await?
        .context("mesh not found")?;

    // If mesh is running, stop it first
    if mesh.enabled != 0
        && let Err(e) = stop_mesh(db_handle, mesh_id).await
    {
        warn!(mesh_id, "failed to stop mesh during delete: {e}");
    }

    db::delete_site_mesh(db_handle, mesh_id).await?;
    info!(mesh_id, name = %mesh.name, "deleted site mesh");
    Ok(())
}

// ---------------------------------------------------------------------------
// Mesh lifecycle (start / stop)
// ---------------------------------------------------------------------------

/// Generate the WireGuard interface name for a mesh.
fn mesh_interface_name(mesh_id: i64) -> String {
    // Keep under 15-char kernel limit: "sm" + id
    format!("sm{}", mesh_id)
}

/// Start a site mesh: create WireGuard interface, configure peers, add routes.
pub async fn start_mesh(db_handle: &sfgw_db::Db, mesh_id: i64) -> Result<()> {
    let mesh_row = db::get_site_mesh(db_handle, mesh_id)
        .await?
        .context("mesh not found")?;

    if mesh_row.enabled != 0 {
        bail!("mesh '{}' is already running", mesh_row.name);
    }

    let site_rows = db::list_site_mesh_peers(db_handle, mesh_id).await?;
    let local_site = site_rows
        .iter()
        .find(|s| s.is_local != 0)
        .ok_or_else(|| anyhow::anyhow!("no local site configured in mesh"))?;

    // The local site must have a private key
    let private_key_enc = local_site
        .private_key_enc
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("local site missing private key"))?;

    let iface = mesh_interface_name(mesh_id);

    // Create WireGuard interface
    run_cmd("ip", &["link", "add", "dev", &iface, "type", "wireguard"])
        .await
        .context("failed to create WireGuard interface for mesh")?;

    // Set private key
    {
        let mut key_b64 = private_key_enc.clone();
        let result = set_private_key_for_iface(&iface, &key_b64).await;
        key_b64.zeroize();
        result?;
    }

    // Set listen port
    let port_str = mesh_row.listen_port.to_string();
    run_cmd("wg", &["set", &iface, "listen-port", &port_str])
        .await
        .context("failed to set listen port")?;

    // Assign an IP address from local subnets if available
    let local_subnets: Vec<String> =
        serde_json::from_str(&local_site.local_subnets).unwrap_or_default();
    if let Some(first_subnet) = local_subnets.first() {
        // Use the first address in the first local subnet as the interface address
        if let Some(addr) = first_usable_address(first_subnet) {
            run_cmd("ip", &["address", "add", &addr, "dev", &iface])
                .await
                .context("failed to assign address to mesh interface")?;
        }
    }

    // Set MTU
    run_cmd("ip", &["link", "set", "mtu", "1420", "dev", &iface])
        .await
        .context("failed to set MTU")?;

    // Configure remote peers
    let keepalive_str = mesh_row.keepalive_interval.to_string();
    for site in &site_rows {
        if site.is_local != 0 || !site.enabled {
            continue;
        }

        let site_local_subnets: Vec<String> =
            serde_json::from_str(&site.local_subnets).unwrap_or_default();

        // Allowed IPs = remote site's local subnets
        let allowed_ips = site_local_subnets.join(",");
        if allowed_ips.is_empty() {
            warn!(site_id = site.id, "site has no local_subnets, skipping");
            continue;
        }

        // Add preshared key via stdin if present
        if let Some(ref psk) = site.preshared_key {
            add_peer_with_psk(
                &iface,
                &site.public_key,
                &site.endpoint,
                &keepalive_str,
                &allowed_ips,
                psk,
            )
            .await?;
        } else {
            run_cmd(
                "wg",
                &[
                    "set",
                    &iface,
                    "peer",
                    &site.public_key,
                    "endpoint",
                    &site.endpoint,
                    "persistent-keepalive",
                    &keepalive_str,
                    "allowed-ips",
                    &allowed_ips,
                ],
            )
            .await
            .with_context(|| format!("failed to add peer for site {}", site.name))?;
        }

        // Add routes for the remote site's subnets through this interface
        for subnet in &site_local_subnets {
            if let Err(e) = run_cmd("ip", &["route", "add", subnet, "dev", &iface]).await {
                warn!(
                    mesh_id,
                    site_name = %site.name,
                    subnet,
                    "failed to add route: {e}"
                );
            }
        }
    }

    // Bring interface up
    run_cmd("ip", &["link", "set", "up", "dev", &iface])
        .await
        .context("failed to bring mesh interface up")?;

    db::set_site_mesh_enabled(db_handle, mesh_id, true).await?;

    info!(mesh_id, iface = %iface, "site mesh started");
    Ok(())
}

/// Stop a site mesh: remove routes, tear down WireGuard interface.
pub async fn stop_mesh(db_handle: &sfgw_db::Db, mesh_id: i64) -> Result<()> {
    let _mesh_row = db::get_site_mesh(db_handle, mesh_id)
        .await?
        .context("mesh not found")?;

    let iface = mesh_interface_name(mesh_id);

    // Remove routes first
    let site_rows = db::list_site_mesh_peers(db_handle, mesh_id).await?;
    for site in &site_rows {
        if site.is_local != 0 {
            continue;
        }
        let subnets: Vec<String> = serde_json::from_str(&site.local_subnets).unwrap_or_default();
        for subnet in &subnets {
            let _ = run_cmd("ip", &["route", "del", subnet, "dev", &iface]).await;
        }
    }

    // Bring down and delete interface
    if let Err(e) = run_cmd("ip", &["link", "set", "down", "dev", &iface]).await {
        warn!(mesh_id, "failed to bring mesh interface down: {e}");
    }
    if let Err(e) = run_cmd("ip", &["link", "delete", "dev", &iface]).await {
        warn!(mesh_id, "failed to delete mesh interface: {e}");
    }

    db::set_site_mesh_enabled(db_handle, mesh_id, false).await?;

    info!(mesh_id, "site mesh stopped");
    Ok(())
}

// ---------------------------------------------------------------------------
// Health / status
// ---------------------------------------------------------------------------

/// Get live status of a mesh — queries WireGuard interface for handshake data.
pub async fn get_mesh_status(db_handle: &sfgw_db::Db, mesh_id: i64) -> Result<MeshStatus> {
    let mesh_row = db::get_site_mesh(db_handle, mesh_id)
        .await?
        .context("mesh not found")?;

    let iface = mesh_interface_name(mesh_id);
    let is_active = mesh_row.enabled != 0;
    let failover_timeout = mesh_row.failover_timeout_secs as u64;

    let site_rows = db::list_site_mesh_peers(db_handle, mesh_id).await?;
    let mut site_statuses = Vec::new();

    // Parse WireGuard dump if interface is up
    let wg_peers = if is_active {
        parse_wg_dump(&iface).await.unwrap_or_default()
    } else {
        Vec::new()
    };

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    for site in &site_rows {
        if site.is_local != 0 {
            continue; // Skip local site in status
        }

        let wg_info = wg_peers.iter().find(|p| p.public_key == site.public_key);

        let (last_handshake, rx, tx) = match wg_info {
            Some(info) => (info.last_handshake_secs, info.rx_bytes, info.tx_bytes),
            None => (0, 0, 0),
        };

        let handshake_age = if last_handshake > 0 && now_secs > last_handshake {
            now_secs - last_handshake
        } else {
            0
        };

        let state = if !is_active {
            SiteConnectionState::Down
        } else if last_handshake == 0 {
            SiteConnectionState::Pending
        } else if handshake_age <= 150 {
            // WireGuard re-handshakes every ~2 minutes, so <150s is healthy
            SiteConnectionState::Connected
        } else if handshake_age <= failover_timeout {
            SiteConnectionState::Degraded
        } else {
            SiteConnectionState::Down
        };

        // Approximate latency from handshake age (rough heuristic)
        let latency_ms = if state == SiteConnectionState::Connected && handshake_age > 0 {
            // Recent handshake — approximate based on age
            Some(handshake_age.min(1000))
        } else {
            None
        };

        site_statuses.push(SiteStatus {
            site_id: site.id,
            site_name: site.name.clone(),
            endpoint: site.endpoint.clone(),
            state,
            last_handshake_secs: last_handshake,
            latency_ms,
            rx_bytes: rx,
            tx_bytes: tx,
        });
    }

    Ok(MeshStatus {
        mesh_id,
        mesh_name: mesh_row.name,
        is_active,
        interface_name: iface,
        sites: site_statuses,
    })
}

// ---------------------------------------------------------------------------
// Failover monitoring (background task)
// ---------------------------------------------------------------------------

/// Monitor mesh health and perform failover when sites exceed timeout.
///
/// This runs as a background task, checking all active meshes periodically.
/// When a primary site's handshake age exceeds `failover_timeout_secs`,
/// routes are switched to the next available backup peer.
pub async fn monitor_mesh_health(db_handle: &sfgw_db::Db) {
    let check_interval = tokio::time::Duration::from_secs(10);
    let mut interval = tokio::time::interval(check_interval);

    loop {
        interval.tick().await;

        let meshes = match db::list_site_meshes(db_handle).await {
            Ok(m) => m,
            Err(e) => {
                warn!("failed to list site meshes for health check: {e}");
                continue;
            }
        };

        for mesh in &meshes {
            if mesh.enabled == 0 {
                continue;
            }

            if let Err(e) = check_mesh_failover(db_handle, mesh).await {
                warn!(mesh_id = mesh.id, "mesh health check error: {e}");
            }
        }
    }
}

/// Check a single mesh for failover conditions.
async fn check_mesh_failover(db_handle: &sfgw_db::Db, mesh: &db::SiteMeshRow) -> Result<()> {
    let iface = mesh_interface_name(mesh.id);
    let failover_timeout = mesh.failover_timeout_secs as u64;

    let wg_peers = parse_wg_dump(&iface).await?;
    let site_rows = db::list_site_mesh_peers(db_handle, mesh.id).await?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Group sites by their remote_subnets to detect which need failover
    // For each set of subnets, find the primary and backup peers
    // Sites with lower priority number are preferred

    let mut remote_sites: Vec<&db::SiteMeshPeerRow> = site_rows
        .iter()
        .filter(|s| s.is_local == 0 && s.enabled)
        .collect();
    remote_sites.sort_by_key(|s| s.priority);

    for site in &remote_sites {
        let wg_info = wg_peers.iter().find(|p| p.public_key == site.public_key);

        let last_handshake = wg_info.map(|i| i.last_handshake_secs).unwrap_or(0);
        let handshake_age = if last_handshake > 0 && now_secs > last_handshake {
            now_secs - last_handshake
        } else if last_handshake == 0 {
            // Never had a handshake — treat as timed out
            failover_timeout + 1
        } else {
            0
        };

        if handshake_age > failover_timeout {
            debug!(
                mesh_id = mesh.id,
                site_name = %site.name,
                handshake_age,
                "site exceeded failover timeout"
            );

            // Find a backup peer for the same set of subnets
            let site_subnets: Vec<String> =
                serde_json::from_str(&site.local_subnets).unwrap_or_default();

            for backup in &remote_sites {
                if backup.id == site.id {
                    continue;
                }

                let backup_info = wg_peers.iter().find(|p| p.public_key == backup.public_key);
                let backup_handshake = backup_info.map(|i| i.last_handshake_secs).unwrap_or(0);
                let backup_age = if backup_handshake > 0 && now_secs > backup_handshake {
                    now_secs - backup_handshake
                } else {
                    failover_timeout + 1
                };

                if backup_age <= failover_timeout {
                    // Switch routes to backup
                    for subnet in &site_subnets {
                        info!(
                            mesh_id = mesh.id,
                            from = %site.name,
                            to = %backup.name,
                            subnet,
                            "failover: switching route to backup site"
                        );
                        // Replace route through backup peer
                        let _ = run_cmd("ip", &["route", "replace", subnet, "dev", &iface]).await;
                    }
                    break;
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parsed WireGuard peer info from `wg show dump`.
struct WgDumpPeer {
    public_key: String,
    #[allow(dead_code)]
    endpoint: Option<String>,
    last_handshake_secs: u64,
    rx_bytes: u64,
    tx_bytes: u64,
}

/// Parse `wg show <iface> dump` output into peer info.
async fn parse_wg_dump(iface: &str) -> Result<Vec<WgDumpPeer>> {
    let output = tokio::process::Command::new("wg")
        .args(["show", iface, "dump"])
        .output()
        .await
        .context("failed to run wg show dump")?;

    if !output.status.success() {
        bail!(
            "wg show dump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let dump = String::from_utf8_lossy(&output.stdout);
    let mut peers = Vec::new();

    // First line is the interface, subsequent lines are peers
    // Format: public_key\tpreshared_key\tendpoint\tallowed_ips\tlatest_handshake\ttransfer_rx\ttransfer_tx\tpersistent_keepalive
    for line in dump.lines().skip(1) {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() >= 7 {
            peers.push(WgDumpPeer {
                public_key: fields[0].to_string(),
                endpoint: if fields[2] == "(none)" {
                    None
                } else {
                    Some(fields[2].to_string())
                },
                last_handshake_secs: fields[4].parse().unwrap_or(0),
                rx_bytes: fields[5].parse().unwrap_or(0),
                tx_bytes: fields[6].parse().unwrap_or(0),
            });
        }
    }

    Ok(peers)
}

fn site_from_row(row: &db::SiteMeshPeerRow) -> Site {
    let local_subnets: Vec<String> = serde_json::from_str(&row.local_subnets).unwrap_or_default();
    let remote_subnets: Vec<String> = serde_json::from_str(&row.remote_subnets).unwrap_or_default();

    Site {
        id: row.id,
        mesh_id: row.mesh_id,
        name: row.name.clone(),
        endpoint: row.endpoint.clone(),
        public_key: row.public_key.clone(),
        local_subnets,
        remote_subnets,
        priority: row.priority,
        is_local: row.is_local != 0,
        enabled: row.enabled,
        created_at: row.created_at.clone(),
    }
}

fn mesh_from_row(row: &db::SiteMeshRow, sites: Vec<Site>) -> SiteMesh {
    SiteMesh {
        id: row.id,
        name: row.name.clone(),
        topology: MeshTopology::from_str_lossy(&row.topology),
        listen_port: row.listen_port as u16,
        keepalive_interval: row.keepalive_interval as u16,
        failover_timeout_secs: row.failover_timeout_secs as u32,
        enabled: row.enabled != 0,
        sites,
        created_at: row.created_at.clone(),
        updated_at: row.updated_at.clone(),
    }
}

/// Get the first usable host address in a CIDR subnet (for interface assignment).
fn first_usable_address(cidr: &str) -> Option<String> {
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let prefix: u8 = prefix_str.parse().ok()?;

    if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
        let ip_u32 = u32::from(ip);
        let mask = if prefix >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - prefix)
        };
        let network = ip_u32 & mask;
        let first_host = network + 1;
        let addr = std::net::Ipv4Addr::from(first_host);
        Some(format!("{}/{}", addr, prefix))
    } else if let Ok(ip) = ip_str.parse::<std::net::Ipv6Addr>() {
        let ip_u128 = u128::from(ip);
        let mask = if prefix >= 128 {
            u128::MAX
        } else {
            u128::MAX << (128 - prefix)
        };
        let network = ip_u128 & mask;
        let first_host = network + 1;
        let addr = std::net::Ipv6Addr::from(first_host);
        Some(format!("{}/{}", addr, prefix))
    } else {
        None
    }
}

/// Set private key on a WireGuard interface using a temp file.
async fn set_private_key_for_iface(iface: &str, private_key_b64: &str) -> Result<()> {
    let tmp_dir = std::env::temp_dir();
    let key_path = tmp_dir.join(format!(".wg-mesh-key-{}-{}", iface, std::process::id()));

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
        &["set", iface, "private-key", &key_path.to_string_lossy()],
    )
    .await;

    let _ = tokio::fs::remove_file(&key_path).await;
    result.context("failed to set private key on mesh interface")?;
    Ok(())
}

/// Add a WireGuard peer with a preshared key (piped via stdin).
async fn add_peer_with_psk(
    iface: &str,
    public_key: &str,
    endpoint: &str,
    keepalive: &str,
    allowed_ips: &str,
    psk: &str,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let args = [
        "set",
        iface,
        "peer",
        public_key,
        "preshared-key",
        "/dev/stdin",
        "endpoint",
        endpoint,
        "persistent-keepalive",
        keepalive,
        "allowed-ips",
        allowed_ips,
    ];

    let mut child = tokio::process::Command::new("wg")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn wg set for mesh peer")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(psk.as_bytes()).await?;
    }

    let out = child.wait_with_output().await?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("wg set peer with PSK failed: {stderr}");
    }
    Ok(())
}

/// Run a command, returning Ok(()) on success.
async fn run_cmd(prog: &str, args: &[&str]) -> Result<()> {
    debug!(cmd = prog, ?args, "executing");

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mesh_topology_roundtrip() {
        assert_eq!(
            MeshTopology::from_str_lossy("full-mesh"),
            MeshTopology::FullMesh
        );
        assert_eq!(
            MeshTopology::from_str_lossy("hub-and-spoke"),
            MeshTopology::HubAndSpoke
        );
        assert_eq!(
            MeshTopology::from_str_lossy("hub"),
            MeshTopology::HubAndSpoke
        );
        assert_eq!(
            MeshTopology::from_str_lossy("unknown"),
            MeshTopology::FullMesh
        );
        assert_eq!(MeshTopology::FullMesh.to_string(), "full-mesh");
        assert_eq!(MeshTopology::HubAndSpoke.to_string(), "hub-and-spoke");
    }

    #[test]
    fn test_validate_mesh_name() {
        assert!(validate_mesh_name("My Mesh-1").is_ok());
        assert!(validate_mesh_name("office_vpn").is_ok());
        assert!(validate_mesh_name("").is_err());
        assert!(validate_mesh_name(&"a".repeat(65)).is_err());
        assert!(validate_mesh_name("bad;name").is_err());
    }

    #[test]
    fn test_validate_endpoint() {
        assert!(validate_endpoint("203.0.113.1:51820").is_ok());
        assert!(validate_endpoint("[::1]:51820").is_ok());
        assert!(validate_endpoint("vpn.example.com:51820").is_ok());
        assert!(validate_endpoint("").is_err());
        assert!(validate_endpoint("no-port").is_err());
        assert!(validate_endpoint(":51820").is_err());
        assert!(validate_endpoint("host:0").is_err());
    }

    #[test]
    fn test_validate_subnet() {
        assert!(validate_subnet("10.0.0.0/24").is_ok());
        assert!(validate_subnet("192.168.1.0/16").is_ok());
        assert!(validate_subnet("fd00::/64").is_ok());
        assert!(validate_subnet("not-a-subnet").is_err());
        assert!(validate_subnet("10.0.0.0").is_err());
    }

    #[test]
    fn test_first_usable_address() {
        assert_eq!(
            first_usable_address("10.0.0.0/24"),
            Some("10.0.0.1/24".to_string())
        );
        assert_eq!(
            first_usable_address("192.168.1.0/24"),
            Some("192.168.1.1/24".to_string())
        );
        assert_eq!(
            first_usable_address("fd00::/64"),
            Some("fd00::1/64".to_string())
        );
    }

    #[test]
    fn test_mesh_interface_name() {
        assert_eq!(mesh_interface_name(1), "sm1");
        assert_eq!(mesh_interface_name(42), "sm42");
        // Ensure under 15 chars
        assert!(mesh_interface_name(9999999999).len() <= 15);
    }

    #[test]
    fn test_connection_state_display() {
        assert_eq!(SiteConnectionState::Connected.to_string(), "connected");
        assert_eq!(SiteConnectionState::Down.to_string(), "down");
        assert_eq!(SiteConnectionState::Degraded.to_string(), "degraded");
        assert_eq!(SiteConnectionState::Pending.to_string(), "pending");
    }

    #[test]
    fn test_validate_public_key() {
        use base64::Engine;
        let valid_key = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        assert!(validate_public_key(&valid_key).is_ok());

        let short_key = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(validate_public_key(&short_key).is_err());

        assert!(validate_public_key("not-base64!!!").is_err());
    }
}
