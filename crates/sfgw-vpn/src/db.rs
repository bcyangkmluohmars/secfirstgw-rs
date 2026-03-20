// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database operations for VPN tunnels and peers.
//!
//! Works with the `vpn_tunnels` and `vpn_peers` tables.

use anyhow::{Context, Result};

// ---------------------------------------------------------------------------
// Tunnel rows
// ---------------------------------------------------------------------------

/// A raw row from the `vpn_tunnels` table.
pub struct TunnelRow {
    pub id: i64,
    pub name: String,
    pub tunnel_type: String,
    pub enabled: i64,
    pub config: String,
}

/// Insert a new tunnel, returning its assigned ID.
pub async fn insert_tunnel(
    db: &sfgw_db::Db,
    name: &str,
    tunnel_type: &str,
    config_json: &str,
) -> Result<i64> {
    let db = db.lock().await;
    db.execute(
        "INSERT INTO vpn_tunnels (name, type, enabled, config) VALUES (?1, ?2, 0, ?3)",
        rusqlite::params![name, tunnel_type, config_json],
    )
    .context("failed to insert tunnel")?;
    Ok(db.last_insert_rowid())
}

/// Look up a tunnel by name.
pub async fn get_tunnel_by_name(db: &sfgw_db::Db, name: &str) -> Result<Option<TunnelRow>> {
    let db = db.lock().await;
    let mut stmt = db
        .prepare("SELECT id, name, type, enabled, config FROM vpn_tunnels WHERE name = ?1")
        .context("failed to prepare query")?;

    let row = stmt
        .query_row(rusqlite::params![name], |row| {
            Ok(TunnelRow {
                id: row.get(0)?,
                name: row.get(1)?,
                tunnel_type: row.get(2)?,
                enabled: row.get(3)?,
                config: row.get(4)?,
            })
        })
        .optional()
        .context("failed to query tunnel")?;

    Ok(row)
}

/// Look up a tunnel by ID.
pub async fn get_tunnel_by_id(db: &sfgw_db::Db, id: i64) -> Result<Option<TunnelRow>> {
    let db = db.lock().await;
    let mut stmt = db
        .prepare("SELECT id, name, type, enabled, config FROM vpn_tunnels WHERE id = ?1")
        .context("failed to prepare query")?;

    let row = stmt
        .query_row(rusqlite::params![id], |row| {
            Ok(TunnelRow {
                id: row.get(0)?,
                name: row.get(1)?,
                tunnel_type: row.get(2)?,
                enabled: row.get(3)?,
                config: row.get(4)?,
            })
        })
        .optional()
        .context("failed to query tunnel")?;

    Ok(row)
}

/// List all tunnels.
pub async fn list_tunnels(db: &sfgw_db::Db) -> Result<Vec<TunnelRow>> {
    let db = db.lock().await;
    let mut stmt = db
        .prepare("SELECT id, name, type, enabled, config FROM vpn_tunnels ORDER BY id")
        .context("failed to prepare query")?;

    let rows = stmt
        .query_map([], |row| {
            Ok(TunnelRow {
                id: row.get(0)?,
                name: row.get(1)?,
                tunnel_type: row.get(2)?,
                enabled: row.get(3)?,
                config: row.get(4)?,
            })
        })
        .context("failed to query tunnels")?
        .collect::<Result<Vec<_>, _>>()
        .context("failed to read tunnel rows")?;

    Ok(rows)
}

/// Update the enabled flag for a tunnel.
pub async fn set_tunnel_enabled(db: &sfgw_db::Db, id: i64, enabled: bool) -> Result<()> {
    let db = db.lock().await;
    db.execute(
        "UPDATE vpn_tunnels SET enabled = ?1 WHERE id = ?2",
        rusqlite::params![enabled as i64, id],
    )
    .context("failed to update tunnel enabled state")?;
    Ok(())
}

/// Update the config JSON for a tunnel.
pub async fn update_tunnel_config(db: &sfgw_db::Db, id: i64, config_json: &str) -> Result<()> {
    let db = db.lock().await;
    db.execute(
        "UPDATE vpn_tunnels SET config = ?1 WHERE id = ?2",
        rusqlite::params![config_json, id],
    )
    .context("failed to update tunnel config")?;
    Ok(())
}

/// Delete a tunnel by ID. Peers are cascade-deleted by FK constraint.
pub async fn delete_tunnel(db: &sfgw_db::Db, id: i64) -> Result<()> {
    let db = db.lock().await;
    db.execute(
        "DELETE FROM vpn_tunnels WHERE id = ?1",
        rusqlite::params![id],
    )
    .context("failed to delete tunnel")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Peer rows
// ---------------------------------------------------------------------------

/// A raw row from the `vpn_peers` table.
pub struct PeerRow {
    pub id: i64,
    pub tunnel_id: i64,
    pub name: Option<String>,
    pub public_key: String,
    pub private_key_enc: String,
    pub preshared_key: Option<String>,
    pub address: String,
    pub address_v6: Option<String>,
    pub allowed_ips_json: String,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<i64>,
    pub routing_mode: String,
    pub dns: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

fn map_peer_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PeerRow> {
    Ok(PeerRow {
        id: row.get(0)?,
        tunnel_id: row.get(1)?,
        name: row.get(2)?,
        public_key: row.get(3)?,
        private_key_enc: row.get(4)?,
        preshared_key: row.get(5)?,
        address: row.get(6)?,
        address_v6: row.get(7)?,
        allowed_ips_json: row.get(8)?,
        endpoint: row.get(9)?,
        persistent_keepalive: row.get(10)?,
        routing_mode: row.get(11)?,
        dns: row.get(12)?,
        enabled: row.get::<_, i64>(13)? != 0,
        created_at: row.get(14)?,
    })
}

const PEER_COLUMNS: &str = "id, tunnel_id, name, public_key, private_key_enc, \
    preshared_key, address, address_v6, allowed_ips, endpoint, \
    persistent_keepalive, routing_mode, dns, enabled, created_at";

/// Insert a new peer, returning its ID.
#[allow(clippy::too_many_arguments)]
pub async fn insert_peer(
    db: &sfgw_db::Db,
    tunnel_id: i64,
    name: Option<&str>,
    public_key: &str,
    private_key_enc: &str,
    preshared_key: Option<&str>,
    address: &str,
    address_v6: Option<&str>,
    allowed_ips_json: &str,
    endpoint: Option<&str>,
    persistent_keepalive: Option<u16>,
    routing_mode: &str,
    dns: Option<&str>,
) -> Result<i64> {
    let db = db.lock().await;
    db.execute(
        "INSERT INTO vpn_peers (tunnel_id, name, public_key, private_key_enc, \
         preshared_key, address, address_v6, allowed_ips, endpoint, \
         persistent_keepalive, routing_mode, dns) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        rusqlite::params![
            tunnel_id,
            name,
            public_key,
            private_key_enc,
            preshared_key,
            address,
            address_v6,
            allowed_ips_json,
            endpoint,
            persistent_keepalive.map(|v| v as i64),
            routing_mode,
            dns,
        ],
    )
    .context("failed to insert peer")?;
    Ok(db.last_insert_rowid())
}

/// List all peers for a tunnel.
pub async fn list_peers(db: &sfgw_db::Db, tunnel_id: i64) -> Result<Vec<PeerRow>> {
    let db = db.lock().await;
    let mut stmt = db
        .prepare(&format!(
            "SELECT {PEER_COLUMNS} FROM vpn_peers WHERE tunnel_id = ?1 ORDER BY id"
        ))
        .context("failed to prepare peers query")?;

    let rows = stmt
        .query_map(rusqlite::params![tunnel_id], map_peer_row)
        .context("failed to query peers")?
        .collect::<Result<Vec<_>, _>>()
        .context("failed to read peer rows")?;

    Ok(rows)
}

/// Get a single peer by ID.
pub async fn get_peer_by_id(db: &sfgw_db::Db, peer_id: i64) -> Result<Option<PeerRow>> {
    let db = db.lock().await;
    let mut stmt = db
        .prepare(&format!(
            "SELECT {PEER_COLUMNS} FROM vpn_peers WHERE id = ?1"
        ))
        .context("failed to prepare peer query")?;

    let row = stmt
        .query_row(rusqlite::params![peer_id], map_peer_row)
        .optional()
        .context("failed to query peer")?;

    Ok(row)
}

/// Get a peer by tunnel ID and peer ID (ensures the peer belongs to the tunnel).
pub async fn get_peer(db: &sfgw_db::Db, tunnel_id: i64, peer_id: i64) -> Result<Option<PeerRow>> {
    let db = db.lock().await;
    let mut stmt = db
        .prepare(&format!(
            "SELECT {PEER_COLUMNS} FROM vpn_peers WHERE id = ?1 AND tunnel_id = ?2"
        ))
        .context("failed to prepare peer query")?;

    let row = stmt
        .query_row(rusqlite::params![peer_id, tunnel_id], map_peer_row)
        .optional()
        .context("failed to query peer")?;

    Ok(row)
}

/// Delete a peer by ID.
pub async fn delete_peer(db: &sfgw_db::Db, peer_id: i64) -> Result<()> {
    let db = db.lock().await;
    let affected = db
        .execute(
            "DELETE FROM vpn_peers WHERE id = ?1",
            rusqlite::params![peer_id],
        )
        .context("failed to delete peer")?;
    anyhow::ensure!(affected == 1, "peer not found");
    Ok(())
}

/// Count peers in a tunnel (for address auto-assignment).
pub async fn count_peers(db: &sfgw_db::Db, tunnel_id: i64) -> Result<i64> {
    let db = db.lock().await;
    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM vpn_peers WHERE tunnel_id = ?1",
            rusqlite::params![tunnel_id],
            |row| row.get(0),
        )
        .context("failed to count peers")?;
    Ok(count)
}

/// Get all used peer addresses in a tunnel (for auto-assignment).
pub async fn used_addresses(db: &sfgw_db::Db, tunnel_id: i64) -> Result<Vec<String>> {
    let db = db.lock().await;
    let mut stmt = db
        .prepare("SELECT address FROM vpn_peers WHERE tunnel_id = ?1")
        .context("failed to prepare query")?;

    let addrs = stmt
        .query_map(rusqlite::params![tunnel_id], |row| row.get(0))
        .context("failed to query addresses")?
        .collect::<Result<Vec<String>, _>>()
        .context("failed to read addresses")?;

    Ok(addrs)
}

// ---------------------------------------------------------------------------
// Site mesh rows
// ---------------------------------------------------------------------------

/// A raw row from the `site_meshes` table.
pub struct SiteMeshRow {
    pub id: i64,
    pub name: String,
    pub topology: String,
    pub listen_port: i64,
    pub keepalive_interval: i64,
    pub failover_timeout_secs: i64,
    pub enabled: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// A raw row from the `site_mesh_peers` table.
pub struct SiteMeshPeerRow {
    pub id: i64,
    pub mesh_id: i64,
    pub name: String,
    pub endpoint: String,
    pub public_key: String,
    pub private_key_enc: Option<String>,
    pub preshared_key: Option<String>,
    pub local_subnets: String,
    pub remote_subnets: String,
    pub priority: i64,
    pub is_local: i64,
    pub enabled: bool,
    pub created_at: String,
}

fn map_mesh_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SiteMeshRow> {
    Ok(SiteMeshRow {
        id: row.get(0)?,
        name: row.get(1)?,
        topology: row.get(2)?,
        listen_port: row.get(3)?,
        keepalive_interval: row.get(4)?,
        failover_timeout_secs: row.get(5)?,
        enabled: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

const MESH_COLUMNS: &str = "id, name, topology, listen_port, keepalive_interval, \
    failover_timeout_secs, enabled, created_at, updated_at";

fn map_mesh_peer_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SiteMeshPeerRow> {
    Ok(SiteMeshPeerRow {
        id: row.get(0)?,
        mesh_id: row.get(1)?,
        name: row.get(2)?,
        endpoint: row.get(3)?,
        public_key: row.get(4)?,
        private_key_enc: row.get(5)?,
        preshared_key: row.get(6)?,
        local_subnets: row.get(7)?,
        remote_subnets: row.get(8)?,
        priority: row.get(9)?,
        is_local: row.get(10)?,
        enabled: row.get::<_, i64>(11)? != 0,
        created_at: row.get(12)?,
    })
}

const MESH_PEER_COLUMNS: &str = "id, mesh_id, name, endpoint, public_key, \
    private_key_enc, preshared_key, local_subnets, remote_subnets, \
    priority, is_local, enabled, created_at";

/// Insert a new site mesh, returning its ID.
pub async fn insert_site_mesh(
    db: &sfgw_db::Db,
    name: &str,
    topology: &str,
    listen_port: u16,
    keepalive_interval: u16,
    failover_timeout_secs: u32,
) -> Result<i64> {
    let db = db.lock().await;
    db.execute(
        "INSERT INTO site_meshes (name, topology, listen_port, keepalive_interval, failover_timeout_secs) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            name,
            topology,
            listen_port as i64,
            keepalive_interval as i64,
            failover_timeout_secs as i64,
        ],
    )
    .context("failed to insert site mesh")?;
    Ok(db.last_insert_rowid())
}

/// Get a site mesh by ID.
pub async fn get_site_mesh(db: &sfgw_db::Db, id: i64) -> Result<Option<SiteMeshRow>> {
    let db = db.lock().await;
    let mut stmt = db
        .prepare(&format!(
            "SELECT {MESH_COLUMNS} FROM site_meshes WHERE id = ?1"
        ))
        .context("failed to prepare site mesh query")?;

    let row = stmt
        .query_row(rusqlite::params![id], map_mesh_row)
        .optional()
        .context("failed to query site mesh")?;

    Ok(row)
}

/// List all site meshes.
pub async fn list_site_meshes(db: &sfgw_db::Db) -> Result<Vec<SiteMeshRow>> {
    let db = db.lock().await;
    let mut stmt = db
        .prepare(&format!(
            "SELECT {MESH_COLUMNS} FROM site_meshes ORDER BY id"
        ))
        .context("failed to prepare site meshes list query")?;

    let rows = stmt
        .query_map([], map_mesh_row)
        .context("failed to query site meshes")?
        .collect::<Result<Vec<_>, _>>()
        .context("failed to read site mesh rows")?;

    Ok(rows)
}

/// Update a site mesh.
pub async fn update_site_mesh(
    db: &sfgw_db::Db,
    id: i64,
    name: &str,
    topology: &str,
    listen_port: u16,
    keepalive_interval: u16,
    failover_timeout_secs: u32,
) -> Result<()> {
    let db = db.lock().await;
    db.execute(
        "UPDATE site_meshes SET name = ?1, topology = ?2, listen_port = ?3, \
         keepalive_interval = ?4, failover_timeout_secs = ?5, \
         updated_at = datetime('now') WHERE id = ?6",
        rusqlite::params![
            name,
            topology,
            listen_port as i64,
            keepalive_interval as i64,
            failover_timeout_secs as i64,
            id,
        ],
    )
    .context("failed to update site mesh")?;
    Ok(())
}

/// Set the enabled flag for a site mesh.
pub async fn set_site_mesh_enabled(db: &sfgw_db::Db, id: i64, enabled: bool) -> Result<()> {
    let db = db.lock().await;
    db.execute(
        "UPDATE site_meshes SET enabled = ?1, updated_at = datetime('now') WHERE id = ?2",
        rusqlite::params![enabled as i64, id],
    )
    .context("failed to update site mesh enabled state")?;
    Ok(())
}

/// Delete a site mesh. Peers are cascade-deleted by FK constraint.
pub async fn delete_site_mesh(db: &sfgw_db::Db, id: i64) -> Result<()> {
    let db = db.lock().await;
    db.execute(
        "DELETE FROM site_meshes WHERE id = ?1",
        rusqlite::params![id],
    )
    .context("failed to delete site mesh")?;
    Ok(())
}

/// Insert a site mesh peer, returning its ID.
#[allow(clippy::too_many_arguments)]
pub async fn insert_site_mesh_peer(
    db: &sfgw_db::Db,
    mesh_id: i64,
    name: &str,
    endpoint: &str,
    public_key: &str,
    private_key_enc: Option<&str>,
    preshared_key: Option<&str>,
    local_subnets: &str,
    remote_subnets: &str,
    priority: i64,
    is_local: bool,
) -> Result<i64> {
    let db = db.lock().await;
    db.execute(
        "INSERT INTO site_mesh_peers (mesh_id, name, endpoint, public_key, \
         private_key_enc, preshared_key, local_subnets, remote_subnets, priority, is_local) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            mesh_id,
            name,
            endpoint,
            public_key,
            private_key_enc,
            preshared_key,
            local_subnets,
            remote_subnets,
            priority,
            is_local as i64,
        ],
    )
    .context("failed to insert site mesh peer")?;
    Ok(db.last_insert_rowid())
}

/// Get a site mesh peer by ID.
pub async fn get_site_mesh_peer(db: &sfgw_db::Db, peer_id: i64) -> Result<Option<SiteMeshPeerRow>> {
    let db = db.lock().await;
    let mut stmt = db
        .prepare(&format!(
            "SELECT {MESH_PEER_COLUMNS} FROM site_mesh_peers WHERE id = ?1"
        ))
        .context("failed to prepare site mesh peer query")?;

    let row = stmt
        .query_row(rusqlite::params![peer_id], map_mesh_peer_row)
        .optional()
        .context("failed to query site mesh peer")?;

    Ok(row)
}

/// List all peers in a site mesh.
pub async fn list_site_mesh_peers(db: &sfgw_db::Db, mesh_id: i64) -> Result<Vec<SiteMeshPeerRow>> {
    let db = db.lock().await;
    let mut stmt = db
        .prepare(&format!(
            "SELECT {MESH_PEER_COLUMNS} FROM site_mesh_peers WHERE mesh_id = ?1 ORDER BY priority, id"
        ))
        .context("failed to prepare site mesh peers query")?;

    let rows = stmt
        .query_map(rusqlite::params![mesh_id], map_mesh_peer_row)
        .context("failed to query site mesh peers")?
        .collect::<Result<Vec<_>, _>>()
        .context("failed to read site mesh peer rows")?;

    Ok(rows)
}

/// Delete a site mesh peer by ID.
pub async fn delete_site_mesh_peer(db: &sfgw_db::Db, peer_id: i64) -> Result<()> {
    let db = db.lock().await;
    let affected = db
        .execute(
            "DELETE FROM site_mesh_peers WHERE id = ?1",
            rusqlite::params![peer_id],
        )
        .context("failed to delete site mesh peer")?;
    anyhow::ensure!(affected == 1, "site mesh peer not found");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper trait
// ---------------------------------------------------------------------------

trait OptionalRow<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalRow<T> for Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
