// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database operations for VPN tunnels.
//!
//! Works with the `vpn_tunnels` table defined in sfgw-db's schema.

use anyhow::{Context, Result};

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

/// Delete a tunnel by ID.
pub async fn delete_tunnel(db: &sfgw_db::Db, id: i64) -> Result<()> {
    let db = db.lock().await;
    db.execute(
        "DELETE FROM vpn_tunnels WHERE id = ?1",
        rusqlite::params![id],
    )
    .context("failed to delete tunnel")?;
    Ok(())
}

/// Helper trait — rusqlite `query_row` returns Err on no rows; we want Option.
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
