// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Thread-safe handle to the SQLite database.
pub type Db = Arc<Mutex<Connection>>;

/// Default database path.
const DEFAULT_DB_PATH: &str = "/var/lib/sfgw/sfgw.db";

/// Environment variable to override DB path (useful for Docker/dev).
const DB_PATH_ENV: &str = "SFGW_DB_PATH";

/// Open the database (or create it with the initial schema).
pub async fn open_or_create() -> Result<Db> {
    let db_path = std::env::var(DB_PATH_ENV).unwrap_or_else(|_| DEFAULT_DB_PATH.to_string());

    // Ensure parent directory exists
    if let Some(parent) = std::path::Path::new(&db_path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create db directory: {}", parent.display()))?;
    }

    let conn = Connection::open(&db_path)
        .with_context(|| format!("failed to open database: {db_path}"))?;

    // WAL mode for concurrent reads
    conn.pragma_update(None, "journal_mode", "WAL")?;
    // Enforce foreign keys
    conn.pragma_update(None, "foreign_keys", "ON")?;

    init_schema(&conn)?;

    tracing::info!("database opened: {db_path}");
    Ok(Arc::new(Mutex::new(conn)))
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS interfaces (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT NOT NULL UNIQUE,
            role      TEXT NOT NULL DEFAULT 'lan',
            vlan_id   INTEGER,
            enabled   INTEGER NOT NULL DEFAULT 1,
            config    TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS firewall_rules (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            chain     TEXT NOT NULL,
            priority  INTEGER NOT NULL DEFAULT 0,
            rule      TEXT NOT NULL,
            enabled   INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS devices (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            mac        TEXT NOT NULL UNIQUE,
            name       TEXT,
            model      TEXT,
            ip         TEXT,
            adopted    INTEGER NOT NULL DEFAULT 0,
            last_seen  TEXT,
            config     TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS vpn_tunnels (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT NOT NULL UNIQUE,
            type      TEXT NOT NULL,
            enabled   INTEGER NOT NULL DEFAULT 0,
            config    TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'admin',
            created_at    TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token         TEXT PRIMARY KEY,
            user_id       INTEGER NOT NULL REFERENCES users(id),
            tls_session   TEXT NOT NULL,
            client_ip     TEXT NOT NULL,
            fingerprint   TEXT NOT NULL,
            envelope_key  TEXT NOT NULL,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ids_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            severity    TEXT NOT NULL,
            detector    TEXT NOT NULL,
            source_mac  TEXT,
            source_ip   TEXT,
            interface   TEXT NOT NULL,
            vlan        INTEGER,
            description TEXT NOT NULL
        );

        -- Set schema version
        INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '1');
        ",
    )
    .context("failed to initialize database schema")?;

    Ok(())
}
