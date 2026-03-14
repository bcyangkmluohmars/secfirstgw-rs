// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Thread-safe handle to the SQLite database.
///
/// All crates share this type for database access. The `Mutex` ensures
/// only one writer at a time; SQLite WAL mode allows concurrent readers.
///
/// ```
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// let db = sfgw_db::open_in_memory().await.unwrap();
/// let conn = db.lock().await;
/// let version: String = conn
///     .query_row("SELECT value FROM meta WHERE key = 'schema_version'", [], |r| r.get(0))
///     .unwrap();
/// assert!(!version.is_empty());
/// # });
/// ```
pub type Db = Arc<Mutex<Connection>>;

/// Errors from the database layer.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// SQLite error.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    /// I/O error (e.g. creating directories).
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Migration or schema error with context.
    #[error("{context}: {source}")]
    Migration {
        context: String,
        source: rusqlite::Error,
    },

    /// Failed to open or create the database file.
    #[error("failed to open database at {path}: {source}")]
    Open {
        path: String,
        source: rusqlite::Error,
    },

    /// Failed to create the database directory.
    #[error("failed to create database directory {path}: {source}")]
    CreateDir {
        path: String,
        source: std::io::Error,
    },
}

/// Default database path.
const DEFAULT_DB_PATH: &str = "/var/lib/sfgw/sfgw.db";

/// Environment variable to override DB path (useful for Docker/dev).
const DB_PATH_ENV: &str = "SFGW_DB_PATH";

/// Open the database (or create it with the initial schema).
pub async fn open_or_create() -> Result<Db, DbError> {
    let db_path = std::env::var(DB_PATH_ENV).unwrap_or_else(|_| DEFAULT_DB_PATH.to_string());

    // Ensure parent directory exists
    if let Some(parent) = std::path::Path::new(&db_path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| DbError::CreateDir {
            path: parent.display().to_string(),
            source: e,
        })?;
    }

    let conn = Connection::open(&db_path).map_err(|e| DbError::Open {
        path: db_path.clone(),
        source: e,
    })?;

    // WAL mode for concurrent reads
    conn.pragma_update(None, "journal_mode", "WAL")?;
    // Enforce foreign keys
    conn.pragma_update(None, "foreign_keys", "ON")?;

    run_migrations(&conn)?;

    tracing::info!("database opened: {db_path}");
    Ok(Arc::new(Mutex::new(conn)))
}

/// Open an in-memory database with all migrations applied. Useful for testing.
///
/// ```
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// let db = sfgw_db::open_in_memory().await.unwrap();
/// let conn = db.lock().await;
///
/// // All tables exist after migrations
/// let has_interfaces: bool = conn
///     .query_row(
///         "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = 'interfaces'",
///         [],
///         |r| r.get(0),
///     )
///     .unwrap();
/// assert!(has_interfaces);
/// # });
/// ```
pub async fn open_in_memory() -> Result<Db, DbError> {
    let conn = Connection::open_in_memory()?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    run_migrations(&conn)?;
    Ok(Arc::new(Mutex::new(conn)))
}

/// Run all pending migrations.
fn run_migrations(conn: &Connection) -> Result<(), DbError> {
    // Bootstrap: ensure the meta table exists so we can track schema version
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
    )?;

    // Get current schema version (0 if fresh database)
    let current_version: i64 = conn
        .query_row(
            "SELECT COALESCE(CAST(value AS INTEGER), 0) FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    // Embed migration files at compile time
    let migrations: &[(&str, &str)] = &[
        ("001", include_str!("../migrations/001_initial.sql")),
        (
            "002",
            include_str!("../migrations/002_firmware_manifests.sql"),
        ),
        ("003", include_str!("../migrations/003_wan_config.sql")),
        ("004", include_str!("../migrations/004_networks.sql")),
    ];

    for (version_str, sql) in migrations {
        let version: i64 = version_str
            .parse()
            .expect("migration version must be numeric");
        if version > current_version {
            tracing::info!(version, "applying database migration");
            conn.execute_batch(sql).map_err(|e| DbError::Migration {
                context: format!("failed to apply migration {version_str}"),
                source: e,
            })?;
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?1)",
                rusqlite::params![version.to_string()],
            )?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_open_in_memory() {
        let db = open_in_memory()
            .await
            .expect("open_in_memory should succeed");
        let conn = db.lock().await;
        // Verify we can query the meta table
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .expect("schema_version should exist in meta table");
        assert!(!version.is_empty());
    }

    #[tokio::test]
    async fn test_schema_version() {
        let db = open_in_memory()
            .await
            .expect("open_in_memory should succeed");
        let conn = db.lock().await;
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .expect("schema_version should exist");
        // After all migrations, schema version should be "3"
        assert_eq!(version, "4");
    }

    #[tokio::test]
    async fn test_tables_exist() {
        let db = open_in_memory()
            .await
            .expect("open_in_memory should succeed");
        let conn = db.lock().await;

        let expected_tables = [
            "meta",
            "interfaces",
            "firewall_rules",
            "devices",
            "vpn_tunnels",
            "vpn_peers",
            "users",
            "sessions",
            "ids_events",
            "firmware_manifests",
            "wan_configs",
            "networks",
        ];

        for table in &expected_tables {
            let exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    rusqlite::params![table],
                    |r| r.get(0),
                )
                .unwrap_or(false);
            assert!(exists, "table '{table}' should exist after migrations");
        }
    }

    #[tokio::test]
    async fn test_idempotent_init() {
        // Running open_in_memory twice should not fail — migrations are
        // idempotent (CREATE TABLE IF NOT EXISTS).
        let db1 = open_in_memory()
            .await
            .expect("first open_in_memory should succeed");
        drop(db1);

        let db2 = open_in_memory()
            .await
            .expect("second open_in_memory should succeed");
        let conn = db2.lock().await;
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .expect("schema_version should exist after second init");
        assert_eq!(version, "4");
    }

    #[tokio::test]
    async fn test_idempotent_migrations_on_same_db() {
        // Run migrations twice on the same connection — should be a no-op
        // the second time.
        let conn = Connection::open_in_memory().expect("failed to open in-memory db");
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();

        run_migrations(&conn).expect("first migration run should succeed");
        run_migrations(&conn).expect("second migration run should succeed (idempotent)");

        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .expect("schema_version should exist");
        assert_eq!(version, "4");
    }

    #[tokio::test]
    async fn test_foreign_keys_enforced() {
        let db = open_in_memory()
            .await
            .expect("open_in_memory should succeed");
        let conn = db.lock().await;

        // Inserting a vpn_peer referencing a non-existent tunnel_id should fail
        let result = conn.execute(
            "INSERT INTO vpn_peers (tunnel_id, public_key, private_key_enc, address)
             VALUES (9999, 'pk', 'sk', '10.0.0.1')",
            [],
        );
        assert!(
            result.is_err(),
            "foreign key constraint should prevent inserting vpn_peer with invalid tunnel_id"
        );
    }
}
