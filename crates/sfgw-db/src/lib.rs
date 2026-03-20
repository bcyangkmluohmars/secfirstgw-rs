// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;
use zeroize::Zeroize;

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

    /// Encryption key derivation failed.
    #[error("database encryption key derivation failed: {0}")]
    KeyDerivation(String),

    /// Database is encrypted with a different key (wrong hardware).
    #[error(
        "database is bound to different hardware -- cannot decrypt \
             (the DB at {path} was created on a different device)"
    )]
    WrongHardware { path: String },

    /// Database encryption migration failed.
    #[error("failed to migrate unencrypted database to encrypted: {0}")]
    EncryptionMigration(String),
}

/// Default database path.
const DEFAULT_DB_PATH: &str = "/var/lib/sfgw/sfgw.db";

/// Environment variable to override DB path (useful for Docker/dev).
const DB_PATH_ENV: &str = "SFGW_DB_PATH";

/// Open the database (or create it with the initial schema).
///
/// The database is encrypted with SQLCipher using a key derived from
/// hardware fingerprints. This binds the database to the specific device
/// it was created on -- moving the DB file to different hardware will
/// make it undecryptable.
///
/// On first run with an existing unencrypted database, this function
/// transparently migrates it to encrypted format.
pub async fn open_or_create() -> Result<Db, DbError> {
    let db_path = std::env::var(DB_PATH_ENV).unwrap_or_else(|_| DEFAULT_DB_PATH.to_string());

    // Ensure parent directory exists
    if let Some(parent) = std::path::Path::new(&db_path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| DbError::CreateDir {
            path: parent.display().to_string(),
            source: e,
        })?;
    }

    // Derive encryption key from hardware fingerprints
    let db_key =
        sfgw_crypto::db_key::derive_db_key().map_err(|e| DbError::KeyDerivation(format!("{e}")))?;

    let db_exists = std::path::Path::new(&db_path).exists();

    if db_exists {
        // Try opening with encryption key first
        match try_open_encrypted(&db_path, &db_key) {
            Ok(conn) => {
                run_migrations(&conn)?;
                tracing::info!("encrypted database opened: {db_path}");
                return Ok(Arc::new(Mutex::new(conn)));
            }
            Err(e) => {
                tracing::debug!("encrypted open failed, checking if DB is unencrypted: {e}");

                // Check if the database is unencrypted (needs migration)
                if is_unencrypted_sqlite(&db_path) {
                    tracing::warn!(
                        "found unencrypted database at {db_path} -- migrating to encrypted format"
                    );
                    migrate_to_encrypted(&db_path, &db_key)?;
                    tracing::info!("database encryption migration complete: {db_path}");

                    // Now open the encrypted database
                    let conn = try_open_encrypted(&db_path, &db_key).map_err(|e| {
                        DbError::EncryptionMigration(format!("post-migration open failed: {e}"))
                    })?;
                    run_migrations(&conn)?;
                    return Ok(Arc::new(Mutex::new(conn)));
                }

                // DB exists but can't be opened with our key and isn't plaintext
                // -- it was encrypted on different hardware
                return Err(DbError::WrongHardware { path: db_path });
            }
        }
    }

    // Fresh database -- create encrypted from scratch
    let conn = Connection::open(&db_path).map_err(|e| DbError::Open {
        path: db_path.clone(),
        source: e,
    })?;

    apply_encryption_pragmas(&conn, &db_key)?;

    // WAL mode for concurrent reads
    conn.pragma_update(None, "journal_mode", "WAL")?;
    // Enforce foreign keys
    conn.pragma_update(None, "foreign_keys", "ON")?;

    run_migrations(&conn)?;

    tracing::info!("encrypted database created: {db_path}");
    Ok(Arc::new(Mutex::new(conn)))
}

/// Open an in-memory database with all migrations applied. Useful for testing.
///
/// In-memory databases are NOT encrypted (no persistence = no need for
/// encryption at rest). This keeps tests simple and fast.
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

/// Try to open an existing database file with SQLCipher encryption.
///
/// Returns the connection if the key is correct, or an error if the
/// database cannot be decrypted.
fn try_open_encrypted(
    db_path: &str,
    db_key: &sfgw_crypto::db_key::DbEncryptionKey,
) -> Result<Connection, DbError> {
    let conn = Connection::open(db_path).map_err(|e| DbError::Open {
        path: db_path.to_string(),
        source: e,
    })?;

    apply_encryption_pragmas(&conn, db_key)?;

    // Verify the key works by reading from the database.
    // If the key is wrong, this will fail with "not a database" or similar.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|e| DbError::Open {
            path: db_path.to_string(),
            source: e,
        })?;

    // WAL mode for concurrent reads
    conn.pragma_update(None, "journal_mode", "WAL")?;
    // Enforce foreign keys
    conn.pragma_update(None, "foreign_keys", "ON")?;

    Ok(conn)
}

/// Apply SQLCipher encryption PRAGMAs to a connection.
///
/// MUST be called immediately after `Connection::open()` and before any
/// other SQL statements. SQLCipher requires the key PRAGMA to be the very
/// first statement on a connection.
fn apply_encryption_pragmas(
    conn: &Connection,
    db_key: &sfgw_crypto::db_key::DbEncryptionKey,
) -> Result<(), DbError> {
    // Format as raw hex key for SQLCipher.
    // SQLCipher raw key format: PRAGMA key = "x'<hex>'";
    let mut hex_key = db_key.to_hex();

    // Use execute_batch for the key PRAGMA to avoid parameter binding issues
    // with SQLCipher's PRAGMA key syntax.
    let pragma_sql = format!("PRAGMA key = \"x'{hex_key}'\";");
    conn.execute_batch(&pragma_sql)?;

    // Zeroize the hex key immediately
    hex_key.zeroize();

    // Set cipher page size to match SQLite default page size
    conn.pragma_update(None, "cipher_page_size", 4096)?;

    // Set KDF iterations (SQLCipher 4.x default is 256000)
    conn.pragma_update(None, "kdf_iter", 256000)?;

    Ok(())
}

/// Check if a file is an unencrypted SQLite database by reading its header.
///
/// SQLite files start with the magic string "SQLite format 3\0".
/// Encrypted databases will have random-looking bytes instead.
fn is_unencrypted_sqlite(path: &str) -> bool {
    let Ok(header) = std::fs::read(path) else {
        return false;
    };
    // SQLite header magic: first 16 bytes
    header.len() >= 16 && &header[..16] == b"SQLite format 3\0"
}

/// Migrate an unencrypted SQLite database to SQLCipher encrypted format.
///
/// Uses the `ATTACH DATABASE ... KEY ...` + `sqlcipher_export()` pattern
/// to create an encrypted copy, then swaps the files.
fn migrate_to_encrypted(
    db_path: &str,
    db_key: &sfgw_crypto::db_key::DbEncryptionKey,
) -> Result<(), DbError> {
    let encrypted_path = format!("{db_path}.encrypted");
    let backup_path = format!("{db_path}.unencrypted-backup");

    // Open the unencrypted database (no key PRAGMA)
    let conn = Connection::open(db_path).map_err(|e| DbError::Open {
        path: db_path.to_string(),
        source: e,
    })?;

    // Format the hex key for the ATTACH statement
    let mut hex_key = db_key.to_hex();

    // Attach an encrypted database and export all data to it
    let attach_sql =
        format!("ATTACH DATABASE '{encrypted_path}' AS encrypted KEY \"x'{hex_key}'\";");
    conn.execute_batch(&attach_sql)
        .map_err(|e| DbError::EncryptionMigration(format!("ATTACH encrypted DB failed: {e}")))?;

    // Set cipher parameters on the encrypted database
    conn.execute_batch("PRAGMA encrypted.cipher_page_size = 4096;")
        .map_err(|e| {
            DbError::EncryptionMigration(format!("cipher_page_size PRAGMA failed: {e}"))
        })?;
    conn.execute_batch("PRAGMA encrypted.kdf_iter = 256000;")
        .map_err(|e| DbError::EncryptionMigration(format!("kdf_iter PRAGMA failed: {e}")))?;

    // Export all data from the plaintext DB to the encrypted one
    conn.execute_batch("SELECT sqlcipher_export('encrypted');")
        .map_err(|e| DbError::EncryptionMigration(format!("sqlcipher_export failed: {e}")))?;

    conn.execute_batch("DETACH DATABASE encrypted;")
        .map_err(|e| DbError::EncryptionMigration(format!("DETACH failed: {e}")))?;

    // Zeroize the hex key
    hex_key.zeroize();

    // Close the unencrypted connection
    drop(conn);

    // Swap files: unencrypted -> backup, encrypted -> main
    std::fs::rename(db_path, &backup_path).map_err(|e| {
        DbError::EncryptionMigration(format!("failed to move unencrypted DB to backup: {e}"))
    })?;
    std::fs::rename(&encrypted_path, db_path).map_err(|e| {
        // Try to restore the backup
        let _ = std::fs::rename(&backup_path, db_path);
        DbError::EncryptionMigration(format!("failed to move encrypted DB into place: {e}"))
    })?;

    // Remove WAL/SHM files from the old unencrypted DB if they exist
    let _ = std::fs::remove_file(format!("{backup_path}-wal"));
    let _ = std::fs::remove_file(format!("{backup_path}-shm"));

    tracing::warn!(
        "unencrypted database backup saved at {backup_path} -- \
         delete it after verifying the encrypted database works correctly"
    );

    Ok(())
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
        (
            "005",
            include_str!("../migrations/005_vlan_trunk_model.sql"),
        ),
        (
            "006",
            include_str!("../migrations/006_wireless_networks.sql"),
        ),
        ("007", include_str!("../migrations/007_ddns.sql")),
        (
            "008",
            include_str!("../migrations/008_wan_health_config.sql"),
        ),
        ("009", include_str!("../migrations/009_qos_rules.sql")),
        ("010", include_str!("../migrations/010_custom_zones.sql")),
        (
            "011",
            include_str!("../migrations/011_wireless_advanced.sql"),
        ),
        ("012", include_str!("../migrations/012_upnp_mappings.sql")),
        (
            "013",
            include_str!("../migrations/013_firmware_settings.sql"),
        ),
        ("014", include_str!("../migrations/014_log_keys.sql")),
        ("015", include_str!("../migrations/015_site_mesh.sql")),
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
        // After all migrations, schema version should be "15"
        assert_eq!(version, "15");
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
            "wireless_networks",
            "ddns_configs",
            "wan_health_config",
            "qos_rules",
            "custom_zones",
            "upnp_mappings",
            "firmware_settings",
            "log_keys",
            "site_meshes",
            "site_mesh_peers",
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
        // Running open_in_memory twice should not fail -- migrations are
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
        assert_eq!(version, "15");
    }

    #[tokio::test]
    async fn test_idempotent_migrations_on_same_db() {
        // Run migrations twice on the same connection -- should be a no-op
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
        assert_eq!(version, "15");
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

    #[tokio::test]
    async fn test_is_unencrypted_sqlite_detection() {
        // Create a temp unencrypted DB
        let dir = std::env::temp_dir();
        let path = dir.join("sfgw-test-unenc.db");
        let path_str = path.to_string_lossy().to_string();

        {
            let conn = Connection::open(&path).expect("open temp db");
            conn.execute_batch("CREATE TABLE test (id INTEGER);")
                .expect("create table");
        }

        assert!(
            is_unencrypted_sqlite(&path_str),
            "fresh SQLite file should be detected as unencrypted"
        );

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_encrypted_db_roundtrip() {
        // Test creating and reopening an encrypted database
        let dir = std::env::temp_dir();
        let path = dir.join("sfgw-test-encrypted-roundtrip.db");
        let path_str = path.to_string_lossy().to_string();

        // Clean up any previous test run
        let _ = std::fs::remove_file(&path);

        // Derive key (uses real hardware fingerprint)
        let db_key = sfgw_crypto::db_key::derive_db_key().expect("key derivation should succeed");

        // Create encrypted database
        {
            let conn = Connection::open(&path_str).expect("open new db");
            apply_encryption_pragmas(&conn, &db_key).expect("apply encryption");
            conn.pragma_update(None, "journal_mode", "WAL").unwrap();
            conn.execute_batch("CREATE TABLE test (id INTEGER, name TEXT);")
                .expect("create table");
            conn.execute("INSERT INTO test VALUES (1, 'hello')", [])
                .expect("insert");
        }

        // Verify it's NOT readable as unencrypted SQLite
        assert!(
            !is_unencrypted_sqlite(&path_str),
            "encrypted DB should not have plaintext SQLite header"
        );

        // Reopen with correct key
        {
            let conn =
                try_open_encrypted(&path_str, &db_key).expect("encrypted reopen should succeed");
            let name: String = conn
                .query_row("SELECT name FROM test WHERE id = 1", [], |r| r.get(0))
                .expect("query should succeed");
            assert_eq!(name, "hello");
        }

        // Clean up
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path_str}-wal"));
        let _ = std::fs::remove_file(format!("{path_str}-shm"));
    }

    #[tokio::test]
    async fn test_unencrypted_to_encrypted_migration() {
        let dir = std::env::temp_dir();
        let path = dir.join("sfgw-test-migration.db");
        let path_str = path.to_string_lossy().to_string();
        let backup_path = format!("{path_str}.unencrypted-backup");

        // Clean up any previous test run
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&backup_path);

        // Derive key
        let db_key = sfgw_crypto::db_key::derive_db_key().expect("key derivation should succeed");

        // Create an unencrypted database with test data
        {
            let conn = Connection::open(&path_str).expect("open unencrypted db");
            conn.execute_batch(
                "CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT);
                 INSERT INTO test VALUES (1, 'pre-migration');
                 INSERT INTO test VALUES (2, 'should-survive');",
            )
            .expect("seed unencrypted db");
        }

        assert!(is_unencrypted_sqlite(&path_str));

        // Migrate to encrypted
        migrate_to_encrypted(&path_str, &db_key).expect("migration should succeed");

        // Verify it's no longer unencrypted
        assert!(!is_unencrypted_sqlite(&path_str));

        // Verify data survived the migration
        {
            let conn = try_open_encrypted(&path_str, &db_key)
                .expect("encrypted open after migration should succeed");
            let value: String = conn
                .query_row("SELECT value FROM test WHERE id = 2", [], |r| r.get(0))
                .expect("query migrated data");
            assert_eq!(value, "should-survive");
        }

        // Verify backup exists
        assert!(
            std::path::Path::new(&backup_path).exists(),
            "unencrypted backup should exist"
        );

        // Clean up
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&backup_path);
        let _ = std::fs::remove_file(format!("{path_str}-wal"));
        let _ = std::fs::remove_file(format!("{path_str}-shm"));
    }

    // -- Migration 005 tests --------------------------------------------------

    /// Helper: run migrations 001-004 on a raw connection, then insert test data
    /// so we can verify the upgrade path when 005 runs on top.
    fn setup_pre_005(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        )
        .expect("meta table creation should succeed");

        let pre_005_migrations: &[(&str, &str)] = &[
            ("001", include_str!("../migrations/001_initial.sql")),
            (
                "002",
                include_str!("../migrations/002_firmware_manifests.sql"),
            ),
            ("003", include_str!("../migrations/003_wan_config.sql")),
            ("004", include_str!("../migrations/004_networks.sql")),
        ];

        for (version_str, sql) in pre_005_migrations {
            conn.execute_batch(sql)
                .unwrap_or_else(|e| panic!("migration {version_str} should apply cleanly: {e}"));
        }

        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '4')",
            [],
        )
        .expect("setting schema_version to 4 should succeed");
    }

    #[tokio::test]
    async fn test_migration_005_interfaces_has_pvid_column() {
        // After all migrations, pvid column must exist and be writable.
        let db = open_in_memory()
            .await
            .expect("open_in_memory should succeed");
        let conn = db.lock().await;

        conn.execute(
            "INSERT INTO interfaces (name, pvid) VALUES ('eth0', 10)",
            [],
        )
        .expect("insert with explicit pvid should succeed -- column must exist");

        let pvid: i64 = conn
            .query_row("SELECT pvid FROM interfaces WHERE name = 'eth0'", [], |r| {
                r.get(0)
            })
            .expect("pvid should be readable from interfaces table");

        assert_eq!(pvid, 10, "pvid should be 10 as inserted");
    }

    #[tokio::test]
    async fn test_migration_005_interfaces_no_role_column() {
        // After migration 005, the role column must not exist.
        let db = open_in_memory()
            .await
            .expect("open_in_memory should succeed");
        let conn = db.lock().await;

        let result = conn.query_row("SELECT role FROM interfaces LIMIT 1", [], |r| {
            r.get::<_, String>(0)
        });

        assert!(
            result.is_err(),
            "SELECT role FROM interfaces should fail -- column must not exist after migration 005"
        );
    }

    #[tokio::test]
    async fn test_migration_005_void_vlan_exists() {
        // Migration 005 inserts a void VLAN 1 row into networks.
        let db = open_in_memory()
            .await
            .expect("open_in_memory should succeed");
        let conn = db.lock().await;

        let (zone, enabled): (String, i64) = conn
            .query_row(
                "SELECT zone, enabled FROM networks WHERE vlan_id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("void VLAN 1 row must exist in networks after migration 005");

        assert_eq!(zone, "void", "VLAN 1 must have zone='void'");
        assert_eq!(enabled, 0, "VLAN 1 void must be disabled (enabled=0)");
    }

    #[tokio::test]
    async fn test_migration_005_lan_vlan_10() {
        // Simulate upgrade path: start with migrations 001-004 and a LAN row
        // with vlan_id=NULL, then apply 005 and verify vlan_id becomes 10.
        let conn = Connection::open_in_memory().expect("failed to open in-memory db");
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();

        setup_pre_005(&conn);

        // Insert a LAN network row with vlan_id=NULL (pre-005 state)
        conn.execute(
            "INSERT INTO networks (name, zone, vlan_id, subnet, gateway, dhcp_enabled, enabled)
             VALUES ('LAN', 'lan', NULL, '192.168.1.0/24', '192.168.1.1', 1, 1)",
            [],
        )
        .expect("LAN network insert should succeed");

        // Insert an interface with role='lan' (pre-005 schema)
        conn.execute(
            "INSERT INTO interfaces (name, mac, ips, mtu, is_up, role, enabled)
             VALUES ('eth0', 'aa:bb:cc:dd:ee:ff', '[]', 1500, 1, 'lan', 1)",
            [],
        )
        .expect("interface insert into pre-005 schema should succeed");

        // Apply migration 005
        conn.execute_batch(include_str!("../migrations/005_vlan_trunk_model.sql"))
            .expect("migration 005 should apply cleanly");

        // Verify interfaces.pvid = 10
        let pvid: i64 = conn
            .query_row("SELECT pvid FROM interfaces WHERE name = 'eth0'", [], |r| {
                r.get(0)
            })
            .expect("pvid should exist after migration 005");
        assert_eq!(pvid, 10, "lan interface should get pvid=10");

        // Verify role column is gone
        let role_result = conn.query_row("SELECT role FROM interfaces LIMIT 1", [], |r| {
            r.get::<_, String>(0)
        });
        assert!(
            role_result.is_err(),
            "role column must not exist after migration 005"
        );

        // Verify LAN network vlan_id updated to 10
        let vlan_id: i64 = conn
            .query_row("SELECT vlan_id FROM networks WHERE zone = 'lan'", [], |r| {
                r.get(0)
            })
            .expect("LAN network row should still exist");
        assert_eq!(vlan_id, 10, "LAN network vlan_id should be updated to 10");
    }

    #[tokio::test]
    async fn test_migration_005_preserves_non_role_fields() {
        // Verify all non-role fields survive the rename-create-copy-drop migration.
        let conn = Connection::open_in_memory().expect("failed to open in-memory db");
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();

        setup_pre_005(&conn);

        conn.execute(
            "INSERT INTO interfaces (name, mac, ips, mtu, is_up, role, enabled, config)
             VALUES ('eth1', 'de:ad:be:ef:00:01', '[\"10.0.0.1/24\"]', 9000, 1, 'lan', 1, '{\"speed\":1000}')",
            [],
        )
        .expect("pre-005 interface insert should succeed");

        conn.execute_batch(include_str!("../migrations/005_vlan_trunk_model.sql"))
            .expect("migration 005 should apply cleanly");

        let (name, mac, ips, mtu, is_up, enabled, config): (
            String, String, String, i64, i64, i64, String,
        ) = conn
            .query_row(
                "SELECT name, mac, ips, mtu, is_up, enabled, config FROM interfaces WHERE name = 'eth1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
            )
            .expect("eth1 row must survive migration 005");

        assert_eq!(name, "eth1", "name must be preserved");
        assert_eq!(mac, "de:ad:be:ef:00:01", "mac must be preserved");
        assert_eq!(ips, "[\"10.0.0.1/24\"]", "ips must be preserved");
        assert_eq!(mtu, 9000, "mtu must be preserved");
        assert_eq!(is_up, 1, "is_up must be preserved");
        assert_eq!(enabled, 1, "enabled must be preserved");
        assert_eq!(config, "{\"speed\":1000}", "config must be preserved");
    }

    #[tokio::test]
    async fn test_migration_005_wan_gets_pvid_zero() {
        // WAN interfaces must get pvid=0 -- they are outside the internal VLAN space.
        let conn = Connection::open_in_memory().expect("failed to open in-memory db");
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();

        setup_pre_005(&conn);

        conn.execute(
            "INSERT INTO interfaces (name, mac, ips, mtu, is_up, role, enabled)
             VALUES ('eth0', 'aa:bb:cc:dd:ee:ff', '[]', 1500, 1, 'wan', 1)",
            [],
        )
        .expect("WAN interface insert into pre-005 schema should succeed");

        conn.execute_batch(include_str!("../migrations/005_vlan_trunk_model.sql"))
            .expect("migration 005 should apply cleanly");

        let pvid: i64 = conn
            .query_row("SELECT pvid FROM interfaces WHERE name = 'eth0'", [], |r| {
                r.get(0)
            })
            .expect("pvid must exist after migration 005");

        assert_eq!(
            pvid, 0,
            "WAN interface must get pvid=0 (not an internal VLAN port)"
        );
    }
}
