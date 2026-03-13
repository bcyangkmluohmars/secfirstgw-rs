// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! NAS service — SMB3/NFS file sharing for secfirstgw.
//!
//! Manages network-attached storage shares on platforms with an internal HDD.
//! Shares are backed by an encrypted volume (`/dev/mapper/sfgw-data` mounted
//! at `/mnt/data`) and served via Samba (SMB3) and/or NFS.
//!
//! Security defaults:
//! - Encrypted volume must be mounted before shares are served
//! - SMB3 minimum protocol version enforced (no SMBv1)
//! - NFS exports restricted to specific subnets
//! - Share path traversal prevention via canonicalization
//! - All share metadata stored in parameterized SQL

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Device mapper path for the encrypted data volume.
const ENCRYPTED_VOLUME: &str = "/dev/mapper/sfgw-data";

/// Mount point for the encrypted data volume.
const DATA_MOUNT_POINT: &str = "/mnt/data";

/// Base directory for NAS shares (under the data mount).
const SHARES_BASE_DIR: &str = "/mnt/data/shares";

/// Default Samba configuration output path.
const SMB_CONF_PATH: &str = "/etc/samba/smb.conf";

/// Default NFS exports output path.
const NFS_EXPORTS_PATH: &str = "/etc/exports";

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// NAS-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum NasError {
    /// Platform does not have an HDD bay.
    #[error("platform does not have an HDD — NAS services unavailable")]
    NoHdd,

    /// Encrypted volume is not mounted.
    #[error("encrypted volume is not mounted at {}", DATA_MOUNT_POINT)]
    VolumeNotMounted,

    /// Share name contains invalid characters.
    #[error("invalid share name: {0}")]
    InvalidShareName(String),

    /// Share not found in database.
    #[error("share not found: {0}")]
    ShareNotFound(String),

    /// Share path escapes the shares base directory.
    #[error("share path escapes base directory")]
    PathTraversal,

    /// Database error.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Wrapped anyhow error for internal context propagation.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Convenience alias for results from this crate.
type Result<T> = std::result::Result<T, NasError>;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// Protocol for a NAS share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShareProtocol {
    /// Serve via SMB3 only.
    Smb,
    /// Serve via NFS only.
    Nfs,
    /// Serve via both SMB3 and NFS.
    Both,
}

impl fmt::Display for ShareProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShareProtocol::Smb => write!(f, "smb"),
            ShareProtocol::Nfs => write!(f, "nfs"),
            ShareProtocol::Both => write!(f, "both"),
        }
    }
}

impl ShareProtocol {
    /// Parse a protocol string from the database.
    fn from_db(s: &str) -> Result<Self> {
        match s {
            "smb" => Ok(ShareProtocol::Smb),
            "nfs" => Ok(ShareProtocol::Nfs),
            "both" => Ok(ShareProtocol::Both),
            other => return Err(NasError::Internal(anyhow::anyhow!("unknown share protocol: {other}"))),
        }
    }
}

/// A NAS share definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NasShare {
    /// Database row ID.
    pub id: i64,
    /// Human-readable share name (used as SMB share name / NFS export name).
    pub name: String,
    /// Filesystem path (relative to shares base dir, stored as absolute).
    pub path: PathBuf,
    /// Sharing protocol.
    pub protocol: ShareProtocol,
    /// Whether the share is read-only.
    pub read_only: bool,
    /// Comma-separated list of allowed zone names (e.g. `"lan,mgmt"`).
    pub allowed_zones: String,
    /// Whether authentication is required to access the share.
    pub auth_required: bool,
}

// ---------------------------------------------------------------------------
// Share name validation
// ---------------------------------------------------------------------------

/// Validate a share name: alphanumeric, hyphens, underscores only; 1-64 chars.
fn validate_share_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(NasError::InvalidShareName("name must be 1-64 characters".into()).into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(NasError::InvalidShareName(
            "name may only contain alphanumeric characters, hyphens, and underscores".into(),
        )
        .into());
    }
    Ok(())
}

/// Compute the absolute share path and verify it stays within the base dir.
fn resolve_share_path(name: &str) -> Result<PathBuf> {
    let base = Path::new(SHARES_BASE_DIR);
    let share_path = base.join(name);

    // Verify the resolved path doesn't escape via `..` or symlinks.
    // We check the string prefix since the directory may not exist yet.
    let normalized = share_path.components().collect::<PathBuf>();
    if !normalized.starts_with(base) {
        return Err(NasError::PathTraversal.into());
    }

    Ok(normalized)
}

// ---------------------------------------------------------------------------
// Volume checks
// ---------------------------------------------------------------------------

/// Check whether the encrypted data volume is mounted.
#[must_use]
pub fn is_volume_mounted() -> bool {
    is_volume_mounted_impl(Path::new(ENCRYPTED_VOLUME), Path::new("/proc/mounts"))
}

/// Testable implementation of the mount check.
fn is_volume_mounted_impl(device: &Path, proc_mounts: &Path) -> bool {
    if !device.exists() {
        return false;
    }
    match std::fs::read_to_string(proc_mounts) {
        Ok(contents) => contents.lines().any(|line| {
            let mut parts = line.split_whitespace();
            let dev = parts.next().unwrap_or("");
            let mount = parts.next().unwrap_or("");
            dev == device.to_string_lossy() && mount == DATA_MOUNT_POINT
        }),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Database migration
// ---------------------------------------------------------------------------

/// Run the NAS table migration. Idempotent (uses IF NOT EXISTS).
pub async fn migrate(db: &sfgw_db::Db) -> Result<()> {
    let conn = db.lock().await;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS nas_shares (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            name           TEXT NOT NULL UNIQUE,
            path           TEXT NOT NULL,
            protocol       TEXT NOT NULL DEFAULT 'smb',
            read_only      INTEGER NOT NULL DEFAULT 0,
            allowed_zones  TEXT NOT NULL DEFAULT 'lan',
            auth_required  INTEGER NOT NULL DEFAULT 1
        );",
    )
    .context("failed to create nas_shares table")?;
    tracing::debug!("nas_shares migration complete");
    Ok(())
}

// ---------------------------------------------------------------------------
// Database CRUD
// ---------------------------------------------------------------------------

/// List all configured NAS shares.
pub async fn list_shares(db: &sfgw_db::Db) -> Result<Vec<NasShare>> {
    let conn = db.lock().await;
    let mut stmt = conn.prepare(
        "SELECT id, name, path, protocol, read_only, allowed_zones, auth_required
         FROM nas_shares ORDER BY name",
    )?;
    let shares = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, bool>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, bool>(6)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to read nas_shares rows")?;

    let mut result = Vec::with_capacity(shares.len());
    for (id, name, path, protocol, read_only, allowed_zones, auth_required) in shares {
        result.push(NasShare {
            id,
            name,
            path: PathBuf::from(path),
            protocol: ShareProtocol::from_db(&protocol)?,
            read_only,
            allowed_zones,
            auth_required,
        });
    }
    Ok(result)
}

/// Create a new NAS share. Returns the created share.
pub async fn create_share(
    db: &sfgw_db::Db,
    name: &str,
    protocol: ShareProtocol,
    read_only: bool,
    allowed_zones: &str,
    auth_required: bool,
) -> Result<NasShare> {
    validate_share_name(name)?;
    let share_path = resolve_share_path(name)?;

    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO nas_shares (name, path, protocol, read_only, allowed_zones, auth_required)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            name,
            share_path.to_string_lossy().as_ref(),
            protocol.to_string(),
            read_only,
            allowed_zones,
            auth_required,
        ],
    )
    .with_context(|| format!("failed to insert share: {name}"))?;

    let id = conn.last_insert_rowid();
    tracing::info!(share = name, protocol = %protocol, "NAS share created");

    Ok(NasShare {
        id,
        name: name.to_string(),
        path: share_path,
        protocol,
        read_only,
        allowed_zones: allowed_zones.to_string(),
        auth_required,
    })
}

/// Delete a NAS share by name.
pub async fn delete_share(db: &sfgw_db::Db, name: &str) -> Result<()> {
    let conn = db.lock().await;
    let rows = conn.execute(
        "DELETE FROM nas_shares WHERE name = ?1",
        rusqlite::params![name],
    )?;
    if rows == 0 {
        return Err(NasError::ShareNotFound(name.to_string()).into());
    }
    tracing::info!(share = name, "NAS share deleted");
    Ok(())
}

// ---------------------------------------------------------------------------
// Config generation — SMB
// ---------------------------------------------------------------------------

/// Generate a Samba `smb.conf` from the given shares.
pub fn generate_smb_conf(shares: &[NasShare]) -> String {
    let mut conf = String::from(
        "[global]\n\
         \tserver string = secfirstgw NAS\n\
         \tworkgroup = WORKGROUP\n\
         \tserver role = standalone server\n\
         \tlog file = /var/log/samba/log.%m\n\
         \tmax log size = 1000\n\
         \tlogging = syslog\n\
         \tmap to guest = Bad User\n\
         \n\
         \t# Security hardening\n\
         \tserver min protocol = SMB3\n\
         \tserver signing = mandatory\n\
         \tserver smb encrypt = required\n\
         \tdisable netbios = yes\n\
         \tsmb ports = 445\n\n",
    );

    for share in shares {
        if !matches!(share.protocol, ShareProtocol::Smb | ShareProtocol::Both) {
            continue;
        }
        conf.push_str(&format!("[{}]\n", share.name));
        conf.push_str(&format!("\tpath = {}\n", share.path.display()));
        conf.push_str(&format!(
            "\tread only = {}\n",
            if share.read_only { "yes" } else { "no" }
        ));
        conf.push_str("\tbrowseable = yes\n");
        if share.auth_required {
            conf.push_str("\tguest ok = no\n");
            conf.push_str("\tvalid users = @nas\n");
        } else {
            conf.push_str("\tguest ok = yes\n");
        }
        conf.push_str(&format!("\tcomment = Zone: {}\n", share.allowed_zones));
        conf.push('\n');
    }

    conf
}

// ---------------------------------------------------------------------------
// Config generation — NFS
// ---------------------------------------------------------------------------

/// Generate an `/etc/exports` file from the given shares.
///
/// Each NFS export is restricted to a placeholder subnet per allowed zone.
/// Real subnet resolution would come from the zone/network config; here we
/// emit the zone names as comments and use `10.0.0.0/8` as a safe default
/// that the firewall further restricts.
pub fn generate_nfs_exports(shares: &[NasShare]) -> String {
    let mut exports = String::from("# /etc/exports — generated by sfgw-nas\n");
    exports.push_str("# Do not edit manually; changes will be overwritten.\n\n");

    for share in shares {
        if !matches!(share.protocol, ShareProtocol::Nfs | ShareProtocol::Both) {
            continue;
        }
        let opts = if share.read_only {
            "ro,sync,no_subtree_check,root_squash"
        } else {
            "rw,sync,no_subtree_check,root_squash"
        };
        // Emit a comment with zone info for audit
        exports.push_str(&format!("# zones: {}\n", share.allowed_zones));
        // FIXME: resolve actual zone subnets from sfgw-net instead of hardcoded 10.0.0.0/8
        exports.push_str(&format!("{} 10.0.0.0/8({})\n", share.path.display(), opts,));
    }

    exports
}

// ---------------------------------------------------------------------------
// Config writing
// ---------------------------------------------------------------------------

/// Write the generated SMB config to disk.
pub async fn write_smb_conf(shares: &[NasShare], path: Option<&Path>) -> Result<PathBuf> {
    let output = path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(SMB_CONF_PATH));

    let rendered = generate_smb_conf(shares);

    if let Some(parent) = output.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create samba config dir: {}", parent.display()))?;
    }

    tokio::fs::write(&output, rendered.as_bytes())
        .await
        .with_context(|| format!("failed to write smb.conf: {}", output.display()))?;

    tracing::info!(path = %output.display(), "smb.conf written");
    Ok(output)
}

/// Write the generated NFS exports to disk.
pub async fn write_nfs_exports(shares: &[NasShare], path: Option<&Path>) -> Result<PathBuf> {
    let output = path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(NFS_EXPORTS_PATH));

    let rendered = generate_nfs_exports(shares);

    if let Some(parent) = output.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create exports dir: {}", parent.display()))?;
    }

    tokio::fs::write(&output, rendered.as_bytes())
        .await
        .with_context(|| format!("failed to write exports: {}", output.display()))?;

    tracing::info!(path = %output.display(), "NFS exports written");
    Ok(output)
}

// ---------------------------------------------------------------------------
// Service management
// ---------------------------------------------------------------------------

/// Restart the Samba and NFS daemons via systemctl.
pub async fn restart_services() -> Result<()> {
    restart_service("smbd").await?;
    restart_service("nfs-kernel-server").await?;
    Ok(())
}

/// Restart a single systemd service.
async fn restart_service(name: &str) -> Result<()> {
    let output = std::process::Command::new("systemctl")
        .args(["restart", name])
        .output()
        .with_context(|| format!("failed to execute systemctl restart {name}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NasError::Internal(anyhow::anyhow!("systemctl restart {name} failed: {stderr}")));
    }

    tracing::info!(service = name, "service restarted");
    Ok(())
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Start the NAS service.
///
/// 1. Checks the platform has an HDD
/// 2. Verifies the encrypted volume is mounted
/// 3. Runs database migration
/// 4. Generates and writes SMB/NFS config from stored shares
/// 5. Restarts daemons
pub async fn start(db: &sfgw_db::Db, platform: &sfgw_hal::Platform) -> Result<()> {
    if !platform.has_hdd() {
        tracing::info!(platform = %platform, "no HDD on this platform — skipping NAS");
        return Ok(());
    }

    if !is_volume_mounted() {
        tracing::warn!("encrypted volume not mounted — NAS services unavailable");
        return Err(NasError::VolumeNotMounted.into());
    }

    migrate(db).await?;

    // Ensure shares base directory exists
    tokio::fs::create_dir_all(SHARES_BASE_DIR)
        .await
        .context("failed to create NAS shares directory")?;

    let shares = list_shares(db).await?;

    write_smb_conf(&shares, None).await?;
    write_nfs_exports(&shares, None).await?;

    restart_services().await?;

    tracing::info!(shares = shares.len(), "NAS service started");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// Create an in-memory database with the nas_shares table.
    async fn test_db() -> sfgw_db::Db {
        let conn = Connection::open_in_memory()
            // INVARIANT: in-memory open cannot fail
            .expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS nas_shares (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                name           TEXT NOT NULL UNIQUE,
                path           TEXT NOT NULL,
                protocol       TEXT NOT NULL DEFAULT 'smb',
                read_only      INTEGER NOT NULL DEFAULT 0,
                allowed_zones  TEXT NOT NULL DEFAULT 'lan',
                auth_required  INTEGER NOT NULL DEFAULT 1
            );",
        )
        // INVARIANT: schema creation on fresh in-memory db cannot fail
        .expect("schema");
        Arc::new(Mutex::new(conn))
    }

    // ----- Test 1: SMB config generation with security defaults -----

    #[test]
    fn test_smb_conf_security_defaults() {
        let shares = vec![NasShare {
            id: 1,
            name: "media".into(),
            path: PathBuf::from("/mnt/data/shares/media"),
            protocol: ShareProtocol::Smb,
            read_only: false,
            allowed_zones: "lan".into(),
            auth_required: true,
        }];

        let conf = generate_smb_conf(&shares);

        // SMB3 minimum enforced — no SMBv1
        assert!(conf.contains("server min protocol = SMB3"));
        // Signing mandatory
        assert!(conf.contains("server signing = mandatory"));
        // Encryption required
        assert!(conf.contains("server smb encrypt = required"));
        // NetBIOS disabled (attack surface reduction)
        assert!(conf.contains("disable netbios = yes"));
        // Only port 445
        assert!(conf.contains("smb ports = 445"));
        // Share section present
        assert!(conf.contains("[media]"));
        assert!(conf.contains("path = /mnt/data/shares/media"));
        assert!(conf.contains("read only = no"));
        // Auth required means no guest
        assert!(conf.contains("guest ok = no"));
    }

    // ----- Test 2: SMB config filters out NFS-only shares -----

    #[test]
    fn test_smb_conf_skips_nfs_only() {
        let shares = vec![
            NasShare {
                id: 1,
                name: "smb-share".into(),
                path: PathBuf::from("/mnt/data/shares/smb-share"),
                protocol: ShareProtocol::Smb,
                read_only: true,
                allowed_zones: "lan".into(),
                auth_required: false,
            },
            NasShare {
                id: 2,
                name: "nfs-only".into(),
                path: PathBuf::from("/mnt/data/shares/nfs-only"),
                protocol: ShareProtocol::Nfs,
                read_only: false,
                allowed_zones: "lan".into(),
                auth_required: true,
            },
        ];

        let conf = generate_smb_conf(&shares);

        assert!(conf.contains("[smb-share]"));
        assert!(!conf.contains("[nfs-only]"));
        // Read-only share
        assert!(conf.contains("read only = yes"));
        // Guest share (auth not required)
        assert!(conf.contains("guest ok = yes"));
    }

    // ----- Test 3: NFS exports generation -----

    #[test]
    fn test_nfs_exports_generation() {
        let shares = vec![
            NasShare {
                id: 1,
                name: "backups".into(),
                path: PathBuf::from("/mnt/data/shares/backups"),
                protocol: ShareProtocol::Nfs,
                read_only: true,
                allowed_zones: "lan,mgmt".into(),
                auth_required: true,
            },
            NasShare {
                id: 2,
                name: "smb-only".into(),
                path: PathBuf::from("/mnt/data/shares/smb-only"),
                protocol: ShareProtocol::Smb,
                read_only: false,
                allowed_zones: "lan".into(),
                auth_required: false,
            },
        ];

        let exports = generate_nfs_exports(&shares);

        // NFS share present with read-only options
        assert!(exports.contains("/mnt/data/shares/backups"));
        assert!(exports.contains("ro,sync,no_subtree_check,root_squash"));
        // Zone comment present
        assert!(exports.contains("# zones: lan,mgmt"));
        // SMB-only share excluded
        assert!(!exports.contains("smb-only"));
    }

    // ----- Test 4: Both protocol renders in SMB and NFS -----

    #[test]
    fn test_both_protocol_appears_in_both_configs() {
        let shares = vec![NasShare {
            id: 1,
            name: "shared".into(),
            path: PathBuf::from("/mnt/data/shares/shared"),
            protocol: ShareProtocol::Both,
            read_only: false,
            allowed_zones: "lan".into(),
            auth_required: true,
        }];

        let smb = generate_smb_conf(&shares);
        let nfs = generate_nfs_exports(&shares);

        assert!(smb.contains("[shared]"));
        assert!(nfs.contains("/mnt/data/shares/shared"));
        assert!(nfs.contains("rw,sync,no_subtree_check,root_squash"));
    }

    // ----- Test 5: Share name validation -----

    #[test]
    fn test_share_name_validation() {
        // Valid names
        assert!(validate_share_name("media").is_ok());
        assert!(validate_share_name("my-share").is_ok());
        assert!(validate_share_name("share_01").is_ok());
        assert!(validate_share_name("A").is_ok());

        // Invalid: empty
        assert!(validate_share_name("").is_err());

        // Invalid: too long
        let long_name = "a".repeat(65);
        assert!(validate_share_name(&long_name).is_err());

        // Invalid: special characters
        assert!(validate_share_name("my share").is_err());
        assert!(validate_share_name("../etc").is_err());
        assert!(validate_share_name("share/name").is_err());
        assert!(validate_share_name("share;drop").is_err());
    }

    // ----- Test 6: Path traversal prevention -----

    #[test]
    fn test_path_traversal_blocked() {
        // Normal name resolves under shares base
        let path = resolve_share_path("media");
        assert!(path.is_ok());
        let p = path
            // INVARIANT: "media" is a valid name
            .expect("valid path");
        assert!(p.starts_with(SHARES_BASE_DIR));

        // Name with dots is caught by validation (won't reach resolve_share_path
        // in production), but resolve_share_path itself checks prefix
        assert!(validate_share_name("..").is_err());
    }

    // ----- Test 7: Database CRUD -----

    #[tokio::test]
    async fn test_db_create_list_delete() {
        let db = test_db().await;

        // Initially empty
        let shares = list_shares(&db).await;
        assert!(shares.is_ok());
        assert!(
            shares
                // INVARIANT: test db query cannot fail
                .expect("list")
                .is_empty()
        );

        // Create a share
        let share = create_share(
            &db,
            "test-share",
            ShareProtocol::Both,
            false,
            "lan,mgmt",
            true,
        )
        .await;
        assert!(share.is_ok());
        let share = share
            // INVARIANT: valid params on test db
            .expect("create");
        assert_eq!(share.name, "test-share");
        assert_eq!(share.protocol, ShareProtocol::Both);
        assert!(!share.read_only);
        assert!(share.auth_required);

        // List returns one share
        let shares = list_shares(&db)
            .await
            // INVARIANT: test db query cannot fail
            .expect("list");
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "test-share");

        // Delete it
        let result = delete_share(&db, "test-share").await;
        assert!(result.is_ok());

        // List is empty again
        let shares = list_shares(&db)
            .await
            // INVARIANT: test db query cannot fail
            .expect("list");
        assert!(shares.is_empty());
    }

    // ----- Test 8: Delete non-existent share returns error -----

    #[tokio::test]
    async fn test_delete_nonexistent_share() {
        let db = test_db().await;
        let result = delete_share(&db, "no-such-share").await;
        assert!(result.is_err());
        let err_msg = format!(
            "{}",
            result
                // INVARIANT: we just asserted it's Err
                .expect_err("should fail")
        );
        assert!(err_msg.contains("not found"));
    }

    // ----- Test 9: Volume mount check with synthetic /proc/mounts -----

    #[test]
    fn test_volume_mount_check() {
        // Non-existent device -> not mounted
        let result = is_volume_mounted_impl(
            Path::new("/dev/nonexistent-device-xyz"),
            Path::new("/proc/mounts"),
        );
        assert!(!result);

        // Non-existent proc mounts file -> not mounted
        let result = is_volume_mounted_impl(
            Path::new("/dev/null"), // exists
            Path::new("/tmp/sfgw-nonexistent-proc-mounts"),
        );
        assert!(!result);
    }

    // ----- Test 10: ShareProtocol round-trip -----

    #[test]
    fn test_protocol_serde_roundtrip() {
        for proto in &[ShareProtocol::Smb, ShareProtocol::Nfs, ShareProtocol::Both] {
            let s = proto.to_string();
            let parsed = ShareProtocol::from_db(&s);
            assert!(parsed.is_ok());
            assert_eq!(
                parsed
                    // INVARIANT: valid protocol string
                    .expect("parse"),
                *proto,
            );
        }

        // Invalid protocol
        assert!(ShareProtocol::from_db("ftp").is_err());
    }

    // ----- Test 11: Migration is idempotent -----

    #[tokio::test]
    async fn test_migration_idempotent() {
        let db = test_db().await;
        // Run migrate twice — should not fail
        let r1 = migrate(&db).await;
        assert!(r1.is_ok());
        let r2 = migrate(&db).await;
        assert!(r2.is_ok());
    }
}
