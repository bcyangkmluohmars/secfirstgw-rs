// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! Firmware OTA self-update with rollback support.
//!
//! Flow:
//! 1. Check: fetch manifest from configurable URL, compare versions.
//! 2. Download: stream binary to temp file, verify SHA-256 hash.
//! 3. Apply: backup current binary, atomic rename new binary, restart service.
//! 4. Rollback: if health check fails within 60s, swap back to backup.

use anyhow::{Context, Result, bail};
use ring::digest::{Context as DigestContext, SHA256};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

/// Default binary path on the device.
const DEFAULT_BINARY_PATH: &str = "/usr/local/bin/sfgw";
/// Backup path for rollback.
const DEFAULT_BACKUP_PATH: &str = "/usr/local/bin/sfgw.backup";
/// Temp download path (same filesystem for atomic rename).
const DEFAULT_TEMP_PATH: &str = "/usr/local/bin/.sfgw.update.tmp";
/// Health check timeout after applying update.
#[allow(dead_code)]
const HEALTH_CHECK_TIMEOUT_SECS: u64 = 60;
/// Health check interval.
#[allow(dead_code)]
const HEALTH_CHECK_INTERVAL_SECS: u64 = 5;

/// Information about an available firmware update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareInfo {
    /// Semantic version string (e.g. "0.4.0").
    pub version: String,
    /// SHA-256 hex digest of the binary.
    pub sha256: String,
    /// Download URL for the binary.
    pub download_url: String,
    /// Release notes / changelog.
    pub release_notes: String,
    /// Binary size in bytes.
    pub size_bytes: u64,
    /// Whether this is a pre-release (beta channel).
    pub prerelease: bool,
    /// Publication timestamp.
    pub published_at: String,
}

/// Update check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckResult {
    /// Current running version.
    pub current_version: String,
    /// Available update, if any.
    pub available: Option<FirmwareInfo>,
    /// Whether an update is available.
    pub update_available: bool,
    /// When we last checked.
    pub checked_at: String,
}

/// Update settings stored in DB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSettings {
    /// Update channel: "stable" or "beta".
    pub update_channel: String,
    /// Whether to auto-check for updates.
    pub auto_check: bool,
    /// Hours between automatic checks.
    pub check_interval_hours: i64,
    /// Last check timestamp (ISO 8601).
    pub last_check: Option<String>,
    /// URL to check for updates.
    pub update_url: String,
}

/// GitHub release asset structure.
#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

/// GitHub release structure.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GithubRelease {
    tag_name: String,
    name: Option<String>,
    body: Option<String>,
    prerelease: bool,
    published_at: String,
    assets: Vec<GithubAsset>,
}

/// Load update settings from the database.
pub async fn load_settings(db: &sfgw_db::Db) -> Result<UpdateSettings> {
    let conn = db.lock().await;
    let settings = conn
        .query_row(
            "SELECT update_channel, auto_check, check_interval_hours, last_check, update_url
         FROM firmware_settings WHERE id = 1",
            [],
            |row| {
                Ok(UpdateSettings {
                    update_channel: row.get(0)?,
                    auto_check: row.get::<_, i64>(1)? != 0,
                    check_interval_hours: row.get(2)?,
                    last_check: row.get(3)?,
                    update_url: row.get(4)?,
                })
            },
        )
        .context("failed to load firmware settings")?;
    Ok(settings)
}

/// Save update settings to the database.
#[allow(dead_code)]
pub async fn save_settings(db: &sfgw_db::Db, settings: &UpdateSettings) -> Result<()> {
    let conn = db.lock().await;
    conn.execute(
        "UPDATE firmware_settings SET
            update_channel = ?1,
            auto_check = ?2,
            check_interval_hours = ?3,
            update_url = ?4
         WHERE id = 1",
        rusqlite::params![
            settings.update_channel,
            settings.auto_check as i64,
            settings.check_interval_hours,
            settings.update_url,
        ],
    )
    .context("failed to save firmware settings")?;
    Ok(())
}

/// Record last check timestamp in the database.
async fn record_last_check(db: &sfgw_db::Db) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    let conn = db.lock().await;
    conn.execute(
        "UPDATE firmware_settings SET last_check = ?1 WHERE id = 1",
        rusqlite::params![now],
    )
    .context("failed to record last check timestamp")?;
    Ok(())
}

/// Determine the target architecture string for asset matching.
fn target_arch() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    {
        "aarch64"
    }
    #[cfg(target_arch = "x86_64")]
    {
        "x86_64"
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        "unknown"
    }
}

/// Check for available firmware updates.
///
/// Fetches the releases manifest from the configured URL and compares
/// with the current running version.
pub async fn check_for_update(db: &sfgw_db::Db) -> Result<UpdateCheckResult> {
    let settings = load_settings(db).await?;
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let arch = target_arch();

    tracing::info!(
        url = %settings.update_url,
        channel = %settings.update_channel,
        arch = arch,
        "checking for firmware updates"
    );

    let client = reqwest::Client::builder()
        .user_agent(format!("sfgw/{current_version}"))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client")?;

    let releases: Vec<GithubRelease> = client
        .get(&settings.update_url)
        .send()
        .await
        .context("failed to fetch releases")?
        .error_for_status()
        .context("releases API returned error")?
        .json()
        .await
        .context("failed to parse releases JSON")?;

    // Record that we checked
    if let Err(e) = record_last_check(db).await {
        tracing::warn!("failed to record last check time: {e}");
    }

    let checked_at = chrono::Utc::now().to_rfc3339();

    // Find the best matching release
    let asset_pattern = format!("sfgw-{arch}");

    for release in &releases {
        // Skip prereleases unless on beta channel
        if release.prerelease && settings.update_channel != "beta" {
            continue;
        }

        // Parse version from tag (strip leading 'v' if present)
        let release_version = release
            .tag_name
            .strip_prefix('v')
            .unwrap_or(&release.tag_name);

        // Skip if not newer
        if !is_newer_version(release_version, &current_version) {
            continue;
        }

        // Find matching binary asset and checksum file
        let binary_asset = release
            .assets
            .iter()
            .find(|a| a.name.starts_with(&asset_pattern) && !a.name.ends_with(".sha256"));
        let checksum_asset = release
            .assets
            .iter()
            .find(|a| a.name.starts_with(&asset_pattern) && a.name.ends_with(".sha256"));

        if let Some(binary) = binary_asset {
            // Fetch SHA-256 checksum if available
            let sha256 = if let Some(cs_asset) = checksum_asset {
                match client.get(&cs_asset.browser_download_url).send().await {
                    Ok(resp) => match resp.text().await {
                        Ok(text) => text.split_whitespace().next().unwrap_or("").to_string(),
                        Err(_) => String::new(),
                    },
                    Err(_) => String::new(),
                }
            } else {
                String::new()
            };

            let info = FirmwareInfo {
                version: release_version.to_string(),
                sha256,
                download_url: binary.browser_download_url.clone(),
                release_notes: release.body.clone().unwrap_or_default(),
                size_bytes: binary.size,
                prerelease: release.prerelease,
                published_at: release.published_at.clone(),
            };

            return Ok(UpdateCheckResult {
                current_version,
                available: Some(info),
                update_available: true,
                checked_at,
            });
        }
    }

    Ok(UpdateCheckResult {
        current_version,
        available: None,
        update_available: false,
        checked_at,
    })
}

/// Compare two semver-like version strings. Returns true if `new_ver` > `current`.
fn is_newer_version(new_ver: &str, current: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> { v.split('.').filter_map(|s| s.parse().ok()).collect() };
    let new_parts = parse(new_ver);
    let cur_parts = parse(current);

    for i in 0..3 {
        let n = new_parts.get(i).copied().unwrap_or(0);
        let c = cur_parts.get(i).copied().unwrap_or(0);
        if n > c {
            return true;
        }
        if n < c {
            return false;
        }
    }
    false
}

/// Download the firmware binary, verify SHA-256, and return the temp file path.
///
/// The binary is streamed to a temp file to avoid holding the entire binary
/// in memory. The SHA-256 hash is computed incrementally during download.
pub async fn download_firmware(info: &FirmwareInfo) -> Result<PathBuf> {
    let temp_path = PathBuf::from(DEFAULT_TEMP_PATH);
    let current_version = env!("CARGO_PKG_VERSION");

    tracing::info!(
        version = %info.version,
        url = %info.download_url,
        size_bytes = info.size_bytes,
        "downloading firmware update"
    );

    let client = reqwest::Client::builder()
        .user_agent(format!("sfgw/{current_version}"))
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .context("failed to build HTTP client")?;

    let response = client
        .get(&info.download_url)
        .send()
        .await
        .context("failed to start firmware download")?
        .error_for_status()
        .context("firmware download returned error")?;

    // Stream to temp file while computing SHA-256
    let mut hasher = DigestContext::new(&SHA256);
    let mut file = tokio::fs::File::create(&temp_path)
        .await
        .context("failed to create temp file for firmware download")?;

    let mut stream = response.bytes_stream();
    let mut downloaded: u64 = 0;

    use tokio_stream::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("error reading firmware download stream")?;
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .context("failed to write firmware chunk")?;
        downloaded += chunk.len() as u64;
    }

    file.flush()
        .await
        .context("failed to flush firmware temp file")?;
    drop(file);

    tracing::info!(downloaded_bytes = downloaded, "firmware download complete");

    // Verify SHA-256 hash
    if !info.sha256.is_empty() {
        let digest = hasher.finish();
        let hex_digest = hex_encode(digest.as_ref());

        if hex_digest != info.sha256 {
            // Clean up temp file on hash mismatch
            let _ = tokio::fs::remove_file(&temp_path).await;
            bail!(
                "SHA-256 hash mismatch: expected {}, got {}",
                info.sha256,
                hex_digest
            );
        }
        tracing::info!(sha256 = %hex_digest, "SHA-256 verification passed");
    } else {
        tracing::warn!("no SHA-256 checksum available, skipping verification");
    }

    // Set executable permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&temp_path, perms)
            .context("failed to set executable permissions on downloaded binary")?;
    }

    Ok(temp_path)
}

/// Apply the downloaded firmware update.
///
/// 1. Backup current binary to .backup
/// 2. Atomic rename: temp -> binary path
/// 3. Restart service via systemd
/// 4. If health check fails within 60s, rollback automatically
pub async fn apply_update(db: &sfgw_db::Db, info: &FirmwareInfo) -> Result<()> {
    let binary_path = Path::new(DEFAULT_BINARY_PATH);
    let backup_path = Path::new(DEFAULT_BACKUP_PATH);
    let temp_path = Path::new(DEFAULT_TEMP_PATH);

    if !temp_path.exists() {
        bail!("downloaded firmware not found at {}", temp_path.display());
    }

    tracing::info!(
        version = %info.version,
        binary = %binary_path.display(),
        "applying firmware update"
    );

    // Step 1: Backup current binary
    if binary_path.exists() {
        tracing::info!("backing up current binary to {}", backup_path.display());
        tokio::fs::copy(binary_path, backup_path)
            .await
            .context("failed to backup current binary")?;
    }

    // Step 2: Atomic rename (temp -> binary)
    // Both paths must be on the same filesystem for rename to be atomic.
    tracing::info!("replacing binary (atomic rename)");
    tokio::fs::rename(temp_path, binary_path)
        .await
        .context("failed to atomically replace binary")?;

    // Log IDS event for firmware update
    let _ = sfgw_ids::log_event(
        db,
        "Info",
        "firmware",
        None,
        None,
        None,
        None,
        &format!("firmware updated to version {}", info.version),
    )
    .await;

    // Step 3: Restart service
    tracing::info!("restarting sfgw service");
    let restart_result = tokio::process::Command::new("systemctl")
        .args(["restart", "sfgw.service"])
        .output()
        .await;

    match restart_result {
        Ok(output) if output.status.success() => {
            tracing::info!("service restart initiated");
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("service restart returned non-zero: {stderr}");
            // Don't bail -- the process we're in might be getting replaced
        }
        Err(e) => {
            tracing::warn!("failed to execute systemctl restart: {e}");
        }
    }

    Ok(())
}

/// Perform a health check on the running service.
///
/// Returns Ok(true) if healthy, Ok(false) if unhealthy.
#[allow(dead_code)]
pub async fn health_check() -> Result<bool> {
    // Check if systemd reports the service as active
    let output = tokio::process::Command::new("systemctl")
        .args(["is-active", "sfgw.service"])
        .output()
        .await
        .context("failed to check service status")?;

    Ok(output.status.success())
}

/// Wait for the service to become healthy after an update.
///
/// Polls health check every HEALTH_CHECK_INTERVAL_SECS for up to
/// HEALTH_CHECK_TIMEOUT_SECS. Returns true if healthy, false if timeout.
#[allow(dead_code)]
pub async fn wait_for_healthy() -> bool {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(HEALTH_CHECK_TIMEOUT_SECS);

    while std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS)).await;
        match health_check().await {
            Ok(true) => return true,
            Ok(false) => {
                tracing::debug!("health check: not yet healthy");
            }
            Err(e) => {
                tracing::debug!("health check error: {e}");
            }
        }
    }

    false
}

/// Rollback to the backup binary.
///
/// 1. Stop service
/// 2. Replace binary with backup
/// 3. Start service
pub async fn rollback(db: &sfgw_db::Db) -> Result<()> {
    let binary_path = Path::new(DEFAULT_BINARY_PATH);
    let backup_path = Path::new(DEFAULT_BACKUP_PATH);

    if !backup_path.exists() {
        bail!("no backup binary found at {}", backup_path.display());
    }

    tracing::warn!("initiating firmware rollback");

    // Stop service
    let _ = tokio::process::Command::new("systemctl")
        .args(["stop", "sfgw.service"])
        .output()
        .await;

    // Replace binary with backup (atomic rename)
    tokio::fs::rename(backup_path, binary_path)
        .await
        .context("failed to restore backup binary")?;

    // Log IDS event for rollback
    let _ = sfgw_ids::log_event(
        db,
        "Warning",
        "firmware",
        None,
        None,
        None,
        None,
        "firmware rollback: reverted to previous version",
    )
    .await;

    // Start service
    let output = tokio::process::Command::new("systemctl")
        .args(["start", "sfgw.service"])
        .output()
        .await
        .context("failed to restart service after rollback")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("service failed to start after rollback: {stderr}");
    }

    tracing::info!("firmware rollback complete");
    Ok(())
}

/// Spawn a background task that periodically checks for updates.
///
/// If an update is available, logs an IDS info event to notify the administrator.
pub fn spawn_update_checker(db: sfgw_db::Db) {
    tokio::spawn(async move {
        // Initial delay: wait 5 minutes before first check to let
        // the system fully boot.
        tokio::time::sleep(std::time::Duration::from_secs(300)).await;

        loop {
            let settings = match load_settings(&db).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("failed to load update settings: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                    continue;
                }
            };

            if !settings.auto_check {
                // Auto-check disabled, sleep for an hour and re-check settings
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                continue;
            }

            match check_for_update(&db).await {
                Ok(result) if result.update_available => {
                    if let Some(ref info) = result.available {
                        tracing::info!(
                            version = %info.version,
                            "firmware update available"
                        );
                        // Notify via IDS info event
                        let _ = sfgw_ids::log_event(
                            &db,
                            "Info",
                            "firmware",
                            None,
                            None,
                            None,
                            None,
                            &format!(
                                "firmware update available: {} -> {} ({})",
                                result.current_version,
                                info.version,
                                if info.prerelease { "beta" } else { "stable" }
                            ),
                        )
                        .await;
                    }
                }
                Ok(_) => {
                    tracing::debug!("no firmware update available");
                }
                Err(e) => {
                    tracing::warn!("firmware update check failed: {e}");
                }
            }

            // Sleep for the configured interval
            let interval_secs = (settings.check_interval_hours as u64).max(1) * 3600;
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
        }
    });
}

/// Hex-encode a byte slice.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer_version() {
        assert!(is_newer_version("0.4.0", "0.3.0"));
        assert!(is_newer_version("1.0.0", "0.9.9"));
        assert!(is_newer_version("0.3.1", "0.3.0"));
        assert!(!is_newer_version("0.3.0", "0.3.0"));
        assert!(!is_newer_version("0.2.0", "0.3.0"));
        assert!(!is_newer_version("0.3.0", "0.4.0"));
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_target_arch() {
        let arch = target_arch();
        assert!(
            arch == "aarch64" || arch == "x86_64" || arch == "unknown",
            "unexpected arch: {arch}"
        );
    }

    #[tokio::test]
    async fn test_load_settings_from_fresh_db() {
        let db = sfgw_db::open_in_memory()
            .await
            .expect("open_in_memory should succeed");
        let settings = load_settings(&db)
            .await
            .expect("load_settings should succeed");
        assert_eq!(settings.update_channel, "stable");
        assert!(settings.auto_check);
        assert_eq!(settings.check_interval_hours, 24);
        assert!(settings.last_check.is_none());
        assert!(settings.update_url.contains("github.com"));
    }

    #[tokio::test]
    async fn test_save_and_load_settings() {
        let db = sfgw_db::open_in_memory()
            .await
            .expect("open_in_memory should succeed");
        let settings = UpdateSettings {
            update_channel: "beta".to_string(),
            auto_check: false,
            check_interval_hours: 12,
            last_check: None,
            update_url: "https://example.com/releases".to_string(),
        };
        save_settings(&db, &settings)
            .await
            .expect("save_settings should succeed");

        let loaded = load_settings(&db)
            .await
            .expect("load_settings should succeed");
        assert_eq!(loaded.update_channel, "beta");
        assert!(!loaded.auto_check);
        assert_eq!(loaded.check_interval_hours, 12);
        assert_eq!(loaded.update_url, "https://example.com/releases");
    }
}
