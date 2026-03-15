// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! High-level orchestration and service lifecycle management for secfirstgw.
//!
//! The controller is responsible for:
//! - **Service health monitoring** -- periodically checks if gateway services
//!   (dnsmasq, nftables, WireGuard) are running.
//! - **Device lifecycle management** -- tracks adopted devices, detects offline
//!   devices, triggers re-adoption if needed.
//! - **Config reconciliation** -- when config changes in the DB, pushes updates
//!   to the relevant services.
//! - **Watchdog** -- restarts crashed services automatically.

use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sfgw_db::Db;
use std::fmt;
use std::path::Path;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors specific to the controller crate.
#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
    #[error("service not found: {0}")]
    ServiceNotFound(String),
    #[error("service restart failed for {name}: {reason}")]
    RestartFailed { name: String, reason: String },
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// Wrapped anyhow error for internal context propagation.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Convenience alias for results from this crate.
type Result<T> = std::result::Result<T, ControllerError>;

// ---------------------------------------------------------------------------
// ServiceStatus
// ---------------------------------------------------------------------------

/// Status of a managed system service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStatus {
    /// Service process is running normally.
    Running,
    /// Service is not running (clean stop).
    Stopped,
    /// Service exited with an error or is in a failed state.
    Failed,
    /// Status could not be determined.
    Unknown,
}

impl fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => write!(f, "running"),
            Self::Stopped => write!(f, "stopped"),
            Self::Failed => write!(f, "failed"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl ServiceStatus {
    /// Parse a status string (as stored in the DB) into a `ServiceStatus`.
    #[must_use]
    pub fn from_str_lossy(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "running" => Self::Running,
            "stopped" => Self::Stopped,
            "failed" => Self::Failed,
            _ => Self::Unknown,
        }
    }

    /// Returns `true` if the service requires attention (not running).
    #[must_use]
    pub fn needs_restart(&self) -> bool {
        matches!(self, Self::Failed | Self::Stopped)
    }
}

// ---------------------------------------------------------------------------
// ServiceHealth (DB row)
// ---------------------------------------------------------------------------

/// Health record for a single service, stored in the `service_health` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHealth {
    pub name: String,
    pub status: ServiceStatus,
    pub last_check: String,
    pub last_restart: Option<String>,
    pub restart_count: i64,
}

// ---------------------------------------------------------------------------
// Managed services list
// ---------------------------------------------------------------------------

/// Services the controller monitors and can restart.
pub const MANAGED_SERVICES: &[&str] = &["dnsmasq", "nftables", "wireguard"];

/// Maximum automatic restarts before giving up (per service, without manual
/// reset).
const MAX_AUTO_RESTARTS: i64 = 5;

/// Health check interval.
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Device check interval.
const DEVICE_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// How long before an adopted device is considered offline (seconds).
const DEVICE_OFFLINE_THRESHOLD_SECS: i64 = 300;

// ---------------------------------------------------------------------------
// Controller struct
// ---------------------------------------------------------------------------

/// High-level controller that owns the background monitoring loops.
pub struct Controller {
    db: Db,
}

impl Controller {
    /// Create a new controller backed by the given database handle.
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Returns a reference to the database handle.
    pub fn db(&self) -> &Db {
        &self.db
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Start the controller: initialise the `service_health` table and spawn
/// background monitoring loops. Returns immediately.
pub async fn start(db: &Db) -> Result<()> {
    ensure_service_health_table(db).await?;

    // Seed initial rows for each managed service.
    for svc in MANAGED_SERVICES {
        upsert_service_health(db, svc, ServiceStatus::Unknown).await?;
    }

    let db_health = db.clone();
    tokio::spawn(async move {
        health_check_loop(db_health).await;
    });

    let db_device = db.clone();
    tokio::spawn(async move {
        device_check_loop(db_device).await;
    });

    tracing::info!("network controller ready (health + device monitoring active)");
    Ok(())
}

// ---------------------------------------------------------------------------
// Service probing
// ---------------------------------------------------------------------------

/// Check whether a service process is currently running.
///
/// Uses `/proc` scanning to avoid shelling out where possible, falling back
/// to `systemctl is-active` when `/proc` is unavailable (e.g. Docker).
#[must_use]
pub fn check_service(name: &str) -> ServiceStatus {
    // First try: look for a matching process name in /proc.
    if let Some(status) = check_service_via_proc(name) {
        return status;
    }

    // Fallback: use `systemctl is-active`.
    check_service_via_systemctl(name)
}

/// Scan `/proc/*/comm` for a process whose comm matches `name`.
fn check_service_via_proc(name: &str) -> Option<ServiceStatus> {
    let proc_dir = Path::new("/proc");
    if !proc_dir.exists() {
        return None;
    }

    let entries = match std::fs::read_dir(proc_dir) {
        Ok(e) => e,
        Err(_) => return None,
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let fname = file_name.to_string_lossy();
        // Only look at numeric directories (PIDs).
        if !fname.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let comm_path = entry.path().join("comm");
        if let Ok(comm) = std::fs::read_to_string(&comm_path)
            && comm.trim() == name
        {
            return Some(ServiceStatus::Running);
        }
    }

    Some(ServiceStatus::Stopped)
}

/// Use `systemctl is-active` as a fallback.
fn check_service_via_systemctl(name: &str) -> ServiceStatus {
    let output = std::process::Command::new("systemctl")
        .arg("is-active")
        .arg(name)
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            parse_systemctl_status(stdout.trim())
        }
        Err(_) => ServiceStatus::Unknown,
    }
}

/// Parse the single-word output of `systemctl is-active`.
#[must_use]
pub fn parse_systemctl_status(output: &str) -> ServiceStatus {
    match output.trim().to_lowercase().as_str() {
        "active" => ServiceStatus::Running,
        "inactive" => ServiceStatus::Stopped,
        "failed" => ServiceStatus::Failed,
        "activating" | "deactivating" | "reloading" => ServiceStatus::Running,
        _ => ServiceStatus::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Service restart
// ---------------------------------------------------------------------------

/// Attempt to restart a managed service via `systemctl restart`.
pub async fn restart_service(name: &str) -> Result<()> {
    if !MANAGED_SERVICES.contains(&name) {
        return Err(ControllerError::ServiceNotFound(name.to_owned()));
    }

    tracing::warn!(service = %name, "restarting service");

    let output = tokio::process::Command::new("systemctl")
        .arg("restart")
        .arg(name)
        .output()
        .await
        .with_context(|| format!("failed to execute systemctl restart {name}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ControllerError::RestartFailed {
            name: name.to_owned(),
            reason: stderr.to_string(),
        });
    }

    tracing::info!(service = %name, "service restarted successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

/// Create the `service_health` table if it does not exist.
async fn ensure_service_health_table(db: &Db) -> Result<()> {
    let conn = db.lock().await;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS service_health (
            name          TEXT PRIMARY KEY,
            status        TEXT NOT NULL DEFAULT 'unknown',
            last_check    TEXT NOT NULL DEFAULT '',
            last_restart  TEXT,
            restart_count INTEGER NOT NULL DEFAULT 0
        );",
    )
    .context("failed to create service_health table")?;
    Ok(())
}

/// Insert or update a service health row.
async fn upsert_service_health(db: &Db, name: &str, status: ServiceStatus) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO service_health (name, status, last_check)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(name) DO UPDATE SET status = ?2, last_check = ?3",
        rusqlite::params![name, status.to_string(), now],
    )?;
    Ok(())
}

/// Record a restart attempt in the DB.
async fn record_restart(db: &Db, name: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let conn = db.lock().await;
    conn.execute(
        "UPDATE service_health
         SET last_restart = ?1, restart_count = restart_count + 1
         WHERE name = ?2",
        rusqlite::params![now, name],
    )?;
    Ok(())
}

/// Get the current restart count for a service.
async fn get_restart_count(db: &Db, name: &str) -> Result<i64> {
    let conn = db.lock().await;
    let count: i64 = conn
        .query_row(
            "SELECT restart_count FROM service_health WHERE name = ?1",
            rusqlite::params![name],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(count)
}

/// Load all service health records.
pub async fn get_all_service_health(db: &Db) -> Result<Vec<ServiceHealth>> {
    let conn = db.lock().await;
    let mut stmt = conn.prepare(
        "SELECT name, status, last_check, last_restart, restart_count FROM service_health",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(ServiceHealth {
            name: row.get(0)?,
            status: ServiceStatus::from_str_lossy(&row.get::<_, String>(1)?),
            last_check: row.get(2)?,
            last_restart: row.get(3)?,
            restart_count: row.get(4)?,
        })
    })?;
    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Config reconciliation
// ---------------------------------------------------------------------------

/// Detect whether a config-change flag is set for a given service domain.
///
/// The convention is a row in the `meta` table:
///   key = "config_changed:<domain>"  value = "1"
///
/// Domains map to services: "dns" -> dnsmasq, "firewall" -> nftables,
/// "vpn" -> wireguard.
pub async fn check_config_changed(db: &Db, domain: &str) -> Result<bool> {
    let key = format!("config_changed:{domain}");
    let conn = db.lock().await;
    let val: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            rusqlite::params![key],
            |r| r.get(0),
        )
        .ok();
    Ok(val.as_deref() == Some("1"))
}

/// Clear the config-change flag after the service has been reloaded.
async fn clear_config_changed(db: &Db, domain: &str) -> Result<()> {
    let key = format!("config_changed:{domain}");
    let conn = db.lock().await;
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, '0')",
        rusqlite::params![key],
    )?;
    Ok(())
}

/// Map a config domain to the service that needs restarting.
#[must_use]
pub fn domain_to_service(domain: &str) -> Option<&'static str> {
    match domain {
        "dns" => Some("dnsmasq"),
        "firewall" => Some("nftables"),
        "vpn" => Some("wireguard"),
        _ => None,
    }
}

/// Check all config domains and restart services whose config has changed.
async fn reconcile_configs(db: &Db) {
    let domains = ["dns", "firewall", "vpn"];
    for domain in &domains {
        match check_config_changed(db, domain).await {
            Ok(true) => {
                if let Some(svc) = domain_to_service(domain) {
                    tracing::info!(domain = %domain, service = %svc, "config change detected, restarting");
                    if let Err(e) = restart_service(svc).await {
                        tracing::error!(service = %svc, error = %e, "config reconciliation restart failed");
                    } else if let Err(e) = clear_config_changed(db, domain).await {
                        tracing::error!(domain = %domain, error = %e, "failed to clear config_changed flag");
                    }
                }
            }
            Ok(false) => {}
            Err(e) => {
                tracing::error!(domain = %domain, error = %e, "failed to check config_changed");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Device offline detection
// ---------------------------------------------------------------------------

/// Determine whether a device should be considered offline based on its
/// `last_seen` timestamp and a threshold.
#[must_use]
pub fn is_device_offline(last_seen: Option<&str>, threshold_secs: i64) -> bool {
    let Some(ts_str) = last_seen else {
        // Never seen -- treat as offline.
        return true;
    };

    let Ok(ts) = chrono::DateTime::parse_from_rfc3339(ts_str) else {
        // Unparseable timestamp -- treat as offline.
        return true;
    };

    let elapsed = Utc::now().signed_duration_since(ts);
    elapsed.num_seconds() > threshold_secs
}

/// Check adopted devices and mark any that have gone offline.
async fn check_devices(db: &Db) {
    let devices = match sfgw_adopt::list_devices(db).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "failed to list devices for offline check");
            return;
        }
    };

    for dev in &devices {
        if dev.state != sfgw_adopt::AdoptionState::Adopted {
            continue;
        }

        if is_device_offline(dev.last_seen.as_deref(), DEVICE_OFFLINE_THRESHOLD_SECS) {
            tracing::warn!(
                mac = %dev.mac,
                last_seen = ?dev.last_seen,
                "adopted device appears offline"
            );
            // Mark in the DB so the API/UI can surface it.
            if let Err(e) = mark_device_offline(db, &dev.mac).await {
                tracing::error!(mac = %dev.mac, error = %e, "failed to mark device offline");
            }
        }
    }
}

/// Store an offline flag for a device in the meta table.
async fn mark_device_offline(db: &Db, mac: &str) -> Result<()> {
    let key = format!("device_offline:{mac}");
    let now = Utc::now().to_rfc3339();
    let conn = db.lock().await;
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
        rusqlite::params![key, now],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Background loops
// ---------------------------------------------------------------------------

/// Background loop: check service health every 30 seconds.
async fn health_check_loop(db: Db) {
    let mut interval = tokio::time::interval(HEALTH_CHECK_INTERVAL);
    loop {
        interval.tick().await;

        for svc_name in MANAGED_SERVICES {
            let status = check_service(svc_name);
            if let Err(e) = upsert_service_health(&db, svc_name, status).await {
                tracing::error!(service = %svc_name, error = %e, "failed to update service health");
                continue;
            }

            tracing::debug!(service = %svc_name, status = %status, "health check");

            // Watchdog: restart if needed and under the restart cap.
            if status.needs_restart() {
                let restart_count = get_restart_count(&db, svc_name).await.unwrap_or(0);
                if restart_count < MAX_AUTO_RESTARTS {
                    tracing::warn!(
                        service = %svc_name,
                        status = %status,
                        restarts = restart_count,
                        "watchdog triggering restart"
                    );
                    if let Err(e) = restart_service(svc_name).await {
                        tracing::error!(service = %svc_name, error = %e, "watchdog restart failed");
                    }
                    if let Err(e) = record_restart(&db, svc_name).await {
                        tracing::error!(service = %svc_name, error = %e, "failed to record restart");
                    }
                } else {
                    tracing::error!(
                        service = %svc_name,
                        restarts = restart_count,
                        "max auto-restarts reached, manual intervention required"
                    );
                }
            }
        }

        // Config reconciliation runs on the same cadence as health checks.
        reconcile_configs(&db).await;
    }
}

/// Background loop: check adopted devices every 60 seconds.
async fn device_check_loop(db: Db) {
    let mut interval = tokio::time::interval(DEVICE_CHECK_INTERVAL);
    loop {
        interval.tick().await;
        tracing::debug!("running device offline check");
        check_devices(&db).await;
    }
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test helpers -------------------------------------------------------

    /// Create an in-memory SQLite database with the gateway schema.
    async fn test_db() -> Db {
        use rusqlite::Connection;
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let conn = Connection::open_in_memory().expect("open in-memory db"); // INVARIANT: in-memory open cannot fail
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
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
            CREATE TABLE IF NOT EXISTS service_health (
                name          TEXT PRIMARY KEY,
                status        TEXT NOT NULL DEFAULT 'unknown',
                last_check    TEXT NOT NULL DEFAULT '',
                last_restart  TEXT,
                restart_count INTEGER NOT NULL DEFAULT 0
            );",
        )
        .expect("create test schema"); // INVARIANT: static DDL cannot fail

        Arc::new(Mutex::new(conn))
    }

    // -- ServiceStatus parsing ----------------------------------------------

    #[test]
    fn service_status_from_str_lossy_known_values() {
        assert_eq!(
            ServiceStatus::from_str_lossy("running"),
            ServiceStatus::Running
        );
        assert_eq!(
            ServiceStatus::from_str_lossy("stopped"),
            ServiceStatus::Stopped
        );
        assert_eq!(
            ServiceStatus::from_str_lossy("failed"),
            ServiceStatus::Failed
        );
        assert_eq!(
            ServiceStatus::from_str_lossy("Running"),
            ServiceStatus::Running
        );
        assert_eq!(
            ServiceStatus::from_str_lossy("  FAILED  "),
            ServiceStatus::Failed
        );
    }

    #[test]
    fn service_status_from_str_lossy_unknown() {
        assert_eq!(ServiceStatus::from_str_lossy(""), ServiceStatus::Unknown);
        assert_eq!(
            ServiceStatus::from_str_lossy("banana"),
            ServiceStatus::Unknown
        );
        assert_eq!(
            ServiceStatus::from_str_lossy("activating"),
            ServiceStatus::Unknown
        );
    }

    #[test]
    fn parse_systemctl_status_values() {
        assert_eq!(parse_systemctl_status("active"), ServiceStatus::Running);
        assert_eq!(parse_systemctl_status("inactive"), ServiceStatus::Stopped);
        assert_eq!(parse_systemctl_status("failed"), ServiceStatus::Failed);
        assert_eq!(parse_systemctl_status("activating"), ServiceStatus::Running);
        assert_eq!(
            parse_systemctl_status("deactivating"),
            ServiceStatus::Running
        );
        assert_eq!(
            parse_systemctl_status("unknown-thing"),
            ServiceStatus::Unknown
        );
    }

    #[test]
    fn service_status_needs_restart() {
        assert!(ServiceStatus::Failed.needs_restart());
        assert!(ServiceStatus::Stopped.needs_restart());
        assert!(!ServiceStatus::Running.needs_restart());
        assert!(!ServiceStatus::Unknown.needs_restart());
    }

    // -- Device offline detection -------------------------------------------

    #[test]
    fn device_offline_when_never_seen() {
        assert!(is_device_offline(None, 300));
    }

    #[test]
    fn device_offline_with_bad_timestamp() {
        assert!(is_device_offline(Some("not-a-date"), 300));
    }

    #[test]
    fn device_offline_when_stale() {
        // 10 minutes ago -- threshold is 5 minutes.
        let ten_min_ago = (Utc::now() - chrono::Duration::seconds(600)).to_rfc3339();
        assert!(is_device_offline(Some(&ten_min_ago), 300));
    }

    #[test]
    fn device_online_when_recent() {
        let just_now = Utc::now().to_rfc3339();
        assert!(!is_device_offline(Some(&just_now), 300));
    }

    // -- Config change detection --------------------------------------------

    #[tokio::test]
    async fn config_change_detected_and_cleared() {
        let db = test_db().await;

        // Initially no change flagged.
        let changed = check_config_changed(&db, "dns")
            .await
            .expect("check config"); // INVARIANT: in-memory DB query
        assert!(!changed);

        // Flag a change.
        {
            let conn = db.lock().await;
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, '1')",
                rusqlite::params!["config_changed:dns"],
            )
            .expect("insert flag"); // INVARIANT: in-memory DB
        }

        let changed = check_config_changed(&db, "dns")
            .await
            .expect("check config");
        assert!(changed);

        // Clear it.
        clear_config_changed(&db, "dns").await.expect("clear flag");

        let changed = check_config_changed(&db, "dns")
            .await
            .expect("check config");
        assert!(!changed);
    }

    // -- Domain-to-service mapping ------------------------------------------

    #[test]
    fn domain_to_service_mapping() {
        assert_eq!(domain_to_service("dns"), Some("dnsmasq"));
        assert_eq!(domain_to_service("firewall"), Some("nftables"));
        assert_eq!(domain_to_service("vpn"), Some("wireguard"));
        assert_eq!(domain_to_service("nonexistent"), None);
    }

    // -- DB upsert / restart tracking ---------------------------------------

    #[tokio::test]
    async fn upsert_and_read_service_health() {
        let db = test_db().await;

        upsert_service_health(&db, "dnsmasq", ServiceStatus::Running)
            .await
            .expect("upsert");

        let all = get_all_service_health(&db).await.expect("get all");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "dnsmasq");
        assert_eq!(all[0].status, ServiceStatus::Running);
        assert_eq!(all[0].restart_count, 0);

        // Update status.
        upsert_service_health(&db, "dnsmasq", ServiceStatus::Failed)
            .await
            .expect("upsert update");
        let all = get_all_service_health(&db).await.expect("get all");
        assert_eq!(all[0].status, ServiceStatus::Failed);
    }

    #[tokio::test]
    async fn restart_count_increments() {
        let db = test_db().await;

        upsert_service_health(&db, "nftables", ServiceStatus::Failed)
            .await
            .expect("upsert");

        record_restart(&db, "nftables")
            .await
            .expect("record restart");
        record_restart(&db, "nftables")
            .await
            .expect("record restart");

        let count = get_restart_count(&db, "nftables").await.expect("count");
        assert_eq!(count, 2);
    }

    // -- ServiceStatus Display roundtrip ------------------------------------

    #[test]
    fn service_status_display_roundtrip() {
        for status in &[
            ServiceStatus::Running,
            ServiceStatus::Stopped,
            ServiceStatus::Failed,
            ServiceStatus::Unknown,
        ] {
            let s = status.to_string();
            assert_eq!(ServiceStatus::from_str_lossy(&s), *status);
        }
    }
}
