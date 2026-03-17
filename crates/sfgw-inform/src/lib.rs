// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! Ubiquiti Inform protocol implementation for secfirstgw.
//!
//! Implements the stock UniFi Inform protocol on port 8080 to adopt and manage
//! UniFi devices (switches, APs) without a Ubiquiti controller.
//!
//! **INTEROP CODE**: This crate uses AES-128-CBC, AES-128-GCM, and MD5 for
//! compatibility with stock UniFi firmware. These are weaker than the project's
//! standard crypto (AES-256-GCM, no MD5) but required for protocol compatibility.
//! All weak crypto usage is isolated in the `crypto` module.
//!
//! ## Architecture
//!
//! - `packet` — TNBU binary format parse/serialize
//! - `crypto` — AES-128-CBC/GCM encrypt/decrypt, default key, authkey management
//! - `codec` — zlib/snappy compression
//! - `payload` — Inform JSON types, OUI database, model codes
//! - `state` — Device state machine (Pending/Ignored/Adopting/Adopted/Phantom)
//! - `rate` — Two-tier rate limiting per source IP
//! - `handler` — HTTP handler for POST /inform
//!
//! ## Security Features (vs. stock UniFi Controller)
//!
//! - Passive validation before showing devices (OUI, IP match, model check)
//! - Phantom device detection with IDS alerting
//! - Per-IP rate limiting with automatic IDS escalation
//! - Hardware fingerprint verification via SSH before authkey delivery
//! - Per-device SSH credentials after adoption (no shared password)
//! - Inform listener bound to MGMT interface only

pub mod codec;
pub mod crypto;
pub mod handler;
pub mod packet;
pub mod payload;
pub mod port_config;
pub mod provision;
pub mod rate;
pub mod state;
pub mod system_cfg;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::routing::post;
use tokio::sync::Mutex;

use handler::InformState;
use rate::RateLimiter;

/// Shared handle to the running Inform listener.
///
/// Allows starting/stopping the listener from the API without a restart.
pub type InformHandle = Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>;

/// Handle to the Inform state (in-memory device map with live stats).
pub type StateHandle = Arc<Mutex<Option<Arc<handler::InformState>>>>;

/// Create a new (empty) InformHandle.
pub fn new_handle() -> InformHandle {
    Arc::new(Mutex::new(None))
}

/// Create a new (empty) StateHandle.
pub fn new_state_handle() -> StateHandle {
    Arc::new(Mutex::new(None))
}

/// Meta key for the Ubiquiti Inform enabled setting.
const META_KEY_INFORM_ENABLED: &str = "ubiquiti_inform_enabled";

/// Check whether Ubiquiti Inform is enabled in settings.
pub async fn is_enabled(db: &sfgw_db::Db) -> Result<bool> {
    let conn = db.lock().await;
    let result = conn.query_row(
        "SELECT value FROM meta WHERE key = ?1",
        [META_KEY_INFORM_ENABLED],
        |r| r.get::<_, String>(0),
    );
    match result {
        Ok(val) => Ok(val == "true"),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => Err(e).context("failed to read inform enabled setting"),
    }
}

/// Enable or disable Ubiquiti Inform.
///
/// When enabled:
/// - Adds DNS overrides for `unifi` and `unifi.lan` pointing to MGMT IP
/// - Starts HTTP listener on port 8080 (MGMT interface only)
///
/// When disabled:
/// - Removes the DNS overrides
/// - Stops the listener (on next restart)
pub async fn set_enabled(
    db: &sfgw_db::Db,
    enabled: bool,
    inform_handle: &InformHandle,
    state_handle: &StateHandle,
) -> Result<()> {
    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![
            META_KEY_INFORM_ENABLED,
            if enabled { "true" } else { "false" }
        ],
    )?;
    drop(conn);

    // Update DNS overrides and listener lifecycle
    if enabled {
        ensure_dns_overrides(db).await?;
        // Hot-start the listener if not already running
        let is_running = inform_handle.lock().await.is_some();
        if !is_running {
            start(db, inform_handle, state_handle).await?;
        }
    } else {
        remove_dns_overrides(db).await?;
        stop(inform_handle).await;
    }

    tracing::info!(enabled, "ubiquiti inform setting updated");
    Ok(())
}

/// Ensure DNS overrides for `unifi` and `unifi.lan` point to the MGMT gateway IP.
async fn ensure_dns_overrides(db: &sfgw_db::Db) -> Result<()> {
    // Find the MGMT gateway IP from the networks table
    let mgmt_ip = {
        let conn = db.lock().await;
        conn.query_row(
            "SELECT gateway FROM networks WHERE zone = 'mgmt' AND enabled = 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .context("no enabled MGMT network found — cannot set Inform DNS overrides")?
    };

    // Load existing user overrides
    let mut overrides = sfgw_dns::load_dns_overrides(db).await?;

    // Remove any existing unifi/unifi.lan entries (avoid duplicates)
    overrides.retain(|o| o.domain != "unifi" && o.domain != "unifi.lan");

    // Add system overrides
    overrides.push(sfgw_dns::DnsOverride {
        domain: "unifi".into(),
        ip: mgmt_ip.clone(),
    });
    overrides.push(sfgw_dns::DnsOverride {
        domain: "unifi.lan".into(),
        ip: mgmt_ip.clone(),
    });

    sfgw_dns::save_dns_overrides(db, &overrides).await?;

    // Trigger dnsmasq reload so overrides take effect immediately
    if let Err(e) = sfgw_dns::reload_by_pid_file(db).await {
        tracing::warn!(error = %e, "failed to reload dnsmasq after DNS override change");
    }

    tracing::info!(
        mgmt_ip = %mgmt_ip,
        "DNS overrides set: unifi → {mgmt_ip}, unifi.lan → {mgmt_ip}"
    );

    Ok(())
}

/// Remove the `unifi` and `unifi.lan` DNS overrides.
async fn remove_dns_overrides(db: &sfgw_db::Db) -> Result<()> {
    let mut overrides = sfgw_dns::load_dns_overrides(db).await?;
    let before = overrides.len();
    overrides.retain(|o| o.domain != "unifi" && o.domain != "unifi.lan");

    if overrides.len() != before {
        sfgw_dns::save_dns_overrides(db, &overrides).await?;
        if let Err(e) = sfgw_dns::reload_by_pid_file(db).await {
            tracing::warn!(error = %e, "failed to reload dnsmasq after DNS override removal");
        }
        tracing::info!("DNS overrides removed: unifi, unifi.lan");
    }

    Ok(())
}

/// Start the Ubiquiti Inform listener on port 8080.
///
/// Binds to the MGMT interface IP only (not 0.0.0.0).
/// Stores the join handle in `inform_handle` for lifecycle management.
///
/// Call this only if `is_enabled()` returns true.
pub async fn start(
    db: &sfgw_db::Db,
    inform_handle: &InformHandle,
    state_handle: &StateHandle,
) -> Result<()> {
    // Ensure DNS overrides are set
    ensure_dns_overrides(db).await?;

    // Load existing devices from DB into memory
    let devices = load_devices_from_db(db).await?;

    let state = Arc::new(InformState {
        db: db.clone(),
        devices: Mutex::new(devices),
        rate_limiter: RateLimiter::new(),
    });

    // Find MGMT interface IP for binding
    let bind_addr = resolve_mgmt_bind_addr(db).await?;

    let app = Router::new()
        .route("/inform", post(handler::handle_inform))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind Inform listener on {bind_addr}"))?;

    tracing::info!(
        bind = %bind_addr,
        "Ubiquiti Inform listener started (TNBU protocol, port 8080)"
    );

    // Spawn rate limiter cleanup task
    let state_cleanup = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(120));
        loop {
            interval.tick().await;
            state_cleanup.rate_limiter.cleanup();
        }
    });

    // Spawn the HTTP server
    let handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!(error = %e, "Inform listener exited with error");
        }
    });

    *state_handle.lock().await = Some(state);
    *inform_handle.lock().await = Some(handle);
    Ok(())
}

/// Stop the Inform listener if running.
pub async fn stop(inform_handle: &InformHandle) {
    let mut guard = inform_handle.lock().await;
    if let Some(handle) = guard.take() {
        handle.abort();
        tracing::info!("Ubiquiti Inform listener stopped");
    }
}

/// Load Ubiquiti devices from the database into the in-memory map.
async fn load_devices_from_db(db: &sfgw_db::Db) -> Result<HashMap<String, state::UbntDevice>> {
    let conn = db.lock().await;
    let mut stmt = conn.prepare("SELECT mac, config FROM devices")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;

    let mut devices = HashMap::new();
    for row in rows {
        let (mac, config_json) = row?;
        // Try to parse as UbntDevice — if it's a different device type, skip
        if let Ok(dev) = serde_json::from_str::<state::UbntDevice>(&config_json) {
            devices.insert(mac, dev);
        }
    }

    tracing::debug!(count = devices.len(), "loaded Ubiquiti devices from DB");
    Ok(devices)
}

/// Resolve the MGMT interface bind address for port 8080.
async fn resolve_mgmt_bind_addr(db: &sfgw_db::Db) -> Result<SocketAddr> {
    let conn = db.lock().await;
    let mgmt_ip: String = conn
        .query_row(
            "SELECT gateway FROM networks WHERE zone = 'mgmt' AND enabled = 1",
            [],
            |r| r.get(0),
        )
        .context("no enabled MGMT network — cannot start Inform listener")?;

    let addr: SocketAddr = format!("{mgmt_ip}:8080")
        .parse()
        .with_context(|| format!("invalid MGMT IP for binding: {mgmt_ip}"))?;

    Ok(addr)
}

/// Initiate device adoption (set state to Adopting, then spawn SSH provisioning).
///
/// Returns immediately after setting state. The SSH provisioning runs in background.
/// On success, device transitions to Adopted. On failure, stays at Adopting (retryable).
pub async fn adopt_device(db: &sfgw_db::Db, mac: &str) -> Result<()> {
    // Load the device from DB
    let device = {
        let conn = db.lock().await;
        let config_json: String = conn
            .query_row(
                "SELECT config FROM devices WHERE mac = ?1",
                rusqlite::params![mac],
                |r| r.get(0),
            )
            .with_context(|| format!("device {mac} not found"))?;

        let mut dev: state::UbntDevice =
            serde_json::from_str(&config_json).context("failed to parse device config")?;

        // Set to Adopting
        dev.state = state::UbntDeviceState::Adopting;
        let updated = serde_json::to_string(&dev)?;
        conn.execute(
            "UPDATE devices SET config = ?1 WHERE mac = ?2",
            rusqlite::params![updated, mac],
        )?;
        dev
    };

    tracing::info!(mac = %mac, model = %device.model_display, "adoption initiated — spawning SSH provisioning");

    // Spawn async provisioning (non-blocking)
    let db_clone = db.clone();
    tokio::spawn(async move {
        match provision::provision_device(&db_clone, &device).await {
            Ok(result) => {
                tracing::info!(
                    mac = %device.mac,
                    serial = %result.fingerprint.serialno,
                    "adoption complete — device verified and provisioned"
                );
            }
            Err(e) => {
                tracing::error!(
                    mac = %device.mac,
                    error = %e,
                    "adoption failed — device stays in Adopting state (retryable)"
                );
                // Log to IDS as a warning
                if let Err(ids_err) = sfgw_ids::log_event(
                    &db_clone,
                    "warning",
                    "ubnt-inform",
                    Some(&device.mac),
                    Some(&device.source_ip),
                    None,
                    None,
                    &format!("SSH provisioning failed for {}: {e}", device.model_display),
                )
                .await
                {
                    tracing::warn!(error = %ids_err, "failed to log adoption failure to IDS");
                }
            }
        }
    });

    Ok(())
}

/// List all Ubiquiti devices (any state).
pub async fn list_devices(
    db: &sfgw_db::Db,
    state_handle: &StateHandle,
) -> Result<Vec<state::UbntDevice>> {
    // Prefer in-memory state (has live stats) over DB-only
    if let Some(ref inform_state) = *state_handle.lock().await {
        let devices = inform_state.devices.lock().await;
        return Ok(devices.values().cloned().collect());
    }
    // Fallback: DB only (no live stats)
    let devices = load_devices_from_db(db).await?;
    Ok(devices.into_values().collect())
}

/// Get port configuration for a device.
pub async fn get_port_config(
    db: &sfgw_db::Db,
    state_handle: &StateHandle,
    mac: &str,
) -> Result<Option<port_config::SwitchConfig>> {
    // Prefer in-memory state
    if let Some(ref inform_state) = *state_handle.lock().await {
        let devices = inform_state.devices.lock().await;
        if let Some(dev) = devices.get(mac) {
            return Ok(dev.port_config.clone());
        }
    }
    // Fallback: DB
    let conn = db.lock().await;
    let config_json: String = match conn.query_row(
        "SELECT config FROM devices WHERE mac = ?1",
        rusqlite::params![mac],
        |r| r.get(0),
    ) {
        Ok(c) => c,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let dev: state::UbntDevice = serde_json::from_str(&config_json)?;
    Ok(dev.port_config)
}

/// Set port configuration for a device. Persists to DB and updates in-memory state.
pub async fn set_port_config(
    db: &sfgw_db::Db,
    state_handle: &StateHandle,
    mac: &str,
    config: port_config::SwitchConfig,
) -> Result<()> {
    // Update in-memory state
    if let Some(ref inform_state) = *state_handle.lock().await {
        let mut devices = inform_state.devices.lock().await;
        if let Some(dev) = devices.get_mut(mac) {
            dev.port_config = Some(config.clone());
        }
    }

    // Persist to DB
    let conn = db.lock().await;
    let config_json: String = conn
        .query_row(
            "SELECT config FROM devices WHERE mac = ?1",
            rusqlite::params![mac],
            |r| r.get(0),
        )
        .with_context(|| format!("device {mac} not found"))?;

    let mut dev: state::UbntDevice =
        serde_json::from_str(&config_json).context("failed to parse device config")?;
    dev.port_config = Some(config);
    let updated = serde_json::to_string(&dev)?;
    conn.execute(
        "UPDATE devices SET config = ?1 WHERE mac = ?2",
        rusqlite::params![updated, mac],
    )?;

    tracing::info!(mac = %mac, "port configuration updated");
    Ok(())
}

/// Remove/forget a Ubiquiti device from the database and in-memory state.
pub async fn remove_device(
    db: &sfgw_db::Db,
    mac: &str,
    state_handle: &StateHandle,
) -> Result<bool> {
    // Remove from in-memory state
    if let Some(ref inform_state) = *state_handle.lock().await {
        inform_state.devices.lock().await.remove(mac);
    }

    let conn = db.lock().await;
    let rows = conn.execute("DELETE FROM devices WHERE mac = ?1", rusqlite::params![mac])?;
    if rows > 0 {
        tracing::info!(mac = %mac, "device removed from inform database");
    }
    Ok(rows > 0)
}

/// Set a device to Ignored state.
pub async fn ignore_device(db: &sfgw_db::Db, mac: &str) -> Result<bool> {
    let conn = db.lock().await;
    let config_json: String = match conn.query_row(
        "SELECT config FROM devices WHERE mac = ?1",
        rusqlite::params![mac],
        |r| r.get(0),
    ) {
        Ok(c) => c,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(false),
        Err(e) => return Err(e.into()),
    };

    let mut dev: state::UbntDevice =
        serde_json::from_str(&config_json).context("failed to parse device config")?;

    dev.state = state::UbntDeviceState::Ignored;
    let updated = serde_json::to_string(&dev)?;

    conn.execute(
        "UPDATE devices SET config = ?1 WHERE mac = ?2",
        rusqlite::params![updated, mac],
    )?;

    tracing::info!(mac = %mac, "device ignored");
    Ok(true)
}

/// List Ubiquiti devices in a specific state.
pub async fn list_by_state(
    db: &sfgw_db::Db,
    filter: state::UbntDeviceState,
) -> Result<Vec<state::UbntDevice>> {
    let devices = load_devices_from_db(db).await?;
    Ok(devices
        .into_values()
        .filter(|d| d.state == filter)
        .collect())
}
