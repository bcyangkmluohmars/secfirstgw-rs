// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! Active Directory / LDAP integration endpoints.
//!
//! Provides configuration, testing, domain join/leave, and user/group sync
//! for seamless SMB access via Samba + winbind.
//!
//! Endpoints:
//! - `GET  /auth/ad/config`  — Get AD configuration (password redacted)
//! - `PUT  /auth/ad/config`  — Save AD configuration
//! - `POST /auth/ad/test`    — Test LDAP connection
//! - `POST /auth/ad/join`    — Join the AD domain
//! - `POST /auth/ad/leave`   — Leave the AD domain
//! - `POST /auth/ad/sync`    — Trigger manual user/group sync
//! - `GET  /auth/ad/status`  — Get AD join status + sync info

use crate::error::ApiError;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::process::Command;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Meta table helpers
// ---------------------------------------------------------------------------

/// Read a meta key from the database, returning `None` if absent.
async fn meta_get(db: &sfgw_db::Db, key: &str) -> Result<Option<String>, ApiError> {
    let conn = db.lock().await;
    let result = conn.query_row(
        "SELECT value FROM meta WHERE key = ?1",
        rusqlite::params![key],
        |row| row.get::<_, String>(0),
    );
    match result {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(ApiError::Internal(format!("meta read error: {e}"))),
    }
}

/// Upsert a meta key/value pair.
async fn meta_set(db: &sfgw_db::Db, key: &str, value: &str) -> Result<(), ApiError> {
    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, value],
    )
    .map_err(|e| ApiError::Internal(format!("meta write error: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for `PUT /auth/ad/config`.
#[derive(Debug, Deserialize)]
struct AdConfigRequest {
    /// AD server hostname or IP (e.g. "dc01.corp.local").
    server: String,
    /// AD domain (e.g. "corp.local").
    domain: String,
    /// Base DN for LDAP searches (e.g. "DC=corp,DC=local").
    base_dn: String,
    /// Service account DN for LDAP bind.
    bind_user: String,
    /// Bind password. Only updated if provided and non-empty.
    #[serde(default)]
    bind_password: Option<String>,
    /// LDAP user filter override.
    #[serde(default)]
    user_filter: Option<String>,
    /// LDAP group filter override.
    #[serde(default)]
    group_filter: Option<String>,
    /// Sync interval in minutes.
    #[serde(default)]
    sync_interval: Option<u32>,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a hostname/IP: non-empty, no whitespace, no shell metacharacters.
fn validate_server(server: &str) -> Result<(), ApiError> {
    if server.is_empty() {
        return Err(ApiError::Validation("server is required".into()));
    }
    if server.len() > 253 {
        return Err(ApiError::Validation(
            "server hostname must be 253 characters or fewer".into(),
        ));
    }
    // Only allow hostname-safe characters: alphanumeric, dots, hyphens, colons (IPv6), brackets
    if !server
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
    {
        return Err(ApiError::Validation(
            "server contains invalid characters".into(),
        ));
    }
    Ok(())
}

/// Validate a domain name: non-empty, reasonable format.
fn validate_domain(domain: &str) -> Result<(), ApiError> {
    if domain.is_empty() {
        return Err(ApiError::Validation("domain is required".into()));
    }
    if domain.len() > 253 {
        return Err(ApiError::Validation(
            "domain must be 253 characters or fewer".into(),
        ));
    }
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return Err(ApiError::Validation(
            "domain contains invalid characters".into(),
        ));
    }
    if !domain.contains('.') {
        return Err(ApiError::Validation(
            "domain must contain at least one dot (e.g. corp.local)".into(),
        ));
    }
    Ok(())
}

/// Validate a base DN: non-empty, basic LDAP DN format check.
fn validate_base_dn(dn: &str) -> Result<(), ApiError> {
    if dn.is_empty() {
        return Err(ApiError::Validation("base_dn is required".into()));
    }
    if dn.len() > 1024 {
        return Err(ApiError::Validation(
            "base_dn must be 1024 characters or fewer".into(),
        ));
    }
    // Reject shell metacharacters in DN
    if dn.chars().any(|c| {
        matches!(
            c,
            ';' | '|' | '&' | '$' | '`' | '\'' | '"' | '\\' | '\n' | '\r'
        )
    }) {
        return Err(ApiError::Validation(
            "base_dn contains invalid characters".into(),
        ));
    }
    Ok(())
}

/// Validate a bind user DN.
fn validate_bind_user(user: &str) -> Result<(), ApiError> {
    if user.is_empty() {
        return Err(ApiError::Validation("bind_user is required".into()));
    }
    if user.len() > 1024 {
        return Err(ApiError::Validation(
            "bind_user must be 1024 characters or fewer".into(),
        ));
    }
    if user
        .chars()
        .any(|c| matches!(c, ';' | '|' | '&' | '$' | '`' | '\n' | '\r'))
    {
        return Err(ApiError::Validation(
            "bind_user contains invalid characters".into(),
        ));
    }
    Ok(())
}

/// Validate an LDAP filter string.
fn validate_ldap_filter(filter: &str) -> Result<(), ApiError> {
    if filter.len() > 4096 {
        return Err(ApiError::Validation(
            "LDAP filter must be 4096 characters or fewer".into(),
        ));
    }
    // Must start with '(' and end with ')' if non-empty
    if !filter.is_empty() && (!filter.starts_with('(') || !filter.ends_with(')')) {
        return Err(ApiError::Validation(
            "LDAP filter must be enclosed in parentheses".into(),
        ));
    }
    // Reject shell metacharacters
    if filter
        .chars()
        .any(|c| matches!(c, ';' | '|' | '`' | '$' | '\n' | '\r'))
    {
        return Err(ApiError::Validation(
            "LDAP filter contains invalid characters".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GET /auth/ad/config — read config (password redacted)
// ---------------------------------------------------------------------------

async fn get_config(Extension(db): Extension<sfgw_db::Db>) -> Result<Json<Value>, ApiError> {
    let enabled = meta_get(&db, "ad_enabled").await?.unwrap_or_default();
    let server = meta_get(&db, "ad_server").await?.unwrap_or_default();
    let domain = meta_get(&db, "ad_domain").await?.unwrap_or_default();
    let base_dn = meta_get(&db, "ad_base_dn").await?.unwrap_or_default();
    let bind_user = meta_get(&db, "ad_bind_user").await?.unwrap_or_default();
    let user_filter = meta_get(&db, "ad_user_filter")
        .await?
        .unwrap_or_else(|| "(&(objectClass=user)(objectCategory=person))".into());
    let group_filter = meta_get(&db, "ad_group_filter")
        .await?
        .unwrap_or_else(|| "(objectClass=group)".into());
    let sync_interval = meta_get(&db, "ad_sync_interval")
        .await?
        .unwrap_or_else(|| "60".into());
    let last_sync = meta_get(&db, "ad_last_sync").await?.unwrap_or_default();

    // Indicate whether a bind password is configured, but never return it
    let has_password = meta_get(&db, "ad_bind_password")
        .await?
        .map(|p| !p.is_empty())
        .unwrap_or(false);

    Ok(Json(json!({
        "success": true,
        "data": {
            "enabled": enabled == "true",
            "server": server,
            "domain": domain,
            "base_dn": base_dn,
            "bind_user": bind_user,
            "has_bind_password": has_password,
            "user_filter": user_filter,
            "group_filter": group_filter,
            "sync_interval": sync_interval.parse::<u32>().unwrap_or(60),
            "last_sync": last_sync,
        },
    })))
}

// ---------------------------------------------------------------------------
// PUT /auth/ad/config — save config
// ---------------------------------------------------------------------------

async fn save_config(
    Extension(db): Extension<sfgw_db::Db>,
    Json(body): Json<AdConfigRequest>,
) -> Result<Json<Value>, ApiError> {
    // Validate all fields
    validate_server(&body.server)?;
    validate_domain(&body.domain)?;
    validate_base_dn(&body.base_dn)?;
    validate_bind_user(&body.bind_user)?;

    if let Some(ref filter) = body.user_filter {
        validate_ldap_filter(filter)?;
    }
    if let Some(ref filter) = body.group_filter {
        validate_ldap_filter(filter)?;
    }
    if let Some(interval) = body.sync_interval
        && (interval == 0 || interval > 1440)
    {
        return Err(ApiError::Validation(
            "sync_interval must be between 1 and 1440 minutes".into(),
        ));
    }

    info!(server = %body.server, domain = %body.domain, "saving AD configuration");

    meta_set(&db, "ad_enabled", "true").await?;
    meta_set(&db, "ad_server", &body.server).await?;
    meta_set(&db, "ad_domain", &body.domain).await?;
    meta_set(&db, "ad_base_dn", &body.base_dn).await?;
    meta_set(&db, "ad_bind_user", &body.bind_user).await?;

    // Only update password if provided and non-empty
    if let Some(ref pw) = body.bind_password
        && !pw.is_empty()
    {
        meta_set(&db, "ad_bind_password", pw).await?;
    }

    if let Some(ref filter) = body.user_filter {
        meta_set(&db, "ad_user_filter", filter).await?;
    }
    if let Some(ref filter) = body.group_filter {
        meta_set(&db, "ad_group_filter", filter).await?;
    }
    if let Some(interval) = body.sync_interval {
        meta_set(&db, "ad_sync_interval", &interval.to_string()).await?;
    }

    Ok(Json(json!({
        "success": true,
        "data": { "message": "AD configuration saved" },
    })))
}

// ---------------------------------------------------------------------------
// POST /auth/ad/test — test LDAP connection
// ---------------------------------------------------------------------------

async fn test_connection(Extension(db): Extension<sfgw_db::Db>) -> Result<Json<Value>, ApiError> {
    let server = meta_get(&db, "ad_server").await?.unwrap_or_default();
    let _base_dn = meta_get(&db, "ad_base_dn").await?.unwrap_or_default();
    let bind_user = meta_get(&db, "ad_bind_user").await?.unwrap_or_default();
    let bind_password = meta_get(&db, "ad_bind_password").await?.unwrap_or_default();

    if server.is_empty() || bind_user.is_empty() {
        return Err(ApiError::Validation(
            "AD server and bind user must be configured before testing".into(),
        ));
    }

    info!(server = %server, "testing AD/LDAP connection");

    let ldap_url = format!("ldap://{server}:389");

    // Use ldap3 crate to test connection + bind
    let (conn, mut ldap) = match ldap3::LdapConnAsync::new(&ldap_url).await {
        Ok(pair) => pair,
        Err(e) => {
            warn!(server = %server, error = %e, "LDAP connection failed");
            return Ok(Json(json!({
                "success": true,
                "data": {
                    "connected": false,
                    "error": format!("connection failed: unable to reach {server}"),
                },
            })));
        }
    };

    // Drive the connection in the background
    ldap3::drive!(conn);

    // Attempt simple bind
    match ldap.simple_bind(&bind_user, &bind_password).await {
        Ok(result) => {
            let rc = result.rc;
            let _ = ldap.unbind().await;

            if rc == 0 {
                // Try a search to verify base_dn
                info!(server = %server, "LDAP bind successful");
                Ok(Json(json!({
                    "success": true,
                    "data": {
                        "connected": true,
                        "message": "LDAP bind successful",
                    },
                })))
            } else {
                warn!(server = %server, rc, "LDAP bind returned non-zero result");
                Ok(Json(json!({
                    "success": true,
                    "data": {
                        "connected": false,
                        "error": format!("bind failed with LDAP result code {rc}"),
                    },
                })))
            }
        }
        Err(e) => {
            warn!(server = %server, error = %e, "LDAP bind failed");
            let _ = ldap.unbind().await;
            Ok(Json(json!({
                "success": true,
                "data": {
                    "connected": false,
                    "error": "bind failed: invalid credentials or unreachable server",
                },
            })))
        }
    }
}

// ---------------------------------------------------------------------------
// POST /auth/ad/join — join AD domain
// ---------------------------------------------------------------------------

async fn join_domain(Extension(db): Extension<sfgw_db::Db>) -> Result<Json<Value>, ApiError> {
    let server = meta_get(&db, "ad_server").await?.unwrap_or_default();
    let domain = meta_get(&db, "ad_domain").await?.unwrap_or_default();
    let bind_user = meta_get(&db, "ad_bind_user").await?.unwrap_or_default();
    let bind_password = meta_get(&db, "ad_bind_password").await?.unwrap_or_default();

    if server.is_empty() || domain.is_empty() || bind_user.is_empty() {
        return Err(ApiError::Validation(
            "AD server, domain, and bind user must be configured before joining".into(),
        ));
    }

    // Re-validate to prevent injection via stored values
    validate_server(&server)?;
    validate_domain(&domain)?;

    info!(domain = %domain, server = %server, "joining AD domain");

    // Extract workgroup (short name) from domain: "corp.local" -> "CORP"
    let workgroup = domain.split('.').next().unwrap_or(&domain).to_uppercase();
    let realm = domain.to_uppercase();

    // Step 1: Write AD-aware smb.conf
    let smb_conf = format!(
        "[global]\n\
         workgroup = {workgroup}\n\
         realm = {realm}\n\
         security = ads\n\
         encrypt passwords = yes\n\
         \n\
         # Winbind configuration\n\
         idmap config * : backend = tdb\n\
         idmap config * : range = 10000-20000\n\
         idmap config {workgroup} : backend = rid\n\
         idmap config {workgroup} : range = 20001-30000\n\
         winbind enum users = yes\n\
         winbind enum groups = yes\n\
         winbind use default domain = yes\n\
         winbind refresh tickets = yes\n\
         \n\
         # Name resolution\n\
         password server = {server}\n\
         dns proxy = no\n\
         \n\
         # Logging\n\
         log file = /var/log/samba/%m.log\n\
         max log size = 1000\n\
         log level = 1\n"
    );

    std::fs::write("/etc/samba/smb.conf", &smb_conf)
        .map_err(|e| ApiError::Internal(format!("failed to write smb.conf: {e}")))?;

    // Step 2: Join the domain via `net ads join`
    // Extract a simple username from the bind DN for net ads join
    // The bind_user might be "CN=svc-nas,OU=Services,DC=corp,DC=local"
    // or "svc-nas@corp.local" — extract the username part
    let join_user = if bind_user.contains('=') {
        // DN format: extract CN value
        bind_user
            .split(',')
            .find(|p| p.trim().to_uppercase().starts_with("CN="))
            .and_then(|cn| cn.split('=').nth(1))
            .unwrap_or(&bind_user)
            .to_string()
    } else if bind_user.contains('@') {
        // UPN format: extract before @
        bind_user
            .split('@')
            .next()
            .unwrap_or(&bind_user)
            .to_string()
    } else {
        bind_user.clone()
    };

    let output = Command::new("net")
        .args(["ads", "join", "-U"])
        .arg(format!("{join_user}%{bind_password}"))
        .output()
        .map_err(|e| ApiError::Internal(format!("failed to execute net ads join: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(domain = %domain, error = %stderr, "net ads join failed");
        return Ok(Json(json!({
            "success": false,
            "error": "domain join failed",
        })));
    }

    info!(domain = %domain, "successfully joined AD domain");

    // Step 3: Restart Samba + winbind
    restart_samba_services();

    Ok(Json(json!({
        "success": true,
        "data": {
            "message": format!("successfully joined domain {domain}"),
            "domain": domain,
            "workgroup": workgroup,
        },
    })))
}

// ---------------------------------------------------------------------------
// POST /auth/ad/leave — leave AD domain
// ---------------------------------------------------------------------------

async fn leave_domain(Extension(db): Extension<sfgw_db::Db>) -> Result<Json<Value>, ApiError> {
    let bind_user = meta_get(&db, "ad_bind_user").await?.unwrap_or_default();
    let bind_password = meta_get(&db, "ad_bind_password").await?.unwrap_or_default();
    let domain = meta_get(&db, "ad_domain").await?.unwrap_or_default();

    info!(domain = %domain, "leaving AD domain");

    // Extract simple username for net ads leave
    let leave_user = if bind_user.contains('=') {
        bind_user
            .split(',')
            .find(|p| p.trim().to_uppercase().starts_with("CN="))
            .and_then(|cn| cn.split('=').nth(1))
            .unwrap_or(&bind_user)
            .to_string()
    } else if bind_user.contains('@') {
        bind_user
            .split('@')
            .next()
            .unwrap_or(&bind_user)
            .to_string()
    } else {
        bind_user.clone()
    };

    // Leave the domain
    let output = Command::new("net")
        .args(["ads", "leave", "-U"])
        .arg(format!("{leave_user}%{bind_password}"))
        .output()
        .map_err(|e| ApiError::Internal(format!("failed to execute net ads leave: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(error = %stderr, "net ads leave failed (continuing with config revert)");
    }

    // Revert smb.conf to standalone mode
    let smb_conf = "[global]\n\
         workgroup = WORKGROUP\n\
         security = user\n\
         encrypt passwords = yes\n\
         map to guest = Bad User\n\
         \n\
         log file = /var/log/samba/%m.log\n\
         max log size = 1000\n\
         log level = 1\n";

    std::fs::write("/etc/samba/smb.conf", smb_conf)
        .map_err(|e| ApiError::Internal(format!("failed to write smb.conf: {e}")))?;

    // Disable AD in meta
    meta_set(&db, "ad_enabled", "false").await?;

    // Restart services
    restart_samba_services();

    info!("successfully left AD domain and reverted to standalone mode");

    Ok(Json(json!({
        "success": true,
        "data": { "message": "left AD domain and reverted to standalone mode" },
    })))
}

// ---------------------------------------------------------------------------
// POST /auth/ad/sync — trigger manual user/group sync
// ---------------------------------------------------------------------------

async fn sync_users(Extension(db): Extension<sfgw_db::Db>) -> Result<Json<Value>, ApiError> {
    info!("triggering AD user/group sync");

    // Get domain users via wbinfo
    let users = run_wbinfo_list("-u");
    let groups = run_wbinfo_list("-g");

    // Record last sync time
    let now = chrono::Utc::now().to_rfc3339();
    meta_set(&db, "ad_last_sync", &now).await?;

    info!(
        user_count = users.len(),
        group_count = groups.len(),
        "AD sync completed"
    );

    Ok(Json(json!({
        "success": true,
        "data": {
            "users": users,
            "groups": groups,
            "user_count": users.len(),
            "group_count": groups.len(),
            "synced_at": now,
        },
    })))
}

// ---------------------------------------------------------------------------
// GET /auth/ad/status — domain join status
// ---------------------------------------------------------------------------

async fn get_status(Extension(db): Extension<sfgw_db::Db>) -> Result<Json<Value>, ApiError> {
    // Check if joined via `net ads testjoin`
    let joined = Command::new("net")
        .args(["ads", "testjoin"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let last_sync = meta_get(&db, "ad_last_sync").await?.unwrap_or_default();
    let domain = meta_get(&db, "ad_domain").await?.unwrap_or_default();
    let enabled = meta_get(&db, "ad_enabled").await?.unwrap_or_default() == "true";

    // Get user/group counts (best-effort)
    let user_count = run_wbinfo_list("-u").len();
    let group_count = run_wbinfo_list("-g").len();

    Ok(Json(json!({
        "success": true,
        "data": {
            "enabled": enabled,
            "joined": joined,
            "domain": domain,
            "last_sync": last_sync,
            "user_count": user_count,
            "group_count": group_count,
        },
    })))
}

// ---------------------------------------------------------------------------
// Routers
// ---------------------------------------------------------------------------

/// Protected AD routes (config read, status, test connection).
pub fn router() -> Router {
    Router::new()
        .route("/auth/ad/config", get(get_config).put(save_config))
        .route("/auth/ad/status", get(get_status))
        .route("/auth/ad/test", post(test_connection))
}

/// Critical AD routes (join/leave domain, sync — 5/min rate limit).
pub fn critical_router() -> Router {
    Router::new()
        .route("/auth/ad/join", post(join_domain))
        .route("/auth/ad/leave", post(leave_domain))
        .route("/auth/ad/sync", post(sync_users))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Run `wbinfo <flag>` and return the output lines.
fn run_wbinfo_list(flag: &str) -> Vec<String> {
    Command::new("wbinfo")
        .arg(flag)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Restart Samba and winbind services (best-effort).
fn restart_samba_services() {
    for svc in &["smbd", "nmbd", "winbind"] {
        match Command::new("rc-service").args([svc, "restart"]).output() {
            Ok(o) if o.status.success() => {
                info!(service = svc, "restarted successfully");
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                warn!(service = svc, error = %stderr, "restart failed, trying systemctl");
                // Fallback to systemctl
                let _ = Command::new("systemctl").args(["restart", svc]).output();
            }
            Err(e) => {
                warn!(service = svc, error = %e, "failed to restart");
            }
        }
    }
}
