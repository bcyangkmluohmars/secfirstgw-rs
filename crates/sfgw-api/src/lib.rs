// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod auth;
pub mod middleware;

use anyhow::{Context, Result};
use axum::{
    Extension, Json, Router,
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use tower_http::services::{ServeDir, ServeFile};

use crate::middleware::AuthUser;

/// Start the axum web API and serve the UI.
///
/// Listens on the address specified by SFGW_LISTEN_ADDR (default: 0.0.0.0:8443).
/// In production this will be :443 with TLS. For dev/Docker we use :8443 without TLS.
pub async fn serve(db: &sfgw_db::Db) -> Result<()> {
    let listen_addr: SocketAddr = std::env::var("SFGW_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8443".to_string())
        .parse()
        .context("invalid SFGW_LISTEN_ADDR")?;

    let db = db.clone();

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/api/v1/auth/login", post(login_handler))
        .route("/api/v1/auth/setup", post(setup_handler));

    // Protected routes (auth required via AuthUser extractor)
    let protected_routes = Router::new()
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/system", get(system_handler))
        .route("/api/v1/interfaces", get(interfaces_handler))
        .route("/api/v1/devices", get(devices_handler))
        .route("/api/v1/auth/me", get(me_handler))
        .route("/api/v1/auth/logout", post(logout_handler));

    // Serve the frontend SPA from SFGW_WEB_DIR (if set and the directory exists).
    // API routes take priority; unmatched requests fall back to static files,
    // with index.html as the final fallback for client-side routing.
    let app = if let Some(web_dir) = std::env::var("SFGW_WEB_DIR")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
    {
        let index_html = web_dir.join("index.html");
        let serve_dir = ServeDir::new(&web_dir).not_found_service(ServeFile::new(&index_html));

        Router::new()
            .merge(public_routes)
            .merge(protected_routes)
            .layer(Extension(db))
            .layer(tower_http::trace::TraceLayer::new_for_http())
            .fallback_service(serve_dir)
    } else {
        Router::new()
            .merge(public_routes)
            .merge(protected_routes)
            .layer(Extension(db))
            .layer(tower_http::trace::TraceLayer::new_for_http())
    };

    tracing::info!("API server listening on {listen_addr}");

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind to {listen_addr}"))?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("API server error")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Public handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login_handler(
    Extension(db): Extension<sfgw_db::Db>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    // Look up user
    let user_and_hash = match auth::get_user_by_username(&db, &body.username).await {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid credentials" })),
            );
        }
        Err(e) => {
            tracing::error!("login db error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
            );
        }
    };

    let (user, password_hash) = user_and_hash;

    // Verify password
    match auth::verify_password(&body.password, &password_hash) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid credentials" })),
            );
        }
        Err(e) => {
            tracing::error!("password verification error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
            );
        }
    }

    // Determine client IP — prefer X-Forwarded-For, fall back to socket addr
    let client_ip = middleware::client_ip_from_headers(&headers);
    let client_ip = if client_ip == "unknown" {
        addr.ip().to_string()
    } else {
        client_ip
    };

    let fingerprint = middleware::fingerprint_from_headers(&headers);

    // Create session
    match auth::create_session(&db, user.id, &client_ip, &fingerprint, "").await {
        Ok((token, expires_at)) => (
            StatusCode::OK,
            Json(json!({
                "token": token,
                "expires_at": expires_at.to_rfc3339(),
            })),
        ),
        Err(e) => {
            tracing::error!("session creation error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
            )
        }
    }
}

#[derive(Deserialize)]
struct SetupRequest {
    username: String,
    password: String,
}

async fn setup_handler(
    Extension(db): Extension<sfgw_db::Db>,
    Json(body): Json<SetupRequest>,
) -> impl IntoResponse {
    // Only allow setup if no users exist
    match auth::user_count(&db).await {
        Ok(count) if count > 0 => {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "setup already completed — users exist" })),
            );
        }
        Err(e) => {
            tracing::error!("setup user count error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
            );
        }
        _ => {}
    }

    // Validate input
    if body.username.is_empty() || body.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "username and password are required" })),
        );
    }

    if body.password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "password must be at least 8 characters" })),
        );
    }

    // Hash the password
    let password_hash = match auth::hash_password(&body.password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("password hash error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
            );
        }
    };

    // Create the admin user
    match auth::create_user(&db, &body.username, &password_hash, "admin").await {
        Ok(user_id) => (
            StatusCode::CREATED,
            Json(json!({
                "user_id": user_id,
                "username": body.username,
                "role": "admin",
            })),
        ),
        Err(e) => {
            tracing::error!("user creation error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// System-info helpers
// ---------------------------------------------------------------------------

/// Read system uptime in seconds from `/proc/uptime`.
fn read_uptime_secs() -> f64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(String::from))
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0)
}

/// Memory sizes in MiB parsed from `/proc/meminfo`.
struct MemInfo {
    total_mb: u64,
    used_mb: u64,
    free_mb: u64,
}

/// Parse `/proc/meminfo` and return total, used and free memory in MiB.
///
/// "used" is defined as total minus available (MemAvailable), which matches
/// what tools like `free` and `htop` report.  When MemAvailable is missing we
/// fall back to `total - free - buffers - cached`.
fn read_meminfo() -> MemInfo {
    let content = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();

    let field = |name: &str| -> u64 {
        content
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    };

    let total_kb = field("MemTotal:");
    let available_kb = field("MemAvailable:");
    let free_kb = field("MemFree:");
    let buffers_kb = field("Buffers:");
    let cached_kb = field("Cached:");

    let used_kb = if available_kb > 0 {
        total_kb.saturating_sub(available_kb)
    } else {
        total_kb.saturating_sub(free_kb + buffers_kb + cached_kb)
    };

    let effective_free_kb = total_kb.saturating_sub(used_kb);

    MemInfo {
        total_mb: total_kb / 1024,
        used_mb: used_kb / 1024,
        free_mb: effective_free_kb / 1024,
    }
}

/// Read the first three load-average values from `/proc/loadavg`.
fn read_loadavg() -> (f64, f64, f64) {
    let content = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let mut parts = content.split_whitespace();
    let a = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let b = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let c = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    (a, b, c)
}

/// Read the system hostname.
fn read_hostname() -> String {
    // Try the syscall-backed file first, fall back to /etc/hostname.
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Read the kernel version string from `/proc/version`.
fn read_kernel_version() -> String {
    std::fs::read_to_string("/proc/version")
        .ok()
        .and_then(|s| {
            // Format: "Linux version 6.x.y-... (gcc ...) #1 ..."
            // We want the third token (the version number).
            s.split_whitespace().nth(2).map(String::from)
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Count logical CPUs by scanning `/proc/cpuinfo` for "processor" lines.
fn read_cpu_count() -> usize {
    let content = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let count = content
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count();
    if count == 0 { 1 } else { count }
}

/// Read the machine hardware architecture via `std::env::consts::ARCH`.
fn read_arch() -> &'static str {
    std::env::consts::ARCH
}

// ---------------------------------------------------------------------------
// Protected handlers (require AuthUser)
// ---------------------------------------------------------------------------

async fn status_handler(_auth: AuthUser) -> Json<Value> {
    let uptime = read_uptime_secs();
    let (load1, load5, load15) = read_loadavg();
    let mem = read_meminfo();

    Json(json!({
        "status": "ok",
        "uptime_secs": uptime,
        "load_average": [load1, load5, load15],
        "memory": {
            "total_mb": mem.total_mb,
            "used_mb": mem.used_mb,
            "free_mb": mem.free_mb,
        },
        "services": {
            "firewall": "running",
            "dns": "running",
            "vpn": "stopped",
            "ids": "running",
            "nas": "stopped"
        }
    }))
}

async fn system_handler(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> Json<Value> {
    let version = {
        let conn = db.lock().await;
        conn.query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap_or_else(|_| "unknown".to_string())
    };

    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "schema_version": version,
        "platform": std::env::var("SFGW_PLATFORM").unwrap_or_else(|_| "unknown".to_string()),
        "hostname": read_hostname(),
        "kernel": read_kernel_version(),
        "arch": read_arch(),
        "cpu_count": read_cpu_count(),
    }))
}

async fn interfaces_handler(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> Json<Value> {
    let interfaces = {
        let conn = db.lock().await;
        let mut stmt = conn
            .prepare("SELECT name, role, vlan_id, enabled FROM interfaces")
            .unwrap();
        let rows: Vec<Value> = stmt
            .query_map([], |row| {
                Ok(json!({
                    "name": row.get::<_, String>(0)?,
                    "role": row.get::<_, String>(1)?,
                    "vlan_id": row.get::<_, Option<i64>>(2)?,
                    "enabled": row.get::<_, bool>(3)?,
                }))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        rows
    };

    Json(json!({ "interfaces": interfaces }))
}

async fn devices_handler(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> Json<Value> {
    let devices = {
        let conn = db.lock().await;
        let mut stmt = conn
            .prepare("SELECT mac, name, model, ip, adopted, last_seen FROM devices")
            .unwrap();
        let rows: Vec<Value> = stmt
            .query_map([], |row| {
                Ok(json!({
                    "mac": row.get::<_, String>(0)?,
                    "name": row.get::<_, Option<String>>(1)?,
                    "model": row.get::<_, Option<String>>(2)?,
                    "ip": row.get::<_, Option<String>>(3)?,
                    "adopted": row.get::<_, bool>(4)?,
                    "last_seen": row.get::<_, Option<String>>(5)?,
                }))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        rows
    };

    Json(json!({ "devices": devices }))
}

async fn me_handler(auth_user: AuthUser) -> Json<Value> {
    Json(json!({
        "user": {
            "id": auth_user.user.id,
            "username": auth_user.user.username,
            "role": auth_user.user.role,
            "created_at": auth_user.user.created_at,
        }
    }))
}

async fn logout_handler(
    auth_user: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    match auth::delete_session(&db, &auth_user.token).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "logged out" }))),
        Err(e) => {
            tracing::error!("logout error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
            )
        }
    }
}
