// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod auth;
pub mod e2ee;
pub mod middleware;

use anyhow::{Context, Result};
use axum::{
    Extension, Json, Router,
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use tower_http::services::{ServeDir, ServeFile};

use crate::middleware::AuthUser;

/// Start the axum web API and serve the UI.
pub async fn serve(db: &sfgw_db::Db) -> Result<()> {
    let listen_addr: SocketAddr = std::env::var("SFGW_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8443".to_string())
        .parse()
        .context("invalid SFGW_LISTEN_ADDR")?;

    let db = db.clone();
    let negotiate_store = e2ee::new_negotiate_store();

    // Public routes (no auth required)
    // /auth/session — unified E2EE key exchange + optional session resume
    // /auth/login   — authenticate with credentials (plain or E2EE-encrypted)
    // /auth/setup   — initial admin setup (only when no users exist)
    let public_routes = Router::new()
        .route("/api/v1/auth/session", post(session_handler))
        .route("/api/v1/auth/login", post(login_handler))
        .route("/api/v1/auth/setup", post(setup_handler));

    // Protected routes (auth required)
    // E2EE middleware handles transparent encrypt/decrypt for all these
    let protected_routes = Router::new()
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/system", get(system_handler))
        .route("/api/v1/interfaces", get(interfaces_handler))
        .route("/api/v1/devices", get(devices_handler))
        .route("/api/v1/auth/me", get(me_handler))
        .route("/api/v1/auth/logout", post(logout_handler))
        .layer(axum::middleware::from_fn(e2ee::e2ee_layer));

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
            .layer(Extension(negotiate_store))
            .layer(tower_http::trace::TraceLayer::new_for_http())
            .fallback_service(serve_dir)
    } else {
        Router::new()
            .merge(public_routes)
            .merge(protected_routes)
            .layer(Extension(db))
            .layer(Extension(negotiate_store))
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
// /auth/session — Unified E2EE session endpoint
// ---------------------------------------------------------------------------
//
// Always performs X25519 key exchange.
// If a valid token is provided, resumes the session with a new envelope key.
// If no token or invalid token, returns the negotiate context for login.
//
// Request:  { client_public_key: base64, token?: string }
// Response: { negotiate_id: string, server_public_key: base64,
//             authenticated: bool, user?: {...}, envelope?: {iv, data} }

#[derive(Deserialize)]
struct SessionRequest {
    client_public_key: String,
    token: Option<String>,
}

async fn session_handler(
    Extension(db): Extension<sfgw_db::Db>,
    Extension(negotiate_store): Extension<e2ee::NegotiateStore>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<SessionRequest>,
) -> impl IntoResponse {
    // Always do the key exchange
    let client_pub = match B64.decode(&body.client_public_key) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid base64 in client_public_key" })),
            );
        }
    };

    let (negotiate_id, server_pub) = match e2ee::negotiate(&negotiate_store, &client_pub).await {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    };

    let mut response = json!({
        "negotiate_id": negotiate_id,
        "server_public_key": B64.encode(&server_pub),
        "authenticated": false,
    });

    // If token provided, try to validate + resume
    if let Some(ref token) = body.token {
        let client_ip = resolve_client_ip(&headers, &addr);
        let fingerprint = middleware::fingerprint_from_headers(&headers);

        if let Ok(Some(user_id)) =
            auth::validate_session(&db, token, &client_ip, &fingerprint).await
        {
            if let Ok(Some(user)) = auth::get_user_by_id(&db, user_id).await {
                // Generate new envelope key for this session
                if let Ok(env_key) = e2ee::generate_envelope_key() {
                    let env_key_b64 = B64.encode(&env_key);
                    let _ = auth::update_envelope_key(&db, token, &env_key_b64).await;

                    // Get the negotiate AES key to encrypt the envelope key
                    if let Ok(neg_key) =
                        e2ee::take_negotiate_key(&negotiate_store, &negotiate_id).await
                    {
                        if let Ok(sealed) = e2ee::Envelope::seal(&neg_key, &env_key) {
                            response["authenticated"] = json!(true);
                            response["user"] = json!({
                                "id": user.id,
                                "username": user.username,
                                "role": user.role,
                            });
                            response["envelope"] = json!({
                                "iv": sealed.iv,
                                "data": sealed.data,
                            });
                        }
                    }
                }
            }
        }
    }

    (StatusCode::OK, Json(response))
}

// ---------------------------------------------------------------------------
// /auth/login — Authenticate with credentials
// ---------------------------------------------------------------------------
//
// Supports two modes:
// 1. E2EE: { negotiate_id, ciphertext, iv } — credentials encrypted with negotiate key
// 2. Plain: { username, password } — for curl/testing (still TLS-protected)
//
// Response includes encrypted envelope key for E2EE sessions.

#[derive(Deserialize)]
struct LoginRequest {
    username: Option<String>,
    password: Option<String>,
    negotiate_id: Option<String>,
    ciphertext: Option<String>,
    iv: Option<String>,
}

#[derive(Deserialize)]
struct E2eeCredentials {
    username: String,
    password: String,
}

async fn login_handler(
    Extension(db): Extension<sfgw_db::Db>,
    Extension(negotiate_store): Extension<e2ee::NegotiateStore>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    // Extract credentials (E2EE or plain)
    let (username, password, negotiate_key) = if let (Some(nid), Some(ct), Some(iv)) =
        (&body.negotiate_id, &body.ciphertext, &body.iv)
    {
        let neg_key = match e2ee::take_negotiate_key(&negotiate_store, nid).await {
            Ok(k) => k,
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
        };

        let ct_bytes = match B64.decode(ct) {
            Ok(b) => b,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "invalid base64 in ciphertext" })),
                );
            }
        };
        let iv_bytes = match B64.decode(iv) {
            Ok(b) => b,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "invalid base64 in iv" })),
                );
            }
        };

        let plaintext = match e2ee::decrypt(&neg_key, &ct_bytes, &iv_bytes) {
            Ok(pt) => pt,
            Err(e) => {
                tracing::warn!("E2EE login decrypt failed: {e}");
                return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "decryption failed" })));
            }
        };

        let creds: E2eeCredentials = match serde_json::from_slice(&plaintext) {
            Ok(c) => c,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "invalid decrypted payload" })),
                );
            }
        };

        (creds.username, creds.password, Some(neg_key))
    } else if let (Some(u), Some(p)) = (body.username, body.password) {
        (u, p, None)
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "provide credentials (E2EE or plain)" })),
        );
    };

    // Verify user
    let (user, password_hash) = match auth::get_user_by_username(&db, &username).await {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid credentials" })));
        }
        Err(e) => {
            tracing::error!("login db error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
            );
        }
    };

    match auth::verify_password(&password, &password_hash) {
        Ok(true) => {}
        Ok(false) => {
            return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid credentials" })));
        }
        Err(e) => {
            tracing::error!("password verify error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
            );
        }
    }

    let client_ip = resolve_client_ip(&headers, &addr);
    let fingerprint = middleware::fingerprint_from_headers(&headers);

    // Generate envelope key for E2EE sessions
    let envelope_key = negotiate_key
        .as_ref()
        .and_then(|_| e2ee::generate_envelope_key().ok());
    let envelope_key_b64 = envelope_key.as_ref().map(|k| B64.encode(k)).unwrap_or_default();

    // Create session
    match auth::create_session(&db, user.id, &client_ip, &fingerprint, &envelope_key_b64).await {
        Ok((token, expires_at)) => {
            let mut response = json!({
                "token": token,
                "expires_at": expires_at.to_rfc3339(),
            });

            // Encrypt envelope key with negotiate key
            if let (Some(neg_key), Some(env_key)) = (&negotiate_key, &envelope_key) {
                if let Ok(sealed) = e2ee::Envelope::seal(neg_key, env_key) {
                    response["envelope"] = json!({ "iv": sealed.iv, "data": sealed.data });
                }
            }

            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            tracing::error!("session creation error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// /auth/setup — Initial admin setup
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SetupRequest {
    username: String,
    password: String,
}

async fn setup_handler(
    Extension(db): Extension<sfgw_db::Db>,
    Json(body): Json<SetupRequest>,
) -> impl IntoResponse {
    match auth::user_count(&db).await {
        Ok(count) if count > 0 => {
            return (StatusCode::CONFLICT, Json(json!({ "error": "setup already completed" })));
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
// Helpers
// ---------------------------------------------------------------------------

fn resolve_client_ip(headers: &HeaderMap, addr: &SocketAddr) -> String {
    let ip = middleware::client_ip_from_headers(headers);
    if ip == "unknown" {
        addr.ip().to_string()
    } else {
        ip
    }
}

// ---------------------------------------------------------------------------
// System-info helpers
// ---------------------------------------------------------------------------

fn read_uptime_secs() -> f64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(String::from))
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0)
}

struct MemInfo {
    total_mb: u64,
    used_mb: u64,
    free_mb: u64,
}

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
    MemInfo {
        total_mb: total_kb / 1024,
        used_mb: used_kb / 1024,
        free_mb: total_kb.saturating_sub(used_kb) / 1024,
    }
}

fn read_loadavg() -> (f64, f64, f64) {
    let content = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let mut parts = content.split_whitespace();
    let a = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let b = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let c = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    (a, b, c)
}

fn read_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn read_kernel_version() -> String {
    std::fs::read_to_string("/proc/version")
        .ok()
        .and_then(|s| s.split_whitespace().nth(2).map(String::from))
        .unwrap_or_else(|| "unknown".to_string())
}

fn read_cpu_count() -> usize {
    let content = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let count = content.lines().filter(|l| l.starts_with("processor")).count();
    if count == 0 { 1 } else { count }
}

fn read_arch() -> &'static str {
    std::env::consts::ARCH
}

// ---------------------------------------------------------------------------
// Protected handlers
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
