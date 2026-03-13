// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

pub mod auth;
pub mod e2ee;
pub mod middleware;
pub mod ratelimit;
pub mod tls;

use anyhow::{Context, Result};
use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, Path, Query},
    http::{HeaderMap, Method, StatusCode, header::HeaderName},
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};

use crate::middleware::AuthUser;
use crate::ratelimit::RateLimiter;

/// Start the axum web API and serve the UI over TLS 1.3.
pub async fn serve(db: &sfgw_db::Db) -> Result<()> {
    let listen_addr: SocketAddr = std::env::var("SFGW_LISTEN_ADDR")
        .unwrap_or_else(|_| "[::]:8443".to_string())
        .parse()
        .context("invalid SFGW_LISTEN_ADDR")?;

    let db = db.clone();
    let negotiate_store = e2ee::new_negotiate_store();
    let envelope_key_store = e2ee::new_envelope_key_store();

    // ----- Rate limiters -----
    // Auth endpoints: 5 requests per minute per IP
    let auth_limiter = RateLimiter::new(5, Duration::from_secs(60));
    // All other endpoints: 60 requests per minute per IP
    let general_limiter = RateLimiter::new(60, Duration::from_secs(60));

    // ----- CORS -----
    let listen_host = if listen_addr.ip().is_unspecified() {
        "localhost".to_string()
    } else {
        listen_addr.ip().to_string()
    };
    let origin = format!("https://{}:{}", listen_host, listen_addr.port());
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::exact(
            origin.parse().context("failed to parse CORS origin")?,
        ))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            HeaderName::from_static("x-e2ee-negotiate-id"),
            HeaderName::from_static("x-e2ee-iv"),
        ])
        .allow_credentials(true);

    // ----- Public routes (no auth required, stricter rate limit) -----
    let public_routes = Router::new()
        .route("/api/v1/auth/session", post(session_handler))
        .route("/api/v1/auth/login", post(login_handler))
        .route("/api/v1/auth/setup", post(setup_handler))
        .layer(axum::middleware::from_fn_with_state(
            auth_limiter.clone(),
            ratelimit::rate_limit_middleware,
        ));

    // ----- Protected routes (auth required, general rate limit) -----
    let protected_routes = Router::new()
        // System
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/system", get(system_handler))
        .route("/api/v1/interfaces", get(interfaces_handler))
        .route("/api/v1/auth/me", get(me_handler))
        .route("/api/v1/auth/logout", post(logout_handler))
        // Firewall
        .route("/api/v1/firewall/rules", get(fw_list_rules).post(fw_insert_rule))
        .route("/api/v1/firewall/rules/{id}", put(fw_update_rule).delete(fw_delete_rule))
        .route("/api/v1/firewall/rules/{id}/toggle", post(fw_toggle_rule))
        .route("/api/v1/firewall/apply", post(fw_apply_rules))
        // VPN tunnels
        .route("/api/v1/vpn/tunnels", get(vpn_list_tunnels).post(vpn_create_tunnel))
        .route("/api/v1/vpn/tunnels/{id}", get(vpn_get_tunnel).delete(vpn_delete_tunnel))
        .route("/api/v1/vpn/tunnels/{id}/start", post(vpn_start_tunnel))
        .route("/api/v1/vpn/tunnels/{id}/stop", post(vpn_stop_tunnel))
        .route("/api/v1/vpn/tunnels/{id}/status", get(vpn_get_status))
        // VPN peers
        .route("/api/v1/vpn/tunnels/{id}/peers", get(vpn_list_peers).post(vpn_add_peer))
        .route("/api/v1/vpn/tunnels/{id}/peers/{peer_id}", delete(vpn_remove_peer))
        .route("/api/v1/vpn/tunnels/{id}/peers/{peer_id}/config", get(vpn_peer_config))
        // DNS/DHCP
        .route("/api/v1/dns/config", get(dns_get_config).put(dns_save_config))
        .route("/api/v1/dns/dhcp/ranges", get(dns_get_dhcp_ranges).put(dns_save_dhcp_ranges))
        .route("/api/v1/dns/dhcp/leases", get(dns_get_dhcp_leases))
        .route("/api/v1/dns/dhcp/static", get(dns_get_static_leases).put(dns_save_static_leases))
        .route("/api/v1/dns/overrides", get(dns_get_overrides).put(dns_save_overrides))
        // IDS
        .route("/api/v1/ids/events", get(ids_list_events))
        .route("/api/v1/ids/events/stats", get(ids_event_stats))
        // Devices
        .route("/api/v1/devices", get(devices_list))
        .route("/api/v1/devices/pending", get(devices_list_pending))
        .route("/api/v1/devices/{mac}/approve", post(devices_approve))
        .route("/api/v1/devices/{mac}/reject", post(devices_reject))
        .route("/api/v1/devices/{mac}/config", get(devices_get_config).put(devices_push_config))
        .layer(axum::middleware::from_fn(e2ee::e2ee_layer))
        .layer(axum::middleware::from_fn_with_state(
            general_limiter.clone(),
            ratelimit::rate_limit_middleware,
        ));

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
            .layer(cors)
            .layer(Extension(db))
            .layer(Extension(negotiate_store))
            .layer(Extension(envelope_key_store))
            .layer(tower_http::trace::TraceLayer::new_for_http())
            .fallback_service(serve_dir)
    } else {
        Router::new()
            .merge(public_routes)
            .merge(protected_routes)
            .layer(cors)
            .layer(Extension(db))
            .layer(Extension(negotiate_store))
            .layer(Extension(envelope_key_store))
            .layer(tower_http::trace::TraceLayer::new_for_http())
    };

    // ----- TLS 1.3 configuration -----
    let tls_config = tls::load_or_create_tls_config()
        .context("failed to configure TLS")?;
    let rustls_config = tls::into_axum_rustls_config(tls_config).await?;

    tracing::info!("API server listening on {listen_addr} (TLS 1.3)");

    axum_server::bind_rustls(listen_addr, rustls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
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
    /// ML-KEM-1024 encapsulation key (base64).  Optional for backwards
    /// compatibility — when absent, only X25519 is used for key exchange.
    /// Web browsers do not yet support ML-KEM in Web Crypto, so the
    /// frontend will omit this until a WASM ML-KEM library is integrated.
    kem_public_key: Option<String>,
    token: Option<String>,
}

async fn session_handler(
    Extension(db): Extension<sfgw_db::Db>,
    Extension(negotiate_store): Extension<e2ee::NegotiateStore>,
    Extension(envelope_key_store): Extension<e2ee::EnvelopeKeyStore>,
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

    // Decode optional ML-KEM encapsulation key for hybrid key exchange.
    let kem_pub = match &body.kem_public_key {
        Some(b64) => match B64.decode(b64) {
            Ok(b) => Some(b),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "invalid base64 in kem_public_key" })),
                );
            }
        },
        None => None,
    };

    let neg_result = match e2ee::negotiate(
        &negotiate_store,
        &client_pub,
        kem_pub.as_deref(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    };

    let negotiate_id = neg_result.negotiate_id;

    let mut response = json!({
        "negotiate_id": negotiate_id,
        "server_public_key": B64.encode(&neg_result.server_public_key),
        "authenticated": false,
    });

    // Include ML-KEM ciphertext if hybrid key exchange was performed.
    if let Some(ref ct) = neg_result.kem_ciphertext {
        response["kem_ciphertext"] = json!(B64.encode(ct));
    }

    // If token provided, try to validate + resume
    if let Some(ref token) = body.token {
        let client_ip = resolve_client_ip(&addr);
        let fingerprint = middleware::fingerprint_from_headers(&headers);

        if let Ok(Some(user_id)) =
            auth::validate_session(&db, token, &client_ip, &fingerprint).await
        {
            if let Ok(Some(user)) = auth::get_user_by_id(&db, user_id).await {
                // Generate new envelope key for this session
                if let Ok(env_key) = e2ee::generate_envelope_key() {
                    // Store envelope key in memory only — never persisted to DB
                    {
                        let mut store = envelope_key_store.lock().await;
                        store.insert(token.to_string(), env_key.to_vec());
                    }

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
    Extension(envelope_key_store): Extension<e2ee::EnvelopeKeyStore>,
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

    let client_ip = resolve_client_ip(&addr);
    let fingerprint = middleware::fingerprint_from_headers(&headers);

    // Generate envelope key for E2EE sessions
    let envelope_key = negotiate_key
        .as_ref()
        .and_then(|_| e2ee::generate_envelope_key().ok());

    // Create session — envelope key is NOT stored in DB (empty string placeholder)
    match auth::create_session(&db, user.id, &client_ip, &fingerprint, "").await {
        Ok((token, expires_at)) => {
            let mut response = json!({
                "token": token,
                "expires_at": expires_at.to_rfc3339(),
            });

            // Store envelope key in memory and encrypt it with negotiate key for the client
            if let (Some(neg_key), Some(env_key)) = (&negotiate_key, &envelope_key) {
                {
                    let mut store = envelope_key_store.lock().await;
                    store.insert(token.clone(), env_key.to_vec());
                }
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
    // Validate input before acquiring the lock
    if body.username.is_empty() || body.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "username and password are required" })),
        );
    }

    if body.password.len() < 12 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "password must be at least 12 characters" })),
        );
    }

    if !body.password.chars().any(|c| c.is_ascii_uppercase())
        || !body.password.chars().any(|c| c.is_ascii_lowercase())
        || !body.password.chars().any(|c| c.is_ascii_digit())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "password must contain at least one uppercase letter, one lowercase letter, and one digit" })),
        );
    }

    // Hash password before holding the lock (Argon2 is CPU-intensive)
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

    // Atomic check-and-create: hold the DB lock for both operations
    // to prevent TOCTOU race where two concurrent requests both see count=0.
    let conn = db.lock().await;

    let count: i64 = match conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("setup user count error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
            );
        }
    };

    if count > 0 {
        return (StatusCode::CONFLICT, Json(json!({ "error": "setup already completed" })));
    }

    match conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?1, ?2, ?3)",
        rusqlite::params![body.username, password_hash, "admin"],
    ) {
        Ok(_) => {
            let user_id = conn.last_insert_rowid();
            (
                StatusCode::CREATED,
                Json(json!({
                    "user_id": user_id,
                    "username": body.username,
                    "role": "admin",
                })),
            )
        }
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

/// Resolve the client IP from the socket peer address.
///
/// Never trusts X-Forwarded-For or other proxy headers.
fn resolve_client_ip(addr: &SocketAddr) -> String {
    addr.ip().to_string()
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

async fn status_handler(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> Json<Value> {
    let uptime = read_uptime_secs();
    let (load1, load5, load15) = read_loadavg();
    let mem = read_meminfo();

    // Check actual service state rather than hardcoding
    let fw_status = {
        let conn = db.lock().await;
        let rule_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM firewall_rules WHERE enabled = 1", [], |r| r.get(0))
            .unwrap_or(0);
        if rule_count > 0 { "running" } else { "stopped" }
    };

    let dns_status = {
        // Check if dnsmasq PID file exists and process is alive
        let running = std::fs::read_to_string("/run/dnsmasq.pid")
            .or_else(|_| std::fs::read_to_string("/var/run/dnsmasq/dnsmasq.pid"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .map(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
            .unwrap_or(false);
        if running { "running" } else { "stopped" }
    };

    let vpn_status = {
        let conn = db.lock().await;
        let tunnel_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM vpn_tunnels WHERE enabled = 1", [], |r| r.get(0))
            .unwrap_or(0);
        if tunnel_count > 0 { "running" } else { "stopped" }
    };

    // IDS is spawned as a background task at boot; if we are serving requests it is running
    let ids_status = "running";

    // NAS: check if any HDD is present via platform detection
    let nas_status = if std::path::Path::new("/dev/sda").exists()
        || std::path::Path::new("/dev/nvme0").exists()
    {
        "running"
    } else {
        "stopped"
    };

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
            "firewall": fw_status,
            "dns": dns_status,
            "vpn": vpn_status,
            "ids": ids_status,
            "nas": nas_status,
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
) -> impl IntoResponse {
    let conn = db.lock().await;
    let mut stmt = match conn.prepare("SELECT name, role, vlan_id, enabled FROM interfaces") {
        Ok(s) => s,
        Err(e) => return internal_err(anyhow::anyhow!("{e}")),
    };
    let rows: Vec<Value> = match stmt.query_map([], |row| {
        Ok(json!({
            "name": row.get::<_, String>(0)?,
            "role": row.get::<_, String>(1)?,
            "vlan_id": row.get::<_, Option<i64>>(2)?,
            "enabled": row.get::<_, bool>(3)?,
        }))
    }) {
        Ok(mapped) => mapped.filter_map(|r| r.ok()).collect(),
        Err(e) => return internal_err(anyhow::anyhow!("{e}")),
    };
    (StatusCode::OK, Json(json!({ "interfaces": rows })))
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

// ---------------------------------------------------------------------------
// Helper: convert anyhow::Error → JSON error response
// ---------------------------------------------------------------------------

fn err_response(status: StatusCode, e: impl Into<anyhow::Error>) -> (StatusCode, Json<Value>) {
    let e: anyhow::Error = e.into();
    // Never expose internal error details to clients.
    // Log the actual error for debugging, return a generic message.
    let generic_msg = if status.is_server_error() {
        tracing::error!("{e:#}");
        "internal server error"
    } else {
        tracing::warn!("{e:#}");
        match status.as_u16() {
            400 => "bad request",
            401 => "unauthorized",
            403 => "forbidden",
            404 => "not found",
            409 => "conflict",
            422 => "validation error",
            429 => "too many requests",
            _ => "request error",
        }
    };
    (status, Json(json!({ "error": generic_msg })))
}

fn internal_err(e: impl Into<anyhow::Error>) -> (StatusCode, Json<Value>) {
    let e: anyhow::Error = e.into();
    tracing::error!("{e:#}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": "internal server error" })),
    )
}

// ===========================================================================
// Firewall handlers
// ===========================================================================

async fn fw_list_rules(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    match sfgw_fw::load_rules(&db).await {
        Ok(rules) => (StatusCode::OK, Json(json!({ "rules": rules }))),
        Err(e) => internal_err(e),
    }
}

async fn fw_insert_rule(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Json(rule): Json<sfgw_fw::FirewallRule>,
) -> impl IntoResponse {
    match sfgw_fw::insert_rule(&db, &rule).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))),
        Err(e) => internal_err(e),
    }
}

async fn fw_update_rule(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(id): Path<i64>,
    Json(mut rule): Json<sfgw_fw::FirewallRule>,
) -> impl IntoResponse {
    rule.id = Some(id);
    match sfgw_fw::update_rule(&db, &rule).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "updated" }))),
        Err(e) => err_response(StatusCode::NOT_FOUND, e),
    }
}

async fn fw_delete_rule(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match sfgw_fw::delete_rule(&db, id).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "deleted" }))),
        Err(e) => err_response(StatusCode::NOT_FOUND, e),
    }
}

#[derive(Deserialize)]
struct ToggleBody {
    enabled: bool,
}

async fn fw_toggle_rule(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(id): Path<i64>,
    Json(body): Json<ToggleBody>,
) -> impl IntoResponse {
    match sfgw_fw::toggle_rule(&db, id, body.enabled).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "toggled", "enabled": body.enabled }))),
        Err(e) => err_response(StatusCode::NOT_FOUND, e),
    }
}

async fn fw_apply_rules(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    match sfgw_fw::apply_rules(&db).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "applied" }))),
        Err(e) => internal_err(e),
    }
}

// ===========================================================================
// VPN handlers
// ===========================================================================

async fn vpn_list_tunnels(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    match sfgw_vpn::tunnel::list_tunnels(&db).await {
        Ok(tunnels) => (StatusCode::OK, Json(json!({ "tunnels": tunnels }))),
        Err(e) => internal_err(e),
    }
}

async fn vpn_create_tunnel(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Json(body): Json<sfgw_vpn::CreateTunnelRequest>,
) -> impl IntoResponse {
    match sfgw_vpn::tunnel::create_tunnel(&db, &body).await {
        Ok(tunnel) => (StatusCode::CREATED, Json(json!({ "tunnel": tunnel }))),
        Err(e) => err_response(StatusCode::BAD_REQUEST, e),
    }
}

async fn vpn_get_tunnel(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match sfgw_vpn::tunnel::get_tunnel_by_id(&db, id).await {
        Ok(Some(tunnel)) => (StatusCode::OK, Json(json!({ "tunnel": tunnel }))),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tunnel not found" })),
        ),
        Err(e) => internal_err(e),
    }
}

async fn vpn_delete_tunnel(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match sfgw_vpn::tunnel::delete_tunnel(&db, id).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "deleted" }))),
        Err(e) => err_response(StatusCode::NOT_FOUND, e),
    }
}

async fn vpn_start_tunnel(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match sfgw_vpn::tunnel::start_tunnel(&db, id).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "started" }))),
        Err(e) => internal_err(e),
    }
}

async fn vpn_stop_tunnel(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match sfgw_vpn::tunnel::stop_tunnel(&db, id).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "stopped" }))),
        Err(e) => internal_err(e),
    }
}

async fn vpn_get_status(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match sfgw_vpn::tunnel::get_tunnel_by_id(&db, id).await {
        Ok(Some(tunnel)) => {
            match sfgw_vpn::tunnel::get_status(&tunnel.name).await {
                Ok(status) => (StatusCode::OK, Json(json!({ "status": status }))),
                Err(e) => internal_err(e),
            }
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tunnel not found" })),
        ),
        Err(e) => internal_err(e),
    }
}

async fn vpn_list_peers(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match sfgw_vpn::peer::list_peers(&db, id).await {
        Ok(peers) => (StatusCode::OK, Json(json!({ "peers": peers }))),
        Err(e) => internal_err(e),
    }
}

async fn vpn_add_peer(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(id): Path<i64>,
    Json(body): Json<sfgw_vpn::CreatePeerRequest>,
) -> impl IntoResponse {
    match sfgw_vpn::peer::add_peer(&db, id, &body).await {
        Ok(peer) => (StatusCode::CREATED, Json(json!({ "peer": peer }))),
        Err(e) => err_response(StatusCode::BAD_REQUEST, e),
    }
}

async fn vpn_remove_peer(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path((id, peer_id)): Path<(i64, i64)>,
) -> impl IntoResponse {
    match sfgw_vpn::peer::remove_peer(&db, id, peer_id).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "peer removed" }))),
        Err(e) => err_response(StatusCode::NOT_FOUND, e),
    }
}

#[derive(Deserialize)]
struct PeerConfigQuery {
    /// Server endpoint for the client config (e.g., "vpn.example.com:51820").
    endpoint: String,
}

async fn vpn_peer_config(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path((id, peer_id)): Path<(i64, i64)>,
    Query(params): Query<PeerConfigQuery>,
) -> impl IntoResponse {
    match sfgw_vpn::peer::generate_client_config(&db, id, peer_id, &params.endpoint).await {
        Ok(config) => (
            StatusCode::OK,
            Json(json!({ "config": config })),
        ),
        Err(e) => err_response(StatusCode::NOT_FOUND, e),
    }
}

// ===========================================================================
// DNS/DHCP handlers
// ===========================================================================

async fn dns_get_config(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    match sfgw_dns::load_dns_config(&db).await {
        Ok(cfg) => (StatusCode::OK, Json(json!({ "config": cfg }))),
        Err(e) => internal_err(e),
    }
}

async fn dns_save_config(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Json(cfg): Json<sfgw_dns::DnsConfig>,
) -> impl IntoResponse {
    match sfgw_dns::save_dns_config(&db, &cfg).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "saved" }))),
        Err(e) => internal_err(e),
    }
}

async fn dns_get_dhcp_ranges(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    match sfgw_dns::load_dhcp_ranges(&db).await {
        Ok(ranges) => (StatusCode::OK, Json(json!({ "ranges": ranges }))),
        Err(e) => internal_err(e),
    }
}

async fn dns_save_dhcp_ranges(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Json(ranges): Json<Vec<sfgw_dns::DhcpRange>>,
) -> impl IntoResponse {
    match sfgw_dns::save_dhcp_ranges(&db, &ranges).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "saved" }))),
        Err(e) => internal_err(e),
    }
}

async fn dns_get_dhcp_leases(
    _auth: AuthUser,
) -> impl IntoResponse {
    match sfgw_dns::read_leases(None).await {
        Ok(leases) => (StatusCode::OK, Json(json!({ "leases": leases }))),
        Err(e) => internal_err(e),
    }
}

async fn dns_get_static_leases(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    match sfgw_dns::load_static_leases(&db).await {
        Ok(leases) => (StatusCode::OK, Json(json!({ "leases": leases }))),
        Err(e) => internal_err(e),
    }
}

async fn dns_save_static_leases(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Json(leases): Json<Vec<sfgw_dns::DhcpStaticLease>>,
) -> impl IntoResponse {
    match sfgw_dns::save_static_leases(&db, &leases).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "saved" }))),
        Err(e) => internal_err(e),
    }
}

async fn dns_get_overrides(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    match sfgw_dns::load_dns_overrides(&db).await {
        Ok(overrides) => (StatusCode::OK, Json(json!({ "overrides": overrides }))),
        Err(e) => internal_err(e),
    }
}

async fn dns_save_overrides(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Json(overrides): Json<Vec<sfgw_dns::DnsOverride>>,
) -> impl IntoResponse {
    match sfgw_dns::save_dns_overrides(&db, &overrides).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "saved" }))),
        Err(e) => internal_err(e),
    }
}

// ===========================================================================
// IDS handlers
// ===========================================================================

#[derive(Deserialize)]
struct IdsEventsQuery {
    limit: Option<i64>,
    severity: Option<String>,
}

async fn ids_list_events(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Query(params): Query<IdsEventsQuery>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100).min(1000);

    let result = {
        let conn = db.lock().await;

        let map_row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<Value> {
            Ok(json!({
                "id": row.get::<_, i64>(0)?,
                "timestamp": row.get::<_, String>(1)?,
                "severity": row.get::<_, String>(2)?,
                "detector": row.get::<_, String>(3)?,
                "source_mac": row.get::<_, Option<String>>(4)?,
                "source_ip": row.get::<_, Option<String>>(5)?,
                "interface": row.get::<_, String>(6)?,
                "vlan": row.get::<_, Option<i64>>(7)?,
                "description": row.get::<_, String>(8)?,
            }))
        };

        let events: Result<Vec<Value>, _> = if let Some(ref severity) = params.severity {
            let mut stmt = match conn.prepare(
                "SELECT id, timestamp, severity, detector, source_mac, source_ip, interface, vlan, description \
                 FROM ids_events WHERE severity = ?1 ORDER BY id DESC LIMIT ?2",
            ) {
                Ok(s) => s,
                Err(e) => return internal_err(anyhow::anyhow!("{e}")),
            };
            stmt.query_map(rusqlite::params![severity, limit], map_row)
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
        } else {
            let mut stmt = match conn.prepare(
                "SELECT id, timestamp, severity, detector, source_mac, source_ip, interface, vlan, description \
                 FROM ids_events ORDER BY id DESC LIMIT ?1",
            ) {
                Ok(s) => s,
                Err(e) => return internal_err(anyhow::anyhow!("{e}")),
            };
            stmt.query_map(rusqlite::params![limit], map_row)
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
        };

        match events {
            Ok(v) => v,
            Err(e) => return internal_err(anyhow::anyhow!("{e}")),
        }
    };

    (StatusCode::OK, Json(json!({ "events": result })))
}

async fn ids_event_stats(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    let result = {
        let conn = db.lock().await;

        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM ids_events", [], |r| r.get(0))
            .unwrap_or(0);

        let mut by_severity = json!({});
        if let Ok(mut stmt) =
            conn.prepare("SELECT severity, COUNT(*) FROM ids_events GROUP BY severity")
        {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            }) {
                for row in rows.flatten() {
                    by_severity[row.0] = json!(row.1);
                }
            }
        }

        let mut by_detector = json!({});
        if let Ok(mut stmt) =
            conn.prepare("SELECT detector, COUNT(*) FROM ids_events GROUP BY detector")
        {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            }) {
                for row in rows.flatten() {
                    by_detector[row.0] = json!(row.1);
                }
            }
        }

        json!({
            "total": total,
            "by_severity": by_severity,
            "by_detector": by_detector,
        })
    };

    (StatusCode::OK, Json(result))
}

// ===========================================================================
// Device handlers
// ===========================================================================

async fn devices_list(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    match sfgw_adopt::list_devices(&db).await {
        Ok(devices) => (StatusCode::OK, Json(json!({ "devices": devices }))),
        Err(e) => internal_err(e),
    }
}

async fn devices_list_pending(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    match sfgw_adopt::list_pending(&db).await {
        Ok(devices) => (StatusCode::OK, Json(json!({ "devices": devices }))),
        Err(e) => internal_err(e),
    }
}

async fn devices_approve(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(mac): Path<String>,
    Json(body): Json<sfgw_adopt::AdoptionRequest>,
) -> impl IntoResponse {
    // Ensure the MAC in the path matches the body
    let mut request = body;
    request.device_mac = mac;

    // Initialize the CA for signing
    let ca = match sfgw_adopt::start(&db).await {
        Ok(ca) => ca,
        Err(e) => return internal_err(e),
    };

    match sfgw_adopt::approve_device(&db, &ca, &request).await {
        Ok(response) => (StatusCode::OK, Json(json!({ "adoption": response }))),
        Err(e) => err_response(StatusCode::BAD_REQUEST, e),
    }
}

async fn devices_reject(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(mac): Path<String>,
) -> impl IntoResponse {
    match sfgw_adopt::reject_device(&db, &mac).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "rejected" }))),
        Err(e) => err_response(StatusCode::NOT_FOUND, e),
    }
}

async fn devices_get_config(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(mac): Path<String>,
) -> impl IntoResponse {
    match sfgw_adopt::get_device_config(&db, &mac).await {
        Ok(config) => (StatusCode::OK, Json(json!({ "config": config }))),
        Err(e) => err_response(StatusCode::NOT_FOUND, e),
    }
}

async fn devices_push_config(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(mac): Path<String>,
    Json(config): Json<Value>,
) -> impl IntoResponse {
    match sfgw_adopt::push_config(&db, &mac, config).await {
        Ok(seq) => (StatusCode::OK, Json(json!({ "status": "queued", "sequence_number": seq }))),
        Err(e) => err_response(StatusCode::NOT_FOUND, e),
    }
}
