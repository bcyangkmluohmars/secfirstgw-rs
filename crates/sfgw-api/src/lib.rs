// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

pub mod auth;
pub mod e2ee;
pub mod events;
pub mod middleware;
pub mod ratelimit;
pub mod tls;

use anyhow::{Context, Result};
use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, Path, Query},
    http::{HeaderMap, Method, StatusCode, header::HeaderName},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};

use crate::middleware::AuthUser;
use crate::ratelimit::RateLimiter;

/// Start the axum web API and serve the UI over TLS 1.3.
pub async fn serve(db: &sfgw_db::Db, event_tx: events::EventTx) -> Result<()> {
    let listen_addr: SocketAddr = std::env::var("SFGW_LISTEN_ADDR")
        .unwrap_or_else(|_| "[::]:443".to_string())
        .parse()
        .context("invalid SFGW_LISTEN_ADDR")?;

    let db = db.clone();
    let negotiate_store = e2ee::new_negotiate_store();
    let envelope_key_store = e2ee::new_envelope_key_store();

    // ----- Rate limiters -----
    // Auth mutations (login, session, setup POST): 10 requests per minute per IP.
    // Normal login flow uses ~3 (session + login + setup-check), so 10 gives margin.
    let auth_limiter = RateLimiter::new(10, Duration::from_secs(60));
    // Protected API + read-only public endpoints: 120 requests per minute per IP.
    // Dashboard loads ~8-10 API calls at once, so 60 was too tight for power users.
    let general_limiter = RateLimiter::new(120, Duration::from_secs(60));

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
    // Auth mutations (login, session, setup POST) use the stricter auth limiter.
    // Setup status check (GET) is on the general limiter — read-only, called on every page load.
    let auth_rate_limited = Router::new()
        .route("/api/v1/auth/session", post(session_handler))
        .route("/api/v1/auth/login", post(login_handler))
        .route("/api/v1/auth/setup", post(setup_handler))
        .layer(axum::middleware::from_fn_with_state(
            auth_limiter.clone(),
            ratelimit::rate_limit_middleware,
        ));
    let public_status = Router::new()
        .route("/api/v1/auth/setup", get(setup_status_handler))
        .layer(axum::middleware::from_fn_with_state(
            general_limiter.clone(),
            ratelimit::rate_limit_middleware,
        ));
    let public_routes = auth_rate_limited.merge(public_status);

    // ----- Protected routes (auth required, general rate limit) -----
    let protected_routes = Router::new()
        // System
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/system", get(system_handler))
        .route("/api/v1/interfaces", get(interfaces_handler))
        .route(
            "/api/v1/interfaces/{name}",
            put(interface_update).delete(interface_delete),
        )
        .route("/api/v1/interfaces/{name}/toggle", post(interface_toggle))
        .route("/api/v1/interfaces/vlan", post(interface_create_vlan))
        .route("/api/v1/auth/me", get(me_handler))
        .route("/api/v1/auth/logout", post(logout_handler))
        // Personality
        .route(
            "/api/v1/personality",
            get(personality_get).put(personality_set),
        )
        // User management
        .route("/api/v1/users", get(users_list).post(users_create))
        .route("/api/v1/users/{id}", put(users_update).delete(users_delete))
        .route("/api/v1/users/{id}/password", post(users_change_password))
        // Firewall
        .route(
            "/api/v1/firewall/rules",
            get(fw_list_rules).post(fw_insert_rule),
        )
        .route(
            "/api/v1/firewall/rules/{id}",
            put(fw_update_rule).delete(fw_delete_rule),
        )
        .route("/api/v1/firewall/rules/{id}/toggle", post(fw_toggle_rule))
        .route("/api/v1/firewall/apply", post(fw_apply_rules))
        // VPN tunnels
        .route(
            "/api/v1/vpn/tunnels",
            get(vpn_list_tunnels).post(vpn_create_tunnel),
        )
        .route(
            "/api/v1/vpn/tunnels/{id}",
            get(vpn_get_tunnel).delete(vpn_delete_tunnel),
        )
        .route("/api/v1/vpn/tunnels/{id}/start", post(vpn_start_tunnel))
        .route("/api/v1/vpn/tunnels/{id}/stop", post(vpn_stop_tunnel))
        .route("/api/v1/vpn/tunnels/{id}/status", get(vpn_get_status))
        // VPN peers
        .route(
            "/api/v1/vpn/tunnels/{id}/peers",
            get(vpn_list_peers).post(vpn_add_peer),
        )
        .route(
            "/api/v1/vpn/tunnels/{id}/peers/{peer_id}",
            delete(vpn_remove_peer),
        )
        .route(
            "/api/v1/vpn/tunnels/{id}/peers/{peer_id}/config",
            get(vpn_peer_config),
        )
        // DNS/DHCP
        .route(
            "/api/v1/dns/config",
            get(dns_get_config).put(dns_save_config),
        )
        .route(
            "/api/v1/dns/dhcp/ranges",
            get(dns_get_dhcp_ranges).put(dns_save_dhcp_ranges),
        )
        .route("/api/v1/dns/dhcp/leases", get(dns_get_dhcp_leases))
        .route(
            "/api/v1/dns/dhcp/static",
            get(dns_get_static_leases).put(dns_save_static_leases),
        )
        .route(
            "/api/v1/dns/overrides",
            get(dns_get_overrides).put(dns_save_overrides),
        )
        // WAN
        .route("/api/v1/wan", get(wan_list))
        .route(
            "/api/v1/wan/{interface}",
            get(wan_get).put(wan_set).delete(wan_delete),
        )
        .route("/api/v1/wan/{interface}/status", get(wan_status))
        .route("/api/v1/wan/{interface}/reconnect", post(wan_reconnect))
        // Ports (PVID/tagged VLAN per-port config + live reconfiguration)
        .route(
            "/api/v1/ports/{name}",
            get(port_get_handler).put(port_update_handler),
        )
        // Zones (read-only VLAN zone view)
        .route("/api/v1/zones", get(zones_list_handler))
        .route("/api/v1/zones/{zone}", get(zone_get_handler))
        // IDS
        .route("/api/v1/ids/events", get(ids_list_events))
        .route("/api/v1/ids/events/stats", get(ids_event_stats))
        // Devices
        .route("/api/v1/devices", get(devices_list))
        .route("/api/v1/devices/pending", get(devices_list_pending))
        .route("/api/v1/devices/{mac}/approve", post(devices_approve))
        .route("/api/v1/devices/{mac}/reject", post(devices_reject))
        .route(
            "/api/v1/devices/{mac}/config",
            get(devices_get_config).put(devices_push_config),
        )
        .layer(axum::middleware::from_fn(e2ee::e2ee_layer))
        .layer(axum::middleware::from_fn_with_state(
            general_limiter.clone(),
            ratelimit::rate_limit_middleware,
        ));

    // SSE event stream — auth required but no E2EE (streaming, not request/response).
    let sse_routes = Router::new()
        .route("/api/v1/events/stream", get(events::event_stream_handler))
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
            .merge(sse_routes)
            .layer(cors)
            .layer(axum::middleware::from_fn(security_headers_middleware))
            .layer(Extension(event_tx))
            .layer(Extension(db))
            .layer(Extension(negotiate_store))
            .layer(Extension(envelope_key_store))
            .layer(tower_http::trace::TraceLayer::new_for_http())
            .fallback_service(serve_dir)
    } else {
        Router::new()
            .merge(public_routes)
            .merge(protected_routes)
            .merge(sse_routes)
            .layer(cors)
            .layer(axum::middleware::from_fn(security_headers_middleware))
            .layer(Extension(event_tx))
            .layer(Extension(db))
            .layer(Extension(negotiate_store))
            .layer(Extension(envelope_key_store))
            .layer(tower_http::trace::TraceLayer::new_for_http())
    };

    // ----- TLS 1.3 configuration -----
    let tls_config = tls::load_or_create_tls_config().context("failed to configure TLS")?;
    let rustls_config = tls::into_axum_rustls_config(tls_config).await?;

    tracing::info!("API server listening on {listen_addr} (TLS 1.3)");

    axum_server::bind_rustls(listen_addr, rustls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("API server error")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

/// Middleware that adds security headers to every response.
async fn security_headers_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    use axum::http::HeaderValue;

    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        axum::http::header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"),
    );
    headers.insert(
        axum::http::header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    );
    // no-store on API responses; static assets could use different caching
    // but for a gateway admin panel, no-store is safest.
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );

    response
}

// ---------------------------------------------------------------------------
// Personality
// ---------------------------------------------------------------------------

async fn personality_get(_auth: AuthUser) -> Json<Value> {
    let active = sfgw_personality::active();
    let all: Vec<Value> = sfgw_personality::Personality::ALL
        .iter()
        .map(|p| {
            json!({
                "name": p.name(),
                "description": p.description(),
                "active": *p == active,
            })
        })
        .collect();
    Json(json!({ "active": active.name(), "personalities": all }))
}

async fn personality_set(_auth: AuthUser, Json(body): Json<Value>) -> impl IntoResponse {
    let name = match body.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": "missing field: name" })),
            );
        }
    };

    match sfgw_personality::Personality::from_name(name) {
        Some(p) => {
            sfgw_personality::set(p);
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "active": p.name() })),
            )
        }
        None => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": format!("unknown personality: {name}") })),
        ),
    }
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

    let neg_result = match e2ee::negotiate(&negotiate_store, &client_pub, kem_pub.as_deref()).await
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
            && let Ok(Some(user)) = auth::get_user_by_id(&db, user_id).await
        {
            // Generate new envelope key for this session
            if let Ok(env_key) = e2ee::generate_envelope_key() {
                // Store envelope key in memory only — never persisted to DB
                {
                    let mut store = envelope_key_store.lock().await;
                    store.insert(token.to_string(), env_key.to_vec());
                }

                // Get the negotiate AES key to encrypt the envelope key
                if let Ok(neg_key) = e2ee::take_negotiate_key(&negotiate_store, &negotiate_id).await
                    && let Ok(sealed) = e2ee::Envelope::seal(&neg_key, &env_key)
                {
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
    let (username, password, negotiate_key) =
        if let (Some(nid), Some(ct), Some(iv)) = (&body.negotiate_id, &body.ciphertext, &body.iv) {
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
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({ "error": "decryption failed" })),
                    );
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

    match auth::verify_password(&password, &password_hash) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid credentials" })),
            );
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

async fn setup_status_handler(Extension(db): Extension<sfgw_db::Db>) -> impl IntoResponse {
    let conn = db.lock().await;
    let count: i64 = match conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("setup status user count error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
            );
        }
    };
    (StatusCode::OK, Json(json!({ "needed": count == 0 })))
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
            Json(
                json!({ "error": "password must contain at least one uppercase letter, one lowercase letter, and one digit" }),
            ),
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
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "setup already completed" })),
        );
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
    let count = content
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count();
    if count == 0 { 1 } else { count }
}

fn read_arch() -> &'static str {
    std::env::consts::ARCH
}

// ---------------------------------------------------------------------------
// Protected handlers
// ---------------------------------------------------------------------------

async fn status_handler(_auth: AuthUser, Extension(db): Extension<sfgw_db::Db>) -> Json<Value> {
    let uptime = read_uptime_secs() as u64;
    let (load1, load5, load15) = read_loadavg();
    let mem = read_meminfo();

    // Check actual service state rather than hardcoding
    let fw_status = {
        let conn = db.lock().await;
        let rule_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM firewall_rules", [], |r| r.get(0))
            .unwrap_or(0);
        let enabled_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM firewall_rules WHERE enabled = 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if rule_count == 0 {
            "not_configured"
        } else if enabled_count > 0 {
            "running"
        } else {
            "disabled"
        }
    };

    let dns_status = {
        // Check if dnsmasq PID file exists and process is alive
        let pid_alive = std::fs::read_to_string("/run/sfgw-dnsmasq.pid")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .map(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
            .unwrap_or(false);
        // DNS config is stored as JSON in the meta KV table
        let conn = db.lock().await;
        let has_config: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM meta WHERE key = 'dns_config'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;
        if pid_alive {
            "running"
        } else if has_config {
            "stopped"
        } else {
            "not_configured"
        }
    };

    let vpn_status = {
        let conn = db.lock().await;
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM vpn_tunnels", [], |r| r.get(0))
            .unwrap_or(0);
        let enabled: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM vpn_tunnels WHERE enabled = 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if total == 0 {
            "not_configured"
        } else if enabled > 0 {
            "running"
        } else {
            "disabled"
        }
    };

    // IDS is spawned as a background task at boot; if we are serving requests it is running
    let ids_status = "running";

    // NAS: check if storage devices are present
    let nas_status = {
        let has_storage = std::path::Path::new("/dev/sda").exists()
            || std::path::Path::new("/dev/nvme0").exists();
        let has_share_config = std::path::Path::new("/etc/samba/smb.conf").exists()
            || std::path::Path::new("/etc/exports").exists();
        if has_storage && has_share_config {
            "running"
        } else if has_storage {
            "not_configured"
        } else {
            "unavailable"
        }
    };

    let net_io = sfgw_net::read_net_io();

    Json(json!({
        "status": "ok",
        "uptime_secs": uptime,
        "load_average": [load1, load5, load15],
        "memory": {
            "total_mb": mem.total_mb,
            "used_mb": mem.used_mb,
            "free_mb": mem.free_mb,
        },
        "network": net_io,
        "services": {
            "firewall": fw_status,
            "dns": dns_status,
            "vpn": vpn_status,
            "ids": ids_status,
            "nas": nas_status,
        }
    }))
}

async fn system_handler(_auth: AuthUser, Extension(db): Extension<sfgw_db::Db>) -> Json<Value> {
    let version = {
        let conn = db.lock().await;
        conn.query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap_or_else(|_| "unknown".to_string())
    };

    let board = sfgw_hal::detect_board().map(|b| {
        json!({
            "board_id": b.board_id,
            "model": b.model,
            "short_name": b.short_name,
            "port_count": b.port_count,
            "ports": b.ports.iter().map(|p| json!({
                "label": p.label,
                "iface": p.iface,
                "connector": p.connector.to_string(),
                "default_zone": p.default_zone,
            })).collect::<Vec<_>>(),
        })
    });

    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "schema_version": version,
        "platform": std::env::var("SFGW_PLATFORM").unwrap_or_else(|_| "unknown".to_string()),
        "hostname": read_hostname(),
        "kernel": read_kernel_version(),
        "arch": read_arch(),
        "cpu_count": read_cpu_count(),
        "board": board,
    }))
}

async fn interfaces_handler(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    let conn = db.lock().await;
    let mut stmt = match conn.prepare(
        "SELECT name, mac, ips, mtu, is_up, pvid, tagged_vlans, enabled FROM interfaces ORDER BY name",
    ) {
        Ok(s) => s,
        Err(e) => return internal_err(anyhow::anyhow!("{e}")),
    };
    let rows: Vec<Value> = match stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let ips_json: String = row.get(2)?;
        let ips: Value = serde_json::from_str(&ips_json).unwrap_or(Value::Array(vec![]));
        let tagged_json: String = row.get(6)?;
        let tagged_vlans: Value =
            serde_json::from_str(&tagged_json).unwrap_or(Value::Array(vec![]));

        // Detect hardware port type from sysfs
        let port_info = detect_port_type(&name);

        Ok(json!({
            "name": name,
            "mac": row.get::<_, String>(1)?,
            "ips": ips,
            "mtu": row.get::<_, i64>(3)?,
            "is_up": row.get::<_, bool>(4)?,
            "pvid": row.get::<_, i64>(5)?,
            "tagged_vlans": tagged_vlans,
            "enabled": row.get::<_, bool>(7)?,
            "speed": port_info.0,
            "driver": port_info.1,
            "port_type": port_info.2,
        }))
    }) {
        Ok(mapped) => mapped.filter_map(|r| r.ok()).collect(),
        Err(e) => return internal_err(anyhow::anyhow!("{e}")),
    };
    (StatusCode::OK, Json(json!({ "interfaces": rows })))
}

/// Detect port type, speed, and driver from sysfs.
/// Returns (speed_mbps_or_null, driver_name, port_type_label).
fn detect_port_type(name: &str) -> (Value, Value, Value) {
    let base = format!("/sys/class/net/{name}");

    // Speed (e.g. "1000", "10000", "25000")
    let speed: Value = std::fs::read_to_string(format!("{base}/speed"))
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&s| s > 0)
        .map(|s| json!(s))
        .unwrap_or(Value::Null);

    // Driver name from device/driver symlink
    let driver: Value = std::fs::read_link(format!("{base}/device/driver"))
        .ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string()))
        .map(|d| json!(d))
        .unwrap_or(Value::Null);

    // Derive port type from driver + speed
    let driver_str = driver.as_str().unwrap_or("");
    let speed_val = speed.as_i64().unwrap_or(0);
    let port_type = match driver_str {
        // Common 1G copper drivers
        "e1000" | "e1000e" | "igb" | "igc" | "r8169" | "tg3" | "bnxt_en" | "atlantic" => {
            json!(format!("RJ45 {}", format_speed(speed_val)))
        }
        // 10G/25G SFP+ drivers
        "ixgbe" | "i40e" | "ice" | "bnx2x" => {
            if speed_val >= 25000 {
                json!("SFP28")
            } else {
                json!(format!("SFP+ {}", format_speed(speed_val)))
            }
        }
        // Mellanox
        "mlx4_en" | "mlx5_core" => {
            if speed_val >= 100000 {
                json!("QSFP28")
            } else if speed_val >= 40000 {
                json!("QSFP+")
            } else {
                json!(format!("SFP+ {}", format_speed(speed_val)))
            }
        }
        // Intel X520/X710 etc
        "igb_uio" | "vfio-pci" => json!("SR-IOV VF"),
        // Virtual
        "virtio_net" | "vmxnet3" | "hv_netvsc" | "xen_netfront" => json!("Virtual"),
        // Bridge/VLAN/bond
        "bridge" => json!("Bridge"),
        "bonding" => json!("Bond"),
        "802.1Q" => json!("VLAN"),
        // Docker veth
        "veth" => json!("veth"),
        _ => {
            // Check if it's a VLAN (name contains dot)
            if name.contains('.') {
                json!("VLAN")
            } else if name.starts_with("br") {
                json!("Bridge")
            } else if name.starts_with("bond") {
                json!("Bond")
            } else if name == "lo" {
                json!("Loopback")
            } else if name.starts_with("docker") || name.starts_with("veth") {
                json!("Container")
            } else {
                json!("Ethernet")
            }
        }
    };

    (speed, driver, port_type)
}

fn format_speed(mbps: i64) -> String {
    match mbps {
        s if s >= 100000 => format!("{}G", s / 1000),
        s if s >= 1000 => format!("{}G", s / 1000),
        s if s > 0 => format!("{}M", s),
        _ => String::new(),
    }
}

/// Update interface properties (pvid, tagged_vlans, mtu, enabled).
async fn interface_update(
    _auth: AuthUser,
    Path(name): Path<String>,
    Extension(db): Extension<sfgw_db::Db>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let conn = db.lock().await;

    // Build dynamic UPDATE
    let mut sets = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(pvid) = body.get("pvid").and_then(|v| v.as_i64()) {
        // pvid=0 is valid (WAN port — outside internal VLAN space). 1-4094 are internal VLANs.
        if pvid != 0 && !(1..=4094).contains(&pvid) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": "pvid must be 0 (WAN) or 1-4094" })),
            );
        }
        sets.push("pvid = ?");
        params.push(Box::new(pvid));
    }
    if let Some(tagged) = body.get("tagged_vlans").and_then(|v| v.as_array()) {
        // Validate each VLAN ID is in the valid range 1-4094
        for vlan in tagged {
            if let Some(v) = vlan.as_i64() {
                if !(1..=4094).contains(&v) {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Json(json!({ "error": "tagged VLAN IDs must be 1-4094" })),
                    );
                }
            } else {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "tagged_vlans must be an array of integers" })),
                );
            }
        }
        let json_str = serde_json::to_string(tagged).unwrap_or_else(|_| "[]".to_string());
        sets.push("tagged_vlans = ?");
        params.push(Box::new(json_str));
    }
    if let Some(mtu) = body.get("mtu").and_then(|v| v.as_i64()) {
        if !(576..=9216).contains(&mtu) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": "mtu must be 576-9216" })),
            );
        }
        sets.push("mtu = ?");
        params.push(Box::new(mtu));
    }
    if let Some(enabled) = body.get("enabled").and_then(|v| v.as_bool()) {
        sets.push("enabled = ?");
        params.push(Box::new(enabled as i32));
    }

    if sets.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "no fields to update" })),
        );
    }

    let sql = format!("UPDATE interfaces SET {} WHERE name = ?", sets.join(", "));
    params.push(Box::new(name.clone()));

    let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    match conn.execute(&sql, param_refs.as_slice()) {
        Ok(0) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "interface not found" })),
        ),
        Ok(_) => {
            tracing::info!(interface = %name, "interface updated");
            (StatusCode::OK, Json(json!({ "ok": true })))
        }
        Err(e) => internal_err(anyhow::anyhow!("{e}")),
    }
}

/// Toggle interface enabled state.
async fn interface_toggle(
    _auth: AuthUser,
    Path(name): Path<String>,
    Extension(db): Extension<sfgw_db::Db>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let enabled = match body.get("enabled").and_then(|v| v.as_bool()) {
        Some(e) => e,
        None => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": "missing 'enabled' boolean" })),
            );
        }
    };
    let conn = db.lock().await;
    match conn.execute(
        "UPDATE interfaces SET enabled = ? WHERE name = ?",
        rusqlite::params![enabled as i32, name],
    ) {
        Ok(0) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "interface not found" })),
        ),
        Ok(_) => {
            tracing::info!(interface = %name, enabled, "interface toggled");
            (StatusCode::OK, Json(json!({ "ok": true })))
        }
        Err(e) => internal_err(anyhow::anyhow!("{e}")),
    }
}

/// Create a VLAN sub-interface.
async fn interface_create_vlan(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let parent = match body.get("parent").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": "missing 'parent' interface name" })),
            );
        }
    };
    let vlan_id = match body.get("vlan_id").and_then(|v| v.as_i64()) {
        Some(v) if (1..=4094).contains(&v) => v,
        _ => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": "vlan_id must be 1-4094" })),
            );
        }
    };
    // pvid for the new VLAN sub-interface defaults to the VLAN ID itself
    // (the sub-interface carries exactly that VLAN as its native VLAN).
    let pvid = body
        .get("pvid")
        .and_then(|v| v.as_i64())
        .unwrap_or(vlan_id);
    if pvid != 0 && !(1..=4094).contains(&pvid) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "pvid must be 0 (WAN) or 1-4094" })),
        );
    }

    let vlan_name = format!("{parent}.{vlan_id}");
    let conn = db.lock().await;

    // Check parent exists
    let parent_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM interfaces WHERE name = ?",
            [&parent],
            |row| row.get::<_, i64>(0),
        )
        .map(|c| c > 0)
        .unwrap_or(false);

    if !parent_exists {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("parent interface '{parent}' not found") })),
        );
    }

    // Check VLAN doesn't already exist
    let already_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM interfaces WHERE name = ?",
            [&vlan_name],
            |row| row.get::<_, i64>(0),
        )
        .map(|c| c > 0)
        .unwrap_or(false);

    if already_exists {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": format!("interface '{vlan_name}' already exists") })),
        );
    }

    match conn.execute(
        "INSERT INTO interfaces (name, mac, ips, mtu, is_up, pvid, tagged_vlans, enabled)
         VALUES (?, '', '[]', 1500, 0, ?, '[]', 1)",
        rusqlite::params![vlan_name, pvid],
    ) {
        Ok(_) => {
            tracing::info!(
                parent = %parent,
                vlan_id,
                vlan_name = %vlan_name,
                pvid,
                "VLAN sub-interface created"
            );
            (
                StatusCode::CREATED,
                Json(json!({
                    "name": vlan_name,
                    "vlan_id": vlan_id,
                    "pvid": pvid,
                })),
            )
        }
        Err(e) => internal_err(anyhow::anyhow!("{e}")),
    }
}

/// Delete a VLAN sub-interface. Only allows deleting VLAN interfaces (name contains a dot).
async fn interface_delete(
    _auth: AuthUser,
    Path(name): Path<String>,
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    let conn = db.lock().await;

    // Only allow deleting VLAN sub-interfaces. These are identified by a dot in the name
    // (e.g. "eth0.10"). Physical interfaces like "eth0" or "lo" cannot be deleted.
    if !name.contains('.') {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "cannot delete physical interfaces, only VLAN sub-interfaces (name must contain a dot)" })),
        );
    }

    match conn.execute("DELETE FROM interfaces WHERE name = ?", [&name]) {
        Ok(0) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "interface not found" })),
        ),
        Ok(_) => {
            tracing::info!(interface = %name, "VLAN sub-interface deleted");
            (StatusCode::OK, Json(json!({ "ok": true })))
        }
        Err(e) => internal_err(anyhow::anyhow!("{e}")),
    }
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
    // Log the actual error for debugging, return a sassy message.
    let msg: &str = if status.is_server_error() {
        tracing::error!("{e:#}");
        "internal server error"
    } else {
        tracing::warn!("{e:#}");
        match status.as_u16() {
            401 => sfgw_personality::messages::unauthorized(),
            403 => sfgw_personality::messages::forbidden(),
            404 => sfgw_personality::messages::not_found(),
            429 => sfgw_personality::messages::rate_limited(),
            400 => "bad request",
            409 => "conflict",
            422 => "validation error",
            _ => "request error",
        }
    };
    (status, Json(json!({ "error": msg })))
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
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "status": "toggled", "enabled": body.enabled })),
        ),
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
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // Determine tunnel type from the request body
    let tunnel_type = body
        .get("tunnel_type")
        .and_then(|v| v.as_str())
        .unwrap_or("wireguard");

    match sfgw_vpn::TunnelType::from_str_lossy(tunnel_type) {
        sfgw_vpn::TunnelType::IPsec => {
            let request: sfgw_vpn::CreateIpsecTunnelRequest = match serde_json::from_value(body) {
                Ok(r) => r,
                Err(e) => {
                    return err_response(
                        StatusCode::BAD_REQUEST,
                        anyhow::anyhow!("invalid IPsec tunnel request: {e}"),
                    );
                }
            };
            match sfgw_vpn::ipsec::create_ipsec_tunnel(&db, &request).await {
                Ok(tunnel) => (StatusCode::CREATED, Json(json!({ "tunnel": tunnel }))),
                Err(e) => err_response(StatusCode::BAD_REQUEST, e),
            }
        }
        sfgw_vpn::TunnelType::WireGuard => {
            let request: sfgw_vpn::CreateTunnelRequest = match serde_json::from_value(body) {
                Ok(r) => r,
                Err(e) => {
                    return err_response(
                        StatusCode::BAD_REQUEST,
                        anyhow::anyhow!("invalid WireGuard tunnel request: {e}"),
                    );
                }
            };
            match sfgw_vpn::tunnel::create_tunnel(&db, &request).await {
                Ok(tunnel) => (StatusCode::CREATED, Json(json!({ "tunnel": tunnel }))),
                Err(e) => err_response(StatusCode::BAD_REQUEST, e),
            }
        }
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
        Ok(Some(tunnel)) => match tunnel.tunnel_type {
            sfgw_vpn::TunnelType::IPsec => {
                match sfgw_vpn::ipsec::get_ipsec_status(&tunnel.name).await {
                    Ok(status) => (StatusCode::OK, Json(json!({ "status": status }))),
                    Err(e) => internal_err(e),
                }
            }
            sfgw_vpn::TunnelType::WireGuard => {
                match sfgw_vpn::tunnel::get_status(&tunnel.name).await {
                    Ok(status) => (StatusCode::OK, Json(json!({ "status": status }))),
                    Err(e) => internal_err(e),
                }
            }
        },
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
        Ok(config) => (StatusCode::OK, Json(json!({ "config": config }))),
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

async fn dns_get_dhcp_leases(_auth: AuthUser) -> impl IntoResponse {
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
            && let Ok(rows) = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
        {
            for row in rows.flatten() {
                by_severity[row.0] = json!(row.1);
            }
        }

        let mut by_detector = json!({});
        if let Ok(mut stmt) =
            conn.prepare("SELECT detector, COUNT(*) FROM ids_events GROUP BY detector")
            && let Ok(rows) = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
        {
            for row in rows.flatten() {
                by_detector[row.0] = json!(row.1);
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

async fn devices_list(_auth: AuthUser, Extension(db): Extension<sfgw_db::Db>) -> impl IntoResponse {
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
        Ok(seq) => (
            StatusCode::OK,
            Json(json!({ "status": "queued", "sequence_number": seq })),
        ),
        Err(e) => err_response(StatusCode::NOT_FOUND, e),
    }
}

// ---------------------------------------------------------------------------
// WAN configuration handlers
// ---------------------------------------------------------------------------

async fn wan_list(_auth: AuthUser, Extension(db): Extension<sfgw_db::Db>) -> impl IntoResponse {
    match sfgw_net::wan::list_wan_configs(&db).await {
        Ok(configs) => (StatusCode::OK, Json(json!({ "configs": configs }))),
        Err(e) => internal_err(e),
    }
}

async fn wan_get(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(interface): Path<String>,
) -> impl IntoResponse {
    match sfgw_net::wan::get_wan_config(&db, &interface).await {
        Ok(Some(config)) => (StatusCode::OK, Json(json!({ "config": config }))),
        Ok(None) => err_response(
            StatusCode::NOT_FOUND,
            anyhow::anyhow!("WAN config not found"),
        ),
        Err(e) => internal_err(e),
    }
}

async fn wan_set(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(interface): Path<String>,
    Json(mut config): Json<sfgw_net::wan::WanPortConfig>,
) -> impl IntoResponse {
    // Ensure the path parameter matches the body
    config.interface = interface;

    if let Err(e) = sfgw_net::wan::validate_wan_config(&config) {
        return err_response(StatusCode::UNPROCESSABLE_ENTITY, e);
    }

    match sfgw_net::wan::set_wan_config(&db, &config).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "status": "saved", "wan_config": config })),
        ),
        Err(e) => internal_err(e),
    }
}

async fn wan_delete(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(interface): Path<String>,
) -> impl IntoResponse {
    match sfgw_net::wan::remove_wan_config(&db, &interface).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "removed" }))),
        Err(e) => internal_err(e),
    }
}

async fn wan_status(_auth: AuthUser, Path(interface): Path<String>) -> impl IntoResponse {
    match sfgw_net::wan::detect_wan_status(&interface).await {
        Ok(status) => (StatusCode::OK, Json(json!({ "wan_status": status }))),
        Err(e) => internal_err(e),
    }
}

async fn wan_reconnect(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(interface): Path<String>,
) -> impl IntoResponse {
    let config = match sfgw_net::wan::get_wan_config(&db, &interface).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return err_response(
                StatusCode::NOT_FOUND,
                anyhow::anyhow!("WAN config not found"),
            );
        }
        Err(e) => return internal_err(e),
    };

    match sfgw_net::wan::apply_wan_config(&config).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "reconnecting" }))),
        Err(e) => internal_err(e),
    }
}

// ---------------------------------------------------------------------------
// User management
// ---------------------------------------------------------------------------

const VALID_ROLES: &[&str] = &["admin", "readonly"];

async fn users_list(auth: AuthUser, Extension(db): Extension<sfgw_db::Db>) -> impl IntoResponse {
    if auth.user.role != "admin" {
        return err_response(StatusCode::FORBIDDEN, anyhow::anyhow!("admin only"));
    }
    let conn = db.lock().await;
    let mut stmt =
        match conn.prepare("SELECT id, username, role, created_at FROM users ORDER BY id") {
            Ok(s) => s,
            Err(e) => return internal_err(e),
        };
    let rows = match stmt.query_map([], |row| {
        Ok(json!({
            "id": row.get::<_, i64>(0)?,
            "username": row.get::<_, String>(1)?,
            "role": row.get::<_, String>(2)?,
            "created_at": row.get::<_, String>(3)?,
        }))
    }) {
        Ok(r) => r,
        Err(e) => return internal_err(e),
    };
    let users: Vec<Value> = rows.filter_map(|r| r.ok()).collect();

    (StatusCode::OK, Json(json!({ "users": users })))
}

async fn users_create(
    auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if auth.user.role != "admin" {
        return err_response(StatusCode::FORBIDDEN, anyhow::anyhow!("admin only"));
    }

    let username = match body.get("username").and_then(|v| v.as_str()) {
        Some(u) if !u.is_empty() && u.len() <= 64 => u,
        _ => {
            return err_response(
                StatusCode::BAD_REQUEST,
                anyhow::anyhow!("username required (1-64 chars)"),
            );
        }
    };
    let password = match body.get("password").and_then(|v| v.as_str()) {
        Some(p) if p.len() >= 8 => p,
        _ => {
            return err_response(
                StatusCode::BAD_REQUEST,
                anyhow::anyhow!("password required (min 8 chars)"),
            );
        }
    };
    let role = body.get("role").and_then(|v| v.as_str()).unwrap_or("admin");
    if !VALID_ROLES.contains(&role) {
        return err_response(StatusCode::BAD_REQUEST, anyhow::anyhow!("invalid role"));
    }

    let password_hash = match auth::hash_password(password) {
        Ok(h) => h,
        Err(e) => return internal_err(e),
    };

    match auth::create_user(&db, username, &password_hash, role).await {
        Ok(id) => (
            StatusCode::CREATED,
            Json(json!({ "id": id, "username": username, "role": role })),
        ),
        Err(e) => {
            if e.to_string().contains("UNIQUE") {
                err_response(
                    StatusCode::CONFLICT,
                    anyhow::anyhow!("username already exists"),
                )
            } else {
                internal_err(e)
            }
        }
    }
}

async fn users_update(
    auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if auth.user.role != "admin" {
        return err_response(StatusCode::FORBIDDEN, anyhow::anyhow!("admin only"));
    }

    let conn = db.lock().await;

    // Build dynamic UPDATE
    let mut sets = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(role) = body.get("role").and_then(|v| v.as_str()) {
        if !VALID_ROLES.contains(&role) {
            return err_response(StatusCode::BAD_REQUEST, anyhow::anyhow!("invalid role"));
        }
        // Prevent demoting last admin
        if role != "admin" && id == auth.user.id {
            let admin_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM users WHERE role = 'admin'", [], |r| {
                    r.get(0)
                })
                .unwrap_or(0);
            if admin_count <= 1 {
                return err_response(
                    StatusCode::BAD_REQUEST,
                    anyhow::anyhow!("cannot demote the last admin"),
                );
            }
        }
        sets.push(format!("role = ?{}", params.len() + 1));
        params.push(Box::new(role.to_string()));
    }

    if let Some(username) = body.get("username").and_then(|v| v.as_str()) {
        if username.is_empty() || username.len() > 64 {
            return err_response(
                StatusCode::BAD_REQUEST,
                anyhow::anyhow!("username must be 1-64 chars"),
            );
        }
        sets.push(format!("username = ?{}", params.len() + 1));
        params.push(Box::new(username.to_string()));
    }

    if sets.is_empty() {
        return err_response(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!("nothing to update"),
        );
    }

    params.push(Box::new(id));
    let sql = format!(
        "UPDATE users SET {} WHERE id = ?{}",
        sets.join(", "),
        params.len()
    );
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();

    match conn.execute(&sql, param_refs.as_slice()) {
        Ok(0) => err_response(StatusCode::NOT_FOUND, anyhow::anyhow!("user not found")),
        Ok(_) => (StatusCode::OK, Json(json!({ "ok": true }))),
        Err(e) => {
            if e.to_string().contains("UNIQUE") {
                err_response(
                    StatusCode::CONFLICT,
                    anyhow::anyhow!("username already exists"),
                )
            } else {
                internal_err(e)
            }
        }
    }
}

async fn users_delete(
    auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if auth.user.role != "admin" {
        return err_response(StatusCode::FORBIDDEN, anyhow::anyhow!("admin only"));
    }

    // Cannot delete yourself
    if id == auth.user.id {
        return err_response(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!("cannot delete your own account"),
        );
    }

    let conn = db.lock().await;

    // Prevent deleting last admin
    let target_role: String = match conn.query_row(
        "SELECT role FROM users WHERE id = ?1",
        rusqlite::params![id],
        |r| r.get(0),
    ) {
        Ok(r) => r,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return err_response(StatusCode::NOT_FOUND, anyhow::anyhow!("user not found"));
        }
        Err(e) => return internal_err(e),
    };

    if target_role == "admin" {
        let admin_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM users WHERE role = 'admin'", [], |r| {
                r.get(0)
            })
            .unwrap_or(0);
        if admin_count <= 1 {
            return err_response(
                StatusCode::BAD_REQUEST,
                anyhow::anyhow!("cannot delete the last admin"),
            );
        }
    }

    // Delete sessions for this user first
    let _ = conn.execute(
        "DELETE FROM sessions WHERE user_id = ?1",
        rusqlite::params![id],
    );

    match conn.execute("DELETE FROM users WHERE id = ?1", rusqlite::params![id]) {
        Ok(0) => err_response(StatusCode::NOT_FOUND, anyhow::anyhow!("user not found")),
        Ok(_) => (StatusCode::OK, Json(json!({ "ok": true }))),
        Err(e) => internal_err(e),
    }
}

async fn users_change_password(
    auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // Admins can change any password; non-admins can only change their own
    if auth.user.role != "admin" && auth.user.id != id {
        return err_response(StatusCode::FORBIDDEN, anyhow::anyhow!("forbidden"));
    }

    let new_password = match body.get("password").and_then(|v| v.as_str()) {
        Some(p) if p.len() >= 8 => p,
        _ => {
            return err_response(
                StatusCode::BAD_REQUEST,
                anyhow::anyhow!("password required (min 8 chars)"),
            );
        }
    };

    let password_hash = match auth::hash_password(new_password) {
        Ok(h) => h,
        Err(e) => return internal_err(e),
    };

    let conn = db.lock().await;

    // Invalidate all existing sessions for this user (force re-login)
    let _ = conn.execute(
        "DELETE FROM sessions WHERE user_id = ?1",
        rusqlite::params![id],
    );

    match conn.execute(
        "UPDATE users SET password_hash = ?1 WHERE id = ?2",
        rusqlite::params![password_hash, id],
    ) {
        Ok(0) => err_response(StatusCode::NOT_FOUND, anyhow::anyhow!("user not found")),
        Ok(_) => (StatusCode::OK, Json(json!({ "ok": true }))),
        Err(e) => internal_err(e),
    }
}

// ===========================================================================
// Port config handlers — /api/v1/ports/{name}
// ===========================================================================

/// Reject port names that could be used for path traversal or injection.
///
/// This is defense-in-depth: queries are parameterized so SQL injection is not
/// possible, but we still reject clearly malformed names before touching the DB.
fn is_valid_port_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('.')
        && !name.contains('/')
        && !name.contains('\\')
}

/// GET /api/v1/ports/{name}
///
/// Returns pvid and tagged_vlans for a specific port. No `role` field.
async fn port_get_handler(
    _auth: AuthUser,
    Path(name): Path<String>,
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    if !is_valid_port_name(&name) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "invalid port name" })),
        );
    }

    let conn = db.lock().await;
    let result = conn.query_row(
        "SELECT name, mac, ips, mtu, is_up, pvid, tagged_vlans, enabled FROM interfaces WHERE name = ?1",
        rusqlite::params![name],
        |row| {
            let n: String = row.get(0)?;
            let mac: String = row.get(1)?;
            let ips_json: String = row.get(2)?;
            let mtu: i64 = row.get(3)?;
            let is_up: bool = row.get(4)?;
            let pvid: i64 = row.get(5)?;
            let tagged_json: String = row.get(6)?;
            let enabled: bool = row.get(7)?;
            Ok((n, mac, ips_json, mtu, is_up, pvid, tagged_json, enabled))
        },
    );

    match result {
        Ok((n, mac, ips_json, mtu, is_up, pvid, tagged_json, enabled)) => {
            let ips: Value = serde_json::from_str(&ips_json).unwrap_or(Value::Array(vec![]));
            let tagged_vlans: Value =
                serde_json::from_str(&tagged_json).unwrap_or(Value::Array(vec![]));
            let port_info = detect_port_type(&n);
            tracing::info!(port = %n, pvid, "port config retrieved");
            (
                StatusCode::OK,
                Json(json!({
                    "name": n,
                    "mac": mac,
                    "ips": ips,
                    "mtu": mtu,
                    "is_up": is_up,
                    "pvid": pvid,
                    "tagged_vlans": tagged_vlans,
                    "enabled": enabled,
                    "speed": port_info.0,
                    "driver": port_info.1,
                    "port_type": port_info.2,
                })),
            )
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "port not found" })),
        ),
        Err(e) => {
            tracing::error!("port_get_handler db error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
            )
        }
    }
}

/// PUT /api/v1/ports/{name}
///
/// Accepts `pvid` (0 or 1–4094) and `tagged_vlans` (array of 1–4094).
/// After persisting to DB triggers live switch + firewall reconfiguration.
/// If reconfiguration fails the DB write is preserved (source of truth) and
/// the error is logged; the endpoint still returns 200.
async fn port_update_handler(
    _auth: AuthUser,
    Path(name): Path<String>,
    Extension(db): Extension<sfgw_db::Db>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if !is_valid_port_name(&name) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "invalid port name" })),
        );
    }

    // Validate input before acquiring the lock
    let pvid_opt = if let Some(pvid_val) = body.get("pvid") {
        match pvid_val.as_i64() {
            Some(p) if p == 0 || (1..=4094).contains(&p) => Some(p),
            _ => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "pvid must be 0 (WAN) or 1-4094" })),
                );
            }
        }
    } else {
        None
    };

    let tagged_opt = if let Some(tagged_val) = body.get("tagged_vlans") {
        match tagged_val.as_array() {
            Some(arr) => {
                for v in arr {
                    match v.as_i64() {
                        Some(id) if (1..=4094).contains(&id) => {}
                        Some(_) => {
                            return (
                                StatusCode::UNPROCESSABLE_ENTITY,
                                Json(json!({ "error": "tagged VLAN IDs must be 1-4094" })),
                            );
                        }
                        None => {
                            return (
                                StatusCode::UNPROCESSABLE_ENTITY,
                                Json(json!({ "error": "tagged_vlans must be an array of integers" })),
                            );
                        }
                    }
                }
                Some(arr.clone())
            }
            None => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "tagged_vlans must be an array" })),
                );
            }
        }
    } else {
        None
    };

    if pvid_opt.is_none() && tagged_opt.is_none() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "provide pvid and/or tagged_vlans" })),
        );
    }

    // Persist to DB
    {
        let conn = db.lock().await;

        let mut sets = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(pvid) = pvid_opt {
            sets.push("pvid = ?");
            params.push(Box::new(pvid));
        }
        if let Some(tagged) = tagged_opt {
            let json_str = serde_json::to_string(&tagged).unwrap_or_else(|_| "[]".to_string());
            sets.push("tagged_vlans = ?");
            params.push(Box::new(json_str));
        }

        let sql = format!("UPDATE interfaces SET {} WHERE name = ?", sets.join(", "));
        params.push(Box::new(name.clone()));

        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        match conn.execute(&sql, param_refs.as_slice()) {
            Ok(0) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "port not found" })),
                );
            }
            Ok(_) => {
                tracing::info!(port = %name, "port VLAN config updated");
            }
            Err(e) => {
                tracing::error!("port_update_handler db error: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "internal server error" })),
                );
            }
        }
        // DB lock dropped here — must release before calling reconfigure_networks
    }

    // Trigger live reconfiguration.
    // Both reconfigure_networks and apply_rules acquire their own DB locks,
    // so the lock above must be dropped first (done by the block above).
    // Failures are logged but do not prevent returning 200: DB is source of truth;
    // the ASIC and firewall will be brought in sync on next boot.
    if let Err(e) = sfgw_net::switch::reconfigure_networks(&db).await {
        tracing::warn!(port = %name, "switch reconfiguration failed after port update: {e}");
    }
    if let Err(e) = sfgw_fw::apply_rules(&db).await {
        tracing::warn!(port = %name, "firewall reapply failed after port update: {e}");
    }

    (StatusCode::OK, Json(json!({ "ok": true })))
}

// ===========================================================================
// Zone handlers — /api/v1/zones
// ===========================================================================

/// GET /api/v1/zones
///
/// Returns all network zones with their VLAN IDs, ordered by zone name.
async fn zones_list_handler(
    _auth: AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    let conn = db.lock().await;
    let mut stmt = match conn.prepare(
        "SELECT id, name, zone, vlan_id, subnet, gateway, dhcp_enabled, enabled \
         FROM networks ORDER BY zone",
    ) {
        Ok(s) => s,
        Err(e) => return internal_err(anyhow::anyhow!("{e}")),
    };

    let rows: Vec<Value> = match stmt.query_map([], |row| {
        Ok(json!({
            "id": row.get::<_, i64>(0)?,
            "name": row.get::<_, String>(1)?,
            "zone": row.get::<_, String>(2)?,
            "vlan_id": row.get::<_, Option<i64>>(3)?,
            "subnet": row.get::<_, Option<String>>(4)?,
            "gateway": row.get::<_, Option<String>>(5)?,
            "dhcp_enabled": row.get::<_, bool>(6)?,
            "enabled": row.get::<_, bool>(7)?,
        }))
    }) {
        Ok(mapped) => mapped.filter_map(|r| r.ok()).collect(),
        Err(e) => return internal_err(anyhow::anyhow!("{e}")),
    };

    (StatusCode::OK, Json(json!({ "zones": rows })))
}

/// GET /api/v1/zones/{zone}
///
/// Returns a specific zone with its VLAN ID and names of interfaces whose
/// PVID matches the zone's VLAN ID.
async fn zone_get_handler(
    _auth: AuthUser,
    Path(zone_name): Path<String>,
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    let conn = db.lock().await;

    // Fetch the zone
    let zone_result = conn.query_row(
        "SELECT id, name, zone, vlan_id, subnet, gateway, dhcp_enabled, enabled \
         FROM networks WHERE zone = ?1",
        rusqlite::params![zone_name],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, bool>(6)?,
                row.get::<_, bool>(7)?,
            ))
        },
    );

    let (id, name, zone, vlan_id, subnet, gateway, dhcp_enabled, enabled) = match zone_result {
        Ok(row) => row,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "zone not found" })),
            );
        }
        Err(e) => {
            tracing::error!("zone_get_handler db error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
            );
        }
    };

    // Find interfaces with pvid matching this zone's vlan_id
    let interfaces: Vec<String> = if let Some(vid) = vlan_id {
        let mut stmt = match conn.prepare(
            "SELECT name FROM interfaces WHERE pvid = ?1 ORDER BY name",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("zone_get_handler interface query prepare error: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "internal server error" })),
                );
            }
        };
        match stmt.query_map(rusqlite::params![vid], |row| row.get::<_, String>(0)) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                tracing::error!("zone_get_handler interface query error: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "internal server error" })),
                );
            }
        }
    } else {
        vec![]
    };

    tracing::info!(zone = %zone, vlan_id = ?vlan_id, "zone config retrieved");
    (
        StatusCode::OK,
        Json(json!({
            "id": id,
            "name": name,
            "zone": zone,
            "vlan_id": vlan_id,
            "subnet": subnet,
            "gateway": gateway,
            "dhcp_enabled": dhcp_enabled,
            "enabled": enabled,
            "interfaces": interfaces,
        })),
    )
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> sfgw_db::Db {
        sfgw_db::open_in_memory()
            .await
            .expect("failed to open in-memory db")
    }

    // ── Port GET query shape ──────────────────────────────────────────

    /// Test that the port GET query returns correct pvid and tagged_vlans.
    #[tokio::test]
    async fn test_port_get_query_shape() {
        let db = test_db().await;
        {
            let conn = db.lock().await;
            conn.execute(
                "INSERT INTO interfaces (name, mac, ips, mtu, is_up, pvid, tagged_vlans, enabled)
                 VALUES ('eth1', '00:11:22:33:44:55', '[]', 1500, 1, 10, '[20,30]', 1)",
                [],
            )
            .expect("insert failed");
        }

        let conn = db.lock().await;
        let (pvid, tagged_json): (i64, String) = conn
            .query_row(
                "SELECT pvid, tagged_vlans FROM interfaces WHERE name = ?1",
                rusqlite::params!["eth1"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("query failed");

        assert_eq!(pvid, 10, "pvid must be 10");
        let tagged: Vec<i64> = serde_json::from_str(&tagged_json).expect("json parse failed");
        assert_eq!(tagged, vec![20, 30], "tagged_vlans must be [20,30]");
    }

    // ── Port PUT persists pvid and tagged_vlans ───────────────────────

    /// Test that a port UPDATE correctly persists pvid and tagged_vlans.
    #[tokio::test]
    async fn test_port_update_persists_vlan_config() {
        let db = test_db().await;
        {
            let conn = db.lock().await;
            conn.execute(
                "INSERT INTO interfaces (name, mac, ips, mtu, is_up, pvid, tagged_vlans, enabled)
                 VALUES ('eth2', '00:aa:bb:cc:dd:ee', '[]', 1500, 1, 10, '[]', 1)",
                [],
            )
            .expect("insert failed");
        }

        // Execute the same UPDATE logic as port_update_handler
        {
            let conn = db.lock().await;
            let tagged_json = serde_json::to_string(&[10i64, 20]).unwrap();
            conn.execute(
                "UPDATE interfaces SET pvid = ?1, tagged_vlans = ?2 WHERE name = ?3",
                rusqlite::params![3001i64, tagged_json, "eth2"],
            )
            .expect("update failed");
        }

        // Re-query and verify
        let conn = db.lock().await;
        let (pvid, tagged_json): (i64, String) = conn
            .query_row(
                "SELECT pvid, tagged_vlans FROM interfaces WHERE name = ?1",
                rusqlite::params!["eth2"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("re-query failed");

        assert_eq!(pvid, 3001, "pvid must be 3001 after update");
        let tagged: Vec<i64> = serde_json::from_str(&tagged_json).expect("json parse failed");
        assert_eq!(tagged, vec![10, 20], "tagged_vlans must be [10,20] after update");
    }

    // ── Port PUT validation ───────────────────────────────────────────

    /// Test that pvid=5000 is rejected as out of range.
    #[test]
    fn test_port_update_rejects_invalid_pvid_high() {
        let pvid: i64 = 5000;
        let valid = pvid == 0 || (1..=4094).contains(&pvid);
        assert!(!valid, "pvid=5000 must be rejected");
    }

    /// Test that pvid=-1 is rejected as out of range.
    #[test]
    fn test_port_update_rejects_invalid_pvid_negative() {
        let pvid: i64 = -1;
        let valid = pvid == 0 || (1..=4094).contains(&pvid);
        assert!(!valid, "pvid=-1 must be rejected");
    }

    // ── Zones query returns vlan_id ───────────────────────────────────

    /// Test that the zones list query returns zones with their vlan_id.
    #[tokio::test]
    async fn test_zones_query_returns_vlan_id() {
        let db = test_db().await;
        // After migrations, void zone (vlan_id=1) exists.
        // Add a LAN zone with vlan_id=10.
        {
            let conn = db.lock().await;
            conn.execute(
                "INSERT INTO networks (name, zone, vlan_id, subnet, gateway, dhcp_enabled, enabled)
                 VALUES ('LAN', 'lan', 10, '192.168.1.0/24', '192.168.1.1', 1, 1)",
                [],
            )
            .expect("insert LAN failed");
        }

        let conn = db.lock().await;
        let mut stmt = conn
            .prepare("SELECT zone, vlan_id FROM networks ORDER BY zone")
            .expect("prepare failed");
        let rows: Vec<(String, Option<i64>)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query failed")
            .filter_map(|r| r.ok())
            .collect();

        // void zone must have vlan_id=1
        let void_row = rows.iter().find(|(z, _)| z == "void");
        assert!(void_row.is_some(), "void zone must exist");
        assert_eq!(void_row.unwrap().1, Some(1), "void must have vlan_id=1");

        // lan zone must have vlan_id=10
        let lan_row = rows.iter().find(|(z, _)| z == "lan");
        assert!(lan_row.is_some(), "lan zone must exist");
        assert_eq!(lan_row.unwrap().1, Some(10), "lan must have vlan_id=10");
    }

    // ── Zone GET returns associated interfaces ────────────────────────

    /// Test that interfaces with matching pvid are returned for a zone.
    #[tokio::test]
    async fn test_zone_get_returns_associated_interfaces() {
        let db = test_db().await;

        {
            let conn = db.lock().await;

            // Insert a LAN network zone with vlan_id=10
            conn.execute(
                "INSERT INTO networks (name, zone, vlan_id, subnet, gateway, dhcp_enabled, enabled)
                 VALUES ('LAN', 'lan', 10, '192.168.1.0/24', '192.168.1.1', 1, 1)",
                [],
            )
            .expect("insert network failed");

            // eth1 and eth2 on VLAN 10, eth3 on VLAN 3000
            let ifaces: &[(&str, i64)] = &[("eth1", 10), ("eth2", 10), ("eth3", 3000)];
            for (name, pvid) in ifaces {
                conn.execute(
                    "INSERT INTO interfaces (name, mac, ips, mtu, is_up, pvid, tagged_vlans, enabled)
                     VALUES (?1, '00:00:00:00:00:00', '[]', 1500, 1, ?2, '[]', 1)",
                    rusqlite::params![name, pvid],
                )
                .expect("insert interface failed");
            }
        }

        // Query interfaces with pvid matching LAN's vlan_id=10
        let conn = db.lock().await;
        let vlan_id: i64 = conn
            .query_row(
                "SELECT vlan_id FROM networks WHERE zone = ?1",
                rusqlite::params!["lan"],
                |row| row.get(0),
            )
            .expect("zone query failed");

        let mut stmt = conn
            .prepare("SELECT name FROM interfaces WHERE pvid = ?1 ORDER BY name")
            .expect("prepare failed");
        let iface_names: Vec<String> = stmt
            .query_map(rusqlite::params![vlan_id], |row| row.get(0))
            .expect("query failed")
            .filter_map(|r| r.ok())
            .collect();

        assert_eq!(iface_names, vec!["eth1", "eth2"], "only eth1 and eth2 should be in LAN zone");
        assert!(!iface_names.contains(&"eth3".to_string()), "eth3 must not be in LAN zone");
    }

    // ── Port name validation ──────────────────────────────────────────

    #[test]
    fn test_is_valid_port_name() {
        assert!(is_valid_port_name("eth0"));
        assert!(is_valid_port_name("eth7"));
        assert!(is_valid_port_name("wg0"));
        // Reject path traversal characters
        assert!(!is_valid_port_name("eth0.10"));
        assert!(!is_valid_port_name("../etc"));
        assert!(!is_valid_port_name("foo/bar"));
        assert!(!is_valid_port_name("foo\\bar"));
        // Reject empty
        assert!(!is_valid_port_name(""));
    }
}
