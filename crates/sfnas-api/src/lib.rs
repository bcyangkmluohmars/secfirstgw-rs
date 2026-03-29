// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! # sfnas-api
//!
//! REST API server for secfirstNAS.
//!
//! Security stack:
//! - TLS 1.3 only (AES-256-GCM-SHA384 + ChaCha20-Poly1305)
//! - E2EE envelope encryption (hybrid X25519 + ML-KEM-1024 + AES-256-GCM)
//! - Argon2id password hashing with constant-time verification
//! - Session binding (token + IP + User-Agent fingerprint)
//! - Per-IP rate limiting (auth: 10/min, general: 120/min, critical: 5/min)
//!
//! Route tiers:
//! - **Public** (no auth): /auth/session, /auth/login, /auth/setup
//! - **Protected** (auth + E2EE): status, storage, shares, users, system
//! - **Critical** (auth + E2EE + strict rate limit): reboot, shutdown, array create/delete

pub mod auth;
pub mod e2ee;
mod error;
pub mod middleware;
pub mod ratelimit;
pub mod routes;
pub mod tls;

use axum::http::{HeaderName, Method};
use axum::{Extension, Router};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

pub use error::ApiError;

/// Application state shared across all route handlers.
#[derive(Clone)]
pub struct AppState {
    /// Background-refreshed SMART disk cache.
    pub disk_cache: sfnas_storage::DiskCache,
    /// Database handle for auth, sessions, and config.
    pub db: sfgw_db::Db,
    /// LED service handle — kept alive so the background thread isn't stopped.
    _led_service: Option<Arc<sfnas_storage::LedService>>,
}

/// Build the full axum application with all routes, middleware, and security layers.
pub fn build_app(db: &sfgw_db::Db, static_dir: Option<&Path>) -> Router {
    info!("building router: initializing disk cache...");
    let disk_cache = sfnas_storage::DiskCache::new();
    info!("building router: disk cache ready, starting background refresh...");
    disk_cache.start_background_refresh();

    let led_service = sfnas_storage::LedService::start(disk_cache.clone()).map(Arc::new);

    // Keep LED service alive for the server's lifetime via Extension.
    let led_handle: Option<Arc<sfnas_storage::LedService>> = led_service;

    // E2EE stores (in-memory only — never persisted)
    let negotiate_store = e2ee::new_negotiate_store();
    let envelope_key_store = e2ee::new_envelope_key_store();

    // OAuth state store (in-memory, short-lived PKCE + CSRF state)
    let oauth_state_store = routes::oauth::new_oauth_state_store();

    // ----- Rate limiters (per-IP, different tiers) -----
    let auth_limiter = ratelimit::RateLimiter::new(10, Duration::from_secs(60));
    let general_limiter = ratelimit::RateLimiter::new(120, Duration::from_secs(60));
    let critical_limiter = ratelimit::RateLimiter::new(5, Duration::from_secs(60));

    // ----- Public routes (no auth, strict 10/min) -----
    let public_routes = routes::auth::public_router()
        .merge(routes::oauth::public_router())
        .layer(axum::middleware::from_fn_with_state(
            auth_limiter,
            ratelimit::rate_limit_middleware,
        ));

    // ----- Critical routes (auth + E2EE + 5/min) -----
    let critical_routes = Router::new()
        .merge(routes::system::critical_router())
        .merge(routes::storage::critical_router())
        .merge(routes::ad::critical_router())
        .layer(axum::middleware::from_fn(e2ee::e2ee_layer))
        .layer(axum::middleware::from_fn(middleware::require_auth))
        .layer(axum::middleware::from_fn_with_state(
            critical_limiter,
            ratelimit::rate_limit_middleware,
        ));

    // ----- Protected routes (auth + E2EE + 120/min) -----
    let protected_routes = Router::new()
        .merge(routes::auth::protected_router())
        .merge(routes::status::router())
        .merge(routes::storage::router())
        .merge(routes::shares::router())
        .merge(routes::users::router())
        .merge(routes::system::router())
        .merge(routes::ad::router())
        .merge(routes::oauth::protected_router())
        .layer(axum::middleware::from_fn(e2ee::e2ee_layer))
        .layer(axum::middleware::from_fn(middleware::require_auth))
        .layer(axum::middleware::from_fn_with_state(
            general_limiter,
            ratelimit::rate_limit_middleware,
        ));

    // ----- CORS -----
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::any())
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            HeaderName::from_static("x-sfgw-e2ee"),
        ])
        .allow_credentials(false);

    let mut app = Router::new()
        .nest("/api/v1", public_routes)
        .nest("/api/v1", critical_routes)
        .nest("/api/v1", protected_routes);

    // Serve static files for the web-nas SPA if the directory exists
    if let Some(dir) = static_dir
        && dir.is_dir()
    {
        app = app.fallback_service(
            tower_http::services::ServeDir::new(dir)
                .fallback(tower_http::services::ServeFile::new(dir.join("index.html"))),
        );
        info!(path = %dir.display(), "serving static files for web-nas");
    }

    app.layer(cors)
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .layer(Extension(db.clone()))
        .layer(Extension(disk_cache))
        .layer(Extension(negotiate_store))
        .layer(Extension(envelope_key_store))
        .layer(Extension(led_handle))
        .layer(Extension(oauth_state_store))
        .layer(TraceLayer::new_for_http())
}

/// Start the API server over TLS 1.3.
///
/// Also spawns an HTTP :80 → HTTPS redirect listener.
pub async fn serve(
    db: &sfgw_db::Db,
    bind_addr: SocketAddr,
    static_dir: Option<&Path>,
) -> Result<(), ApiError> {
    let app = build_app(db, static_dir);

    // HTTP → HTTPS redirect
    let https_port = bind_addr.port();
    let redirect_addr = SocketAddr::new(bind_addr.ip(), 80);
    tokio::spawn(async move {
        if let Err(e) = serve_http_redirect(redirect_addr, https_port).await {
            tracing::warn!("HTTP redirect listener failed: {e}");
        }
    });

    // TLS 1.3 configuration
    let tls_config = tls::load_or_create_tls_config()
        .map_err(|e| ApiError::Server(format!("TLS configuration failed: {e}")))?;
    let rustls_config = tls::into_axum_rustls_config(tls_config)
        .await
        .map_err(|e| ApiError::Server(format!("TLS setup failed: {e}")))?;

    info!(%bind_addr, "secfirstNAS API server starting (TLS 1.3)");

    axum_server::bind_rustls(bind_addr, rustls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| ApiError::Server(format!("server error: {e}")))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP → HTTPS redirect
// ---------------------------------------------------------------------------

async fn serve_http_redirect(addr: SocketAddr, https_port: u16) -> Result<(), std::io::Error> {
    use axum::response::Redirect;

    let app = Router::new().fallback(
        move |req: axum::http::Request<axum::body::Body>| async move {
            let host = req
                .headers()
                .get(axum::http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("localhost");
            let host_no_port = host.split(':').next().unwrap_or(host);
            let path_and_query = req
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            let https_uri = if https_port == 443 {
                format!("https://{host_no_port}{path_and_query}")
            } else {
                format!("https://{host_no_port}:{https_port}{path_and_query}")
            };
            Redirect::permanent(&https_uri)
        },
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("HTTP→HTTPS redirect listening on {addr}");
    axum::serve(listener, app).await
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

async fn security_headers_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
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
        HeaderValue::from_static("default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"),
    );
    headers.insert(
        axum::http::header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    );
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );

    response
}
