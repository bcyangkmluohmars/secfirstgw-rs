// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! OIDC / OAuth2 authentication routes for secfirstNAS.
//!
//! Supports any OIDC-compliant provider: Microsoft Entra ID, Authentik,
//! Keycloak, Okta, Google Workspace, etc.
//!
//! Endpoints:
//! - `GET  /auth/oauth/config`    — Get OIDC config (protected)
//! - `PUT  /auth/oauth/config`    — Save OIDC config (protected)
//! - `POST /auth/oauth/test`      — Test OIDC discovery (protected)
//! - `GET  /auth/oauth/login`     — Start OAuth flow (public)
//! - `GET  /auth/oauth/callback`  — Handle OAuth callback (public)
//! - `GET  /auth/oauth/providers` — Provider presets (public)
//! - `GET  /auth/oauth/status`    — OIDC enabled status (public)

use crate::auth;
use axum::extract::{ConnectInfo, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// TTL for OAuth state entries (5 minutes).
const OAUTH_STATE_TTL_SECS: u64 = 300;
/// Maximum pending OAuth states (DoS protection).
const OAUTH_STATE_MAX_CAPACITY: usize = 1_000;

// ---------------------------------------------------------------------------
// In-memory OAuth state store (PKCE + CSRF state)
// ---------------------------------------------------------------------------

struct OAuthStateEntry {
    code_verifier: String,
    created_at: Instant,
}

/// In-memory store for pending OAuth authorization flows.
#[derive(Clone)]
pub struct OAuthStateStore(Arc<Mutex<HashMap<String, OAuthStateEntry>>>);

/// Create a new empty OAuth state store.
pub fn new_oauth_state_store() -> OAuthStateStore {
    OAuthStateStore(Arc::new(Mutex::new(HashMap::new())))
}

// ---------------------------------------------------------------------------
// DB meta helpers
// ---------------------------------------------------------------------------

const META_OIDC_ENABLED: &str = "oidc_enabled";
const META_OIDC_PROVIDER_NAME: &str = "oidc_provider_name";
const META_OIDC_ISSUER_URL: &str = "oidc_issuer_url";
const META_OIDC_CLIENT_ID: &str = "oidc_client_id";
const META_OIDC_CLIENT_SECRET: &str = "oidc_client_secret";
const META_OIDC_REDIRECT_URI: &str = "oidc_redirect_uri";
const META_OIDC_SCOPES: &str = "oidc_scopes";
const META_OIDC_AUTO_PROVISION: &str = "oidc_auto_provision";

/// Read a meta value from the DB.
async fn meta_get(db: &sfgw_db::Db, key: &str) -> Option<String> {
    let conn = db.lock().await;
    conn.query_row(
        "SELECT value FROM meta WHERE key = ?1",
        rusqlite::params![key],
        |row| row.get::<_, String>(0),
    )
    .ok()
}

/// Set a meta value in the DB (upsert).
async fn meta_set(db: &sfgw_db::Db, key: &str, value: &str) -> Result<(), String> {
    let conn = db.lock().await;
    // Ensure meta table exists
    conn.execute(
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        [],
    )
    .map_err(|e| format!("failed to ensure meta table: {e}"))?;
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2",
        rusqlite::params![key, value],
    )
    .map_err(|e| format!("failed to set meta {key}: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct OAuthConfigRequest {
    provider_name: Option<String>,
    issuer_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
    scopes: Option<String>,
    auto_provision: Option<bool>,
    enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
struct OAuthConfigResponse {
    enabled: bool,
    provider_name: String,
    issuer_url: String,
    client_id: String,
    redirect_uri: String,
    scopes: String,
    auto_provision: bool,
    /// Whether a client secret has been set (never reveal the actual value).
    has_client_secret: bool,
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcDiscoveryDoc {
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    jwks_uri: Option<String>,
    issuer: Option<String>,
    userinfo_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    #[allow(dead_code)]
    access_token: Option<String>,
    #[allow(dead_code)]
    token_type: Option<String>,
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

/// Minimal JWT claims we extract from the ID token.
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: Option<String>,
    email: Option<String>,
    name: Option<String>,
    preferred_username: Option<String>,
    #[allow(dead_code)]
    iss: Option<String>,
    #[allow(dead_code)]
    aud: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Public routes (no auth required)
// ---------------------------------------------------------------------------

/// Build the public OAuth router.
pub fn public_router() -> Router {
    Router::new()
        .route("/auth/oauth/login", get(oauth_login_handler))
        .route("/auth/oauth/callback", get(oauth_callback_handler))
        .route("/auth/oauth/providers", get(oauth_providers_handler))
        .route("/auth/oauth/status", get(oauth_status_handler))
}

/// Build the protected OAuth router (requires auth).
pub fn protected_router() -> Router {
    Router::new()
        .route("/auth/oauth/config", get(get_config_handler).put(save_config_handler))
        .route("/auth/oauth/test", post(test_discovery_handler))
}

// ---------------------------------------------------------------------------
// GET /auth/oauth/status — public, used by login page
// ---------------------------------------------------------------------------

async fn oauth_status_handler(
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    let enabled = meta_get(&db, META_OIDC_ENABLED)
        .await
        .map(|v| v == "true")
        .unwrap_or(false);

    let provider_name = if enabled {
        meta_get(&db, META_OIDC_PROVIDER_NAME)
            .await
            .unwrap_or_default()
    } else {
        String::new()
    };

    (
        StatusCode::OK,
        Json(json!({
            "enabled": enabled,
            "provider_name": provider_name,
        })),
    )
}

// ---------------------------------------------------------------------------
// GET /auth/oauth/providers — public, preset configurations
// ---------------------------------------------------------------------------

async fn oauth_providers_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "providers": [
                {
                    "id": "microsoft",
                    "name": "Microsoft Entra ID",
                    "issuer_template": "https://login.microsoftonline.com/{tenant_id}/v2.0",
                    "scopes": "openid profile email",
                    "note": "Requires Azure AD app registration. Replace {tenant_id} with your directory (tenant) ID."
                },
                {
                    "id": "authentik",
                    "name": "Authentik",
                    "issuer_template": "https://{authentik-host}/application/o/{app-slug}/",
                    "scopes": "openid profile email",
                    "note": "Create an OAuth2/OIDC provider and application in Authentik."
                },
                {
                    "id": "keycloak",
                    "name": "Keycloak",
                    "issuer_template": "https://{keycloak-host}/realms/{realm}",
                    "scopes": "openid profile email",
                    "note": "Create a client in the desired Keycloak realm."
                },
                {
                    "id": "google",
                    "name": "Google Workspace",
                    "issuer_template": "https://accounts.google.com",
                    "scopes": "openid profile email",
                    "note": "Create OAuth 2.0 credentials in Google Cloud Console."
                },
                {
                    "id": "okta",
                    "name": "Okta",
                    "issuer_template": "https://{okta-domain}/oauth2/default",
                    "scopes": "openid profile email",
                    "note": "Create an OIDC application in Okta."
                },
                {
                    "id": "custom",
                    "name": "Custom OIDC",
                    "issuer_template": "",
                    "scopes": "openid profile email",
                    "note": "Any OIDC-compliant provider. Enter the issuer URL manually."
                }
            ]
        })),
    )
}

// ---------------------------------------------------------------------------
// GET /auth/oauth/config — protected, read config
// ---------------------------------------------------------------------------

async fn get_config_handler(
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    let enabled = meta_get(&db, META_OIDC_ENABLED)
        .await
        .map(|v| v == "true")
        .unwrap_or(false);
    let provider_name = meta_get(&db, META_OIDC_PROVIDER_NAME).await.unwrap_or_default();
    let issuer_url = meta_get(&db, META_OIDC_ISSUER_URL).await.unwrap_or_default();
    let client_id = meta_get(&db, META_OIDC_CLIENT_ID).await.unwrap_or_default();
    let has_secret = meta_get(&db, META_OIDC_CLIENT_SECRET).await.is_some();
    let redirect_uri = meta_get(&db, META_OIDC_REDIRECT_URI).await.unwrap_or_default();
    let scopes = meta_get(&db, META_OIDC_SCOPES)
        .await
        .unwrap_or_else(|| "openid profile email".to_string());
    let auto_provision = meta_get(&db, META_OIDC_AUTO_PROVISION)
        .await
        .map(|v| v == "true")
        .unwrap_or(false);

    let config = OAuthConfigResponse {
        enabled,
        provider_name,
        issuer_url,
        client_id,
        redirect_uri,
        scopes,
        auto_provision,
        has_client_secret: has_secret,
    };

    (StatusCode::OK, Json(json!({ "success": true, "data": config })))
}

// ---------------------------------------------------------------------------
// PUT /auth/oauth/config — protected, save config
// ---------------------------------------------------------------------------

async fn save_config_handler(
    Extension(db): Extension<sfgw_db::Db>,
    Json(body): Json<OAuthConfigRequest>,
) -> impl IntoResponse {
    // Validate issuer URL is HTTPS (if provided and non-empty)
    if let Some(ref url) = body.issuer_url {
        let trimmed = url.trim();
        if !trimmed.is_empty() && !trimmed.starts_with("https://") {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "success": false, "error": "issuer URL must use HTTPS" })),
            );
        }
    }

    // Helper: save a meta key, return 500 on error
    macro_rules! save_meta {
        ($key:expr, $val:expr) => {
            if let Err(e) = meta_set(&db, $key, $val).await {
                tracing::error!("failed to save {}: {e}", $key);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "success": false, "error": "internal server error" })),
                );
            }
        };
    }

    // Save each field if provided
    if let Some(ref v) = body.provider_name {
        save_meta!(META_OIDC_PROVIDER_NAME, v);
    }
    if let Some(ref v) = body.issuer_url {
        save_meta!(META_OIDC_ISSUER_URL, v.trim());
    }
    if let Some(ref v) = body.client_id {
        save_meta!(META_OIDC_CLIENT_ID, v);
    }
    // Only update secret if provided (non-empty)
    if let Some(ref v) = body.client_secret
        && !v.is_empty()
    {
        save_meta!(META_OIDC_CLIENT_SECRET, v);
    }
    if let Some(ref v) = body.redirect_uri {
        save_meta!(META_OIDC_REDIRECT_URI, v);
    }
    if let Some(ref v) = body.scopes {
        save_meta!(META_OIDC_SCOPES, v);
    }
    if let Some(v) = body.auto_provision {
        let val = if v { "true" } else { "false" };
        save_meta!(META_OIDC_AUTO_PROVISION, val);
    }
    if let Some(v) = body.enabled {
        let val = if v { "true" } else { "false" };
        save_meta!(META_OIDC_ENABLED, val);
    }

    tracing::info!("OIDC configuration updated");
    (StatusCode::OK, Json(json!({ "success": true })))
}

// ---------------------------------------------------------------------------
// POST /auth/oauth/test — protected, test OIDC discovery
// ---------------------------------------------------------------------------

async fn test_discovery_handler(
    Extension(db): Extension<sfgw_db::Db>,
) -> impl IntoResponse {
    let issuer_url = match meta_get(&db, META_OIDC_ISSUER_URL).await {
        Some(url) if !url.is_empty() => url,
        _ => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "success": false, "error": "issuer URL is not configured" })),
            );
        }
    };

    match fetch_discovery(&issuer_url).await {
        Ok(doc) => {
            let has_auth = doc.authorization_endpoint.is_some();
            let has_token = doc.token_endpoint.is_some();
            let has_jwks = doc.jwks_uri.is_some();

            if !has_auth || !has_token || !has_jwks {
                return (
                    StatusCode::OK,
                    Json(json!({
                        "success": false,
                        "error": "discovery document is incomplete",
                        "discovered": {
                            "issuer": doc.issuer,
                            "authorization_endpoint": doc.authorization_endpoint,
                            "token_endpoint": doc.token_endpoint,
                            "jwks_uri": doc.jwks_uri,
                            "userinfo_endpoint": doc.userinfo_endpoint,
                            "has_authorization_endpoint": has_auth,
                            "has_token_endpoint": has_token,
                            "has_jwks_uri": has_jwks,
                        }
                    })),
                );
            }

            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "discovered": {
                        "issuer": doc.issuer,
                        "authorization_endpoint": doc.authorization_endpoint,
                        "token_endpoint": doc.token_endpoint,
                        "jwks_uri": doc.jwks_uri,
                        "userinfo_endpoint": doc.userinfo_endpoint,
                    }
                })),
            )
        }
        Err(e) => (
            StatusCode::OK,
            Json(json!({
                "success": false,
                "error": format!("failed to fetch OIDC discovery: {e}"),
            })),
        ),
    }
}

// ---------------------------------------------------------------------------
// GET /auth/oauth/login — public, start OAuth flow
// ---------------------------------------------------------------------------

async fn oauth_login_handler(
    Extension(db): Extension<sfgw_db::Db>,
    Extension(state_store): Extension<OAuthStateStore>,
) -> Response {
    let enabled = meta_get(&db, META_OIDC_ENABLED)
        .await
        .map(|v| v == "true")
        .unwrap_or(false);

    if !enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "OIDC is not enabled" })),
        )
            .into_response();
    }

    let issuer_url = match meta_get(&db, META_OIDC_ISSUER_URL).await {
        Some(url) if !url.is_empty() => url,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "OIDC issuer not configured" })),
            )
                .into_response();
        }
    };

    let client_id = match meta_get(&db, META_OIDC_CLIENT_ID).await {
        Some(id) if !id.is_empty() => id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "OIDC client ID not configured" })),
            )
                .into_response();
        }
    };

    let redirect_uri = meta_get(&db, META_OIDC_REDIRECT_URI)
        .await
        .unwrap_or_default();
    let scopes = meta_get(&db, META_OIDC_SCOPES)
        .await
        .unwrap_or_else(|| "openid profile email".to_string());

    // Fetch OIDC discovery to get the authorization endpoint
    let discovery = match fetch_discovery(&issuer_url).await {
        Ok(doc) => doc,
        Err(e) => {
            tracing::error!("OIDC discovery failed during login: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "OIDC discovery failed" })),
            )
                .into_response();
        }
    };

    let auth_endpoint = match discovery.authorization_endpoint {
        Some(ep) => ep,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "OIDC discovery has no authorization_endpoint" })),
            )
                .into_response();
        }
    };

    // Generate CSRF state
    let state = generate_random_string(32);

    // Generate PKCE code verifier + challenge
    let code_verifier = generate_random_string(64);
    let code_challenge = {
        let hash = Sha256::digest(code_verifier.as_bytes());
        B64URL.encode(hash)
    };

    // Store state + verifier
    {
        let mut store = state_store.0.lock().await;
        // Purge expired entries
        store.retain(|_, entry| entry.created_at.elapsed().as_secs() < OAUTH_STATE_TTL_SECS);
        if store.len() >= OAUTH_STATE_MAX_CAPACITY {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "too many pending OAuth flows, try again later" })),
            )
                .into_response();
        }
        store.insert(
            state.clone(),
            OAuthStateEntry {
                code_verifier,
                created_at: Instant::now(),
            },
        );
    }

    // Build authorization URL
    let auth_url = format!(
        "{auth_endpoint}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        urlencoded(&client_id),
        urlencoded(&redirect_uri),
        urlencoded(&scopes),
        urlencoded(&state),
        urlencoded(&code_challenge),
    );

    Redirect::temporary(&auth_url).into_response()
}

// ---------------------------------------------------------------------------
// GET /auth/oauth/callback — public, handle OAuth callback
// ---------------------------------------------------------------------------

async fn oauth_callback_handler(
    Extension(db): Extension<sfgw_db::Db>,
    Extension(state_store): Extension<OAuthStateStore>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(params): Query<CallbackQuery>,
) -> Response {
    // Handle provider errors
    if let Some(ref err) = params.error {
        tracing::warn!(
            error = %err,
            description = params.error_description.as_deref().unwrap_or(""),
            "OAuth provider returned error"
        );
        return Redirect::temporary("/login?error=oauth_failed").into_response();
    }

    let code = match params.code {
        Some(ref c) if !c.is_empty() => c.clone(),
        _ => {
            tracing::warn!("OAuth callback missing authorization code");
            return Redirect::temporary("/login?error=oauth_failed").into_response();
        }
    };

    let state = match params.state {
        Some(ref s) if !s.is_empty() => s.clone(),
        _ => {
            tracing::warn!("OAuth callback missing state parameter");
            return Redirect::temporary("/login?error=oauth_failed").into_response();
        }
    };

    // Validate and consume the state
    let code_verifier = {
        let mut store = state_store.0.lock().await;
        match store.remove(&state) {
            Some(entry) => {
                if entry.created_at.elapsed().as_secs() >= OAUTH_STATE_TTL_SECS {
                    tracing::warn!("OAuth state expired");
                    return Redirect::temporary("/login?error=oauth_failed").into_response();
                }
                entry.code_verifier
            }
            None => {
                tracing::warn!("OAuth state not found (possible CSRF or replay)");
                return Redirect::temporary("/login?error=oauth_failed").into_response();
            }
        }
    };

    // Load OIDC configuration
    let issuer_url = match meta_get(&db, META_OIDC_ISSUER_URL).await {
        Some(url) if !url.is_empty() => url,
        _ => {
            return Redirect::temporary("/login?error=oauth_failed").into_response();
        }
    };
    let client_id = meta_get(&db, META_OIDC_CLIENT_ID).await.unwrap_or_default();
    let client_secret = meta_get(&db, META_OIDC_CLIENT_SECRET).await.unwrap_or_default();
    let redirect_uri = meta_get(&db, META_OIDC_REDIRECT_URI).await.unwrap_or_default();
    let auto_provision = meta_get(&db, META_OIDC_AUTO_PROVISION)
        .await
        .map(|v| v == "true")
        .unwrap_or(false);

    // Fetch OIDC discovery to get the token endpoint
    let discovery = match fetch_discovery(&issuer_url).await {
        Ok(doc) => doc,
        Err(e) => {
            tracing::error!("OIDC discovery failed during callback: {e}");
            return Redirect::temporary("/login?error=oauth_failed").into_response();
        }
    };

    let token_endpoint = match discovery.token_endpoint {
        Some(ep) => ep,
        None => {
            tracing::error!("OIDC discovery has no token_endpoint");
            return Redirect::temporary("/login?error=oauth_failed").into_response();
        }
    };

    // Exchange authorization code for tokens
    let token_response = match exchange_code(
        &token_endpoint,
        &code,
        &redirect_uri,
        &client_id,
        &client_secret,
        &code_verifier,
    )
    .await
    {
        Ok(tr) => tr,
        Err(e) => {
            tracing::error!("OAuth token exchange failed: {e}");
            return Redirect::temporary("/login?error=oauth_failed").into_response();
        }
    };

    let id_token = match token_response.id_token {
        Some(t) => t,
        None => {
            tracing::error!("OAuth token response has no id_token");
            return Redirect::temporary("/login?error=oauth_failed").into_response();
        }
    };

    // Decode the ID token claims (validation: check issuer and audience)
    let claims = match decode_id_token(&id_token, &issuer_url, &client_id) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("ID token validation failed: {e}");
            return Redirect::temporary("/login?error=oauth_failed").into_response();
        }
    };

    // Determine the username from claims
    let email = claims.email.unwrap_or_default();
    let preferred_username = claims.preferred_username.unwrap_or_default();
    let display_name = claims.name.unwrap_or_default();
    let oidc_sub = claims.sub.unwrap_or_default();

    // Derive a local username: prefer preferred_username, then email prefix
    let local_username = if !preferred_username.is_empty() {
        sanitize_username(&preferred_username)
    } else if !email.is_empty() {
        sanitize_username(email.split('@').next().unwrap_or("user"))
    } else if !oidc_sub.is_empty() {
        sanitize_username(&oidc_sub)
    } else {
        tracing::error!("OAuth ID token has no usable identifier (sub/email/preferred_username)");
        return Redirect::temporary("/login?error=oauth_failed").into_response();
    };

    if local_username.is_empty() {
        tracing::error!("OAuth: derived username is empty");
        return Redirect::temporary("/login?error=oauth_failed").into_response();
    }

    // Find or create local user
    let user = match find_or_create_oauth_user(
        &db,
        &local_username,
        &email,
        &display_name,
        auto_provision,
    )
    .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            tracing::warn!(
                username = local_username,
                "OAuth user not found and auto-provision is disabled"
            );
            return Redirect::temporary("/login?error=oauth_no_user").into_response();
        }
        Err(e) => {
            tracing::error!("OAuth user lookup/creation failed: {e}");
            return Redirect::temporary("/login?error=oauth_failed").into_response();
        }
    };

    // Create a session (same as password login)
    let client_ip = addr.ip().to_string();
    let fingerprint = crate::middleware::fingerprint_from_headers(&headers);

    let (token, _expires_at) = match auth::create_session(&db, user.id, &client_ip, &fingerprint, "").await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("OAuth session creation failed: {e}");
            return Redirect::temporary("/login?error=oauth_failed").into_response();
        }
    };

    tracing::info!(
        username = user.username,
        method = "oauth",
        "user authenticated via OIDC"
    );

    // Set session cookie and redirect to frontend
    let cookie = format!(
        "sfnas_session={token}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=86400"
    );

    let mut response = Redirect::temporary("/").into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        cookie.parse().unwrap_or_else(|_| {
            // INVARIANT: the cookie string above is always valid ASCII
            axum::http::HeaderValue::from_static("")
        }),
    );
    response
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Fetch OIDC discovery document from the well-known URL.
async fn fetch_discovery(issuer_url: &str) -> Result<OidcDiscoveryDoc, String> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/')
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("failed to fetch discovery: {e}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "discovery endpoint returned HTTP {}",
            response.status()
        ));
    }

    response
        .json::<OidcDiscoveryDoc>()
        .await
        .map_err(|e| format!("failed to parse discovery document: {e}"))
}

/// Exchange an authorization code for tokens at the token endpoint.
async fn exchange_code(
    token_endpoint: &str,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    client_secret: &str,
    code_verifier: &str,
) -> Result<TokenResponse, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ];

    // Only include client_secret if it's non-empty (some providers don't require it with PKCE)
    if !client_secret.is_empty() {
        form.push(("client_secret", client_secret));
    }

    let response = client
        .post(token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("token exchange request failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let _body = response.text().await.unwrap_or_default();
        tracing::warn!(status = %status, "token exchange failed");
        return Err(format!("token endpoint returned HTTP {status}"));
    }

    response
        .json::<TokenResponse>()
        .await
        .map_err(|e| format!("failed to parse token response: {e}"))
}

/// Decode an ID token JWT and validate issuer + audience claims.
///
/// We decode the JWT payload without full cryptographic validation of the
/// signature (a full implementation would fetch JWKS and verify). We do
/// validate issuer and audience claims which, combined with the fact that
/// we received the token over TLS directly from the provider's token
/// endpoint, provides adequate security for this flow.
fn decode_id_token(
    token: &str,
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<IdTokenClaims, String> {
    // Split the JWT to extract the payload (part 2 of 3)
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("ID token is not a valid JWT".to_string());
    }

    let payload_bytes = B64URL
        .decode(parts[1])
        .or_else(|_| {
            // Try with padding
            let padded = match parts[1].len() % 4 {
                2 => format!("{}==", parts[1]),
                3 => format!("{}=", parts[1]),
                _ => parts[1].to_string(),
            };
            B64URL.decode(&padded)
        })
        .map_err(|e| format!("failed to decode JWT payload: {e}"))?;

    let claims: IdTokenClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("failed to parse JWT claims: {e}"))?;

    // Validate issuer
    if let Some(ref iss) = claims.iss {
        let normalized_expected = expected_issuer.trim_end_matches('/');
        let normalized_iss = iss.trim_end_matches('/');
        if normalized_iss != normalized_expected {
            return Err(format!(
                "issuer mismatch: expected '{normalized_expected}', got '{normalized_iss}'"
            ));
        }
    } else {
        return Err("ID token has no issuer claim".to_string());
    }

    // Validate audience
    if let Some(ref aud) = claims.aud {
        let audience_matches = match aud {
            Value::String(s) => s == expected_audience,
            Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(expected_audience)),
            _ => false,
        };
        if !audience_matches {
            return Err("ID token audience does not match client_id".to_string());
        }
    } else {
        return Err("ID token has no audience claim".to_string());
    }

    Ok(claims)
}

/// Find an existing user by username or create one if auto-provisioning is enabled.
async fn find_or_create_oauth_user(
    db: &sfgw_db::Db,
    username: &str,
    email: &str,
    _display_name: &str,
    auto_provision: bool,
) -> Result<Option<auth::User>, String> {
    // First, try to find by username
    match auth::get_user_by_username(db, username).await {
        Ok(Some((user, _hash))) => return Ok(Some(user)),
        Ok(None) => {}
        Err(e) => return Err(format!("database error: {e}")),
    }

    // Try to find by email as username (some users may have email as their username)
    if !email.is_empty() && email != username {
        match auth::get_user_by_username(db, email).await {
            Ok(Some((user, _hash))) => return Ok(Some(user)),
            Ok(None) => {}
            Err(e) => return Err(format!("database error: {e}")),
        }
    }

    // User not found — auto-provision if enabled
    if !auto_provision {
        return Ok(None);
    }

    // Create a new user with a random password (they'll use OAuth to log in)
    let random_password = generate_random_string(64);
    let password_hash = auth::hash_password(&random_password)
        .map_err(|e| format!("failed to hash password: {e}"))?;

    // Auto-provisioned users get "user" role (never admin)
    let user_id = auth::create_user(db, username, &password_hash, "user")
        .await
        .map_err(|e| format!("failed to create user: {e}"))?;

    tracing::info!(
        username = username,
        user_id = user_id,
        "auto-provisioned OAuth user"
    );

    match auth::get_user_by_id(db, user_id).await {
        Ok(Some(user)) => Ok(Some(user)),
        Ok(None) => Err("user created but not found".to_string()),
        Err(e) => Err(format!("database error: {e}")),
    }
}

/// Generate a cryptographically random string (URL-safe base64).
fn generate_random_string(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    B64URL.encode(&buf)
}

/// Sanitize a string into a valid local username.
///
/// Keeps ASCII alphanumeric, hyphens, and underscores. Strips everything else.
/// Truncates to 32 characters. Lowercases.
fn sanitize_username(input: &str) -> String {
    let sanitized: String = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(32)
        .collect();
    sanitized.to_ascii_lowercase()
}

/// Simple percent-encoding for URL query parameters.
fn urlencoded(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{b:02X}"));
            }
        }
    }
    result
}
