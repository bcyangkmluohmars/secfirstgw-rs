// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! Authentication routes for secfirstNAS.
//!
//! Endpoints:
//! - `POST /auth/session` — E2EE key exchange (X25519 + ML-KEM-1024)
//! - `POST /auth/login`   — Authenticate with credentials (E2EE or plain)
//! - `GET  /auth/setup`   — Check if initial setup is needed
//! - `POST /auth/setup`   — Create the initial admin user
//! - `POST /auth/logout`  — Destroy session
//! - `GET  /auth/me`      — Get current user info

use crate::auth;
use crate::e2ee;
use crate::middleware::AuthUser;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::SocketAddr;

/// Build the auth router (public — no auth required).
pub fn public_router() -> Router {
    Router::new()
        .route("/auth/session", post(session_handler))
        .route("/auth/login", post(login_handler))
        .route("/auth/setup", get(setup_status_handler).post(setup_handler))
}

/// Build the authenticated auth routes (logout, me).
pub fn protected_router() -> Router {
    Router::new()
        .route("/auth/logout", post(logout_handler))
        .route("/auth/me", get(me_handler))
}

// ---------------------------------------------------------------------------
// /auth/session — E2EE key exchange
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SessionRequest {
    client_public_key: String,
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
    let client_pub = match B64.decode(&body.client_public_key) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid base64 in client_public_key" })),
            );
        }
    };

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

    if let Some(ref ct) = neg_result.kem_ciphertext {
        response["kem_ciphertext"] = json!(B64.encode(ct));
    }

    // If token provided, try to validate + resume
    if let Some(ref token) = body.token {
        let client_ip = addr.ip().to_string();
        let fingerprint = crate::middleware::fingerprint_from_headers(&headers);

        if let Ok(Some(user_id)) =
            auth::validate_session(&db, token, &client_ip, &fingerprint).await
            && let Ok(Some(user)) = auth::get_user_by_id(&db, user_id).await
            && let Ok(env_key) = e2ee::generate_envelope_key() {
                {
                    let mut store = envelope_key_store.lock().await;
                    store.insert(token.to_string(), env_key.to_vec());
                }

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

    (StatusCode::OK, Json(response))
}

// ---------------------------------------------------------------------------
// /auth/login — Authenticate with credentials
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct LoginRequest {
    /// E2EE negotiate ID from the session endpoint.
    negotiate_id: Option<String>,
    /// AES-256-GCM encrypted credentials (base64).
    ciphertext: Option<String>,
    /// AES-256-GCM IV (base64).
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
        } else {
            // No plaintext fallback. E2EE is mandatory.
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "E2EE required: provide negotiate_id, ciphertext, and iv" })),
            );
        };

    // Constant-time: verify against dummy hash if user doesn't exist
    let dummy_hash = "$argon2id$v=19$m=19456,t=2,p=1$aaaaaaaaaaaaaaaaaaaaaa$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbA";
    let (user, password_hash) = match auth::get_user_by_username(&db, &username).await {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            let _ = auth::verify_password(&password, dummy_hash);
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

    let client_ip = addr.ip().to_string();
    let fingerprint = crate::middleware::fingerprint_from_headers(&headers);

    let envelope_key = negotiate_key
        .as_ref()
        .and_then(|_| e2ee::generate_envelope_key().ok());

    match auth::create_session(&db, user.id, &client_ip, &fingerprint, "").await {
        Ok((token, expires_at)) => {
            let mut response = json!({
                "token": token,
                "expires_at": expires_at.to_rfc3339(),
            });

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
// /auth/logout + /auth/me
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// /auth/setup/discovery — Hardware discovery during setup (public, setup-only)
// ---------------------------------------------------------------------------

/// Returns bay and disk data for the setup wizard.
///
/// Only available when setup is needed (no users in DB). Returns 403 after
/// setup is complete — prevents unauthenticated hardware enumeration.
///
/// Currently unused (planned for setup wizard UI). Marked as allowed dead code
/// until setup flow is wired into the router.
#[allow(dead_code)]
async fn setup_discovery_handler(
    Extension(db): Extension<sfgw_db::Db>,
    Extension(disk_cache): Extension<sfnas_storage::DiskCache>,
) -> impl IntoResponse {
    // Only allow during setup (no users exist)
    let conn = db.lock().await;
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
        .unwrap_or(1); // Default to 1 (= deny) on error
    drop(conn);

    if count > 0 {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "setup already completed" })),
        );
    }

    let bays = sfnas_storage::Bay::read_all();
    let disks = disk_cache.get();

    (
        StatusCode::OK,
        Json(json!({
            "bays": bays,
            "disks": disks,
        })),
    )
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
