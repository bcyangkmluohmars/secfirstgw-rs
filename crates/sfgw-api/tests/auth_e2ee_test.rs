// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Integration tests for the sfgw-api auth and E2EE endpoints.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::{get, post};
use axum::{Extension, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a fresh DB backed by a temporary file and return the Db handle.
/// The NamedTempFile is returned so its lifetime keeps the file alive.
async fn fresh_db() -> (sfgw_db::Db, NamedTempFile) {
    let tmp = NamedTempFile::new().expect("failed to create temp file");
    let path = tmp.path().to_str().unwrap().to_string();

    // Open the DB directly (avoid env-var races between parallel tests).
    let conn = rusqlite::Connection::open(&path).expect("failed to open db");
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS interfaces (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT NOT NULL UNIQUE,
            mac       TEXT NOT NULL DEFAULT '',
            ips       TEXT NOT NULL DEFAULT '[]',
            mtu       INTEGER NOT NULL DEFAULT 1500,
            is_up     INTEGER NOT NULL DEFAULT 0,
            role      TEXT NOT NULL DEFAULT 'lan',
            vlan_id   INTEGER,
            enabled   INTEGER NOT NULL DEFAULT 1,
            config    TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            chain     TEXT NOT NULL,
            priority  INTEGER NOT NULL DEFAULT 0,
            rule      TEXT NOT NULL,
            enabled   INTEGER NOT NULL DEFAULT 1
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
        CREATE TABLE IF NOT EXISTS vpn_tunnels (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT NOT NULL UNIQUE,
            type      TEXT NOT NULL,
            enabled   INTEGER NOT NULL DEFAULT 0,
            config    TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'admin',
            created_at    TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token         TEXT PRIMARY KEY,
            user_id       INTEGER NOT NULL REFERENCES users(id),
            tls_session   TEXT NOT NULL,
            client_ip     TEXT NOT NULL,
            fingerprint   TEXT NOT NULL,
            envelope_key  TEXT NOT NULL,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at    TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ids_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            severity    TEXT NOT NULL,
            detector    TEXT NOT NULL,
            source_mac  TEXT,
            source_ip   TEXT,
            interface   TEXT NOT NULL,
            vlan        INTEGER,
            description TEXT NOT NULL
        );
        INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '1');
        ",
    )
    .expect("failed to init schema");

    let db: sfgw_db::Db = Arc::new(Mutex::new(conn));
    (db, tmp)
}

/// Build the full axum Router (public + protected) suitable for tower testing.
fn build_app(db: sfgw_db::Db) -> Router {
    let negotiate_store = sfgw_api::e2ee::new_negotiate_store();

    let public_routes = Router::new()
        .route("/api/v1/auth/session", post(proxy_session))
        .route("/api/v1/auth/login", post(proxy_login))
        .route("/api/v1/auth/setup", post(proxy_setup));

    let protected_routes = Router::new()
        .route("/api/v1/status", get(proxy_status))
        .layer(axum::middleware::from_fn(sfgw_api::e2ee::e2ee_layer));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(Extension(db))
        .layer(Extension(negotiate_store))
}

// We need thin wrapper handlers because the real handlers are private (non-pub)
// in sfgw_api. Instead of exposing them, we replicate the router using the
// public modules. However, the actual handler functions in lib.rs are private.
//
// The cleanest approach: re-export a `build_router` from sfgw_api.
// Since we cannot modify lib.rs in this task, we call the endpoints through
// the public API surface by directly invoking the auth/e2ee modules and
// testing the handler logic via HTTP.
//
// Actually, let's check: we can build the same router using the same handler
// signatures. The handlers are async fns — we can define equivalent ones that
// delegate to the same logic. But that's fragile.
//
// Better approach: we'll add a `#[cfg(test)]` or `pub` router builder.
// For now, let's directly test by building a minimal app that calls the same
// underlying functions and test the auth + e2ee logic at integration level.

// ---------------------------------------------------------------------------
// Since the handlers in lib.rs are private, we test the auth and E2EE logic
// directly through the public function API, plus build minimal axum handlers
// that mirror the real ones for HTTP-level testing.
// ---------------------------------------------------------------------------

use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::Json;

// Thin handler wrappers that replicate the behaviour of the private handlers
// in sfgw_api::lib. These call the same public auth/e2ee functions.

#[derive(serde::Deserialize)]
struct SetupRequest {
    username: String,
    password: String,
}

async fn proxy_setup(
    Extension(db): Extension<sfgw_db::Db>,
    Json(body): Json<SetupRequest>,
) -> impl IntoResponse {
    match sfgw_api::auth::user_count(&db).await {
        Ok(count) if count > 0 => {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "setup already completed" })),
            );
        }
        Err(_) => {
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
    let hash = sfgw_api::auth::hash_password(&body.password).unwrap();
    match sfgw_api::auth::create_user(&db, &body.username, &hash, "admin").await {
        Ok(user_id) => (
            StatusCode::CREATED,
            Json(json!({
                "user_id": user_id,
                "username": body.username,
                "role": "admin",
            })),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "internal server error" })),
        ),
    }
}

#[derive(serde::Deserialize)]
struct LoginRequest {
    username: Option<String>,
    password: Option<String>,
    negotiate_id: Option<String>,
    ciphertext: Option<String>,
    iv: Option<String>,
}

#[derive(serde::Deserialize)]
struct E2eeCredentials {
    username: String,
    password: String,
}

async fn proxy_login(
    Extension(db): Extension<sfgw_db::Db>,
    Extension(negotiate_store): Extension<sfgw_api::e2ee::NegotiateStore>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    // Extract credentials
    let (username, password, negotiate_key) = if let (Some(nid), Some(ct), Some(iv)) =
        (&body.negotiate_id, &body.ciphertext, &body.iv)
    {
        let neg_key = match sfgw_api::e2ee::take_negotiate_key(&negotiate_store, nid).await {
            Ok(k) => k,
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
        };
        let ct_bytes = B64.decode(ct).unwrap();
        let iv_bytes = B64.decode(iv).unwrap();
        let plaintext = match sfgw_api::e2ee::decrypt(&neg_key, &ct_bytes, &iv_bytes) {
            Ok(pt) => pt,
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "decryption failed" })),
                )
            }
        };
        let creds: E2eeCredentials = serde_json::from_slice(&plaintext).unwrap();
        (creds.username, creds.password, Some(neg_key))
    } else if let (Some(u), Some(p)) = (body.username, body.password) {
        (u, p, None)
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "provide credentials" })),
        );
    };

    // Verify
    let (user, password_hash) = match sfgw_api::auth::get_user_by_username(&db, &username).await {
        Ok(Some(pair)) => pair,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid credentials" })),
            )
        }
    };
    match sfgw_api::auth::verify_password(&password, &password_hash) {
        Ok(true) => {}
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid credentials" })),
            )
        }
    }

    let fingerprint = sfgw_api::middleware::fingerprint_from_headers(&headers);
    let client_ip = sfgw_api::middleware::client_ip_from_headers(&headers);
    let client_ip = if client_ip == "unknown" {
        "127.0.0.1".to_string()
    } else {
        client_ip
    };

    let envelope_key = negotiate_key
        .as_ref()
        .and_then(|_| sfgw_api::e2ee::generate_envelope_key().ok());
    let envelope_key_b64 = envelope_key
        .as_ref()
        .map(|k| B64.encode(k))
        .unwrap_or_default();

    match sfgw_api::auth::create_session(&db, user.id, &client_ip, &fingerprint, &envelope_key_b64)
        .await
    {
        Ok((token, expires_at)) => {
            let mut response = json!({
                "token": token,
                "expires_at": expires_at.to_rfc3339(),
            });
            if let (Some(neg_key), Some(env_key)) = (&negotiate_key, &envelope_key) {
                if let Ok(sealed) = sfgw_api::e2ee::Envelope::seal(neg_key, env_key) {
                    response["envelope"] = json!({ "iv": sealed.iv, "data": sealed.data });
                }
            }
            (StatusCode::OK, Json(response))
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "internal server error" })),
        ),
    }
}

#[derive(serde::Deserialize)]
struct SessionRequest {
    client_public_key: String,
    token: Option<String>,
}

async fn proxy_session(
    Extension(db): Extension<sfgw_db::Db>,
    Extension(negotiate_store): Extension<sfgw_api::e2ee::NegotiateStore>,
    headers: HeaderMap,
    Json(body): Json<SessionRequest>,
) -> impl IntoResponse {
    let client_pub = match B64.decode(&body.client_public_key) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid base64" })),
            )
        }
    };

    let (negotiate_id, server_pub) =
        match sfgw_api::e2ee::negotiate(&negotiate_store, &client_pub).await {
            Ok(r) => r,
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
        };

    let mut response = json!({
        "negotiate_id": negotiate_id,
        "server_public_key": B64.encode(&server_pub),
        "authenticated": false,
    });

    if let Some(ref token) = body.token {
        let client_ip = {
            let ip = sfgw_api::middleware::client_ip_from_headers(&headers);
            if ip == "unknown" {
                "127.0.0.1".to_string()
            } else {
                ip
            }
        };
        let fingerprint = sfgw_api::middleware::fingerprint_from_headers(&headers);

        if let Ok(Some(user_id)) =
            sfgw_api::auth::validate_session(&db, token, &client_ip, &fingerprint).await
        {
            if let Ok(Some(user)) = sfgw_api::auth::get_user_by_id(&db, user_id).await {
                if let Ok(env_key) = sfgw_api::e2ee::generate_envelope_key() {
                    let env_key_b64 = B64.encode(&env_key);
                    let _ = sfgw_api::auth::update_envelope_key(&db, token, &env_key_b64).await;
                    if let Ok(neg_key) =
                        sfgw_api::e2ee::take_negotiate_key(&negotiate_store, &negotiate_id).await
                    {
                        if let Ok(sealed) = sfgw_api::e2ee::Envelope::seal(&neg_key, &env_key) {
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

async fn proxy_status(
    _auth: sfgw_api::middleware::AuthUser,
) -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

// ---------------------------------------------------------------------------
// Helper: send a request through the router
// ---------------------------------------------------------------------------

async fn send(
    app: &Router,
    req: Request<Body>,
) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("request failed");
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap_or(json!(null));
    (status, json)
}

/// Build a POST request with JSON body.
fn post_json(uri: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::USER_AGENT, "test-agent")
        .header("x-forwarded-for", "127.0.0.1")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

/// Build a GET request, optionally with a bearer token.
fn get_with_token(uri: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::USER_AGENT, "test-agent")
        .header("x-forwarded-for", "127.0.0.1");
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    builder.body(Body::empty()).unwrap()
}

/// Create an admin user through the setup endpoint and return the app + db.
async fn setup_admin(
    username: &str,
    password: &str,
) -> (Router, sfgw_db::Db, NamedTempFile) {
    let (db, tmp) = fresh_db().await;
    let app = build_app(db.clone());
    let (status, _) = send(
        &app,
        post_json(
            "/api/v1/auth/setup",
            &json!({ "username": username, "password": password }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    (app, db, tmp)
}

/// Create admin + login via plain credentials, return (app, token, db, tmpfile).
async fn setup_and_login() -> (Router, String, sfgw_db::Db, NamedTempFile) {
    let (app, db, tmp) = setup_admin("admin", "password1234").await;
    let (status, body) = send(
        &app,
        post_json(
            "/api/v1/auth/login",
            &json!({ "username": "admin", "password": "password1234" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = body["token"].as_str().unwrap().to_string();
    (app, token, db, tmp)
}

// ===========================================================================
// Tests
// ===========================================================================

#[tokio::test]
async fn test_setup_creates_admin() {
    let (db, _tmp) = fresh_db().await;
    let app = build_app(db.clone());

    let (status, body) = send(
        &app,
        post_json(
            "/api/v1/auth/setup",
            &json!({ "username": "admin", "password": "supersecret1" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["username"], "admin");
    assert_eq!(body["role"], "admin");
    assert!(body["user_id"].as_i64().unwrap() > 0);
}

#[tokio::test]
async fn test_setup_rejects_when_users_exist() {
    let (app, _db, _tmp) = setup_admin("admin", "supersecret1").await;

    // Second setup should be rejected
    let (status, body) = send(
        &app,
        post_json(
            "/api/v1/auth/setup",
            &json!({ "username": "admin2", "password": "supersecret2" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["error"].as_str().unwrap().contains("already completed"));
}

#[tokio::test]
async fn test_plain_login() {
    let (app, _db, _tmp) = setup_admin("admin", "password1234").await;

    let (status, body) = send(
        &app,
        post_json(
            "/api/v1/auth/login",
            &json!({ "username": "admin", "password": "password1234" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["token"].as_str().is_some());
    assert!(body["expires_at"].as_str().is_some());
}

#[tokio::test]
async fn test_plain_login_bad_password() {
    let (app, _db, _tmp) = setup_admin("admin", "password1234").await;

    let (status, body) = send(
        &app,
        post_json(
            "/api/v1/auth/login",
            &json!({ "username": "admin", "password": "wrongpassword" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["error"].as_str().is_some());
}

#[tokio::test]
async fn test_session_endpoint_returns_negotiate() {
    let (db, _tmp) = fresh_db().await;
    let app = build_app(db);

    // Generate a client X25519 keypair
    let client_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let client_public = x25519_dalek::PublicKey::from(&client_secret);
    let client_pub_b64 = B64.encode(client_public.as_bytes());

    let (status, body) = send(
        &app,
        post_json(
            "/api/v1/auth/session",
            &json!({ "client_public_key": client_pub_b64 }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["negotiate_id"].as_str().is_some());
    assert!(body["server_public_key"].as_str().is_some());
    assert_eq!(body["authenticated"], false);

    // Verify server public key is valid base64 and 32 bytes
    let server_pub_bytes = B64
        .decode(body["server_public_key"].as_str().unwrap())
        .unwrap();
    assert_eq!(server_pub_bytes.len(), 32);
}

#[tokio::test]
async fn test_session_resume_with_token() {
    let (app, token, _db, _tmp) = setup_and_login().await;

    // Generate client X25519 keypair
    let client_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let client_public = x25519_dalek::PublicKey::from(&client_secret);
    let client_pub_b64 = B64.encode(client_public.as_bytes());

    // Session resume with valid token
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/session")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::USER_AGENT, "test-agent")
        .header("x-forwarded-for", "127.0.0.1")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "client_public_key": client_pub_b64,
                "token": token,
            }))
            .unwrap(),
        ))
        .unwrap();

    let (status, body) = send(&app, req).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["authenticated"], true);
    assert!(body["user"].is_object());
    assert_eq!(body["user"]["username"], "admin");
    assert!(body["envelope"].is_object());
    assert!(body["envelope"]["iv"].as_str().is_some());
    assert!(body["envelope"]["data"].as_str().is_some());
}

#[tokio::test]
async fn test_protected_route_401_without_token() {
    let (db, _tmp) = fresh_db().await;
    let app = build_app(db);

    let (status, body) = send(&app, get_with_token("/api/v1/status", None)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["error"].as_str().is_some());
}

#[tokio::test]
async fn test_protected_route_works_with_token() {
    let (app, token, _db, _tmp) = setup_and_login().await;

    let (status, body) = send(&app, get_with_token("/api/v1/status", Some(&token))).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn test_e2ee_login_flow() {
    // 1. Setup admin
    let (app, _db, _tmp) = setup_admin("admin", "password1234").await;

    // 2. Client generates X25519 keypair
    let client_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let client_public = x25519_dalek::PublicKey::from(&client_secret);
    let client_pub_b64 = B64.encode(client_public.as_bytes());

    // 3. Negotiate: POST /auth/session to get negotiate_id + server_public_key
    let (status, session_body) = send(
        &app,
        post_json(
            "/api/v1/auth/session",
            &json!({ "client_public_key": client_pub_b64 }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let negotiate_id = session_body["negotiate_id"].as_str().unwrap().to_string();
    let server_pub_bytes = B64
        .decode(session_body["server_public_key"].as_str().unwrap())
        .unwrap();

    // 4. Client computes shared secret using x25519
    let server_pub_key = {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&server_pub_bytes);
        x25519_dalek::PublicKey::from(bytes)
    };
    let shared_secret = client_secret.diffie_hellman(&server_pub_key);

    // 5. Derive AES key using HKDF-SHA256 (same as server)
    let aes_key = {
        use ring::hkdf;
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
        let prk = salt.extract(shared_secret.as_bytes());

        struct AesKeyType;
        impl hkdf::KeyType for AesKeyType {
            fn len(&self) -> usize {
                32
            }
        }
        let okm = prk.expand(&[b"sfgw-e2ee-v1"], AesKeyType).unwrap();
        let mut key = [0u8; 32];
        okm.fill(&mut key).unwrap();
        key
    };

    // 6. Encrypt credentials with the negotiate AES key
    let creds_json = serde_json::to_vec(&json!({
        "username": "admin",
        "password": "password1234",
    }))
    .unwrap();

    let (ciphertext, iv) = sfgw_api::e2ee::encrypt(&aes_key, &creds_json).unwrap();

    // 7. POST /auth/login with encrypted credentials
    let (status, login_body) = send(
        &app,
        post_json(
            "/api/v1/auth/login",
            &json!({
                "negotiate_id": negotiate_id,
                "ciphertext": B64.encode(&ciphertext),
                "iv": B64.encode(&iv),
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(login_body["token"].as_str().is_some());
    assert!(login_body["expires_at"].as_str().is_some());

    // 8. Verify envelope is returned (encrypted envelope key)
    assert!(login_body["envelope"].is_object());
    let envelope_iv = login_body["envelope"]["iv"].as_str().unwrap();
    let envelope_data = login_body["envelope"]["data"].as_str().unwrap();

    // 9. Decrypt the envelope key using the negotiate AES key
    let env_ct = B64.decode(envelope_data).unwrap();
    let env_iv = B64.decode(envelope_iv).unwrap();
    let envelope_key_bytes = sfgw_api::e2ee::decrypt(&aes_key, &env_ct, &env_iv).unwrap();
    assert_eq!(envelope_key_bytes.len(), 32);

    // 10. Verify the token works for protected endpoints
    let token = login_body["token"].as_str().unwrap();
    let (status, body) = send(&app, get_with_token("/api/v1/status", Some(token))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn test_setup_rejects_short_password() {
    let (db, _tmp) = fresh_db().await;
    let app = build_app(db);

    let (status, body) = send(
        &app,
        post_json(
            "/api/v1/auth/setup",
            &json!({ "username": "admin", "password": "short" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("at least 8 characters"));
}

#[tokio::test]
async fn test_setup_rejects_empty_fields() {
    let (db, _tmp) = fresh_db().await;
    let app = build_app(db);

    let (status, body) = send(
        &app,
        post_json(
            "/api/v1/auth/setup",
            &json!({ "username": "", "password": "supersecret1" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("required"));
}

#[tokio::test]
async fn test_login_nonexistent_user() {
    let (app, _db, _tmp) = setup_admin("admin", "password1234").await;

    let (status, _) = send(
        &app,
        post_json(
            "/api/v1/auth/login",
            &json!({ "username": "nobody", "password": "password1234" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
