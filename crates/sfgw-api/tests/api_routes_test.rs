// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Integration tests for sfgw-api route handlers (status, system).

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::{get, post};
use axum::{Extension, Router};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Helpers (mirrors auth_e2ee_test.rs pattern)
// ---------------------------------------------------------------------------

/// Build a fresh DB backed by a temporary file and return the Db handle.
async fn fresh_db() -> (sfgw_db::Db, NamedTempFile) {
    let tmp = NamedTempFile::new().expect("failed to create temp file");
    let path = tmp.path().to_str().unwrap().to_string();

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
        INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '2');
        ",
    )
    .expect("failed to init schema");

    let db: sfgw_db::Db = Arc::new(Mutex::new(conn));
    (db, tmp)
}

use axum::Json;
use axum::http::HeaderMap;
use axum::response::IntoResponse;

// Thin handler wrappers that replicate the private handlers in sfgw_api lib.

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

async fn proxy_login(
    Extension(db): Extension<sfgw_db::Db>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let username = body["username"].as_str().unwrap_or_default().to_string();
    let password = body["password"].as_str().unwrap_or_default().to_string();

    if username.is_empty() || password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "provide credentials" })),
        );
    }

    let (user, password_hash) = match sfgw_api::auth::get_user_by_username(&db, &username).await {
        Ok(Some(pair)) => pair,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid credentials" })),
            );
        }
    };
    match sfgw_api::auth::verify_password(&password, &password_hash) {
        Ok(true) => {}
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid credentials" })),
            );
        }
    }

    let fingerprint = sfgw_api::middleware::fingerprint_from_headers(&headers);
    let test_addr: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let client_ip = sfgw_api::middleware::client_ip_from_addr(&test_addr);

    match sfgw_api::auth::create_session(&db, user.id, &client_ip, &fingerprint, "").await {
        Ok((token, expires_at)) => (
            StatusCode::OK,
            Json(json!({
                "token": token,
                "expires_at": expires_at.to_rfc3339(),
            })),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "internal server error" })),
        ),
    }
}

/// Proxy for status_handler: returns service statuses from DB.
async fn proxy_status(
    _auth: sfgw_api::middleware::AuthUser,
    Extension(db): Extension<sfgw_db::Db>,
) -> Json<Value> {
    let fw_status = {
        let conn = db.lock().await;
        let rule_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM firewall_rules WHERE enabled = 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if rule_count > 0 { "running" } else { "stopped" }
    };

    Json(json!({
        "status": "ok",
        "services": {
            "firewall": fw_status,
        }
    }))
}

/// Proxy for system_handler: returns version info from DB.
async fn proxy_system(
    _auth: sfgw_api::middleware::AuthUser,
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
    }))
}

/// Build the axum Router with status and system endpoints protected by auth.
fn build_app(db: sfgw_db::Db) -> Router {
    let negotiate_store = sfgw_api::e2ee::new_negotiate_store();
    let addr: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let public_routes = Router::new()
        .route("/api/v1/auth/setup", post(proxy_setup))
        .route("/api/v1/auth/login", post(proxy_login));

    let protected_routes = Router::new()
        .route("/api/v1/status", get(proxy_status))
        .route("/api/v1/system", get(proxy_system))
        .layer(axum::middleware::from_fn(sfgw_api::e2ee::e2ee_layer));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(Extension(db))
        .layer(Extension(negotiate_store))
        .layer(Extension(axum::extract::ConnectInfo(addr)))
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.expect("request failed");
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap_or(json!(null));
    (status, json)
}

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

fn get_with_token(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::USER_AGENT, "test-agent")
        .header("x-forwarded-for", "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// Create admin + login, return (app, token, db, tmpfile).
async fn setup_and_login() -> (Router, String, sfgw_db::Db, NamedTempFile) {
    let (db, tmp) = fresh_db().await;
    let app = build_app(db.clone());

    // Setup admin
    let (status, _) = send(
        &app,
        post_json(
            "/api/v1/auth/setup",
            &json!({ "username": "admin", "password": "password1234" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Login
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
async fn test_status_endpoint() {
    let (app, token, _db, _tmp) = setup_and_login().await;

    let (status, body) = send(&app, get_with_token("/api/v1/status", &token)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert!(
        body["services"].is_object(),
        "status response should contain services object"
    );
    // In a fresh test DB with no firewall rules, firewall should be stopped
    assert_eq!(body["services"]["firewall"], "stopped");
}

#[tokio::test]
async fn test_status_endpoint_unauthorized() {
    let (db, _tmp) = fresh_db().await;
    let app = build_app(db);

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/status")
        .header(header::USER_AGENT, "test-agent")
        .header("x-forwarded-for", "127.0.0.1")
        .body(Body::empty())
        .unwrap();

    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["error"].as_str().is_some());
}

#[tokio::test]
async fn test_system_endpoint() {
    let (app, token, _db, _tmp) = setup_and_login().await;

    let (status, body) = send(&app, get_with_token("/api/v1/system", &token)).await;

    assert_eq!(status, StatusCode::OK);
    // Should have version and schema_version fields
    assert!(
        body["version"].as_str().is_some(),
        "system response should contain version"
    );
    assert!(
        body["schema_version"].as_str().is_some(),
        "system response should contain schema_version"
    );
    assert_eq!(body["schema_version"], "2");
}

#[tokio::test]
async fn test_system_endpoint_unauthorized() {
    let (db, _tmp) = fresh_db().await;
    let app = build_app(db);

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/system")
        .header(header::USER_AGENT, "test-agent")
        .header("x-forwarded-for", "127.0.0.1")
        .body(Body::empty())
        .unwrap();

    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["error"].as_str().is_some());
}

#[tokio::test]
async fn test_status_with_firewall_rules() {
    let (app, token, db, _tmp) = setup_and_login().await;

    // Insert a firewall rule to make the firewall appear "running"
    {
        let conn = db.lock().await;
        conn.execute(
            "INSERT INTO firewall_rules (chain, priority, rule, enabled) VALUES ('input', 0, 'accept', 1)",
            [],
        )
        .expect("failed to insert firewall rule");
    }

    let (status, body) = send(&app, get_with_token("/api/v1/status", &token)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["services"]["firewall"], "running");
}
