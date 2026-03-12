// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    routing::get,
};
use serde_json::{json, Value};
use std::net::SocketAddr;

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

    let app = Router::new()
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/system", get({
            let db = db.clone();
            move || system_handler(db)
        }))
        .route("/api/v1/interfaces", get({
            let db = db.clone();
            move || interfaces_handler(db)
        }))
        .route("/api/v1/devices", get({
            let db = db.clone();
            move || devices_handler(db)
        }))
        .route("/", get(root_handler))
        .layer(tower_http::trace::TraceLayer::new_for_http());

    tracing::info!("API server listening on {listen_addr}");

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind to {listen_addr}"))?;

    axum::serve(listener, app)
        .await
        .context("API server error")?;

    Ok(())
}

async fn root_handler() -> Json<Value> {
    Json(json!({
        "name": "secfirstgw",
        "version": env!("CARGO_PKG_VERSION"),
        "status": "running"
    }))
}

async fn status_handler() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "uptime_secs": 0,
        "services": {
            "firewall": "running",
            "dns": "running",
            "vpn": "stopped",
            "ids": "running",
            "nas": "stopped"
        }
    }))
}

async fn system_handler(db: sfgw_db::Db) -> Json<Value> {
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
    }))
}

async fn interfaces_handler(db: sfgw_db::Db) -> Json<Value> {
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

async fn devices_handler(db: sfgw_db::Db) -> Json<Value> {
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
