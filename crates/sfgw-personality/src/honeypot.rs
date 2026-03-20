// SPDX-License-Identifier: AGPL-3.0-or-later

//! Honeypot listener on port 28082.
//!
//! Accepts TCP connections, logs the attempt, sends back a troll response
//! in the active personality, and closes the connection.
//! Pure comedy + free threat intel.

use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use anyhow::Context;

/// Default honeypot listen port.
pub const DEFAULT_PORT: u16 = 28082;

/// Meta key for the honeypot enabled setting.
const META_KEY_HONEYPOT_ENABLED: &str = "honeypot_enabled";

/// Check whether the honeypot is enabled in settings.
///
/// Returns `false` if the key is missing (disabled by default).
pub async fn is_enabled(db: &sfgw_db::Db) -> anyhow::Result<bool> {
    let conn = db.lock().await;
    let result = conn.query_row(
        "SELECT value FROM meta WHERE key = ?1",
        [META_KEY_HONEYPOT_ENABLED],
        |r| r.get::<_, String>(0),
    );
    match result {
        Ok(val) => Ok(val == "true"),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => Err(e).context("failed to read honeypot enabled setting"),
    }
}

/// Enable or disable the honeypot.
///
/// This only persists the setting. The caller is responsible for
/// starting or stopping the actual listener.
pub async fn set_enabled(db: &sfgw_db::Db, enabled: bool) -> anyhow::Result<()> {
    let val = if enabled { "true" } else { "false" };
    let conn = db.lock().await;
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
        rusqlite::params![META_KEY_HONEYPOT_ENABLED, val],
    )
    .context("failed to write honeypot enabled setting")?;
    Ok(())
}

/// Start the honeypot listener on the given address (default: `[::]:28082`).
///
/// Each connection is logged and answered with a random troll response
/// matching the active [`Personality`](crate::Personality).
/// The caller should pass a callback to report connection events
/// (e.g. to feed them into the IDS event pipeline).
pub async fn serve(
    listen_addr: SocketAddr,
    on_connection: impl Fn(SocketAddr) + Send + Sync + 'static,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!("honeypot listening on {listen_addr}");

    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("honeypot accept error: {e}");
                continue;
            }
        };

        tracing::warn!(
            peer = %peer,
            port = DEFAULT_PORT,
            "honeypot connection"
        );
        on_connection(peer);

        // Fire and forget — don't let a slow client block the accept loop.
        tokio::spawn(async move {
            let body = crate::messages::honeypot_response();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{body}\n"
            );

            // Read a bit first so we log what they sent (up to 1KB, with timeout).
            let mut buf = [0u8; 1024];
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
            )
            .await;

            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}
