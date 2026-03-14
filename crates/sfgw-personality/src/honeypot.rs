// SPDX-License-Identifier: AGPL-3.0-or-later

//! Honeypot listener on port 28082.
//!
//! Accepts TCP connections, logs the attempt, sends back a troll response
//! in the active personality, and closes the connection.
//! Pure comedy + free threat intel.

use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

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
            port = 28082,
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
