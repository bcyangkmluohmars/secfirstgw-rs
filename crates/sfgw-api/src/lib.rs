// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;

/// Start the axum web API and serve the UI.
///
/// This function blocks until the server is shut down.
pub async fn serve(db: &sfgw_db::Db) -> Result<()> {
    let _ = db;
    todo!("start axum API server")
}
