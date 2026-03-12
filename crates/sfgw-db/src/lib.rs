// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;

/// Thread-safe handle to the SQLite database.
pub type Db = std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>;

/// Open the database (or create it with the initial schema).
pub async fn open_or_create() -> Result<Db> {
    todo!("open or create SQLite database")
}
