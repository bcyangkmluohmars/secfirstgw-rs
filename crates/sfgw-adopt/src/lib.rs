// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;

/// Start the device adoption listener.
pub async fn start(db: &sfgw_db::Db) -> Result<()> {
    let _ = db;
    todo!("start device adoption protocol")
}
