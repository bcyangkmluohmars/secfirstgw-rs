// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;

/// Start the network controller service.
pub async fn start(db: &sfgw_db::Db) -> Result<()> {
    let _ = db;
    todo!("start network controller")
}
