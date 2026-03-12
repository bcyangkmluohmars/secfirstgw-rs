// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;

pub async fn init(db: &sfgw_db::Db) -> Result<()> {
    let _ = db;
    tracing::info!("log subsystem initialized (forward-secret encryption pending)");
    Ok(())
}
