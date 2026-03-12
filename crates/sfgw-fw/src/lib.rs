// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;

pub async fn load_rules(db: &sfgw_db::Db) -> Result<()> {
    let _ = db;
    tracing::info!("firewall rules loaded (nftables pending)");
    Ok(())
}
