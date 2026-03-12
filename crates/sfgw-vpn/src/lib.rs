// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;

pub async fn start(db: &sfgw_db::Db) -> Result<()> {
    let _ = db;
    tracing::info!("VPN service ready (WireGuard multi-core pending)");
    Ok(())
}
