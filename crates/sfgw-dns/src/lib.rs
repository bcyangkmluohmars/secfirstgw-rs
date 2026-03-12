// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;

pub async fn start(db: &sfgw_db::Db) -> Result<()> {
    let _ = db;
    tracing::info!("DNS/DHCP service ready (dnsmasq config pending)");
    Ok(())
}
