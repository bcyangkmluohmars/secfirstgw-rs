// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;

/// Generate dnsmasq configuration from the database and start the service.
pub async fn start(db: &sfgw_db::Db) -> Result<()> {
    let _ = db;
    todo!("generate dnsmasq config and start")
}
