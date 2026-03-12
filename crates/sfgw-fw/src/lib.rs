// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;

/// Load firewall rules from the database and apply them via nftables/netlink.
pub async fn load_rules(db: &sfgw_db::Db) -> Result<()> {
    let _ = db;
    todo!("load nftables rules from db")
}
