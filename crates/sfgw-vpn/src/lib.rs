// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;

/// Start VPN services (WireGuard via boringtun + OpenVPN).
pub async fn start(db: &sfgw_db::Db) -> Result<()> {
    let _ = db;
    todo!("start VPN services")
}
