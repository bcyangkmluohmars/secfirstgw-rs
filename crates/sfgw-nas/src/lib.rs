// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;

pub async fn start(db: &sfgw_db::Db, platform: &sfgw_hal::Platform) -> Result<()> {
    let _ = (db, platform);
    tracing::info!("NAS service ready (SMB/NFS pending)");
    Ok(())
}
