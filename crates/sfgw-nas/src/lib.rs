// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;

/// Start NAS services (SMB via ksmbd, NFS).
pub async fn start(db: &sfgw_db::Db, platform: &sfgw_hal::Platform) -> Result<()> {
    let _ = (db, platform);
    todo!("start NAS services")
}
