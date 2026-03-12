// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;

pub async fn init() -> Result<()> {
    tracing::info!("LCD display initialized (sysfs driver pending)");
    Ok(())
}
