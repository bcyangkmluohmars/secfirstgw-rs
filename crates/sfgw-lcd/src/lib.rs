// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;

/// Initialize the LCD display panel via sysfs.
///
/// Only meaningful on bare-metal platforms; callers should gate on
/// `Platform::has_lcd()` before calling.
pub async fn init() -> Result<()> {
    todo!("initialize LCD display via sysfs")
}
