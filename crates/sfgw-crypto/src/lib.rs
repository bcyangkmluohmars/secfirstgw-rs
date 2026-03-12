// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;

/// Automatically unlock LUKS2 volumes using hardware-derived keys.
///
/// On bare metal, derives the key from ubnthal hardware identity.
/// On VM/Docker, this is a no-op.
pub async fn auto_unlock(platform: &sfgw_hal::Platform) -> Result<()> {
    let _ = platform;
    todo!("auto-unlock LUKS2 volumes")
}
