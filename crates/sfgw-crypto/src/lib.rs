// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod secure_mem;

use anyhow::Result;

/// Automatically unlock LUKS2 volumes using hardware-derived keys.
///
/// - Bare metal: derives key from ubnthal hardware identity (serial + GUID)
/// - VM: prompts for passphrase or uses key file
/// - Docker: no-op (volumes are mounted from host)
pub async fn auto_unlock(platform: &sfgw_hal::Platform) -> Result<()> {
    match platform {
        sfgw_hal::Platform::Docker => {
            tracing::info!("docker mode — skipping disk encryption (using volume mounts)");
            Ok(())
        }
        sfgw_hal::Platform::Vm => {
            tracing::info!("vm mode — LUKS unlock not yet implemented");
            Ok(())
        }
        sfgw_hal::Platform::BareMetal => {
            tracing::info!("bare metal — LUKS auto-unlock not yet implemented");
            Ok(())
        }
    }
}
