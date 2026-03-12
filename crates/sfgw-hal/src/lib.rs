// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::Result;
use std::fmt;

/// Detected runtime platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Running on Ubiquiti bare-metal hardware (ubnthal.ko present).
    BareMetal,
    /// Running inside a virtual machine.
    Vm,
    /// Running inside a Docker container.
    Docker,
}

impl Platform {
    /// Returns `true` if the platform has an LCD panel (bare metal only).
    pub fn has_lcd(&self) -> bool {
        matches!(self, Platform::BareMetal)
    }

    /// Returns `true` if the platform has an internal HDD bay.
    pub fn has_hdd(&self) -> bool {
        matches!(self, Platform::BareMetal)
    }

    /// Returns `true` if the platform has a hardware switch ASIC.
    pub fn has_switch_asic(&self) -> bool {
        matches!(self, Platform::BareMetal)
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Platform::BareMetal => write!(f, "bare-metal"),
            Platform::Vm => write!(f, "vm"),
            Platform::Docker => write!(f, "docker"),
        }
    }
}

/// Detect the current platform by probing the environment.
///
/// Detection order:
/// 1. Check for `/.dockerenv` -> Docker
/// 2. Check for `/dev/ubnthal` (ubnthal.ko) -> BareMetal
/// 3. Check DMI product name for VM signatures -> Vm
/// 4. Fall back to Vm
pub fn init() -> Result<Platform> {
    // Docker: presence of /.dockerenv
    if std::path::Path::new("/.dockerenv").exists() {
        return Ok(Platform::Docker);
    }

    // Bare metal: ubnthal kernel module device node
    if std::path::Path::new("/dev/ubnthal").exists() {
        return Ok(Platform::BareMetal);
    }

    // Check DMI for VM indicators
    if let Ok(product) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
        let product = product.trim().to_lowercase();
        if product.contains("virtualbox")
            || product.contains("vmware")
            || product.contains("kvm")
            || product.contains("qemu")
            || product.contains("hvm")
        {
            return Ok(Platform::Vm);
        }
    }

    // Default to VM for unknown environments
    Ok(Platform::Vm)
}
