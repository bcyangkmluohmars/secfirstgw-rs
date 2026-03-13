// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

use std::fmt;

/// Errors from the hardware abstraction layer.
#[derive(Debug, thiserror::Error)]
pub enum HalError {
    /// Platform detection failed due to an I/O error.
    #[error("platform detection failed: {0}")]
    DetectionFailed(#[from] std::io::Error),
}

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
    #[must_use]
    pub fn has_lcd(&self) -> bool {
        matches!(self, Platform::BareMetal)
    }

    /// Returns `true` if the platform has an internal HDD bay.
    #[must_use]
    pub fn has_hdd(&self) -> bool {
        matches!(self, Platform::BareMetal)
    }

    /// Returns `true` if the platform has a hardware switch ASIC.
    #[must_use]
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
pub fn init() -> Result<Platform, HalError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_returns_platform() {
        let platform = init().expect("init() should return Ok");
        // On any system, we must get one of the three variants.
        assert!(
            matches!(platform, Platform::BareMetal | Platform::Vm | Platform::Docker),
            "init() returned an unexpected platform: {platform:?}"
        );
    }

    #[test]
    fn test_platform_display() {
        assert_eq!(Platform::BareMetal.to_string(), "bare-metal");
        assert_eq!(Platform::Vm.to_string(), "vm");
        assert_eq!(Platform::Docker.to_string(), "docker");
    }

    #[test]
    fn test_has_lcd() {
        assert!(Platform::BareMetal.has_lcd());
        assert!(!Platform::Vm.has_lcd());
        assert!(!Platform::Docker.has_lcd());
    }

    #[test]
    fn test_has_hdd() {
        assert!(Platform::BareMetal.has_hdd());
        assert!(!Platform::Vm.has_hdd());
        assert!(!Platform::Docker.has_hdd());
    }

    #[test]
    fn test_has_switch_asic() {
        assert!(Platform::BareMetal.has_switch_asic());
        assert!(!Platform::Vm.has_switch_asic());
        assert!(!Platform::Docker.has_switch_asic());
    }

    #[test]
    fn test_docker_detection() {
        // If /.dockerenv exists, init() must return Docker.
        // If it doesn't exist, init() must NOT return Docker (unless
        // /dev/ubnthal also doesn't exist, in which case it's Vm).
        let platform = init().expect("init() should return Ok");
        if std::path::Path::new("/.dockerenv").exists() {
            assert_eq!(platform, Platform::Docker);
        } else {
            assert_ne!(platform, Platform::Docker);
        }
    }

    #[test]
    fn test_platform_debug_and_clone() {
        let p = Platform::Vm;
        let p2 = p; // Copy
        assert_eq!(p, p2);
        let _ = format!("{p:?}"); // Debug
    }
}
