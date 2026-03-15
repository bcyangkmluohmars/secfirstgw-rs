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
///
/// The platform determines which hardware features are available
/// (display, HDD, switch ASIC) and how services are configured.
///
/// ```
/// use sfgw_hal::Platform;
///
/// let p = Platform::Vm;
/// assert!(!p.has_display());
/// assert!(!p.has_hdd());
/// assert_eq!(p.to_string(), "vm");
/// ```
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
    /// Returns `true` if the platform may have a display (bare metal only).
    ///
    /// ```
    /// use sfgw_hal::Platform;
    ///
    /// assert!(Platform::BareMetal.has_display());
    /// assert!(!Platform::Vm.has_display());
    /// assert!(!Platform::Docker.has_display());
    /// ```
    #[must_use]
    pub fn has_display(&self) -> bool {
        matches!(self, Platform::BareMetal)
    }

    /// Alias for [`has_display`](Self::has_display).
    #[must_use]
    pub fn has_lcd(&self) -> bool {
        self.has_display()
    }

    /// Returns `true` if the platform has an internal HDD bay.
    ///
    /// ```
    /// use sfgw_hal::Platform;
    ///
    /// assert!(Platform::BareMetal.has_hdd());
    /// assert!(!Platform::Vm.has_hdd());
    /// ```
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
///
/// ```
/// let platform = sfgw_hal::init().expect("platform detection failed");
/// // Always returns one of the three variants
/// assert!(matches!(
///     platform,
///     sfgw_hal::Platform::BareMetal | sfgw_hal::Platform::Vm | sfgw_hal::Platform::Docker
/// ));
/// ```
pub fn init() -> Result<Platform, HalError> {
    // Docker: presence of /.dockerenv
    if std::path::Path::new("/.dockerenv").exists() {
        return Ok(Platform::Docker);
    }

    // Bare metal: ubnthal kernel module (device node or sysfs module entry)
    if std::path::Path::new("/dev/ubnthal").exists()
        || std::path::Path::new("/sys/module/ubnthal").exists()
    {
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

/// Known Ubiquiti board identifiers and their corresponding device models.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardInfo {
    /// Raw board ID from `/proc/ubnthal/board` (e.g. "ea15").
    pub board_id: String,
    /// Human-readable model name (e.g. "UniFi Dream Machine Pro").
    pub model: &'static str,
    /// Short model name for UI display (e.g. "UDM Pro").
    pub short_name: &'static str,
    /// Total number of physical ethernet ports.
    pub port_count: u8,
    /// Port layout descriptor for UI rendering.
    pub ports: &'static [PortDef],
    /// Hardware switch ASIC layout, if present.
    pub switch: Option<&'static SwitchAsic>,
}

impl BoardInfo {
    /// Returns interface names assigned to WAN by default.
    #[must_use]
    pub fn wan_ifaces(&self) -> Vec<&'static str> {
        self.ports.iter().filter(|p| p.default_zone == "wan").map(|p| p.iface).collect()
    }

    /// Returns the MGMT interface name, if any.
    #[must_use]
    pub fn mgmt_iface(&self) -> Option<&'static str> {
        self.ports.iter().find(|p| p.default_zone == "mgmt").map(|p| p.iface)
    }
}

/// Hardware switch ASIC configuration (e.g. RTL8370B on UDM Pro).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchAsic {
    /// swconfig device name (e.g. "switch0").
    pub device: &'static str,
    /// Switch port numbers that are LAN ports.
    pub lan_ports: &'static [u8],
    /// CPU port number (internal, always tagged in every VLAN).
    pub cpu_port: u8,
    /// Additional internal ports tagged in every VLAN (e.g. SFP+ uplink).
    pub internal_ports: &'static [u8],
    /// Dedicated MGMT port number for PVID assignment.
    pub mgmt_port: Option<u8>,
}

/// A port definition for UI rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortDef {
    /// Port label shown in UI (e.g. "1", "WAN1", "SFP+").
    pub label: &'static str,
    /// Linux interface name (e.g. "eth0", "eth8").
    pub iface: &'static str,
    /// Physical connector type.
    pub connector: Connector,
    /// Default zone assignment.
    pub default_zone: &'static str,
}

/// Physical port connector type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connector {
    Rj45,
    SfpPlus,
}

impl fmt::Display for Connector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Connector::Rj45 => write!(f, "RJ45"),
            Connector::SfpPlus => write!(f, "SFP+"),
        }
    }
}

// Switch ASIC definitions
static UDMPRO_SWITCH: SwitchAsic = SwitchAsic {
    device: "switch0",
    lan_ports: &[0, 1, 2, 3, 4, 5, 6],
    cpu_port: 8,
    internal_ports: &[9],
    mgmt_port: Some(7),
};

static UDM_SWITCH: SwitchAsic = SwitchAsic {
    device: "switch0",
    lan_ports: &[0, 1, 2, 3],
    cpu_port: 4,
    internal_ports: &[],
    mgmt_port: None,
};

// UDM Pro / SE port definitions
static UDMPRO_PORTS: &[PortDef] = &[
    PortDef { label: "1", iface: "eth0", connector: Connector::Rj45, default_zone: "lan" },
    PortDef { label: "2", iface: "eth1", connector: Connector::Rj45, default_zone: "lan" },
    PortDef { label: "3", iface: "eth2", connector: Connector::Rj45, default_zone: "lan" },
    PortDef { label: "4", iface: "eth3", connector: Connector::Rj45, default_zone: "lan" },
    PortDef { label: "5", iface: "eth4", connector: Connector::Rj45, default_zone: "lan" },
    PortDef { label: "6", iface: "eth5", connector: Connector::Rj45, default_zone: "lan" },
    PortDef { label: "7", iface: "eth6", connector: Connector::Rj45, default_zone: "lan" },
    PortDef { label: "8", iface: "eth7", connector: Connector::Rj45, default_zone: "mgmt" },
    PortDef { label: "WAN", iface: "eth8", connector: Connector::Rj45, default_zone: "wan" },
    PortDef { label: "WAN2", iface: "eth9", connector: Connector::SfpPlus, default_zone: "wan" },
    PortDef { label: "SFP+", iface: "eth10", connector: Connector::SfpPlus, default_zone: "lan" },
];

static UDM_PORTS: &[PortDef] = &[
    PortDef { label: "1", iface: "eth0", connector: Connector::Rj45, default_zone: "lan" },
    PortDef { label: "2", iface: "eth1", connector: Connector::Rj45, default_zone: "lan" },
    PortDef { label: "3", iface: "eth2", connector: Connector::Rj45, default_zone: "lan" },
    PortDef { label: "4", iface: "eth3", connector: Connector::Rj45, default_zone: "lan" },
    PortDef { label: "WAN", iface: "eth4", connector: Connector::Rj45, default_zone: "wan" },
    PortDef { label: "WAN2", iface: "eth5", connector: Connector::Rj45, default_zone: "wan" },
];

static USG3P_PORTS: &[PortDef] = &[
    PortDef { label: "WAN", iface: "eth0", connector: Connector::Rj45, default_zone: "wan" },
    PortDef { label: "LAN", iface: "eth1", connector: Connector::Rj45, default_zone: "lan" },
    PortDef { label: "VOIP", iface: "eth2", connector: Connector::Rj45, default_zone: "lan" },
];

static USG_PRO4_PORTS: &[PortDef] = &[
    PortDef { label: "WAN", iface: "eth0", connector: Connector::Rj45, default_zone: "wan" },
    PortDef { label: "LAN", iface: "eth1", connector: Connector::Rj45, default_zone: "lan" },
    PortDef { label: "WAN2", iface: "eth2", connector: Connector::Rj45, default_zone: "wan" },
    PortDef { label: "LAN2", iface: "eth3", connector: Connector::Rj45, default_zone: "lan" },
    PortDef { label: "SFP1", iface: "eth4", connector: Connector::SfpPlus, default_zone: "lan" },
    PortDef { label: "SFP2", iface: "eth5", connector: Connector::SfpPlus, default_zone: "lan" },
];

/// Detect the Ubiquiti board model by reading `/proc/ubnthal/board` and
/// `/proc/ubnthal/system.info`.
///
/// Returns `None` if not running on Ubiquiti hardware or board ID is unknown.
#[must_use]
pub fn detect_board() -> Option<BoardInfo> {
    // /proc/ubnthal/board is key=value format, e.g. "boardid=ea15"
    let board_content = std::fs::read_to_string("/proc/ubnthal/board").ok()?;
    let board_id = board_content
        .lines()
        .find_map(|line| line.strip_prefix("boardid="))
        .map(|v| v.trim().to_string())?;

    let (model, short_name, port_count, ports, switch) = match board_id.as_str() {
        "ea15" => ("UniFi Dream Machine Pro", "UDM Pro", 11, UDMPRO_PORTS, Some(&UDMPRO_SWITCH)),
        "ea22" => ("UniFi Dream Machine SE", "UDM SE", 11, UDMPRO_PORTS, Some(&UDMPRO_SWITCH)),
        "ea21" => ("UniFi Dream Machine", "UDM", 6, UDM_PORTS, Some(&UDM_SWITCH)),
        "e610" => ("UniFi Security Gateway 3P", "USG 3P", 3, USG3P_PORTS, None),
        "e612" => ("UniFi Security Gateway Pro 4", "USG Pro 4", 6, USG_PRO4_PORTS, None),
        _ => return None,
    };

    Some(BoardInfo {
        board_id,
        model,
        short_name,
        port_count,
        ports,
        switch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_returns_platform() {
        let platform = init().expect("init() should return Ok");
        // On any system, we must get one of the three variants.
        assert!(
            matches!(
                platform,
                Platform::BareMetal | Platform::Vm | Platform::Docker
            ),
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
