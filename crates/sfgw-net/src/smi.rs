// SPDX-License-Identifier: AGPL-3.0-or-later

//! Low-level SMI register access for the RTL8370MB switch ASIC.
//!
//! Two backends:
//!
//! 1. **`/dev/rtl8370mb`** (preferred) — The kernel module provides atomic
//!    SMI read/write via ioctl. The MDIO bus lock is held for the full
//!    4-operation SMI sequence, preventing PHY polling from corrupting
//!    the transaction.
//!
//! 2. **MDIO ioctl fallback** — Direct `SIOCSMIIREG`/`SIOCGMIIREG` on the
//!    network interface. Each MDIO operation is a separate ioctl, so PHY
//!    polling can interleave. Only used if `/dev/rtl8370mb` is not available
//!    (VMs, testing).
//!
//! # Prerequisites
//!
//! - Kernel module `rtl8370mb_init` loaded (creates `/dev/rtl8370mb`)
//! - Root privileges
//!
//! # Safety
//!
//! This module contains `unsafe` blocks for raw ioctl calls. Each has a
//! `// SAFETY:` comment.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;

/// Chardev path provided by the rtl8370mb kernel module.
const CHARDEV_PATH: &str = "/dev/rtl8370mb";

/// RTL8370MB SMI lock/unlock register.
const SMI_ACCESS_REG: u16 = 0x13C2;
/// Unlock magic value.
const SMI_UNLOCK_VAL: u16 = 0x0249;
/// Lock value (zero).
const SMI_LOCK_VAL: u16 = 0x0000;

// ── Chardev ioctl definitions (must match kernel module) ────────────

/// ioctl message struct (matches `struct rtl8370mb_smi_msg` in the kernel).
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SmiMsg {
    reg: u16,
    val: u16,
}

// ioctl magic 'R', nr=1 for read, nr=2 for write.
// _IOWR('R', 1, struct rtl8370mb_smi_msg) and _IOW('R', 2, ...)
// On Linux: direction(2) | size(14) | type(8) | nr(8)
// SmiMsg is 4 bytes.
const RTL8370MB_SMI_READ: libc::c_ulong = 0xC004_5201;  // _IOWR('R', 1, 4)
const RTL8370MB_SMI_WRITE: libc::c_ulong = 0x4004_5202; // _IOW('R', 2, 4)

// ── MDIO ioctl fallback definitions ─────────────────────────────────

/// MDIO ioctl constants (from linux/sockios.h).
const SIOCGMIIREG: libc::c_ulong = 0x8948;
const SIOCSMIIREG: libc::c_ulong = 0x8949;

/// Maximum length of an interface name (including null terminator).
const IFNAMSIZ: usize = 16;

/// MII ioctl data structure (mirrors `struct mii_ioctl_data` from linux/mii.h).
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct MiiIoctlData {
    phy_id: u16,
    reg_num: u16,
    val_in: u16,
    val_out: u16,
}

/// The `ifreq` structure for MII ioctls.
///
/// Must match `sizeof(struct ifreq)` from the kernel (40 bytes on 64-bit).
/// The kernel copies the full struct via `copy_from_user`/`copy_to_user`.
#[repr(C)]
struct Ifreq {
    ifr_name: [u8; IFNAMSIZ], // 16 bytes
    ifr_data: MiiIoctlData,    // 8 bytes
    _pad: [u8; 16],           // pad to 40 bytes (match struct ifmap on 64-bit)
}

impl Ifreq {
    fn new(ifname: &str, phy_addr: u8) -> Self {
        let mut ifr = Self {
            ifr_name: [0u8; IFNAMSIZ],
            ifr_data: MiiIoctlData {
                phy_id: u16::from(phy_addr),
                ..MiiIoctlData::default()
            },
            _pad: [0u8; 16],
        };
        let name_bytes = ifname.as_bytes();
        let len = name_bytes.len().min(IFNAMSIZ - 1);
        ifr.ifr_name[..len].copy_from_slice(&name_bytes[..len]);
        ifr
    }
}

// ── SMI access backends ─────────────────────────────────────────────

/// SMI backend — either chardev (atomic) or MDIO ioctl (fallback).
enum SmiBackend {
    /// `/dev/rtl8370mb` chardev with atomic SMI ioctls.
    Chardev(File),
    /// MDIO ioctl fallback (non-atomic, for testing only).
    Mdio {
        sock: std::net::UdpSocket,
        ifname: String,
        phy_addr: u8,
    },
}

/// Low-level SMI access to an RTL8370MB switch ASIC.
pub struct SmiAccess {
    backend: SmiBackend,
}

impl SmiAccess {
    /// Create a new SMI access handle.
    ///
    /// Tries `/dev/rtl8370mb` first (atomic, correct). Falls back to MDIO
    /// ioctl on `ifname` (non-atomic, PHY polling can corrupt — for testing
    /// only).
    pub fn new(ifname: &str, phy_addr: u8) -> std::io::Result<Self> {
        // Try chardev first
        if let Ok(file) = OpenOptions::new().read(true).write(true).open(CHARDEV_PATH) {
            tracing::info!("SMI: using {CHARDEV_PATH} (atomic kernel ioctl)");
            return Ok(Self {
                backend: SmiBackend::Chardev(file),
            });
        }

        // Fallback to MDIO ioctl
        tracing::warn!(
            "SMI: {CHARDEV_PATH} not available, falling back to MDIO ioctl on {ifname} \
             (non-atomic — PHY polling may corrupt SMI transactions)"
        );
        let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
        Ok(Self {
            backend: SmiBackend::Mdio {
                sock,
                ifname: ifname.to_string(),
                phy_addr,
            },
        })
    }

    /// Write an RTL8370MB switch register via SMI.
    pub fn smi_write(&self, reg_addr: u16, value: u16) -> std::io::Result<()> {
        match &self.backend {
            SmiBackend::Chardev(file) => {
                let mut msg = SmiMsg {
                    reg: reg_addr,
                    val: value,
                };
                // SAFETY: Valid fd from File, correctly sized SmiMsg struct.
                // The kernel module validates the register address.
                let ret = unsafe {
                    libc::ioctl(file.as_raw_fd(), RTL8370MB_SMI_WRITE as _, &mut msg as *mut SmiMsg)
                };
                if ret < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            }
            SmiBackend::Mdio {
                sock,
                ifname,
                phy_addr,
            } => {
                mdio_smi_write(sock, ifname, *phy_addr, reg_addr, value)
            }
        }
    }

    /// Read an RTL8370MB switch register via SMI.
    pub fn smi_read(&self, reg_addr: u16) -> std::io::Result<u16> {
        match &self.backend {
            SmiBackend::Chardev(file) => {
                let mut msg = SmiMsg {
                    reg: reg_addr,
                    val: 0,
                };
                // SAFETY: Valid fd, correctly sized struct. Kernel writes
                // result into msg.val.
                let ret = unsafe {
                    libc::ioctl(file.as_raw_fd(), RTL8370MB_SMI_READ as _, &mut msg as *mut SmiMsg)
                };
                if ret < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(msg.val)
            }
            SmiBackend::Mdio {
                sock,
                ifname,
                phy_addr,
            } => {
                mdio_smi_read(sock, ifname, *phy_addr, reg_addr)
            }
        }
    }

    /// Unlock the switch for register access.
    pub fn unlock(&self) -> std::io::Result<()> {
        self.smi_write(SMI_ACCESS_REG, SMI_UNLOCK_VAL)
    }

    /// Lock the switch.
    pub fn lock(&self) -> std::io::Result<()> {
        self.smi_write(SMI_ACCESS_REG, SMI_LOCK_VAL)
    }

    /// Execute a closure with the switch unlocked, locking afterwards.
    pub fn with_unlock<F, T>(&self, f: F) -> std::io::Result<T>
    where
        F: FnOnce(&Self) -> std::io::Result<T>,
    {
        self.unlock()?;
        let result = f(self);
        let lock_result = self.lock();
        match result {
            Ok(val) => {
                lock_result?;
                Ok(val)
            }
            Err(e) => {
                let _ = lock_result;
                Err(e)
            }
        }
    }

    /// Returns true if using the atomic chardev backend.
    pub fn is_atomic(&self) -> bool {
        matches!(self.backend, SmiBackend::Chardev(_))
    }
}

// ── MDIO ioctl fallback implementation ──────────────────────────────

fn mdio_write(
    sock: &std::net::UdpSocket,
    ifname: &str,
    phy_addr: u8,
    reg: u16,
    val: u16,
) -> std::io::Result<()> {
    let mut ifr = Ifreq::new(ifname, phy_addr);
    ifr.ifr_data.reg_num = reg;
    ifr.ifr_data.val_in = val;

    // SAFETY: Valid fd, correctly sized ifreq (40 bytes matching kernel struct).
    let ret =
        unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSMIIREG as _, &ifr as *const Ifreq) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn mdio_read(
    sock: &std::net::UdpSocket,
    ifname: &str,
    phy_addr: u8,
    reg: u16,
) -> std::io::Result<u16> {
    let mut ifr = Ifreq::new(ifname, phy_addr);
    ifr.ifr_data.reg_num = reg;

    // SAFETY: Valid fd, correctly sized ifreq. Kernel writes result to val_out.
    let ret =
        unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGMIIREG as _, &mut ifr as *mut Ifreq) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ifr.ifr_data.val_out)
}

fn mdio_smi_write(
    sock: &std::net::UdpSocket,
    ifname: &str,
    phy_addr: u8,
    reg_addr: u16,
    value: u16,
) -> std::io::Result<()> {
    mdio_write(sock, ifname, phy_addr, 31, 0x000E)?;
    mdio_write(sock, ifname, phy_addr, 23, reg_addr)?;
    mdio_write(sock, ifname, phy_addr, 24, value)?;
    mdio_write(sock, ifname, phy_addr, 21, 0x0003)?;
    Ok(())
}

fn mdio_smi_read(
    sock: &std::net::UdpSocket,
    ifname: &str,
    phy_addr: u8,
    reg_addr: u16,
) -> std::io::Result<u16> {
    mdio_write(sock, ifname, phy_addr, 31, 0x000E)?;
    mdio_write(sock, ifname, phy_addr, 23, reg_addr)?;
    mdio_write(sock, ifname, phy_addr, 21, 0x0001)?;
    mdio_read(sock, ifname, phy_addr, 25)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_size_matches_kernel() {
        assert_eq!(
            std::mem::size_of::<Ifreq>(),
            40,
            "Ifreq must be 40 bytes to match kernel sizeof(struct ifreq) on 64-bit"
        );
    }

    #[test]
    fn smi_msg_size() {
        assert_eq!(std::mem::size_of::<SmiMsg>(), 4);
    }

    #[test]
    fn ifreq_name_fits() {
        let ifr = Ifreq::new("eth8", 0x1D);
        assert_eq!(&ifr.ifr_name[..4], b"eth8");
        assert_eq!(ifr.ifr_name[4], 0);
        assert_eq!(ifr.ifr_data.phy_id, 0x1D);
    }
}
