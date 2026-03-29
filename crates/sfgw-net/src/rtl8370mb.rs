// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! RTL8370MB switch ASIC driver.
//!
//! Register addresses and data formats from the Realtek RTL8367C SDK
//! (fabianishere/udm-kernel rtl83xx_api).
//!
//! # VLAN model
//!
//! The chip has two VLAN storage mechanisms:
//!
//! 1. **MC table** (Member Configuration) — 32 direct-mapped entries at
//!    `0x0728 + idx*4`. Each entry maps an MC index to a VID + port mask.
//!    Ports reference VLANs by MC index (not VID).
//!
//! 2. **4K table** — Full 4096-entry VLAN table, accessed indirectly via
//!    staging registers (0x0510) + control register (0x0500). This is the
//!    actual forwarding table.
//!
//! Both must be written for VLANs to work. Port PVID registers (0x0700)
//! store an MC table INDEX (5 bits), not a VID directly.

use crate::smi::SmiAccess;

// ── Register addresses (from rtl8367c_reg.h) ───────────────────────

// VLAN Member Config (MC) table: 4 regs per entry, 32 entries
// Entry layout:
//   Reg0: MBR[7:0] | MBR_EXT[10:8] in bits[8:10]
//   Reg1: FID_MSTI[3:0]
//   Reg2: VBPEN[0] | VBPRI[3:1] | ENVLANPOL[4] | METERIDX[10:5]
//   Reg3: EVID[12:0]  (the actual VLAN ID)
const VLAN_MC_BASE: u16 = 0x0728;

// Per-port PVID: stores MC table INDEX (5 bits per port, 2 ports per register)
// 0x0700: port 0 [4:0], port 1 [12:8]
// 0x0701: port 2 [4:0], port 3 [12:8]
// 0x0702: port 4 [4:0], port 5 [12:8]
// 0x0703: port 6 [4:0], port 7 [12:8]
// 0x0704: port 8 [4:0], port 9 [12:8]
// 0x0705: port 10 [4:0]
const VLAN_PVID_CTRL_BASE: u16 = 0x0700;

// 4K VLAN table indirect access
const TABLE_ACCESS_CTRL: u16 = 0x0500;
const TABLE_ACCESS_ADDR: u16 = 0x0501;
const TABLE_WRITE_DATA_BASE: u16 = 0x0510; // 0x0510-0x0512 (3 regs)
const TABLE_READ_DATA_BASE: u16 = 0x0520; // 0x0520-0x0522 (3 regs)

// Table access command: (op << 3) | target
// op: 0=read, 1=write. target: 3=CVLAN
const TABLE_CMD_WRITE_CVLAN: u16 = (1 << 3) | 3; // 0x000B
const TABLE_CMD_READ_CVLAN: u16 = (0 << 3) | 3; // 0x0003

// Switch Global Control Register — VLAN enable bits
const SGCR: u16 = 0x0000;
const SGCR_EN_VLAN: u16 = 1 << 13;
const SGCR_EN_VLAN_4KTB: u16 = 1 << 14;

// VLAN filter enable — RTL8367C_REG_VLAN_CTRL (0x07A8), bit 0 = global VLAN enable
const VLAN_CTRL: u16 = 0x07A8;

// Port isolation
const PORT_ISOLATION_BASE: u16 = 0x08A2;
// Port link status (read-only)
const PORT_STATUS_BASE: u16 = 0x1352;
// VLAN ingress filter
const VLAN_INGRESS_FILTER: u16 = 0x07A0;

// Chip ID
const CHIP_ID_REG: u16 = 0x1300;
const CHIP_VER_REG: u16 = 0x1301;

/// Max VLAN MC table entries.
pub const MAX_MC_ENTRIES: usize = 32;
/// Max switch port number.
pub const MAX_PORT: u8 = 10;
/// CPU port (EXT1).
pub const CPU_PORT: u8 = 9;

/// 4K VLAN table entry (written indirectly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vlan4kEntry {
    pub vid: u16,
    /// Member port bitmask [10:0].
    pub member: u16,
    /// Untag port bitmask [10:0].
    pub untag: u16,
    /// FID [3:0].
    pub fid: u8,
}

/// MC table entry (written directly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlanMcEntry {
    /// MC table index (0-31).
    pub index: u8,
    /// VLAN ID (EVID, 13 bits).
    pub vid: u16,
    /// Member port bitmask [10:0].
    pub member: u16,
    /// FID [3:0].
    pub fid: u8,
}

/// Port link status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct PortLink {
    pub up: bool,
    pub speed_mbps: u16,
    pub full_duplex: bool,
}

// ── Structured switch state (for API export) ──────────────────────

/// Complete switch ASIC state in a structured, JSON-serializable form.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SwitchState {
    pub chip_id: u16,
    pub chip_version: u16,
    pub global: GlobalConfig,
    pub ports: Vec<PortState>,
    pub mc_table: Vec<McTableEntry>,
    pub vlan_4k_table: Vec<Vlan4kState>,
}

/// Global switch configuration registers.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GlobalConfig {
    pub sgcr_raw: u16,
    pub vlan_enabled: bool,
    pub vlan_4k_enabled: bool,
    pub ingress_filter_raw: u16,
    pub stp_state: [u16; 2],
    pub ext_mode: u16,
    pub ext1_force: u16,
    pub ext1_rgmxf: u16,
    pub cpu_port_mask: u16,
    pub cpu_port_ctrl: u16,
}

/// Per-port state from the switch ASIC.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortState {
    pub port: u8,
    pub status_raw: u16,
    pub link_up: bool,
    pub speed_mbps: u16,
    pub full_duplex: bool,
    pub pvid_mc_index: u8,
    pub isolation_mask: u16,
}

/// MC (Member Configuration) table entry as read from ASIC.
#[derive(Debug, Clone, serde::Serialize)]
pub struct McTableEntry {
    pub index: u8,
    pub vid: u16,
    pub member_mask: u16,
    pub fid: u8,
}

/// 4K VLAN table entry as read from ASIC.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Vlan4kState {
    pub vid: u16,
    pub member_mask: u16,
    pub untag_mask: u16,
    pub fid: u8,
}

/// High-level RTL8370MB switch driver.
pub struct Rtl8370mb {
    smi: SmiAccess,
}

impl Rtl8370mb {
    /// Create a new driver instance.
    pub fn new(smi_iface: &str, phy_addr: u8) -> std::io::Result<Self> {
        Ok(Self {
            smi: SmiAccess::new(smi_iface, phy_addr)?,
        })
    }

    pub fn smi(&self) -> &SmiAccess {
        &self.smi
    }

    /// Verify chip ID. Returns `(chip_id, chip_ver)`.
    pub fn verify_chip(&self) -> std::io::Result<(u16, u16)> {
        self.smi.with_unlock(|smi| {
            let id = smi.smi_read(CHIP_ID_REG)?;
            let ver = smi.smi_read(CHIP_VER_REG)?;
            Ok((id, ver))
        })
    }

    // ── 4K VLAN table (indirect) ───────────────────────────────────

    /// Write a 4K VLAN table entry (indirect access).
    ///
    /// Data format (3 regs):
    ///   Reg0: MBR[7:0] | UNTAG[7:0] << 8
    ///   Reg1: FID[3:0] | flags...
    ///   Reg2: MBR_EXT[10:8] >> 8 | UNTAG_EXT[10:8] >> 8 << 3
    fn write_vlan_4k(&self, smi: &SmiAccess, entry: &Vlan4kEntry) -> std::io::Result<()> {
        let mut data = [0u16; 3];

        // Reg0: MBR low byte | UNTAG low byte
        data[0] = (entry.member & 0xFF) | ((entry.untag & 0xFF) << 8);
        // Reg1: FID[3:0] (other fields zero for basic VLAN)
        data[1] = u16::from(entry.fid) & 0x0F;
        // Reg2: MBR high bits[10:8] | UNTAG high bits[10:8]
        data[2] = ((entry.member >> 8) & 0x07) | (((entry.untag >> 8) & 0x07) << 3);

        // Write staging registers
        for (i, &val) in data.iter().enumerate() {
            smi.smi_write(TABLE_WRITE_DATA_BASE + i as u16, val)?;
        }

        // Set address = VID
        smi.smi_write(TABLE_ACCESS_ADDR, entry.vid)?;

        // Trigger write
        smi.smi_write(TABLE_ACCESS_CTRL, TABLE_CMD_WRITE_CVLAN)?;

        Ok(())
    }

    /// Read a 4K VLAN table entry (indirect access).
    fn read_vlan_4k(&self, smi: &SmiAccess, vid: u16) -> std::io::Result<Vlan4kEntry> {
        // Set address = VID
        smi.smi_write(TABLE_ACCESS_ADDR, vid)?;

        // Trigger read
        smi.smi_write(TABLE_ACCESS_CTRL, TABLE_CMD_READ_CVLAN)?;

        // Read result
        let d0 = smi.smi_read(TABLE_READ_DATA_BASE)?;
        let d1 = smi.smi_read(TABLE_READ_DATA_BASE + 1)?;
        let d2 = smi.smi_read(TABLE_READ_DATA_BASE + 2)?;

        let member = (d0 & 0xFF) | ((d2 & 0x07) << 8);
        let untag = ((d0 >> 8) & 0xFF) | (((d2 >> 3) & 0x07) << 8);
        let fid = (d1 & 0x0F) as u8;

        Ok(Vlan4kEntry {
            vid,
            member,
            untag,
            fid,
        })
    }

    // ── MC table (direct) ──────────────────────────────────────────

    /// Write a VLAN MC table entry.
    ///
    /// Layout (4 regs at 0x0728 + index*4):
    ///   Reg0: MBR[7:0] | MBR_EXT[10:8] in bits[8:10]
    ///   Reg1: FID_MSTI[3:0]
    ///   Reg2: 0 (VBPEN, VBPRI, ENVLANPOL, METERIDX — unused for basic VLAN)
    ///   Reg3: EVID[12:0]
    fn write_vlan_mc(&self, smi: &SmiAccess, entry: &VlanMcEntry) -> std::io::Result<()> {
        if entry.index as usize >= MAX_MC_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("MC index {} out of range", entry.index),
            ));
        }
        let base = VLAN_MC_BASE + u16::from(entry.index) * 4;

        // Reg0: MBR — low 8 bits + ext bits[10:8] in bits[8:10]
        let reg0 = (entry.member & 0xFF) | ((entry.member & 0x0700) >> 8 << 8);
        // Reg1: FID
        let reg1 = u16::from(entry.fid) & 0x0F;
        // Reg2: all zero (no metering/policing)
        let reg2 = 0u16;
        // Reg3: EVID
        let reg3 = entry.vid & 0x1FFF;

        smi.smi_write(base, reg0)?;
        smi.smi_write(base + 1, reg1)?;
        smi.smi_write(base + 2, reg2)?;
        smi.smi_write(base + 3, reg3)?;

        Ok(())
    }

    // ── Port PVID (MC index) ───────────────────────────────────────

    /// Write ALL port PVIDs at once — no read-modify-write.
    ///
    /// Two ports are packed per 16-bit register: even port in bits [4:0],
    /// odd port in bits [12:8]. Writing the full register avoids RMW issues
    /// where a stale read corrupts the adjacent port's PVID.
    ///
    /// `pvids` is a map from port number to MC table index. Ports not in
    /// the map get MC index 0 (VLAN 1 catch-all).
    fn write_all_pvids(&self, smi: &SmiAccess, pvids: &[(u8, u8)]) -> std::io::Result<()> {
        // Build a full port→mc_index lookup (ports 0–10, default 0)
        let mut mc_for_port = [0u8; (MAX_PORT + 1) as usize];
        for &(port, mc_idx) in pvids {
            if port <= MAX_PORT {
                mc_for_port[port as usize] = mc_idx;
            }
        }

        // Write registers 0x0700–0x0705 (two ports each, port 10 alone)
        for reg_idx in 0u16..=5 {
            let even_port = (reg_idx * 2) as usize;
            let odd_port = even_port + 1;

            let even_val = if even_port <= MAX_PORT as usize {
                u16::from(mc_for_port[even_port]) & 0x1F
            } else {
                0
            };
            let odd_val = if odd_port <= MAX_PORT as usize {
                u16::from(mc_for_port[odd_port]) & 0x1F
            } else {
                0
            };

            let val = even_val | (odd_val << 8);
            smi.smi_write(VLAN_PVID_CTRL_BASE + reg_idx, val)?;
        }

        Ok(())
    }

    /// Read port PVID MC index.
    pub fn read_pvid_index(&self, port: u8) -> std::io::Result<u8> {
        if port > MAX_PORT {
            return Err(port_out_of_range(port));
        }
        self.smi.with_unlock(|smi| {
            let reg = VLAN_PVID_CTRL_BASE + u16::from(port / 2);
            let val = smi.smi_read(reg)?;
            if port % 2 == 0 {
                Ok((val & 0x1F) as u8)
            } else {
                Ok(((val >> 8) & 0x1F) as u8)
            }
        })
    }

    // ── Port link status ───────────────────────────────────────────

    pub fn port_get_link(&self, port: u8) -> std::io::Result<PortLink> {
        if port > MAX_PORT {
            return Err(port_out_of_range(port));
        }
        let val = self.smi.smi_read(PORT_STATUS_BASE + u16::from(port))?;
        Ok(PortLink {
            up: val & (1 << 4) != 0,
            full_duplex: val & (1 << 2) != 0,
            speed_mbps: match val & 0x03 {
                0 => 10,
                1 => 100,
                2 => 1000,
                _ => 0,
            },
        })
    }

    // ── Port isolation ─────────────────────────────────────────────

    pub fn port_set_isolation(&self, port: u8, mask: u16) -> std::io::Result<()> {
        if port > MAX_PORT {
            return Err(port_out_of_range(port));
        }
        self.smi
            .smi_write(PORT_ISOLATION_BASE + u16::from(port), mask & 0x07FF)
    }

    pub fn port_get_isolation(&self, port: u8) -> std::io::Result<u16> {
        if port > MAX_PORT {
            return Err(port_out_of_range(port));
        }
        let val = self.smi.smi_read(PORT_ISOLATION_BASE + u16::from(port))?;
        Ok(val & 0x07FF)
    }

    // ── Bulk VLAN programming ──────────────────────────────────────

    /// Program complete VLAN configuration (unlock → write → verify → lock).
    ///
    /// For each VLAN:
    /// 1. Write 4K table entry (indirect) — actual forwarding table
    /// 2. Write MC table entry (direct) — index-to-VID mapping
    /// 3. Set port PVIDs to their MC table index
    ///
    /// `mc_entries` maps MC index → (VID, member mask, untag mask, FID).
    /// `pvids` maps port → MC index.
    pub fn apply_vlan_config(
        &self,
        mc_entries: &[VlanMcEntry],
        vlan_4k_entries: &[Vlan4kEntry],
        pvids: &[(u8, u8)], // (port, mc_index)
    ) -> std::io::Result<()> {
        self.smi.with_unlock(|smi| {
            // Write 4K table entries
            for entry in vlan_4k_entries {
                self.write_vlan_4k(smi, entry)?;

                // Verify by reading back
                let rb = self.read_vlan_4k(smi, entry.vid)?;
                if rb.member != entry.member || rb.untag != entry.untag || rb.fid != entry.fid {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "4K VLAN verify failed vid={}: wrote mbr=0x{:03X} untag=0x{:03X} fid={}, \
                             read mbr=0x{:03X} untag=0x{:03X} fid={}",
                            entry.vid, entry.member, entry.untag, entry.fid,
                            rb.member, rb.untag, rb.fid,
                        ),
                    ));
                }
            }

            // Write MC table entries
            for entry in mc_entries {
                self.write_vlan_mc(smi, entry)?;
            }

            // Set ALL port PVIDs at once (full register writes, no RMW)
            self.write_all_pvids(smi, pvids)?;

            // Enable VLAN processing globally (MUST be set or all VLAN tables are ignored)
            let sgcr = smi.smi_read(SGCR)?;
            smi.smi_write(SGCR, sgcr | SGCR_EN_VLAN | SGCR_EN_VLAN_4KTB)?;
            // RTL8367C/RTL8370B: real VLAN enable is VLAN_CTRL (0x07A8) bit 0
            let vctrl = smi.smi_read(VLAN_CTRL)?;
            smi.smi_write(VLAN_CTRL, vctrl | 0x0001)?;

            // EXT1 (CPU port 9): force RGMII 1G full-duplex link-up.
            //
            // RTL8370B (type 2): 0x1311 must be written bit-by-bit (RMW),
            // then link-toggled, then mirrored to SDS_MISC (0x1D11).
            // See SDK rtl8367c_setAsicPortForceLinkExt() type==2, id==1.

            // 0x1305 bits[7:4] = EXT1 mode, 0x1 = RGMII
            let ext_mode = smi.smi_read(0x1305)?;
            smi.smi_write(0x1305, (ext_mode & 0xFF0F) | (0x0001 << 4))?;

            // 0x1311: set individual bits via read-modify-write
            let mut reg = smi.smi_read(0x1311)?;
            reg = (reg & !0x0003) | 0x0002;  // bits[1:0] speed = 2 (1G)
            reg = set_bit(reg, 2, true);      // duplex = full
            reg = set_bit(reg, 4, true);      // link = up
            reg = set_bit(reg, 5, false);     // rxpause = 0
            reg = set_bit(reg, 6, false);     // txpause = 0
            reg = set_bit(reg, 12, true);     // forcemode = on
            smi.smi_write(0x1311, reg)?;

            // Link toggle: clear bit 4, then set bit 4 (forces MAC re-link)
            smi.smi_write(0x1311, reg & !(1 << 4))?;
            smi.smi_write(0x1311, reg | (1 << 4))?;

            // Mirror to SDS_MISC (0x1D11) — SGMII SerDes side
            let mut sds = smi.smi_read(0x1D11)?;
            sds = set_bit(sds, 10, true);               // CFG_SGMII_FDUP = 1
            sds = (sds & !0x0180) | (0x0002 << 7);      // CFG_SGMII_SPD = 2 (1G)
            sds = set_bit(sds, 9, true);                 // CFG_SGMII_LINK = 1
            sds = set_bit(sds, 13, false);               // CFG_SGMII_TXFC = 0
            sds = set_bit(sds, 14, false);               // CFG_SGMII_RXFC = 0
            smi.smi_write(0x1D11, sds)?;

            let ext1_verify = smi.smi_read(0x1311)?;
            tracing::info!(ext1 = format!("0x{ext1_verify:04X}"), "EXT1 force after config");

            // Set VLAN egress tag mode to ORIGINAL (0) for all ports.
            // PORT_MISC_CFG bits[5:4] = egress mode. Default on RTL8370B is
            // 3 (REAL_KEEP) which bypasses tag stripping entirely.
            // Mode 0 uses the 4K table untag mask: tagged if not in untag,
            // stripped if in untag. Required for VLAN trunking to work.
            for p in 0..=MAX_PORT {
                let reg = 0x000E + u16::from(p) * 0x20;
                let val = smi.smi_read(reg)?;
                smi.smi_write(reg, val & !0x0030)?; // clear bits[5:4]
            }

            // Enable ingress filtering on LAN ports (0-7) + CPU (9)
            smi.smi_write(VLAN_INGRESS_FILTER, 0x02FF)?;

            Ok(())
        })
    }

    /// Read a port's PVID MC index with unlock/lock (for watchdog).
    pub fn read_pvid_locked(&self, port: u8) -> std::io::Result<u8> {
        self.read_pvid_index(port)
    }

    // ── Structured state export ─────────────────────────────────

    /// Read complete switch ASIC state as structured data.
    ///
    /// Returns all port statuses, VLAN tables, isolation masks, and global
    /// configuration in a JSON-serializable form for the web UI.
    #[must_use = "switch state read result must be checked"]
    pub fn read_state(&self) -> std::io::Result<SwitchState> {
        let (chip_id, chip_ver) = self
            .smi
            .with_unlock(|smi| Ok((smi.smi_read(CHIP_ID_REG)?, smi.smi_read(CHIP_VER_REG)?)))?;

        self.smi.with_unlock(|smi| {
            // Global config
            let sgcr = smi.smi_read(SGCR)?;
            let vlan_ctrl = smi.smi_read(VLAN_CTRL)?;
            let ing = smi.smi_read(VLAN_INGRESS_FILTER)?;
            let stp0 = smi.smi_read(0x0A00)?;
            let stp1 = smi.smi_read(0x0A01)?;
            let ext_mode = smi.smi_read(0x1305)?;
            let ext1_force = smi.smi_read(0x1311)?;
            let ext1_rgmxf = smi.smi_read(0x1307)?;
            let cpu_mask = smi.smi_read(0x1219)?;
            let cpu_ctrl = smi.smi_read(0x121A)?;

            let global = GlobalConfig {
                sgcr_raw: sgcr,
                vlan_enabled: vlan_ctrl & 1 != 0,
                vlan_4k_enabled: vlan_ctrl & 1 != 0, // RTL8367C: 4K table always active when VLAN enabled
                ingress_filter_raw: ing,
                stp_state: [stp0, stp1],
                ext_mode,
                ext1_force,
                ext1_rgmxf,
                cpu_port_mask: cpu_mask,
                cpu_port_ctrl: cpu_ctrl,
            };

            // Per-port state
            let mut ports = Vec::with_capacity((MAX_PORT + 1) as usize);
            for p in 0..=MAX_PORT {
                let status = smi.smi_read(PORT_STATUS_BASE + u16::from(p))?;
                let link_up = (status >> 4) & 1 != 0;
                let speed_mbps = match status & 0x03 {
                    0 => 10,
                    1 => 100,
                    2 => 1000,
                    _ => 0,
                };
                let full_duplex = (status >> 2) & 1 != 0;

                // PVID MC index
                let pvid_reg = smi.smi_read(VLAN_PVID_CTRL_BASE + u16::from(p / 2))?;
                let pvid_mc = if p % 2 == 0 {
                    (pvid_reg & 0x1F) as u8
                } else {
                    ((pvid_reg >> 8) & 0x1F) as u8
                };

                // Isolation mask
                let iso = smi.smi_read(PORT_ISOLATION_BASE + u16::from(p))? & 0x07FF;

                ports.push(PortState {
                    port: p,
                    status_raw: status,
                    link_up,
                    speed_mbps,
                    full_duplex,
                    pvid_mc_index: pvid_mc,
                    isolation_mask: iso,
                });
            }

            // MC table (non-empty entries only)
            let mut mc_table = Vec::new();
            for idx in 0u8..MAX_MC_ENTRIES as u8 {
                let base = VLAN_MC_BASE + u16::from(idx) * 4;
                let r0 = smi.smi_read(base)?;
                let r1 = smi.smi_read(base + 1)?;
                let r3 = smi.smi_read(base + 3)?;
                let vid = r3 & 0x1FFF;
                let mbr = (r0 & 0xFF) | (((r0 >> 8) & 0x07) << 8);
                let fid = (r1 & 0x0F) as u8;
                if vid == 0 && mbr == 0 {
                    continue;
                }
                mc_table.push(McTableEntry {
                    index: idx,
                    vid,
                    member_mask: mbr,
                    fid,
                });
            }

            // 4K VLAN table — read entries for VIDs referenced by MC table + VID 1
            let mut vids_to_check = vec![1u16];
            for mc in &mc_table {
                if mc.vid > 1 && !vids_to_check.contains(&mc.vid) {
                    vids_to_check.push(mc.vid);
                }
            }
            vids_to_check.sort_unstable();

            let mut vlan_4k_table = Vec::new();
            for vid in vids_to_check {
                let entry = self.read_vlan_4k(smi, vid)?;
                vlan_4k_table.push(Vlan4kState {
                    vid: entry.vid,
                    member_mask: entry.member,
                    untag_mask: entry.untag,
                    fid: entry.fid,
                });
            }

            Ok(SwitchState {
                chip_id,
                chip_version: chip_ver,
                global,
                ports,
                mc_table,
                vlan_4k_table,
            })
        })
    }

    // ── Debug / diagnostic reads ──────────────────────────────────

    /// Read a raw register (for diagnostics). Caller handles unlock if needed.
    pub fn raw_read(&self, reg: u16) -> std::io::Result<u16> {
        self.smi.smi_read(reg)
    }

    /// Dump complete switch state for debugging.
    ///
    /// Reads all relevant registers and returns a human-readable report.
    /// Uses `with_unlock` for registers that need it.
    pub fn dump_state(&self) -> std::io::Result<String> {
        let mut out = String::with_capacity(4096);

        // Chip ID
        let (chip_id, chip_ver) = self
            .smi
            .with_unlock(|smi| Ok((smi.smi_read(CHIP_ID_REG)?, smi.smi_read(CHIP_VER_REG)?)))?;
        out.push_str(&format!(
            "Chip: id=0x{chip_id:04X} ver=0x{chip_ver:04X}\n\n"
        ));

        self.smi.with_unlock(|smi| {
            // Global control
            let sgcr = smi.smi_read(SGCR)?;
            out.push_str(&format!(
                "SGCR(0x0000): 0x{sgcr:04X}  vlan_en={} 4k_en={}\n\n",
                (sgcr >> 13) & 1,
                (sgcr >> 14) & 1
            ));

            // Port status
            out.push_str("=== Port Status ===\n");
            for p in 0..=MAX_PORT {
                let val = smi.smi_read(PORT_STATUS_BASE + u16::from(p))?;
                let up = (val >> 4) & 1 != 0;
                let speed = match val & 0x03 {
                    0 => "10M",
                    1 => "100M",
                    2 => "1G",
                    _ => "?",
                };
                let duplex = if (val >> 2) & 1 != 0 { "FD" } else { "HD" };
                out.push_str(&format!(
                    "  P{p:2}: {}{speed}/{duplex}  (raw=0x{val:04X})\n",
                    if up { "UP   " } else { "DOWN " }
                ));
            }

            // PVID registers
            out.push_str("\n=== PVID (MC index) ===\n");
            for i in 0u16..=5 {
                let val = smi.smi_read(VLAN_PVID_CTRL_BASE + i)?;
                let even = i * 2;
                let odd = even + 1;
                out.push_str(&format!(
                    "  0x{:04X}={val:04X}  P{}:MC={} P{}:MC={}\n",
                    VLAN_PVID_CTRL_BASE + i,
                    even,
                    val & 0x1F,
                    odd,
                    (val >> 8) & 0x1F
                ));
            }

            // MC table
            out.push_str("\n=== MC Table ===\n");
            for idx in 0u8..MAX_MC_ENTRIES as u8 {
                let base = VLAN_MC_BASE + u16::from(idx) * 4;
                let r0 = smi.smi_read(base)?;
                let r1 = smi.smi_read(base + 1)?;
                let r3 = smi.smi_read(base + 3)?;
                let vid = r3 & 0x1FFF;
                let mbr = (r0 & 0xFF) | (((r0 >> 8) & 0x07) << 8);
                let fid = r1 & 0x0F;
                if vid == 0 && mbr == 0 {
                    continue; // skip empty
                }
                out.push_str(&format!(
                    "  MC[{idx:2}]: VID={vid:4}  MBR=0x{mbr:03X}  FID={fid}\n"
                ));
            }

            // 4K table for configured VLANs
            out.push_str("\n=== 4K VLAN Table ===\n");
            // Read which VIDs are in MC table, plus always check 1
            let mut vids_to_check = vec![1u16];
            for idx in 0u8..MAX_MC_ENTRIES as u8 {
                let base = VLAN_MC_BASE + u16::from(idx) * 4;
                let r3 = smi.smi_read(base + 3)?;
                let vid = r3 & 0x1FFF;
                if vid > 1 && !vids_to_check.contains(&vid) {
                    vids_to_check.push(vid);
                }
            }
            vids_to_check.sort();
            for vid in &vids_to_check {
                let entry = self.read_vlan_4k(smi, *vid)?;
                out.push_str(&format!(
                    "  VID={:4}: MBR=0x{:03X}  UNTAG=0x{:03X}  FID={}\n",
                    entry.vid, entry.member, entry.untag, entry.fid
                ));
            }

            // Port isolation
            out.push_str("\n=== Port Isolation ===\n");
            for p in 0..=MAX_PORT {
                let val = smi.smi_read(PORT_ISOLATION_BASE + u16::from(p))? & 0x07FF;
                out.push_str(&format!("  P{p:2}: mask=0x{val:03X}\n"));
            }

            // Ingress filter
            let ing = smi.smi_read(VLAN_INGRESS_FILTER)?;
            out.push_str(&format!("\nIngress filter: 0x{ing:04X}\n"));

            // STP state
            let stp0 = smi.smi_read(0x0A00)?;
            let stp1 = smi.smi_read(0x0A01)?;
            out.push_str(&format!("\nSTP: 0x{stp0:04X} 0x{stp1:04X}  (3=FWD per 2-bit port)\n"));

            // EXT1 force config
            let ext_mode = smi.smi_read(0x1305)?;
            let ext1_force = smi.smi_read(0x1311)?;
            let ext1_rgmxf = smi.smi_read(0x1307)?;
            out.push_str(&format!(
                "\nEXT mode: 0x{ext_mode:04X}  EXT1 force: 0x{ext1_force:04X}  RGMXF: 0x{ext1_rgmxf:04X}\n"
            ));

            // CPU port config
            let cpu_mask = smi.smi_read(0x1219)?;
            let cpu_ctrl = smi.smi_read(0x121A)?;
            out.push_str(&format!(
                "CPU port: mask=0x{cpu_mask:04X} ctrl=0x{cpu_ctrl:04X}\n"
            ));

            Ok(())
        })?;

        Ok(out)
    }
}

/// Set or clear a single bit in a 16-bit register value.
const fn set_bit(val: u16, bit: u8, on: bool) -> u16 {
    if on {
        val | (1 << bit)
    } else {
        val & !(1 << bit)
    }
}

fn port_out_of_range(port: u8) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("port {port} out of range (max {MAX_PORT})"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vlan_4k_data_format() {
        // VLAN 10: ports 0-6 + CPU(9), untag 0-6
        let entry = Vlan4kEntry {
            vid: 10,
            member: 0x027F, // bits 0-6 + 9
            untag: 0x007F,  // bits 0-6
            fid: 1,
        };

        // Reg0: MBR[7:0]=0x7F | UNTAG[7:0]=0x7F << 8 = 0x7F7F
        let d0 = (entry.member & 0xFF) | ((entry.untag & 0xFF) << 8);
        assert_eq!(d0, 0x7F7F);

        // Reg1: FID=1
        let d1 = u16::from(entry.fid) & 0x0F;
        assert_eq!(d1, 0x0001);

        // Reg2: MBR[10:8]=0x02 >> 8 = 0x02 | UNTAG[10:8]=0x00 << 3 = 0x02
        let d2 = ((entry.member >> 8) & 0x07) | (((entry.untag >> 8) & 0x07) << 3);
        assert_eq!(d2, 0x0002);
    }

    #[test]
    fn vlan_mc_reg_layout() {
        // MC entry: VID=10, members=0x027F (ports 0-6 + 9), fid=1
        let member: u16 = 0x027F;
        let vid: u16 = 10;
        let fid: u8 = 1;

        // Reg0: MBR low 8 bits + ext bits
        let reg0 = (member & 0xFF) | ((member & 0x0700) >> 8 << 8);
        // member = 0x027F → low=0x7F, ext=(0x0200>>8)=0x02, reg0 = 0x7F | (0x02 << 8) = 0x027F
        assert_eq!(reg0, 0x027F);

        // Reg1: FID
        assert_eq!(u16::from(fid) & 0x0F, 1);

        // Reg3: EVID
        assert_eq!(vid & 0x1FFF, 10);
    }

    #[test]
    fn table_access_commands() {
        assert_eq!(TABLE_CMD_WRITE_CVLAN, 0x000B);
        assert_eq!(TABLE_CMD_READ_CVLAN, 0x0003);
    }
}
