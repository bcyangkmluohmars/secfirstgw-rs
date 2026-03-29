#![deny(unsafe_code)]

//! # sfnas-storage
//!
//! Storage management for secfirstNAS.
//!
//! Unified storage stack:
//! ```text
//! Btrfs (single mode) → dm-crypt/LUKS → MD RAID (0/1/5/10) → SATA
//! ```
//!
//! Wraps `mdadm`, `cryptsetup`, `mkfs.btrfs`, and related tools to
//! provide a clean API for creating, managing, and monitoring the
//! full storage pipeline.

mod bay;
mod crypt;
mod disk;
mod disk_cache;
mod error;
mod filesystem;
mod led_service;
mod raid;
mod thermal;

pub use bay::{Bay, BayLedMode, BayState};
pub use crypt::{CryptStatus, CryptVolume};
pub use disk::{Disk, DiskHealth, SmartStatus};
pub use disk_cache::DiskCache;
pub use led_service::LedService;
pub use error::StorageError;
pub use filesystem::{BtrfsUsage, BtrfsVolume, ScrubStatus, SubvolumeInfo};
pub use raid::{MdstatEntry, RaidArray, RaidDetail, RaidLevel, RaidStatus};
pub use thermal::{FanProfile, ThermalManager, ThermalStatus};
