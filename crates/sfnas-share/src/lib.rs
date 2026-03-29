#![deny(unsafe_code)]

//! # sfnas-share
//!
//! SMB3 file sharing management for secfirstNAS.
//!
//! Provides a complete share management stack:
//!
//! - **Samba configuration** — generate, parse, load, and save `smb.conf`
//!   with security-hardened defaults (SMB3 minimum, mandatory signing,
//!   required encryption).
//!
//! - **Share management** — create, modify, and remove SMB shares with
//!   per-user permissions and btrfs quota support. Includes templates
//!   for common share types (public, private, Time Machine).
//!
//! - **User management** — create and manage NAS users (system accounts +
//!   Samba password database) with no-login shells.
//!
//! - **rsync server** — generate `rsyncd.conf` for backup synchronization
//!   with authentication and host-based access control.
//!
//! ## Security defaults
//!
//! - SMB3 minimum protocol version (no SMBv1/SMBv2)
//! - Mandatory signing on all connections
//! - Required encryption on all connections
//! - NetBIOS disabled (port 445 only)
//! - No guest mapping by default
//! - Passwords passed via stdin, never on the command line
//! - rsync secrets file restricted to mode 600

mod error;
mod rsync;
mod samba;
mod share;
mod user;

pub use error::ShareError;
pub use rsync::{RsyncConfig, RsyncModule};
pub use samba::SambaConfig;
pub use share::{Share, SharePermission, UserQuota};
pub use user::{NasUser, ensure_nas_group};
