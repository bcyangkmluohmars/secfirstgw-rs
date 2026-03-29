#![deny(unsafe_code)]

use crate::ShareError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Permission level for a user on a share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SharePermission {
    /// Read-only access to share contents.
    ReadOnly,
    /// Read and write access to share contents.
    ReadWrite,
    /// Full control including permission management.
    Full,
}

/// Per-user quota on a share (requires btrfs qgroups).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserQuota {
    /// Username this quota applies to.
    pub user: String,
    /// Maximum bytes the user may consume.
    pub quota_bytes: u64,
}

/// Represents an SMB share with full configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    /// Share name as it appears in `[section]` of smb.conf.
    pub name: String,
    /// Filesystem path the share exposes.
    pub path: PathBuf,
    /// Human-readable description of the share.
    pub comment: String,
    /// Whether the share is visible in network browsing.
    pub browseable: bool,
    /// Whether the share is read-only.
    pub read_only: bool,
    /// List of users allowed to access this share (empty = all authenticated).
    pub valid_users: Vec<String>,
    /// List of users with write access (even if share is read-only).
    pub write_list: Vec<String>,
    /// Whether guest (unauthenticated) access is allowed.
    pub guest_ok: bool,
    /// Per-user permission overrides.
    pub permissions: BTreeMap<String, SharePermission>,
    /// Per-user quotas (btrfs qgroups).
    pub quotas: Vec<UserQuota>,
    /// Additional smb.conf parameters for this share section.
    pub extra_params: BTreeMap<String, String>,
}

impl Share {
    /// Create a new share with secure defaults.
    ///
    /// The share is created as browseable, read-write, no guest access,
    /// with SMB3 mandatory signing and encryption.
    #[must_use]
    pub fn new(name: &str, path: PathBuf) -> Self {
        Self {
            name: name.to_string(),
            path,
            comment: String::new(),
            browseable: true,
            read_only: false,
            valid_users: Vec::new(),
            write_list: Vec::new(),
            guest_ok: false,
            permissions: BTreeMap::new(),
            quotas: Vec::new(),
            extra_params: BTreeMap::new(),
        }
    }

    /// Create a guest-accessible, read-only public share.
    ///
    /// Suitable for distributing files to all network users without authentication.
    /// The share enforces SMB3 signing and encryption regardless of guest access.
    #[must_use]
    pub fn public(name: &str, path: PathBuf) -> Self {
        Self {
            name: name.to_string(),
            path,
            comment: format!("Public share: {name}"),
            browseable: true,
            read_only: true,
            valid_users: Vec::new(),
            write_list: Vec::new(),
            guest_ok: true,
            permissions: BTreeMap::new(),
            quotas: Vec::new(),
            extra_params: BTreeMap::new(),
        }
    }

    /// Create an authenticated read-write share for specific users.
    ///
    /// Only the listed users may access the share. All listed users get
    /// read-write access by default.
    #[must_use]
    pub fn private(name: &str, path: PathBuf, users: &[&str]) -> Self {
        let user_list: Vec<String> = users.iter().map(|u| (*u).to_string()).collect();
        Self {
            name: name.to_string(),
            path,
            comment: format!("Private share: {name}"),
            browseable: true,
            read_only: false,
            valid_users: user_list.clone(),
            write_list: user_list,
            guest_ok: false,
            permissions: BTreeMap::new(),
            quotas: Vec::new(),
            extra_params: BTreeMap::new(),
        }
    }

    /// Create a macOS Time Machine backup target for a single user.
    ///
    /// Configures the share with `fruit:time machine = yes` for automatic
    /// discovery by macOS clients. The share is restricted to the specified
    /// user and is not browseable to reduce attack surface.
    #[must_use]
    pub fn timemachine(name: &str, path: PathBuf, user: &str) -> Self {
        let mut extra_params = BTreeMap::new();
        extra_params.insert(
            "vfs objects".to_string(),
            "catia fruit streams_xattr acl_xattr".to_string(),
        );
        extra_params.insert("fruit:time machine".to_string(), "yes".to_string());
        extra_params.insert("fruit:time machine max size".to_string(), "0".to_string());
        extra_params.insert("fruit:metadata".to_string(), "stream".to_string());
        extra_params.insert("fruit:model".to_string(), "MacSamba".to_string());

        Self {
            name: name.to_string(),
            path,
            comment: format!("Time Machine backup for {user}"),
            browseable: false,
            read_only: false,
            valid_users: vec![user.to_string()],
            write_list: vec![user.to_string()],
            guest_ok: false,
            permissions: BTreeMap::new(),
            quotas: Vec::new(),
            extra_params,
        }
    }

    /// Parse a share from an smb.conf section.
    ///
    /// `section_name` is the `[name]` without brackets. `config_lines` are
    /// the key=value lines belonging to this section (without the section header).
    pub fn from_smb_conf(section_name: &str, config_lines: &[&str]) -> Result<Self, ShareError> {
        let mut share = Self::new(section_name, PathBuf::new());

        for line in config_lines {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }

            // Split on first '=' only
            let (key, value) = match trimmed.split_once('=') {
                Some((k, v)) => (k.trim().to_lowercase(), v.trim().to_string()),
                None => continue,
            };

            match key.as_str() {
                "path" => {
                    share.path = PathBuf::from(&value);
                }
                "comment" => {
                    share.comment = value;
                }
                "browseable" | "browsable" => {
                    share.browseable = smb_bool(&value);
                }
                "read only" | "read_only" => {
                    share.read_only = smb_bool(&value);
                }
                "writable" | "writeable" | "write ok" => {
                    // writable is the inverse of read_only
                    share.read_only = !smb_bool(&value);
                }
                "valid users" | "valid_users" => {
                    share.valid_users = split_user_list(&value);
                }
                "write list" | "write_list" => {
                    share.write_list = split_user_list(&value);
                }
                "guest ok" | "guest_ok" | "public" => {
                    share.guest_ok = smb_bool(&value);
                }
                _ => {
                    share.extra_params.insert(key, value);
                }
            }
        }

        if share.path.as_os_str().is_empty() {
            return Err(ShareError::Config(format!(
                "share '{section_name}' has no path defined"
            )));
        }

        Ok(share)
    }

    /// Set the permission level for a specific user on this share.
    ///
    /// Updates `valid_users` and `write_list` to match the permission level.
    pub fn set_permission(&mut self, user: &str, permission: SharePermission) {
        self.permissions.insert(user.to_string(), permission);

        // Ensure user is in valid_users
        if !self.valid_users.iter().any(|u| u == user) {
            self.valid_users.push(user.to_string());
        }

        match permission {
            SharePermission::ReadOnly => {
                // Remove from write_list if present
                self.write_list.retain(|u| u != user);
            }
            SharePermission::ReadWrite | SharePermission::Full => {
                // Add to write_list if not present
                if !self.write_list.iter().any(|u| u == user) {
                    self.write_list.push(user.to_string());
                }
            }
        }
    }

    /// Set a disk quota for a user on this share.
    ///
    /// Requires btrfs qgroups to be enabled on the underlying filesystem.
    /// A `quota_bytes` of 0 removes any existing quota for the user.
    pub fn set_quota(&mut self, user: &str, quota_bytes: u64) {
        // Remove existing quota for this user
        self.quotas.retain(|q| q.user != user);

        if quota_bytes > 0 {
            self.quotas.push(UserQuota {
                user: user.to_string(),
                quota_bytes,
            });
        }
    }

    /// Generate the smb.conf section for this share.
    ///
    /// Produces a complete `[name]` section including security defaults
    /// (mandatory signing, required encryption).
    #[must_use]
    pub fn to_smb_conf(&self) -> String {
        let mut conf = format!("[{}]\n", self.name);
        conf.push_str(&format!("    path = {}\n", self.path.display()));

        if !self.comment.is_empty() {
            conf.push_str(&format!("    comment = {}\n", self.comment));
        }

        conf.push_str(&format!(
            "    browseable = {}\n",
            if self.browseable { "yes" } else { "no" }
        ));
        conf.push_str(&format!(
            "    read only = {}\n",
            if self.read_only { "yes" } else { "no" }
        ));

        if !self.valid_users.is_empty() {
            conf.push_str(&format!(
                "    valid users = {}\n",
                self.valid_users.join(" ")
            ));
        }

        if !self.write_list.is_empty() {
            conf.push_str(&format!("    write list = {}\n", self.write_list.join(" ")));
        }

        conf.push_str(&format!(
            "    guest ok = {}\n",
            if self.guest_ok { "yes" } else { "no" }
        ));

        // Security defaults — only if not overridden by extra_params
        if !self.extra_params.contains_key("server signing") {
            conf.push_str("    server signing = mandatory\n");
        }
        if !self.extra_params.contains_key("smb encrypt") {
            conf.push_str("    smb encrypt = required\n");
        }
        if !self.extra_params.contains_key("vfs objects") {
            conf.push_str("    vfs objects = acl_xattr\n");
        }

        // Extra parameters (sorted for deterministic output)
        for (key, value) in &self.extra_params {
            conf.push_str(&format!("    {key} = {value}\n"));
        }

        conf
    }
}

/// Parse an smb.conf boolean value.
///
/// Samba accepts `yes`, `no`, `true`, `false`, `1`, `0`.
#[must_use]
fn smb_bool(value: &str) -> bool {
    matches!(value.to_lowercase().as_str(), "yes" | "true" | "1")
}

/// Split an smb.conf user list (space or comma separated).
fn split_user_list(value: &str) -> Vec<String> {
    value
        .split([' ', ',', '\t'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_share_defaults() {
        let share = Share::new("test", PathBuf::from("/data/shares/test"));
        assert_eq!(share.name, "test");
        assert!(!share.read_only);
        assert!(share.browseable);
        assert!(!share.guest_ok);
        assert!(share.valid_users.is_empty());
    }

    #[test]
    fn test_public_share() {
        let share = Share::public("pub", PathBuf::from("/data/shares/pub"));
        assert!(share.read_only);
        assert!(share.guest_ok);
        assert!(share.browseable);
    }

    #[test]
    fn test_private_share() {
        let share = Share::private(
            "priv",
            PathBuf::from("/data/shares/priv"),
            &["alice", "bob"],
        );
        assert!(!share.read_only);
        assert!(!share.guest_ok);
        assert_eq!(share.valid_users, vec!["alice", "bob"]);
        assert_eq!(share.write_list, vec!["alice", "bob"]);
    }

    #[test]
    fn test_timemachine_share() {
        let share = Share::timemachine("tm-alice", PathBuf::from("/data/tm/alice"), "alice");
        assert!(!share.browseable);
        assert!(!share.read_only);
        assert_eq!(share.valid_users, vec!["alice"]);
        assert!(share.extra_params.contains_key("fruit:time machine"));
        assert_eq!(
            share
                .extra_params
                .get("fruit:time machine")
                .map(String::as_str),
            Some("yes")
        );
    }

    #[test]
    fn test_from_smb_conf_basic() {
        let lines = vec![
            "    path = /data/shares/media",
            "    comment = Media files",
            "    browseable = yes",
            "    read only = no",
            "    valid users = alice bob",
            "    guest ok = no",
        ];

        let share = Share::from_smb_conf("media", &lines);
        // INVARIANT: valid config lines must parse
        let share = share.expect("valid config");

        assert_eq!(share.name, "media");
        assert_eq!(share.path, PathBuf::from("/data/shares/media"));
        assert_eq!(share.comment, "Media files");
        assert!(share.browseable);
        assert!(!share.read_only);
        assert_eq!(share.valid_users, vec!["alice", "bob"]);
        assert!(!share.guest_ok);
    }

    #[test]
    fn test_from_smb_conf_writable_inverse() {
        let lines = vec!["    path = /data/shares/rw", "    writable = yes"];

        let share = Share::from_smb_conf("rw", &lines);
        // INVARIANT: valid config lines must parse
        let share = share.expect("valid config");
        assert!(!share.read_only);
    }

    #[test]
    fn test_from_smb_conf_missing_path() {
        let lines = vec!["    comment = No path share", "    browseable = yes"];

        let result = Share::from_smb_conf("bad", &lines);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_permission_readonly() {
        let mut share = Share::new("test", PathBuf::from("/data/test"));
        share.set_permission("alice", SharePermission::ReadOnly);

        assert!(share.valid_users.contains(&"alice".to_string()));
        assert!(!share.write_list.contains(&"alice".to_string()));
    }

    #[test]
    fn test_set_permission_readwrite() {
        let mut share = Share::new("test", PathBuf::from("/data/test"));
        share.set_permission("bob", SharePermission::ReadWrite);

        assert!(share.valid_users.contains(&"bob".to_string()));
        assert!(share.write_list.contains(&"bob".to_string()));
    }

    #[test]
    fn test_set_permission_upgrade_downgrade() {
        let mut share = Share::new("test", PathBuf::from("/data/test"));

        // Grant write
        share.set_permission("carol", SharePermission::ReadWrite);
        assert!(share.write_list.contains(&"carol".to_string()));

        // Downgrade to read-only
        share.set_permission("carol", SharePermission::ReadOnly);
        assert!(!share.write_list.contains(&"carol".to_string()));
        // Still in valid_users
        assert!(share.valid_users.contains(&"carol".to_string()));
    }

    #[test]
    fn test_set_quota() {
        let mut share = Share::new("test", PathBuf::from("/data/test"));

        // Set quota
        share.set_quota("alice", 1_073_741_824); // 1 GiB
        assert_eq!(share.quotas.len(), 1);
        assert_eq!(share.quotas[0].user, "alice");
        assert_eq!(share.quotas[0].quota_bytes, 1_073_741_824);

        // Update quota
        share.set_quota("alice", 2_147_483_648); // 2 GiB
        assert_eq!(share.quotas.len(), 1);
        assert_eq!(share.quotas[0].quota_bytes, 2_147_483_648);

        // Remove quota (set to 0)
        share.set_quota("alice", 0);
        assert!(share.quotas.is_empty());
    }

    #[test]
    fn test_to_smb_conf_output() {
        let share = Share::private("docs", PathBuf::from("/data/docs"), &["alice"]);
        let conf = share.to_smb_conf();

        assert!(conf.contains("[docs]"));
        assert!(conf.contains("path = /data/docs"));
        assert!(conf.contains("valid users = alice"));
        assert!(conf.contains("write list = alice"));
        assert!(conf.contains("guest ok = no"));
        assert!(conf.contains("server signing = mandatory"));
        assert!(conf.contains("smb encrypt = required"));
    }

    #[test]
    fn test_to_smb_conf_timemachine_has_fruit() {
        let share = Share::timemachine("tm", PathBuf::from("/data/tm"), "alice");
        let conf = share.to_smb_conf();

        assert!(conf.contains("fruit:time machine = yes"));
        assert!(conf.contains("vfs objects = catia fruit streams_xattr acl_xattr"));
        // Should NOT have the default vfs objects line since extra_params overrides it
        let vfs_count = conf.matches("vfs objects").count();
        assert_eq!(vfs_count, 1, "vfs objects should appear exactly once");
    }

    #[test]
    fn test_smb_bool_values() {
        assert!(smb_bool("yes"));
        assert!(smb_bool("Yes"));
        assert!(smb_bool("YES"));
        assert!(smb_bool("true"));
        assert!(smb_bool("1"));
        assert!(!smb_bool("no"));
        assert!(!smb_bool("false"));
        assert!(!smb_bool("0"));
        assert!(!smb_bool("anything"));
    }

    #[test]
    fn test_split_user_list() {
        assert_eq!(split_user_list("alice bob"), vec!["alice", "bob"]);
        assert_eq!(split_user_list("alice,bob"), vec!["alice", "bob"]);
        assert_eq!(split_user_list("  alice  bob  "), vec!["alice", "bob"]);
        assert!(split_user_list("").is_empty());
    }
}
