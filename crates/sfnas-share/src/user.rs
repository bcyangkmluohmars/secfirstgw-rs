#![deny(unsafe_code)]

//! NAS user management — system users and Samba password database.
//!
//! Users are created as system users with `/sbin/nologin` shell (no SSH access)
//! and a home directory under `/data/home/`. Samba passwords are managed via
//! `smbpasswd` with passwords provided through stdin (never on the command line).

use crate::{SambaConfig, ShareError};
use std::process::Command;
use tracing::{debug, error, info, warn};

/// Default home directory base for NAS users.
const HOME_BASE: &str = "/data/home";

/// Shell assigned to NAS users (no interactive login).
const NOLOGIN_SHELL: &str = "/sbin/nologin";

/// Path to the Samba password database for listing users.
const PASSDB_PATH: &str = "/data/config/samba/passdb.tdb";

/// A NAS user account (system + Samba).
#[derive(Debug, Clone)]
pub struct NasUser {
    /// System username (alphanumeric + underscore + hyphen, 1-32 chars).
    pub username: String,
}

impl NasUser {
    /// Create a new NAS user (both system account and Samba password).
    ///
    /// The system user is created with:
    /// - Shell: `/sbin/nologin` (no SSH access)
    /// - Home: `/data/home/<username>`
    /// - No password aging
    ///
    /// The Samba password is set via `smbpasswd -a -s` with the password
    /// provided through stdin.
    pub fn create(username: &str, password: &str) -> Result<Self, ShareError> {
        validate_username(username)?;

        // Check if system user already exists
        if system_user_exists(username) {
            return Err(ShareError::UserAlreadyExists(username.to_string()));
        }

        // Create system user
        let home_dir = format!("{HOME_BASE}/{username}");
        let output = Command::new("adduser")
            .args([
                "-D", // no password (system user)
                "-h",
                &home_dir, // home directory
                "-s",
                NOLOGIN_SHELL, // no shell access
                "-G",
                "nas", // primary group
                username,
            ])
            .output()
            .map_err(|e| ShareError::Command(format!("failed to run adduser: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(username, error = %stderr, "adduser failed");
            return Err(ShareError::Command(format!(
                "adduser failed for '{username}': {stderr}"
            )));
        }

        info!(username, home = home_dir, "system user created");

        // Create home directory with correct permissions
        if let Err(e) = std::fs::create_dir_all(&home_dir) {
            warn!(username, error = %e, "failed to create home directory");
        } else {
            // Set ownership to the new user
            let chown_output = Command::new("chown")
                .args([&format!("{username}:nas"), &home_dir])
                .output();

            if let Err(e) = chown_output {
                warn!(username, error = %e, "failed to chown home directory");
            }

            // Set permissions: rwx for user, rx for group, nothing for others
            let chmod_output = Command::new("chmod").args(["750", &home_dir]).output();

            if let Err(e) = chmod_output {
                warn!(username, error = %e, "failed to chmod home directory");
            }
        }

        // Add to Samba password database
        if let Err(e) = SambaConfig::add_user(username, password) {
            // Rollback: remove the system user we just created
            warn!(username, error = %e, "smbpasswd failed, rolling back system user");
            let _ = remove_system_user(username);
            return Err(e);
        }

        Ok(Self {
            username: username.to_string(),
        })
    }

    /// Delete a NAS user (both system account and Samba password).
    ///
    /// Removes the user from the Samba password database first, then
    /// removes the system account. Home directory is preserved (not deleted).
    pub fn delete(username: &str) -> Result<(), ShareError> {
        validate_username(username)?;

        if !system_user_exists(username) {
            return Err(ShareError::UserNotFound(username.to_string()));
        }

        // Remove from Samba passdb (ignore error if not in passdb)
        if let Err(e) = SambaConfig::remove_user(username) {
            warn!(username, error = %e, "samba user removal failed (may not exist in passdb)");
        }

        // Remove system user (do not remove home directory — data preservation)
        remove_system_user(username)?;

        info!(username, "NAS user deleted");
        Ok(())
    }

    /// Change a NAS user's password (both system and Samba).
    ///
    /// Updates the Samba password via `smbpasswd -s`. System password is
    /// not set since the user has `/sbin/nologin` shell.
    pub fn change_password(username: &str, password: &str) -> Result<(), ShareError> {
        validate_username(username)?;

        if !system_user_exists(username) {
            return Err(ShareError::UserNotFound(username.to_string()));
        }

        SambaConfig::change_password(username, password)?;

        info!(username, "NAS user password changed");
        Ok(())
    }

    /// List all NAS users from the Samba password database.
    ///
    /// Reads usernames from `pdbedit -L` output. Each line is formatted
    /// as `username:uid:full_name`.
    pub fn list() -> Result<Vec<String>, ShareError> {
        let output = Command::new("pdbedit")
            .args(["-L", "-t", PASSDB_PATH])
            .output()
            .map_err(|e| ShareError::Command(format!("failed to run pdbedit: {e}")))?;

        if !output.status.success() {
            // pdbedit may fail if passdb doesn't exist yet — return empty list
            let stderr = String::from_utf8_lossy(&output.stderr);
            debug!(error = %stderr, "pdbedit returned non-zero (passdb may not exist yet)");
            return Ok(Vec::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let users: Vec<String> = stdout
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    return None;
                }
                // pdbedit -L output format: "username:uid:full_name"
                trimmed.split(':').next().map(String::from)
            })
            .collect();

        debug!(count = users.len(), "listed NAS users from passdb");
        Ok(users)
    }

    /// Check if a NAS user exists in the system.
    #[must_use]
    pub fn exists(username: &str) -> bool {
        system_user_exists(username)
    }
}

/// Validate a username for NAS user creation.
///
/// Rules:
/// - 1-32 characters
/// - Must start with a lowercase letter
/// - Only lowercase letters, digits, underscores, and hyphens
/// - Must not be a reserved system username
fn validate_username(username: &str) -> Result<(), ShareError> {
    if username.is_empty() || username.len() > 32 {
        return Err(ShareError::InvalidUsername(
            "username must be 1-32 characters".to_string(),
        ));
    }

    let first = username.as_bytes()[0];
    if !first.is_ascii_lowercase() {
        return Err(ShareError::InvalidUsername(
            "username must start with a lowercase letter".to_string(),
        ));
    }

    if !username
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        return Err(ShareError::InvalidUsername(
            "username may only contain lowercase letters, digits, underscores, and hyphens"
                .to_string(),
        ));
    }

    // Reserved system usernames that must not be used
    const RESERVED: &[&str] = &[
        "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp",
        "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody", "sshd", "samba", "smbd",
        "nmbd", "winbindd", "ntp", "chrony", "admin", "guest", "operator",
    ];

    if RESERVED.contains(&username) {
        return Err(ShareError::InvalidUsername(format!(
            "'{username}' is a reserved system username"
        )));
    }

    Ok(())
}

/// Check if a system user exists by querying `id`.
fn system_user_exists(username: &str) -> bool {
    Command::new("id")
        .arg(username)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Remove a system user via `deluser`.
fn remove_system_user(username: &str) -> Result<(), ShareError> {
    let output = Command::new("deluser")
        .arg(username)
        .output()
        .map_err(|e| ShareError::Command(format!("failed to run deluser: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(username, error = %stderr, "deluser failed");
        return Err(ShareError::Command(format!(
            "deluser failed for '{username}': {stderr}"
        )));
    }

    debug!(username, "system user removed");
    Ok(())
}

/// Ensure the `nas` group exists (idempotent).
///
/// This should be called once at service startup before creating any users.
pub fn ensure_nas_group() -> Result<(), ShareError> {
    let output = Command::new("addgroup")
        .args(["-S", "nas"])
        .output()
        .map_err(|e| ShareError::Command(format!("failed to run addgroup: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "already exists" is fine
        if !stderr.contains("already exists") && !stderr.contains("in use") {
            error!(error = %stderr, "addgroup nas failed");
            return Err(ShareError::Command(format!(
                "addgroup nas failed: {stderr}"
            )));
        }
        debug!("nas group already exists");
    } else {
        info!("nas group created");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("bob-smith").is_ok());
        assert!(validate_username("user_01").is_ok());
        assert!(validate_username("a").is_ok());
        assert!(validate_username("abcdefghijklmnopqrstuvwxyz012345").is_ok()); // 32 chars
    }

    #[test]
    fn test_validate_username_empty() {
        assert!(validate_username("").is_err());
    }

    #[test]
    fn test_validate_username_too_long() {
        let long = "a".repeat(33);
        assert!(validate_username(&long).is_err());
    }

    #[test]
    fn test_validate_username_uppercase() {
        assert!(validate_username("Alice").is_err());
        assert!(validate_username("BOB").is_err());
    }

    #[test]
    fn test_validate_username_starts_with_digit() {
        assert!(validate_username("1user").is_err());
    }

    #[test]
    fn test_validate_username_special_chars() {
        assert!(validate_username("user@name").is_err());
        assert!(validate_username("user name").is_err());
        assert!(validate_username("user.name").is_err());
        assert!(validate_username("../etc").is_err());
        assert!(validate_username("user;drop").is_err());
    }

    #[test]
    fn test_validate_username_reserved() {
        assert!(validate_username("root").is_err());
        assert!(validate_username("nobody").is_err());
        assert!(validate_username("samba").is_err());
        assert!(validate_username("admin").is_err());
        assert!(validate_username("guest").is_err());
    }

    #[test]
    fn test_validate_username_error_message() {
        let err = validate_username("root");
        assert!(err.is_err());
        let msg = format!(
            "{}",
            err
                // INVARIANT: we just checked is_err
                .expect_err("should fail")
        );
        assert!(msg.contains("reserved"));
    }
}
