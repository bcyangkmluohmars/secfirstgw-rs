#![deny(unsafe_code)]

use crate::{Share, ShareError};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use tracing::{debug, error, info, warn};

/// Default path to the Samba configuration file.
const SAMBA_CONF_PATH: &str = "/etc/samba/smb.conf";

/// Directory for persistent Samba data (passdb, etc.).
const SAMBA_CONF_DIR: &str = "/data/config/samba";

/// Path to the Samba password database (tdbsam backend).
const PASSDB_PATH: &str = "/data/config/samba/passdb.tdb";

/// Manages Samba configuration, shares, and service lifecycle.
///
/// Preserves the `[global]` section when adding or removing shares.
/// Configuration is read from and written to `/etc/samba/smb.conf`.
pub struct SambaConfig {
    /// Raw key-value pairs from the `[global]` section.
    global_params: BTreeMap<String, String>,
    /// All configured shares, keyed by share name.
    shares: Vec<Share>,
    /// Path to the smb.conf file (overridable for testing).
    config_path: String,
}

impl SambaConfig {
    /// Create a new Samba configuration with security-hardened defaults.
    ///
    /// The `[global]` section is pre-populated with:
    /// - SMB3 minimum protocol
    /// - Mandatory signing and encryption
    /// - No guest mapping
    /// - tdbsam passdb backend at `/data/config/samba/passdb.tdb`
    #[must_use]
    pub fn new(workgroup: &str) -> Self {
        let mut global_params = BTreeMap::new();
        global_params.insert("workgroup".to_string(), workgroup.to_string());
        global_params.insert("server string".to_string(), "secfirstNAS".to_string());
        global_params.insert("server role".to_string(), "standalone server".to_string());
        global_params.insert("log file".to_string(), "/var/log/samba/%m.log".to_string());
        global_params.insert("max log size".to_string(), "1000".to_string());
        global_params.insert("logging".to_string(), "file".to_string());
        global_params.insert("dns proxy".to_string(), "no".to_string());
        global_params.insert("server min protocol".to_string(), "SMB3".to_string());
        global_params.insert("server signing".to_string(), "mandatory".to_string());
        global_params.insert("smb encrypt".to_string(), "required".to_string());
        global_params.insert("map to guest".to_string(), "never".to_string());
        global_params.insert("usershare allow guests".to_string(), "no".to_string());
        global_params.insert(
            "passdb backend".to_string(),
            format!("tdbsam:{PASSDB_PATH}"),
        );
        global_params.insert("disable netbios".to_string(), "yes".to_string());
        global_params.insert("smb ports".to_string(), "445".to_string());

        Self {
            global_params,
            shares: Vec::new(),
            config_path: SAMBA_CONF_PATH.to_string(),
        }
    }

    /// Load an existing Samba configuration from the default path.
    ///
    /// Parses the `[global]` section and all share sections.
    /// Returns an error if the file cannot be read or parsed.
    pub fn load() -> Result<Self, ShareError> {
        Self::load_from(SAMBA_CONF_PATH)
    }

    /// Load a Samba configuration from a specific file path.
    ///
    /// This is the testable implementation of [`SambaConfig::load`].
    pub fn load_from(path: &str) -> Result<Self, ShareError> {
        let content = std::fs::read_to_string(path).map_err(ShareError::Io)?;
        let mut config = Self::parse_config(&content)?;
        config.config_path = path.to_string();
        debug!(path, shares = config.shares.len(), "loaded samba config");
        Ok(config)
    }

    /// Parse smb.conf content into a `SambaConfig`.
    fn parse_config(content: &str) -> Result<Self, ShareError> {
        let mut global_params = BTreeMap::new();
        let mut shares = Vec::new();

        // Track current section
        let mut current_section: Option<String> = None;
        let mut current_lines: Vec<String> = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }

            // Section header
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                // Flush previous section
                if let Some(ref section) = current_section {
                    if section.eq_ignore_ascii_case("global") {
                        // Parse global params
                        for param_line in &current_lines {
                            if let Some((k, v)) = param_line.split_once('=') {
                                global_params.insert(
                                    k.trim().to_lowercase().to_string(),
                                    v.trim().to_string(),
                                );
                            }
                        }
                    } else {
                        // Parse share section
                        let line_refs: Vec<&str> =
                            current_lines.iter().map(String::as_str).collect();
                        match Share::from_smb_conf(section, &line_refs) {
                            Ok(share) => shares.push(share),
                            Err(e) => {
                                warn!(section, error = %e, "skipping malformed share section");
                            }
                        }
                    }
                }

                let section_name = &trimmed[1..trimmed.len() - 1];
                current_section = Some(section_name.to_string());
                current_lines.clear();
                continue;
            }

            // Content line (belongs to current section)
            current_lines.push(trimmed.to_string());
        }

        // Flush final section
        if let Some(ref section) = current_section {
            if section.eq_ignore_ascii_case("global") {
                for param_line in &current_lines {
                    if let Some((k, v)) = param_line.split_once('=') {
                        global_params
                            .insert(k.trim().to_lowercase().to_string(), v.trim().to_string());
                    }
                }
            } else {
                let line_refs: Vec<&str> = current_lines.iter().map(String::as_str).collect();
                match Share::from_smb_conf(section, &line_refs) {
                    Ok(share) => shares.push(share),
                    Err(e) => {
                        warn!(section, error = %e, "skipping malformed share section");
                    }
                }
            }
        }

        // Apply security defaults if not already set
        global_params
            .entry("server min protocol".to_string())
            .or_insert_with(|| "SMB3".to_string());
        global_params
            .entry("server signing".to_string())
            .or_insert_with(|| "mandatory".to_string());
        global_params
            .entry("smb encrypt".to_string())
            .or_insert_with(|| "required".to_string());

        Ok(Self {
            global_params,
            shares,
            config_path: SAMBA_CONF_PATH.to_string(),
        })
    }

    /// Get a reference to all configured shares.
    #[must_use]
    pub fn shares(&self) -> &[Share] {
        &self.shares
    }

    /// Get a reference to a share by name.
    #[must_use]
    pub fn get_share(&self, name: &str) -> Option<&Share> {
        self.shares.iter().find(|s| s.name == name)
    }

    /// Get a mutable reference to a share by name.
    pub fn get_share_mut(&mut self, name: &str) -> Option<&mut Share> {
        self.shares.iter_mut().find(|s| s.name == name)
    }

    /// Add a share to the configuration.
    ///
    /// Returns an error if a share with the same name already exists.
    pub fn add_share(&mut self, share: Share) -> Result<(), ShareError> {
        if self.shares.iter().any(|s| s.name == share.name) {
            return Err(ShareError::AlreadyExists(share.name));
        }
        info!(share = share.name, path = %share.path.display(), "share added to config");
        self.shares.push(share);
        Ok(())
    }

    /// Remove a share by name.
    ///
    /// Returns an error if no share with the given name exists.
    pub fn remove_share(&mut self, name: &str) -> Result<(), ShareError> {
        let pos = self
            .shares
            .iter()
            .position(|s| s.name == name)
            .ok_or_else(|| ShareError::NotFound(name.into()))?;
        self.shares.remove(pos);
        info!(share = name, "share removed from config");
        Ok(())
    }

    /// Set a global parameter.
    ///
    /// This will appear in the `[global]` section of smb.conf.
    pub fn set_global(&mut self, key: &str, value: &str) {
        self.global_params
            .insert(key.to_lowercase(), value.to_string());
    }

    /// Get a global parameter value.
    #[must_use]
    pub fn get_global(&self, key: &str) -> Option<&str> {
        self.global_params
            .get(&key.to_lowercase())
            .map(String::as_str)
    }

    /// Generate the full smb.conf content.
    ///
    /// Outputs `[global]` section followed by all share sections.
    /// Parameters are sorted alphabetically for deterministic output.
    #[must_use]
    pub fn generate_config(&self) -> String {
        let mut conf = String::from("# Generated by secfirstNAS — do not edit manually\n\n");

        // [global] section
        conf.push_str("[global]\n");
        for (key, value) in &self.global_params {
            conf.push_str(&format!("    {key} = {value}\n"));
        }

        // Share sections
        for share in &self.shares {
            conf.push('\n');
            conf.push_str(&share.to_smb_conf());
        }

        conf
    }

    /// Write the configuration to disk (the configured path).
    ///
    /// Creates the Samba config directory if it does not exist.
    pub fn save(&self) -> Result<(), ShareError> {
        self.save_to(&self.config_path)
    }

    /// Write the configuration to a specific path.
    pub fn save_to(&self, path: &str) -> Result<(), ShareError> {
        let config = self.generate_config();

        // Ensure parent directory exists
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent).map_err(ShareError::Io)?;
        }

        // Ensure samba data directory exists
        std::fs::create_dir_all(SAMBA_CONF_DIR).map_err(ShareError::Io)?;

        std::fs::write(path, &config).map_err(ShareError::Io)?;
        info!(path, "samba config saved");
        Ok(())
    }

    /// Write config to disk and reload the Samba service.
    ///
    /// Equivalent to calling [`save`](Self::save) then [`reload`](Self::reload).
    pub fn apply(&self) -> Result<(), ShareError> {
        self.save()?;
        Self::reload()?;
        Ok(())
    }

    /// Validate the current smb.conf by running `testparm -s`.
    ///
    /// Returns the validated output on success, or an error with testparm's
    /// stderr on failure.
    #[must_use = "check the result to verify config validity"]
    pub fn test_config() -> Result<String, ShareError> {
        let output = Command::new("testparm")
            .args(["-s"])
            .output()
            .map_err(|e| ShareError::Command(format!("failed to run testparm: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(error = %stderr, "testparm validation failed");
            return Err(ShareError::Config(format!("testparm failed: {stderr}")));
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        debug!("testparm validation passed");
        Ok(stdout)
    }

    // -----------------------------------------------------------------------
    // Service management
    // -----------------------------------------------------------------------

    /// Start the Samba service via rc-service.
    pub fn start() -> Result<(), ShareError> {
        run_rc_service("samba", "start")
    }

    /// Stop the Samba service via rc-service.
    pub fn stop() -> Result<(), ShareError> {
        run_rc_service("samba", "stop")
    }

    /// Restart the Samba service via rc-service.
    pub fn restart() -> Result<(), ShareError> {
        run_rc_service("samba", "restart")
    }

    /// Reload the Samba configuration without restarting.
    pub fn reload() -> Result<(), ShareError> {
        run_rc_service("samba", "reload")
    }

    /// Query the Samba service status.
    ///
    /// Returns `true` if the service is running, `false` otherwise.
    #[must_use = "check the returned status"]
    pub fn status() -> Result<bool, ShareError> {
        let output = Command::new("rc-service")
            .args(["samba", "status"])
            .output()
            .map_err(|e| ShareError::Service(format!("failed to query samba status: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let running = output.status.success() && stdout.contains("started");
        debug!(running, "samba service status");
        Ok(running)
    }

    // -----------------------------------------------------------------------
    // User management (Samba password database)
    // -----------------------------------------------------------------------

    /// Add a user to the Samba password database.
    ///
    /// The user must already exist as a system user. Password is provided via
    /// stdin to `smbpasswd -a -s` (no command-line exposure).
    pub fn add_user(username: &str, password: &str) -> Result<(), ShareError> {
        let mut child = Command::new("smbpasswd")
            .args(["-a", "-s", username])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| ShareError::Command(format!("failed to run smbpasswd: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let pw_input = format!("{password}\n{password}\n");
            stdin
                .write_all(pw_input.as_bytes())
                .map_err(ShareError::Io)?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| ShareError::Command(format!("smbpasswd wait failed: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(username, error = %stderr, "smbpasswd -a failed");
            return Err(ShareError::Command(format!(
                "smbpasswd failed for user '{username}': {stderr}"
            )));
        }

        info!(username, "samba user added to passdb");
        Ok(())
    }

    /// Remove a user from the Samba password database.
    pub fn remove_user(username: &str) -> Result<(), ShareError> {
        let output = Command::new("smbpasswd")
            .args(["-x", username])
            .output()
            .map_err(|e| ShareError::Command(format!("failed to run smbpasswd: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(username, error = %stderr, "smbpasswd -x failed");
            return Err(ShareError::UserNotFound(username.to_string()));
        }

        info!(username, "samba user removed from passdb");
        Ok(())
    }

    /// Change a Samba user's password.
    ///
    /// Password is provided via stdin (no command-line exposure).
    pub fn change_password(username: &str, password: &str) -> Result<(), ShareError> {
        let mut child = Command::new("smbpasswd")
            .args(["-s", username])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| ShareError::Command(format!("failed to run smbpasswd: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let pw_input = format!("{password}\n{password}\n");
            stdin
                .write_all(pw_input.as_bytes())
                .map_err(ShareError::Io)?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| ShareError::Command(format!("smbpasswd wait failed: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(username, error = %stderr, "smbpasswd password change failed");
            return Err(ShareError::Command(format!(
                "password change failed for '{username}': {stderr}"
            )));
        }

        info!(username, "samba password changed");
        Ok(())
    }
}

/// Run an rc-service command (start, stop, restart, reload).
fn run_rc_service(service: &str, action: &str) -> Result<(), ShareError> {
    let output = Command::new("rc-service")
        .args([service, action])
        .output()
        .map_err(|e| ShareError::Service(format!("rc-service {service} {action} failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(service, action, error = %stderr, "rc-service command failed");
        return Err(ShareError::Service(format!(
            "rc-service {service} {action}: {stderr}"
        )));
    }

    info!(service, action, "service operation completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_new_has_security_defaults() {
        let config = SambaConfig::new("WORKGROUP");
        let generated = config.generate_config();

        assert!(generated.contains("[global]"));
        assert!(generated.contains("server min protocol = SMB3"));
        assert!(generated.contains("server signing = mandatory"));
        assert!(generated.contains("smb encrypt = required"));
        assert!(generated.contains("map to guest = never"));
        assert!(generated.contains("disable netbios = yes"));
        assert!(generated.contains("smb ports = 445"));
        assert!(generated.contains(&format!("passdb backend = tdbsam:{PASSDB_PATH}")));
    }

    #[test]
    fn test_add_remove_share() {
        let mut config = SambaConfig::new("WORKGROUP");

        let share = Share::new("media", PathBuf::from("/data/shares/media"));
        assert!(config.add_share(share).is_ok());
        assert_eq!(config.shares().len(), 1);

        // Duplicate fails
        let dup = Share::new("media", PathBuf::from("/data/shares/media2"));
        assert!(config.add_share(dup).is_err());

        // Remove
        assert!(config.remove_share("media").is_ok());
        assert!(config.shares().is_empty());

        // Remove non-existent
        assert!(config.remove_share("ghost").is_err());
    }

    #[test]
    fn test_generate_config_preserves_global() {
        let mut config = SambaConfig::new("MYGROUP");
        config.set_global("custom param", "custom value");

        let share = Share::new("docs", PathBuf::from("/data/docs"));
        // INVARIANT: fresh config, no duplicate
        config.add_share(share).expect("add share");

        let generated = config.generate_config();

        // Global section present with custom param
        assert!(generated.contains("workgroup = MYGROUP"));
        assert!(generated.contains("custom param = custom value"));

        // Share section present
        assert!(generated.contains("[docs]"));
        assert!(generated.contains("path = /data/docs"));
    }

    #[test]
    fn test_parse_config_roundtrip() {
        let input = "\
[global]
    workgroup = TESTGROUP
    server min protocol = SMB3
    server signing = mandatory
    smb encrypt = required
    log file = /var/log/samba/%m.log

[shared]
    path = /data/shares/shared
    comment = Shared files
    browseable = yes
    read only = no
    guest ok = no

[readonly]
    path = /data/shares/ro
    read only = yes
    browseable = yes
    guest ok = yes
";

        let config = SambaConfig::parse_config(input);
        // INVARIANT: well-formed config must parse
        let config = config.expect("parse");

        assert_eq!(config.get_global("workgroup"), Some("TESTGROUP"));
        assert_eq!(config.shares().len(), 2);

        let shared = config.get_share("shared");
        assert!(shared.is_some());
        let shared = shared
            // INVARIANT: we just checked is_some
            .expect("shared exists");
        assert_eq!(shared.path, PathBuf::from("/data/shares/shared"));
        assert!(!shared.read_only);
        assert!(!shared.guest_ok);

        let ro = config.get_share("readonly");
        assert!(ro.is_some());
        let ro = ro
            // INVARIANT: we just checked is_some
            .expect("readonly exists");
        assert!(ro.read_only);
        assert!(ro.guest_ok);
    }

    #[test]
    fn test_parse_config_with_comments() {
        let input = "\
# Main samba config
[global]
    workgroup = TEST
    ; This is a comment
    server min protocol = SMB3

# A share
[myshare]
    path = /data/myshare
    ; comment line
    read only = yes
";

        let config = SambaConfig::parse_config(input);
        // INVARIANT: well-formed config with comments must parse
        let config = config.expect("parse");

        assert_eq!(config.get_global("workgroup"), Some("TEST"));
        assert_eq!(config.shares().len(), 1);
    }

    #[test]
    fn test_parse_config_empty() {
        let config = SambaConfig::parse_config("");
        // INVARIANT: empty input should parse without error
        let config = config.expect("parse empty");

        // Should still have security defaults applied
        assert_eq!(config.get_global("server min protocol"), Some("SMB3"));
        assert!(config.shares().is_empty());
    }

    #[test]
    fn test_get_set_global() {
        let mut config = SambaConfig::new("WG");
        config.set_global("max log size", "2000");
        assert_eq!(config.get_global("max log size"), Some("2000"));
    }

    #[test]
    fn test_get_share_mut() {
        let mut config = SambaConfig::new("WG");
        let share = Share::new("test", PathBuf::from("/data/test"));
        // INVARIANT: first share, no duplicate
        config.add_share(share).expect("add");

        let share_mut = config.get_share_mut("test");
        assert!(share_mut.is_some());
        let share_mut = share_mut
            // INVARIANT: just checked is_some
            .expect("mut ref");
        share_mut.read_only = true;

        let share_ref = config.get_share("test");
        assert!(share_ref.is_some());
        assert!(
            share_ref
                // INVARIANT: just checked is_some
                .expect("ref")
                .read_only
        );
    }

    #[test]
    fn test_config_preserves_shares_on_add() {
        let mut config = SambaConfig::new("WG");

        let s1 = Share::new("first", PathBuf::from("/data/first"));
        let s2 = Share::new("second", PathBuf::from("/data/second"));
        // INVARIANT: no duplicates
        config.add_share(s1).expect("add first");
        config.add_share(s2).expect("add second");

        let generated = config.generate_config();
        assert!(generated.contains("[first]"));
        assert!(generated.contains("[second]"));
        assert!(generated.contains("[global]"));
    }

    #[test]
    fn test_generate_config_writable() {
        let config = SambaConfig::new("WG");
        let dir = std::env::temp_dir().join("sfnas-test-samba");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("smb.conf");

        let generated = config.generate_config();
        // INVARIANT: temp dir was just created
        std::fs::write(&path, &generated).expect("write test file");

        // Verify file was written correctly
        let content = std::fs::read_to_string(&path);
        assert!(content.is_ok());
        let content = content
            // INVARIANT: file was just written
            .expect("read back");
        assert!(content.contains("[global]"));
        assert!(content.contains("server min protocol = SMB3"));

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_from_file() {
        let dir = std::env::temp_dir().join("sfnas-test-samba-load");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("smb.conf");
        let path_str = path.to_string_lossy().to_string();

        let content = "\
[global]
    workgroup = LOADED
    server min protocol = SMB3
    server signing = mandatory
    smb encrypt = required

[loadtest]
    path = /data/loadtest
    read only = yes
";
        // INVARIANT: temp dir was just created
        std::fs::write(&path, content).expect("write test file");

        let config = SambaConfig::load_from(&path_str);
        assert!(config.is_ok());
        let config = config
            // INVARIANT: valid file
            .expect("load");

        assert_eq!(config.get_global("workgroup"), Some("LOADED"));
        assert_eq!(config.shares().len(), 1);
        assert!(config.get_share("loadtest").is_some());

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }
}
