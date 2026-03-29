#![deny(unsafe_code)]

//! rsync server configuration for secfirstNAS.
//!
//! Generates `/etc/rsyncd.conf` with rsync modules for backup synchronization.
//! Each module maps a share path with optional user restrictions.
//! Service management via `rc-service rsync`.

use crate::ShareError;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, error, info};

/// Default path to the rsync daemon configuration file.
const RSYNCD_CONF_PATH: &str = "/etc/rsyncd.conf";

/// Default path to the rsync secrets file (user:password pairs).
const RSYNCD_SECRETS_PATH: &str = "/data/config/rsync/rsyncd.secrets";

/// Default path for the rsync lock file.
const RSYNCD_LOCK_PATH: &str = "/var/run/rsyncd.lock";

/// Default path for the rsync log file.
const RSYNCD_LOG_PATH: &str = "/var/log/rsyncd.log";

/// An rsync module (exposed path with access controls).
#[derive(Debug, Clone)]
pub struct RsyncModule {
    /// Module name as it appears in `[section]` of rsyncd.conf.
    pub name: String,
    /// Filesystem path this module exposes.
    pub path: PathBuf,
    /// Human-readable description of this module.
    pub comment: String,
    /// Whether this module is read-only.
    pub read_only: bool,
    /// List of usernames allowed to access this module (empty = all).
    pub auth_users: Vec<String>,
    /// Network hosts allowed to connect (CIDR notation).
    pub hosts_allow: Vec<String>,
    /// Network hosts denied (CIDR notation). Default: deny all.
    pub hosts_deny: Vec<String>,
    /// Maximum number of simultaneous connections.
    pub max_connections: u32,
}

impl RsyncModule {
    /// Create a new rsync module with secure defaults.
    ///
    /// Default configuration:
    /// - Read-only
    /// - No host restrictions (rely on firewall)
    /// - Max 4 simultaneous connections
    #[must_use]
    pub fn new(name: &str, path: PathBuf) -> Self {
        Self {
            name: name.to_string(),
            path,
            comment: String::new(),
            read_only: true,
            auth_users: Vec::new(),
            hosts_allow: Vec::new(),
            hosts_deny: vec!["*".to_string()],
            max_connections: 4,
        }
    }

    /// Generate the rsyncd.conf section for this module.
    #[must_use]
    fn to_conf_section(&self) -> String {
        let mut section = format!("[{}]\n", self.name);
        section.push_str(&format!("    path = {}\n", self.path.display()));

        if !self.comment.is_empty() {
            section.push_str(&format!("    comment = {}\n", self.comment));
        }

        section.push_str(&format!(
            "    read only = {}\n",
            if self.read_only { "yes" } else { "no" }
        ));

        section.push_str(&format!("    max connections = {}\n", self.max_connections));

        if !self.auth_users.is_empty() {
            section.push_str(&format!("    auth users = {}\n", self.auth_users.join(" ")));
            section.push_str(&format!("    secrets file = {RSYNCD_SECRETS_PATH}\n"));
        }

        if !self.hosts_allow.is_empty() {
            section.push_str(&format!(
                "    hosts allow = {}\n",
                self.hosts_allow.join(" ")
            ));
        }

        if !self.hosts_deny.is_empty() {
            section.push_str(&format!("    hosts deny = {}\n", self.hosts_deny.join(" ")));
        }

        // Security: never follow symlinks outside the module path
        section.push_str("    use chroot = yes\n");
        // Don't expose file listing to unauthenticated clients
        section.push_str("    list = no\n");

        section
    }
}

/// Manages the rsync daemon configuration and service lifecycle.
pub struct RsyncConfig {
    /// Global configuration: UID to run as.
    uid: String,
    /// Global configuration: GID to run as.
    gid: String,
    /// All configured rsync modules.
    modules: Vec<RsyncModule>,
    /// Path to the rsyncd.conf file (overridable for testing).
    config_path: String,
}

impl RsyncConfig {
    /// Create a new rsync configuration with secure defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            uid: "nobody".to_string(),
            gid: "nas".to_string(),
            modules: Vec::new(),
            config_path: RSYNCD_CONF_PATH.to_string(),
        }
    }

    /// Get a reference to all configured modules.
    #[must_use]
    pub fn modules(&self) -> &[RsyncModule] {
        &self.modules
    }

    /// Add a module to the configuration.
    ///
    /// Returns an error if a module with the same name already exists.
    pub fn add_module(&mut self, module: RsyncModule) -> Result<(), ShareError> {
        if self.modules.iter().any(|m| m.name == module.name) {
            return Err(ShareError::AlreadyExists(module.name));
        }

        // Validate path is absolute
        if !module.path.is_absolute() {
            return Err(ShareError::InvalidPath(format!(
                "rsync module path must be absolute: {}",
                module.path.display()
            )));
        }

        info!(module = module.name, path = %module.path.display(), "rsync module added");
        self.modules.push(module);
        Ok(())
    }

    /// Convenience method to add a module from components.
    ///
    /// Creates a module with the given name, path, and optional user list.
    /// If `users` is non-empty, authentication is required.
    pub fn add_module_simple(
        &mut self,
        name: &str,
        path: PathBuf,
        users: &[&str],
    ) -> Result<(), ShareError> {
        let mut module = RsyncModule::new(name, path);
        if !users.is_empty() {
            module.auth_users = users.iter().map(|u| (*u).to_string()).collect();
        }
        self.add_module(module)
    }

    /// Remove a module by name.
    pub fn remove_module(&mut self, name: &str) -> Result<(), ShareError> {
        let pos = self
            .modules
            .iter()
            .position(|m| m.name == name)
            .ok_or_else(|| ShareError::NotFound(name.into()))?;
        self.modules.remove(pos);
        info!(module = name, "rsync module removed");
        Ok(())
    }

    /// Generate the full rsyncd.conf content.
    #[must_use]
    pub fn generate(&self) -> String {
        let mut conf = String::from("# Generated by secfirstNAS — do not edit manually\n\n");

        // Global section
        conf.push_str(&format!("uid = {}\n", self.uid));
        conf.push_str(&format!("gid = {}\n", self.gid));
        conf.push_str(&format!("lock file = {RSYNCD_LOCK_PATH}\n"));
        conf.push_str(&format!("log file = {RSYNCD_LOG_PATH}\n"));
        conf.push_str("use chroot = yes\n");
        conf.push_str("strict modes = yes\n");
        // Don't expose modules to unauthenticated scanning
        conf.push_str("list = no\n");
        // Transfer logging for audit trail
        conf.push_str("transfer logging = yes\n");
        conf.push_str("log format = %h %o %f %l %b\n");
        conf.push('\n');

        // Module sections
        for module in &self.modules {
            conf.push_str(&module.to_conf_section());
            conf.push('\n');
        }

        conf
    }

    /// Write the configuration to disk and ensure the secrets file exists.
    pub fn save(&self) -> Result<(), ShareError> {
        self.save_to(&self.config_path)
    }

    /// Write the configuration to a specific path.
    pub fn save_to(&self, path: &str) -> Result<(), ShareError> {
        let config = self.generate();

        // Ensure parent directory exists
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent).map_err(ShareError::Io)?;
        }

        std::fs::write(path, &config).map_err(ShareError::Io)?;
        info!(path, "rsyncd.conf written");

        // Ensure secrets directory exists
        if let Some(parent) = Path::new(RSYNCD_SECRETS_PATH).parent() {
            std::fs::create_dir_all(parent).map_err(ShareError::Io)?;
        }

        // Create secrets file if it doesn't exist (must be mode 600)
        if !Path::new(RSYNCD_SECRETS_PATH).exists() {
            std::fs::write(RSYNCD_SECRETS_PATH, "").map_err(ShareError::Io)?;
            set_file_permissions(RSYNCD_SECRETS_PATH, 0o600)?;
            debug!("created empty rsyncd.secrets");
        }

        Ok(())
    }

    /// Write configuration and restart the rsync service.
    pub fn apply(&self) -> Result<(), ShareError> {
        self.save()?;
        Self::restart()
    }

    // -----------------------------------------------------------------------
    // Secrets management
    // -----------------------------------------------------------------------

    /// Add or update a user's rsync password in the secrets file.
    ///
    /// The secrets file format is `username:password` (one per line).
    /// The file is restricted to mode 600 for security.
    pub fn set_user_password(username: &str, password: &str) -> Result<(), ShareError> {
        let content = std::fs::read_to_string(RSYNCD_SECRETS_PATH).unwrap_or_default();

        let mut lines: Vec<String> = content
            .lines()
            .filter(|line| {
                // Remove existing entry for this user
                !line.starts_with(&format!("{username}:"))
            })
            .map(String::from)
            .collect();

        lines.push(format!("{username}:{password}"));

        let new_content = lines.join("\n") + "\n";

        // Ensure parent directory exists
        if let Some(parent) = Path::new(RSYNCD_SECRETS_PATH).parent() {
            std::fs::create_dir_all(parent).map_err(ShareError::Io)?;
        }

        std::fs::write(RSYNCD_SECRETS_PATH, new_content).map_err(ShareError::Io)?;
        set_file_permissions(RSYNCD_SECRETS_PATH, 0o600)?;

        info!(username, "rsync user password updated");
        Ok(())
    }

    /// Remove a user from the rsync secrets file.
    pub fn remove_user_password(username: &str) -> Result<(), ShareError> {
        let content = std::fs::read_to_string(RSYNCD_SECRETS_PATH).unwrap_or_default();

        let lines: Vec<&str> = content
            .lines()
            .filter(|line| !line.starts_with(&format!("{username}:")))
            .collect();

        let new_content = lines.join("\n") + "\n";
        std::fs::write(RSYNCD_SECRETS_PATH, new_content).map_err(ShareError::Io)?;

        info!(username, "rsync user password removed");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Service management
    // -----------------------------------------------------------------------

    /// Start the rsync daemon via rc-service.
    pub fn start() -> Result<(), ShareError> {
        run_rc_service("rsyncd", "start")
    }

    /// Stop the rsync daemon via rc-service.
    pub fn stop() -> Result<(), ShareError> {
        run_rc_service("rsyncd", "stop")
    }

    /// Restart the rsync daemon via rc-service.
    pub fn restart() -> Result<(), ShareError> {
        run_rc_service("rsyncd", "restart")
    }

    /// Query the rsync daemon status.
    ///
    /// Returns `true` if the service is running, `false` otherwise.
    #[must_use = "check the returned status"]
    pub fn status() -> Result<bool, ShareError> {
        let output = Command::new("rc-service")
            .args(["rsyncd", "status"])
            .output()
            .map_err(|e| ShareError::Service(format!("failed to query rsyncd status: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let running = output.status.success() && stdout.contains("started");
        debug!(running, "rsyncd service status");
        Ok(running)
    }
}

impl Default for RsyncConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Set file permissions using chmod.
fn set_file_permissions(path: &str, mode: u32) -> Result<(), ShareError> {
    let mode_str = format!("{mode:o}");
    let output = Command::new("chmod")
        .args([&mode_str, path])
        .output()
        .map_err(|e| ShareError::Command(format!("chmod failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ShareError::Command(format!(
            "chmod {mode_str} {path} failed: {stderr}"
        )));
    }

    Ok(())
}

/// Run an rc-service command.
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

    #[test]
    fn test_new_config_defaults() {
        let config = RsyncConfig::new();
        let generated = config.generate();

        assert!(generated.contains("uid = nobody"));
        assert!(generated.contains("gid = nas"));
        assert!(generated.contains("use chroot = yes"));
        assert!(generated.contains("strict modes = yes"));
        assert!(generated.contains("list = no"));
        assert!(generated.contains("transfer logging = yes"));
    }

    #[test]
    fn test_add_module() {
        let mut config = RsyncConfig::new();
        let module = RsyncModule::new("backups", PathBuf::from("/data/shares/backups"));

        assert!(config.add_module(module).is_ok());
        assert_eq!(config.modules().len(), 1);

        let generated = config.generate();
        assert!(generated.contains("[backups]"));
        assert!(generated.contains("path = /data/shares/backups"));
        assert!(generated.contains("read only = yes"));
        assert!(generated.contains("use chroot = yes"));
        assert!(generated.contains("list = no"));
    }

    #[test]
    fn test_add_module_duplicate() {
        let mut config = RsyncConfig::new();
        let m1 = RsyncModule::new("sync", PathBuf::from("/data/sync"));
        let m2 = RsyncModule::new("sync", PathBuf::from("/data/sync2"));

        assert!(config.add_module(m1).is_ok());
        assert!(config.add_module(m2).is_err());
    }

    #[test]
    fn test_add_module_relative_path() {
        let mut config = RsyncConfig::new();
        let module = RsyncModule::new("bad", PathBuf::from("relative/path"));

        let result = config.add_module(module);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_module_simple() {
        let mut config = RsyncConfig::new();

        assert!(
            config
                .add_module_simple("docs", PathBuf::from("/data/docs"), &["alice", "bob"])
                .is_ok()
        );

        let generated = config.generate();
        assert!(generated.contains("[docs]"));
        assert!(generated.contains("auth users = alice bob"));
        assert!(generated.contains(&format!("secrets file = {RSYNCD_SECRETS_PATH}")));
    }

    #[test]
    fn test_add_module_no_users() {
        let mut config = RsyncConfig::new();

        assert!(
            config
                .add_module_simple("public", PathBuf::from("/data/public"), &[])
                .is_ok()
        );

        let generated = config.generate();
        assert!(generated.contains("[public]"));
        // No auth users line when empty
        assert!(!generated.contains("auth users"));
    }

    #[test]
    fn test_remove_module() {
        let mut config = RsyncConfig::new();
        let module = RsyncModule::new("temp", PathBuf::from("/data/temp"));
        // INVARIANT: first module, no duplicate
        config.add_module(module).expect("add");

        assert!(config.remove_module("temp").is_ok());
        assert!(config.modules().is_empty());

        // Remove non-existent
        assert!(config.remove_module("ghost").is_err());
    }

    #[test]
    fn test_module_with_hosts() {
        let mut module = RsyncModule::new("restricted", PathBuf::from("/data/restricted"));
        module.hosts_allow = vec!["10.0.0.0/24".to_string(), "192.168.1.0/24".to_string()];
        module.hosts_deny = vec!["*".to_string()];
        module.read_only = false;
        module.max_connections = 2;

        let section = module.to_conf_section();
        assert!(section.contains("hosts allow = 10.0.0.0/24 192.168.1.0/24"));
        assert!(section.contains("hosts deny = *"));
        assert!(section.contains("read only = no"));
        assert!(section.contains("max connections = 2"));
    }

    #[test]
    fn test_module_with_comment() {
        let mut module = RsyncModule::new("backup", PathBuf::from("/data/backup"));
        module.comment = "Frankfurt backup sync".to_string();

        let section = module.to_conf_section();
        assert!(section.contains("comment = Frankfurt backup sync"));
    }

    #[test]
    fn test_generate_writable() {
        let config = RsyncConfig::new();
        let dir = std::env::temp_dir().join("sfnas-test-rsync");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("rsyncd.conf");

        let generated = config.generate();
        // INVARIANT: temp dir was just created
        std::fs::write(&path, &generated).expect("write test file");

        // Verify file was written correctly
        let content = std::fs::read_to_string(&path);
        assert!(content.is_ok());
        let content = content
            // INVARIANT: file was just written
            .expect("read back");
        assert!(content.contains("uid = nobody"));
        assert!(content.contains("strict modes = yes"));

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_default_impl() {
        let config = RsyncConfig::default();
        assert!(config.modules().is_empty());
    }

    #[test]
    fn test_multiple_modules_ordering() {
        let mut config = RsyncConfig::new();

        // INVARIANT: no duplicates
        config
            .add_module_simple("alpha", PathBuf::from("/data/alpha"), &[])
            .expect("add alpha");
        config
            .add_module_simple("beta", PathBuf::from("/data/beta"), &["user1"])
            .expect("add beta");

        let generated = config.generate();
        let alpha_pos = generated.find("[alpha]");
        let beta_pos = generated.find("[beta]");

        assert!(alpha_pos.is_some());
        assert!(beta_pos.is_some());
        // Alpha should appear before beta (insertion order)
        assert!(
            alpha_pos
                // INVARIANT: just checked is_some
                .expect("alpha pos")
                < beta_pos
                    // INVARIANT: just checked is_some
                    .expect("beta pos")
        );
    }
}
