// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(unsafe_code)]

//! DNS/DHCP service — dnsmasq configuration generation, process management,
//! and lease monitoring for secfirstgw.
//!
//! Security defaults:
//! - DNS rebind protection ON
//! - DNSSEC validation ON
//! - No open resolver (bind only to LAN/MGMT interfaces)
//! - Rate limiting on DNS queries
//! - Query logging for IDS correlation

use anyhow::Context;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tera::Tera;
use tokio::sync::Mutex;

/// Errors from the DNS/DHCP crate.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// Database error.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Signal delivery error.
    #[error("signal error: {0}")]
    Signal(#[from] nix::errno::Errno),

    /// Wrapped anyhow error for internal context propagation.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Convenience alias for results from this crate.
type Result<T> = std::result::Result<T, DnsError>;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// Top-level DNS configuration.
///
/// ```
/// use sfgw_dns::DnsConfig;
///
/// let cfg = DnsConfig::default();
/// assert!(cfg.dnssec, "DNSSEC must be on by default");
/// assert!(cfg.rebind_protection, "rebind protection must be on by default");
/// assert_eq!(cfg.upstream_dns, vec!["1.1.1.1", "9.9.9.9"]);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Upstream DNS servers (e.g. `["1.1.1.1", "9.9.9.9"]`).
    pub upstream_dns: Vec<String>,
    /// Local domain name (e.g. `"lan"`).
    pub domain: String,
    /// Enable DNSSEC validation.
    pub dnssec: bool,
    /// Enable DNS rebind protection (blocks private-IP answers from upstream).
    pub rebind_protection: bool,
    /// DNS cache size (number of entries).
    pub cache_size: u32,
    /// Interfaces to bind to (LAN/MGMT only, never WAN).
    pub bind_interfaces: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            upstream_dns: vec!["1.1.1.1".into(), "9.9.9.9".into()],
            domain: "lan".into(),
            dnssec: true,
            rebind_protection: true,
            cache_size: 10000,
            bind_interfaces: vec!["br-lan".into()],
        }
    }
}

/// A DHCP range tied to an interface (VLAN-aware).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpRange {
    /// Interface name (e.g. `"br-lan"`, `"br-lan.10"`).
    pub interface: String,
    /// First IP in pool.
    pub start_ip: String,
    /// Last IP in pool.
    pub end_ip: String,
    /// Subnet mask.
    pub netmask: String,
    /// Default gateway for this range.
    pub gateway: String,
    /// Lease duration (e.g. `"12h"`, `"24h"`).
    pub lease_time: String,
    /// Optional VLAN ID for tagging.
    pub vlan_id: Option<u16>,
}

/// A static DHCP lease (MAC-to-IP binding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpStaticLease {
    /// MAC address.
    pub mac: String,
    /// Fixed IP address.
    pub ip: String,
    /// Optional hostname.
    pub hostname: Option<String>,
}

/// A DNS override entry (split DNS / local override).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsOverride {
    /// Domain name to override.
    pub domain: String,
    /// IP to resolve to.
    pub ip: String,
}

/// A parsed DHCP lease from the dnsmasq lease file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLease {
    /// Lease expiry as Unix timestamp.
    pub expires: u64,
    /// Client MAC address.
    pub mac: String,
    /// Assigned IP address.
    pub ip: String,
    /// Client hostname (may be `"*"` if unknown).
    pub hostname: String,
    /// Client ID (may be `"*"` if unknown).
    pub client_id: String,
}

// ---------------------------------------------------------------------------
// DB keys
// ---------------------------------------------------------------------------

const KEY_DNS_CONFIG: &str = "dns_config";
const KEY_DHCP_RANGES: &str = "dhcp_ranges";
const KEY_DHCP_STATIC_LEASES: &str = "dhcp_static_leases";
const KEY_DNS_OVERRIDES: &str = "dns_overrides";

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

/// Read a JSON value from the `meta` table, returning `None` if the key does
/// not exist.
fn meta_get<T: serde::de::DeserializeOwned>(
    conn: &rusqlite::Connection,
    key: &str,
) -> Result<Option<T>> {
    let mut stmt = conn.prepare("SELECT value FROM meta WHERE key = ?1")?;
    let mut rows = stmt.query(rusqlite::params![key])?;
    match rows.next()? {
        Some(row) => {
            let json_str: String = row.get::<_, String>(0)?;
            let val = serde_json::from_str(&json_str)
                .with_context(|| format!("invalid JSON for meta key `{key}`"))?;
            Ok(Some(val))
        }
        None => Ok(None),
    }
}

/// Write a JSON value to the `meta` table (upsert).
fn meta_set<T: Serialize>(conn: &rusqlite::Connection, key: &str, value: &T) -> Result<()> {
    let json_str = serde_json::to_string(value)?;
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, json_str],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Public DB API
// ---------------------------------------------------------------------------

/// Load `DnsConfig` from the database, returning the default if not set.
pub async fn load_dns_config(db: &sfgw_db::Db) -> Result<DnsConfig> {
    let conn = db.lock().await;
    Ok(meta_get::<DnsConfig>(&conn, KEY_DNS_CONFIG)?.unwrap_or_default())
}

/// Persist `DnsConfig` to the database.
pub async fn save_dns_config(db: &sfgw_db::Db, cfg: &DnsConfig) -> Result<()> {
    let conn = db.lock().await;
    meta_set(&conn, KEY_DNS_CONFIG, cfg)
}

/// Load DHCP ranges from the database.
pub async fn load_dhcp_ranges(db: &sfgw_db::Db) -> Result<Vec<DhcpRange>> {
    let conn = db.lock().await;
    Ok(meta_get::<Vec<DhcpRange>>(&conn, KEY_DHCP_RANGES)?.unwrap_or_default())
}

/// Persist DHCP ranges to the database.
pub async fn save_dhcp_ranges(db: &sfgw_db::Db, ranges: &[DhcpRange]) -> Result<()> {
    let conn = db.lock().await;
    meta_set(&conn, KEY_DHCP_RANGES, &ranges)
}

/// Load static DHCP leases from the database.
pub async fn load_static_leases(db: &sfgw_db::Db) -> Result<Vec<DhcpStaticLease>> {
    let conn = db.lock().await;
    Ok(meta_get::<Vec<DhcpStaticLease>>(&conn, KEY_DHCP_STATIC_LEASES)?.unwrap_or_default())
}

/// Persist static DHCP leases to the database.
pub async fn save_static_leases(db: &sfgw_db::Db, leases: &[DhcpStaticLease]) -> Result<()> {
    let conn = db.lock().await;
    meta_set(&conn, KEY_DHCP_STATIC_LEASES, &leases)
}

/// Load DNS overrides from the database.
pub async fn load_dns_overrides(db: &sfgw_db::Db) -> Result<Vec<DnsOverride>> {
    let conn = db.lock().await;
    Ok(meta_get::<Vec<DnsOverride>>(&conn, KEY_DNS_OVERRIDES)?.unwrap_or_default())
}

/// Persist DNS overrides to the database.
pub async fn save_dns_overrides(db: &sfgw_db::Db, overrides: &[DnsOverride]) -> Result<()> {
    let conn = db.lock().await;
    meta_set(&conn, KEY_DNS_OVERRIDES, &overrides)
}

// ---------------------------------------------------------------------------
// Config generation
// ---------------------------------------------------------------------------

/// Dnsmasq template embedded at compile time.
const DNSMASQ_TEMPLATE: &str = include_str!("templates/dnsmasq.conf.tera");

/// Render the dnsmasq configuration from the current database state.
pub async fn generate_config(db: &sfgw_db::Db) -> Result<String> {
    let dns_config = load_dns_config(db).await?;
    let dhcp_ranges = load_dhcp_ranges(db).await?;
    let static_leases = load_static_leases(db).await?;
    let dns_overrides = load_dns_overrides(db).await?;

    render_template(&dns_config, &dhcp_ranges, &static_leases, &dns_overrides)
}

/// Pure render function (useful for testing without DB).
pub fn render_template(
    dns_config: &DnsConfig,
    dhcp_ranges: &[DhcpRange],
    static_leases: &[DhcpStaticLease],
    dns_overrides: &[DnsOverride],
) -> Result<String> {
    let mut tera = Tera::default();
    tera.add_raw_template("dnsmasq.conf", DNSMASQ_TEMPLATE)
        .context("failed to parse dnsmasq template")?;

    let mut ctx = tera::Context::new();
    ctx.insert("upstream_dns", &dns_config.upstream_dns);
    ctx.insert("domain", &dns_config.domain);
    ctx.insert("dnssec", &dns_config.dnssec);
    ctx.insert("rebind_protection", &dns_config.rebind_protection);
    ctx.insert("cache_size", &dns_config.cache_size);
    ctx.insert("bind_interfaces", &dns_config.bind_interfaces);
    ctx.insert("dhcp_ranges", dhcp_ranges);
    ctx.insert("static_leases", static_leases);
    ctx.insert("dns_overrides", dns_overrides);

    let rendered = tera
        .render("dnsmasq.conf", &ctx)
        .context("failed to render dnsmasq template")?;
    Ok(rendered)
}

/// Default output path for the generated dnsmasq config.
const DEFAULT_CONFIG_PATH: &str = "/etc/dnsmasq.d/sfgw.conf";

/// Default dnsmasq lease file path.
const DEFAULT_LEASE_FILE: &str = "/var/lib/misc/dnsmasq.leases";

/// Default PID file for the managed dnsmasq instance.
const DEFAULT_PID_FILE: &str = "/var/run/dnsmasq/sfgw-dnsmasq.pid";

/// Write the generated config to disk.
pub async fn write_config(db: &sfgw_db::Db, path: Option<&Path>) -> Result<PathBuf> {
    let output = path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));

    let rendered = generate_config(db).await?;

    // Ensure parent directory exists
    if let Some(parent) = output.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create config dir: {}", parent.display()))?;
    }

    tokio::fs::write(&output, rendered.as_bytes())
        .await
        .with_context(|| format!("failed to write dnsmasq config: {}", output.display()))?;

    tracing::info!(path = %output.display(), "dnsmasq config written");
    Ok(output)
}

// ---------------------------------------------------------------------------
// Process management
// ---------------------------------------------------------------------------

/// Handle to a managed dnsmasq process.
pub struct DnsmasqProcess {
    pid_file: PathBuf,
    config_path: PathBuf,
    child: Arc<Mutex<Option<tokio::process::Child>>>,
}

impl DnsmasqProcess {
    /// Read the PID from the pid file (if dnsmasq wrote one).
    async fn read_pid(&self) -> Result<Option<i32>> {
        match tokio::fs::read_to_string(&self.pid_file).await {
            Ok(contents) => {
                let pid: i32 = contents
                    .trim()
                    .parse()
                    .with_context(|| format!("invalid pid in {}", self.pid_file.display()))?;
                Ok(Some(pid))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::Error::from(e)
                .context("failed to read dnsmasq pid file")
                .into()),
        }
    }

    /// Send a signal to the running dnsmasq process.
    async fn send_signal(&self, sig: Signal) -> Result<()> {
        if let Some(pid) = self.read_pid().await? {
            signal::kill(Pid::from_raw(pid), sig)
                .with_context(|| format!("failed to send {sig} to dnsmasq (pid {pid})"))?;
            Ok(())
        } else {
            Err(DnsError::Internal(anyhow::anyhow!(
                "dnsmasq is not running (no pid file)"
            )))
        }
    }
}

/// Start the dnsmasq process with the generated config.
///
/// Generates the config from the DB, writes it to disk, and launches dnsmasq.
pub async fn start(db: &sfgw_db::Db) -> Result<DnsmasqProcess> {
    start_with_paths(db, None, None).await
}

/// Start with explicit config and PID file paths (useful for testing).
pub async fn start_with_paths(
    db: &sfgw_db::Db,
    config_path: Option<&Path>,
    pid_file: Option<&Path>,
) -> Result<DnsmasqProcess> {
    let config_path = write_config(db, config_path).await?;
    let pid_file = pid_file
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PID_FILE));

    // Ensure PID file directory exists
    if let Some(parent) = pid_file.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create pid dir: {}", parent.display()))?;
    }

    let child = tokio::process::Command::new("dnsmasq")
        .arg("--keep-in-foreground")
        .arg(format!("--conf-file={}", config_path.display()))
        .arg(format!("--pid-file={}", pid_file.display()))
        .kill_on_drop(true)
        .spawn()
        .context("failed to start dnsmasq")?;

    let pid = child
        .id()
        .ok_or_else(|| anyhow::anyhow!("dnsmasq process has no PID"))?;

    tracing::info!(
        pid = pid,
        config = %config_path.display(),
        "dnsmasq started"
    );

    Ok(DnsmasqProcess {
        pid_file,
        config_path,
        child: Arc::new(Mutex::new(Some(child))),
    })
}

/// Reload dnsmasq configuration (regenerate config, then SIGHUP).
pub async fn reload(proc: &DnsmasqProcess, db: &sfgw_db::Db) -> Result<()> {
    write_config(db, Some(&proc.config_path)).await?;
    proc.send_signal(Signal::SIGHUP).await?;
    tracing::info!("dnsmasq reloaded (SIGHUP)");
    Ok(())
}

/// Stop the managed dnsmasq process.
pub async fn stop(proc: &DnsmasqProcess) -> Result<()> {
    // Try graceful SIGTERM first via the child handle
    let mut guard = proc.child.lock().await;
    if let Some(ref mut child) = *guard {
        child.kill().await.context("failed to kill dnsmasq")?;
        tracing::info!("dnsmasq stopped");
    } else {
        // Fall back to PID-file-based signal
        drop(guard);
        proc.send_signal(Signal::SIGTERM).await?;
        tracing::info!("dnsmasq stopped via SIGTERM");
    }

    // Clean up PID file
    let _ = tokio::fs::remove_file(&proc.pid_file).await;

    // Mark child as gone
    let mut guard = proc.child.lock().await;
    *guard = None;

    Ok(())
}

// ---------------------------------------------------------------------------
// Lease monitoring
// ---------------------------------------------------------------------------

/// Parse the dnsmasq lease file and return active DHCP leases.
///
/// Each line has the format:
/// `<expiry> <mac> <ip> <hostname> <client-id>`
pub async fn read_leases(lease_file: Option<&Path>) -> Result<Vec<DhcpLease>> {
    let path = lease_file.unwrap_or_else(|| Path::new(DEFAULT_LEASE_FILE));

    let contents = match tokio::fs::read_to_string(path).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!(path = %path.display(), "lease file not found, returning empty");
            return Ok(Vec::new());
        }
        Err(e) => {
            return Err(anyhow::Error::from(e)
                .context(format!("failed to read lease file: {}", path.display()))
                .into());
        }
    };

    let mut leases = Vec::new();
    for (line_no, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(5, ' ').collect();
        if parts.len() < 4 {
            tracing::warn!(line = line_no + 1, "skipping malformed lease line");
            continue;
        }
        let expires: u64 = match parts[0].parse() {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(line = line_no + 1, "skipping lease with invalid expiry");
                continue;
            }
        };
        leases.push(DhcpLease {
            expires,
            mac: parts[1].to_string(),
            ip: parts[2].to_string(),
            hostname: parts[3].to_string(),
            client_id: if parts.len() == 5 {
                parts[4].to_string()
            } else {
                "*".to_string()
            },
        });
    }

    tracing::debug!(count = leases.len(), "parsed DHCP leases");
    Ok(leases)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_renders() {
        let cfg = DnsConfig::default();
        let ranges = vec![DhcpRange {
            interface: "br-lan".into(),
            start_ip: "192.168.1.100".into(),
            end_ip: "192.168.1.200".into(),
            netmask: "255.255.255.0".into(),
            gateway: "192.168.1.1".into(),
            lease_time: "12h".into(),
            vlan_id: None,
        }];
        let statics = vec![DhcpStaticLease {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ip: "192.168.1.10".into(),
            hostname: Some("server".into()),
        }];
        let overrides = vec![DnsOverride {
            domain: "internal.example.com".into(),
            ip: "10.0.0.1".into(),
        }];

        let result = render_template(&cfg, &ranges, &statics, &overrides).unwrap();

        // Security defaults present
        assert!(result.contains("stop-dns-rebind"));
        assert!(result.contains("dnssec"));
        assert!(result.contains("dnssec-check-unsigned"));
        assert!(result.contains("bind-interfaces"));
        assert!(result.contains("log-queries"));
        assert!(result.contains("bogus-priv"));
        assert!(result.contains("domain-needed"));

        // Upstream DNS
        assert!(result.contains("server=1.1.1.1"));
        assert!(result.contains("server=9.9.9.9"));

        // DHCP range
        assert!(result.contains("dhcp-range=br-lan,192.168.1.100,192.168.1.200,255.255.255.0,12h"));

        // Static lease
        assert!(result.contains("dhcp-host=aa:bb:cc:dd:ee:ff,192.168.1.10,server"));

        // DNS override
        assert!(result.contains("address=/internal.example.com/10.0.0.1"));
    }

    #[test]
    fn test_vlan_range_renders() {
        let cfg = DnsConfig::default();
        let ranges = vec![DhcpRange {
            interface: "br-lan.20".into(),
            start_ip: "10.20.0.100".into(),
            end_ip: "10.20.0.200".into(),
            netmask: "255.255.255.0".into(),
            gateway: "10.20.0.1".into(),
            lease_time: "6h".into(),
            vlan_id: Some(20),
        }];

        let result = render_template(&cfg, &ranges, &[], &[]).unwrap();
        assert!(result.contains("VLAN 20"));
        assert!(result.contains("dhcp-range=br-lan.20,10.20.0.100,10.20.0.200"));
    }

    #[test]
    fn test_security_off_flags() {
        let cfg = DnsConfig {
            dnssec: false,
            rebind_protection: false,
            ..DnsConfig::default()
        };

        let result = render_template(&cfg, &[], &[], &[]).unwrap();
        assert!(!result.contains("stop-dns-rebind"));
        assert!(!result.contains("dnssec"));
    }

    #[test]
    fn test_parse_lease_line() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let dir = std::env::temp_dir().join("sfgw-dns-test");
            let _ = tokio::fs::create_dir_all(&dir).await;
            let lease_path = dir.join("test.leases");
            let content = "1700000000 aa:bb:cc:dd:ee:ff 192.168.1.50 myhost 01:aa:bb:cc:dd:ee:ff\n\
                           1700000100 11:22:33:44:55:66 192.168.1.51 * *\n";
            tokio::fs::write(&lease_path, content).await.unwrap();

            let leases = read_leases(Some(&lease_path)).await.unwrap();
            assert_eq!(leases.len(), 2);
            assert_eq!(leases[0].mac, "aa:bb:cc:dd:ee:ff");
            assert_eq!(leases[0].ip, "192.168.1.50");
            assert_eq!(leases[0].hostname, "myhost");
            assert_eq!(leases[1].hostname, "*");

            let _ = tokio::fs::remove_dir_all(&dir).await;
        });
    }

    #[test]
    fn test_missing_lease_file() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let leases = read_leases(Some(Path::new("/tmp/sfgw-nonexistent-leases")))
                .await
                .unwrap();
            assert!(leases.is_empty());
        });
    }

    #[test]
    fn test_dns_config_serde_roundtrip() {
        let cfg = DnsConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let cfg2: DnsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg.upstream_dns, cfg2.upstream_dns);
        assert_eq!(cfg.dnssec, cfg2.dnssec);
    }
}
