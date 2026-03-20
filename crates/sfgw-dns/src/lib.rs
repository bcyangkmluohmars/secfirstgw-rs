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
// First-boot defaults
// ---------------------------------------------------------------------------

/// Seed sensible DNS/DHCP defaults when no configuration exists in the database.
///
/// On a fresh install the `meta` table has no DNS or DHCP keys. This function
/// reads all enabled networks from the `networks` table and creates DNS bind
/// interfaces and DHCP ranges for each one.
///
/// If *either* `dns_config` or `dhcp_ranges` already exists in the DB, this
/// function is a no-op — it never overwrites user configuration.
pub async fn ensure_first_boot_defaults(db: &sfgw_db::Db, wan_gateway: Option<&str>) -> Result<()> {
    let conn = db.lock().await;

    let has_dns: bool = meta_get::<DnsConfig>(&conn, KEY_DNS_CONFIG)?.is_some();
    let has_dhcp: bool = meta_get::<Vec<DhcpRange>>(&conn, KEY_DHCP_RANGES)?.is_some();

    if has_dns && has_dhcp {
        tracing::debug!("DNS/DHCP config already present — skipping first-boot defaults");
        return Ok(());
    }

    tracing::info!("first boot detected — seeding DNS/DHCP defaults");

    // Load all enabled non-void networks to build DNS bind list and DHCP ranges.
    // (zone, vlan_id, subnet, gateway, dhcp_start, dhcp_end, dhcp_enabled)
    type NetworkRow = (String, Option<i32>, String, String, String, String, bool);
    let mut networks: Vec<NetworkRow> = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT zone, vlan_id, subnet, gateway, dhcp_start, dhcp_end, dhcp_enabled \
                 FROM networks WHERE enabled = 1 AND zone != 'void'",
            )
            .map_err(DnsError::Database)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i32>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, bool>(6)?,
                ))
            })
            .map_err(DnsError::Database)?;
        for row in rows {
            networks.push(row.map_err(DnsError::Database)?);
        }
    }

    if !has_dns {
        let mut upstream: Vec<String> = Vec::new();
        if let Some(gw) = wan_gateway {
            upstream.push(gw.to_string());
        }
        upstream.push("1.1.1.1".into());
        upstream.push("9.9.9.9".into());

        let bind_interfaces: Vec<String> = networks
            .iter()
            .map(|(zone, ..)| format!("br-{zone}"))
            .collect();

        let dns_config = DnsConfig {
            upstream_dns: upstream,
            bind_interfaces,
            ..DnsConfig::default()
        };
        meta_set(&conn, KEY_DNS_CONFIG, &dns_config)?;
        tracing::info!(
            upstream = ?dns_config.upstream_dns,
            interfaces = ?dns_config.bind_interfaces,
            "seeded default DNS config"
        );
    }

    if !has_dhcp {
        let mut ranges = Vec::new();
        for (zone, vlan_id, subnet, gateway, dhcp_start, dhcp_end, dhcp_enabled) in &networks {
            if !dhcp_enabled {
                continue;
            }
            // Derive netmask from subnet CIDR prefix
            let netmask = cidr_to_netmask(subnet);
            ranges.push(DhcpRange {
                interface: format!("br-{zone}"),
                start_ip: dhcp_start.clone(),
                end_ip: dhcp_end.clone(),
                netmask,
                gateway: gateway.clone(),
                lease_time: "12h".into(),
                vlan_id: vlan_id.map(|v| v as u16),
            });
        }
        meta_set(&conn, KEY_DHCP_RANGES, &ranges)?;
        tracing::info!(
            count = ranges.len(),
            "seeded default DHCP ranges from enabled networks"
        );
    }

    Ok(())
}

/// Convert a CIDR subnet string (e.g. "192.168.1.0/24") to a dotted netmask.
fn cidr_to_netmask(subnet: &str) -> String {
    let prefix: u32 = subnet
        .split('/')
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(24);
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF,
    )
}

// ---------------------------------------------------------------------------
// Config generation
// ---------------------------------------------------------------------------

/// Dnsmasq template embedded at compile time.
const DNSMASQ_TEMPLATE: &str = include_str!("templates/dnsmasq.conf.tera");

/// Render the dnsmasq configuration from the current database state.
///
/// Automatically detects whether the installed dnsmasq binary supports
/// DNSSEC and disables it in the config if not (stock UDM dnsmasq is
/// compiled with `no-DNSSEC`).
pub async fn generate_config(db: &sfgw_db::Db) -> Result<String> {
    let mut dns_config = load_dns_config(db).await?;
    let dhcp_ranges = load_dhcp_ranges(db).await?;
    let static_leases = load_static_leases(db).await?;
    let dns_overrides = load_dns_overrides(db).await?;

    // Auto-detect DNSSEC support: check if the installed dnsmasq binary
    // was compiled with --enable-dnssec. If not, override the config
    // setting to prevent startup failures.
    if dns_config.dnssec && !dnsmasq_supports_dnssec() {
        tracing::warn!(
            "DNSSEC requested but dnsmasq binary lacks DNSSEC support — disabling"
        );
        dns_config.dnssec = false;
    }

    render_template(&dns_config, &dhcp_ranges, &static_leases, &dns_overrides)
}

/// Check if the installed dnsmasq binary supports DNSSEC.
///
/// Parses the `Compile time options` line from `dnsmasq --version` output.
/// Returns `false` if dnsmasq is not found or reports `no-DNSSEC`.
fn dnsmasq_supports_dnssec() -> bool {
    let output = match std::process::Command::new("dnsmasq")
        .arg("--version")
        .output()
    {
        Ok(o) => o,
        Err(_) => return false,
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Look for "DNSSEC" in compile options (present as either "DNSSEC" or "no-DNSSEC")
    for line in stdout.lines() {
        if line.contains("Compile time options") || line.starts_with("Compile time options") {
            // "no-DNSSEC" means not supported, bare "DNSSEC" means supported
            if line.contains("no-DNSSEC") {
                return false;
            }
            if line.contains("DNSSEC") {
                return true;
            }
        }
    }
    // dnsmasq --version outputs compile options across multiple lines
    if stdout.contains("no-DNSSEC") {
        return false;
    }
    stdout.contains("DNSSEC")
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
const DEFAULT_LEASE_FILE: &str = "/data/sfgw/dnsmasq.leases";

/// Default PID file for the managed dnsmasq instance.
/// Uses /run/ which exists on all modern Linux (systemd, OpenRC, etc.).
const DEFAULT_PID_FILE: &str = "/run/sfgw-dnsmasq.pid";

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
/// On first boot (no DNS/DHCP config in the database) this seeds sensible
/// defaults before generating the dnsmasq configuration.  Pass the WAN
/// gateway IP (if known) so it can be added as the primary upstream DNS
/// server; public resolvers `1.1.1.1` and `9.9.9.9` are always appended
/// as fallback.
pub async fn start(db: &sfgw_db::Db) -> Result<DnsmasqProcess> {
    start_with_upstream(db, None).await
}

/// Like [`start`], but accepts an optional WAN gateway to use as the
/// primary upstream DNS forwarder on first boot.
pub async fn start_with_upstream(
    db: &sfgw_db::Db,
    wan_gateway: Option<&str>,
) -> Result<DnsmasqProcess> {
    ensure_first_boot_defaults(db, wan_gateway).await?;
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

    // Ensure data directory exists (logs + leases go here)
    tokio::fs::create_dir_all("/data/sfgw")
        .await
        .with_context(|| "failed to create /data/sfgw")?;

    let child = tokio::process::Command::new("dnsmasq")
        .arg("--no-daemon")
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

/// Standalone reload: regenerate config and SIGHUP dnsmasq via PID file.
///
/// Use this when you don't have a `DnsmasqProcess` reference (e.g. from
/// another crate that modified DNS overrides in the database).
/// No-op if dnsmasq is not running.
pub async fn reload_by_pid_file(db: &sfgw_db::Db) -> Result<()> {
    write_config(db, None).await?;

    match tokio::fs::read_to_string(DEFAULT_PID_FILE).await {
        Ok(contents) => {
            let pid: i32 = contents
                .trim()
                .parse()
                .with_context(|| format!("invalid PID in {DEFAULT_PID_FILE}"))?;
            signal::kill(Pid::from_raw(pid), Signal::SIGHUP)
                .with_context(|| format!("failed to SIGHUP dnsmasq (pid {pid})"))?;
            tracing::info!(pid, "dnsmasq reloaded via PID file (SIGHUP)");
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!("dnsmasq not running (no PID file) — skipping reload");
        }
        Err(e) => {
            return Err(DnsError::Internal(
                anyhow::Error::from(e).context("failed to read dnsmasq PID file"),
            ));
        }
    }

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
        // When dnssec=false, the "dnssec" directive must not appear as an active line.
        assert!(
            !result.lines().any(|l| l.trim() == "dnssec"),
            "dnssec directive must not be active when dnssec=false"
        );
    }

    #[test]
    fn test_dnssec_enabled() {
        let cfg = DnsConfig {
            dnssec: true,
            ..DnsConfig::default()
        };
        let result = render_template(&cfg, &[], &[], &[]).unwrap();
        assert!(
            result.lines().any(|l| l.trim() == "dnssec"),
            "dnssec directive must be active when dnssec=true"
        );
        assert!(
            result.contains("trust-anchor=.,20326"),
            "DNSSEC trust anchor for root zone must be present"
        );
        assert!(
            result.contains("proxy-dnssec"),
            "proxy-dnssec must be enabled to forward AD flag to clients"
        );
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

    /// Helper: create an in-memory database with the sfgw schema.
    async fn test_db() -> sfgw_db::Db {
        sfgw_db::open_in_memory()
            .await
            .expect("failed to open in-memory db")
    }

    /// Helper: seed the `networks` table with standard defaults for testing.
    async fn seed_networks(db: &sfgw_db::Db) {
        let conn = db.lock().await;
        for (name, zone, vlan_id, subnet, gw, ds, de) in &[
            (
                "LAN",
                "lan",
                10,
                "192.168.1.0/24",
                "192.168.1.1",
                "192.168.1.100",
                "192.168.1.254",
            ),
            (
                "Management",
                "mgmt",
                3000,
                "10.0.0.0/24",
                "10.0.0.1",
                "10.0.0.100",
                "10.0.0.254",
            ),
            (
                "Guest",
                "guest",
                3001,
                "192.168.3.0/24",
                "192.168.3.1",
                "192.168.3.100",
                "192.168.3.254",
            ),
            (
                "DMZ",
                "dmz",
                3002,
                "172.16.0.0/24",
                "172.16.0.1",
                "172.16.0.100",
                "172.16.0.254",
            ),
        ] {
            conn.execute(
                "INSERT OR IGNORE INTO networks (name, zone, vlan_id, subnet, gateway, dhcp_start, dhcp_end, dhcp_enabled, enabled)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, 1)",
                rusqlite::params![name, zone, vlan_id, subnet, gw, ds, de],
            ).unwrap();
        }
    }

    #[tokio::test]
    async fn test_first_boot_defaults_seeds_config() {
        let db = test_db().await;
        seed_networks(&db).await;

        // Verify nothing exists yet.
        let ranges = load_dhcp_ranges(&db).await.unwrap();
        assert!(ranges.is_empty(), "fresh DB should have no DHCP ranges");

        // Seed defaults without a WAN gateway.
        ensure_first_boot_defaults(&db, None).await.unwrap();

        // DNS config should now exist with public fallback resolvers.
        let dns = load_dns_config(&db).await.unwrap();
        assert_eq!(dns.upstream_dns, vec!["1.1.1.1", "9.9.9.9"]);
        assert_eq!(dns.domain, "lan");
        assert!(dns.dnssec);
        assert!(dns.rebind_protection);
        // All 4 enabled zones should have bind interfaces
        assert!(dns.bind_interfaces.contains(&"br-lan".to_string()));
        assert!(dns.bind_interfaces.contains(&"br-mgmt".to_string()));
        assert!(dns.bind_interfaces.contains(&"br-guest".to_string()));
        assert!(dns.bind_interfaces.contains(&"br-dmz".to_string()));

        // DHCP ranges for all 4 zones
        let ranges = load_dhcp_ranges(&db).await.unwrap();
        assert_eq!(ranges.len(), 4);
        let ifaces: Vec<&str> = ranges.iter().map(|r| r.interface.as_str()).collect();
        assert!(ifaces.contains(&"br-lan"));
        assert!(ifaces.contains(&"br-mgmt"));
        assert!(ifaces.contains(&"br-guest"));
        assert!(ifaces.contains(&"br-dmz"));
    }

    #[tokio::test]
    async fn test_first_boot_defaults_with_wan_gateway() {
        let db = test_db().await;
        seed_networks(&db).await;

        ensure_first_boot_defaults(&db, Some("203.0.113.1"))
            .await
            .unwrap();

        let dns = load_dns_config(&db).await.unwrap();
        assert_eq!(
            dns.upstream_dns,
            vec!["203.0.113.1", "1.1.1.1", "9.9.9.9"],
            "WAN gateway should be the primary upstream"
        );
    }

    #[tokio::test]
    async fn test_first_boot_defaults_noop_when_config_exists() {
        let db = test_db().await;

        // Manually save custom DNS config.
        let custom_dns = DnsConfig {
            upstream_dns: vec!["8.8.8.8".into()],
            ..DnsConfig::default()
        };
        save_dns_config(&db, &custom_dns).await.unwrap();

        // Manually save a custom DHCP range.
        let custom_range = DhcpRange {
            interface: "br-lan".into(),
            start_ip: "10.0.0.50".into(),
            end_ip: "10.0.0.100".into(),
            netmask: "255.255.255.0".into(),
            gateway: "10.0.0.1".into(),
            lease_time: "24h".into(),
            vlan_id: None,
        };
        save_dhcp_ranges(&db, &[custom_range]).await.unwrap();

        // Calling first-boot defaults should be a no-op.
        ensure_first_boot_defaults(&db, Some("99.99.99.99"))
            .await
            .unwrap();

        // Verify nothing was overwritten.
        let dns = load_dns_config(&db).await.unwrap();
        assert_eq!(dns.upstream_dns, vec!["8.8.8.8"]);

        let ranges = load_dhcp_ranges(&db).await.unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start_ip, "10.0.0.50");
    }

    #[tokio::test]
    async fn test_first_boot_defaults_generate_valid_config() {
        let db = test_db().await;
        seed_networks(&db).await;

        ensure_first_boot_defaults(&db, Some("203.0.113.1"))
            .await
            .unwrap();

        // generate_config should produce valid dnsmasq output.
        let config = generate_config(&db).await.unwrap();
        assert!(config.contains("server=203.0.113.1"));
        assert!(config.contains("server=1.1.1.1"));
        assert!(config.contains("server=9.9.9.9"));
        assert!(config.contains("dhcp-range=br-lan,192.168.1.100,192.168.1.254,255.255.255.0,12h"));
        assert!(config.contains("dhcp-option=br-lan,3,192.168.1.1"));
        assert!(config.contains("dhcp-option=br-lan,6,192.168.1.1"));
        assert!(config.contains("domain=lan"));
        assert!(config.contains("interface=br-lan"));
        assert!(config.contains("interface=br-mgmt"));
        assert!(config.contains("interface=br-guest"));
        assert!(config.contains("interface=br-dmz"));
        // All zone DHCP ranges
        assert!(config.contains("dhcp-range=br-mgmt,10.0.0.100,10.0.0.254,255.255.255.0,12h"));
        assert!(
            config.contains("dhcp-range=br-guest,192.168.3.100,192.168.3.254,255.255.255.0,12h")
        );
        assert!(config.contains("dhcp-range=br-dmz,172.16.0.100,172.16.0.254,255.255.255.0,12h"));
    }
}
