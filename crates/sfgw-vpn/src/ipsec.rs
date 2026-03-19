// SPDX-License-Identifier: AGPL-3.0-or-later

//! IPsec/IKEv2 tunnel management via strongSwan (swanctl).
//!
//! Generates swanctl.conf snippets, manages tunnel lifecycle, and handles
//! certificate installation for the sfgw-adopt CA integration.
//!
//! # Security
//!
//! - Modern cipher suites ONLY: AES-256-GCM, ChaCha20-Poly1305, SHA-384, X25519
//! - No 3DES, no SHA-1, no DH group 14 or below
//! - All tunnel names/IDs validated against shell metacharacter injection
//! - PSK material wrapped in `SecureBox` — never hardcoded
//! - Config files written with restricted permissions (0o600)

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tracing::{info, warn};

use crate::{
    CreateIpsecTunnelRequest, IpsecAuthMethod, IpsecDbConfig, IpsecMode, TunnelType, VpnError,
    VpnTunnel,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Base directory for swanctl configuration snippets.
const SWANCTL_CONF_DIR: &str = "/etc/swanctl/conf.d";

/// Directory for CA certificates.
const SWANCTL_X509CA_DIR: &str = "/etc/swanctl/x509ca";

/// Directory for server certificates.
const SWANCTL_X509_DIR: &str = "/etc/swanctl/x509";

/// Directory for private keys.
const SWANCTL_PRIVATE_DIR: &str = "/etc/swanctl/private";

/// Modern IKE proposals — AES-256-GCM and ChaCha20-Poly1305 only.
const IKE_PROPOSALS: &str = "aes256gcm16-sha384-x25519,chacha20poly1305-sha384-x25519";

/// Modern ESP proposals — AES-256-GCM and ChaCha20-Poly1305 only.
const ESP_PROPOSALS: &str = "aes256gcm16-sha384,chacha20poly1305-sha384";

/// Default IKE rekey time (4 hours).
const DEFAULT_REKEY_TIME: &str = "14400";

// ---------------------------------------------------------------------------
// Config generation
// ---------------------------------------------------------------------------

/// Generate a swanctl.conf snippet for an IPsec tunnel.
///
/// Returns the config file content as a string. The caller is responsible
/// for writing it to the filesystem.
pub fn generate_swanctl_config(name: &str, config: &IpsecDbConfig) -> Result<String, VpnError> {
    validate_swanctl_name(name)?;
    validate_swanctl_value(&config.local_id)?;

    if let Some(ref addrs) = config.local_addrs {
        validate_swanctl_value(addrs)?;
    }
    if let Some(ref dns) = config.dns {
        validate_swanctl_value(dns)?;
    }

    let mode = IpsecMode::parse(&config.mode)?;
    let auth_method = IpsecAuthMethod::parse(&config.auth_method)?;

    let mut out = String::with_capacity(1024);

    out.push_str("connections {\n");
    out.push_str(&format!("    sfgw-{name} {{\n"));
    out.push_str("        version = 2\n");
    out.push_str(&format!("        proposals = {IKE_PROPOSALS}\n"));
    out.push_str(&format!("        rekey_time = {DEFAULT_REKEY_TIME}\n"));
    out.push_str("        dpd_delay = 30\n");

    // Local address binding
    let local_addrs = config.local_addrs.as_deref().unwrap_or("%any");
    out.push_str(&format!("        local_addrs = {local_addrs}\n"));

    // Pools for roadwarrior mode
    if mode == IpsecMode::RoadWarrior {
        let mut pools = Vec::new();
        if config.pool_v4.is_some() {
            pools.push(format!("pool-{name}-v4"));
        }
        if config.pool_v6.is_some() {
            pools.push(format!("pool-{name}-v6"));
        }
        if !pools.is_empty() {
            out.push_str(&format!("        pools = {}\n", pools.join(",")));
        }
    }

    // Local authentication
    out.push_str("        local {\n");
    match auth_method {
        IpsecAuthMethod::Certificate => {
            out.push_str("            auth = pubkey\n");
            out.push_str(&format!("            id = {}\n", config.local_id));
        }
        IpsecAuthMethod::Psk => {
            out.push_str("            auth = psk\n");
            out.push_str(&format!("            id = {}\n", config.local_id));
        }
        IpsecAuthMethod::EapMschapv2 => {
            out.push_str("            auth = pubkey\n");
            out.push_str(&format!("            id = {}\n", config.local_id));
        }
    }
    out.push_str("        }\n");

    // Remote authentication
    out.push_str("        remote {\n");
    match auth_method {
        IpsecAuthMethod::Certificate => {
            out.push_str("            auth = pubkey\n");
        }
        IpsecAuthMethod::Psk => {
            out.push_str("            auth = psk\n");
        }
        IpsecAuthMethod::EapMschapv2 => {
            out.push_str("            auth = eap-mschapv2\n");
            // EAP requires server to send cert first, client authenticates via EAP
            out.push_str("            eap_id = %any\n");
        }
    }
    out.push_str("        }\n");

    // Children (IPsec SA / traffic selectors)
    out.push_str("        children {\n");
    out.push_str(&format!("            {name} {{\n"));
    out.push_str(&format!(
        "                esp_proposals = {ESP_PROPOSALS}\n"
    ));
    out.push_str(&format!(
        "                rekey_time = {DEFAULT_REKEY_TIME}\n"
    ));

    // Traffic selectors
    match mode {
        IpsecMode::RoadWarrior => {
            out.push_str("                local_ts = 0.0.0.0/0,::/0\n");
            out.push_str("                remote_ts = dynamic\n");
        }
        IpsecMode::SiteToSite => {
            if !config.local_ts.is_empty() {
                for ts in &config.local_ts {
                    validate_swanctl_value(ts)?;
                }
                out.push_str(&format!(
                    "                local_ts = {}\n",
                    config.local_ts.join(",")
                ));
            }
            if !config.remote_ts.is_empty() {
                for ts in &config.remote_ts {
                    validate_swanctl_value(ts)?;
                }
                out.push_str(&format!(
                    "                remote_ts = {}\n",
                    config.remote_ts.join(",")
                ));
            }
        }
    }

    out.push_str("                dpd_action = restart\n");
    out.push_str("                start_action = trap\n");
    out.push_str("            }\n");
    out.push_str("        }\n");
    out.push_str("    }\n");
    out.push_str("}\n");

    // Pools section (roadwarrior only)
    if mode == IpsecMode::RoadWarrior && (config.pool_v4.is_some() || config.pool_v6.is_some()) {
        out.push_str("\npools {\n");
        if let Some(ref pool_v4) = config.pool_v4 {
            validate_swanctl_value(pool_v4)?;
            out.push_str(&format!("    pool-{name}-v4 {{\n"));
            out.push_str(&format!("        addrs = {pool_v4}\n"));
            if let Some(ref dns) = config.dns {
                out.push_str(&format!("        dns = {dns}\n"));
            }
            out.push_str("    }\n");
        }
        if let Some(ref pool_v6) = config.pool_v6 {
            validate_swanctl_value(pool_v6)?;
            out.push_str(&format!("    pool-{name}-v6 {{\n"));
            out.push_str(&format!("        addrs = {pool_v6}\n"));
            if let Some(ref dns) = config.dns {
                out.push_str(&format!("        dns = {dns}\n"));
            }
            out.push_str("    }\n");
        }
        out.push_str("}\n");
    }

    // Secrets section (PSK only — cert secrets reference files, PSK needs explicit section)
    if auth_method == IpsecAuthMethod::Psk {
        out.push_str("\nsecrets {\n");
        out.push_str(&format!("    ike-sfgw-{name} {{\n"));
        // PSK references a file rather than inlining — prevents config injection
        // and keeps secrets out of the config text.
        let psk_path = psk_file_path(name);
        out.push_str(&format!("        file = {}\n", psk_path.display()));
        out.push_str("    }\n");
        out.push_str("}\n");
    }

    Ok(out)
}

/// Path to the swanctl config file for a given tunnel name.
#[must_use]
pub fn config_file_path(name: &str) -> PathBuf {
    Path::new(SWANCTL_CONF_DIR).join(format!("sfgw-{name}.conf"))
}

/// Path to the PSK secret file for a given tunnel (used for PSK auth).
#[must_use]
pub fn psk_file_path(name: &str) -> PathBuf {
    Path::new(SWANCTL_PRIVATE_DIR).join(format!("sfgw-{name}.psk"))
}

// ---------------------------------------------------------------------------
// Tunnel lifecycle
// ---------------------------------------------------------------------------

/// Create an IPsec tunnel: validate, persist to DB, write swanctl config.
pub async fn create_ipsec_tunnel(
    db: &sfgw_db::Db,
    request: &CreateIpsecTunnelRequest,
) -> Result<VpnTunnel> {
    let name = &request.name;

    // Validate tunnel name (same rules as WireGuard)
    if name.len() > 15 || name.is_empty() {
        bail!("tunnel name must be 1-15 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("tunnel name must be alphanumeric, dash, or underscore");
    }

    // Validate no shell metacharacters in all string inputs
    validate_swanctl_name(name).map_err(|e| anyhow::anyhow!("{e}"))?;

    if let Some(ref id) = request.local_id {
        validate_swanctl_value(id).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // Validate pools if roadwarrior
    if request.mode == IpsecMode::RoadWarrior {
        if request.pool_v4.is_none() && request.pool_v6.is_none() {
            bail!("roadwarrior mode requires at least one IP pool (pool_v4 or pool_v6)");
        }
        if let Some(ref pool) = request.pool_v4 {
            validate_cidr(pool)?;
        }
        if let Some(ref pool) = request.pool_v6 {
            validate_cidr(pool)?;
        }
    }

    // Validate traffic selectors if site-to-site
    if request.mode == IpsecMode::SiteToSite {
        if let Some(ref ts) = request.local_ts {
            for t in ts {
                validate_cidr(t)?;
            }
        }
        if let Some(ref ts) = request.remote_ts {
            for t in ts {
                validate_cidr(t)?;
            }
        }
    }

    // Check name collision
    if crate::db::get_tunnel_by_name(db, name).await?.is_some() {
        bail!("tunnel '{}' already exists", name);
    }

    let local_id = request
        .local_id
        .clone()
        .unwrap_or_else(|| format!("sfgw-{name}"));

    let db_config = IpsecDbConfig {
        mode: request.mode.to_string(),
        auth_method: request.auth_method.to_string(),
        local_id,
        listen_port: request.listen_port,
        local_addrs: request.local_addrs.clone(),
        pool_v4: request.pool_v4.clone(),
        pool_v6: request.pool_v6.clone(),
        local_ts: request.local_ts.clone().unwrap_or_default(),
        remote_ts: request.remote_ts.clone().unwrap_or_default(),
        dns: request.dns.clone(),
        zone: request.zone.clone(),
    };

    let config_json =
        serde_json::to_string(&db_config).context("failed to serialize IPsec config")?;

    // Validate that the config generates valid swanctl output before persisting
    generate_swanctl_config(name, &db_config).map_err(|e| anyhow::anyhow!("{e}"))?;

    let id = crate::db::insert_tunnel(db, name, "ipsec", &config_json).await?;

    // Write the swanctl config file
    if let Err(e) = write_swanctl_config(name, &db_config).await {
        warn!(tunnel = name, "failed to write swanctl config: {e}");
    }

    info!(tunnel = name, mode = %request.mode, auth = %request.auth_method, "created IPsec tunnel");

    Ok(VpnTunnel {
        id,
        name: name.to_string(),
        tunnel_type: TunnelType::IPsec,
        enabled: false,
        listen_port: request.listen_port.unwrap_or(500),
        public_key: String::new(), // IPsec uses certificates, not WG public keys
        address: db_config.pool_v4.clone().unwrap_or_default(),
        address_v6: db_config.pool_v6.clone(),
        dns: request.dns.clone(),
        mtu: 1400, // Typical IPsec MTU
        zone: request.zone.clone(),
        // IPsec uses local_addrs for WAN binding, not bind_interface
        bind_interface: None,
        peers: Vec::new(),
    })
}

/// Start an IPsec tunnel via swanctl.
pub async fn start_ipsec_tunnel(db: &sfgw_db::Db, tunnel_id: i64) -> Result<()> {
    let row = crate::db::get_tunnel_by_id(db, tunnel_id)
        .await?
        .context("tunnel not found")?;

    if row.enabled != 0 {
        bail!("tunnel '{}' is already running", row.name);
    }

    let db_config: IpsecDbConfig =
        serde_json::from_str(&row.config).context("corrupt IPsec config in DB")?;

    // Ensure config file is written
    write_swanctl_config(&row.name, &db_config).await?;

    // Load all swanctl configs
    run_swanctl(&["--load-all"])
        .await
        .context("swanctl --load-all failed")?;

    // For site-to-site, initiate the connection
    let mode = IpsecMode::parse(&db_config.mode).map_err(|e| anyhow::anyhow!("{e}"))?;
    if mode == IpsecMode::SiteToSite {
        run_swanctl(&["--initiate", "--child", &row.name])
            .await
            .context("swanctl --initiate failed")?;
    }

    crate::db::set_tunnel_enabled(db, row.id, true).await?;
    info!(tunnel = row.name, "IPsec tunnel started");
    Ok(())
}

/// Stop an IPsec tunnel via swanctl.
pub async fn stop_ipsec_tunnel(db: &sfgw_db::Db, tunnel_id: i64) -> Result<()> {
    let row = crate::db::get_tunnel_by_id(db, tunnel_id)
        .await?
        .context("tunnel not found")?;

    let ike_name = format!("sfgw-{}", row.name);
    if let Err(e) = run_swanctl(&["--terminate", "--ike", &ike_name]).await {
        warn!(tunnel = row.name.as_str(), "swanctl --terminate: {e}");
    }

    crate::db::set_tunnel_enabled(db, row.id, false).await?;
    info!(tunnel = row.name, "IPsec tunnel stopped");
    Ok(())
}

/// Delete an IPsec tunnel: stop, remove config file, remove from DB.
pub async fn delete_ipsec_tunnel(db: &sfgw_db::Db, tunnel_id: i64) -> Result<()> {
    let row = crate::db::get_tunnel_by_id(db, tunnel_id)
        .await?
        .context("tunnel not found")?;

    // Best-effort stop
    if row.enabled != 0
        && let Err(e) = stop_ipsec_tunnel(db, tunnel_id).await
    {
        warn!(
            tunnel = row.name.as_str(),
            "failed to stop IPsec tunnel during delete: {e}"
        );
    }

    // Remove swanctl config file
    let conf_path = config_file_path(&row.name);
    if let Err(e) = tokio::fs::remove_file(&conf_path).await {
        warn!(path = %conf_path.display(), "failed to remove swanctl config: {e}");
    }

    // Remove PSK file if it exists
    let psk_path = psk_file_path(&row.name);
    if let Err(e) = tokio::fs::remove_file(&psk_path).await {
        // Not an error if it doesn't exist (non-PSK auth)
        tracing::debug!(path = %psk_path.display(), "PSK file removal: {e}");
    }

    // Reload swanctl to pick up removal
    if let Err(e) = run_swanctl(&["--load-all"]).await {
        warn!(
            tunnel = row.name.as_str(),
            "swanctl reload after delete: {e}"
        );
    }

    crate::db::delete_tunnel(db, row.id).await?;
    info!(tunnel = row.name, "IPsec tunnel deleted");
    Ok(())
}

/// Get IPsec tunnel status by parsing `swanctl --list-sas`.
pub async fn get_ipsec_status(name: &str) -> Result<IpsecStatus> {
    validate_swanctl_name(name).map_err(|e| anyhow::anyhow!("{e}"))?;

    let ike_name = format!("sfgw-{name}");
    let output = tokio::process::Command::new("swanctl")
        .args(["--list-sas", "--ike", &ike_name])
        .output()
        .await;

    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            Ok(parse_swanctl_sas(&stdout, name))
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            tracing::debug!(tunnel = name, "swanctl --list-sas: {stderr}");
            Ok(IpsecStatus {
                name: name.to_string(),
                is_up: false,
                ike_state: "none".to_string(),
                child_sas: Vec::new(),
            })
        }
        Err(e) => {
            tracing::debug!(tunnel = name, "swanctl not available: {e}");
            Ok(IpsecStatus {
                name: name.to_string(),
                is_up: false,
                ike_state: "unavailable".to_string(),
                child_sas: Vec::new(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Certificate management
// ---------------------------------------------------------------------------

/// Install a server certificate and key from the sfgw-adopt CA.
///
/// - `ca_cert_pem`: CA certificate in PEM format
/// - `server_cert_pem`: Server certificate in PEM format
/// - `server_key_pem`: Server private key in PEM format (will be written with 0o600 perms)
pub async fn install_server_cert(
    ca_cert_pem: &str,
    server_cert_pem: &str,
    server_key_pem: &str,
) -> Result<()> {
    // Write CA cert
    let ca_path = Path::new(SWANCTL_X509CA_DIR).join("sfgw-ca.pem");
    write_file_restricted(&ca_path, ca_cert_pem.as_bytes(), 0o644).await?;

    // Write server cert
    let cert_path = Path::new(SWANCTL_X509_DIR).join("sfgw-server.pem");
    write_file_restricted(&cert_path, server_cert_pem.as_bytes(), 0o644).await?;

    // Write server key (restricted permissions)
    let key_path = Path::new(SWANCTL_PRIVATE_DIR).join("sfgw-server.pem");
    write_file_restricted(&key_path, server_key_pem.as_bytes(), 0o600).await?;

    // Reload credentials
    run_swanctl(&["--load-creds"])
        .await
        .context("failed to reload strongSwan credentials")?;

    info!("installed server certificate for IPsec");
    Ok(())
}

// ---------------------------------------------------------------------------
// Status types
// ---------------------------------------------------------------------------

/// IPsec tunnel status from swanctl --list-sas.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IpsecStatus {
    pub name: String,
    pub is_up: bool,
    pub ike_state: String,
    pub child_sas: Vec<ChildSaStatus>,
}

/// Status of a child SA (IPsec SA / traffic flow).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChildSaStatus {
    pub name: String,
    pub state: String,
    pub local_ts: String,
    pub remote_ts: String,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Characters allowed in swanctl names/identifiers.
/// Must be alphanumeric, dash, underscore, or dot. No shell metacharacters.
fn validate_swanctl_name(name: &str) -> Result<(), VpnError> {
    if name.is_empty() || name.len() > 64 {
        return Err(VpnError::ConfigInjection(
            "name must be 1-64 characters".to_string(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(VpnError::ConfigInjection(format!(
            "name contains invalid characters: {name}"
        )));
    }
    Ok(())
}

/// Validate a value that will be placed in swanctl.conf.
/// Must not contain shell metacharacters, newlines, or braces that could
/// break the config syntax.
fn validate_swanctl_value(value: &str) -> Result<(), VpnError> {
    if value.len() > 512 {
        return Err(VpnError::ConfigInjection(
            "value too long (max 512 chars)".to_string(),
        ));
    }
    // Reject characters that could break swanctl.conf syntax or enable injection
    const FORBIDDEN: &[char] = &[
        '{', '}', '\n', '\r', '#', '"', '\'', '`', '$', '\\', ';', '|', '&',
    ];
    if value.chars().any(|c| FORBIDDEN.contains(&c)) {
        return Err(VpnError::ConfigInjection(
            "value contains forbidden characters".to_string(),
        ));
    }
    Ok(())
}

/// Validate a CIDR notation address (e.g. "10.10.0.0/24" or "fd10::0/112").
fn validate_cidr(cidr: &str) -> Result<()> {
    match cidr.split_once('/') {
        Some((ip, prefix)) => {
            ip.parse::<std::net::IpAddr>()
                .map_err(|_| anyhow::anyhow!("invalid CIDR address: {cidr}"))?;
            let prefix_num: u8 = prefix
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid prefix length in: {cidr}"))?;
            // Sanity check prefix length
            if ip.contains(':') && prefix_num > 128 {
                bail!("invalid IPv6 prefix length: {prefix_num}");
            }
            if !ip.contains(':') && prefix_num > 32 {
                bail!("invalid IPv4 prefix length: {prefix_num}");
            }
        }
        None => {
            bail!("CIDR notation required (e.g. 10.0.0.0/24), got: {cidr}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Write the swanctl config file to disk.
async fn write_swanctl_config(name: &str, config: &IpsecDbConfig) -> Result<()> {
    let content = generate_swanctl_config(name, config).map_err(|e| anyhow::anyhow!("{e}"))?;
    let path = config_file_path(name);

    write_file_restricted(&path, content.as_bytes(), 0o600)
        .await
        .with_context(|| format!("failed to write swanctl config: {}", path.display()))?;

    tracing::debug!(path = %path.display(), "wrote swanctl config");
    Ok(())
}

/// Write bytes to a file with specified Unix permissions.
async fn write_file_restricted(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create directory: {}", parent.display()))?;
    }

    tokio::fs::write(path, data)
        .await
        .with_context(|| format!("failed to write: {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        tokio::fs::set_permissions(path, perms)
            .await
            .with_context(|| format!("failed to set permissions on: {}", path.display()))?;
    }

    // Suppress unused variable warning on non-Unix
    #[cfg(not(unix))]
    let _ = mode;

    Ok(())
}

/// Run a swanctl command and return Ok(()) on success.
async fn run_swanctl(args: &[&str]) -> Result<()> {
    tracing::debug!(cmd = "swanctl", ?args, "executing");

    let output = tokio::process::Command::new("swanctl")
        .args(args)
        .output()
        .await
        .context("failed to execute swanctl")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("swanctl failed (exit {}): {stderr}", output.status);
    }

    Ok(())
}

/// Parse `swanctl --list-sas` output for a specific connection.
///
/// The output format is loosely structured text. We do a best-effort parse.
fn parse_swanctl_sas(output: &str, name: &str) -> IpsecStatus {
    let ike_name = format!("sfgw-{name}");
    let mut is_up = false;
    let mut ike_state = "none".to_string();
    let mut child_sas = Vec::new();

    let mut in_our_sa = false;

    for line in output.lines() {
        let trimmed = line.trim();

        // Look for our IKE SA
        if trimmed.starts_with(&ike_name) {
            in_our_sa = true;
            is_up = true;
            // Try to extract state from line like: "sfgw-test: #1, ESTABLISHED"
            if let Some(state_part) = trimmed.rsplit(',').next() {
                ike_state = state_part.trim().to_lowercase();
            }
            continue;
        }

        if in_our_sa {
            // A new IKE SA starts (different connection) — stop
            if !trimmed.is_empty()
                && !trimmed.starts_with(&ike_name)
                && !line.starts_with(' ')
                && !line.starts_with('\t')
            {
                break;
            }

            // Look for child SA info
            // Format: "  name: #1, reqid 1, INSTALLED, TUNNEL, ESP"
            if trimmed.contains("INSTALLED") || trimmed.contains("REKEYING") {
                let child_name = trimmed.split(':').next().unwrap_or("").trim().to_string();
                let state = if trimmed.contains("INSTALLED") {
                    "installed"
                } else {
                    "rekeying"
                };
                child_sas.push(ChildSaStatus {
                    name: child_name,
                    state: state.to_string(),
                    local_ts: String::new(),
                    remote_ts: String::new(),
                });
            }
        }
    }

    IpsecStatus {
        name: name.to_string(),
        is_up,
        ike_state,
        child_sas,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_roadwarrior_config() -> IpsecDbConfig {
        IpsecDbConfig {
            mode: "roadwarrior".to_string(),
            auth_method: "certificate".to_string(),
            local_id: "gateway.secfirstgw.local".to_string(),
            listen_port: None,
            local_addrs: None,
            pool_v4: Some("10.10.0.0/24".to_string()),
            pool_v6: Some("fd10::0/112".to_string()),
            local_ts: Vec::new(),
            remote_ts: Vec::new(),
            dns: Some("10.10.0.1".to_string()),
            zone: "vpn".to_string(),
        }
    }

    fn sample_s2s_config() -> IpsecDbConfig {
        IpsecDbConfig {
            mode: "site-to-site".to_string(),
            auth_method: "psk".to_string(),
            local_id: "site-a.secfirstgw.local".to_string(),
            listen_port: None,
            local_addrs: Some("203.0.113.1".to_string()),
            pool_v4: None,
            pool_v6: None,
            local_ts: vec!["192.168.1.0/24".to_string()],
            remote_ts: vec!["192.168.2.0/24".to_string()],
            dns: None,
            zone: "vpn".to_string(),
        }
    }

    #[test]
    fn generate_roadwarrior_config() {
        let config = sample_roadwarrior_config();
        let result = generate_swanctl_config("rw-test", &config).unwrap();

        assert!(result.contains("sfgw-rw-test {"));
        assert!(result.contains("version = 2"));
        assert!(result.contains(IKE_PROPOSALS));
        assert!(result.contains(ESP_PROPOSALS));
        assert!(result.contains("auth = pubkey"));
        assert!(result.contains("id = gateway.secfirstgw.local"));
        assert!(result.contains("local_ts = 0.0.0.0/0,::/0"));
        assert!(result.contains("remote_ts = dynamic"));
        assert!(result.contains("pool-rw-test-v4"));
        assert!(result.contains("pool-rw-test-v6"));
        assert!(result.contains("addrs = 10.10.0.0/24"));
        assert!(result.contains("addrs = fd10::0/112"));
        assert!(result.contains("dns = 10.10.0.1"));
    }

    #[test]
    fn generate_s2s_config() {
        let config = sample_s2s_config();
        let result = generate_swanctl_config("s2s-test", &config).unwrap();

        assert!(result.contains("sfgw-s2s-test {"));
        assert!(result.contains("auth = psk"));
        assert!(result.contains("id = site-a.secfirstgw.local"));
        assert!(result.contains("local_addrs = 203.0.113.1"));
        assert!(result.contains("local_ts = 192.168.1.0/24"));
        assert!(result.contains("remote_ts = 192.168.2.0/24"));
        // PSK mode should have a secrets section
        assert!(result.contains("secrets {"));
        assert!(result.contains("ike-sfgw-s2s-test"));
        // Should NOT have pools
        assert!(!result.contains("pools {"));
    }

    #[test]
    fn generate_eap_config() {
        let config = IpsecDbConfig {
            mode: "roadwarrior".to_string(),
            auth_method: "eap-mschapv2".to_string(),
            local_id: "gw.example.com".to_string(),
            listen_port: None,
            local_addrs: None,
            pool_v4: Some("10.20.0.0/24".to_string()),
            pool_v6: None,
            local_ts: Vec::new(),
            remote_ts: Vec::new(),
            dns: Some("1.1.1.1".to_string()),
            zone: "vpn".to_string(),
        };
        let result = generate_swanctl_config("eap-test", &config).unwrap();

        // Local uses pubkey, remote uses eap-mschapv2
        assert!(result.contains("auth = pubkey"));
        assert!(result.contains("auth = eap-mschapv2"));
        assert!(result.contains("eap_id = %any"));
    }

    #[test]
    fn cipher_proposals_modern_only() {
        let config = sample_roadwarrior_config();
        let result = generate_swanctl_config("cipher-test", &config).unwrap();

        // Must contain modern ciphers
        assert!(result.contains("aes256gcm16-sha384-x25519"));
        assert!(result.contains("chacha20poly1305-sha384-x25519"));
        assert!(result.contains("aes256gcm16-sha384"));
        assert!(result.contains("chacha20poly1305-sha384"));

        // Must NOT contain weak ciphers
        assert!(!result.contains("3des"));
        assert!(!result.contains("sha1"));
        assert!(!result.contains("modp1024"));
        assert!(!result.contains("modp2048"));
    }

    #[test]
    fn config_file_path_validation() {
        let path = config_file_path("my-tunnel");
        assert_eq!(
            path,
            PathBuf::from("/etc/swanctl/conf.d/sfgw-my-tunnel.conf")
        );
    }

    #[test]
    fn psk_file_path_validation() {
        let path = psk_file_path("my-tunnel");
        assert_eq!(
            path,
            PathBuf::from("/etc/swanctl/private/sfgw-my-tunnel.psk")
        );
    }

    #[test]
    fn reject_injection_in_name() {
        let result = validate_swanctl_name("test; rm -rf /");
        assert!(result.is_err());

        let result = validate_swanctl_name("test\ninjection");
        assert!(result.is_err());

        let result = validate_swanctl_name("");
        assert!(result.is_err());
    }

    #[test]
    fn reject_injection_in_value() {
        let result = validate_swanctl_value("normal.value");
        assert!(result.is_ok());

        let result = validate_swanctl_value("value}\nnew_section {");
        assert!(result.is_err());

        let result = validate_swanctl_value("$(whoami)");
        assert!(result.is_err());

        let result = validate_swanctl_value("test`cmd`");
        assert!(result.is_err());
    }

    #[test]
    fn accept_valid_names() {
        assert!(validate_swanctl_name("my-tunnel").is_ok());
        assert!(validate_swanctl_name("tunnel_1").is_ok());
        assert!(validate_swanctl_name("TestTunnel").is_ok());
    }

    #[test]
    fn ipsec_auth_method_display_parse() {
        assert_eq!(IpsecAuthMethod::Certificate.to_string(), "certificate");
        assert_eq!(IpsecAuthMethod::Psk.to_string(), "psk");
        assert_eq!(IpsecAuthMethod::EapMschapv2.to_string(), "eap-mschapv2");

        assert_eq!(
            IpsecAuthMethod::parse("certificate").unwrap(),
            IpsecAuthMethod::Certificate
        );
        assert_eq!(
            IpsecAuthMethod::parse("cert").unwrap(),
            IpsecAuthMethod::Certificate
        );
        assert_eq!(IpsecAuthMethod::parse("psk").unwrap(), IpsecAuthMethod::Psk);
        assert_eq!(
            IpsecAuthMethod::parse("eap-mschapv2").unwrap(),
            IpsecAuthMethod::EapMschapv2
        );
        assert!(IpsecAuthMethod::parse("invalid").is_err());
    }

    #[test]
    fn ipsec_mode_display_parse() {
        assert_eq!(IpsecMode::RoadWarrior.to_string(), "roadwarrior");
        assert_eq!(IpsecMode::SiteToSite.to_string(), "site-to-site");

        assert_eq!(
            IpsecMode::parse("roadwarrior").unwrap(),
            IpsecMode::RoadWarrior
        );
        assert_eq!(
            IpsecMode::parse("road-warrior").unwrap(),
            IpsecMode::RoadWarrior
        );
        assert_eq!(
            IpsecMode::parse("site-to-site").unwrap(),
            IpsecMode::SiteToSite
        );
        assert_eq!(IpsecMode::parse("s2s").unwrap(), IpsecMode::SiteToSite);
        assert!(IpsecMode::parse("invalid").is_err());
    }

    #[test]
    fn tunnel_type_serde_roundtrip() {
        let wg = TunnelType::WireGuard;
        let ipsec = TunnelType::IPsec;

        let wg_json = serde_json::to_string(&wg).unwrap();
        let ipsec_json = serde_json::to_string(&ipsec).unwrap();

        assert_eq!(wg_json, "\"wireguard\"");
        assert_eq!(ipsec_json, "\"ipsec\"");

        let wg_back: TunnelType = serde_json::from_str(&wg_json).unwrap();
        let ipsec_back: TunnelType = serde_json::from_str(&ipsec_json).unwrap();

        assert_eq!(wg_back, TunnelType::WireGuard);
        assert_eq!(ipsec_back, TunnelType::IPsec);
    }

    #[test]
    fn tunnel_type_display() {
        assert_eq!(TunnelType::WireGuard.to_string(), "wireguard");
        assert_eq!(TunnelType::IPsec.to_string(), "ipsec");
    }

    #[test]
    fn tunnel_type_from_str_lossy() {
        assert_eq!(TunnelType::from_str_lossy("ipsec"), TunnelType::IPsec);
        assert_eq!(TunnelType::from_str_lossy("IPSEC"), TunnelType::IPsec);
        assert_eq!(
            TunnelType::from_str_lossy("wireguard"),
            TunnelType::WireGuard
        );
        assert_eq!(TunnelType::from_str_lossy("unknown"), TunnelType::WireGuard);
    }

    #[test]
    fn validate_cidr_valid() {
        assert!(validate_cidr("10.10.0.0/24").is_ok());
        assert!(validate_cidr("192.168.1.0/24").is_ok());
        assert!(validate_cidr("fd10::0/112").is_ok());
        assert!(validate_cidr("0.0.0.0/0").is_ok());
        assert!(validate_cidr("::/0").is_ok());
    }

    #[test]
    fn validate_cidr_invalid() {
        assert!(validate_cidr("not-a-cidr").is_err());
        assert!(validate_cidr("10.10.0.0").is_err()); // missing prefix
        assert!(validate_cidr("10.10.0.0/33").is_err()); // too large for v4
        assert!(validate_cidr("fd10::0/129").is_err()); // too large for v6
    }

    #[test]
    fn parse_swanctl_sas_empty() {
        let status = parse_swanctl_sas("", "test");
        assert!(!status.is_up);
        assert_eq!(status.ike_state, "none");
        assert!(status.child_sas.is_empty());
    }

    #[test]
    fn parse_swanctl_sas_established() {
        let output = "sfgw-test: #1, ESTABLISHED, IKEv2\n\
                       test: #1, reqid 1, INSTALLED, TUNNEL, ESP";
        let status = parse_swanctl_sas(output, "test");
        assert!(status.is_up);
    }

    #[test]
    fn ipsec_local_addrs_in_swanctl_config() {
        let config = IpsecDbConfig {
            mode: "site-to-site".to_string(),
            auth_method: "psk".to_string(),
            local_id: "gw.example.com".to_string(),
            listen_port: None,
            local_addrs: Some("203.0.113.5".to_string()),
            pool_v4: None,
            pool_v6: None,
            local_ts: vec!["192.168.1.0/24".to_string()],
            remote_ts: vec!["192.168.2.0/24".to_string()],
            dns: None,
            zone: "vpn".to_string(),
        };
        let result = generate_swanctl_config("wan-bind", &config).unwrap();
        assert!(
            result.contains("local_addrs = 203.0.113.5"),
            "local_addrs should appear in swanctl config for WAN binding"
        );
    }

    #[test]
    fn ipsec_default_local_addrs_is_any() {
        let config = sample_roadwarrior_config();
        let result = generate_swanctl_config("default-bind", &config).unwrap();
        assert!(
            result.contains("local_addrs = %any"),
            "default local_addrs should be %any when not specified"
        );
    }

    #[test]
    fn vpn_tunnel_bind_interface_serde() {
        let tunnel = VpnTunnel {
            id: 1,
            name: "wg0".to_string(),
            tunnel_type: TunnelType::WireGuard,
            enabled: true,
            listen_port: 51820,
            public_key: "test-key".to_string(),
            address: "10.0.0.1/24".to_string(),
            address_v6: None,
            dns: None,
            mtu: 1420,
            zone: "vpn".to_string(),
            bind_interface: Some("eth0".to_string()),
            peers: Vec::new(),
        };
        let json = serde_json::to_string(&tunnel).unwrap();
        assert!(json.contains("\"bind_interface\":\"eth0\""));

        let parsed: VpnTunnel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.bind_interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn vpn_tunnel_bind_interface_none_omitted() {
        let tunnel = VpnTunnel {
            id: 1,
            name: "wg0".to_string(),
            tunnel_type: TunnelType::WireGuard,
            enabled: true,
            listen_port: 51820,
            public_key: "test-key".to_string(),
            address: "10.0.0.1/24".to_string(),
            address_v6: None,
            dns: None,
            mtu: 1420,
            zone: "vpn".to_string(),
            bind_interface: None,
            peers: Vec::new(),
        };
        let json = serde_json::to_string(&tunnel).unwrap();
        assert!(
            !json.contains("bind_interface"),
            "None bind_interface should be omitted from JSON"
        );
    }

    #[test]
    fn vpn_tunnel_bind_interface_deserialize_missing() {
        let json = r#"{"id":1,"name":"wg0","tunnel_type":"wireguard","enabled":true,"listen_port":51820,"public_key":"k","address":"10.0.0.1/24","dns":null,"mtu":1420,"zone":"vpn"}"#;
        let parsed: VpnTunnel = serde_json::from_str(json).unwrap();
        assert!(
            parsed.bind_interface.is_none(),
            "missing bind_interface should default to None"
        );
    }
}
