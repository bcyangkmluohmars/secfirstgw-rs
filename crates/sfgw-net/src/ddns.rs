// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dynamic DNS (DDNS) client.
//!
//! Supports the DynDNS2 protocol (used by DynDNS, No-IP, and many others),
//! DuckDNS, and Cloudflare. Detects WAN IP changes and updates the configured
//! DDNS provider(s) automatically.

use crate::{NetError, Result};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// DDNS provider type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DdnsProvider {
    /// Standard DynDNS2 protocol (DynDNS, No-IP, etc.).
    Dyndns2,
    /// DuckDNS.
    Duckdns,
    /// Cloudflare DNS API.
    Cloudflare,
}

impl DdnsProvider {
    /// Parse a provider string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "dyndns2" | "dyndns" => Some(Self::Dyndns2),
            "duckdns" => Some(Self::Duckdns),
            "cloudflare" | "cf" => Some(Self::Cloudflare),
            _ => None,
        }
    }

    /// Canonical name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dyndns2 => "dyndns2",
            Self::Duckdns => "duckdns",
            Self::Cloudflare => "cloudflare",
        }
    }
}

impl std::fmt::Display for DdnsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single DDNS configuration entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdnsConfig {
    /// Row ID (None for new configs).
    pub id: Option<i64>,
    /// Hostname to update (e.g. "myhost.dyndns.org").
    pub hostname: String,
    /// Provider type.
    pub provider: String,
    /// Provider server (e.g. "members.dyndns.org" for DynDNS2).
    /// None uses the provider default.
    pub server: Option<String>,
    /// Username or API token.
    pub username: Option<String>,
    /// Password or API key.
    pub password: Option<String>,
    /// WAN interface to read IP from (e.g. "eth8").
    pub wan_interface: String,
    /// How often to check for IP changes (seconds).
    pub update_interval_secs: i64,
    /// Whether this config is active.
    pub enabled: bool,
    /// Last known IP address sent to the provider.
    pub last_ip: Option<String>,
    /// Last update timestamp (ISO 8601).
    pub last_update: Option<String>,
    /// Last status message from the provider.
    pub last_status: Option<String>,
}

/// DDNS update result from a provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdnsUpdateResult {
    /// Whether the update succeeded.
    pub success: bool,
    /// Status message from the provider.
    pub status: String,
    /// The IP that was sent.
    pub ip: String,
}

// ── Validation ──────────────────────────────────────────────────────

/// Errors specific to DDNS configuration validation.
#[derive(Debug, thiserror::Error)]
pub enum DdnsValidationError {
    #[error("invalid hostname '{0}': must be a valid FQDN")]
    Hostname(String),

    #[error("unknown provider '{0}': supported providers are dyndns2, duckdns, cloudflare")]
    Provider(String),

    #[error("invalid WAN interface '{0}'")]
    WanInterface(String),

    #[error("update interval {0} out of range: must be 60-86400 seconds")]
    UpdateInterval(i64),

    #[error("{0} provider requires {1}")]
    MissingCredential(String, String),
}

/// Validate a hostname: must be non-empty, only valid DNS characters, no wildcards.
fn validate_hostname(hostname: &str) -> std::result::Result<(), DdnsValidationError> {
    if hostname.is_empty() || hostname.len() > 253 {
        return Err(DdnsValidationError::Hostname(hostname.to_string()));
    }
    // Only alphanumeric, hyphens, dots (standard DNS)
    if !hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
    {
        return Err(DdnsValidationError::Hostname(hostname.to_string()));
    }
    // Must contain at least one dot (FQDN)
    if !hostname.contains('.') {
        return Err(DdnsValidationError::Hostname(hostname.to_string()));
    }
    Ok(())
}

/// Validate a DDNS configuration before saving.
pub fn validate_ddns_config(config: &DdnsConfig) -> std::result::Result<(), DdnsValidationError> {
    validate_hostname(&config.hostname)?;

    // Validate provider
    if DdnsProvider::from_str_loose(&config.provider).is_none() {
        return Err(DdnsValidationError::Provider(config.provider.clone()));
    }

    // Validate WAN interface name (reuse from wan module)
    crate::wan::validate_interface_name(&config.wan_interface)
        .map_err(|_| DdnsValidationError::WanInterface(config.wan_interface.clone()))?;

    // Update interval: 60s to 86400s (1 minute to 1 day)
    if config.update_interval_secs < 60 || config.update_interval_secs > 86400 {
        return Err(DdnsValidationError::UpdateInterval(
            config.update_interval_secs,
        ));
    }

    // Provider-specific credential requirements
    let provider =
        DdnsProvider::from_str_loose(&config.provider).expect("provider already validated"); // INVARIANT: validated above
    match provider {
        DdnsProvider::Dyndns2 => {
            if config.username.as_deref().unwrap_or("").is_empty() {
                return Err(DdnsValidationError::MissingCredential(
                    "dyndns2".to_string(),
                    "username".to_string(),
                ));
            }
            if config.password.as_deref().unwrap_or("").is_empty() {
                return Err(DdnsValidationError::MissingCredential(
                    "dyndns2".to_string(),
                    "password".to_string(),
                ));
            }
        }
        DdnsProvider::Duckdns => {
            // DuckDNS uses a token, stored in password field
            if config.password.as_deref().unwrap_or("").is_empty() {
                return Err(DdnsValidationError::MissingCredential(
                    "duckdns".to_string(),
                    "token (in password field)".to_string(),
                ));
            }
        }
        DdnsProvider::Cloudflare => {
            // Cloudflare uses zone ID (username) + API token (password)
            let zone_id = config.username.as_deref().unwrap_or("");
            if zone_id.is_empty() {
                return Err(DdnsValidationError::MissingCredential(
                    "cloudflare".to_string(),
                    "zone_id (in username field)".to_string(),
                ));
            }
            // Zone ID is a hex string — reject anything that could manipulate the API URL path
            if !zone_id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(DdnsValidationError::MissingCredential(
                    "cloudflare".to_string(),
                    "zone_id must be a hex string".to_string(),
                ));
            }
            if config.password.as_deref().unwrap_or("").is_empty() {
                return Err(DdnsValidationError::MissingCredential(
                    "cloudflare".to_string(),
                    "API token (in password field)".to_string(),
                ));
            }
        }
    }

    Ok(())
}

// ── Database operations ─────────────────────────────────────────────

/// List all DDNS configurations.
#[must_use = "DDNS config list result should be checked"]
pub async fn list_ddns_configs(db: &sfgw_db::Db) -> Result<Vec<DdnsConfig>> {
    let conn = db.lock().await;
    let mut stmt = conn
        .prepare(
            "SELECT id, hostname, provider, server, username, password,
                    wan_interface, update_interval_secs, enabled,
                    last_ip, last_update, last_status
             FROM ddns_configs ORDER BY id ASC",
        )
        .context("failed to prepare ddns_configs query")?;

    let rows = stmt
        .query_map([], |row| {
            Ok(DdnsConfig {
                id: Some(row.get(0)?),
                hostname: row.get(1)?,
                provider: row.get(2)?,
                server: row.get(3)?,
                username: row.get(4)?,
                password: row.get(5)?,
                wan_interface: row.get(6)?,
                update_interval_secs: row.get(7)?,
                enabled: row.get::<_, i64>(8)? != 0,
                last_ip: row.get(9)?,
                last_update: row.get(10)?,
                last_status: row.get(11)?,
            })
        })
        .context("failed to query ddns_configs")?;

    let mut configs = Vec::new();
    for row in rows {
        configs.push(row?);
    }
    Ok(configs)
}

/// Get a single DDNS config by ID.
#[must_use = "DDNS config result should be checked"]
pub async fn get_ddns_config(db: &sfgw_db::Db, id: i64) -> Result<Option<DdnsConfig>> {
    let conn = db.lock().await;
    let result = conn.query_row(
        "SELECT id, hostname, provider, server, username, password,
                wan_interface, update_interval_secs, enabled,
                last_ip, last_update, last_status
         FROM ddns_configs WHERE id = ?1",
        rusqlite::params![id],
        |row| {
            Ok(DdnsConfig {
                id: Some(row.get(0)?),
                hostname: row.get(1)?,
                provider: row.get(2)?,
                server: row.get(3)?,
                username: row.get(4)?,
                password: row.get(5)?,
                wan_interface: row.get(6)?,
                update_interval_secs: row.get(7)?,
                enabled: row.get::<_, i64>(8)? != 0,
                last_ip: row.get(9)?,
                last_update: row.get(10)?,
                last_status: row.get(11)?,
            })
        },
    );

    match result {
        Ok(config) => Ok(Some(config)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(NetError::Database(e)),
    }
}

/// Create a new DDNS configuration. Returns the new row ID.
pub async fn create_ddns_config(db: &sfgw_db::Db, config: &DdnsConfig) -> Result<i64> {
    validate_ddns_config(config).map_err(|e| NetError::Internal(e.into()))?;

    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO ddns_configs (hostname, provider, server, username, password,
                                   wan_interface, update_interval_secs, enabled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            config.hostname,
            config.provider,
            config.server,
            config.username,
            config.password,
            config.wan_interface,
            config.update_interval_secs,
            config.enabled as i64,
        ],
    )
    .context("failed to insert ddns_config")?;

    let id = conn.last_insert_rowid();
    tracing::info!(
        id,
        hostname = %config.hostname,
        provider = %config.provider,
        "DDNS config created"
    );
    Ok(id)
}

/// Update an existing DDNS configuration.
pub async fn update_ddns_config(db: &sfgw_db::Db, id: i64, config: &DdnsConfig) -> Result<bool> {
    validate_ddns_config(config).map_err(|e| NetError::Internal(e.into()))?;

    let conn = db.lock().await;
    let affected = conn
        .execute(
            "UPDATE ddns_configs SET
                hostname = ?1, provider = ?2, server = ?3,
                username = ?4, password = ?5, wan_interface = ?6,
                update_interval_secs = ?7, enabled = ?8
             WHERE id = ?9",
            rusqlite::params![
                config.hostname,
                config.provider,
                config.server,
                config.username,
                config.password,
                config.wan_interface,
                config.update_interval_secs,
                config.enabled as i64,
                id,
            ],
        )
        .context("failed to update ddns_config")?;

    if affected > 0 {
        tracing::info!(
            id,
            hostname = %config.hostname,
            "DDNS config updated"
        );
    }
    Ok(affected > 0)
}

/// Delete a DDNS configuration.
pub async fn delete_ddns_config(db: &sfgw_db::Db, id: i64) -> Result<bool> {
    let conn = db.lock().await;
    let affected = conn
        .execute(
            "DELETE FROM ddns_configs WHERE id = ?1",
            rusqlite::params![id],
        )
        .context("failed to delete ddns_config")?;

    if affected > 0 {
        tracing::info!(id, "DDNS config deleted");
    }
    Ok(affected > 0)
}

/// Record a DDNS update result in the database.
async fn record_update_result(db: &sfgw_db::Db, id: i64, ip: &str, status: &str) -> Result<()> {
    let conn = db.lock().await;
    conn.execute(
        "UPDATE ddns_configs SET last_ip = ?1, last_update = datetime('now'), last_status = ?2
         WHERE id = ?3",
        rusqlite::params![ip, status, id],
    )
    .context("failed to record DDNS update result")?;
    Ok(())
}

// ── IP detection ────────────────────────────────────────────────────

/// Read the current IPv4 address of a WAN interface.
///
/// Uses `ip -4 -o addr show dev <interface>` to read the IP.
pub fn detect_wan_ipv4(interface: &str) -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", interface])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(inet_pos) = line.find("inet ") {
            let rest = &line[inet_pos + 5..];
            let addr_cidr = rest.split_whitespace().next()?;
            let addr = addr_cidr.split('/').next()?;
            // Validate it parses as an IP
            if addr.parse::<IpAddr>().is_ok() {
                return Some(addr.to_string());
            }
        }
    }
    None
}

/// Detect WAN IPv6 (global scope) from an interface.
pub fn detect_wan_ipv6(interface: &str) -> Option<String> {
    let output = std::process::Command::new("ip")
        .args([
            "-6", "-o", "addr", "show", "dev", interface, "scope", "global",
        ])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(inet6_pos) = line.find("inet6 ") {
            let rest = &line[inet6_pos + 6..];
            let addr_cidr = rest.split_whitespace().next()?;
            let addr = addr_cidr.split('/').next()?;
            if addr.parse::<IpAddr>().is_ok() {
                return Some(addr.to_string());
            }
        }
    }
    None
}

// ── Provider update implementations ─────────────────────────────────

/// Build a reqwest HTTP client with TLS and a reasonable timeout.
fn build_http_client() -> std::result::Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("sfgw-ddns/1.0")
        .build()
}

/// Validate that a DDNS server address is not a private/loopback IP (SSRF prevention).
///
/// Rejects: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
/// 169.254.0.0/16, ::1, fc00::/7, fe80::/10, and "localhost".
fn validate_server_not_private(server: &str) -> std::result::Result<(), String> {
    // Extract host, handling IPv6 bracket notation (e.g., "[::1]:8080").
    let host = if server.starts_with('[') {
        // IPv6 bracket notation: [::1]:port → ::1
        server
            .strip_prefix('[')
            .and_then(|s| s.split(']').next())
            .unwrap_or(server)
    } else if server.parse::<IpAddr>().is_ok() {
        // Raw IP (IPv4 or IPv6 without port) — use as-is.
        server
    } else {
        // Hostname with optional port: "example.com:8080" → "example.com".
        server.split(':').next().unwrap_or(server)
    };

    // Reject localhost by name.
    if host.eq_ignore_ascii_case("localhost") {
        return Err("DDNS server must not be localhost".to_string());
    }

    // Try to parse as IP address directly.
    if let Ok(ip) = host.parse::<IpAddr>()
        && is_private_ip(&ip)
    {
        return Err(format!(
            "DDNS server must not be a private/loopback address: {ip}"
        ));
    }

    Ok(())
}

/// Check if an IP address is private, loopback, or link-local.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()          // 127.0.0.0/8
                || v4.is_private()    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local() // 169.254.0.0/16
                || v4.is_unspecified() // 0.0.0.0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()          // ::1
                || v6.is_unspecified() // ::
                // fc00::/7 (unique local) — check first byte
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 (link-local) — check first 10 bits
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Perform a DynDNS2 protocol update.
///
/// Protocol: `GET /nic/update?hostname=<host>&myip=<ip>` with HTTP Basic auth.
/// Server defaults to `members.dyndns.org` if not specified.
///
/// Response codes:
/// - `good <ip>` — update successful
/// - `nochg <ip>` — IP unchanged (no update needed)
/// - `badauth` — authentication failure
/// - `abuse` — account blocked
/// - `911` — server error
async fn update_dyndns2(config: &DdnsConfig, ip: &str) -> DdnsUpdateResult {
    let server = config.server.as_deref().unwrap_or("members.dyndns.org");
    let username = config.username.as_deref().unwrap_or("");
    let password = config.password.as_deref().unwrap_or("");

    // SSRF prevention: reject private/loopback server addresses.
    if let Err(e) = validate_server_not_private(server) {
        return DdnsUpdateResult {
            success: false,
            status: e,
            ip: ip.to_string(),
        };
    }

    // Build URL with proper encoding of user-controlled parameters.
    let base = format!("https://{server}/nic/update");
    let url = match url::Url::parse_with_params(
        &base,
        &[("hostname", config.hostname.as_str()), ("myip", ip)],
    ) {
        Ok(u) => u,
        Err(e) => {
            return DdnsUpdateResult {
                success: false,
                status: format!("invalid DDNS URL: {e}"),
                ip: ip.to_string(),
            };
        }
    };

    let client = match build_http_client() {
        Ok(c) => c,
        Err(e) => {
            return DdnsUpdateResult {
                success: false,
                status: format!("failed to build HTTP client: {e}"),
                ip: ip.to_string(),
            };
        }
    };

    let resp = client
        .get(url)
        .basic_auth(username, Some(password))
        .send()
        .await;

    match resp {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            let trimmed = body.trim();
            let success = trimmed.starts_with("good") || trimmed.starts_with("nochg");
            DdnsUpdateResult {
                success,
                status: trimmed.to_string(),
                ip: ip.to_string(),
            }
        }
        Err(e) => DdnsUpdateResult {
            success: false,
            status: format!("HTTP request failed: {e}"),
            ip: ip.to_string(),
        },
    }
}

/// Perform a DuckDNS update.
///
/// Protocol: `GET https://www.duckdns.org/update?domains=<subdomain>&token=<token>&ip=<ip>`
/// The hostname should be just the subdomain part (before `.duckdns.org`).
async fn update_duckdns(config: &DdnsConfig, ip: &str) -> DdnsUpdateResult {
    let token = config.password.as_deref().unwrap_or("");
    // Strip .duckdns.org suffix if present (users might include it)
    let subdomain = config
        .hostname
        .strip_suffix(".duckdns.org")
        .unwrap_or(&config.hostname);

    // Build URL with proper encoding of user-controlled parameters.
    let url = match url::Url::parse_with_params(
        "https://www.duckdns.org/update",
        &[("domains", subdomain), ("token", token), ("ip", ip)],
    ) {
        Ok(u) => u,
        Err(e) => {
            return DdnsUpdateResult {
                success: false,
                status: format!("invalid DuckDNS URL: {e}"),
                ip: ip.to_string(),
            };
        }
    };

    let client = match build_http_client() {
        Ok(c) => c,
        Err(e) => {
            return DdnsUpdateResult {
                success: false,
                status: format!("failed to build HTTP client: {e}"),
                ip: ip.to_string(),
            };
        }
    };

    let resp = client.get(url).send().await;

    match resp {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            let trimmed = body.trim();
            let success = trimmed == "OK";
            DdnsUpdateResult {
                success,
                status: trimmed.to_string(),
                ip: ip.to_string(),
            }
        }
        Err(e) => DdnsUpdateResult {
            success: false,
            status: format!("HTTP request failed: {e}"),
            ip: ip.to_string(),
        },
    }
}

/// Perform a Cloudflare DNS update.
///
/// Uses the Cloudflare API v4:
/// 1. List DNS records for the zone to find the record ID.
/// 2. PATCH the record with the new IP.
///
/// `username` field = zone ID, `password` field = API token.
async fn update_cloudflare(config: &DdnsConfig, ip: &str) -> DdnsUpdateResult {
    let zone_id = config.username.as_deref().unwrap_or("");
    let api_token = config.password.as_deref().unwrap_or("");

    let client = match build_http_client() {
        Ok(c) => c,
        Err(e) => {
            return DdnsUpdateResult {
                success: false,
                status: format!("failed to build HTTP client: {e}"),
                ip: ip.to_string(),
            };
        }
    };

    // Step 1: Find the DNS record ID
    // Cloudflare API uses path segments for zone_id (not query params), so we
    // URL-encode it to prevent path traversal. The hostname is a query param
    // and gets properly encoded by Url::parse_with_params.
    let list_base = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
        url::form_urlencoded::byte_serialize(zone_id.as_bytes()).collect::<String>(),
    );
    let list_url =
        match url::Url::parse_with_params(&list_base, &[("type", "A"), ("name", &config.hostname)])
        {
            Ok(u) => u,
            Err(e) => {
                return DdnsUpdateResult {
                    success: false,
                    status: format!("invalid Cloudflare URL: {e}"),
                    ip: ip.to_string(),
                };
            }
        };

    let list_resp = client
        .get(list_url)
        .header("Authorization", format!("Bearer {api_token}"))
        .header("Content-Type", "application/json")
        .send()
        .await;

    let list_body = match list_resp {
        Ok(r) => match r.json::<serde_json::Value>().await {
            Ok(v) => v,
            Err(e) => {
                return DdnsUpdateResult {
                    success: false,
                    status: format!("failed to parse Cloudflare response: {e}"),
                    ip: ip.to_string(),
                };
            }
        },
        Err(e) => {
            return DdnsUpdateResult {
                success: false,
                status: format!("Cloudflare list request failed: {e}"),
                ip: ip.to_string(),
            };
        }
    };

    let record_id = list_body["result"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|r| r["id"].as_str());

    let record_id = match record_id {
        Some(id) => id.to_string(),
        None => {
            return DdnsUpdateResult {
                success: false,
                status: format!(
                    "no A record found for {} in zone {zone_id}",
                    config.hostname
                ),
                ip: ip.to_string(),
            };
        }
    };

    // Step 2: Update the record (URL-encode path segments to prevent traversal).
    let update_url = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
        url::form_urlencoded::byte_serialize(zone_id.as_bytes()).collect::<String>(),
        url::form_urlencoded::byte_serialize(record_id.as_bytes()).collect::<String>(),
    );

    let update_body = serde_json::json!({
        "type": "A",
        "name": config.hostname,
        "content": ip,
        "ttl": 1,
        "proxied": false,
    });

    let update_resp = client
        .put(&update_url)
        .header("Authorization", format!("Bearer {api_token}"))
        .header("Content-Type", "application/json")
        .json(&update_body)
        .send()
        .await;

    match update_resp {
        Ok(r) => {
            let body = r.json::<serde_json::Value>().await.unwrap_or_default();
            let success = body["success"].as_bool().unwrap_or(false);
            let status = if success {
                format!("good {ip}")
            } else {
                let errors = body["errors"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|e| e["message"].as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_else(|| "unknown error".to_string());
                format!("error: {errors}")
            };
            DdnsUpdateResult {
                success,
                status,
                ip: ip.to_string(),
            }
        }
        Err(e) => DdnsUpdateResult {
            success: false,
            status: format!("Cloudflare update request failed: {e}"),
            ip: ip.to_string(),
        },
    }
}

/// Perform a DDNS update for the given config and IP.
pub async fn perform_update(config: &DdnsConfig, ip: &str) -> DdnsUpdateResult {
    let provider = DdnsProvider::from_str_loose(&config.provider);
    match provider {
        Some(DdnsProvider::Dyndns2) => update_dyndns2(config, ip).await,
        Some(DdnsProvider::Duckdns) => update_duckdns(config, ip).await,
        Some(DdnsProvider::Cloudflare) => update_cloudflare(config, ip).await,
        None => DdnsUpdateResult {
            success: false,
            status: format!("unknown provider: {}", config.provider),
            ip: ip.to_string(),
        },
    }
}

/// Force an immediate DDNS update for a specific config ID.
/// Returns the update result.
pub async fn force_update(db: &sfgw_db::Db, id: i64) -> Result<DdnsUpdateResult> {
    let config = get_ddns_config(db, id)
        .await?
        .ok_or_else(|| NetError::Internal(anyhow::anyhow!("DDNS config {id} not found")))?;

    let ip = detect_wan_ipv4(&config.wan_interface).ok_or_else(|| {
        NetError::Internal(anyhow::anyhow!(
            "could not detect IPv4 on interface {}",
            config.wan_interface
        ))
    })?;

    let result = perform_update(&config, &ip).await;

    let status_str = if result.success {
        format!("ok: {}", result.status)
    } else {
        format!("error: {}", result.status)
    };
    record_update_result(db, id, &ip, &status_str).await?;

    tracing::info!(
        id,
        hostname = %config.hostname,
        ip = %ip,
        success = result.success,
        status = %result.status,
        "DDNS force update"
    );

    Ok(result)
}

// ── Background task ─────────────────────────────────────────────────

/// Handle for controlling the DDNS background tasks.
pub type DdnsHandle = Arc<Mutex<HashMap<i64, tokio::task::JoinHandle<()>>>>;

/// Create a new DDNS task handle.
pub fn new_handle() -> DdnsHandle {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Spawn background update loops for all enabled DDNS configs.
///
/// Each config gets its own tokio task that checks the WAN IP at the
/// configured interval and updates the provider if the IP has changed.
pub async fn start_background_tasks(db: &sfgw_db::Db, handle: &DdnsHandle) -> Result<()> {
    let configs = list_ddns_configs(db).await?;
    let mut tasks = handle.lock().await;

    for config in configs {
        if !config.enabled {
            continue;
        }
        let Some(id) = config.id else {
            continue;
        };

        let db_clone = db.clone();
        let task = tokio::spawn(async move {
            ddns_update_loop(db_clone, id).await;
        });

        tasks.insert(id, task);
        tracing::info!(
            id,
            hostname = %config.hostname,
            interval_secs = config.update_interval_secs,
            "DDNS background task started"
        );
    }

    Ok(())
}

/// Stop all background DDNS tasks.
pub async fn stop_background_tasks(handle: &DdnsHandle) {
    let mut tasks = handle.lock().await;
    for (id, task) in tasks.drain() {
        task.abort();
        tracing::info!(id, "DDNS background task stopped");
    }
}

/// Reload background tasks (stop all, restart from DB).
pub async fn reload_background_tasks(db: &sfgw_db::Db, handle: &DdnsHandle) -> Result<()> {
    stop_background_tasks(handle).await;
    start_background_tasks(db, handle).await
}

/// The per-config update loop.
async fn ddns_update_loop(db: sfgw_db::Db, config_id: i64) {
    // Initial delay to let networking settle
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    loop {
        // Re-read config each iteration (user may have changed interval/credentials)
        let config = match get_ddns_config(&db, config_id).await {
            Ok(Some(c)) => c,
            Ok(None) => {
                tracing::info!(config_id, "DDNS config deleted, stopping loop");
                return;
            }
            Err(e) => {
                tracing::warn!(config_id, error = %e, "failed to read DDNS config");
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                continue;
            }
        };

        if !config.enabled {
            tracing::debug!(config_id, "DDNS config disabled, stopping loop");
            return;
        }

        let interval = std::time::Duration::from_secs(config.update_interval_secs as u64);

        // Detect current WAN IP
        let current_ip = detect_wan_ipv4(&config.wan_interface);

        if let Some(ip) = current_ip {
            // Only update if IP changed
            let ip_changed = config.last_ip.as_deref() != Some(&ip);

            if ip_changed {
                tracing::info!(
                    config_id,
                    hostname = %config.hostname,
                    old_ip = ?config.last_ip,
                    new_ip = %ip,
                    "WAN IP changed, updating DDNS"
                );

                let result = perform_update(&config, &ip).await;
                let status_str = if result.success {
                    format!("ok: {}", result.status)
                } else {
                    format!("error: {}", result.status)
                };

                if let Err(e) = record_update_result(&db, config_id, &ip, &status_str).await {
                    tracing::warn!(config_id, error = %e, "failed to record DDNS update result");
                }

                if result.success {
                    tracing::info!(
                        config_id,
                        hostname = %config.hostname,
                        ip = %ip,
                        "DDNS update successful"
                    );
                } else {
                    tracing::warn!(
                        config_id,
                        hostname = %config.hostname,
                        status = %result.status,
                        "DDNS update failed"
                    );
                }
            } else {
                tracing::debug!(
                    config_id,
                    hostname = %config.hostname,
                    ip = %ip,
                    "WAN IP unchanged, skipping DDNS update"
                );
            }
        } else {
            tracing::warn!(
                config_id,
                interface = %config.wan_interface,
                "could not detect WAN IPv4, skipping DDNS check"
            );
        }

        tokio::time::sleep(interval).await;
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_parse() {
        assert_eq!(
            DdnsProvider::from_str_loose("dyndns2"),
            Some(DdnsProvider::Dyndns2)
        );
        assert_eq!(
            DdnsProvider::from_str_loose("DynDNS"),
            Some(DdnsProvider::Dyndns2)
        );
        assert_eq!(
            DdnsProvider::from_str_loose("duckdns"),
            Some(DdnsProvider::Duckdns)
        );
        assert_eq!(
            DdnsProvider::from_str_loose("cloudflare"),
            Some(DdnsProvider::Cloudflare)
        );
        assert_eq!(
            DdnsProvider::from_str_loose("cf"),
            Some(DdnsProvider::Cloudflare)
        );
        assert_eq!(DdnsProvider::from_str_loose("unknown"), None);
    }

    #[test]
    fn test_validate_hostname() {
        assert!(validate_hostname("myhost.example.com").is_ok());
        assert!(validate_hostname("sub.domain.dyndns.org").is_ok());
        assert!(validate_hostname("my-host.duckdns.org").is_ok());
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("nodotshere").is_err());
        assert!(validate_hostname("has spaces.com").is_err());
        assert!(validate_hostname("has;injection.com").is_err());
    }

    #[test]
    fn test_validate_ddns_config_dyndns2() {
        let config = DdnsConfig {
            id: None,
            hostname: "myhost.dyndns.org".to_string(),
            provider: "dyndns2".to_string(),
            server: None,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            wan_interface: "eth8".to_string(),
            update_interval_secs: 300,
            enabled: true,
            last_ip: None,
            last_update: None,
            last_status: None,
        };
        assert!(validate_ddns_config(&config).is_ok());
    }

    #[test]
    fn test_validate_ddns_config_missing_username() {
        let config = DdnsConfig {
            id: None,
            hostname: "myhost.dyndns.org".to_string(),
            provider: "dyndns2".to_string(),
            server: None,
            username: None,
            password: Some("pass".to_string()),
            wan_interface: "eth8".to_string(),
            update_interval_secs: 300,
            enabled: true,
            last_ip: None,
            last_update: None,
            last_status: None,
        };
        assert!(validate_ddns_config(&config).is_err());
    }

    #[test]
    fn test_validate_ddns_config_bad_interval() {
        let config = DdnsConfig {
            id: None,
            hostname: "myhost.dyndns.org".to_string(),
            provider: "dyndns2".to_string(),
            server: None,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            wan_interface: "eth8".to_string(),
            update_interval_secs: 5, // too low
            enabled: true,
            last_ip: None,
            last_update: None,
            last_status: None,
        };
        assert!(validate_ddns_config(&config).is_err());
    }

    #[test]
    fn test_validate_ddns_config_duckdns() {
        let config = DdnsConfig {
            id: None,
            hostname: "myhost.duckdns.org".to_string(),
            provider: "duckdns".to_string(),
            server: None,
            username: None,
            password: Some("my-token-here".to_string()),
            wan_interface: "eth8".to_string(),
            update_interval_secs: 300,
            enabled: true,
            last_ip: None,
            last_update: None,
            last_status: None,
        };
        assert!(validate_ddns_config(&config).is_ok());
    }

    #[test]
    fn test_validate_ddns_config_cloudflare() {
        let config = DdnsConfig {
            id: None,
            hostname: "myhost.example.com".to_string(),
            provider: "cloudflare".to_string(),
            server: None,
            username: Some("abc123def456abc789def012abc345de".to_string()),
            password: Some("api-token-here".to_string()),
            wan_interface: "eth8".to_string(),
            update_interval_secs: 300,
            enabled: true,
            last_ip: None,
            last_update: None,
            last_status: None,
        };
        assert!(validate_ddns_config(&config).is_ok());
    }

    #[test]
    fn test_validate_ddns_config_bad_provider() {
        let config = DdnsConfig {
            id: None,
            hostname: "myhost.example.com".to_string(),
            provider: "godaddy".to_string(),
            server: None,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            wan_interface: "eth8".to_string(),
            update_interval_secs: 300,
            enabled: true,
            last_ip: None,
            last_update: None,
            last_status: None,
        };
        assert!(validate_ddns_config(&config).is_err());
    }

    #[tokio::test]
    async fn test_ddns_crud() {
        let db = sfgw_db::open_in_memory()
            .await
            .expect("open_in_memory should succeed");

        // List should be empty initially
        let configs = list_ddns_configs(&db).await.expect("list should succeed");
        assert!(configs.is_empty());

        // Create
        let config = DdnsConfig {
            id: None,
            hostname: "test.dyndns.org".to_string(),
            provider: "dyndns2".to_string(),
            server: None,
            username: Some("testuser".to_string()),
            password: Some("testpass".to_string()),
            wan_interface: "eth8".to_string(),
            update_interval_secs: 300,
            enabled: true,
            last_ip: None,
            last_update: None,
            last_status: None,
        };
        let id = create_ddns_config(&db, &config)
            .await
            .expect("create should succeed");
        assert!(id > 0);

        // Read
        let fetched = get_ddns_config(&db, id)
            .await
            .expect("get should succeed")
            .expect("config should exist");
        assert_eq!(fetched.hostname, "test.dyndns.org");
        assert_eq!(fetched.provider, "dyndns2");
        assert!(fetched.enabled);

        // Update
        let mut updated = fetched.clone();
        updated.hostname = "updated.dyndns.org".to_string();
        updated.update_interval_secs = 600;
        let did_update = update_ddns_config(&db, id, &updated)
            .await
            .expect("update should succeed");
        assert!(did_update);

        let fetched2 = get_ddns_config(&db, id)
            .await
            .expect("get should succeed")
            .expect("config should exist");
        assert_eq!(fetched2.hostname, "updated.dyndns.org");
        assert_eq!(fetched2.update_interval_secs, 600);

        // List should have 1
        let configs = list_ddns_configs(&db).await.expect("list should succeed");
        assert_eq!(configs.len(), 1);

        // Delete
        let did_delete = delete_ddns_config(&db, id)
            .await
            .expect("delete should succeed");
        assert!(did_delete);

        // Should be gone
        let gone = get_ddns_config(&db, id).await.expect("get should succeed");
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn test_record_update_result() {
        let db = sfgw_db::open_in_memory()
            .await
            .expect("open_in_memory should succeed");

        let config = DdnsConfig {
            id: None,
            hostname: "test.dyndns.org".to_string(),
            provider: "dyndns2".to_string(),
            server: None,
            username: Some("testuser".to_string()),
            password: Some("testpass".to_string()),
            wan_interface: "eth8".to_string(),
            update_interval_secs: 300,
            enabled: true,
            last_ip: None,
            last_update: None,
            last_status: None,
        };
        let id = create_ddns_config(&db, &config)
            .await
            .expect("create should succeed");

        record_update_result(&db, id, "1.2.3.4", "ok: good 1.2.3.4")
            .await
            .expect("record should succeed");

        let fetched = get_ddns_config(&db, id)
            .await
            .expect("get should succeed")
            .expect("config should exist");
        assert_eq!(fetched.last_ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(fetched.last_status.as_deref(), Some("ok: good 1.2.3.4"));
        assert!(fetched.last_update.is_some());
    }

    #[test]
    fn test_ddns_config_serde() {
        let config = DdnsConfig {
            id: Some(1),
            hostname: "test.example.com".to_string(),
            provider: "dyndns2".to_string(),
            server: Some("members.dyndns.org".to_string()),
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            wan_interface: "eth8".to_string(),
            update_interval_secs: 300,
            enabled: true,
            last_ip: Some("1.2.3.4".to_string()),
            last_update: Some("2024-01-01T00:00:00Z".to_string()),
            last_status: Some("good 1.2.3.4".to_string()),
        };

        let json = serde_json::to_string(&config).expect("serialize should succeed");
        let back: DdnsConfig = serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(back.hostname, "test.example.com");
        assert_eq!(back.provider, "dyndns2");
        assert_eq!(back.last_ip.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn test_ssrf_rejects_private_ips() {
        assert!(validate_server_not_private("localhost").is_err());
        assert!(validate_server_not_private("127.0.0.1").is_err());
        assert!(validate_server_not_private("10.0.0.1").is_err());
        assert!(validate_server_not_private("192.168.1.1").is_err());
        assert!(validate_server_not_private("172.16.0.1").is_err());
        assert!(validate_server_not_private("169.254.1.1").is_err());
        assert!(validate_server_not_private("::1").is_err());
        assert!(validate_server_not_private("0.0.0.0").is_err());
        // With port
        assert!(validate_server_not_private("localhost:8080").is_err());
        assert!(validate_server_not_private("192.168.1.1:443").is_err());
    }

    #[test]
    fn test_ssrf_allows_public_servers() {
        assert!(validate_server_not_private("members.dyndns.org").is_ok());
        assert!(validate_server_not_private("api.cloudflare.com").is_ok());
        assert!(validate_server_not_private("1.1.1.1").is_ok());
        assert!(validate_server_not_private("8.8.8.8").is_ok());
        assert!(validate_server_not_private("example.com:443").is_ok());
    }
}
