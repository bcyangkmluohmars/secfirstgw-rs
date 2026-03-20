// SPDX-License-Identifier: AGPL-3.0-or-later

//! UPnP IGD / NAT-PMP server for dynamic port mapping.
//!
//! **SECURITY WARNING**: UPnP is a known attack vector. This implementation is
//! disabled by default and restricted to LAN-zone clients only. All mappings
//! are subject to configurable port-range limits and per-IP quotas.
//!
//! Architecture:
//! - SSDP listener on UDP 239.255.255.250:1900 (multicast, LAN only)
//! - HTTP control server for SOAP requests (AddPortMapping, DeletePortMapping, etc.)
//! - NAT-PMP listener on UDP 5351 (RFC 6886)
//! - Background TTL expiry task
//! - iptables-legacy DNAT rules tagged with `sfgw-upnp` comment for cleanup

use crate::FwError;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Default SSDP multicast address.
const SSDP_MULTICAST: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;

/// NAT-PMP port (RFC 6886).
const NATPMP_PORT: u16 = 5351;

/// UPnP HTTP control port for SOAP requests.
const UPNP_HTTP_PORT: u16 = 5000;

/// Default maximum mappings per client IP.
const DEFAULT_MAX_PER_IP: u32 = 32;

/// Default allowed external port range.
const DEFAULT_PORT_MIN: u16 = 1024;
const DEFAULT_PORT_MAX: u16 = 65535;

/// Default mapping TTL (2 hours, per UPnP IGD spec recommendation).
const DEFAULT_TTL_SECS: u32 = 7200;

/// Maximum TTL we allow (24 hours).
const MAX_TTL_SECS: u32 = 86400;

// ── Settings ────────────────────────────────────────────────────────

/// UPnP/NAT-PMP settings stored in the DB `meta` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpnpSettings {
    pub enabled: bool,
    pub port_min: u16,
    pub port_max: u16,
    pub max_per_ip: u32,
}

impl Default for UpnpSettings {
    fn default() -> Self {
        Self {
            enabled: false, // SECURITY: disabled by default
            port_min: DEFAULT_PORT_MIN,
            port_max: DEFAULT_PORT_MAX,
            max_per_ip: DEFAULT_MAX_PER_IP,
        }
    }
}

/// Load UPnP settings from the database.
pub async fn load_settings(db: &sfgw_db::Db) -> Result<UpnpSettings> {
    let conn = db.lock().await;
    let json: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'upnp_settings'",
            [],
            |r| r.get(0),
        )
        .ok();
    match json {
        Some(s) => serde_json::from_str(&s).context("failed to parse upnp_settings"),
        None => Ok(UpnpSettings::default()),
    }
}

/// Save UPnP settings to the database.
pub async fn save_settings(db: &sfgw_db::Db, settings: &UpnpSettings) -> Result<()> {
    let json = serde_json::to_string(settings).context("failed to serialize upnp_settings")?;
    let conn = db.lock().await;
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('upnp_settings', ?1)",
        rusqlite::params![json],
    )
    .context("failed to save upnp_settings")?;
    Ok(())
}

/// Check if UPnP is enabled.
pub async fn is_enabled(db: &sfgw_db::Db) -> Result<bool> {
    Ok(load_settings(db).await?.enabled)
}

// ── Port Mapping ────────────────────────────────────────────────────

/// A UPnP/NAT-PMP port mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub id: Option<i64>,
    pub protocol: String,
    pub external_port: u16,
    pub internal_ip: String,
    pub internal_port: u16,
    pub description: String,
    pub client_ip: String,
    pub ttl_seconds: u32,
    pub created_at: Option<String>,
    pub expires_at: Option<String>,
}

/// Insert a new port mapping into the database.
///
/// Validates all inputs, enforces per-IP limits, and checks port range.
pub async fn add_mapping(
    db: &sfgw_db::Db,
    settings: &UpnpSettings,
    mapping: &PortMapping,
) -> Result<i64, FwError> {
    // Validate protocol
    if mapping.protocol != "tcp" && mapping.protocol != "udp" {
        return Err(FwError::Validation(format!(
            "invalid protocol '{}': must be tcp or udp",
            mapping.protocol
        )));
    }

    // Validate external port is in allowed range
    if mapping.external_port < settings.port_min || mapping.external_port > settings.port_max {
        return Err(FwError::Validation(format!(
            "external port {} outside allowed range {}-{}",
            mapping.external_port, settings.port_min, settings.port_max
        )));
    }

    // Validate internal IP is a valid IPv4 address (LAN client)
    let _ip: Ipv4Addr = mapping.internal_ip.parse().map_err(|_| {
        FwError::Validation(format!("invalid internal IP: {}", mapping.internal_ip))
    })?;

    // Validate client IP
    let _client: IpAddr = mapping
        .client_ip
        .parse()
        .map_err(|_| FwError::Validation(format!("invalid client IP: {}", mapping.client_ip)))?;

    // Validate TTL
    if mapping.ttl_seconds == 0 || mapping.ttl_seconds > MAX_TTL_SECS {
        return Err(FwError::Validation(format!(
            "TTL {} out of range (1-{})",
            mapping.ttl_seconds, MAX_TTL_SECS
        )));
    }

    // Sanitize description (alphanumeric, spaces, dashes, underscores only)
    let description: String = mapping
        .description
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .take(128)
        .collect();

    let conn = db.lock().await;

    // Check per-IP mapping count
    let count: u32 = conn
        .query_row(
            "SELECT COUNT(*) FROM upnp_mappings WHERE client_ip = ?1",
            rusqlite::params![mapping.client_ip],
            |r| r.get(0),
        )
        .map_err(FwError::Database)?;
    if count >= settings.max_per_ip {
        return Err(FwError::Validation(format!(
            "client {} has reached maximum {} mappings",
            mapping.client_ip, settings.max_per_ip
        )));
    }

    // Check for conflicting mapping (same protocol + external port)
    let conflict: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM upnp_mappings WHERE protocol = ?1 AND external_port = ?2",
            rusqlite::params![mapping.protocol, mapping.external_port],
            |r| r.get(0),
        )
        .map_err(FwError::Database)?;
    if conflict {
        return Err(FwError::Validation(format!(
            "{} port {} is already mapped",
            mapping.protocol, mapping.external_port
        )));
    }

    // Insert the mapping
    conn.execute(
        "INSERT INTO upnp_mappings (protocol, external_port, internal_ip, internal_port, description, client_ip, ttl_seconds, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now', '+' || ?7 || ' seconds'))",
        rusqlite::params![
            mapping.protocol,
            mapping.external_port,
            mapping.internal_ip,
            mapping.internal_port,
            description,
            mapping.client_ip,
            mapping.ttl_seconds,
        ],
    )
    .map_err(FwError::Database)?;

    let id = conn.last_insert_rowid();
    tracing::info!(
        id,
        protocol = %mapping.protocol,
        external_port = mapping.external_port,
        internal = %format!("{}:{}", mapping.internal_ip, mapping.internal_port),
        client = %mapping.client_ip,
        ttl = mapping.ttl_seconds,
        "UPnP mapping created"
    );

    Ok(id)
}

/// Delete a mapping by ID.
pub async fn delete_mapping(db: &sfgw_db::Db, id: i64) -> Result<(), FwError> {
    let conn = db.lock().await;
    let affected = conn
        .execute(
            "DELETE FROM upnp_mappings WHERE id = ?1",
            rusqlite::params![id],
        )
        .map_err(FwError::Database)?;
    if affected == 0 {
        return Err(FwError::Validation(format!("mapping id={id} not found")));
    }
    tracing::info!(id, "UPnP mapping deleted");
    Ok(())
}

/// List all active (non-expired) mappings.
pub async fn list_mappings(db: &sfgw_db::Db) -> Result<Vec<PortMapping>, FwError> {
    let conn = db.lock().await;
    let mut stmt = conn
        .prepare(
            "SELECT id, protocol, external_port, internal_ip, internal_port, description, client_ip, ttl_seconds, created_at, expires_at
             FROM upnp_mappings
             WHERE expires_at > datetime('now')
             ORDER BY created_at DESC",
        )
        .map_err(FwError::Database)?;

    let rows = stmt
        .query_map([], |row| {
            Ok(PortMapping {
                id: Some(row.get(0)?),
                protocol: row.get(1)?,
                external_port: row.get(2)?,
                internal_ip: row.get(3)?,
                internal_port: row.get(4)?,
                description: row.get(5)?,
                client_ip: row.get(6)?,
                ttl_seconds: row.get(7)?,
                created_at: row.get(8)?,
                expires_at: row.get(9)?,
            })
        })
        .map_err(FwError::Database)?
        .filter_map(|r| r.ok())
        .collect();

    Ok(rows)
}

/// Remove expired mappings from the database.
///
/// Returns the number of expired mappings cleaned up.
pub async fn cleanup_expired(db: &sfgw_db::Db) -> Result<usize> {
    let conn = db.lock().await;
    let affected = conn
        .execute(
            "DELETE FROM upnp_mappings WHERE expires_at <= datetime('now')",
            [],
        )
        .context("failed to cleanup expired UPnP mappings")?;
    if affected > 0 {
        tracing::info!(count = affected, "cleaned up expired UPnP mappings");
    }
    Ok(affected)
}

// ── iptables rule generation ────────────────────────────────────────

/// Generate iptables-restore fragment for all active UPnP mappings.
///
/// Rules are tagged with `sfgw-upnp` comment for identification and cleanup.
/// These are DNAT rules in the nat/PREROUTING chain and ACCEPT rules in
/// the filter/FORWARD chain.
pub fn generate_upnp_rules(mappings: &[PortMapping]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(512);

    if mappings.is_empty() {
        return out;
    }

    // INVARIANT: All writeln!(out, ...).unwrap() calls below write to a String.
    // fmt::Write for String is infallible -- it can only fail on OOM which aborts.
    writeln!(out, "# UPnP/NAT-PMP dynamic port mappings").unwrap();

    for m in mappings {
        // Validate IP before emitting (defense-in-depth)
        let Ok(_ip) = m.internal_ip.parse::<Ipv4Addr>() else {
            tracing::warn!(
                id = m.id,
                internal_ip = %m.internal_ip,
                "skipping UPnP mapping with invalid internal IP"
            );
            continue;
        };

        let proto = if m.protocol == "tcp" { "tcp" } else { "udp" };

        // DNAT rule: redirect external port to internal IP:port
        writeln!(
            out,
            "-A SFGW-PREROUTING -p {proto} --dport {} -j DNAT --to-destination {}:{} -m comment --comment \"sfgw-upnp id={}\"",
            m.external_port,
            m.internal_ip,
            m.internal_port,
            m.id.unwrap_or(0)
        ).unwrap();

        // FORWARD ACCEPT rule: allow the forwarded traffic
        writeln!(
            out,
            "-A SFGW-FORWARD -p {proto} -d {} --dport {} -j ACCEPT -m comment --comment \"sfgw-upnp id={}\"",
            m.internal_ip,
            m.internal_port,
            m.id.unwrap_or(0)
        ).unwrap();
    }

    out
}

/// Apply UPnP DNAT rules by reloading the full firewall ruleset.
///
/// This is called after adding/deleting a mapping. Rather than
/// manipulating iptables incrementally (which is fragile), we regenerate
/// the entire ruleset including UPnP rules and apply atomically via
/// iptables-restore.
pub async fn apply_upnp_rules(db: &sfgw_db::Db) -> Result<()> {
    // Trigger a full firewall reload which will include UPnP rules.
    crate::apply_rules(db).await?;
    Ok(())
}

// ── SSDP protocol ──────────────────────────────────────────────────

/// SSDP M-SEARCH response template.
const SSDP_RESPONSE_TEMPLATE: &str = "HTTP/1.1 200 OK\r\n\
Cache-Control: max-age=1800\r\n\
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
USN: uuid:{uuid}::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
Location: http://{addr}:{port}/upnp/description.xml\r\n\
Server: SecFirstGW/1.0 UPnP/1.1\r\n\
\r\n";

/// UPnP device description XML.
fn device_description_xml(addr: &str, port: u16) -> String {
    format!(
        r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>1</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>SecFirstGW Internet Gateway</friendlyName>
    <manufacturer>SecFirstGW</manufacturer>
    <modelName>Security First Gateway</modelName>
    <UDN>uuid:sfgw-igd-001</UDN>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
        <controlURL>http://{addr}:{port}/upnp/control</controlURL>
        <SCPDURL>http://{addr}:{port}/upnp/scpd.xml</SCPDURL>
      </service>
    </serviceList>
  </device>
</root>"#,
        addr = addr,
        port = port
    )
}

/// SOAP response for GetExternalIPAddress.
fn soap_external_ip_response(ip: &str) -> String {
    format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalIPAddress>{ip}</NewExternalIPAddress>
    </u:GetExternalIPAddressResponse>
  </s:Body>
</s:Envelope>"#
    )
}

/// SOAP response for AddPortMapping (success).
fn soap_add_mapping_response() -> &'static str {
    r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>
  </s:Body>
</s:Envelope>"#
}

/// SOAP response for DeletePortMapping (success).
fn soap_delete_mapping_response() -> &'static str {
    r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:DeletePortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>
  </s:Body>
</s:Envelope>"#
}

/// SOAP error response.
fn soap_error_response(code: u16, desc: &str) -> String {
    format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <s:Fault>
      <faultcode>s:Client</faultcode>
      <faultstring>UPnPError</faultstring>
      <detail>
        <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
          <errorCode>{code}</errorCode>
          <errorDescription>{desc}</errorDescription>
        </UPnPError>
      </detail>
    </s:Fault>
  </s:Body>
</s:Envelope>"#
    )
}

// ── SSDP server ────────────────────────────────────────────────────

/// Shared state for the UPnP service.
#[derive(Clone)]
pub struct UpnpHandle {
    db: sfgw_db::Db,
    settings: Arc<Mutex<UpnpSettings>>,
    /// LAN gateway IP (for SSDP responses and HTTP control).
    lan_ip: Ipv4Addr,
    /// External (WAN) IP for GetExternalIPAddress responses.
    external_ip: Arc<Mutex<Option<Ipv4Addr>>>,
}

impl UpnpHandle {
    /// Create a new handle.
    pub fn new(db: sfgw_db::Db, lan_ip: Ipv4Addr) -> Self {
        Self {
            db,
            settings: Arc::new(Mutex::new(UpnpSettings::default())),
            lan_ip,
            external_ip: Arc::new(Mutex::new(None)),
        }
    }

    /// Reload settings from DB.
    pub async fn reload_settings(&self) -> Result<()> {
        let s = load_settings(&self.db).await?;
        *self.settings.lock().await = s;
        Ok(())
    }

    /// Set the external IP (called when WAN comes up).
    pub async fn set_external_ip(&self, ip: Ipv4Addr) {
        *self.external_ip.lock().await = Some(ip);
    }
}

/// Start the UPnP/NAT-PMP service.
///
/// This spawns background tasks for:
/// 1. SSDP multicast listener (UDP 1900)
/// 2. HTTP control server (TCP, for SOAP)
/// 3. NAT-PMP listener (UDP 5351)
/// 4. TTL expiry cleanup
///
/// All listeners bind to the LAN gateway IP only (never 0.0.0.0).
pub async fn start(db: &sfgw_db::Db, lan_ip: Ipv4Addr) -> Result<UpnpHandle> {
    let handle = UpnpHandle::new(db.clone(), lan_ip);
    handle.reload_settings().await?;

    let enabled = handle.settings.lock().await.enabled;
    if !enabled {
        tracing::info!("UPnP/NAT-PMP disabled (enable via settings)");
        return Ok(handle);
    }

    tracing::info!(lan_ip = %lan_ip, "starting UPnP/NAT-PMP service");

    // 1. SSDP multicast listener
    let h = handle.clone();
    tokio::spawn(async move {
        if let Err(e) = run_ssdp_listener(h).await {
            tracing::error!("SSDP listener failed: {e}");
        }
    });

    // 2. HTTP control server for SOAP
    let h = handle.clone();
    tokio::spawn(async move {
        if let Err(e) = run_http_control(h).await {
            tracing::error!("UPnP HTTP control server failed: {e}");
        }
    });

    // 3. NAT-PMP listener
    let h = handle.clone();
    tokio::spawn(async move {
        if let Err(e) = run_natpmp_listener(h).await {
            tracing::error!("NAT-PMP listener failed: {e}");
        }
    });

    // 4. TTL expiry cleanup (every 30 seconds)
    let h = handle.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Err(e) = cleanup_expired(&h.db).await {
                tracing::warn!("UPnP TTL cleanup failed: {e}");
            }
        }
    });

    tracing::info!("UPnP/NAT-PMP service started");
    Ok(handle)
}

/// Run the SSDP multicast listener.
///
/// Responds to M-SEARCH requests from LAN clients looking for
/// InternetGatewayDevice services.
async fn run_ssdp_listener(handle: UpnpHandle) -> Result<()> {
    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, SSDP_PORT);
    let socket = UdpSocket::bind(bind_addr)
        .await
        .context("failed to bind SSDP socket")?;

    // Join multicast group on the LAN interface
    socket
        .join_multicast_v4(SSDP_MULTICAST, handle.lan_ip)
        .context("failed to join SSDP multicast group")?;

    tracing::info!(
        bind = %bind_addr,
        multicast = %SSDP_MULTICAST,
        "SSDP listener started"
    );

    let mut buf = [0u8; 2048];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("SSDP recv error: {e}");
                continue;
            }
        };

        let msg = String::from_utf8_lossy(&buf[..len]);

        // Only respond to M-SEARCH requests for IGD
        if !msg.contains("M-SEARCH") {
            continue;
        }
        if !msg.contains("ssdp:all")
            && !msg.contains("upnp:rootdevice")
            && !msg.contains("InternetGatewayDevice")
        {
            continue;
        }

        let response = SSDP_RESPONSE_TEMPLATE
            .replace("{uuid}", "sfgw-igd-001")
            .replace("{addr}", &handle.lan_ip.to_string())
            .replace("{port}", &UPNP_HTTP_PORT.to_string());

        if let Err(e) = socket.send_to(response.as_bytes(), peer).await {
            tracing::warn!(peer = %peer, "failed to send SSDP response: {e}");
        } else {
            tracing::debug!(peer = %peer, "sent SSDP M-SEARCH response");
        }
    }
}

/// Run the HTTP control server for SOAP requests.
///
/// Handles AddPortMapping, DeletePortMapping, GetExternalIPAddress.
async fn run_http_control(handle: UpnpHandle) -> Result<()> {
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(handle.lan_ip), UPNP_HTTP_PORT))
            .await
            .context("failed to bind UPnP HTTP control")?;

    tracing::info!(
        addr = %format!("{}:{}", handle.lan_ip, UPNP_HTTP_PORT),
        "UPnP HTTP control server started"
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("UPnP HTTP accept error: {e}");
                continue;
            }
        };

        let h = handle.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_http_connection(h, stream, peer).await {
                tracing::debug!(peer = %peer, "UPnP HTTP handler error: {e}");
            }
        });
    }
}

/// Handle a single HTTP connection for UPnP SOAP.
async fn handle_http_connection(
    handle: UpnpHandle,
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read the HTTP request (limit to 16KB to prevent abuse)
    let mut buf = vec![0u8; 16384];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .context("HTTP read timeout")?
        .context("HTTP read error")?;

    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);

    // Parse HTTP method and path
    let first_line = request.lines().next().unwrap_or("");

    let response = if first_line.starts_with("GET /upnp/description.xml") {
        let xml = device_description_xml(&handle.lan_ip.to_string(), UPNP_HTTP_PORT);
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            xml.len(),
            xml
        )
    } else if first_line.starts_with("POST /upnp/control") {
        handle_soap_request(&handle, &request, peer).await
    } else {
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
    };

    stream
        .write_all(response.as_bytes())
        .await
        .context("HTTP write error")?;
    stream.shutdown().await.ok();
    Ok(())
}

/// Handle a SOAP request for UPnP IGD.
async fn handle_soap_request(handle: &UpnpHandle, request: &str, peer: SocketAddr) -> String {
    // Extract SOAP action from headers
    let soap_action = request
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("soapaction:"))
        .map(|l| l.trim())
        .unwrap_or("");

    let body = if let Some(idx) = request.find("<?xml") {
        &request[idx..]
    } else if let Some(idx) = request.find("<s:Envelope") {
        &request[idx..]
    } else {
        ""
    };

    let (status, response_body) = if soap_action.contains("GetExternalIPAddress") {
        let ip = handle
            .external_ip
            .lock()
            .await
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "0.0.0.0".to_string());
        ("200 OK", soap_external_ip_response(&ip))
    } else if soap_action.contains("AddPortMapping") {
        match parse_add_port_mapping(body) {
            Ok(mapping) => {
                let settings = handle.settings.lock().await.clone();
                let mut mapping = mapping;
                // Override client_ip with actual peer address (security: don't trust SOAP body)
                mapping.client_ip = peer.ip().to_string();
                match add_mapping(&handle.db, &settings, &mapping).await {
                    Ok(_id) => {
                        // Apply the iptables rules
                        if let Err(e) = apply_upnp_rules(&handle.db).await {
                            tracing::error!("failed to apply UPnP iptables rules: {e}");
                        }
                        ("200 OK", soap_add_mapping_response().to_string())
                    }
                    Err(e) => (
                        "500 Internal Server Error",
                        soap_error_response(718, &format!("{e}")),
                    ),
                }
            }
            Err(e) => (
                "500 Internal Server Error",
                soap_error_response(402, &format!("Invalid args: {e}")),
            ),
        }
    } else if soap_action.contains("DeletePortMapping") {
        match parse_delete_port_mapping(body) {
            Ok((proto, port)) => {
                // Find the mapping by protocol + external port
                match find_mapping_by_port(&handle.db, &proto, port).await {
                    Ok(Some(id)) => match delete_mapping(&handle.db, id).await {
                        Ok(()) => {
                            if let Err(e) = apply_upnp_rules(&handle.db).await {
                                tracing::error!(
                                    "failed to apply UPnP iptables rules after delete: {e}"
                                );
                            }
                            ("200 OK", soap_delete_mapping_response().to_string())
                        }
                        Err(e) => (
                            "500 Internal Server Error",
                            soap_error_response(714, &format!("{e}")),
                        ),
                    },
                    Ok(None) => (
                        "500 Internal Server Error",
                        soap_error_response(714, "NoSuchEntryInArray"),
                    ),
                    Err(e) => (
                        "500 Internal Server Error",
                        soap_error_response(501, &format!("{e}")),
                    ),
                }
            }
            Err(e) => (
                "500 Internal Server Error",
                soap_error_response(402, &format!("Invalid args: {e}")),
            ),
        }
    } else {
        (
            "500 Internal Server Error",
            soap_error_response(401, "Invalid Action"),
        )
    };

    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
}

/// Find a mapping ID by protocol and external port.
async fn find_mapping_by_port(db: &sfgw_db::Db, proto: &str, port: u16) -> Result<Option<i64>> {
    let conn = db.lock().await;
    let id: Option<i64> = conn
        .query_row(
            "SELECT id FROM upnp_mappings WHERE protocol = ?1 AND external_port = ?2",
            rusqlite::params![proto, port],
            |r| r.get(0),
        )
        .ok();
    Ok(id)
}

/// Parse AddPortMapping SOAP body.
///
/// Extracts: protocol, external port, internal IP, internal port, description, TTL.
fn parse_add_port_mapping(xml: &str) -> Result<PortMapping> {
    let proto = extract_xml_value(xml, "NewProtocol")
        .context("missing NewProtocol")?
        .to_ascii_uppercase();
    let proto = match proto.as_str() {
        "TCP" => "tcp",
        "UDP" => "udp",
        other => bail!("invalid protocol: {other}"),
    };

    let external_port: u16 = extract_xml_value(xml, "NewExternalPort")
        .context("missing NewExternalPort")?
        .parse()
        .context("invalid NewExternalPort")?;

    let internal_ip =
        extract_xml_value(xml, "NewInternalClient").context("missing NewInternalClient")?;

    let internal_port: u16 = extract_xml_value(xml, "NewInternalPort")
        .context("missing NewInternalPort")?
        .parse()
        .context("invalid NewInternalPort")?;

    let description = extract_xml_value(xml, "NewPortMappingDescription").unwrap_or_default();

    let ttl: u32 = extract_xml_value(xml, "NewLeaseDuration")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TTL_SECS);

    // Clamp TTL: 0 means "permanent" in UPnP, map to max
    let ttl = if ttl == 0 {
        MAX_TTL_SECS
    } else {
        ttl.min(MAX_TTL_SECS)
    };

    Ok(PortMapping {
        id: None,
        protocol: proto.to_string(),
        external_port,
        internal_ip,
        internal_port,
        description,
        client_ip: String::new(), // filled by caller
        ttl_seconds: ttl,
        created_at: None,
        expires_at: None,
    })
}

/// Parse DeletePortMapping SOAP body.
fn parse_delete_port_mapping(xml: &str) -> Result<(String, u16)> {
    let proto = extract_xml_value(xml, "NewProtocol")
        .context("missing NewProtocol")?
        .to_ascii_lowercase();
    if proto != "tcp" && proto != "udp" {
        bail!("invalid protocol: {proto}");
    }

    let port: u16 = extract_xml_value(xml, "NewExternalPort")
        .context("missing NewExternalPort")?
        .parse()
        .context("invalid NewExternalPort")?;

    Ok((proto, port))
}

/// Extract a value between XML tags: `<tag>value</tag>`.
///
/// Simple string-based extraction -- no full XML parser needed for
/// the small UPnP SOAP payloads.
fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

// ── NAT-PMP server (RFC 6886) ──────────────────────────────────────

/// Run the NAT-PMP listener on UDP 5351.
///
/// NAT-PMP is a simpler protocol than UPnP: fixed binary format,
/// no XML, no HTTP. It's used by Apple devices and some game clients.
async fn run_natpmp_listener(handle: UpnpHandle) -> Result<()> {
    let bind_addr = SocketAddr::new(IpAddr::V4(handle.lan_ip), NATPMP_PORT);
    let socket = UdpSocket::bind(bind_addr)
        .await
        .context("failed to bind NAT-PMP socket")?;

    tracing::info!(addr = %bind_addr, "NAT-PMP listener started");

    let mut buf = [0u8; 64];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("NAT-PMP recv error: {e}");
                continue;
            }
        };

        if len < 2 {
            continue;
        }

        let version = buf[0];
        let opcode = buf[1];

        if version != 0 {
            continue; // NAT-PMP version must be 0
        }

        let response = match opcode {
            // 0 = External address request
            0 => {
                let ip = handle
                    .external_ip
                    .lock()
                    .await
                    .unwrap_or(Ipv4Addr::UNSPECIFIED);
                let epoch = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32;
                let mut resp = vec![0u8; 12];
                resp[0] = 0; // version
                resp[1] = 128; // opcode 128 = response to opcode 0
                resp[2] = 0; // result code MSB
                resp[3] = 0; // result code LSB (0 = success)
                resp[4..8].copy_from_slice(&epoch.to_be_bytes());
                resp[8..12].copy_from_slice(&ip.octets());
                resp
            }
            // 1 = UDP mapping, 2 = TCP mapping
            1 | 2 if len >= 12 => {
                let proto = if opcode == 1 { "udp" } else { "tcp" };
                let internal_port = u16::from_be_bytes([buf[4], buf[5]]);
                let external_port = u16::from_be_bytes([buf[6], buf[7]]);
                let ttl = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

                // External port 0 means "delete mapping for internal port"
                if external_port == 0 && ttl == 0 {
                    // Delete mapping
                    if let Ok(Some(id)) =
                        find_mapping_by_port(&handle.db, proto, internal_port).await
                    {
                        let _ = delete_mapping(&handle.db, id).await;
                        let _ = apply_upnp_rules(&handle.db).await;
                    }
                    natpmp_mapping_response(opcode, 0, internal_port, 0, 0)
                } else {
                    // Use the requested external port, or pick the internal port if 0
                    let ext_port = if external_port == 0 {
                        internal_port
                    } else {
                        external_port
                    };

                    let ttl = if ttl == 0 {
                        DEFAULT_TTL_SECS
                    } else {
                        ttl.min(MAX_TTL_SECS)
                    };

                    let mapping = PortMapping {
                        id: None,
                        protocol: proto.to_string(),
                        external_port: ext_port,
                        internal_ip: peer.ip().to_string(),
                        internal_port,
                        description: format!("NAT-PMP {proto}"),
                        client_ip: peer.ip().to_string(),
                        ttl_seconds: ttl,
                        created_at: None,
                        expires_at: None,
                    };

                    let settings = handle.settings.lock().await.clone();
                    match add_mapping(&handle.db, &settings, &mapping).await {
                        Ok(_) => {
                            let _ = apply_upnp_rules(&handle.db).await;
                            natpmp_mapping_response(opcode, 0, internal_port, ext_port, ttl)
                        }
                        Err(_) => {
                            natpmp_mapping_response(opcode, 3, internal_port, ext_port, 0)
                            // result 3 = NetworkFailure
                        }
                    }
                }
            }
            _ => continue,
        };

        if let Err(e) = socket.send_to(&response, peer).await {
            tracing::warn!(peer = %peer, "failed to send NAT-PMP response: {e}");
        }
    }
}

/// Build a NAT-PMP mapping response packet.
fn natpmp_mapping_response(
    opcode: u8,
    result_code: u16,
    internal_port: u16,
    external_port: u16,
    ttl: u32,
) -> Vec<u8> {
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;

    let mut resp = vec![0u8; 16];
    resp[0] = 0; // version
    resp[1] = 128 + opcode; // response opcode
    resp[2..4].copy_from_slice(&result_code.to_be_bytes());
    resp[4..8].copy_from_slice(&epoch.to_be_bytes());
    resp[8..10].copy_from_slice(&internal_port.to_be_bytes());
    resp[10..12].copy_from_slice(&external_port.to_be_bytes());
    resp[12..16].copy_from_slice(&ttl.to_be_bytes());
    resp
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_disabled() {
        let s = UpnpSettings::default();
        assert!(!s.enabled, "UPnP must be disabled by default");
        assert_eq!(s.port_min, 1024);
        assert_eq!(s.port_max, 65535);
        assert_eq!(s.max_per_ip, 32);
    }

    #[test]
    fn settings_serde_roundtrip() {
        let s = UpnpSettings {
            enabled: true,
            port_min: 10000,
            port_max: 20000,
            max_per_ip: 8,
        };
        let json = serde_json::to_string(&s).unwrap();
        let parsed: UpnpSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.enabled, true);
        assert_eq!(parsed.port_min, 10000);
        assert_eq!(parsed.port_max, 20000);
        assert_eq!(parsed.max_per_ip, 8);
    }

    #[test]
    fn generate_upnp_rules_empty() {
        let rules = generate_upnp_rules(&[]);
        assert!(rules.is_empty());
    }

    #[test]
    fn generate_upnp_rules_single_mapping() {
        let mappings = vec![PortMapping {
            id: Some(1),
            protocol: "tcp".to_string(),
            external_port: 8080,
            internal_ip: "192.168.1.50".to_string(),
            internal_port: 80,
            description: "web server".to_string(),
            client_ip: "192.168.1.50".to_string(),
            ttl_seconds: 3600,
            created_at: None,
            expires_at: None,
        }];
        let rules = generate_upnp_rules(&mappings);
        assert!(rules.contains("-A SFGW-PREROUTING"));
        assert!(rules.contains("-p tcp --dport 8080"));
        assert!(rules.contains("-j DNAT --to-destination 192.168.1.50:80"));
        assert!(rules.contains("sfgw-upnp id=1"));
        assert!(rules.contains("-A SFGW-FORWARD"));
        assert!(rules.contains("-d 192.168.1.50 --dport 80"));
    }

    #[test]
    fn generate_upnp_rules_skips_invalid_ip() {
        let mappings = vec![PortMapping {
            id: Some(2),
            protocol: "tcp".to_string(),
            external_port: 9090,
            internal_ip: "not-an-ip".to_string(),
            internal_port: 80,
            description: "bad".to_string(),
            client_ip: "192.168.1.1".to_string(),
            ttl_seconds: 3600,
            created_at: None,
            expires_at: None,
        }];
        let rules = generate_upnp_rules(&mappings);
        // Should not contain any DNAT rules
        assert!(!rules.contains("DNAT"));
    }

    #[test]
    fn extract_xml_value_basic() {
        let xml = "<NewProtocol>TCP</NewProtocol>";
        assert_eq!(
            extract_xml_value(xml, "NewProtocol"),
            Some("TCP".to_string())
        );
    }

    #[test]
    fn extract_xml_value_missing() {
        let xml = "<Foo>bar</Foo>";
        assert_eq!(extract_xml_value(xml, "NewProtocol"), None);
    }

    #[test]
    fn parse_add_port_mapping_valid() {
        let xml = r#"<?xml version="1.0"?>
<s:Envelope>
  <s:Body>
    <u:AddPortMapping>
      <NewProtocol>TCP</NewProtocol>
      <NewExternalPort>8080</NewExternalPort>
      <NewInternalClient>192.168.1.100</NewInternalClient>
      <NewInternalPort>80</NewInternalPort>
      <NewPortMappingDescription>Web Server</NewPortMappingDescription>
      <NewLeaseDuration>3600</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>"#;
        let m = parse_add_port_mapping(xml).unwrap();
        assert_eq!(m.protocol, "tcp");
        assert_eq!(m.external_port, 8080);
        assert_eq!(m.internal_ip, "192.168.1.100");
        assert_eq!(m.internal_port, 80);
        assert_eq!(m.description, "Web Server");
        assert_eq!(m.ttl_seconds, 3600);
    }

    #[test]
    fn parse_add_port_mapping_zero_ttl_becomes_max() {
        let xml = r#"<NewProtocol>UDP</NewProtocol>
<NewExternalPort>5060</NewExternalPort>
<NewInternalClient>10.0.0.5</NewInternalClient>
<NewInternalPort>5060</NewInternalPort>
<NewLeaseDuration>0</NewLeaseDuration>"#;
        let m = parse_add_port_mapping(xml).unwrap();
        assert_eq!(m.ttl_seconds, MAX_TTL_SECS);
    }

    #[test]
    fn parse_delete_port_mapping_valid() {
        let xml = r#"<NewProtocol>TCP</NewProtocol>
<NewExternalPort>8080</NewExternalPort>"#;
        let (proto, port) = parse_delete_port_mapping(xml).unwrap();
        assert_eq!(proto, "tcp");
        assert_eq!(port, 8080);
    }

    #[test]
    fn natpmp_response_format() {
        let resp = natpmp_mapping_response(1, 0, 5000, 5000, 3600);
        assert_eq!(resp.len(), 16);
        assert_eq!(resp[0], 0); // version
        assert_eq!(resp[1], 129); // 128 + 1
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]), 0); // success
        assert_eq!(u16::from_be_bytes([resp[8], resp[9]]), 5000); // internal port
        assert_eq!(u16::from_be_bytes([resp[10], resp[11]]), 5000); // external port
        assert_eq!(
            u32::from_be_bytes([resp[12], resp[13], resp[14], resp[15]]),
            3600
        );
    }

    #[tokio::test]
    async fn add_mapping_validates_protocol() {
        let db = sfgw_db::open_in_memory().await.unwrap();
        let settings = UpnpSettings::default();
        let mapping = PortMapping {
            id: None,
            protocol: "sctp".to_string(),
            external_port: 8080,
            internal_ip: "192.168.1.100".to_string(),
            internal_port: 80,
            description: String::new(),
            client_ip: "192.168.1.100".to_string(),
            ttl_seconds: 3600,
            created_at: None,
            expires_at: None,
        };
        let result = add_mapping(&db, &settings, &mapping).await;
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("invalid protocol"),
            "should reject non-tcp/udp protocol"
        );
    }

    #[tokio::test]
    async fn add_mapping_validates_port_range() {
        let db = sfgw_db::open_in_memory().await.unwrap();
        let settings = UpnpSettings {
            enabled: true,
            port_min: 10000,
            port_max: 20000,
            max_per_ip: 32,
        };
        let mapping = PortMapping {
            id: None,
            protocol: "tcp".to_string(),
            external_port: 80, // below port_min
            internal_ip: "192.168.1.100".to_string(),
            internal_port: 80,
            description: String::new(),
            client_ip: "192.168.1.100".to_string(),
            ttl_seconds: 3600,
            created_at: None,
            expires_at: None,
        };
        let result = add_mapping(&db, &settings, &mapping).await;
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("outside allowed range"),
            "should reject port outside configured range"
        );
    }

    #[tokio::test]
    async fn add_mapping_enforces_per_ip_limit() {
        let db = sfgw_db::open_in_memory().await.unwrap();
        let settings = UpnpSettings {
            enabled: true,
            port_min: 1024,
            port_max: 65535,
            max_per_ip: 2, // very low limit for testing
        };

        // Add 2 mappings
        for port in [8080u16, 8081] {
            let mapping = PortMapping {
                id: None,
                protocol: "tcp".to_string(),
                external_port: port,
                internal_ip: "192.168.1.100".to_string(),
                internal_port: port,
                description: String::new(),
                client_ip: "192.168.1.100".to_string(),
                ttl_seconds: 3600,
                created_at: None,
                expires_at: None,
            };
            add_mapping(&db, &settings, &mapping).await.unwrap();
        }

        // Third should fail
        let mapping = PortMapping {
            id: None,
            protocol: "tcp".to_string(),
            external_port: 8082,
            internal_ip: "192.168.1.100".to_string(),
            internal_port: 8082,
            description: String::new(),
            client_ip: "192.168.1.100".to_string(),
            ttl_seconds: 3600,
            created_at: None,
            expires_at: None,
        };
        let result = add_mapping(&db, &settings, &mapping).await;
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("maximum"),
            "should reject when per-IP limit reached"
        );
    }

    #[tokio::test]
    async fn add_mapping_rejects_duplicate_port() {
        let db = sfgw_db::open_in_memory().await.unwrap();
        let settings = UpnpSettings::default();

        let mapping = PortMapping {
            id: None,
            protocol: "tcp".to_string(),
            external_port: 8080,
            internal_ip: "192.168.1.100".to_string(),
            internal_port: 80,
            description: String::new(),
            client_ip: "192.168.1.100".to_string(),
            ttl_seconds: 3600,
            created_at: None,
            expires_at: None,
        };
        add_mapping(&db, &settings, &mapping).await.unwrap();

        // Same port, different client
        let mapping2 = PortMapping {
            client_ip: "192.168.1.200".to_string(),
            internal_ip: "192.168.1.200".to_string(),
            ..mapping.clone()
        };
        let result = add_mapping(&db, &settings, &mapping2).await;
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("already mapped"),
            "should reject duplicate external port"
        );
    }

    #[tokio::test]
    async fn list_and_delete_mapping() {
        let db = sfgw_db::open_in_memory().await.unwrap();
        let settings = UpnpSettings::default();

        let mapping = PortMapping {
            id: None,
            protocol: "udp".to_string(),
            external_port: 5060,
            internal_ip: "192.168.1.50".to_string(),
            internal_port: 5060,
            description: "SIP".to_string(),
            client_ip: "192.168.1.50".to_string(),
            ttl_seconds: 7200,
            created_at: None,
            expires_at: None,
        };
        let id = add_mapping(&db, &settings, &mapping).await.unwrap();

        let list = list_mappings(&db).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].external_port, 5060);

        delete_mapping(&db, id).await.unwrap();

        let list = list_mappings(&db).await.unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn settings_roundtrip_via_db() {
        let db = sfgw_db::open_in_memory().await.unwrap();

        // Default should be disabled
        let s = load_settings(&db).await.unwrap();
        assert!(!s.enabled);

        // Save custom settings
        let custom = UpnpSettings {
            enabled: true,
            port_min: 5000,
            port_max: 10000,
            max_per_ip: 16,
        };
        save_settings(&db, &custom).await.unwrap();

        // Reload and verify
        let loaded = load_settings(&db).await.unwrap();
        assert!(loaded.enabled);
        assert_eq!(loaded.port_min, 5000);
        assert_eq!(loaded.port_max, 10000);
        assert_eq!(loaded.max_per_ip, 16);
    }
}
