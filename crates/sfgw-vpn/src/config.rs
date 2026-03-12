// SPDX-License-Identifier: AGPL-3.0-or-later

//! WireGuard configuration file generation and parsing.
//!
//! Supports the standard `wg-quick` INI format for import/export
//! and QR code data generation for mobile peer provisioning.

use anyhow::{bail, Context, Result};
use zeroize::Zeroize;

use crate::{TunnelConfig, WgPeer};

/// Generate a WireGuard config file string for the tunnel itself (server side).
///
/// **Security**: The returned string contains the private key.
/// It must NEVER be logged or returned in API responses.
/// The SecureBox is temporarily opened to extract the base64 key.
pub fn generate_interface_config(config: &TunnelConfig) -> Result<String> {
    let mut private_key_b64 = crate::keys::private_key_to_base64(&config.private_key)?;

    let mut out = String::with_capacity(512);

    out.push_str("[Interface]\n");
    out.push_str(&format!("PrivateKey = {}\n", private_key_b64));
    out.push_str(&format!("Address = {}\n", config.address));
    out.push_str(&format!("ListenPort = {}\n", config.listen_port));
    out.push_str(&format!("MTU = {}\n", config.mtu));

    // Zeroize the plaintext key immediately after use
    private_key_b64.zeroize();

    if let Some(ref dns) = config.dns {
        out.push_str(&format!("DNS = {}\n", dns));
    }

    for peer in &config.peers {
        out.push('\n');
        out.push_str(&format_peer_section(peer));
    }

    Ok(out)
}

/// Generate a WireGuard config for a specific peer (client-side config).
///
/// This is what you'd give to the peer device / show as QR code.
/// `server_public_key` is the tunnel's public key.
/// `server_endpoint` is the public IP:port of this gateway.
pub fn generate_peer_config(
    peer_private_key: &str,
    peer_address: &str,
    dns: Option<&str>,
    mtu: u16,
    server_public_key: &str,
    server_endpoint: &str,
    allowed_ips: &[String],
    preshared_key: Option<&str>,
    persistent_keepalive: Option<u16>,
) -> String {
    let mut out = String::with_capacity(512);

    out.push_str("[Interface]\n");
    out.push_str(&format!("PrivateKey = {}\n", peer_private_key));
    out.push_str(&format!("Address = {}\n", peer_address));
    out.push_str(&format!("MTU = {}\n", mtu));

    if let Some(dns) = dns {
        out.push_str(&format!("DNS = {}\n", dns));
    }

    out.push_str("\n[Peer]\n");
    out.push_str(&format!("PublicKey = {}\n", server_public_key));

    if let Some(psk) = preshared_key {
        out.push_str(&format!("PresharedKey = {}\n", psk));
    }

    if !allowed_ips.is_empty() {
        out.push_str(&format!("AllowedIPs = {}\n", allowed_ips.join(", ")));
    }

    out.push_str(&format!("Endpoint = {}\n", server_endpoint));

    if let Some(ka) = persistent_keepalive {
        out.push_str(&format!("PersistentKeepalive = {}\n", ka));
    }

    out
}

/// Generate QR code data string for a mobile peer.
/// This is simply the peer config — scan it with the WireGuard mobile app.
pub fn generate_qr_data(
    peer_private_key: &str,
    peer_address: &str,
    dns: Option<&str>,
    mtu: u16,
    server_public_key: &str,
    server_endpoint: &str,
    allowed_ips: &[String],
    preshared_key: Option<&str>,
    persistent_keepalive: Option<u16>,
) -> String {
    generate_peer_config(
        peer_private_key,
        peer_address,
        dns,
        mtu,
        server_public_key,
        server_endpoint,
        allowed_ips,
        preshared_key,
        persistent_keepalive,
    )
}

/// Parse a WireGuard config file into a `TunnelConfig`.
///
/// Handles both `[Interface]` and `[Peer]` sections.
/// The private key is immediately wrapped in SecureBox upon parsing.
pub fn parse_config(input: &str) -> Result<TunnelConfig> {
    let mut private_key = String::new();
    let mut address = String::new();
    let mut listen_port: u16 = 51820;
    let mut dns: Option<String> = None;
    let mut mtu: u16 = 1420;
    let mut peers: Vec<WgPeer> = Vec::new();

    let mut current_section = Section::None;
    let mut current_peer: Option<PeerBuilder> = None;

    for line in input.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.eq_ignore_ascii_case("[interface]") {
            // Flush any pending peer
            if let Some(pb) = current_peer.take() {
                peers.push(pb.build()?);
            }
            current_section = Section::Interface;
            continue;
        }

        if line.eq_ignore_ascii_case("[peer]") {
            // Flush previous peer
            if let Some(pb) = current_peer.take() {
                peers.push(pb.build()?);
            }
            current_section = Section::Peer;
            current_peer = Some(PeerBuilder::default());
            continue;
        }

        // Parse key = value
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim().to_lowercase(), v.trim().to_string()),
            None => continue,
        };

        match current_section {
            Section::Interface => match key.as_str() {
                "privatekey" => private_key = value,
                "address" => address = value,
                "listenport" => {
                    listen_port = value.parse().context("invalid ListenPort")?;
                }
                "dns" => dns = Some(value),
                "mtu" => mtu = value.parse().context("invalid MTU")?,
                _ => { /* ignore unknown keys */ }
            },
            Section::Peer => {
                if let Some(ref mut pb) = current_peer {
                    match key.as_str() {
                        "publickey" => pb.public_key = Some(value),
                        "presharedkey" => pb.preshared_key = Some(value),
                        "allowedips" => {
                            pb.allowed_ips = value
                                .split(',')
                                .map(|s| s.trim().to_string())
                                .collect();
                        }
                        "endpoint" => pb.endpoint = Some(value),
                        "persistentkeepalive" => {
                            pb.persistent_keepalive =
                                Some(value.parse().context("invalid PersistentKeepalive")?);
                        }
                        _ => {}
                    }
                }
            }
            Section::None => {}
        }
    }

    // Flush last peer
    if let Some(pb) = current_peer.take() {
        peers.push(pb.build()?);
    }

    if private_key.is_empty() {
        bail!("missing PrivateKey in [Interface]");
    }
    if address.is_empty() {
        bail!("missing Address in [Interface]");
    }

    let public_key = crate::keys::public_key_from_private(&private_key)
        .context("invalid PrivateKey")?;

    // Wrap the private key in SecureBox immediately
    let secure_key = crate::keys::wrap_private_key(&private_key)?;

    // Zeroize the plaintext private key string
    private_key.zeroize();

    Ok(TunnelConfig {
        listen_port,
        private_key: secure_key,
        public_key,
        address,
        dns,
        mtu,
        peers,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Section {
    None,
    Interface,
    Peer,
}

#[derive(Default)]
struct PeerBuilder {
    public_key: Option<String>,
    preshared_key: Option<String>,
    allowed_ips: Vec<String>,
    endpoint: Option<String>,
    persistent_keepalive: Option<u16>,
}

impl PeerBuilder {
    fn build(self) -> Result<WgPeer> {
        let public_key = self.public_key.context("peer missing PublicKey")?;
        Ok(WgPeer {
            public_key,
            preshared_key: self.preshared_key,
            allowed_ips: self.allowed_ips,
            endpoint: self.endpoint,
            persistent_keepalive: self.persistent_keepalive,
        })
    }
}

fn format_peer_section(peer: &WgPeer) -> String {
    let mut out = String::new();
    out.push_str("[Peer]\n");
    out.push_str(&format!("PublicKey = {}\n", peer.public_key));
    if let Some(ref psk) = peer.preshared_key {
        out.push_str(&format!("PresharedKey = {}\n", psk));
    }
    if !peer.allowed_ips.is_empty() {
        out.push_str(&format!("AllowedIPs = {}\n", peer.allowed_ips.join(", ")));
    }
    if let Some(ref ep) = peer.endpoint {
        out.push_str(&format!("Endpoint = {}\n", ep));
    }
    if let Some(ka) = peer.persistent_keepalive {
        out.push_str(&format!("PersistentKeepalive = {}\n", ka));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        // Use a real keypair for the test (parser derives public key from private)
        let kp = crate::keys::generate_keypair().unwrap();
        let private_key_b64 = crate::keys::private_key_to_base64(&kp.private_key).unwrap();
        let config_str = format!(
            "[Interface]\n\
             PrivateKey = {}\n\
             Address = 10.0.0.1/24\n\
             ListenPort = 51820\n\
             DNS = 1.1.1.1\n\
             MTU = 1420\n\
             \n\
             [Peer]\n\
             PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n\
             AllowedIPs = 10.0.0.2/32\n\
             Endpoint = 203.0.113.1:51820\n\
             PersistentKeepalive = 25\n",
            private_key_b64
        );

        let parsed = parse_config(&config_str).unwrap();
        assert_eq!(parsed.address, "10.0.0.1/24");
        assert_eq!(parsed.listen_port, 51820);
        assert_eq!(parsed.dns.as_deref(), Some("1.1.1.1"));
        assert_eq!(parsed.mtu, 1420);
        assert_eq!(parsed.public_key, kp.public_key);
        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.peers[0].allowed_ips, vec!["10.0.0.2/32"]);
        assert_eq!(
            parsed.peers[0].endpoint.as_deref(),
            Some("203.0.113.1:51820")
        );
        assert_eq!(parsed.peers[0].persistent_keepalive, Some(25));

        // Generate config back and re-parse
        let regenerated = generate_interface_config(&parsed).unwrap();
        let reparsed = parse_config(&regenerated).unwrap();
        assert_eq!(reparsed.address, parsed.address);
        assert_eq!(reparsed.listen_port, parsed.listen_port);
        assert_eq!(reparsed.peers.len(), parsed.peers.len());
    }
}
