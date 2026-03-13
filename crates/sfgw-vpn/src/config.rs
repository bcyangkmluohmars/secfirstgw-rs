// SPDX-License-Identifier: AGPL-3.0-or-later

//! WireGuard configuration file generation and parsing.
//!
//! Supports the standard `wg-quick` INI format for import/export
//! and QR code data generation for mobile peer provisioning.

use anyhow::{Context, Result, bail};
use zeroize::Zeroize;

use crate::{TunnelConfig, WgPeer};

/// Generate a WireGuard config file string for the tunnel itself (server side).
///
/// **Security**: The returned string contains the private key.
/// It must NEVER be logged or returned in API responses.
pub fn generate_interface_config(config: &TunnelConfig, peers: &[WgPeer]) -> Result<String> {
    let mut private_key_b64 = crate::keys::private_key_to_base64(&config.private_key)?;

    let mut out = String::with_capacity(512);

    out.push_str("[Interface]\n");
    out.push_str(&format!("PrivateKey = {}\n", private_key_b64));
    out.push_str(&format!("Address = {}\n", config.address));

    // Add IPv6 address for dual-stack
    if let Some(ref v6) = config.address_v6 {
        out.push_str(&format!("Address = {}\n", v6));
    }

    out.push_str(&format!("ListenPort = {}\n", config.listen_port));
    out.push_str(&format!("MTU = {}\n", config.mtu));

    // Zeroize the plaintext key immediately after use
    private_key_b64.zeroize();

    if let Some(ref dns) = config.dns {
        out.push_str(&format!("DNS = {}\n", dns));
    }

    for peer in peers {
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
#[allow(clippy::too_many_arguments)]
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

/// Parse a WireGuard config file into a `TunnelConfig`.
///
/// Handles both `[Interface]` and `[Peer]` sections.
/// The private key is immediately wrapped in SecureBox upon parsing.
pub fn parse_config(input: &str) -> Result<TunnelConfig> {
    let mut private_key = String::new();
    let mut addresses: Vec<String> = Vec::new();
    let mut listen_port: u16 = 51820;
    let mut dns: Option<String> = None;
    let mut mtu: u16 = 1420;

    let mut current_section = Section::None;

    for line in input.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.eq_ignore_ascii_case("[interface]") {
            current_section = Section::Interface;
            continue;
        }

        if line.eq_ignore_ascii_case("[peer]") {
            // We only parse [Interface] for TunnelConfig
            break;
        }

        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim().to_lowercase(), v.trim().to_string()),
            None => continue,
        };

        if current_section == Section::Interface {
            match key.as_str() {
                "privatekey" => private_key = value,
                "address" => addresses.push(value),
                "listenport" => {
                    listen_port = value.parse().context("invalid ListenPort")?;
                }
                "dns" => dns = Some(value),
                "mtu" => mtu = value.parse().context("invalid MTU")?,
                _ => {}
            }
        }
    }

    if private_key.is_empty() {
        bail!("missing PrivateKey in [Interface]");
    }
    if addresses.is_empty() {
        bail!("missing Address in [Interface]");
    }

    let public_key =
        crate::keys::public_key_from_private(&private_key).context("invalid PrivateKey")?;

    let secure_key = crate::keys::wrap_private_key(&private_key)?;
    private_key.zeroize();

    // Separate IPv4 and IPv6 addresses
    let (address, address_v6) = split_addresses(&addresses);

    Ok(TunnelConfig {
        listen_port,
        private_key: secure_key,
        public_key,
        address,
        address_v6,
        dns,
        mtu,
        zone: "vpn".to_string(),
        bind_interface: None,
    })
}

/// Split a list of addresses into primary IPv4 and optional IPv6.
fn split_addresses(addresses: &[String]) -> (String, Option<String>) {
    let mut v4 = None;
    let mut v6 = None;

    for addr in addresses {
        if addr.contains(':') {
            v6 = Some(addr.clone());
        } else if v4.is_none() {
            v4 = Some(addr.clone());
        }
    }

    (v4.unwrap_or_else(|| addresses[0].clone()), v6)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Interface,
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
        let kp = crate::keys::generate_keypair().unwrap();
        let private_key_b64 = crate::keys::private_key_to_base64(&kp.private_key).unwrap();
        let config_str = format!(
            "[Interface]\n\
             PrivateKey = {}\n\
             Address = 10.0.0.1/24\n\
             Address = fd00::1/64\n\
             ListenPort = 51820\n\
             DNS = 1.1.1.1\n\
             MTU = 1420\n",
            private_key_b64
        );

        let parsed = parse_config(&config_str).unwrap();
        assert_eq!(parsed.address, "10.0.0.1/24");
        assert_eq!(parsed.address_v6.as_deref(), Some("fd00::1/64"));
        assert_eq!(parsed.listen_port, 51820);
        assert_eq!(parsed.dns.as_deref(), Some("1.1.1.1"));
        assert_eq!(parsed.mtu, 1420);
        assert_eq!(parsed.public_key, kp.public_key);
    }

    #[test]
    fn generate_peer_config_dual_stack() {
        let config = generate_peer_config(
            "cHJpdmF0ZWtleWhlcmUxMjM0NTY3ODkwMTIzNA==",
            "10.0.0.2/32, fd00::2/128",
            Some("1.1.1.1, 2606:4700:4700::1111"),
            1420,
            "c2VydmVycHVibGlja2V5MTIzNDU2Nzg5MDEyMzQ=",
            "vpn.example.com:51820",
            &["0.0.0.0/0".to_string(), "::/0".to_string()],
            None,
            Some(25),
        );

        assert!(config.contains("Address = 10.0.0.2/32, fd00::2/128"));
        assert!(config.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(config.contains("PersistentKeepalive = 25"));
        assert!(config.contains("DNS = 1.1.1.1, 2606:4700:4700::1111"));
    }

    #[test]
    fn split_addresses_v4_only() {
        let addrs = vec!["10.0.0.1/24".to_string()];
        let (v4, v6) = split_addresses(&addrs);
        assert_eq!(v4, "10.0.0.1/24");
        assert!(v6.is_none());
    }

    #[test]
    fn split_addresses_dual_stack() {
        let addrs = vec!["10.0.0.1/24".to_string(), "fd00::1/64".to_string()];
        let (v4, v6) = split_addresses(&addrs);
        assert_eq!(v4, "10.0.0.1/24");
        assert_eq!(v6.as_deref(), Some("fd00::1/64"));
    }
}
