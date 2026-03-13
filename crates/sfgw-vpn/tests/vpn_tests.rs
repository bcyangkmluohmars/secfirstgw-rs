// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests for the sfgw-vpn crate.
//!
//! Tests cover:
//! - Tunnel CRUD (create, list, get, delete)
//! - Peer management (add, remove, list, client config generation)
//! - Key generation and SecureBox wrapping
//! - Config file generation and parsing
//! - Dual-stack (IPv4 + IPv6) support
//! - Split/full tunnel routing modes

use sfgw_vpn::*;

/// Create an in-memory test database with the full schema.
async fn test_db() -> sfgw_db::Db {
    use rusqlite::Connection;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let conn = Connection::open_in_memory().unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();

    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS vpn_tunnels (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT NOT NULL UNIQUE,
            type      TEXT NOT NULL,
            enabled   INTEGER NOT NULL DEFAULT 0,
            config    TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS vpn_peers (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            tunnel_id           INTEGER NOT NULL REFERENCES vpn_tunnels(id) ON DELETE CASCADE,
            name                TEXT,
            public_key          TEXT NOT NULL,
            private_key_enc     TEXT NOT NULL,
            preshared_key       TEXT,
            address             TEXT NOT NULL,
            address_v6          TEXT,
            allowed_ips         TEXT NOT NULL DEFAULT '[]',
            endpoint            TEXT,
            persistent_keepalive INTEGER,
            routing_mode        TEXT NOT NULL DEFAULT 'split',
            dns                 TEXT,
            enabled             INTEGER NOT NULL DEFAULT 1,
            created_at          TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_peers_tunnel_pubkey
            ON vpn_peers(tunnel_id, public_key);
        INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '2');
        ",
    )
    .unwrap();

    Arc::new(Mutex::new(conn))
}

// ---------------------------------------------------------------------------
// Tunnel CRUD tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_tunnel() {
    let db = test_db().await;
    let req = CreateTunnelRequest {
        name: "wg0".to_string(),
        listen_port: 51820,
        address: "10.0.0.1/24".to_string(),
        address_v6: Some("fd00::1/64".to_string()),
        dns: Some("1.1.1.1".to_string()),
        mtu: Some(1420),
        zone: "vpn".to_string(),
        bind_interface: None,
    };

    let tunnel = tunnel::create_tunnel(&db, &req).await.unwrap();
    assert_eq!(tunnel.name, "wg0");
    assert_eq!(tunnel.listen_port, 51820);
    assert_eq!(tunnel.address, "10.0.0.1/24");
    assert_eq!(tunnel.address_v6.as_deref(), Some("fd00::1/64"));
    assert_eq!(tunnel.dns.as_deref(), Some("1.1.1.1"));
    assert_eq!(tunnel.mtu, 1420);
    assert_eq!(tunnel.zone, "vpn");
    assert!(!tunnel.enabled);
    assert!(!tunnel.public_key.is_empty());
}

#[tokio::test]
async fn test_create_tunnel_duplicate_name() {
    let db = test_db().await;
    let req = CreateTunnelRequest {
        name: "wg0".to_string(),
        listen_port: 51820,
        address: "10.0.0.1/24".to_string(),
        address_v6: None,
        dns: None,
        mtu: None,
        zone: "vpn".to_string(),
        bind_interface: None,
    };

    tunnel::create_tunnel(&db, &req).await.unwrap();
    let err = tunnel::create_tunnel(&db, &req).await;
    assert!(err.is_err());
}

#[tokio::test]
async fn test_create_tunnel_invalid_name() {
    let db = test_db().await;
    let req = CreateTunnelRequest {
        name: "this_name_is_way_too_long_for_iface".to_string(),
        listen_port: 51820,
        address: "10.0.0.1/24".to_string(),
        address_v6: None,
        dns: None,
        mtu: None,
        zone: "vpn".to_string(),
        bind_interface: None,
    };

    let err = tunnel::create_tunnel(&db, &req).await;
    assert!(err.is_err());
}

#[tokio::test]
async fn test_list_tunnels() {
    let db = test_db().await;

    for i in 0..3 {
        let req = CreateTunnelRequest {
            name: format!("wg{i}"),
            listen_port: 51820 + i as u16,
            address: format!("10.0.{i}.1/24"),
            address_v6: None,
            dns: None,
            mtu: None,
            zone: "vpn".to_string(),
        bind_interface: None,
        };
        tunnel::create_tunnel(&db, &req).await.unwrap();
    }

    let tunnels = tunnel::list_tunnels(&db).await.unwrap();
    assert_eq!(tunnels.len(), 3);
    assert_eq!(tunnels[0].name, "wg0");
    assert_eq!(tunnels[1].name, "wg1");
    assert_eq!(tunnels[2].name, "wg2");
}

#[tokio::test]
async fn test_get_tunnel_by_id() {
    let db = test_db().await;
    let req = CreateTunnelRequest {
        name: "wg0".to_string(),
        listen_port: 51820,
        address: "10.0.0.1/24".to_string(),
        address_v6: None,
        dns: None,
        mtu: None,
        zone: "vpn".to_string(),
        bind_interface: None,
    };

    let created = tunnel::create_tunnel(&db, &req).await.unwrap();
    let fetched = tunnel::get_tunnel_by_id(&db, created.id).await.unwrap();

    assert!(fetched.is_some());
    let fetched = fetched.unwrap();
    assert_eq!(fetched.name, "wg0");
    assert_eq!(fetched.id, created.id);
}

#[tokio::test]
async fn test_get_tunnel_not_found() {
    let db = test_db().await;
    let result = tunnel::get_tunnel_by_id(&db, 999).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_delete_tunnel() {
    let db = test_db().await;
    let req = CreateTunnelRequest {
        name: "wg0".to_string(),
        listen_port: 51820,
        address: "10.0.0.1/24".to_string(),
        address_v6: None,
        dns: None,
        mtu: None,
        zone: "vpn".to_string(),
        bind_interface: None,
    };

    let created = tunnel::create_tunnel(&db, &req).await.unwrap();
    tunnel::delete_tunnel(&db, created.id).await.unwrap();

    let result = tunnel::get_tunnel_by_id(&db, created.id).await.unwrap();
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// Peer management tests
// ---------------------------------------------------------------------------

async fn create_test_tunnel(db: &sfgw_db::Db) -> VpnTunnel {
    let req = CreateTunnelRequest {
        name: "wg0".to_string(),
        listen_port: 51820,
        address: "10.0.0.1/24".to_string(),
        address_v6: Some("fd00::1/64".to_string()),
        dns: Some("1.1.1.1".to_string()),
        mtu: Some(1420),
        zone: "vpn".to_string(),
        bind_interface: None,
    };
    tunnel::create_tunnel(db, &req).await.unwrap()
}

#[tokio::test]
async fn test_add_peer_auto_address() {
    let db = test_db().await;
    let tunnel = create_test_tunnel(&db).await;

    let req = CreatePeerRequest {
        name: Some("laptop".to_string()),
        address: None, // auto-assign
        address_v6: None,
        allowed_ips: vec![],
        endpoint: None,
        persistent_keepalive: Some(25),
        routing_mode: RoutingMode::Split,
        dns: None,
    };

    let peer = peer::add_peer(&db, tunnel.id, &req).await.unwrap();

    assert_eq!(peer.name.as_deref(), Some("laptop"));
    assert!(!peer.public_key.is_empty());
    assert!(peer.address.starts_with("10.0.0."));
    assert!(peer.address.ends_with("/32"));
    assert!(peer.address_v6.is_some());
    assert!(peer.enabled);
    assert_eq!(peer.routing_mode, RoutingMode::Split);
    assert_eq!(peer.persistent_keepalive, Some(25));
}

#[tokio::test]
async fn test_add_peer_explicit_address() {
    let db = test_db().await;
    let tunnel = create_test_tunnel(&db).await;

    let req = CreatePeerRequest {
        name: Some("phone".to_string()),
        address: Some("10.0.0.50/32".to_string()),
        address_v6: Some("fd00::50/128".to_string()),
        allowed_ips: vec![],
        endpoint: None,
        persistent_keepalive: None,
        routing_mode: RoutingMode::Full,
        dns: Some("8.8.8.8".to_string()),
    };

    let peer = peer::add_peer(&db, tunnel.id, &req).await.unwrap();
    assert_eq!(peer.address, "10.0.0.50/32");
    assert_eq!(peer.address_v6.as_deref(), Some("fd00::50/128"));
    assert_eq!(peer.routing_mode, RoutingMode::Full);
    assert_eq!(peer.dns.as_deref(), Some("8.8.8.8"));
}

#[tokio::test]
async fn test_add_multiple_peers_unique_keys() {
    let db = test_db().await;
    let tunnel = create_test_tunnel(&db).await;

    let mut public_keys = Vec::new();
    for i in 0..5 {
        let req = CreatePeerRequest {
            name: Some(format!("peer{i}")),
            address: None,
            address_v6: None,
            allowed_ips: vec![],
            endpoint: None,
            persistent_keepalive: None,
            routing_mode: RoutingMode::Split,
            dns: None,
        };
        let peer = peer::add_peer(&db, tunnel.id, &req).await.unwrap();
        assert!(!public_keys.contains(&peer.public_key), "duplicate key generated");
        public_keys.push(peer.public_key);
    }

    assert_eq!(public_keys.len(), 5);
}

#[tokio::test]
async fn test_list_peers() {
    let db = test_db().await;
    let tunnel = create_test_tunnel(&db).await;

    for i in 0..3 {
        let req = CreatePeerRequest {
            name: Some(format!("peer{i}")),
            address: None,
            address_v6: None,
            allowed_ips: vec![],
            endpoint: None,
            persistent_keepalive: None,
            routing_mode: RoutingMode::Split,
            dns: None,
        };
        peer::add_peer(&db, tunnel.id, &req).await.unwrap();
    }

    let peers = peer::list_peers(&db, tunnel.id).await.unwrap();
    assert_eq!(peers.len(), 3);
}

#[tokio::test]
async fn test_remove_peer() {
    let db = test_db().await;
    let tunnel = create_test_tunnel(&db).await;

    let req = CreatePeerRequest {
        name: Some("temp".to_string()),
        address: None,
        address_v6: None,
        allowed_ips: vec![],
        endpoint: None,
        persistent_keepalive: None,
        routing_mode: RoutingMode::Split,
        dns: None,
    };
    let peer = peer::add_peer(&db, tunnel.id, &req).await.unwrap();

    peer::remove_peer(&db, tunnel.id, peer.id).await.unwrap();

    let peers = peer::list_peers(&db, tunnel.id).await.unwrap();
    assert_eq!(peers.len(), 0);
}

#[tokio::test]
async fn test_remove_peer_wrong_tunnel() {
    let db = test_db().await;
    let tunnel = create_test_tunnel(&db).await;

    let req = CreatePeerRequest {
        name: Some("peer1".to_string()),
        address: None,
        address_v6: None,
        allowed_ips: vec![],
        endpoint: None,
        persistent_keepalive: None,
        routing_mode: RoutingMode::Split,
        dns: None,
    };
    let peer = peer::add_peer(&db, tunnel.id, &req).await.unwrap();

    // Try to remove from a non-existent tunnel
    let err = peer::remove_peer(&db, 999, peer.id).await;
    assert!(err.is_err());
}

#[tokio::test]
async fn test_cascade_delete_peers() {
    let db = test_db().await;
    let tunnel = create_test_tunnel(&db).await;

    for i in 0..3 {
        let req = CreatePeerRequest {
            name: Some(format!("peer{i}")),
            address: None,
            address_v6: None,
            allowed_ips: vec![],
            endpoint: None,
            persistent_keepalive: None,
            routing_mode: RoutingMode::Split,
            dns: None,
        };
        peer::add_peer(&db, tunnel.id, &req).await.unwrap();
    }

    // Delete the tunnel — peers should cascade-delete
    tunnel::delete_tunnel(&db, tunnel.id).await.unwrap();

    let peers = peer::list_peers(&db, tunnel.id).await.unwrap();
    assert_eq!(peers.len(), 0);
}

// ---------------------------------------------------------------------------
// Client config generation tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_generate_client_config_split() {
    let db = test_db().await;
    let tunnel = create_test_tunnel(&db).await;

    let req = CreatePeerRequest {
        name: Some("laptop".to_string()),
        address: Some("10.0.0.2/32".to_string()),
        address_v6: Some("fd00::2/128".to_string()),
        allowed_ips: vec!["192.168.1.0/24".to_string()],
        endpoint: None,
        persistent_keepalive: Some(25),
        routing_mode: RoutingMode::Split,
        dns: None,
    };
    let peer = peer::add_peer(&db, tunnel.id, &req).await.unwrap();

    let config = peer::generate_client_config(
        &db,
        tunnel.id,
        peer.id,
        "vpn.example.com:51820",
    )
    .await
    .unwrap();

    // Verify the config contains expected fields
    assert!(config.contains("[Interface]"));
    assert!(config.contains("PrivateKey = "));
    assert!(config.contains("Address = "));
    assert!(config.contains("[Peer]"));
    assert!(config.contains(&format!("PublicKey = {}", tunnel.public_key)));
    assert!(config.contains("Endpoint = vpn.example.com:51820"));
    assert!(config.contains("PersistentKeepalive = 25"));
    assert!(config.contains("PresharedKey = ")); // PSK is auto-generated
    assert!(config.contains("MTU = 1420"));

    // Should NOT contain 0.0.0.0/0 (split tunnel)
    assert!(!config.contains("0.0.0.0/0"));
}

#[tokio::test]
async fn test_generate_client_config_full() {
    let db = test_db().await;
    let tunnel = create_test_tunnel(&db).await;

    let req = CreatePeerRequest {
        name: Some("phone".to_string()),
        address: Some("10.0.0.3/32".to_string()),
        address_v6: None,
        allowed_ips: vec![],
        endpoint: None,
        persistent_keepalive: None,
        routing_mode: RoutingMode::Full,
        dns: None,
    };
    let peer = peer::add_peer(&db, tunnel.id, &req).await.unwrap();

    let config = peer::generate_client_config(
        &db,
        tunnel.id,
        peer.id,
        "1.2.3.4:51820",
    )
    .await
    .unwrap();

    // Full tunnel: should have 0.0.0.0/0 and ::/0
    assert!(config.contains("0.0.0.0/0"));
    assert!(config.contains("::/0"));
}

// ---------------------------------------------------------------------------
// Key management tests
// ---------------------------------------------------------------------------

#[test]
fn test_keypair_generation() {
    let kp = keys::generate_keypair().unwrap();
    assert!(!kp.public_key.is_empty());

    // Verify the public key can be derived from the private key
    let derived = keys::public_key_from_secure(&kp.private_key).unwrap();
    assert_eq!(kp.public_key, derived);
}

#[test]
fn test_keypairs_are_unique() {
    let a = keys::generate_keypair().unwrap();
    let b = keys::generate_keypair().unwrap();
    assert_ne!(a.public_key, b.public_key);
}

#[test]
fn test_preshared_key_generation() {
    let psk = keys::generate_preshared_key();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&psk)
        .unwrap();
    assert_eq!(decoded.len(), 32);
}

use base64::Engine;

#[test]
fn test_private_key_securebox_roundtrip() {
    let kp = keys::generate_keypair().unwrap();
    let b64 = keys::private_key_to_base64(&kp.private_key).unwrap();

    // Re-wrap
    let rewrapped = keys::wrap_private_key(&b64).unwrap();
    let derived = keys::public_key_from_secure(&rewrapped).unwrap();
    assert_eq!(kp.public_key, derived);
}

// ---------------------------------------------------------------------------
// Config generation tests
// ---------------------------------------------------------------------------

#[test]
fn test_config_parse_dual_stack() {
    let kp = keys::generate_keypair().unwrap();
    let key_b64 = keys::private_key_to_base64(&kp.private_key).unwrap();

    let input = format!(
        "[Interface]\n\
         PrivateKey = {key_b64}\n\
         Address = 10.0.0.1/24\n\
         Address = fd00::1/64\n\
         ListenPort = 51820\n\
         DNS = 1.1.1.1, 2606:4700:4700::1111\n\
         MTU = 1420\n"
    );

    let parsed = config::parse_config(&input).unwrap();
    assert_eq!(parsed.address, "10.0.0.1/24");
    assert_eq!(parsed.address_v6.as_deref(), Some("fd00::1/64"));
    assert_eq!(parsed.listen_port, 51820);
    assert_eq!(parsed.mtu, 1420);
}

#[test]
fn test_generate_peer_config_format() {
    let conf = config::generate_peer_config(
        "cHJpdmF0ZWtleWhlcmUxMjM0NTY3ODkwMTIzNA==",
        "10.0.0.2/32",
        Some("1.1.1.1"),
        1420,
        "c2VydmVycHVibGlja2V5MTIzNDU2Nzg5MDEyMzQ=",
        "vpn.example.com:51820",
        &["10.0.0.0/24".to_string()],
        Some("cHJlc2hhcmVka2V5MTIzNDU2Nzg5MDEyMzQ1Ng=="),
        Some(25),
    );

    assert!(conf.starts_with("[Interface]\n"));
    assert!(conf.contains("PrivateKey = "));
    assert!(conf.contains("Address = 10.0.0.2/32"));
    assert!(conf.contains("DNS = 1.1.1.1"));
    assert!(conf.contains("[Peer]"));
    assert!(conf.contains("PresharedKey = "));
    assert!(conf.contains("AllowedIPs = 10.0.0.0/24"));
    assert!(conf.contains("Endpoint = vpn.example.com:51820"));
    assert!(conf.contains("PersistentKeepalive = 25"));
}

// ---------------------------------------------------------------------------
// Routing mode tests
// ---------------------------------------------------------------------------

#[test]
fn test_routing_mode_serialization() {
    assert_eq!(
        serde_json::to_string(&RoutingMode::Full).unwrap(),
        "\"full\""
    );
    assert_eq!(
        serde_json::to_string(&RoutingMode::Split).unwrap(),
        "\"split\""
    );

    let full: RoutingMode = serde_json::from_str("\"full\"").unwrap();
    assert_eq!(full, RoutingMode::Full);

    let split: RoutingMode = serde_json::from_str("\"split\"").unwrap();
    assert_eq!(split, RoutingMode::Split);
}

#[test]
fn test_routing_mode_from_str_lossy() {
    assert_eq!(RoutingMode::from_str_lossy("full"), RoutingMode::Full);
    assert_eq!(RoutingMode::from_str_lossy("FULL"), RoutingMode::Full);
    assert_eq!(RoutingMode::from_str_lossy("split"), RoutingMode::Split);
    assert_eq!(RoutingMode::from_str_lossy("garbage"), RoutingMode::Split);
}

// ---------------------------------------------------------------------------
// Tunnel status test (offline — no real interface)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_status_offline() {
    let status = tunnel::get_status("nonexistent_wg99").await.unwrap();
    assert!(!status.is_up);
    assert_eq!(status.rx_bytes, 0);
    assert_eq!(status.tx_bytes, 0);
    assert!(status.peers.is_empty());
}

// ---------------------------------------------------------------------------
// Zone integration test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_zone_assignment() {
    let db = test_db().await;
    let req = CreateTunnelRequest {
        name: "wg-guest".to_string(),
        listen_port: 51821,
        address: "10.1.0.1/24".to_string(),
        address_v6: None,
        dns: None,
        mtu: None,
        zone: "guest".to_string(), // Custom zone
        bind_interface: None,
    };

    let tunnel = tunnel::create_tunnel(&db, &req).await.unwrap();
    assert_eq!(tunnel.zone, "guest");

    // Fetch and verify zone persists
    let fetched = tunnel::get_tunnel_by_id(&db, tunnel.id).await.unwrap().unwrap();
    assert_eq!(fetched.zone, "guest");
}

// ---------------------------------------------------------------------------
// IPv6 only tunnel test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_tunnel_ipv6_only() {
    let db = test_db().await;
    let req = CreateTunnelRequest {
        name: "wg-v6".to_string(),
        listen_port: 51822,
        address: "10.0.0.1/24".to_string(),
        address_v6: Some("fd00::1/64".to_string()),
        dns: Some("2606:4700:4700::1111".to_string()),
        mtu: Some(1400),
        zone: "vpn".to_string(),
        bind_interface: None,
    };

    let tunnel = tunnel::create_tunnel(&db, &req).await.unwrap();
    assert!(tunnel.address_v6.is_some());
    assert_eq!(tunnel.dns.as_deref(), Some("2606:4700:4700::1111"));
}

// ===========================================================================
// IPsec/IKEv2 tests
// ===========================================================================

// ---------------------------------------------------------------------------
// IPsec tunnel creation (roadwarrior)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_ipsec_tunnel_roadwarrior() {
    let db = test_db().await;
    let req = CreateIpsecTunnelRequest {
        name: "ipsec-rw".to_string(),
        mode: IpsecMode::RoadWarrior,
        auth_method: IpsecAuthMethod::Certificate,
        local_id: Some("gw.secfirstgw.local".to_string()),
        listen_port: None,
        local_addrs: None,
        pool_v4: Some("10.10.0.0/24".to_string()),
        pool_v6: Some("fd10::0/112".to_string()),
        local_ts: None,
        remote_ts: None,
        dns: Some("10.10.0.1".to_string()),
        zone: "vpn".to_string(),
    };

    let tunnel = ipsec::create_ipsec_tunnel(&db, &req).await.unwrap();
    assert_eq!(tunnel.name, "ipsec-rw");
    assert_eq!(tunnel.tunnel_type, TunnelType::IPsec);
    assert!(!tunnel.enabled);
    assert_eq!(tunnel.zone, "vpn");
}

// ---------------------------------------------------------------------------
// IPsec tunnel creation (site-to-site)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_ipsec_tunnel_s2s() {
    let db = test_db().await;
    let req = CreateIpsecTunnelRequest {
        name: "ipsec-s2s".to_string(),
        mode: IpsecMode::SiteToSite,
        auth_method: IpsecAuthMethod::Psk,
        local_id: Some("site-a.example.com".to_string()),
        listen_port: None,
        local_addrs: Some("203.0.113.1".to_string()),
        pool_v4: None,
        pool_v6: None,
        local_ts: Some(vec!["192.168.1.0/24".to_string()]),
        remote_ts: Some(vec!["192.168.2.0/24".to_string()]),
        dns: None,
        zone: "vpn".to_string(),
    };

    let tunnel = ipsec::create_ipsec_tunnel(&db, &req).await.unwrap();
    assert_eq!(tunnel.name, "ipsec-s2s");
    assert_eq!(tunnel.tunnel_type, TunnelType::IPsec);
}

// ---------------------------------------------------------------------------
// IPsec duplicate name rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_ipsec_tunnel_duplicate_name() {
    let db = test_db().await;
    let req = CreateIpsecTunnelRequest {
        name: "ipsec-dup".to_string(),
        mode: IpsecMode::RoadWarrior,
        auth_method: IpsecAuthMethod::Certificate,
        local_id: None,
        listen_port: None,
        local_addrs: None,
        pool_v4: Some("10.20.0.0/24".to_string()),
        pool_v6: None,
        local_ts: None,
        remote_ts: None,
        dns: None,
        zone: "vpn".to_string(),
    };

    ipsec::create_ipsec_tunnel(&db, &req).await.unwrap();
    let err = ipsec::create_ipsec_tunnel(&db, &req).await;
    assert!(err.is_err());
}

// ---------------------------------------------------------------------------
// IPsec roadwarrior requires pool
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_ipsec_rw_no_pool_fails() {
    let db = test_db().await;
    let req = CreateIpsecTunnelRequest {
        name: "ipsec-nopool".to_string(),
        mode: IpsecMode::RoadWarrior,
        auth_method: IpsecAuthMethod::Certificate,
        local_id: None,
        listen_port: None,
        local_addrs: None,
        pool_v4: None,
        pool_v6: None,
        local_ts: None,
        remote_ts: None,
        dns: None,
        zone: "vpn".to_string(),
    };

    let err = ipsec::create_ipsec_tunnel(&db, &req).await;
    assert!(err.is_err());
}

// ---------------------------------------------------------------------------
// IPsec invalid name rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_ipsec_tunnel_invalid_name() {
    let db = test_db().await;
    let req = CreateIpsecTunnelRequest {
        name: "bad;name".to_string(),
        mode: IpsecMode::RoadWarrior,
        auth_method: IpsecAuthMethod::Certificate,
        local_id: None,
        listen_port: None,
        local_addrs: None,
        pool_v4: Some("10.20.0.0/24".to_string()),
        pool_v6: None,
        local_ts: None,
        remote_ts: None,
        dns: None,
        zone: "vpn".to_string(),
    };

    let err = ipsec::create_ipsec_tunnel(&db, &req).await;
    assert!(err.is_err());
}

// ---------------------------------------------------------------------------
// IPsec list mixed with WireGuard tunnels
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_mixed_tunnel_types() {
    let db = test_db().await;

    // Create a WireGuard tunnel
    let wg_req = CreateTunnelRequest {
        name: "wg0".to_string(),
        listen_port: 51820,
        address: "10.0.0.1/24".to_string(),
        address_v6: None,
        dns: None,
        mtu: None,
        zone: "vpn".to_string(),
        bind_interface: None,
    };
    tunnel::create_tunnel(&db, &wg_req).await.unwrap();

    // Create an IPsec tunnel
    let ipsec_req = CreateIpsecTunnelRequest {
        name: "ipsec-rw".to_string(),
        mode: IpsecMode::RoadWarrior,
        auth_method: IpsecAuthMethod::Certificate,
        local_id: None,
        listen_port: None,
        local_addrs: None,
        pool_v4: Some("10.10.0.0/24".to_string()),
        pool_v6: None,
        local_ts: None,
        remote_ts: None,
        dns: None,
        zone: "vpn".to_string(),
    };
    ipsec::create_ipsec_tunnel(&db, &ipsec_req).await.unwrap();

    let tunnels = tunnel::list_tunnels(&db).await.unwrap();
    assert_eq!(tunnels.len(), 2);
    assert_eq!(tunnels[0].tunnel_type, TunnelType::WireGuard);
    assert_eq!(tunnels[1].tunnel_type, TunnelType::IPsec);
}

// ---------------------------------------------------------------------------
// IPsec delete tunnel
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_delete_ipsec_tunnel() {
    let db = test_db().await;
    let req = CreateIpsecTunnelRequest {
        name: "ipsec-del".to_string(),
        mode: IpsecMode::SiteToSite,
        auth_method: IpsecAuthMethod::Psk,
        local_id: Some("del.example.com".to_string()),
        listen_port: None,
        local_addrs: None,
        pool_v4: None,
        pool_v6: None,
        local_ts: Some(vec!["192.168.1.0/24".to_string()]),
        remote_ts: Some(vec!["192.168.2.0/24".to_string()]),
        dns: None,
        zone: "vpn".to_string(),
    };

    let tunnel = ipsec::create_ipsec_tunnel(&db, &req).await.unwrap();
    tunnel::delete_tunnel(&db, tunnel.id).await.unwrap();

    let result = tunnel::get_tunnel_by_id(&db, tunnel.id).await.unwrap();
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// swanctl.conf generation tests (integration-level)
// ---------------------------------------------------------------------------

#[test]
fn test_swanctl_config_roadwarrior_generation() {
    let config = IpsecDbConfig {
        mode: "roadwarrior".to_string(),
        auth_method: "certificate".to_string(),
        local_id: "gw.secfirstgw.local".to_string(),
        listen_port: None,
        local_addrs: None,
        pool_v4: Some("10.10.0.0/24".to_string()),
        pool_v6: Some("fd10::0/112".to_string()),
        local_ts: Vec::new(),
        remote_ts: Vec::new(),
        dns: Some("10.10.0.1".to_string()),
        zone: "vpn".to_string(),
    };

    let result = ipsec::generate_swanctl_config("rw-integ", &config).unwrap();

    // Verify structure
    assert!(result.contains("connections {"));
    assert!(result.contains("sfgw-rw-integ {"));
    assert!(result.contains("version = 2"));
    assert!(result.contains("pools {"));
    assert!(result.contains("pool-rw-integ-v4 {"));
    assert!(result.contains("pool-rw-integ-v6 {"));
    assert!(result.contains("remote_ts = dynamic"));

    // Verify no weak ciphers
    assert!(!result.contains("3des"));
    assert!(!result.contains("sha1"));
    assert!(!result.contains("modp1024"));
}

#[test]
fn test_swanctl_config_s2s_generation() {
    let config = IpsecDbConfig {
        mode: "site-to-site".to_string(),
        auth_method: "psk".to_string(),
        local_id: "site-a.example.com".to_string(),
        listen_port: None,
        local_addrs: Some("203.0.113.1".to_string()),
        pool_v4: None,
        pool_v6: None,
        local_ts: vec!["192.168.1.0/24".to_string()],
        remote_ts: vec!["192.168.2.0/24".to_string()],
        dns: None,
        zone: "vpn".to_string(),
    };

    let result = ipsec::generate_swanctl_config("s2s-integ", &config).unwrap();

    assert!(result.contains("local_addrs = 203.0.113.1"));
    assert!(result.contains("local_ts = 192.168.1.0/24"));
    assert!(result.contains("remote_ts = 192.168.2.0/24"));
    assert!(result.contains("secrets {"));
    assert!(!result.contains("pools {"));
}

// ---------------------------------------------------------------------------
// TunnelType serde tests (integration)
// ---------------------------------------------------------------------------

#[test]
fn test_tunnel_type_serde_ipsec() {
    let tt = TunnelType::IPsec;
    let json = serde_json::to_string(&tt).unwrap();
    assert_eq!(json, "\"ipsec\"");

    let back: TunnelType = serde_json::from_str(&json).unwrap();
    assert_eq!(back, TunnelType::IPsec);
}

#[test]
fn test_tunnel_type_serde_wireguard() {
    let tt = TunnelType::WireGuard;
    let json = serde_json::to_string(&tt).unwrap();
    assert_eq!(json, "\"wireguard\"");

    let back: TunnelType = serde_json::from_str(&json).unwrap();
    assert_eq!(back, TunnelType::WireGuard);
}

// ---------------------------------------------------------------------------
// IpsecAuthMethod + IpsecMode Display/parsing tests (integration)
// ---------------------------------------------------------------------------

#[test]
fn test_ipsec_auth_method_roundtrip() {
    for method in [
        IpsecAuthMethod::Certificate,
        IpsecAuthMethod::Psk,
        IpsecAuthMethod::EapMschapv2,
    ] {
        let s = method.to_string();
        let parsed = IpsecAuthMethod::parse(&s).unwrap();
        assert_eq!(method, parsed);
    }
}

#[test]
fn test_ipsec_mode_roundtrip() {
    for mode in [IpsecMode::RoadWarrior, IpsecMode::SiteToSite] {
        let s = mode.to_string();
        let parsed = IpsecMode::parse(&s).unwrap();
        assert_eq!(mode, parsed);
    }
}
