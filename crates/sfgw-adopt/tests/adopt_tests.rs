// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests for the sfgw-adopt crate.
//!
//! Covers the CA, signing, device adoption protocol, state parsing,
//! and inform encryption/decryption.

use std::sync::Arc;
use tokio::sync::Mutex;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use sfgw_adopt::ca::GatewayCA;
use sfgw_adopt::inform::{
    InformPayload, InformResponse, decrypt_payload, encrypt_response, load_latest_firmware,
    register_firmware,
};
use sfgw_adopt::protocol::{approve_device, discover_device, parse_state, reject_device};
use sfgw_adopt::signing::{SignedPayload, sign_config, sign_firmware_manifest, verify_signature};
use sfgw_adopt::{AdoptionRequest, AdoptionState, DeviceInfo};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn fresh_db() -> sfgw_db::Db {
    let conn = rusqlite::Connection::open_in_memory().expect("failed to open in-memory database");
    conn.execute_batch(
        "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE devices (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             mac TEXT NOT NULL UNIQUE,
             name TEXT,
             model TEXT,
             ip TEXT,
             adopted INTEGER NOT NULL DEFAULT 0,
             last_seen TEXT,
             config TEXT NOT NULL DEFAULT '{}'
         );
         CREATE TABLE firmware_manifests (
             id         INTEGER PRIMARY KEY AUTOINCREMENT,
             model      TEXT NOT NULL,
             version    TEXT NOT NULL,
             sha256     TEXT NOT NULL,
             size_bytes INTEGER NOT NULL,
             url        TEXT NOT NULL,
             signature  TEXT NOT NULL,
             created_at TEXT NOT NULL DEFAULT (datetime('now'))
         );
         CREATE INDEX idx_firmware_manifests_model_version
             ON firmware_manifests(model, version);
         INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '2');",
    )
    .expect("failed to initialise test schema");
    Arc::new(Mutex::new(conn))
}

fn sample_device_info(mac: &str) -> DeviceInfo {
    DeviceInfo {
        mac: mac.to_string(),
        model: "USW-24-PoE".to_string(),
        ip: "192.168.1.50".to_string(),
        firmware_version: "1.0.0".to_string(),
        capabilities: vec!["poe".to_string(), "vlan".to_string()],
    }
}

/// Generate an X25519 keypair and return (secret, base64-encoded public key).
fn gen_x25519_keypair() -> (x25519_dalek::StaticSecret, String) {
    let rng = ring::rand::SystemRandom::new();
    let mut secret_bytes = [0u8; 32];
    ring::rand::SecureRandom::fill(&rng, &mut secret_bytes).expect("RNG fill");
    let secret = x25519_dalek::StaticSecret::from(secret_bytes);
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret, B64.encode(public.as_bytes()))
}

/// Generate an ML-KEM-1024 keypair and return (decaps key bytes, base64-encoded encaps key).
fn gen_ml_kem_keypair() -> (Vec<u8>, String) {
    use fips203::ml_kem_1024;
    use fips203::traits::{KeyGen, SerDes};

    let (ek, dk) = ml_kem_1024::KG::try_keygen().expect("ML-KEM-1024 keygen");
    let ek_bytes = ek.into_bytes();
    let dk_bytes = dk.into_bytes();
    (dk_bytes.to_vec(), B64.encode(ek_bytes))
}

fn make_adoption_request(
    mac: &str,
    with_pq: bool,
) -> (AdoptionRequest, x25519_dalek::StaticSecret) {
    let (_secret, pub_b64) = gen_x25519_keypair();
    let kem_pub = if with_pq {
        let (_dk, ek_b64) = gen_ml_kem_keypair();
        Some(ek_b64)
    } else {
        None
    };
    let req = AdoptionRequest {
        device_mac: mac.to_string(),
        device_model: "USW-24-PoE".to_string(),
        device_ip: "192.168.1.50".to_string(),
        device_public_key: pub_b64,
        device_kem_public_key: kem_pub,
    };
    (req, _secret)
}

/// Insert a device in Pending state into the DB.
async fn insert_pending_device(db: &sfgw_db::Db, mac: &str) {
    discover_device(db, &sample_device_info(mac))
        .await
        .expect("discover_device");
}

// ===========================================================================
// CA Tests
// ===========================================================================

#[tokio::test]
async fn ca_init_generates_keypair_on_first_boot() {
    let db = fresh_db().await;
    let ca = GatewayCA::init(&db).await.expect("CA init");

    // Public key must be non-empty.
    assert!(
        !ca.public_key().is_empty(),
        "CA public key must not be empty after first-boot init"
    );

    // CA cert PEM must be present.
    assert!(
        ca.cert_pem.contains("-----BEGIN SFGW CA CERTIFICATE-----"),
        "CA cert PEM must contain the correct header"
    );

    // Keys must be persisted in the meta table.
    let conn = db.lock().await;
    let ca_key: String = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'gateway_ca_key'",
            [],
            |r| r.get(0),
        )
        .expect("CA key must be stored in meta table");
    assert!(!ca_key.is_empty(), "stored CA key must not be empty");

    let ca_vk: String = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'gateway_ca_vk'",
            [],
            |r| r.get(0),
        )
        .expect("CA verifying key must be stored in meta table");
    assert!(
        !ca_vk.is_empty(),
        "stored CA verifying key must not be empty"
    );
}

#[tokio::test]
async fn ca_init_loads_existing_keypair_idempotent() {
    let db = fresh_db().await;
    let ca1 = GatewayCA::init(&db).await.expect("first CA init");
    let pk1 = ca1.public_key().to_vec();
    let cert1 = ca1.cert_pem.clone();

    // Drop ca1 and reinitialise — should load from DB, not generate new keys.
    drop(ca1);
    let ca2 = GatewayCA::init(&db).await.expect("second CA init");
    let pk2 = ca2.public_key().to_vec();
    let cert2 = ca2.cert_pem.clone();

    assert_eq!(pk1, pk2, "public key must be identical across init calls");
    assert_eq!(cert1, cert2, "CA cert must be identical across init calls");
}

#[tokio::test]
async fn ca_signs_device_cert_returns_pem() {
    let db = fresh_db().await;
    let ca = GatewayCA::init(&db).await.expect("CA init");

    let device_pub_key = [0x42u8; 32]; // dummy 32-byte key
    let pem = ca
        .sign_device_cert("AA:BB:CC:DD:EE:FF", &device_pub_key)
        .expect("sign_device_cert");

    assert!(
        pem.contains("-----BEGIN SFGW DEVICE CERTIFICATE-----"),
        "device cert PEM must contain correct header"
    );
    assert!(
        pem.contains("-----END SFGW DEVICE CERTIFICATE-----"),
        "device cert PEM must contain correct footer"
    );
}

#[tokio::test]
async fn ca_public_key_is_non_empty() {
    let db = fresh_db().await;
    let ca = GatewayCA::init(&db).await.expect("CA init");
    assert!(
        !ca.public_key().is_empty(),
        "CA public key must not be empty"
    );
    // ML-DSA-65 public key length is 1952 bytes.
    assert_eq!(
        ca.public_key().len(),
        1952,
        "ML-DSA-65 public key must be 1952 bytes"
    );
}

// ===========================================================================
// Signing Tests
// ===========================================================================

#[tokio::test]
async fn sign_config_verify_roundtrip() {
    let db = fresh_db().await;
    let ca = GatewayCA::init(&db).await.expect("CA init");

    let payload = b"test config payload for signing roundtrip";
    let signed = sign_config(payload, &ca).expect("sign_config");
    let recovered = verify_signature(&signed, ca.public_key(), Some(ca.ed25519_public_key()))
        .expect("verify_signature");

    assert_eq!(recovered, payload, "verified payload must match original");
}

#[tokio::test]
async fn verify_signature_tampered_payload_fails() {
    let db = fresh_db().await;
    let ca = GatewayCA::init(&db).await.expect("CA init");

    let payload = b"original payload";
    let signed = sign_config(payload, &ca).expect("sign_config");

    // Tamper with the payload field.
    let tampered = SignedPayload {
        payload: B64.encode(b"tampered payload"),
        signature_ml_dsa_65: signed.signature_ml_dsa_65.clone(),
        signature_ed25519: signed.signature_ed25519.clone(),
    };

    let result = verify_signature(&tampered, ca.public_key(), Some(ca.ed25519_public_key()));
    assert!(
        result.is_err(),
        "verification must fail for tampered payload"
    );
}

#[tokio::test]
async fn verify_signature_wrong_public_key_fails() {
    let db = fresh_db().await;
    let ca = GatewayCA::init(&db).await.expect("CA init");

    let payload = b"payload signed by correct CA";
    let signed = sign_config(payload, &ca).expect("sign_config");

    // Create a second CA with a different keypair.
    let db2 = fresh_db().await;
    let ca2 = GatewayCA::init(&db2).await.expect("second CA init");

    let result = verify_signature(&signed, ca2.public_key(), Some(ca2.ed25519_public_key()));
    assert!(
        result.is_err(),
        "verification must fail with a different CA public key"
    );
}

#[tokio::test]
async fn sign_firmware_manifest_produces_valid_manifest() {
    let db = fresh_db().await;
    let ca = GatewayCA::init(&db).await.expect("CA init");

    let manifest = sign_firmware_manifest(
        "2.0.0",
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "https://fw.example.com/firmware-2.0.0.bin",
        1024,
        &ca,
    )
    .expect("sign_firmware_manifest");

    assert_eq!(manifest.version, "2.0.0");
    assert_eq!(
        manifest.sha256,
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    );
    assert_eq!(manifest.url, "https://fw.example.com/firmware-2.0.0.bin");

    // The embedded signed payload must verify against the CA public key.
    let recovered_bytes = verify_signature(
        &manifest.signed,
        ca.public_key(),
        Some(ca.ed25519_public_key()),
    )
    .expect("manifest signature verify");
    let recovered: serde_json::Value =
        serde_json::from_slice(&recovered_bytes).expect("manifest JSON parse");
    assert_eq!(recovered["version"], "2.0.0");
    assert_eq!(
        recovered["url"],
        "https://fw.example.com/firmware-2.0.0.bin"
    );
}

// ===========================================================================
// Device Adoption Flow
// ===========================================================================

#[tokio::test]
async fn discover_device_creates_pending() {
    let db = fresh_db().await;
    let info = sample_device_info("AA:BB:CC:DD:EE:01");
    discover_device(&db, &info).await.expect("discover_device");

    let conn = db.lock().await;
    let config_json: String = conn
        .query_row(
            "SELECT config FROM devices WHERE mac = ?1",
            ["AA:BB:CC:DD:EE:01"],
            |r| r.get(0),
        )
        .expect("device must exist in DB");

    let state = parse_state(&config_json);
    assert_eq!(
        state,
        AdoptionState::Pending,
        "newly discovered device must be in Pending state"
    );
}

#[tokio::test]
async fn discover_device_is_idempotent() {
    let db = fresh_db().await;
    let info = sample_device_info("AA:BB:CC:DD:EE:02");

    discover_device(&db, &info).await.expect("first discover");
    discover_device(&db, &info).await.expect("second discover");

    // Only one row should exist.
    let conn = db.lock().await;
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM devices WHERE mac = ?1",
            ["AA:BB:CC:DD:EE:02"],
            |r| r.get(0),
        )
        .expect("count query");
    assert_eq!(
        count, 1,
        "idempotent discover must not create duplicate rows"
    );
}

#[tokio::test]
async fn approve_device_transitions_pending_to_adopted() {
    let db = fresh_db().await;
    let ca = GatewayCA::init(&db).await.expect("CA init");
    let mac = "AA:BB:CC:DD:EE:03";

    insert_pending_device(&db, mac).await;

    let (req, _secret) = make_adoption_request(mac, true);
    let response = approve_device(&db, &ca, &req)
        .await
        .expect("approve_device");

    // Verify response fields.
    assert!(
        response
            .gateway_ca_cert
            .contains("-----BEGIN SFGW CA CERTIFICATE-----"),
        "response must include gateway CA cert"
    );
    assert!(
        response
            .device_cert
            .contains("-----BEGIN SFGW DEVICE CERTIFICATE-----"),
        "response must include device cert"
    );
    assert!(
        !response.gateway_ecdh_public.is_empty(),
        "response must include ECDH public key"
    );
    assert_eq!(response.initial_sequence, 1, "initial sequence must be 1");

    // Verify DB state is now Adopted.
    let conn = db.lock().await;
    let (adopted, config_json): (i64, String) = conn
        .query_row(
            "SELECT adopted, config FROM devices WHERE mac = ?1",
            [mac],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("device query");
    assert_eq!(adopted, 1, "adopted flag must be 1");
    let state = parse_state(&config_json);
    assert_eq!(
        state,
        AdoptionState::Adopted,
        "config state must be Adopted"
    );
}

#[tokio::test]
async fn approve_device_fails_for_non_pending() {
    let db = fresh_db().await;
    let ca = GatewayCA::init(&db).await.expect("CA init");
    let mac = "AA:BB:CC:DD:EE:04";

    // Insert and then reject the device so it is not Pending.
    insert_pending_device(&db, mac).await;
    reject_device(&db, mac).await.expect("reject_device");

    let (req, _secret) = make_adoption_request(mac, false);
    let result = approve_device(&db, &ca, &req).await;
    assert!(
        result.is_err(),
        "approve_device must fail for a non-pending device"
    );
}

#[tokio::test]
async fn reject_device_transitions_to_rejected() {
    let db = fresh_db().await;
    let mac = "AA:BB:CC:DD:EE:05";
    insert_pending_device(&db, mac).await;

    reject_device(&db, mac).await.expect("reject_device");

    let conn = db.lock().await;
    let config_json: String = conn
        .query_row("SELECT config FROM devices WHERE mac = ?1", [mac], |r| {
            r.get(0)
        })
        .expect("device query");
    let state = parse_state(&config_json);
    assert_eq!(
        state,
        AdoptionState::Rejected,
        "rejected device must be in Rejected state"
    );
}

#[tokio::test]
async fn reject_device_nonexistent_mac_fails() {
    let db = fresh_db().await;
    let result = reject_device(&db, "FF:FF:FF:FF:FF:FF").await;
    assert!(
        result.is_err(),
        "reject_device must fail for a non-existent MAC"
    );
}

#[tokio::test]
async fn each_adopted_device_gets_unique_key_material() {
    let db = fresh_db().await;
    let ca = GatewayCA::init(&db).await.expect("CA init");

    let mac_a = "AA:BB:CC:DD:EE:A1";
    let mac_b = "AA:BB:CC:DD:EE:B2";
    insert_pending_device(&db, mac_a).await;
    insert_pending_device(&db, mac_b).await;

    let (req_a, _) = make_adoption_request(mac_a, false);
    let (req_b, _) = make_adoption_request(mac_b, false);

    let resp_a = approve_device(&db, &ca, &req_a)
        .await
        .expect("approve device A");
    let resp_b = approve_device(&db, &ca, &req_b)
        .await
        .expect("approve device B");

    // ECDH public keys must differ (ephemeral per adoption).
    assert_ne!(
        resp_a.gateway_ecdh_public, resp_b.gateway_ecdh_public,
        "each device must receive a unique gateway ECDH public key"
    );

    // Device certs must differ.
    assert_ne!(
        resp_a.device_cert, resp_b.device_cert,
        "each device must receive a unique certificate"
    );

    // Symmetric keys stored in DB config must differ.
    let conn = db.lock().await;
    let cfg_a: String = conn
        .query_row("SELECT config FROM devices WHERE mac = ?1", [mac_a], |r| {
            r.get(0)
        })
        .expect("device A config");
    let cfg_b: String = conn
        .query_row("SELECT config FROM devices WHERE mac = ?1", [mac_b], |r| {
            r.get(0)
        })
        .expect("device B config");

    let val_a: serde_json::Value = serde_json::from_str(&cfg_a).expect("parse A config");
    let val_b: serde_json::Value = serde_json::from_str(&cfg_b).expect("parse B config");
    assert_ne!(
        val_a["symmetric_key"], val_b["symmetric_key"],
        "each device must have a unique symmetric key"
    );
}

#[tokio::test]
async fn adoption_response_includes_required_fields() {
    let db = fresh_db().await;
    let ca = GatewayCA::init(&db).await.expect("CA init");
    let mac = "AA:BB:CC:DD:EE:06";
    insert_pending_device(&db, mac).await;

    let (req, _) = make_adoption_request(mac, true);
    let response = approve_device(&db, &ca, &req)
        .await
        .expect("approve_device");

    // Gateway CA cert present.
    assert!(
        !response.gateway_ca_cert.is_empty(),
        "gateway_ca_cert must be present"
    );

    // Device cert present.
    assert!(
        !response.device_cert.is_empty(),
        "device_cert must be present"
    );

    // ECDH public key is valid base64 decoding to 32 bytes.
    let ecdh_bytes = B64
        .decode(&response.gateway_ecdh_public)
        .expect("ECDH public key must be valid base64");
    assert_eq!(ecdh_bytes.len(), 32, "ECDH public key must be 32 bytes");

    // Initial sequence is 1.
    assert_eq!(response.initial_sequence, 1);

    // ML-KEM ciphertext present when PQ key was provided.
    assert!(
        response.ml_kem_ciphertext.is_some(),
        "ML-KEM ciphertext must be present when device provides KEM key"
    );
}

// ===========================================================================
// Protocol State Parsing
// ===========================================================================

#[test]
fn parse_state_correctly_parses_all_states() {
    let cases = [
        (
            r#"{"adoption_state":"Discovered"}"#,
            AdoptionState::Discovered,
        ),
        (r#"{"adoption_state":"Pending"}"#, AdoptionState::Pending),
        (r#"{"adoption_state":"Approved"}"#, AdoptionState::Approved),
        (r#"{"adoption_state":"Adopted"}"#, AdoptionState::Adopted),
        (r#"{"adoption_state":"Rejected"}"#, AdoptionState::Rejected),
    ];
    for (json, expected) in &cases {
        let state = parse_state(json);
        assert_eq!(
            state, *expected,
            "parse_state({json}) should produce {expected:?}"
        );
    }
}

#[test]
fn parse_state_defaults_to_discovered_for_invalid() {
    // Missing field.
    assert_eq!(parse_state("{}"), AdoptionState::Discovered);
    // Invalid JSON.
    assert_eq!(parse_state("not json at all"), AdoptionState::Discovered);
    // Unknown state string.
    assert_eq!(
        parse_state(r#"{"adoption_state":"UnknownState"}"#),
        AdoptionState::Discovered
    );
    // Empty string.
    assert_eq!(parse_state(""), AdoptionState::Discovered);
    // Null value.
    assert_eq!(
        parse_state(r#"{"adoption_state":null}"#),
        AdoptionState::Discovered
    );
}

// ===========================================================================
// Inform Encryption
// ===========================================================================

#[test]
fn encrypt_response_decrypt_roundtrip() {
    let key = [0xABu8; 32];
    let response = InformResponse {
        sequence_number: 42,
        config_update: None,
        firmware_update: None,
        inform_interval_secs: 30,
    };

    let encrypted_b64 = encrypt_response(&response, &key).expect("encrypt_response");

    // We cannot directly call decrypt_payload with an InformResponse because
    // decrypt_payload expects InformPayload JSON. Instead, verify the roundtrip
    // by decrypting the raw bytes and parsing back as InformResponse.
    let ct_bytes = B64.decode(&encrypted_b64).expect("base64 decode");

    // Decrypt manually using ring.
    use ring::aead::{self, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    let (nonce_bytes, encrypted) = ct_bytes.split_at(aead::NONCE_LEN);
    let nonce_arr: [u8; 12] = nonce_bytes.try_into().expect("nonce length");
    let unbound = UnboundKey::new(&AES_256_GCM, &key).expect("unbound key");
    let opening_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_arr);
    let mut in_out = encrypted.to_vec();
    let plaintext = opening_key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .expect("AES-256-GCM decryption");
    let recovered: InformResponse = serde_json::from_slice(plaintext).expect("JSON parse");

    assert_eq!(recovered.sequence_number, 42);
    assert_eq!(recovered.inform_interval_secs, 30);
}

#[test]
fn inform_decrypt_payload_roundtrip() {
    let key = [0xCDu8; 32];
    let payload = InformPayload {
        mac: "AA:BB:CC:DD:EE:FF".to_string(),
        uptime_secs: 3600,
        firmware_version: "1.2.3".to_string(),
        sequence_number: 10,
        metrics: serde_json::json!({"cpu": 12.5}),
        ids_events: vec![],
    };

    // Encrypt the payload manually (simulating what a device would send).
    let json_bytes = serde_json::to_vec(&payload).expect("JSON serialise");
    use ring::aead::{self, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    use ring::rand::SecureRandom;

    let unbound = UnboundKey::new(&AES_256_GCM, &key).expect("unbound key");
    let sealing_key = LessSafeKey::new(unbound);
    let rng = ring::rand::SystemRandom::new();
    let mut nonce_bytes = [0u8; aead::NONCE_LEN];
    rng.fill(&mut nonce_bytes).expect("rng fill");
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = json_bytes;
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .expect("seal");
    let mut ct = Vec::with_capacity(aead::NONCE_LEN + in_out.len());
    ct.extend_from_slice(&nonce_bytes);
    ct.extend_from_slice(&in_out);
    let ct_b64 = B64.encode(&ct);

    // Decrypt using the public API.
    let recovered = decrypt_payload(&ct_b64, &key).expect("decrypt_payload");
    assert_eq!(recovered.mac, "AA:BB:CC:DD:EE:FF");
    assert_eq!(recovered.uptime_secs, 3600);
    assert_eq!(recovered.sequence_number, 10);
}

#[test]
fn inform_tampered_ciphertext_fails_decryption() {
    let key = [0xEFu8; 32];
    let response = InformResponse {
        sequence_number: 99,
        config_update: None,
        firmware_update: None,
        inform_interval_secs: 30,
    };

    let encrypted_b64 = encrypt_response(&response, &key).expect("encrypt_response");
    let mut ct_bytes = B64.decode(&encrypted_b64).expect("base64 decode");

    // Tamper with the ciphertext (after the 12-byte nonce).
    if ct_bytes.len() > 13 {
        ct_bytes[13] ^= 0xFF;
    }

    let tampered_b64 = B64.encode(&ct_bytes);

    // decrypt_payload expects InformPayload but the important thing is the
    // AEAD authentication fails before JSON parsing.
    let result = decrypt_payload(&tampered_b64, &key);
    assert!(
        result.is_err(),
        "tampered ciphertext must fail AEAD authentication"
    );
}

#[test]
fn inform_wrong_key_fails_decryption() {
    let key = [0x11u8; 32];
    let wrong_key = [0x22u8; 32];
    let response = InformResponse {
        sequence_number: 7,
        config_update: None,
        firmware_update: None,
        inform_interval_secs: 60,
    };

    let encrypted_b64 = encrypt_response(&response, &key).expect("encrypt_response");

    let result = decrypt_payload(&encrypted_b64, &wrong_key);
    assert!(result.is_err(), "decryption with wrong key must fail");
}

// ===========================================================================
// Firmware Manifest Tests
// ===========================================================================

#[tokio::test]
async fn load_latest_firmware_returns_none_when_no_firmware_registered() {
    let db = fresh_db().await;

    let result = load_latest_firmware(&db, "USW-24-PoE")
        .await
        .expect("load_latest_firmware");

    assert!(
        result.is_none(),
        "must return None when no firmware manifests exist for the model"
    );
}

#[tokio::test]
async fn firmware_version_comparison_returns_newer_manifest() {
    let db = fresh_db().await;
    let ca = GatewayCA::init(&db).await.expect("CA init");

    // Register two firmware versions for the same model.
    register_firmware(
        &db,
        &ca,
        "USW-24-PoE",
        "1.0.0",
        "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
        2048,
        "https://fw.example.com/usw-1.0.0.bin",
    )
    .await
    .expect("register firmware 1.0.0");

    register_firmware(
        &db,
        &ca,
        "USW-24-PoE",
        "2.1.0",
        "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222",
        4096,
        "https://fw.example.com/usw-2.1.0.bin",
    )
    .await
    .expect("register firmware 2.1.0");

    // Latest firmware should be version 2.1.0 (highest id).
    let latest = load_latest_firmware(&db, "USW-24-PoE")
        .await
        .expect("load_latest_firmware")
        .expect("firmware row must exist");

    assert_eq!(latest.version, "2.1.0");
    assert_eq!(latest.size_bytes, 4096);
    assert_eq!(latest.model, "USW-24-PoE");

    // A device on version 1.0.0 should see 2.1.0 as newer.
    assert!(
        sfgw_adopt::inform::is_newer_version(&latest.version, "1.0.0"),
        "2.1.0 must be newer than 1.0.0"
    );

    // A device already on 2.1.0 should NOT see it as newer.
    assert!(
        !sfgw_adopt::inform::is_newer_version(&latest.version, "2.1.0"),
        "2.1.0 must not be newer than itself"
    );

    // A device on 3.0.0 should NOT see 2.1.0 as newer.
    assert!(
        !sfgw_adopt::inform::is_newer_version(&latest.version, "3.0.0"),
        "2.1.0 must not be newer than 3.0.0"
    );
}

#[tokio::test]
async fn firmware_manifest_signature_is_verified_by_ca_public_key() {
    let db = fresh_db().await;
    let ca = GatewayCA::init(&db).await.expect("CA init");

    register_firmware(
        &db,
        &ca,
        "UAP-AC-Pro",
        "3.5.2",
        "cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333",
        8192,
        "https://fw.example.com/uap-3.5.2.bin",
    )
    .await
    .expect("register firmware");

    let row = load_latest_firmware(&db, "UAP-AC-Pro")
        .await
        .expect("load_latest_firmware")
        .expect("firmware row must exist");

    // Decode the stored signature and verify it against the CA public key.
    let sig_bytes = B64.decode(&row.signature).expect("decode signature base64");

    // Reconstruct the canonical payload that was signed.
    let canonical = serde_json::json!({
        "model": row.model,
        "version": row.version,
        "sha256": row.sha256,
        "size_bytes": row.size_bytes,
        "url": row.url,
    });
    let payload_bytes = serde_json::to_vec(&canonical).expect("serialise canonical payload");

    // Verify using ML-DSA-65.
    use fips204::ml_dsa_65;
    use fips204::traits::{SerDes, Verifier};

    let vk_arr: &[u8; ml_dsa_65::PK_LEN] = ca
        .public_key()
        .try_into()
        .expect("CA public key correct length");
    let vk = ml_dsa_65::PublicKey::try_from_bytes(*vk_arr).expect("deserialise CA public key");

    let sig_arr: [u8; ml_dsa_65::SIG_LEN] = sig_bytes
        .as_slice()
        .try_into()
        .expect("signature correct length");

    assert!(
        vk.verify(&payload_bytes, &sig_arr, b""),
        "firmware manifest signature must verify against the gateway CA public key"
    );

    // Tampered payload must NOT verify.
    let tampered = serde_json::json!({
        "model": row.model,
        "version": "9.9.9",
        "sha256": row.sha256,
        "size_bytes": row.size_bytes,
        "url": row.url,
    });
    let tampered_bytes = serde_json::to_vec(&tampered).expect("serialise tampered payload");
    assert!(
        !vk.verify(&tampered_bytes, &sig_arr, b""),
        "tampered firmware manifest must NOT verify"
    );
}
