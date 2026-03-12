// SPDX-License-Identifier: AGPL-3.0-or-later

//! E2EE middleware layer for the entire API.
//!
//! Architecture:
//! 1. `/api/v1/auth/negotiate` — X25519 key exchange, returns negotiate_id + server pubkey
//! 2. `/api/v1/auth/login` — credentials encrypted with negotiate key (one-shot)
//!    Response includes an envelope_key encrypted with the negotiate key.
//! 3. All subsequent authenticated requests: body encrypted/decrypted with envelope_key
//!    via transparent axum middleware. Header `X-SFGW-E2EE: true` signals encryption.
//!
//! Body format (encrypted): `{ "iv": "base64", "data": "base64" }`
//! The actual JSON body is inside `data` after AES-256-GCM decryption.

use axum::{
    body::{Body, Bytes},
    http::{Request, Response, StatusCode, header},
    middleware::Next,
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use http_body_util::BodyExt;
use ring::{
    aead,
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519},
    hkdf,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use uuid::Uuid;

const NEGOTIATE_TTL_SECS: u64 = 120;
const HKDF_INFO: &[u8] = b"sfgw-e2ee-v1";

// ---------------------------------------------------------------------------
// Negotiate store (short-lived key exchange sessions)
// ---------------------------------------------------------------------------

struct NegotiateEntry {
    aes_key: [u8; 32],
    created_at: Instant,
}

#[derive(Clone)]
pub struct NegotiateStore(Arc<Mutex<HashMap<String, NegotiateEntry>>>);

pub fn new_negotiate_store() -> NegotiateStore {
    NegotiateStore(Arc::new(Mutex::new(HashMap::new())))
}

/// Perform the server side of the X25519 key exchange.
/// Returns `(negotiate_id, server_public_key_bytes)`.
pub async fn negotiate(
    store: &NegotiateStore,
    client_public_key: &[u8],
) -> Result<(String, Vec<u8>), &'static str> {
    if client_public_key.len() != 32 {
        return Err("client public key must be 32 bytes");
    }

    let rng = SystemRandom::new();

    let server_private = EphemeralPrivateKey::generate(&X25519, &rng)
        .map_err(|_| "failed to generate server keypair")?;
    let server_public = server_private
        .compute_public_key()
        .map_err(|_| "failed to compute server public key")?;
    let server_public_bytes = server_public.as_ref().to_vec();

    let peer_public = UnparsedPublicKey::new(&X25519, client_public_key);
    let shared_secret = agreement::agree_ephemeral(server_private, &peer_public, |secret| {
        secret.to_vec()
    })
    .map_err(|_| "ECDH key agreement failed")?;

    let aes_key = derive_aes_key(&shared_secret)?;
    let negotiate_id = Uuid::new_v4().to_string();

    let mut store = store.0.lock().await;
    // Purge expired
    store.retain(|_, entry| entry.created_at.elapsed().as_secs() < NEGOTIATE_TTL_SECS);
    store.insert(
        negotiate_id.clone(),
        NegotiateEntry {
            aes_key,
            created_at: Instant::now(),
        },
    );

    Ok((negotiate_id, server_public_bytes))
}

/// Consume a negotiate entry and return its AES key.
pub async fn take_negotiate_key(
    store: &NegotiateStore,
    negotiate_id: &str,
) -> Result<[u8; 32], &'static str> {
    let mut store = store.0.lock().await;
    let entry = store
        .remove(negotiate_id)
        .ok_or("negotiate session not found or expired")?;
    if entry.created_at.elapsed().as_secs() >= NEGOTIATE_TTL_SECS {
        return Err("negotiate session expired");
    }
    Ok(entry.aes_key)
}

// ---------------------------------------------------------------------------
// AES-256-GCM encrypt / decrypt
// ---------------------------------------------------------------------------

/// Encrypt plaintext with AES-256-GCM. Returns (ciphertext_with_tag, iv).
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12]), &'static str> {
    let rng = SystemRandom::new();
    let mut iv = [0u8; 12];
    rng.fill(&mut iv)
        .map_err(|_| "failed to generate IV")?;

    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| "failed to create AES key")?;
    let sealing_key = aead::LessSafeKey::new(unbound);

    let mut in_out = plaintext.to_vec();
    let nonce = aead::Nonce::try_assume_unique_for_key(&iv)
        .map_err(|_| "invalid nonce")?;
    sealing_key
        .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| "encryption failed")?;

    Ok((in_out, iv))
}

/// Decrypt ciphertext with AES-256-GCM. Returns plaintext.
pub fn decrypt(
    key: &[u8; 32],
    ciphertext: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if iv.len() != 12 {
        return Err("IV must be 12 bytes");
    }

    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| "failed to create AES key")?;
    let opening_key = aead::LessSafeKey::new(unbound);

    let mut in_out = ciphertext.to_vec();
    let nonce = aead::Nonce::try_assume_unique_for_key(iv)
        .map_err(|_| "invalid nonce")?;
    let plaintext = opening_key
        .open_in_place(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| "decryption failed")?;

    Ok(plaintext.to_vec())
}

/// Generate a random 32-byte envelope key.
pub fn generate_envelope_key() -> Result<[u8; 32], &'static str> {
    let rng = SystemRandom::new();
    let mut key = [0u8; 32];
    rng.fill(&mut key).map_err(|_| "failed to generate random key")?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// E2EE envelope format
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct Envelope {
    pub iv: String,   // base64
    pub data: String,  // base64
}

impl Envelope {
    pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Self, &'static str> {
        let (ct, iv) = encrypt(key, plaintext)?;
        Ok(Self {
            iv: B64.encode(iv),
            data: B64.encode(ct),
        })
    }

    pub fn open(&self, key: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
        let ct = B64.decode(&self.data).map_err(|_| "invalid base64 in data")?;
        let iv = B64.decode(&self.iv).map_err(|_| "invalid base64 in iv")?;
        decrypt(key, &ct, &iv)
    }
}

// ---------------------------------------------------------------------------
// Axum E2EE middleware
// ---------------------------------------------------------------------------

/// Transparent E2EE middleware for all API requests.
///
/// When `X-SFGW-E2EE: true` is present:
/// - Decrypts request body using the session's envelope_key
/// - Encrypts response body before sending back
///
/// Headers are NOT encrypted (TLS handles transport security).
pub async fn e2ee_layer(request: Request<Body>, next: Next) -> Response<Body> {
    let is_e2ee = request
        .headers()
        .get("x-sfgw-e2ee")
        .is_some_and(|v| v == "true");

    if !is_e2ee {
        return next.run(request).await;
    }

    // Extract bearer token
    let token = match request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
    {
        Some(t) if !t.is_empty() => t,
        _ => {
            return (StatusCode::BAD_REQUEST, "E2EE requires Authorization header")
                .into_response();
        }
    };

    // Look up envelope key from session via DB
    let db = match request.extensions().get::<sfgw_db::Db>().cloned() {
        Some(db) => db,
        None => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "db not available")
                .into_response();
        }
    };

    let envelope_key = {
        let conn = db.lock().await;
        match conn.query_row(
            "SELECT envelope_key FROM sessions WHERE token = ?1",
            rusqlite::params![token],
            |row| row.get::<_, String>(0),
        ) {
            Ok(key_b64) if !key_b64.is_empty() => {
                match B64.decode(&key_b64) {
                    Ok(k) if k.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&k);
                        arr
                    }
                    _ => {
                        return (StatusCode::INTERNAL_SERVER_ERROR, "corrupted envelope key")
                            .into_response();
                    }
                }
            }
            Ok(_) => {
                // No envelope key for this session — E2EE not set up
                return (StatusCode::BAD_REQUEST, "session has no E2EE envelope key")
                    .into_response();
            }
            Err(_) => {
                return (StatusCode::UNAUTHORIZED, "invalid session").into_response();
            }
        }
    };

    // Decrypt request body (if present)
    let (parts, body) = request.into_parts();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "failed to read body").into_response();
        }
    };

    let decrypted_body = if body_bytes.is_empty() {
        Bytes::new()
    } else {
        let envelope: Envelope = match serde_json::from_slice(&body_bytes) {
            Ok(e) => e,
            Err(_) => {
                return (StatusCode::BAD_REQUEST, "E2EE body must be {iv, data}")
                    .into_response();
            }
        };
        match envelope.open(&envelope_key) {
            Ok(pt) => Bytes::from(pt),
            Err(e) => {
                tracing::warn!("E2EE request decrypt failed: {e}");
                return (StatusCode::BAD_REQUEST, "E2EE decryption failed").into_response();
            }
        }
    };

    // Rebuild request with decrypted body
    let new_request = Request::from_parts(parts, Body::from(decrypted_body));

    // Run the actual handler
    let response = next.run(new_request).await;

    // Encrypt response body
    let (resp_parts, resp_body) = response.into_parts();
    let resp_bytes = match resp_body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "failed to read response").into_response(),
    };

    if resp_bytes.is_empty() {
        return Response::from_parts(resp_parts, Body::empty());
    }

    match Envelope::seal(&envelope_key, &resp_bytes) {
        Ok(envelope) => {
            let encrypted = serde_json::to_vec(&envelope).unwrap_or_default();
            let mut response = Response::new(Body::from(encrypted));
            *response.status_mut() = resp_parts.status;
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                "application/json".parse().unwrap(),
            );
            response.headers_mut().insert(
                "x-sfgw-e2ee",
                "true".parse().unwrap(),
            );
            response
        }
        Err(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "failed to encrypt response").into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn derive_aes_key(shared_secret: &[u8]) -> Result<[u8; 32], &'static str> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(shared_secret);
    let okm = prk
        .expand(&[HKDF_INFO], AesKeyType)
        .map_err(|_| "HKDF expand failed")?;
    let mut key = [0u8; 32];
    okm.fill(&mut key).map_err(|_| "HKDF fill failed")?;
    Ok(key)
}

struct AesKeyType;

impl hkdf::KeyType for AesKeyType {
    fn len(&self) -> usize {
        32
    }
}
