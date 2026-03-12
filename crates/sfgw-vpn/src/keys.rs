// SPDX-License-Identifier: AGPL-3.0-or-later

//! WireGuard key management.
//!
//! Generates Curve25519 keypairs and preshared keys.
//! Private keys are base64-encoded for DB storage.
//! TODO: Wrap private keys in SecureBox for encrypted in-memory storage.

use anyhow::Result;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

/// A WireGuard keypair (private + public).
pub struct WgKeypair {
    /// Base64-encoded private key. NEVER log or return in API responses.
    pub private_key: String,
    /// Base64-encoded public key. Safe to share with peers.
    pub public_key: String,
}

/// Generate a new WireGuard Curve25519 keypair.
pub fn generate_keypair() -> WgKeypair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    WgKeypair {
        private_key: BASE64.encode(secret.to_bytes()),
        public_key: BASE64.encode(public.as_bytes()),
    }
}

/// Derive the public key from a base64-encoded private key.
pub fn public_key_from_private(private_key_b64: &str) -> Result<String> {
    let private_bytes: [u8; 32] = BASE64
        .decode(private_key_b64)?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("invalid private key length: {}", v.len()))?;

    let secret = StaticSecret::from(private_bytes);
    let public = PublicKey::from(&secret);
    Ok(BASE64.encode(public.as_bytes()))
}

/// Generate a random 256-bit preshared key (base64-encoded).
/// Used for additional quantum-resistance layer between peers.
pub fn generate_preshared_key() -> String {
    let mut key = [0u8; 32];
    // OsRng implements CryptoRng — suitable for key material
    use rand::RngCore;
    OsRng.fill_bytes(&mut key);
    BASE64.encode(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrip() {
        let kp = generate_keypair();
        let derived_pub = public_key_from_private(&kp.private_key).unwrap();
        assert_eq!(kp.public_key, derived_pub);
    }

    #[test]
    fn preshared_key_length() {
        let psk = generate_preshared_key();
        let decoded = BASE64.decode(&psk).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn keypairs_are_unique() {
        let a = generate_keypair();
        let b = generate_keypair();
        assert_ne!(a.private_key, b.private_key);
        assert_ne!(a.public_key, b.public_key);
    }
}
