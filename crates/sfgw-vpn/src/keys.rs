// SPDX-License-Identifier: AGPL-3.0-or-later

//! WireGuard key management.
//!
//! Generates Curve25519 keypairs and preshared keys.
//! Private keys are wrapped in `SecureBox<Vec<u8>>` for encrypted in-memory
//! storage. They are only unwrapped (decrypted) when needed — e.g. to write
//! a WireGuard config file or pass to `wg set`.

use anyhow::Result;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::rngs::OsRng;
use sfgw_crypto::secure_mem::SecureBox;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// A WireGuard keypair (private + public).
///
/// The private key is encrypted in memory via `SecureBox`.
/// It cannot be cloned — move semantics only.
pub struct WgKeypair {
    /// Private key bytes (raw 32-byte Curve25519 scalar) in a SecureBox.
    /// NEVER log or return in API responses.
    pub private_key: SecureBox<Vec<u8>>,
    /// Base64-encoded public key. Safe to share with peers.
    pub public_key: String,
}

/// Generate a new WireGuard Curve25519 keypair.
///
/// The private key is immediately wrapped in a `SecureBox` and the
/// plaintext is zeroized. Only the public key is kept as a plain string.
#[must_use = "generated keypair contains private key material that must not be discarded"]
pub fn generate_keypair() -> Result<WgKeypair> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    let private_bytes = secret.to_bytes().to_vec();
    let secure_private = SecureBox::new(private_bytes)?;
    // private_bytes was moved into SecureBox::new which zeroizes the input

    Ok(WgKeypair {
        private_key: secure_private,
        public_key: BASE64.encode(public.as_bytes()),
    })
}

/// Wrap a base64-encoded private key string into a `SecureBox<Vec<u8>>`.
///
/// Decodes the base64, validates length (32 bytes for Curve25519),
/// wraps in SecureBox, and zeroizes intermediaries.
pub fn wrap_private_key(private_key_b64: &str) -> Result<SecureBox<Vec<u8>>> {
    let mut raw = BASE64
        .decode(private_key_b64)
        .map_err(|e| anyhow::anyhow!("invalid base64 private key: {e}"))?;

    if raw.len() != 32 {
        raw.zeroize();
        anyhow::bail!("invalid private key length: {} (expected 32)", raw.len());
    }

    let sbox = SecureBox::new(raw)?;
    // raw was moved into SecureBox::new which zeroizes the input
    Ok(sbox)
}

/// Temporarily open a SecureBox private key and return its base64 encoding.
///
/// The caller should use the returned string immediately and let it drop.
/// The intermediate plaintext is zeroized after encoding.
pub fn private_key_to_base64(sbox: &SecureBox<Vec<u8>>) -> Result<String> {
    let mut plaintext = sbox.open()?;
    let encoded = BASE64.encode(&plaintext);
    plaintext.zeroize();
    Ok(encoded)
}

/// Derive the public key from a SecureBox-wrapped private key.
pub fn public_key_from_secure(sbox: &SecureBox<Vec<u8>>) -> Result<String> {
    let mut private_bytes = sbox.open()?;
    let arr: [u8; 32] = private_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid private key length: {}", private_bytes.len()))?;

    let secret = StaticSecret::from(arr);
    let public = PublicKey::from(&secret);
    let result = BASE64.encode(public.as_bytes());

    private_bytes.zeroize();
    Ok(result)
}

/// Derive the public key from a base64-encoded private key.
pub fn public_key_from_private(private_key_b64: &str) -> Result<String> {
    let mut private_bytes: [u8; 32] = BASE64
        .decode(private_key_b64)?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("invalid private key length: {}", v.len()))?;

    let secret = StaticSecret::from(private_bytes);
    let public = PublicKey::from(&secret);
    let result = BASE64.encode(public.as_bytes());

    private_bytes.zeroize();
    Ok(result)
}

/// Generate a random 256-bit preshared key (base64-encoded).
/// Used for additional quantum-resistance layer between peers.
#[must_use = "generated preshared key must not be discarded"]
pub fn generate_preshared_key() -> String {
    let mut key = [0u8; 32];
    // OsRng implements CryptoRng — suitable for key material
    use rand::RngCore;
    OsRng.fill_bytes(&mut key);
    let encoded = BASE64.encode(key);
    key.zeroize();
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrip() {
        let kp = generate_keypair().unwrap();
        // Open the private key, derive public, compare
        let derived_pub = public_key_from_secure(&kp.private_key).unwrap();
        assert_eq!(kp.public_key, derived_pub);
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let kp = generate_keypair().unwrap();
        let b64 = private_key_to_base64(&kp.private_key).unwrap();

        // Re-wrap the base64 key
        let rewrapped = wrap_private_key(&b64).unwrap();
        let derived = public_key_from_secure(&rewrapped).unwrap();
        assert_eq!(kp.public_key, derived);
    }

    #[test]
    fn preshared_key_length() {
        let psk = generate_preshared_key();
        let decoded = BASE64.decode(&psk).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn keypairs_are_unique() {
        let a = generate_keypair().unwrap();
        let b = generate_keypair().unwrap();
        let a_b64 = private_key_to_base64(&a.private_key).unwrap();
        let b_b64 = private_key_to_base64(&b.private_key).unwrap();
        assert_ne!(a_b64, b_b64);
        assert_ne!(a.public_key, b.public_key);
    }

    #[test]
    fn wrap_rejects_wrong_length() {
        let short_b64 = BASE64.encode(vec![0u8; 16]);
        assert!(wrap_private_key(&short_b64).is_err());
    }
}
