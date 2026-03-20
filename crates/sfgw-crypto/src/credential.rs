// SPDX-License-Identifier: AGPL-3.0-or-later

//! Application-level credential encryption for secrets stored in the DB.
//!
//! Even though the database is encrypted with SQLCipher, SSH passwords get
//! an additional layer of AES-256-GCM encryption at the application level.
//! This provides defense-in-depth: if an attacker bypasses SQLCipher
//! (memory dump, key extraction), individual credentials remain encrypted
//! with a separate hardware-derived key.
//!
//! ## Format
//!
//! Encrypted credentials are stored as base64-encoded blobs:
//! `base64(nonce || ciphertext || tag)` where nonce is 12 bytes and tag is 16 bytes.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroize;

use crate::{CryptoError, HkdfLen};

/// HKDF salt for credential encryption key derivation (domain separator).
const CREDENTIAL_KEY_SALT: &[u8] = b"sfgw-credential-encryption-v1";

/// HKDF info context for credential encryption.
const CREDENTIAL_KEY_INFO: &[u8] = b"ssh-credential-encryption-key";

/// Prefix for encrypted credential values (distinguishes from plaintext).
const ENCRYPTED_PREFIX: &str = "enc:";

/// Derive a 32-byte credential encryption key from hardware fingerprints.
///
/// Uses the same hardware identity as the DB key but with a different
/// HKDF salt and info, producing an independent key.
pub fn derive_credential_key() -> Result<CredentialKey, CryptoError> {
    let mut ikm = crate::db_key::collect_hardware_fingerprint_for_credential()?;

    if ikm.len() < 16 {
        return Err(CryptoError::CryptoFailed(
            "insufficient hardware fingerprint for credential key".to_string(),
        ));
    }

    let mut key = [0u8; 32];

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, CREDENTIAL_KEY_SALT);
    let prk = salt.extract(&ikm);
    let info_refs = [CREDENTIAL_KEY_INFO];
    let okm = prk.expand(&info_refs, HkdfLen(32)).map_err(|_| {
        CryptoError::CryptoFailed("HKDF expand failed for credential key".to_string())
    })?;
    okm.fill(&mut key).map_err(|_| {
        CryptoError::CryptoFailed("HKDF fill failed for credential key".to_string())
    })?;

    ikm.zeroize();

    Ok(CredentialKey { key })
}

/// A 32-byte credential encryption key that zeroizes on drop.
pub struct CredentialKey {
    key: [u8; 32],
}

impl Drop for CredentialKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl CredentialKey {
    /// Encrypt a plaintext credential, returning a base64-encoded string
    /// prefixed with `enc:`.
    ///
    /// Format: `enc:base64(nonce[12] || ciphertext || tag[16])`
    pub fn encrypt(&self, plaintext: &str) -> Result<String, CryptoError> {
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| CryptoError::CryptoFailed("failed to generate nonce".to_string()))?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key)
            .map_err(|_| CryptoError::CryptoFailed("failed to create AES key".to_string()))?;
        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.as_bytes().to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::CryptoFailed("AES-GCM seal failed".to_string()))?;

        // Prepend nonce to ciphertext+tag
        let mut blob = Vec::with_capacity(12 + in_out.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&in_out);

        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&blob);
        Ok(format!("{ENCRYPTED_PREFIX}{encoded}"))
    }

    /// Decrypt a credential string. Accepts both encrypted (`enc:...`) and
    /// plaintext values (for migration from unencrypted storage).
    ///
    /// If the value is plaintext (no `enc:` prefix), returns it unchanged.
    /// This enables transparent migration: old plaintext values work until
    /// re-encrypted on next write.
    pub fn decrypt(&self, value: &str) -> Result<String, CryptoError> {
        let encoded = match value.strip_prefix(ENCRYPTED_PREFIX) {
            Some(e) => e,
            None => return Ok(value.to_string()), // Plaintext (migration)
        };

        use base64::Engine;
        let blob = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| CryptoError::CryptoFailed(format!("base64 decode failed: {e}")))?;

        if blob.len() < 12 + 16 {
            return Err(CryptoError::CryptoFailed(
                "encrypted credential too short".to_string(),
            ));
        }

        let (nonce_bytes, ciphertext_and_tag) = blob.split_at(12);
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce_bytes);

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key)
            .map_err(|_| CryptoError::CryptoFailed("failed to create AES key".to_string()))?;
        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(nonce_arr);

        let mut in_out = ciphertext_and_tag.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| {
                CryptoError::CryptoFailed(
                    "AES-GCM decrypt failed (wrong key or tampered)".to_string(),
                )
            })?;

        String::from_utf8(plaintext.to_vec()).map_err(|_| {
            CryptoError::CryptoFailed("decrypted credential is not valid UTF-8".to_string())
        })
    }

    /// Check whether a value is already encrypted.
    pub fn is_encrypted(value: &str) -> bool {
        value.starts_with(ENCRYPTED_PREFIX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_credential_key().expect("key derivation should succeed");
        let plaintext = "s3cur3-p@ssw0rd!";
        let encrypted = key.encrypt(plaintext).expect("encrypt should succeed");

        assert!(encrypted.starts_with("enc:"), "must have enc: prefix");
        assert_ne!(encrypted, plaintext, "encrypted must differ from plaintext");

        let decrypted = key.decrypt(&encrypted).expect("decrypt should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_plaintext_passthrough() {
        let key = derive_credential_key().expect("key derivation should succeed");
        let plaintext = "legacy-unencrypted-password";
        let result = key
            .decrypt(plaintext)
            .expect("plaintext passthrough should succeed");
        assert_eq!(result, plaintext);
    }

    #[test]
    fn different_encryptions_produce_different_ciphertexts() {
        let key = derive_credential_key().expect("key derivation should succeed");
        let plaintext = "same-password";
        let enc1 = key.encrypt(plaintext).unwrap();
        let enc2 = key.encrypt(plaintext).unwrap();
        assert_ne!(
            enc1, enc2,
            "random nonces should produce different ciphertexts"
        );

        // Both should decrypt to the same value
        assert_eq!(key.decrypt(&enc1).unwrap(), plaintext);
        assert_eq!(key.decrypt(&enc2).unwrap(), plaintext);
    }

    #[test]
    fn is_encrypted_detection() {
        assert!(CredentialKey::is_encrypted("enc:AAAA"));
        assert!(!CredentialKey::is_encrypted("plaintext-password"));
    }
}
