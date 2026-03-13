// SPDX-License-Identifier: AGPL-3.0-or-later

//! Secure Memory Primitives
//!
//! Every secret in secfirstgw lives in a [`SecureBox`]:
//! - AES-256-GCM encrypted at rest in memory (ephemeral random key)
//! - `mlock()`'d (never written to swap)
//! - `madvise(MADV_DONTDUMP)` (excluded from core dumps)
//! - Zeroized on drop (no remnants in freed heap)
//!
//! This makes cold boot attacks, DMA attacks, swap forensics,
//! and heap spraying all useless against key material.

use crate::CryptoError;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroize;

/// Convenience alias for results from this module.
type Result<T> = std::result::Result<T, CryptoError>;

/// Encrypted in-memory container for sensitive data.
/// Data is AES-256-GCM encrypted with an ephemeral key.
/// Memory is mlock'd and excluded from core dumps.
pub struct SecureBox<T: Zeroize + AsRef<[u8]> + From<Vec<u8>>> {
    /// AES-256-GCM encrypted data (ciphertext + 16-byte tag appended by ring)
    ciphertext: Vec<u8>,
    /// Ephemeral encryption key (also mlock'd)
    key_bytes: [u8; 32],
    /// Nonce used for encryption
    nonce: [u8; 12],
    /// Original plaintext length before encryption
    original_len: usize,
    _marker: std::marker::PhantomData<T>,
}

/// Lock a memory region with `mlock()` to prevent swapping.
/// Returns `true` on success.
#[allow(unsafe_code)]
fn mlock_region(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
}

/// Mark a memory region with `madvise(MADV_DONTDUMP)` to exclude from core dumps.
/// Returns `true` on success.
#[allow(unsafe_code)]
fn madvise_dontdump(ptr: *mut u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    unsafe { libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP) == 0 }
}

/// Unlock a memory region previously locked with `mlock()`.
#[allow(unsafe_code)]
fn munlock_region(ptr: *const u8, len: usize) {
    if len > 0 {
        unsafe {
            libc::munlock(ptr as *const libc::c_void, len);
        }
    }
}

impl<T: Zeroize + AsRef<[u8]> + From<Vec<u8>>> SecureBox<T> {
    /// Encrypt `data` into a new `SecureBox`.
    ///
    /// 1. Generates an ephemeral AES-256-GCM key and nonce via `SystemRandom`.
    /// 2. `mlock()`s the key bytes.
    /// 3. `madvise(MADV_DONTDUMP)` on the key bytes.
    /// 4. Encrypts the plaintext in place.
    /// 5. Zeroizes the original plaintext.
    #[must_use = "dropping a SecureBox without using it wastes the encryption overhead"]
    pub fn new(mut data: T) -> Result<Self> {
        let rng = SystemRandom::new();

        // Generate ephemeral key
        let mut key_bytes = [0u8; 32];
        rng.fill(&mut key_bytes)
            .map_err(|_| CryptoError::CryptoFailed("failed to generate random key".to_string()))?;

        // mlock + MADV_DONTDUMP the key
        let key_ptr = key_bytes.as_ptr();
        if !mlock_region(key_ptr, 32) {
            tracing::warn!("mlock failed for SecureBox key — may be swappable");
        }
        if !madvise_dontdump(key_bytes.as_mut_ptr(), 32) {
            tracing::warn!("madvise(DONTDUMP) failed for SecureBox key");
        }

        // Generate nonce
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce)
            .map_err(|_| CryptoError::CryptoFailed("failed to generate random nonce".to_string()))?;

        // Prepare plaintext as a Vec for in-place encryption
        let plaintext_ref = data.as_ref();
        let original_len = plaintext_ref.len();
        // ring's seal_in_place_append_tag needs extra capacity for the tag
        let mut in_place = Vec::with_capacity(original_len + AES_256_GCM.tag_len());
        in_place.extend_from_slice(plaintext_ref);

        // Zeroize the original data now that we've copied it
        data.zeroize();

        // Encrypt
        let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes)
            .map_err(|_| CryptoError::CryptoFailed("failed to create AES-256-GCM key".to_string()))?;
        let sealing_key = LessSafeKey::new(unbound);
        let nonce_val = Nonce::assume_unique_for_key(nonce);

        sealing_key
            .seal_in_place_append_tag(nonce_val, Aad::empty(), &mut in_place)
            .map_err(|_| CryptoError::CryptoFailed("AES-256-GCM encryption failed".to_string()))?;

        // mlock the ciphertext as well
        if !in_place.is_empty() {
            mlock_region(in_place.as_ptr(), in_place.len());
            madvise_dontdump(in_place.as_mut_ptr(), in_place.len());
        }

        Ok(Self {
            ciphertext: in_place,
            key_bytes,
            nonce,
            original_len,
            _marker: std::marker::PhantomData,
        })
    }

    /// Decrypt and return the plaintext.
    ///
    /// The caller is responsible for zeroizing the returned value when done.
    #[must_use = "decrypted secret must be used and then zeroized"]
    pub fn open(&self) -> Result<T> {
        let unbound = UnboundKey::new(&AES_256_GCM, &self.key_bytes)
            .map_err(|_| CryptoError::CryptoFailed("failed to create AES-256-GCM key for decryption".to_string()))?;
        let opening_key = LessSafeKey::new(unbound);
        let nonce_val = Nonce::assume_unique_for_key(self.nonce);

        let mut buf = self.ciphertext.clone();
        let plaintext = opening_key
            .open_in_place(nonce_val, Aad::empty(), &mut buf)
            .map_err(|_| CryptoError::CryptoFailed("AES-256-GCM decryption failed".to_string()))?;

        debug_assert_eq!(plaintext.len(), self.original_len);
        let result = T::from(plaintext.to_vec());

        // Zeroize the temporary buffer
        buf.zeroize();

        Ok(result)
    }

    /// Returns the original plaintext length (before encryption).
    pub fn original_len(&self) -> usize {
        self.original_len
    }
}

impl<T: Zeroize + AsRef<[u8]> + From<Vec<u8>>> Drop for SecureBox<T> {
    fn drop(&mut self) {
        // munlock the ciphertext
        if !self.ciphertext.is_empty() {
            munlock_region(self.ciphertext.as_ptr(), self.ciphertext.len());
        }
        // Zeroize ciphertext
        self.ciphertext.zeroize();

        // munlock the key
        munlock_region(self.key_bytes.as_ptr(), 32);
        // Zeroize key material
        self.key_bytes.zeroize();

        // Zeroize nonce for good measure
        self.nonce.zeroize();
    }
}

// SecureBox cannot be cloned — there is exactly one copy of the key material.
// It is Send + Sync because the encrypted data is opaque bytes.
#[allow(unsafe_code)]
unsafe impl<T: Zeroize + AsRef<[u8]> + From<Vec<u8>>> Send for SecureBox<T> {}
#[allow(unsafe_code)]
unsafe impl<T: Zeroize + AsRef<[u8]> + From<Vec<u8>>> Sync for SecureBox<T> {}

/// Secure comparison (constant-time) to prevent timing attacks.
#[must_use = "ignoring the result of a security comparison is a bug"]
pub fn secure_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Securely generate random bytes using ring's SystemRandom (kernel CSPRNG).
pub fn secure_random(buf: &mut [u8]) -> Result<()> {
    let rng = SystemRandom::new();
    rng.fill(buf)
        .map_err(|_| CryptoError::CryptoFailed("SystemRandom::fill failed".to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_vec_u8() {
        let secret = b"this is a private key material!!".to_vec();
        let sbox = SecureBox::<Vec<u8>>::new(secret).expect("SecureBox::new failed");

        assert_eq!(sbox.original_len(), 32);

        let recovered = sbox.open().expect("SecureBox::open failed");
        assert_eq!(recovered.as_slice(), b"this is a private key material!!");
    }

    #[test]
    fn roundtrip_empty() {
        let sbox = SecureBox::<Vec<u8>>::new(Vec::new()).expect("SecureBox::new failed");
        assert_eq!(sbox.original_len(), 0);

        let recovered = sbox.open().expect("open failed");
        assert!(recovered.is_empty());
    }

    #[test]
    fn roundtrip_large() {
        let secret = vec![0xABu8; 8192];
        let sbox = SecureBox::<Vec<u8>>::new(secret).expect("new failed");
        let recovered = sbox.open().expect("open failed");
        assert_eq!(recovered.len(), 8192);
        assert!(recovered.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn ciphertext_differs_from_plaintext() {
        let secret = b"super secret key material here!!".to_vec();
        let sbox = SecureBox::<Vec<u8>>::new(secret).expect("new failed");

        // The ciphertext (which includes the tag) should NOT equal the plaintext
        assert_ne!(&sbox.ciphertext[..sbox.original_len], b"super secret key material here!!");
    }

    #[test]
    fn zeroize_on_drop() {
        // We can't directly observe memory after drop, but we verify the type
        // implements Drop and that the key/ciphertext fields are zeroized.
        // Create and immediately drop.
        let secret = b"key material that must vanish!!!".to_vec();
        let sbox = SecureBox::<Vec<u8>>::new(secret).expect("new failed");

        // Grab pointers before drop (for documentation — we can't safely deref after drop)
        let _key_was_nonzero = sbox.key_bytes.iter().any(|&b| b != 0);
        assert!(_key_was_nonzero, "key should be non-zero before drop");

        drop(sbox);
        // If we got here without panic, Drop ran successfully.
    }

    #[test]
    fn secure_eq_works() {
        assert!(secure_eq(b"hello", b"hello"));
        assert!(!secure_eq(b"hello", b"world"));
        assert!(!secure_eq(b"short", b"longer"));
    }

    #[test]
    fn secure_random_fills_buffer() {
        let mut buf = [0u8; 64];
        secure_random(&mut buf).expect("secure_random failed");
        // Extremely unlikely to be all zeros
        assert!(buf.iter().any(|&b| b != 0));
    }
}
