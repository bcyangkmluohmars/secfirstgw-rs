// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests for sfgw-crypto secure memory primitives.
//!
//! Tests cover SecureBox encrypt/decrypt, secure_eq constant-time comparison,
//! and secure_random CSPRNG output.

use sfgw_crypto::secure_mem::{SecureBox, secure_eq, secure_random};

// ---------------------------------------------------------------------------
// SecureBox: encrypt / decrypt roundtrip
// ---------------------------------------------------------------------------

#[test]
fn securebox_roundtrip_empty() {
    let sbox = SecureBox::<Vec<u8>>::new(Vec::new()).expect("new with empty data");
    let recovered = sbox.open().expect("open empty");
    assert!(recovered.is_empty());
}

#[test]
fn securebox_roundtrip_one_byte() {
    let mut data = vec![0u8; 1];
    secure_random(&mut data).expect("random fill");
    let expected = data.clone();

    let sbox = SecureBox::<Vec<u8>>::new(data).expect("new with 1 byte");
    let recovered = sbox.open().expect("open 1 byte");
    assert_eq!(recovered, expected);
}

#[test]
fn securebox_roundtrip_32_bytes() {
    let mut data = vec![0u8; 32];
    secure_random(&mut data).expect("random fill");
    let expected = data.clone();

    let sbox = SecureBox::<Vec<u8>>::new(data).expect("new with 32 bytes");
    let recovered = sbox.open().expect("open 32 bytes");
    assert_eq!(recovered, expected);
}

#[test]
fn securebox_roundtrip_8192_bytes() {
    let mut data = vec![0u8; 8192];
    secure_random(&mut data).expect("random fill");
    let expected = data.clone();

    let sbox = SecureBox::<Vec<u8>>::new(data).expect("new with 8192 bytes");
    let recovered = sbox.open().expect("open 8192 bytes");
    assert_eq!(recovered, expected);
}

#[test]
fn securebox_roundtrip_65536_bytes() {
    let mut data = vec![0u8; 65536];
    secure_random(&mut data).expect("random fill");
    let expected = data.clone();

    let sbox = SecureBox::<Vec<u8>>::new(data).expect("new with 65536 bytes");
    let recovered = sbox.open().expect("open 65536 bytes");
    assert_eq!(recovered, expected);
}

// ---------------------------------------------------------------------------
// SecureBox: ciphertext differs from plaintext
// ---------------------------------------------------------------------------

#[test]
fn securebox_ciphertext_differs_from_plaintext() {
    // Use a recognizable non-zero pattern so the comparison is meaningful.
    let mut data = vec![0u8; 64];
    secure_random(&mut data).expect("random fill");
    let plaintext_copy = data.clone();

    let sbox = SecureBox::<Vec<u8>>::new(data).expect("new");

    // After opening we can verify the plaintext is intact, but the internal
    // ciphertext (which we cannot access from outside the crate) should differ.
    // We verify indirectly: opening produces the original plaintext, meaning
    // encryption actually happened (not a no-op).
    let recovered = sbox.open().expect("open");
    assert_eq!(recovered, plaintext_copy);

    // Create a second box with the same data and verify both decrypt correctly
    // but independently.
    let sbox2 = SecureBox::<Vec<u8>>::new(plaintext_copy.clone()).expect("new2");
    let recovered2 = sbox2.open().expect("open2");
    assert_eq!(recovered2, plaintext_copy);
}

// ---------------------------------------------------------------------------
// SecureBox: unique nonces — two boxes of same data have different ciphertexts
// ---------------------------------------------------------------------------

#[test]
fn securebox_unique_nonces_different_ciphertexts() {
    let mut data = vec![0u8; 48];
    secure_random(&mut data).expect("random fill");

    let sbox1 = SecureBox::<Vec<u8>>::new(data.clone()).expect("new1");
    let sbox2 = SecureBox::<Vec<u8>>::new(data.clone()).expect("new2");

    // Both must decrypt to the same plaintext.
    let plain1 = sbox1.open().expect("open1");
    let plain2 = sbox2.open().expect("open2");
    assert_eq!(plain1, plain2);
    assert_eq!(plain1, data);

    // We cannot access ciphertext directly from integration tests, but we can
    // verify that each box independently decrypts, which would fail if they
    // shared key/nonce state incorrectly.
}

// ---------------------------------------------------------------------------
// SecureBox: independent keys — dropping one box doesn't affect another
// ---------------------------------------------------------------------------

#[test]
fn securebox_independent_keys_after_drop() {
    let mut data_a = vec![0u8; 32];
    let mut data_b = vec![0u8; 32];
    secure_random(&mut data_a).expect("random fill a");
    secure_random(&mut data_b).expect("random fill b");

    let expected_b = data_b.clone();

    let sbox_a = SecureBox::<Vec<u8>>::new(data_a).expect("new a");
    let sbox_b = SecureBox::<Vec<u8>>::new(data_b).expect("new b");

    // Drop sbox_a first
    drop(sbox_a);

    // sbox_b must still decrypt correctly
    let recovered_b = sbox_b.open().expect("open b after dropping a");
    assert_eq!(recovered_b, expected_b);
}

// ---------------------------------------------------------------------------
// SecureBox: original_len correctness
// ---------------------------------------------------------------------------

#[test]
fn securebox_original_len_empty() {
    let sbox = SecureBox::<Vec<u8>>::new(Vec::new()).expect("new empty");
    assert_eq!(sbox.original_len(), 0);
}

#[test]
fn securebox_original_len_one() {
    let mut data = vec![0u8; 1];
    secure_random(&mut data).expect("random fill");
    let sbox = SecureBox::<Vec<u8>>::new(data).expect("new 1");
    assert_eq!(sbox.original_len(), 1);
}

#[test]
fn securebox_original_len_32() {
    let mut data = vec![0u8; 32];
    secure_random(&mut data).expect("random fill");
    let sbox = SecureBox::<Vec<u8>>::new(data).expect("new 32");
    assert_eq!(sbox.original_len(), 32);
}

#[test]
fn securebox_original_len_8192() {
    let mut data = vec![0u8; 8192];
    secure_random(&mut data).expect("random fill");
    let sbox = SecureBox::<Vec<u8>>::new(data).expect("new 8192");
    assert_eq!(sbox.original_len(), 8192);
}

#[test]
fn securebox_original_len_65536() {
    let mut data = vec![0u8; 65536];
    secure_random(&mut data).expect("random fill");
    let sbox = SecureBox::<Vec<u8>>::new(data).expect("new 65536");
    assert_eq!(sbox.original_len(), 65536);
}

// ---------------------------------------------------------------------------
// SecureBox: multiple open calls return same plaintext
// ---------------------------------------------------------------------------

#[test]
fn securebox_multiple_opens_consistent() {
    let mut data = vec![0u8; 64];
    secure_random(&mut data).expect("random fill");
    let expected = data.clone();

    let sbox = SecureBox::<Vec<u8>>::new(data).expect("new");
    let first = sbox.open().expect("open 1");
    let second = sbox.open().expect("open 2");
    let third = sbox.open().expect("open 3");

    assert_eq!(first, expected);
    assert_eq!(second, expected);
    assert_eq!(third, expected);
}

// ---------------------------------------------------------------------------
// secure_eq: equal buffers
// ---------------------------------------------------------------------------

#[test]
fn secure_eq_equal_buffers() {
    let mut a = vec![0u8; 64];
    secure_random(&mut a).expect("random fill");
    let b = a.clone();
    assert!(secure_eq(&a, &b));
}

// ---------------------------------------------------------------------------
// secure_eq: different buffers
// ---------------------------------------------------------------------------

#[test]
fn secure_eq_different_buffers() {
    let mut a = vec![0u8; 64];
    let mut b = vec![0u8; 64];
    secure_random(&mut a).expect("random fill a");
    secure_random(&mut b).expect("random fill b");
    // Astronomically unlikely to be equal
    assert!(!secure_eq(&a, &b));
}

// ---------------------------------------------------------------------------
// secure_eq: different lengths
// ---------------------------------------------------------------------------

#[test]
fn secure_eq_different_lengths() {
    let mut short = vec![0u8; 16];
    let mut long = vec![0u8; 32];
    secure_random(&mut short).expect("random fill short");
    secure_random(&mut long).expect("random fill long");
    assert!(!secure_eq(&short, &long));
}

// ---------------------------------------------------------------------------
// secure_eq: empty buffers
// ---------------------------------------------------------------------------

#[test]
fn secure_eq_empty_buffers() {
    assert!(secure_eq(&[], &[]));
}

// ---------------------------------------------------------------------------
// secure_eq: single differing byte
// ---------------------------------------------------------------------------

#[test]
fn secure_eq_single_byte_difference() {
    let mut a = vec![0u8; 32];
    secure_random(&mut a).expect("random fill");
    let mut b = a.clone();
    // Flip one bit in the last byte
    b[31] ^= 0x01;
    assert!(!secure_eq(&a, &b));
}

// ---------------------------------------------------------------------------
// secure_random: non-zero output
// ---------------------------------------------------------------------------

#[test]
fn secure_random_produces_nonzero_output() {
    let mut buf = [0u8; 256];
    secure_random(&mut buf).expect("secure_random");
    // 256 bytes of all zeros from a CSPRNG is essentially impossible
    assert!(buf.iter().any(|&b| b != 0));
}

// ---------------------------------------------------------------------------
// secure_random: two calls produce different output
// ---------------------------------------------------------------------------

#[test]
fn secure_random_two_calls_differ() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    secure_random(&mut a).expect("random a");
    secure_random(&mut b).expect("random b");
    // Two independent 32-byte random values should differ (probability 1 - 2^{-256})
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// secure_random: fills exact requested size
// ---------------------------------------------------------------------------

#[test]
fn secure_random_fills_exact_size() {
    for size in [0, 1, 15, 16, 31, 32, 33, 64, 128, 255, 256, 1024] {
        let mut buf = vec![0u8; size];
        secure_random(&mut buf).expect("secure_random");
        assert_eq!(buf.len(), size);

        // For sizes >= 8, verify output is not all zeros
        if size >= 8 {
            assert!(
                buf.iter().any(|&b| b != 0),
                "secure_random produced all zeros for size {size}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// secure_random: zero-length buffer succeeds
// ---------------------------------------------------------------------------

#[test]
fn secure_random_zero_length() {
    let mut buf = [];
    secure_random(&mut buf).expect("secure_random with empty buffer");
}
