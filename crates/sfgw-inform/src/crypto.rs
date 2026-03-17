// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ubiquiti Inform encryption — AES-128-CBC and AES-128-GCM.
//!
//! **INTEROP CODE**: This module uses AES-128-CBC and MD5, which are weaker
//! than the project's standard (AES-256-GCM, no MD5). This is required for
//! compatibility with stock UniFi firmware. All usage is isolated here.
//!
//! - Unadopted devices: AES-128-CBC with key = MD5("ubnt")
//! - Adopted devices:   AES-128-GCM with per-device authkey (16 bytes)
//!
//! GCM mode uses the 40-byte TNBU header as Additional Authenticated Data.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{AesGcm, KeyInit};
use aes_gcm::aes::Aes128;

/// AES-128-GCM with 16-byte nonce (UniFi uses full 16-byte IV as GCM nonce,
/// matching Java's GCMParameterSpec(128, iv)).
type Aes128Gcm16 = AesGcm<Aes128, typenum::U16, typenum::U16>;
use anyhow::{Context, Result, bail};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use md5::{Digest, Md5};

use crate::packet::TnbuPacket;

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

/// The well-known default encryption key for unadopted devices.
///
/// Derived as `MD5("ubnt")` = `ba86f2bbe107c7c57eb5f2690775c712`.
/// This is public knowledge — it provides no real security, only
/// protocol framing. INTEROP ONLY.
pub fn default_key() -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(b"ubnt");
    let result = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&result);
    key
}

/// Parse a 32-char hex authkey string into 16 bytes.
pub fn parse_authkey(hex: &str) -> Result<[u8; 16]> {
    if hex.len() != 32 {
        bail!("authkey must be 32 hex chars, got {}", hex.len());
    }
    let mut key = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).context("invalid hex in authkey")?;
        key[i] = u8::from_str_radix(s, 16).context("invalid hex digit in authkey")?;
    }
    Ok(key)
}

/// Generate a random 16-byte authkey, returned as 32-char hex string.
pub fn generate_authkey() -> Result<String> {
    let mut key = [0u8; 16];
    // Use ring for CSPRNG
    let rng = ring::rand::SystemRandom::new();
    ring::rand::SecureRandom::fill(&rng, &mut key)
        .map_err(|_| anyhow::anyhow!("RNG failure generating authkey"))?;
    Ok(hex::encode(&key))
}

/// Decrypt a TNBU packet payload using AES-128-CBC (for unadopted / default key).
///
/// PKCS7 padding is stripped from the result.
pub fn decrypt_cbc(payload: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>> {
    if payload.is_empty() {
        bail!("empty CBC payload");
    }
    // AES-128-CBC requires payload length to be a multiple of 16
    if payload.len() % 16 != 0 {
        bail!(
            "CBC payload length {} is not a multiple of 16",
            payload.len()
        );
    }

    let mut buf = payload.to_vec();
    let decryptor = Aes128CbcDec::new(key.into(), iv.into());
    let plaintext = decryptor
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|e| anyhow::anyhow!("AES-128-CBC decryption failed: {e}"))?;

    Ok(plaintext.to_vec())
}

/// Encrypt a payload using AES-128-CBC with PKCS7 padding.
pub fn encrypt_cbc(plaintext: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    let encryptor = Aes128CbcEnc::new(key.into(), iv.into());
    encryptor.encrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(plaintext)
}

/// Decrypt a TNBU packet payload using AES-128-GCM (for adopted devices).
///
/// The 40-byte TNBU header is used as AAD (Additional Authenticated Data).
/// The full 16-byte IV is used as the GCM nonce (matching Java's
/// `GCMParameterSpec(128, iv)` used by UniFi firmware).
///
/// Input `payload` contains: ciphertext || 16-byte auth tag.
pub fn decrypt_gcm(packet: &TnbuPacket, key: &[u8; 16]) -> Result<Vec<u8>> {
    if packet.payload.len() < 16 {
        bail!("GCM payload too short for auth tag");
    }

    let cipher = Aes128Gcm16::new(key.into());
    // Use original wire header bytes as AAD (critical for GCM authentication)
    let fallback_header;
    let aad = match &packet.raw_header {
        Some(h) => h.as_slice(),
        None => {
            fallback_header = packet.header_bytes();
            &fallback_header
        }
    };
    let nonce = aes_gcm::Nonce::<typenum::U16>::from_slice(&packet.iv);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &packet.payload,
                aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("AES-128-GCM decryption/auth failed: {e}"))
}

/// Encrypt a payload using AES-128-GCM with the TNBU header as AAD.
///
/// Returns ciphertext || 16-byte auth tag. Caller must set the IV in the
/// packet header to match the nonce used here (full 16 bytes).
pub fn encrypt_gcm(plaintext: &[u8], key: &[u8; 16], packet: &TnbuPacket) -> Result<Vec<u8>> {
    let cipher = Aes128Gcm16::new(key.into());
    let aad = packet.header_bytes();
    let nonce = aes_gcm::Nonce::<typenum::U16>::from_slice(&packet.iv);

    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("AES-128-GCM encryption failed: {e}"))
}

/// Hex encoding helper (no extra dependency needed).
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_key_matches_known_value() {
        let key = default_key();
        let expected: [u8; 16] = [
            0xba, 0x86, 0xf2, 0xbb, 0xe1, 0x07, 0xc7, 0xc5, 0x7e, 0xb5, 0xf2, 0x69, 0x07, 0x75,
            0xc7, 0x12,
        ];
        assert_eq!(key, expected);
    }

    #[test]
    fn cbc_roundtrip() {
        let key = default_key();
        let iv = [0x42u8; 16];
        let plaintext = b"hello ubiquiti world!";

        let ciphertext = encrypt_cbc(plaintext, &key, &iv);
        let decrypted = decrypt_cbc(&ciphertext, &key, &iv).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn cbc_invalid_padding() {
        let key = default_key();
        let iv = [0x42u8; 16];
        // 16 bytes of zeros is unlikely to have valid PKCS7 padding
        let garbage = [0u8; 16];
        let result = decrypt_cbc(&garbage, &key, &iv);
        assert!(result.is_err());
    }

    #[test]
    fn parse_authkey_valid() {
        let hex = "ba86f2bbe107c7c57eb5f2690775c712";
        let key = parse_authkey(hex).expect("parse");
        assert_eq!(key, default_key());
    }

    #[test]
    fn parse_authkey_invalid_length() {
        assert!(parse_authkey("abcd").is_err());
    }

    #[test]
    fn generate_authkey_format() {
        let hex = generate_authkey().expect("generate");
        assert_eq!(hex.len(), 32);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn gcm_decrypt_pycryptodome_packet() {
        // Packet built with PyCryptodome: AES.new(key, AES.MODE_GCM, nonce=iv)
        // key = MD5("ubnt"), payload = {"mac": "aa:bb:cc:dd:ee:ff", "model": "TEST"}
        let packet_hex = "544e425500000000aabbccddeeff00099e75a693b98b7b9e099e82d08cab62b8000000010000003de538d3c289d82bbae61eb32b14fc906c82e2eb66c499341f313385613a21b8e5b22456df324e0d4bf21bc8e583adc2d6a33094c181002b3ae8030dd5fd";
        let packet_bytes: Vec<u8> = (0..packet_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&packet_hex[i..i + 2], 16).unwrap())
            .collect();

        let pkt = crate::packet::parse(&packet_bytes).expect("parse");
        assert!(pkt.flags.is_gcm());
        assert!(!pkt.flags.is_compressed());

        let key = default_key();
        let result = decrypt_gcm(&pkt, &key);
        assert!(result.is_ok(), "GCM decrypt failed: {:?}", result.err());

        let plaintext = result.unwrap();
        let json_str = String::from_utf8(plaintext).expect("utf8");
        assert!(json_str.contains("aa:bb:cc:dd:ee:ff"));
    }

    /// Full GCM+Snappy roundtrip: encrypt → wrap in TNBU → parse → decrypt → decompress.
    /// This tests the exact same code path that a real GCM+Snappy inform packet would take.
    #[test]
    fn gcm_snappy_roundtrip() {
        let key = default_key();
        let json = br#"{"mac":"ac:8b:a9:a8:a5:e1","model":"USXG","hostname":"UBNT","version":"6.6.65"}"#;

        // Compress with Snappy (like the real device does)
        let mut encoder = snap::raw::Encoder::new();
        let compressed = encoder.compress_vec(json).expect("snappy compress");

        // Build a TNBU packet header for GCM+Snappy (flags 0x000D)
        let mac = [0xac, 0x8b, 0xa9, 0xa8, 0xa5, 0xe1];
        let iv = [0x11u8; 16]; // arbitrary IV

        // Build the packet struct first (for encrypt_gcm which needs the header as AAD)
        let mut pkt = crate::packet::TnbuPacket {
            version: 0,
            mac,
            flags: crate::packet::PacketFlags::GCM_SNAPPY,
            iv,
            data_version: 1,
            payload: Vec::new(), // placeholder — will be replaced with ciphertext
            raw_header: None,
        };

        // Compute what the header bytes will be AFTER we know the ciphertext length.
        // GCM adds a 16-byte tag, so payload = compressed_len + 16.
        let ciphertext_len = compressed.len() + 16; // GCM tag
        pkt.payload = vec![0u8; ciphertext_len]; // dummy for header_bytes calculation

        // Now encrypt
        let encrypted = encrypt_gcm(&compressed, &key, &pkt).expect("gcm encrypt");
        assert_eq!(encrypted.len(), ciphertext_len, "GCM output should be plaintext + 16 tag");

        // Put the real ciphertext in the packet
        pkt.payload = encrypted;

        // Serialize to wire format
        let wire = crate::packet::serialize(&pkt);

        // Parse it back (like the handler does)
        let parsed = crate::packet::parse(&wire).expect("parse");
        assert!(parsed.flags.is_gcm());
        assert!(parsed.flags.is_snappy());
        assert_eq!(parsed.payload.len(), ciphertext_len);

        // Decrypt GCM (using raw_header as AAD, just like real packets)
        let decrypted = decrypt_gcm(&parsed, &key).expect("gcm decrypt");
        assert_eq!(decrypted, compressed, "GCM decrypt should yield compressed data");

        // Decompress
        let decompressed = crate::codec::decompress(&decrypted, parsed.flags).expect("snappy decompress");
        assert_eq!(decompressed, json);
    }

    /// Test that GCM AAD matches between header_bytes() and raw_header from parse().
    /// A mismatch here would cause GCM auth failure on real packets.
    #[test]
    fn gcm_aad_consistency() {
        let mac = [0xac, 0x8b, 0xa9, 0xa8, 0xa5, 0xe1];
        let iv = [0x42u8; 16];
        let payload = vec![0xAA; 100]; // dummy

        let pkt = crate::packet::TnbuPacket {
            version: 0,
            mac,
            flags: crate::packet::PacketFlags::GCM_SNAPPY,
            iv,
            data_version: 1,
            payload: payload.clone(),
            raw_header: None,
        };

        // Serialize and re-parse
        let wire = crate::packet::serialize(&pkt);
        let parsed = crate::packet::parse(&wire).expect("parse");

        // raw_header from parse() must match header_bytes() from the original
        let constructed_header = pkt.header_bytes();
        let parsed_header = parsed.raw_header.as_ref().unwrap();
        assert_eq!(&constructed_header, parsed_header, "AAD mismatch: constructed vs parsed header");
    }
}
