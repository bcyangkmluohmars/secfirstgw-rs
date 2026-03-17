// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compression codecs for Ubiquiti Inform payloads.
//!
//! Adopted devices may send compressed payloads:
//! - Flag 0x0b → zlib (deflate)
//! - Flag 0x0d → snappy
//!
//! Maximum decompressed size is capped to prevent decompression bombs.

use anyhow::{Result, bail};
use flate2::read::ZlibDecoder;
use std::io::Read;

use crate::packet::PacketFlags;

/// Maximum decompressed payload size (10 MiB). Prevents decompression bombs.
const MAX_DECOMPRESSED_SIZE: usize = 10 * 1024 * 1024;

/// Decompress a payload based on the packet flags.
///
/// Returns the input unchanged if the flags indicate no compression.
pub fn decompress(data: &[u8], flags: PacketFlags) -> Result<Vec<u8>> {
    if flags.is_zlib() {
        decompress_zlib(data)
    } else if flags.is_snappy() {
        decompress_snappy(data)
    } else {
        Ok(data.to_vec())
    }
}

/// Compress a payload using zlib (for GCM+zlib responses).
pub fn compress_zlib(data: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("zlib compress write");
    encoder.finish().expect("zlib compress finish")
}

fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut output = Vec::new();

    // Read in chunks to enforce size limit
    let mut buf = [0u8; 8192];
    loop {
        let n = decoder.read(&mut buf)?;
        if n == 0 {
            break;
        }
        output.extend_from_slice(&buf[..n]);
        if output.len() > MAX_DECOMPRESSED_SIZE {
            bail!(
                "decompressed zlib payload exceeds {MAX_DECOMPRESSED_SIZE} bytes — \
                 possible decompression bomb"
            );
        }
    }

    Ok(output)
}

fn decompress_snappy(data: &[u8]) -> Result<Vec<u8>> {
    // Check declared size first (snappy encodes uncompressed length in header)
    let decoded_len = snap::raw::decompress_len(data)
        .map_err(|e| anyhow::anyhow!("snappy header invalid: {e}"))?;

    if decoded_len > MAX_DECOMPRESSED_SIZE {
        bail!(
            "snappy declares {decoded_len} bytes output — exceeds {MAX_DECOMPRESSED_SIZE} limit, \
             possible decompression bomb"
        );
    }

    let mut output = vec![0u8; decoded_len];
    let actual = snap::raw::Decoder::new()
        .decompress(data, &mut output)
        .map_err(|e| anyhow::anyhow!("snappy decompression failed: {e}"))?;

    output.truncate(actual);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zlib_roundtrip() {
        let original = b"hello from ubiquiti inform payload, this is some test data";
        let compressed = compress_zlib(original);
        let decompressed = decompress_zlib(&compressed).expect("decompress");
        assert_eq!(decompressed, original);
    }

    #[test]
    fn snappy_roundtrip() {
        let original = b"snappy test payload for inform protocol";
        let mut encoder = snap::raw::Encoder::new();
        let compressed = encoder.compress_vec(original).expect("compress");
        let decompressed = decompress_snappy(&compressed).expect("decompress");
        assert_eq!(decompressed, original);
    }

    #[test]
    fn decompress_uncompressed_noop() {
        let data = b"plain data";
        let result = decompress(data, PacketFlags::CBC).expect("decompress");
        assert_eq!(result, data);
    }
}
