// SPDX-License-Identifier: AGPL-3.0-or-later

//! TNBU packet format — parse and serialize Ubiquiti Inform protocol packets.
//!
//! ```text
//! Offset  Size  Field
//! 0       4     Magic: "TNBU" (0x54 0x4E 0x42 0x55)
//! 4       4     Packet version (0)
//! 8       6     Hardware address (MAC)
//! 14      2     Flags
//! 16      16    Initialization vector (AES)
//! 32      4     Data version (1)
//! 36      4     Data length
//! 40      N     Encrypted payload
//! ```
//!
//! **Interop code**: this implements the stock Ubiquiti Inform binary format.

/// TNBU magic bytes: `T`, `N`, `B`, `U`.
const MAGIC: [u8; 4] = [0x54, 0x4E, 0x42, 0x55];

/// Minimum valid packet size: 40-byte header + at least 1 byte payload.
const MIN_PACKET_SIZE: usize = 40;

/// Encryption/compression flags extracted from the 2-byte flags field.
///
/// Flags are a bitfield:
/// - Bit 0 (`0x01`): encrypted
/// - Bit 1 (`0x02`): zlib compressed
/// - Bit 2 (`0x04`): snappy compressed
/// - Bit 3 (`0x08`): AES-128-GCM (else AES-128-CBC)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketFlags(pub u16);

impl PacketFlags {
    const ENCRYPTED: u16 = 0x01;
    const ZLIB: u16 = 0x02;
    const SNAPPY: u16 = 0x04;
    const GCM: u16 = 0x08;

    /// Convenience constants for serialization.
    pub const CBC: Self = Self(Self::ENCRYPTED);
    pub const CBC_ZLIB: Self = Self(Self::ENCRYPTED | Self::ZLIB);
    pub const CBC_SNAPPY: Self = Self(Self::ENCRYPTED | Self::SNAPPY);
    pub const GCM_ONLY: Self = Self(Self::ENCRYPTED | Self::GCM);
    pub const GCM_ZLIB: Self = Self(Self::ENCRYPTED | Self::GCM | Self::ZLIB);
    pub const GCM_SNAPPY: Self = Self(Self::ENCRYPTED | Self::GCM | Self::SNAPPY);

    fn from_u16(val: u16) -> Self {
        Self(val)
    }

    fn to_u16(self) -> u16 {
        self.0
    }

    /// Whether this mode uses GCM (requires AAD from header).
    pub fn is_gcm(self) -> bool {
        self.0 & Self::GCM != 0
    }

    /// Whether the payload is zlib-compressed after decryption.
    pub fn is_zlib(self) -> bool {
        self.0 & Self::ZLIB != 0
    }

    /// Whether the payload is snappy-compressed after decryption.
    pub fn is_snappy(self) -> bool {
        self.0 & Self::SNAPPY != 0
    }

    /// Whether the payload is compressed after decryption.
    pub fn is_compressed(self) -> bool {
        self.is_zlib() || self.is_snappy()
    }
}

/// Parsed TNBU packet header + encrypted payload.
#[derive(Debug, Clone)]
pub struct TnbuPacket {
    /// Packet protocol version (always 0 in current firmware).
    pub version: u32,
    /// Device MAC address (6 bytes).
    pub mac: [u8; 6],
    /// Encryption and compression mode.
    pub flags: PacketFlags,
    /// AES initialization vector (16 bytes).
    pub iv: [u8; 16],
    /// Data format version (always 1 in current firmware).
    pub data_version: u32,
    /// Encrypted payload bytes.
    pub payload: Vec<u8>,
    /// Original 40-byte header from the wire (used as GCM AAD).
    /// Only set for parsed (incoming) packets, not for constructed (outgoing) ones.
    pub raw_header: Option<Vec<u8>>,
}

impl TnbuPacket {
    /// Format MAC as colon-separated hex string (lowercase).
    pub fn mac_str(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5],
        )
    }

    /// The first 40 bytes of the wire format (used as GCM AAD).
    pub fn header_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(40);
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.extend_from_slice(&self.mac);
        buf.extend_from_slice(&self.flags.to_u16().to_be_bytes());
        buf.extend_from_slice(&self.iv);
        buf.extend_from_slice(&self.data_version.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf
    }
}

/// Errors from packet parsing.
#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("packet too short ({0} bytes, minimum {MIN_PACKET_SIZE})")]
    TooShort(usize),

    #[error("invalid magic (expected TNBU, got {0:02x?})")]
    BadMagic([u8; 4]),

    #[error("declared payload length {declared} exceeds available data {available}")]
    LengthMismatch { declared: usize, available: usize },
}

/// Parse raw bytes into a `TnbuPacket`.
pub fn parse(data: &[u8]) -> std::result::Result<TnbuPacket, PacketError> {
    if data.len() < MIN_PACKET_SIZE {
        return Err(PacketError::TooShort(data.len()));
    }

    // Magic check
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&data[0..4]);
    if magic != MAGIC {
        return Err(PacketError::BadMagic(magic));
    }

    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    let mut mac = [0u8; 6];
    mac.copy_from_slice(&data[8..14]);

    let flags = PacketFlags::from_u16(u16::from_be_bytes([data[14], data[15]]));

    let mut iv = [0u8; 16];
    iv.copy_from_slice(&data[16..32]);

    let data_version = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
    let data_length = u32::from_be_bytes([data[36], data[37], data[38], data[39]]) as usize;

    let available = data.len() - 40;
    if data_length > available {
        return Err(PacketError::LengthMismatch {
            declared: data_length,
            available,
        });
    }

    let payload = data[40..40 + data_length].to_vec();
    let raw_header = data[..40].to_vec();

    Ok(TnbuPacket {
        version,
        mac,
        flags,
        iv,
        data_version,
        payload,
        raw_header: Some(raw_header),
    })
}

/// Serialize a TNBU response packet to wire format.
pub fn serialize(packet: &TnbuPacket) -> Vec<u8> {
    let mut buf = Vec::with_capacity(40 + packet.payload.len());
    buf.extend_from_slice(&MAGIC);
    buf.extend_from_slice(&packet.version.to_be_bytes());
    buf.extend_from_slice(&packet.mac);
    buf.extend_from_slice(&packet.flags.to_u16().to_be_bytes());
    buf.extend_from_slice(&packet.iv);
    buf.extend_from_slice(&packet.data_version.to_be_bytes());
    buf.extend_from_slice(&(packet.payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&packet.payload);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_packet() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Magic
        pkt.extend_from_slice(&MAGIC);
        // Version 0
        pkt.extend_from_slice(&0u32.to_be_bytes());
        // MAC: aa:bb:cc:dd:ee:ff
        pkt.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        // Flags: CBC (0x01)
        pkt.extend_from_slice(&0x0001u16.to_be_bytes());
        // IV: 16 bytes of 0x42
        pkt.extend_from_slice(&[0x42u8; 16]);
        // Data version: 1
        pkt.extend_from_slice(&1u32.to_be_bytes());
        // Data length: 4
        pkt.extend_from_slice(&4u32.to_be_bytes());
        // Payload: "test"
        pkt.extend_from_slice(b"test");
        pkt
    }

    #[test]
    fn parse_valid_packet() {
        let data = sample_packet();
        let pkt = parse(&data).expect("should parse");
        assert_eq!(pkt.version, 0);
        assert_eq!(pkt.mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(pkt.mac_str(), "aa:bb:cc:dd:ee:ff");
        assert_eq!(pkt.flags, PacketFlags::CBC);
        assert_eq!(pkt.iv, [0x42u8; 16]);
        assert_eq!(pkt.data_version, 1);
        assert_eq!(pkt.payload, b"test");
    }

    #[test]
    fn parse_too_short() {
        let err = parse(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, PacketError::TooShort(10)));
    }

    #[test]
    fn parse_bad_magic() {
        let mut data = sample_packet();
        data[0] = 0xFF;
        let err = parse(&data).unwrap_err();
        assert!(matches!(err, PacketError::BadMagic(_)));
    }

    #[test]
    fn parse_length_mismatch() {
        let mut data = sample_packet();
        // Set declared length to 100 but only 4 bytes available
        data[36..40].copy_from_slice(&100u32.to_be_bytes());
        let err = parse(&data).unwrap_err();
        assert!(matches!(err, PacketError::LengthMismatch { .. }));
    }

    #[test]
    fn roundtrip_serialize() {
        let data = sample_packet();
        let pkt = parse(&data).expect("parse");
        let serialized = serialize(&pkt);
        assert_eq!(data, serialized);
    }

    #[test]
    fn gcm_flags() {
        assert!(!PacketFlags::CBC.is_gcm());
        assert!(PacketFlags::GCM_ONLY.is_gcm());
        assert!(PacketFlags::GCM_ZLIB.is_gcm());
        assert!(PacketFlags::GCM_SNAPPY.is_gcm());
        // CBC + compression: not GCM
        assert!(!PacketFlags::CBC_ZLIB.is_gcm());
        assert!(!PacketFlags::CBC_SNAPPY.is_gcm());
        // Compression detection
        assert!(PacketFlags::CBC_ZLIB.is_compressed());
        assert!(PacketFlags::CBC_SNAPPY.is_compressed());
        assert!(PacketFlags::GCM_ZLIB.is_compressed());
        assert!(!PacketFlags::CBC.is_compressed());
        assert!(!PacketFlags::GCM_ONLY.is_compressed());
    }
}
