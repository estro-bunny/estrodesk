use estrodesk_protocol::{ScreenFrameHeader, MAX_ENCODED_FRAME_BYTES};
use thiserror::Error;

const HEADER_LENGTH_BYTES: usize = 4;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAGIC: &[u8; 4] = b"EDSF";

/// Maximum encoded screen packet size, excluding outer secure-channel framing.
pub const MAX_SCREEN_PACKET_BYTES: usize =
    4 + HEADER_LENGTH_BYTES + MAX_HEADER_BYTES + MAX_ENCODED_FRAME_BYTES as usize;

#[derive(Debug, Error)]
pub enum ScreenPacketError {
    #[error("screen packet is too large")]
    TooLarge,
    #[error("screen packet is truncated or has invalid framing")]
    InvalidFraming,
    #[error("screen packet header is invalid: {0}")]
    InvalidHeader(String),
    #[error("screen payload length does not match its header")]
    PayloadLengthMismatch,
    #[error("screen packet JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
}

/// A validated header and its encoded frame bytes.
///
/// This codec only serializes/deserializes the binary record. Callers must put
/// the resulting bytes inside SecureChannel encryption before network use;
/// this helper does not provide confidentiality or authenticity itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenFramePacket {
    pub header: ScreenFrameHeader,
    pub payload: Vec<u8>,
}

impl ScreenFramePacket {
    pub fn new(
        header: ScreenFrameHeader,
        payload: Vec<u8>,
    ) -> Result<Self, ScreenPacketError> {
        header
            .validate()
            .map_err(|error| ScreenPacketError::InvalidHeader(error.to_string()))?;
        if payload.len() != header.payload_len as usize {
            return Err(ScreenPacketError::PayloadLengthMismatch);
        }
        if payload.len() > MAX_ENCODED_FRAME_BYTES as usize {
            return Err(ScreenPacketError::TooLarge);
        }
        Ok(Self { header, payload })
    }

    /// Format: magic | u32 header length | JSON header | encoded payload.
    pub fn encode(&self) -> Result<Vec<u8>, ScreenPacketError> {
        self.header
            .validate()
            .map_err(|error| ScreenPacketError::InvalidHeader(error.to_string()))?;
        if self.payload.len() != self.header.payload_len as usize {
            return Err(ScreenPacketError::PayloadLengthMismatch);
        }

        let header = serde_json::to_vec(&self.header)?;
        if header.len() > MAX_HEADER_BYTES
            || self.payload.len() > MAX_ENCODED_FRAME_BYTES as usize
        {
            return Err(ScreenPacketError::TooLarge);
        }

        let total = MAGIC.len() + HEADER_LENGTH_BYTES + header.len() + self.payload.len();
        if total > MAX_SCREEN_PACKET_BYTES {
            return Err(ScreenPacketError::TooLarge);
        }

        let mut output = Vec::with_capacity(total);
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&(header.len() as u32).to_be_bytes());
        output.extend_from_slice(&header);
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    /// Decode only after the caller has authenticated/decrypted the outer
    /// transport record. Lengths are checked before copying the payload.
    pub fn decode(input: &[u8]) -> Result<Self, ScreenPacketError> {
        if input.len() > MAX_SCREEN_PACKET_BYTES {
            return Err(ScreenPacketError::TooLarge);
        }
        if input.len() < MAGIC.len() + HEADER_LENGTH_BYTES || &input[..4] != MAGIC {
            return Err(ScreenPacketError::InvalidFraming);
        }

        let header_len = u32::from_be_bytes(input[4..8].try_into().unwrap()) as usize;
        if header_len == 0 || header_len > MAX_HEADER_BYTES {
            return Err(ScreenPacketError::InvalidFraming);
        }
        let payload_start = MAGIC.len() + HEADER_LENGTH_BYTES + header_len;
        if payload_start > input.len() {
            return Err(ScreenPacketError::InvalidFraming);
        }

        let header: ScreenFrameHeader = serde_json::from_slice(&input[8..payload_start])?;
        header
            .validate()
            .map_err(|error| ScreenPacketError::InvalidHeader(error.to_string()))?;
        let payload_len = input.len() - payload_start;
        if payload_len != header.payload_len as usize {
            return Err(ScreenPacketError::PayloadLengthMismatch);
        }

        Ok(Self {
            header,
            payload: input[payload_start..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use estrodesk_protocol::ScreenCodec;

    fn packet(payload: Vec<u8>) -> ScreenFramePacket {
        ScreenFramePacket::new(
            ScreenFrameHeader {
                session_id: "session-1".into(),
                stream_id: "stream-1".into(),
                frame_id: 7,
                timestamp_micros: 116_667,
                width: 2,
                height: 2,
                codec: ScreenCodec::RawBgra8,
                keyframe: true,
                payload_len: payload.len() as u32,
            },
            payload,
        )
        .unwrap()
    }

    #[test]
    fn binary_packet_round_trips() {
        let original = packet(vec![1, 2, 3, 4]);
        let encoded = original.encode().unwrap();
        assert_eq!(ScreenFramePacket::decode(&encoded).unwrap(), original);
    }

    #[test]
    fn rejects_payload_length_mismatch() {
        let original = packet(vec![1, 2, 3, 4]);
        let encoded = original.encode().unwrap();
        let mut bad = encoded;
        bad.pop();
        assert!(matches!(
            ScreenFramePacket::decode(&bad),
            Err(ScreenPacketError::PayloadLengthMismatch)
        ));
    }

    #[test]
    fn rejects_bad_magic() {
        let original = packet(vec![1, 2, 3, 4]);
        let mut encoded = original.encode().unwrap();
        encoded[0] = b'X';
        assert!(matches!(
            ScreenFramePacket::decode(&encoded),
            Err(ScreenPacketError::InvalidFraming)
        ));
    }

    #[test]
    fn rejects_declared_header_length_past_packet() {
        let original = packet(vec![1, 2, 3, 4]);
        let mut encoded = original.encode().unwrap();
        encoded[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            ScreenFramePacket::decode(&encoded),
            Err(ScreenPacketError::InvalidFraming)
                | Err(ScreenPacketError::TooLarge)
        ));
    }
}
