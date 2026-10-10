use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_SCREEN_DIMENSION: u32 = 16_384;
pub const MAX_SCREEN_PIXELS: u64 = 67_108_864;
pub const MAX_ENCODED_FRAME_BYTES: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub version: u16,
    pub message: Message,
}

impl Envelope {
    pub fn new(message: Message) -> Self {
        Self { version: PROTOCOL_VERSION, message }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if let Message::ScreenStreamStart(start) = &self.message {
            start.validate()?;
        }
        if let Message::ScreenFrame(frame) = &self.message {
            frame.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data")]
pub enum Message {
    Hello(Hello),
    HelloAck(HelloAck),
    Authenticate(Authentication),
    AuthenticateAck(AuthenticationAck),
    SessionStart(SessionStart),
    SessionStarted(SessionStarted),
    SessionEnd(SessionEnd),
    SessionEnded(SessionEnded),
    ScreenStreamStart(ScreenStreamStart),
    ScreenStreamStarted { stream_id: String },
    ScreenFrame(ScreenFrameHeader),
    ScreenStreamStop { stream_id: String },
    ScreenStreamStopped { stream_id: String },
    Ping { nonce: u64 },
    Pong { nonce: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hello {
    pub device_id: String,
    pub device_name: String,
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelloAck {
    pub device_id: String,
    pub capabilities: Capabilities,
    pub public_key: String,
    pub ephemeral_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Capabilities {
    pub screen: bool,
    pub input: bool,
    pub clipboard: bool,
    pub files: bool,
    pub audio: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Authentication {
    pub public_key: String,
    pub ephemeral_public_key: String,
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthenticationAck {
    pub accepted: bool,
    pub reason: Option<String>,
    pub public_key: Option<String>,
    pub proof: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionStart {
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionStarted {
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionEnd {
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionEnded {
    pub session_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScreenCodec {
    RawBgra8,
    Jpeg,
    H264,
    Vp9,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenStreamStart {
    pub session_id: String,
    pub stream_id: String,
    pub width: u32,
    pub height: u32,
    pub codec: ScreenCodec,
    pub target_fps: u16,
}

impl ScreenStreamStart {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_dimensions(self.width, self.height)?;
        if self.session_id.is_empty() || self.stream_id.is_empty() {
            return Err(ProtocolError::InvalidScreenMetadata("session_id and stream_id must not be empty"));
        }
        if !(1..=120).contains(&self.target_fps) {
            return Err(ProtocolError::InvalidScreenMetadata("target_fps must be between 1 and 120"));
        }
        Ok(())
    }
}

/// Metadata for a separately framed encoded payload. The pixel bytes are not
/// embedded in JSON; a future binary transport frame will carry them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenFrameHeader {
    pub session_id: String,
    pub stream_id: String,
    pub frame_id: u64,
    pub timestamp_micros: u64,
    pub width: u32,
    pub height: u32,
    pub codec: ScreenCodec,
    pub keyframe: bool,
    pub payload_len: u32,
}

impl ScreenFrameHeader {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_dimensions(self.width, self.height)?;
        if self.session_id.is_empty() || self.stream_id.is_empty() {
            return Err(ProtocolError::InvalidScreenMetadata("session_id and stream_id must not be empty"));
        }
        if self.payload_len == 0 || self.payload_len > MAX_ENCODED_FRAME_BYTES {
            return Err(ProtocolError::InvalidScreenMetadata("payload_len is outside the permitted range"));
        }
        Ok(())
    }
}

fn validate_dimensions(width: u32, height: u32) -> Result<(), ProtocolError> {
    if width == 0
        || height == 0
        || width > MAX_SCREEN_DIMENSION
        || height > MAX_SCREEN_DIMENSION
        || u64::from(width) * u64::from(height) > MAX_SCREEN_PIXELS
    {
        return Err(ProtocolError::InvalidScreenMetadata("dimensions are outside the permitted range"));
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u16),
    #[error("invalid screen metadata: {0}")]
    InvalidScreenMetadata(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips_as_json() {
        let envelope = Envelope::new(Message::Ping { nonce: 42 });
        let encoded = serde_json::to_string(&envelope).unwrap();
        let decoded: Envelope = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, envelope);
        assert!(decoded.validate().is_ok());
    }

    #[test]
    fn rejects_unknown_protocol_version() {
        let envelope = Envelope {
            version: PROTOCOL_VERSION + 1,
            message: Message::Ping { nonce: 1 },
        };
        assert_eq!(
            envelope.validate(),
            Err(ProtocolError::UnsupportedVersion(PROTOCOL_VERSION + 1))
        );
    }

    #[test]
    fn accepts_valid_screen_stream_start() {
        let start = ScreenStreamStart {
            session_id: "session-1".into(),
            stream_id: "screen-1".into(),
            width: 1920,
            height: 1080,
            codec: ScreenCodec::H264,
            target_fps: 60,
        };
        assert!(start.validate().is_ok());
        assert!(Envelope::new(Message::ScreenStreamStart(start)).validate().is_ok());
    }

    #[test]
    fn rejects_oversized_screen_dimensions() {
        let header = ScreenFrameHeader {
            session_id: "session-1".into(),
            stream_id: "screen-1".into(),
            frame_id: 1,
            timestamp_micros: 16_667,
            width: 16_384,
            height: 16_384,
            codec: ScreenCodec::RawBgra8,
            keyframe: true,
            payload_len: 1024,
        };
        assert!(header.validate().is_err());
    }

    #[test]
    fn rejects_oversized_encoded_payload() {
        let header = ScreenFrameHeader {
            session_id: "session-1".into(),
            stream_id: "screen-1".into(),
            frame_id: 1,
            timestamp_micros: 16_667,
            width: 1280,
            height: 720,
            codec: ScreenCodec::Jpeg,
            keyframe: true,
            payload_len: MAX_ENCODED_FRAME_BYTES + 1,
        };
        assert!(header.validate().is_err());
    }

    #[test]
    fn rejects_invalid_frame_rate() {
        let start = ScreenStreamStart {
            session_id: "session-1".into(),
            stream_id: "screen-1".into(),
            width: 1280,
            height: 720,
            codec: ScreenCodec::Jpeg,
            target_fps: 0,
        };
        assert!(start.validate().is_err());
    }
}
