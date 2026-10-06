use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;

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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u16),
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
}
