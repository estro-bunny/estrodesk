use estrodesk_crypto::{derive_directional_keys, transcript_hash, CryptoError, DeviceIdentity, EphemeralKeyExchange};
use estrodesk_protocol::{Authentication, AuthenticationAck, Capabilities, Hello, HelloAck, Message};
use thiserror::Error;

pub mod trust;
pub mod trust_store;
pub use trust::{TrustError, TrustStatus, TrustStore, TrustedDevice};
pub use trust_store::{load as load_trust_store, save as save_trust_store, trust_path, PersistentTrustError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState { Initial, HelloSent, Authenticated, Established, Failed }

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("unexpected handshake message")] UnexpectedMessage,
    #[error("invalid encoded handshake key")] InvalidEncoding,
    #[error("invalid handshake key length")] InvalidKeyLength,
    #[error("cryptographic verification failed")] Crypto(#[from] CryptoError),
    #[error("peer rejected authentication: {0}")] Rejected(String),
}

pub struct SessionKeys { pub send_key: [u8; 32], pub receive_key: [u8; 32] }

pub struct ControllerHandshake { identity: DeviceIdentity, ephemeral: EphemeralKeyExchange, host_identity: Option<[u8; 32]>, host_ephemeral: Option<[u8; 32]>, state: HandshakeState }
impl ControllerHandshake {
    pub fn new(identity: DeviceIdentity) -> Self { Self { identity, ephemeral: EphemeralKeyExchange::generate(), host_identity: None, host_ephemeral: None, state: HandshakeState::Initial } }
    pub fn state(&self) -> HandshakeState { self.state }
    pub fn hello(&mut self, device_id: impl Into<String>, device_name: impl Into<String>, capabilities: Capabilities) -> Message {
        if self.state != HandshakeState::Initial { self.state = HandshakeState::Failed; } else { self.state = HandshakeState::HelloSent; }
        Message::Hello(Hello { device_id: device_id.into(), device_name: device_name.into(), capabilities })
    }
    pub fn receive_hello_ack(&mut self, ack: HelloAck) -> Result<Message, HandshakeError> {
        if self.state != HandshakeState::HelloSent { return Err(HandshakeError::UnexpectedMessage); }
        let host_identity = decode_32(&ack.public_key)?; let host_ephemeral = decode_32(&ack.ephemeral_public_key)?;
        let transcript = transcript_hash(&self.identity.public_key_bytes(), &host_identity, &self.ephemeral.public_key_bytes(), &host_ephemeral);
        let proof = self.identity.sign(&transcript); self.host_identity = Some(host_identity); self.host_ephemeral = Some(host_ephemeral);
        Ok(Message::Authenticate(Authentication { public_key: hex::encode(self.identity.public_key_bytes()), ephemeral_public_key: hex::encode(self.ephemeral.public_key_bytes()), proof: hex::encode(proof) }))
    }
    pub fn receive_authentication_ack(&mut self, ack: AuthenticationAck) -> Result<SessionKeys, HandshakeError> {
        if self.state != HandshakeState::HelloSent { return Err(HandshakeError::UnexpectedMessage); }
        if !ack.accepted { self.state = HandshakeState::Failed; return Err(HandshakeError::Rejected(ack.reason.unwrap_or_else(|| "peer rejected authentication".into()))); }
        let host_identity = self.host_identity.ok_or(HandshakeError::UnexpectedMessage)?; let host_ephemeral = self.host_ephemeral.ok_or(HandshakeError::UnexpectedMessage)?;
        let public_key = decode_32(ack.public_key.as_deref().ok_or(HandshakeError::UnexpectedMessage)?)?;
        if public_key != host_identity { self.state = HandshakeState::Failed; return Err(HandshakeError::Rejected("authentication identity changed".into())); }
        let proof = decode_64(ack.proof.as_deref().ok_or(HandshakeError::UnexpectedMessage)?)?;
        let transcript = transcript_hash(&self.identity.public_key_bytes(), &host_identity, &self.ephemeral.public_key_bytes(), &host_ephemeral);
        DeviceIdentity::verify(&host_identity, &transcript, &proof)?;
        let shared = self.ephemeral.derive_shared_secret(&host_ephemeral); let (send_key, receive_key) = derive_directional_keys(&shared, &transcript)?;
        self.state = HandshakeState::Established; Ok(SessionKeys { send_key, receive_key })
    }
    pub fn host_public_key(&self) -> Option<[u8; 32]> { self.host_identity }
}

pub struct HostHandshake { identity: DeviceIdentity, ephemeral: EphemeralKeyExchange, controller_identity: Option<[u8; 32]>, controller_ephemeral: Option<[u8; 32]>, state: HandshakeState }
impl HostHandshake {
    pub fn new(identity: DeviceIdentity) -> Self { Self { identity, ephemeral: EphemeralKeyExchange::generate(), controller_identity: None, controller_ephemeral: None, state: HandshakeState::Initial } }
    pub fn state(&self) -> HandshakeState { self.state }
    pub fn receive_hello(&mut self, _hello: Hello, device_id: impl Into<String>, capabilities: Capabilities) -> Result<Message, HandshakeError> {
        if self.state != HandshakeState::Initial { return Err(HandshakeError::UnexpectedMessage); }
        Ok(Message::HelloAck(HelloAck { device_id: device_id.into(), capabilities, public_key: hex::encode(self.identity.public_key_bytes()), ephemeral_public_key: hex::encode(self.ephemeral.public_key_bytes()) }))
    }
    pub fn receive_authentication(&mut self, auth: Authentication) -> Result<(Message, SessionKeys), HandshakeError> {
        if self.state != HandshakeState::Initial { return Err(HandshakeError::UnexpectedMessage); }
        let controller_identity = decode_32(&auth.public_key)?; let controller_ephemeral = decode_32(&auth.ephemeral_public_key)?; let proof = decode_64(&auth.proof)?;
        let transcript = transcript_hash(&controller_identity, &self.identity.public_key_bytes(), &controller_ephemeral, &self.ephemeral.public_key_bytes());
        DeviceIdentity::verify(&controller_identity, &transcript, &proof)?;
        self.controller_identity = Some(controller_identity); self.controller_ephemeral = Some(controller_ephemeral);
        let host_proof = self.identity.sign(&transcript); let shared = self.ephemeral.derive_shared_secret(&controller_ephemeral); let (controller_to_host, host_to_controller) = derive_directional_keys(&shared, &transcript)?;
        self.state = HandshakeState::Authenticated;
        Ok((Message::AuthenticateAck(AuthenticationAck { accepted: true, reason: None, public_key: Some(hex::encode(self.identity.public_key_bytes())), proof: Some(hex::encode(host_proof)) }), SessionKeys { send_key: host_to_controller, receive_key: controller_to_host }))
    }
    pub fn controller_public_key(&self) -> Option<[u8; 32]> { self.controller_identity }
}

fn decode_32(value: &str) -> Result<[u8; 32], HandshakeError> { let bytes = hex::decode(value).map_err(|_| HandshakeError::InvalidEncoding)?; bytes.try_into().map_err(|_| HandshakeError::InvalidKeyLength) }
fn decode_64(value: &str) -> Result<[u8; 64], HandshakeError> { let bytes = hex::decode(value).map_err(|_| HandshakeError::InvalidEncoding)?; bytes.try_into().map_err(|_| HandshakeError::InvalidKeyLength) }

#[cfg(test)]
mod tests {
    use super::*;
    fn capabilities() -> Capabilities { Capabilities { screen: true, input: true, clipboard: true, files: false, audio: false } }
    #[test] fn mutual_handshake_derives_matching_directional_keys() {
        let mut controller = ControllerHandshake::new(DeviceIdentity::generate()); let mut host = HostHandshake::new(DeviceIdentity::generate());
        let Message::Hello(hello) = controller.hello("controller", "Bunni PC", capabilities()) else { panic!() }; let Message::HelloAck(ack) = host.receive_hello(hello, "host", capabilities()).unwrap() else { panic!() }; let Message::Authenticate(auth) = controller.receive_hello_ack(ack).unwrap() else { panic!() }; let (Message::AuthenticateAck(ack), host_keys) = host.receive_authentication(auth).unwrap() else { panic!() }; let controller_keys = controller.receive_authentication_ack(ack).unwrap();
        assert_eq!(controller_keys.send_key, host_keys.receive_key); assert_eq!(controller_keys.receive_key, host_keys.send_key); assert_eq!(controller.state(), HandshakeState::Established); assert_eq!(host.state(), HandshakeState::Authenticated);
    }
    #[test] fn forged_controller_proof_is_rejected() {
        let mut controller = ControllerHandshake::new(DeviceIdentity::generate()); let mut host = HostHandshake::new(DeviceIdentity::generate()); let Message::Hello(hello) = controller.hello("controller", "Bunni PC", capabilities()) else { panic!() }; let Message::HelloAck(ack) = host.receive_hello(hello, "host", capabilities()).unwrap() else { panic!() }; let Message::Authenticate(mut auth) = controller.receive_hello_ack(ack).unwrap() else { panic!() }; auth.proof.replace_range(0..2, "00"); assert!(matches!(host.receive_authentication(auth), Err(HandshakeError::Crypto(_))));
    }
    #[test] fn wrong_host_proof_is_rejected_by_controller() {
        let mut controller = ControllerHandshake::new(DeviceIdentity::generate()); let mut host = HostHandshake::new(DeviceIdentity::generate()); let Message::Hello(hello) = controller.hello("controller", "Bunni PC", capabilities()) else { panic!() }; let Message::HelloAck(ack) = host.receive_hello(hello, "host", capabilities()).unwrap() else { panic!() }; let Message::Authenticate(auth) = controller.receive_hello_ack(ack).unwrap() else { panic!() }; let (Message::AuthenticateAck(mut ack), _) = host.receive_authentication(auth).unwrap() else { panic!() }; ack.proof.as_mut().unwrap().replace_range(0..2, "00"); assert!(matches!(controller.receive_authentication_ack(ack), Err(HandshakeError::Crypto(_))));
    }
}
