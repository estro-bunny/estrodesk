use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
}

#[derive(Debug)]
pub struct DeviceIdentity {
    signing_key: SigningKey,
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    pub fn verify(
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), CryptoError> {
        let key = VerifyingKey::from_bytes(public_key)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let sig = Signature::from_bytes(signature);

        key.verify(message, &sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

pub struct EphemeralKeyExchange {
    secret: StaticSecret,
    public: PublicKey,
}

impl EphemeralKeyExchange {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn derive_shared_secret(&self, peer_public_key: &[u8; 32]) -> [u8; 32] {
        self.secret
            .diffie_hellman(&PublicKey::from(*peer_public_key))
            .to_bytes()
    }
}

pub fn transcript_hash(
    controller_identity: &[u8; 32],
    host_identity: &[u8; 32],
    controller_ephemeral: &[u8; 32],
    host_ephemeral: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ESTRODESK-HANDSHAKE-V1");
    hasher.update(controller_identity);
    hasher.update(host_identity);
    hasher.update(controller_ephemeral);
    hasher.update(host_ephemeral);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_can_sign_and_verify() {
        let identity = DeviceIdentity::generate();
        let message = b"estrodesk handshake";
        let signature = identity.sign(message);

        assert!(DeviceIdentity::verify(
            &identity.public_key_bytes(),
            message,
            &signature
        )
        .is_ok());
    }

    #[test]
    fn modified_message_fails_verification() {
        let identity = DeviceIdentity::generate();
        let signature = identity.sign(b"original");

        assert!(DeviceIdentity::verify(
            &identity.public_key_bytes(),
            b"modified",
            &signature
        )
        .is_err());
    }

    #[test]
    fn both_peers_derive_the_same_shared_secret() {
        let controller = EphemeralKeyExchange::generate();
        let host = EphemeralKeyExchange::generate();

        let controller_secret =
            controller.derive_shared_secret(&host.public_key_bytes());
        let host_secret =
            host.derive_shared_secret(&controller.public_key_bytes());

        assert_eq!(controller_secret, host_secret);
    }

    #[test]
    fn transcript_hash_changes_when_handshake_material_changes() {
        let a = transcript_hash(&[1; 32], &[2; 32], &[3; 32], &[4; 32]);
        let b = transcript_hash(&[1; 32], &[2; 32], &[3; 32], &[5; 32]);

        assert_ne!(a, b);
    }
}
