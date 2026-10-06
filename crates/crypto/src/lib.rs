use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use rand_core::OsRng;
use thiserror::Error;

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
}
