use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

const KEY_INFO: &[u8] = b"ESTRODESK-SESSION-KEY-V1";
const NONCE_SIZE: usize = 12;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("key derivation failed")]
    KeyDerivationFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
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

pub fn derive_session_key(
    shared_secret: &[u8; 32],
    transcript: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(transcript), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(KEY_INFO, &mut key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(key)
}

pub struct SessionCipher {
    cipher: ChaCha20Poly1305,
}

impl SessionCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),
        }
    }

    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.cipher
            .encrypt(Nonce::from_slice(nonce), plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
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
    fn session_keys_match_for_both_peers() {
        let controller = EphemeralKeyExchange::generate();
        let host = EphemeralKeyExchange::generate();
        let shared_a =
            controller.derive_shared_secret(&host.public_key_bytes());
        let shared_b =
            host.derive_shared_secret(&controller.public_key_bytes());

        let transcript = transcript_hash(
            &[1; 32],
            &[2; 32],
            &controller.public_key_bytes(),
            &host.public_key_bytes(),
        );

        assert_eq!(
            derive_session_key(&shared_a, &transcript).unwrap(),
            derive_session_key(&shared_b, &transcript).unwrap()
        );
    }

    #[test]
    fn encrypted_message_round_trips_and_tampering_fails() {
        let key = [7u8; 32];
        let cipher = SessionCipher::new(&key);
        let nonce = [9u8; NONCE_SIZE];
        let plaintext = b"hello from estrodesk";

        let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();
        assert_eq!(
            cipher.decrypt(&nonce, &ciphertext).unwrap(),
            plaintext
        );

        let mut tampered = ciphertext.clone();
        tampered[0] ^= 1;
        assert!(cipher.decrypt(&nonce, &tampered).is_err());
    }
}
