use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

const KEY_INFO: &[u8] = b"ESTRODESK-SESSION-KEY-V1";
const DIRECTIONAL_KEY_INFO: &[u8] = b"ESTRODESK-DIRECTIONAL-KEYS-V1";
const NONCE_SIZE: usize = 12;

mod identity_store;
pub use identity_store::IdentityStorageError;

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

#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    signing_key: SigningKey,
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        Self { signing_key: SigningKey::generate(&mut OsRng) }
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
        self.secret.diffie_hellman(&PublicKey::from(*peer_public_key)).to_bytes()
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

pub fn derive_directional_keys(
    shared_secret: &[u8; 32],
    transcript: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(transcript), shared_secret);
    let mut keys = [0u8; 64];
    hk.expand(DIRECTIONAL_KEY_INFO, &mut keys)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    let mut controller_to_host = [0u8; 32];
    let mut host_to_controller = [0u8; 32];
    controller_to_host.copy_from_slice(&keys[..32]);
    host_to_controller.copy_from_slice(&keys[32..]);
    Ok((controller_to_host, host_to_controller))
}

pub struct SessionCipher {
    cipher: ChaCha20Poly1305,
}

impl SessionCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self { cipher: ChaCha20Poly1305::new(key.into()) }
    }

    pub fn encrypt(&self, nonce: &[u8; NONCE_SIZE], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.encrypt_with_aad(nonce, plaintext, &[])
    }

    pub fn encrypt_with_aad(
        &self,
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.cipher
            .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    pub fn decrypt(&self, nonce: &[u8; NONCE_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.decrypt_with_aad(nonce, ciphertext, &[])
    }

    pub fn decrypt_with_aad(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake() -> ([u8; 32], [u8; 32], [u8; 32]) {
        let controller = EphemeralKeyExchange::generate();
        let host = EphemeralKeyExchange::generate();
        let shared = controller.derive_shared_secret(&host.public_key_bytes());
        let transcript = transcript_hash(&[1; 32], &[2; 32], &controller.public_key_bytes(), &host.public_key_bytes());
        let (c2h, h2c) = derive_directional_keys(&shared, &transcript).unwrap();
        (c2h, h2c, transcript)
    }

    #[test]
    fn generated_identity_can_sign_and_verify() {
        let identity = DeviceIdentity::generate();
        let message = b"estrodesk handshake";
        let signature = identity.sign(message);
        assert!(DeviceIdentity::verify(&identity.public_key_bytes(), message, &signature).is_ok());
    }

    #[test]
    fn modified_message_fails_verification() {
        let identity = DeviceIdentity::generate();
        let signature = identity.sign(b"original");
        assert!(DeviceIdentity::verify(&identity.public_key_bytes(), b"modified", &signature).is_err());
    }

    #[test]
    fn both_peers_derive_the_same_shared_secret() {
        let controller = EphemeralKeyExchange::generate();
        let host = EphemeralKeyExchange::generate();
        assert_eq!(controller.derive_shared_secret(&host.public_key_bytes()), host.derive_shared_secret(&controller.public_key_bytes()));
    }

    #[test]
    fn directional_keys_are_distinct() {
        let (c2h, h2c, _) = handshake();
        assert_ne!(c2h, h2c);
    }

    #[test]
    fn session_keys_match_for_both_peers() {
        let (c2h, h2c, _) = handshake();
        assert_ne!(c2h, h2c);
    }

    #[test]
    fn encrypted_message_round_trips_with_aad_and_tampering_fails() {
        let (c2h, _, _) = handshake();
        let cipher = SessionCipher::new(&c2h);
        let nonce = [9u8; NONCE_SIZE];
        let aad = b"sequence:0";
        let plaintext = b"hello from estrodesk";
        let ciphertext = cipher.encrypt_with_aad(&nonce, plaintext, aad).unwrap();
        assert_eq!(cipher.decrypt_with_aad(&nonce, &ciphertext, aad).unwrap(), plaintext);
        assert!(cipher.decrypt_with_aad(&nonce, &ciphertext, b"sequence:1").is_err());
    }
}
