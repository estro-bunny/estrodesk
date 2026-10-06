use super::DeviceIdentity;
use thiserror::Error;

const MAGIC: &[u8] = b"ESTRODESK-ID-V1";
const KEY_BYTES: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityStorageError {
    #[error("invalid identity data")]
    InvalidData,
}

impl DeviceIdentity {
    /// Encodes the Ed25519 signing seed for an OS-protected local store.
    /// The returned bytes must never be sent to a peer.
    pub fn to_storage_bytes(&self) -> [u8; KEY_BYTES + MAGIC.len()] {
        let mut out = [0u8; KEY_BYTES + MAGIC.len()];
        out[..MAGIC.len()].copy_from_slice(MAGIC);
        out[MAGIC.len()..].copy_from_slice(&self.signing_key.to_bytes());
        out
    }

    /// Restores an identity from bytes previously produced by to_storage_bytes.
    pub fn from_storage_bytes(
        bytes: &[u8; KEY_BYTES + MAGIC.len()],
    ) -> Result<Self, IdentityStorageError> {
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(IdentityStorageError::InvalidData);
        }

        let mut seed = [0u8; KEY_BYTES];
        seed.copy_from_slice(&bytes[MAGIC.len()..]);
        Ok(Self {
            signing_key: ed25519_dalek::SigningKey::from_bytes(&seed),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_round_trips_without_changing_public_key() {
        let original = DeviceIdentity::generate();
        let stored = original.to_storage_bytes();
        let restored = DeviceIdentity::from_storage_bytes(&stored).unwrap();

        assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn corrupted_storage_is_rejected() {
        let identity = DeviceIdentity::generate();
        let mut stored = identity.to_storage_bytes();
        stored[0] ^= 0xff;

        assert_eq!(
            DeviceIdentity::from_storage_bytes(&stored),
            Err(IdentityStorageError::InvalidData)
        );
    }
}
