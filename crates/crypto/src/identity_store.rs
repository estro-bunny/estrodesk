use super::DeviceIdentity;
use thiserror::Error;

const MAGIC: &[u8] = b"ESTRODESK-ID-V1";
const KEY_BYTES: usize = 32;
const STORAGE_BYTES: usize = KEY_BYTES + MAGIC.len();
const KEYRING_SERVICE: &str = "com.estrobunny.estrodesk";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityStorageError {
    #[error("invalid identity data in the credential store")]
    InvalidData,
    #[error("the operating-system credential store is unavailable")]
    CredentialStoreUnavailable,
    #[error("could not save identity to the operating-system credential store")]
    SaveFailed,
}

impl DeviceIdentity {
    /// Encodes the Ed25519 signing seed for an OS-protected local store.
    /// The returned bytes must never be sent to a peer.
    pub fn to_storage_bytes(&self) -> [u8; STORAGE_BYTES] {
        let mut out = [0u8; STORAGE_BYTES];
        out[..MAGIC.len()].copy_from_slice(MAGIC);
        out[MAGIC.len()..].copy_from_slice(&self.signing_key.to_bytes());
        out
    }

    /// Restores an identity from bytes previously produced by to_storage_bytes.
    pub fn from_storage_bytes(
        bytes: &[u8; STORAGE_BYTES],
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

    /// Loads this device's long-lived identity from the operating-system
    /// credential store, creating and saving one on first use.
    ///
    /// This intentionally fails closed: if the credential store cannot be
    /// accessed or written, the caller must not silently fall back to a new
    /// temporary identity, because that would change the device fingerprint.
    pub fn load_or_generate(
        account: &str,
    ) -> Result<Self, IdentityStorageError> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, account)
            .map_err(|_| IdentityStorageError::CredentialStoreUnavailable)?;

        match entry.get_password() {
            Ok(encoded) => {
                let decoded = hex::decode(encoded)
                    .map_err(|_| IdentityStorageError::InvalidData)?;
                let stored: [u8; STORAGE_BYTES] = decoded
                    .try_into()
                    .map_err(|_| IdentityStorageError::InvalidData)?;
                Self::from_storage_bytes(&stored)
            }
            Err(keyring::Error::NoEntry) => {
                let identity = Self::generate();
                let encoded = hex::encode(identity.to_storage_bytes());
                entry
                    .set_password(&encoded)
                    .map_err(|_| IdentityStorageError::SaveFailed)?;
                Ok(identity)
            }
            Err(_) => Err(IdentityStorageError::CredentialStoreUnavailable),
        }
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
