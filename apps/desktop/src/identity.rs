use estrodesk_crypto::{DeviceIdentity, IdentityStorageError};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const IDENTITY_FILE: &str = "identity.bin";

#[derive(Debug)]
pub enum IdentityError {
    Io(io::Error),
    InvalidStorage(IdentityStorageError),
}

impl From<io::Error> for IdentityError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<IdentityStorageError> for IdentityError {
    fn from(error: IdentityStorageError) -> Self {
        Self::InvalidStorage(error)
    }
}

pub fn identity_path(data_dir: &Path) -> PathBuf {
    data_dir.join(IDENTITY_FILE)
}

pub fn load_or_create(data_dir: &Path) -> Result<DeviceIdentity, IdentityError> {
    fs::create_dir_all(data_dir)?;
    let path = identity_path(data_dir);

    match fs::read(&path) {
        Ok(bytes) => {
            let bytes: [u8; 46] = bytes
                .try_into()
                .map_err(|_| IdentityStorageError::InvalidData)?;
            Ok(DeviceIdentity::from_storage_bytes(&bytes)?)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let identity = DeviceIdentity::generate();
            let bytes = identity.to_storage_bytes();
            write_private_file(&path, &bytes)?;
            Ok(identity)
        }
        Err(error) => Err(error.into()),
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), io::Error> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_created_and_then_reused() {
        let dir = std::env::temp_dir().join(format!("estrodesk-identity-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let first = load_or_create(&dir).unwrap();
        let second = load_or_create(&dir).unwrap();
        assert_eq!(first.public_key_bytes(), second.public_key_bytes());

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn identity_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("estrodesk-perms-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let _ = load_or_create(&dir).unwrap();
        let mode = fs::metadata(identity_path(&dir)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }
}
