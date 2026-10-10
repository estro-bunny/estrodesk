use crate::trust::{TrustError, TrustStatus, TrustStore, TrustedDevice};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const TRUST_FILE: &str = "trusted-devices.json";
const VERSION: u16 = 1;

#[derive(Debug)]
pub enum PersistentTrustError { Io(io::Error), InvalidData, Trust(TrustError), Serialization(String) }
impl From<io::Error> for PersistentTrustError { fn from(error: io::Error) -> Self { Self::Io(error) } }
impl From<TrustError> for PersistentTrustError { fn from(error: TrustError) -> Self { Self::Trust(error) } }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredDevice { public_key: String, device_name: String, status: String }
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredTrustStore { version: u16, devices: Vec<StoredDevice> }

pub fn trust_path(data_dir: &Path) -> PathBuf { data_dir.join(TRUST_FILE) }

pub fn load(data_dir: &Path) -> Result<TrustStore, PersistentTrustError> {
    let path = trust_path(data_dir);
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(TrustStore::new()),
        Err(error) => return Err(error.into()),
    };
    let stored: StoredTrustStore = serde_json::from_str(&contents).map_err(|error| PersistentTrustError::Serialization(error.to_string()))?;
    if stored.version != VERSION { return Err(PersistentTrustError::InvalidData); }

    let mut store = TrustStore::new();
    for device in stored.devices {
        let decoded = hex::decode(device.public_key).map_err(|_| PersistentTrustError::InvalidData)?;
        let public_key: [u8; 32] = decoded.try_into().map_err(|_| PersistentTrustError::InvalidData)?;
        let status = match device.status.as_str() { "trusted" => TrustStatus::Trusted, "revoked" => TrustStatus::Revoked, _ => return Err(PersistentTrustError::InvalidData) };
        store.insert_loaded(TrustedDevice { public_key, device_name: device.device_name, status })?;
    }
    Ok(store)
}

pub fn save(data_dir: &Path, store: &TrustStore) -> Result<(), PersistentTrustError> {
    fs::create_dir_all(data_dir)?;
    let devices = store.devices().map(|device| StoredDevice {
        public_key: hex::encode(device.public_key),
        device_name: device.device_name.clone(),
        status: match device.status { TrustStatus::Trusted => "trusted", TrustStatus::Revoked => "revoked" }.into(),
    }).collect();
    let payload = StoredTrustStore { version: VERSION, devices };
    let json = serde_json::to_string_pretty(&payload).map_err(|error| PersistentTrustError::Serialization(error.to_string()))?;

    // Never replace the live trust store with a partially-written file. Write the
    // complete payload beside it, flush it, then atomically rename it into place.
    let path = trust_path(data_dir);
    let temp_path = data_dir.join(format!(".{TRUST_FILE}.tmp-{}", std::process::id()));
    let result = (|| -> Result<(), io::Error> {
        use std::io::Write;
        let mut file = fs::File::create(&temp_path)?;
        file.write_all(format!("{json}\n").as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp_path, &path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_store_loads_empty_and_round_trips() {
        let dir = std::env::temp_dir().join(format!("estrodesk-trust-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut store = load(&dir).unwrap();
        let key = [42u8; 32];
        store.trust(key, "Bunni PC").unwrap();
        store.revoke(&key).unwrap();
        save(&dir, &store).unwrap();
        let restored = load(&dir).unwrap();
        assert_eq!(restored.status(&key), Some(TrustStatus::Revoked));
        let temp = dir.join(format!(".{TRUST_FILE}.tmp-{}", std::process::id()));
        assert!(!temp.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
