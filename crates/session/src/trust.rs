use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStatus { Trusted, Revoked }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedDevice { pub public_key: [u8; 32], pub device_name: String, pub status: TrustStatus }

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustError {
    #[error("device is already known")] AlreadyKnown,
    #[error("device is not known")] UnknownDevice,
}

#[derive(Debug, Default)]
pub struct TrustStore { devices: BTreeMap<[u8; 32], TrustedDevice> }

impl TrustStore {
    pub fn new() -> Self { Self::default() }

    /// Adds a device only after the caller has obtained explicit user approval.
    pub fn trust(&mut self, public_key: [u8; 32], device_name: impl Into<String>) -> Result<(), TrustError> {
        if self.devices.contains_key(&public_key) { return Err(TrustError::AlreadyKnown); }
        self.devices.insert(public_key, TrustedDevice { public_key, device_name: device_name.into(), status: TrustStatus::Trusted });
        Ok(())
    }

    pub(crate) fn insert_loaded(&mut self, device: TrustedDevice) -> Result<(), TrustError> {
        if self.devices.insert(device.public_key, device).is_some() { return Err(TrustError::AlreadyKnown); }
        Ok(())
    }

    pub fn devices(&self) -> impl Iterator<Item = &TrustedDevice> { self.devices.values() }
    pub fn status(&self, public_key: &[u8; 32]) -> Option<TrustStatus> { self.devices.get(public_key).map(|d| d.status) }
    pub fn is_trusted(&self, public_key: &[u8; 32]) -> bool { self.status(public_key) == Some(TrustStatus::Trusted) }

    pub fn revoke(&mut self, public_key: &[u8; 32]) -> Result<(), TrustError> {
        let device = self.devices.get_mut(public_key).ok_or(TrustError::UnknownDevice)?;
        device.status = TrustStatus::Revoked;
        Ok(())
    }

    pub fn forget(&mut self, public_key: &[u8; 32]) -> Result<(), TrustError> {
        self.devices.remove(public_key).ok_or(TrustError::UnknownDevice)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn trusted_device_requires_explicit_add() { let mut store = TrustStore::new(); let key = [7u8; 32]; assert!(!store.is_trusted(&key)); store.trust(key, "Bunni PC").unwrap(); assert!(store.is_trusted(&key)); }
    #[test] fn duplicate_trust_is_rejected() { let mut store = TrustStore::new(); let key = [8u8; 32]; store.trust(key, "Bunni PC").unwrap(); assert_eq!(store.trust(key, "Again"), Err(TrustError::AlreadyKnown)); }
    #[test] fn revoked_device_cannot_remain_trusted() { let mut store = TrustStore::new(); let key = [9u8; 32]; store.trust(key, "Bunni PC").unwrap(); store.revoke(&key).unwrap(); assert!(!store.is_trusted(&key)); assert_eq!(store.status(&key), Some(TrustStatus::Revoked)); }
    #[test] fn forgetting_removes_device() { let mut store = TrustStore::new(); let key = [10u8; 32]; store.trust(key, "Bunni PC").unwrap(); store.forget(&key).unwrap(); assert_eq!(store.status(&key), None); }
}
