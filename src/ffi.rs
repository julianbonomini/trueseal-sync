// FFI bindings for Swift and Kotlin via UniFFI.
//
// Exposes a thin facade over hush-sync internals. Complex generics (RelayClient<T>)
// are not exposed here — those require a platform-specific transport adapter.
//
// All exported types are wrapped in Arc<> as required by UniFFI for object types.

use std::sync::{Arc, Mutex};

use crate::device::DeviceKeypair;
use crate::keys::NoisePublicKey;
use crate::message;
use crate::revocation::{self, PairedList};

// uniffi::setup_scaffolding!() is called in lib.rs (crate root).

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("invalid pairing payload: {msg}")]
    InvalidPairingPayload { msg: String },
}

// ── HushDevice ────────────────────────────────────────────────────────────────

/// A device's complete keypair identity.
/// Generated once per device install; persist the raw bytes and reconstruct via
/// `HushDevice::from_bytes` (not yet exposed — add when persistence is needed).
#[derive(uniffi::Object)]
pub struct HushDevice {
    inner: DeviceKeypair,
}

#[uniffi::export]
impl HushDevice {
    /// Generate a fresh device keypair.
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        Arc::new(Self {
            inner: DeviceKeypair::generate(),
        })
    }

    /// X25519 noise public key (32 bytes) — the device's relay identity.
    pub fn noise_public_key(&self) -> Vec<u8> {
        self.inner.public_key().0.to_vec()
    }

    /// Ed25519 signing public key (32 bytes) — embedded in Envelopes.
    pub fn signing_public_key(&self) -> Vec<u8> {
        self.inner.signing_public_key().0.to_vec()
    }

    /// Produce a pairing payload (64 bytes) suitable for encoding as a QR code.
    /// The caller is responsible for QR encoding/decoding.
    pub fn pairing_payload(&self) -> Vec<u8> {
        message::pairing_payload(
            &self.inner.public_key().0,
            &self.inner.signing_public_key().0,
        )
    }
}

// ── Pairing ───────────────────────────────────────────────────────────────────

/// The public keys extracted from a scanned pairing payload.
#[derive(uniffi::Record)]
pub struct PairingInfo {
    pub noise_pub: Vec<u8>,
    pub signing_pub: Vec<u8>,
}

/// Decode a pairing payload (from a scanned QR code) into the remote device's keys.
#[uniffi::export]
pub fn decode_pairing_payload(bytes: Vec<u8>) -> Result<PairingInfo, FfiError> {
    let (noise_pub, signing_pub) = message::decode_pairing_payload(&bytes)
        .map_err(|e| FfiError::InvalidPairingPayload { msg: e.to_string() })?;
    Ok(PairingInfo {
        noise_pub: noise_pub.to_vec(),
        signing_pub: signing_pub.to_vec(),
    })
}

// ── HushPairedList ────────────────────────────────────────────────────────────

/// Thread-safe paired device list. Callers update this when pairing or revoking.
#[derive(uniffi::Object)]
pub struct HushPairedList {
    inner: Mutex<PairedList>,
}

#[uniffi::export]
impl HushPairedList {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(PairedList::new()),
        })
    }

    /// Add a device's noise public key (32 bytes) to the trusted list.
    pub fn add(&self, noise_pub: Vec<u8>) {
        if let Ok(key) = noise_pub.as_slice().try_into() as Result<[u8; 32], _> {
            // FFI surface: signing pub not available here; pass zeroed placeholder.
            // This path will be replaced when issue #16 lands.
            self.inner.lock().unwrap().add(
                NoisePublicKey(key),
                crate::keys::SigningPublicKey([0u8; 32]),
            );
        }
    }

    /// Whether `noise_pub` is in the trusted list.
    pub fn contains(&self, noise_pub: Vec<u8>) -> bool {
        if let Ok(key) = noise_pub.as_slice().try_into() as Result<[u8; 32], _> {
            return self.inner.lock().unwrap().contains(&NoisePublicKey(key));
        }
        false
    }

    /// Number of paired devices.
    pub fn len(&self) -> u64 {
        self.inner.lock().unwrap().len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }
}

// ── Revocation ────────────────────────────────────────────────────────────────

/// Process an incoming Revoke from `sender_noise_pub` (32 bytes).
/// If the sender is trusted, clears `list` and returns a fresh `HushDevice`.
/// If the sender is unknown, returns None and leaves `list` unchanged.
#[uniffi::export]
pub fn handle_revoke(
    list: Arc<HushPairedList>,
    sender_noise_pub: Vec<u8>,
) -> Option<Arc<HushDevice>> {
    let key: [u8; 32] = sender_noise_pub.as_slice().try_into().ok()?;
    let new_kp = revocation::handle_revoke(&mut list.inner.lock().unwrap(), &NoisePublicKey(key))?;
    Some(Arc::new(HushDevice { inner: new_kp }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HushDevice::generate produces distinct keypairs.
    #[test]
    fn generate_produces_unique_devices() {
        let a = HushDevice::generate();
        let b = HushDevice::generate();
        assert_ne!(a.noise_public_key(), b.noise_public_key());
    }

    /// Pairing payload round-trips through the FFI layer.
    #[test]
    fn pairing_payload_ffi_round_trips() {
        let device = HushDevice::generate();
        let payload = device.pairing_payload();
        let info = decode_pairing_payload(payload).expect("should decode");
        assert_eq!(info.noise_pub, device.noise_public_key());
        assert_eq!(info.signing_pub, device.signing_public_key());
    }

    /// decode_pairing_payload returns error on short input.
    #[test]
    fn decode_pairing_payload_rejects_short_input() {
        let result = decode_pairing_payload(vec![0u8; 10]);
        assert!(result.is_err());
    }

    /// HushPairedList add/contains/len work correctly.
    #[test]
    fn paired_list_ffi_operations() {
        let list = HushPairedList::new();
        let device = HushDevice::generate();
        let key = device.noise_public_key();

        assert!(!list.contains(key.clone()));
        list.add(key.clone());
        assert!(list.contains(key.clone()));
        assert_eq!(list.len(), 1);
    }

    /// handle_revoke via FFI clears the list and returns a fresh device.
    #[test]
    fn handle_revoke_ffi_clears_list() {
        let device = HushDevice::generate();
        let list = HushPairedList::new();
        list.add(device.noise_public_key());

        let new_device =
            handle_revoke(list.clone(), device.noise_public_key()).expect("revoke should succeed");

        assert!(list.is_empty());
        assert_ne!(new_device.noise_public_key(), device.noise_public_key());
    }

    /// handle_revoke from unknown sender returns None.
    #[test]
    fn handle_revoke_ffi_ignores_unknown_sender() {
        let trusted = HushDevice::generate();
        let stranger = HushDevice::generate();
        let list = HushPairedList::new();
        list.add(trusted.noise_public_key());

        let result = handle_revoke(list.clone(), stranger.noise_public_key());
        assert!(result.is_none());
        assert_eq!(list.len(), 1);
    }
}
