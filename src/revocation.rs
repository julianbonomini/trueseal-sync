use crate::device::DeviceKeypair;
use crate::keys::{NoisePublicKey, SigningPublicKey};

/// An entry in the paired list — associates a device's noise and signing public keys.
#[derive(Clone)]
struct PairedEntry {
    noise_pub: NoisePublicKey,
    signing_pub: SigningPublicKey,
}

/// The set of devices this device trusts — i.e. devices it has paired with.
/// Stores both noise (X25519) and signing (Ed25519) keys so that inbound
/// `Message::Revoke` envelopes (authenticated by signing key) can be mapped
/// back to the sender's noise public key for `handle_revoke`.
pub struct PairedList {
    entries: Vec<PairedEntry>,
}

impl PairedList {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a device to the trusted list by both its noise and signing public keys.
    pub fn add(&mut self, noise_pub: NoisePublicKey, signing_pub: SigningPublicKey) {
        if !self.entries.iter().any(|e| e.noise_pub == noise_pub) {
            self.entries.push(PairedEntry {
                noise_pub,
                signing_pub,
            });
        }
    }

    /// Whether `noise_pub` is in the trusted list.
    pub fn contains(&self, noise_pub: &NoisePublicKey) -> bool {
        self.entries.iter().any(|e| &e.noise_pub == noise_pub)
    }

    /// Look up the noise public key for a given signing public key.
    /// Returns `None` if the signing key is not in the list.
    pub fn noise_pub_for_signing(&self, signing_pub: &[u8; 32]) -> Option<NoisePublicKey> {
        self.entries
            .iter()
            .find(|e| &e.signing_pub.0 == signing_pub)
            .map(|e| e.noise_pub)
    }

    /// Number of paired devices.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries — called on revocation.
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    /// Iterator over all noise public keys in the list.
    pub fn iter(&self) -> impl Iterator<Item = &NoisePublicKey> {
        self.entries.iter().map(|e| &e.noise_pub)
    }
}

impl Default for PairedList {
    fn default() -> Self {
        Self::new()
    }
}

/// Process an incoming Revoke from `sender_noise_pub`.
/// - If the sender is in `list`, wipes `list` and returns a fresh `DeviceKeypair`.
/// - If the sender is NOT in `list`, the revoke is ignored (None returned, list untouched).
///
/// Both sides must call this after a revoke cycle: the sender calls it on
/// itself after pushing `Message::Revoke` to all paired devices.
pub fn handle_revoke(
    list: &mut PairedList,
    sender_noise_pub: &NoisePublicKey,
) -> Option<DeviceKeypair> {
    if !list.contains(sender_noise_pub) {
        return None;
    }
    list.clear();
    Some(DeviceKeypair::generate())
}

/// Process an incoming Revoke identified by the sender's signing key.
/// Looks up the sender's noise public key in `list`, then delegates to `handle_revoke`.
/// Returns a new `DeviceKeypair` if the revoke was accepted, `None` if ignored.
pub fn handle_revoke_by_signing_pub(
    list: &mut PairedList,
    sender_signing_pub: &[u8; 32],
) -> Option<DeviceKeypair> {
    let noise_pub = list.noise_pub_for_signing(sender_signing_pub)?;
    handle_revoke(list, &noise_pub)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tracer bullet: a revoke from a trusted sender wipes the list and returns a new keypair.
    #[test]
    fn revoke_from_trusted_sender_clears_list_and_rotates_keypair() {
        let sender = DeviceKeypair::generate();
        let mut list = PairedList::new();
        list.add(sender.public_key(), sender.signing_public_key());

        let old_pub = sender.public_key();
        let new_kp =
            handle_revoke(&mut list, &old_pub).expect("revoke from trusted sender should succeed");

        assert!(list.is_empty(), "list should be cleared after revoke");
        assert_ne!(
            new_kp.public_key(),
            old_pub,
            "new keypair should differ from the sender's key"
        );
    }

    /// A revoke from an unknown sender is ignored.
    #[test]
    fn revoke_from_unknown_sender_is_ignored() {
        let trusted = DeviceKeypair::generate();
        let stranger = DeviceKeypair::generate();
        let mut list = PairedList::new();
        list.add(trusted.public_key(), trusted.signing_public_key());

        let result = handle_revoke(&mut list, &stranger.public_key());

        assert!(result.is_none(), "revoke from stranger should be ignored");
        assert_eq!(list.len(), 1, "list should be unchanged");
    }

    /// After a revoke, a second revoke from the same sender is ignored
    /// (sender is no longer in the now-empty list).
    #[test]
    fn second_revoke_from_same_sender_is_ignored() {
        let sender = DeviceKeypair::generate();
        let mut list = PairedList::new();
        list.add(sender.public_key(), sender.signing_public_key());

        let _ = handle_revoke(&mut list, &sender.public_key());
        let result = handle_revoke(&mut list, &sender.public_key());

        assert!(result.is_none(), "second revoke should be ignored");
        assert!(list.is_empty());
    }

    /// Integration scenario: A and B are paired. A sends Revoke. Both end up isolated.
    /// (We simulate the message delivery manually — the relay integration is already
    /// covered by relay tests; here we verify the state transitions.)
    #[test]
    fn paired_devices_both_isolated_after_revoke_cycle() {
        let device_a = DeviceKeypair::generate();
        let device_b = DeviceKeypair::generate();

        // Both are paired with each other
        let mut a_list = PairedList::new();
        let mut b_list = PairedList::new();
        a_list.add(device_b.public_key(), device_b.signing_public_key());
        b_list.add(device_a.public_key(), device_a.signing_public_key());

        // A initiates revoke: A clears its own list and rotates
        let new_a = handle_revoke(&mut a_list, &device_b.public_key())
            .expect("A should revoke using B's key as authorization signal");

        // B receives the Revoke message (from A) and processes it
        let new_b = handle_revoke(&mut b_list, &device_a.public_key())
            .expect("B should process revoke from A");

        // Both lists are now empty — both devices are isolated
        assert!(a_list.is_empty(), "A's list should be empty");
        assert!(b_list.is_empty(), "B's list should be empty");

        // Both have fresh keypairs distinct from the originals
        assert_ne!(new_a.public_key(), device_a.public_key());
        assert_ne!(new_b.public_key(), device_b.public_key());
    }

    /// handle_revoke_by_signing_pub accepts a revoke identified by the sender's signing key.
    #[test]
    fn revoke_by_signing_pub_from_trusted_sender() {
        let sender = DeviceKeypair::generate();
        let mut list = PairedList::new();
        list.add(sender.public_key(), sender.signing_public_key());

        let signing_bytes = sender.signing_public_key().0;
        let new_kp = handle_revoke_by_signing_pub(&mut list, &signing_bytes)
            .expect("revoke by signing pub should succeed");

        assert!(list.is_empty());
        assert_ne!(new_kp.public_key(), sender.public_key());
    }

    /// handle_revoke_by_signing_pub from an unknown signing key is ignored.
    #[test]
    fn revoke_by_signing_pub_from_unknown_sender_ignored() {
        let trusted = DeviceKeypair::generate();
        let stranger = DeviceKeypair::generate();
        let mut list = PairedList::new();
        list.add(trusted.public_key(), trusted.signing_public_key());

        let result = handle_revoke_by_signing_pub(&mut list, &stranger.signing_public_key().0);
        assert!(result.is_none());
        assert_eq!(list.len(), 1);
    }
}
