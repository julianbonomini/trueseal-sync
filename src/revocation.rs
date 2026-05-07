use crate::device::DeviceKeypair;

/// The set of devices this device trusts — i.e. devices it has paired with.
/// Stored as their noise public keys (X25519). The signing key is used to
/// verify envelope authorship (in RelayClient), so it is not needed here.
pub struct PairedList {
    entries: Vec<[u8; 32]>,
}

impl PairedList {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a device's noise public key to the trusted list.
    pub fn add(&mut self, noise_pub: [u8; 32]) {
        if !self.entries.contains(&noise_pub) {
            self.entries.push(noise_pub);
        }
    }

    /// Whether `noise_pub` is in the trusted list.
    pub fn contains(&self, noise_pub: &[u8; 32]) -> bool {
        self.entries.contains(noise_pub)
    }

    /// Number of paired devices.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries — called on revocation.
    fn clear(&mut self) {
        self.entries.clear();
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
pub fn handle_revoke(list: &mut PairedList, sender_noise_pub: &[u8; 32]) -> Option<DeviceKeypair> {
    if !list.contains(sender_noise_pub) {
        return None;
    }
    list.clear();
    Some(DeviceKeypair::generate())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tracer bullet: a revoke from a trusted sender wipes the list and returns a new keypair.
    #[test]
    fn revoke_from_trusted_sender_clears_list_and_rotates_keypair() {
        let sender = DeviceKeypair::generate();
        let mut list = PairedList::new();
        list.add(sender.noise.public_key);

        let old_pub = sender.noise.public_key;
        let new_kp =
            handle_revoke(&mut list, &old_pub).expect("revoke from trusted sender should succeed");

        assert!(list.is_empty(), "list should be cleared after revoke");
        assert_ne!(
            new_kp.noise.public_key, old_pub,
            "new keypair should differ from the sender's key"
        );
    }

    /// A revoke from an unknown sender is ignored.
    #[test]
    fn revoke_from_unknown_sender_is_ignored() {
        let trusted = DeviceKeypair::generate();
        let stranger = DeviceKeypair::generate();
        let mut list = PairedList::new();
        list.add(trusted.noise.public_key);

        let result = handle_revoke(&mut list, &stranger.noise.public_key);

        assert!(result.is_none(), "revoke from stranger should be ignored");
        assert_eq!(list.len(), 1, "list should be unchanged");
    }

    /// After a revoke, a second revoke from the same sender is ignored
    /// (sender is no longer in the now-empty list).
    #[test]
    fn second_revoke_from_same_sender_is_ignored() {
        let sender = DeviceKeypair::generate();
        let mut list = PairedList::new();
        list.add(sender.noise.public_key);

        let _ = handle_revoke(&mut list, &sender.noise.public_key);
        let result = handle_revoke(&mut list, &sender.noise.public_key);

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
        a_list.add(device_b.noise.public_key);
        b_list.add(device_a.noise.public_key);

        // A initiates revoke: A clears its own list and rotates
        let new_a = handle_revoke(&mut a_list, &device_b.noise.public_key)
            .expect("A should revoke using B's key as authorization signal");

        // B receives the Revoke message (from A) and processes it
        let new_b = handle_revoke(&mut b_list, &device_a.noise.public_key)
            .expect("B should process revoke from A");

        // Both lists are now empty — both devices are isolated
        assert!(a_list.is_empty(), "A's list should be empty");
        assert!(b_list.is_empty(), "B's list should be empty");

        // Both have fresh keypairs distinct from the originals
        assert_ne!(new_a.noise.public_key, device_a.noise.public_key);
        assert_ne!(new_b.noise.public_key, device_b.noise.public_key);
    }
}
