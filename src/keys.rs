/// The X25519 public key identifying a Device — used for Noise XX sessions
/// and addressed encryption. This is the device's relay identity.
/// Passing a `SigningPublicKey` where a `NoisePublicKey` is expected is a compile error.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct NoisePublicKey(pub [u8; 32]);

impl From<[u8; 32]> for NoisePublicKey {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl From<NoisePublicKey> for [u8; 32] {
    fn from(k: NoisePublicKey) -> Self {
        k.0
    }
}

/// The Ed25519 verifying key identifying a Device — embedded in Envelopes as
/// `author_pub` and used for signature verification.
/// Passing a `NoisePublicKey` where a `SigningPublicKey` is expected is a compile error.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SigningPublicKey(pub [u8; 32]);

impl From<[u8; 32]> for SigningPublicKey {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl From<SigningPublicKey> for [u8; 32] {
    fn from(k: SigningPublicKey) -> Self {
        k.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tracer bullet: NoisePublicKey and SigningPublicKey round-trip through [u8;32].
    #[test]
    fn noise_public_key_round_trips() {
        let bytes = [7u8; 32];
        let key = NoisePublicKey::from(bytes);
        let back: [u8; 32] = key.into();
        assert_eq!(back, bytes);
    }

    /// SigningPublicKey round-trips through [u8;32].
    #[test]
    fn signing_public_key_round_trips() {
        let bytes = [9u8; 32];
        let key = SigningPublicKey::from(bytes);
        let back: [u8; 32] = key.into();
        assert_eq!(back, bytes);
    }

    /// NoisePublicKey and SigningPublicKey are distinct types — the type system
    /// prevents mixing them up (verified at compile time, not runtime).
    #[test]
    fn same_bytes_produce_distinct_types() {
        let bytes = [1u8; 32];
        let noise = NoisePublicKey::from(bytes);
        let signing = SigningPublicKey::from(bytes);
        // Both hold the same bytes but are different types
        assert_eq!(noise.0, signing.0);
        // The line below would be a compile error — that's the point:
        // let _: NoisePublicKey = signing; // does not compile
    }
}
