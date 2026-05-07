use ed25519_dalek::SigningKey;
use hush_noise::keypair::{generate_keypair as noise_generate, Keypair as NoiseKeypair};
use rand::thread_rng;

use crate::envelope::SigningKeypair;
use crate::keys::{NoisePublicKey, SigningPublicKey};

/// A device's complete identity — bundles the X25519 keypair (for Noise XX
/// sessions and addressed encryption) with the Ed25519 keypair (for signing
/// Envelopes). Generated once per device, persisted by the caller.
pub struct DeviceKeypair {
    /// X25519 keypair — used for Noise XX handshakes and addressed encryption.
    pub noise: NoiseKeypair,
    /// Ed25519 keypair — used to sign Envelopes.
    pub signing: SigningKey,
}

impl DeviceKeypair {
    /// Generate a fresh DeviceKeypair from a cryptographically secure source.
    pub fn generate() -> Self {
        Self {
            noise: noise_generate(),
            signing: SigningKey::generate(&mut thread_rng()),
        }
    }

    /// Reconstruct a DeviceKeypair from raw private key bytes.
    /// `noise_priv` is 32 bytes (X25519 scalar); `signing_priv` is 32 bytes (Ed25519 seed).
    /// Returns an error if the bytes are invalid.
    pub fn from_bytes(noise_priv: [u8; 32], signing_priv: [u8; 32]) -> Result<Self, &'static str> {
        use hush_noise::keypair::Keypair as NoiseKeypair;
        // Derive the X25519 public key from the private scalar.
        let noise_pub =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(noise_priv));
        let noise = NoiseKeypair::new(noise_priv, noise_pub.to_bytes());
        let signing = SigningKey::from_bytes(&signing_priv);
        Ok(Self { noise, signing })
    }
    pub fn public_key(&self) -> NoisePublicKey {
        NoisePublicKey(self.noise.public_key)
    }

    /// The device's Ed25519 verifying key — embedded in Envelopes as author_pub.
    pub fn signing_public_key(&self) -> SigningPublicKey {
        SigningPublicKey(self.signing.verifying_key().to_bytes())
    }

    /// Wrap the device's Ed25519 signing key as a `SigningKeypair` for use with `Envelope::build`.
    pub fn signing_keypair(&self) -> SigningKeypair {
        // Reconstruct from secret key bytes — ed25519_dalek::SigningKey doesn't impl Clone.
        let secret = self.signing.to_bytes();
        SigningKeypair::from_signing_key(SigningKey::from_bytes(&secret))
    }
}
