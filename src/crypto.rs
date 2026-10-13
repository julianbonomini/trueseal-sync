use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::keys::NoisePublicKey;
use crate::version;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("decryption failed")]
    DecryptionFailed,
}

// Wire layout: [ephemeral_pub (32)] [nonce (12)] [ciphertext+tag]
const EPH_PUB_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const OVERHEAD: usize = EPH_PUB_LEN + NONCE_LEN;

/// Generate the ephemeral X25519 keypair for one seal. Used by the
/// Envelope's two-phase seal (ADR-0031): the ephemeral public key is signed
/// BEFORE encrypting, because the signature itself lives inside the
/// ciphertext.
///
/// SINGLE-USE: the ephemeral key derives the AEAD key, and the AEAD nonce
/// is zero — sealing twice with the same ephemeral key reuses a
/// (key, nonce) pair, which breaks ChaCha20-Poly1305 confidentiality.
/// One ephemeral key, one seal, ever.
pub(crate) fn ephemeral_keypair() -> (StaticSecret, [u8; 32]) {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    (secret, *public.as_bytes())
}

/// The ephemeral public key of a sealed blob (the first 32 bytes), if present.
pub fn ephemeral_pub_of(ciphertext: &[u8]) -> Option<[u8; 32]> {
    ciphertext.get(..EPH_PUB_LEN)?.try_into().ok()
}

/// The HKDF-SHA256 info for one seal: the versioned domain string plus the
/// ephemeral and recipient public keys (ADR-0031: both are bound into the
/// key derivation, so a blob re-addressed or re-keyed in transit derives a
/// different key and fails to open).
fn hkdf_info(eph_pub: &[u8; 32], recipient_pub: &[u8; 32]) -> Vec<u8> {
    let mut info = version::addressed_encryption_hkdf_info();
    info.extend_from_slice(eph_pub);
    info.extend_from_slice(recipient_pub);
    info
}

/// The AEAD associated data for one seal: binds the same triple
/// (End-to-End Version, ephemeral key, recipient key) so the ciphertext
/// cannot be re-labelled or re-addressed.
fn aad(eph_pub: &[u8; 32], recipient_pub: &[u8; 32]) -> Vec<u8> {
    let mut aad = version::addressed_encryption_aad();
    aad.extend_from_slice(eph_pub);
    aad.extend_from_slice(recipient_pub);
    aad
}

/// Seal `plaintext` to `recipient_pub` with a fresh ephemeral keypair.
pub fn encrypt(recipient_pub: NoisePublicKey, plaintext: &[u8]) -> Vec<u8> {
    let (eph_secret, _) = ephemeral_keypair();
    encrypt_with_ephemeral(recipient_pub, &eph_secret, plaintext)
}

/// Seal `plaintext` with a caller-supplied ephemeral key. The Envelope uses
/// this for its two-phase seal: sign the ephemeral public key first, then
/// encrypt the sealed plaintext (signature included) with that key.
///
/// SINGLE-USE: see [`ephemeral_keypair`] — one ephemeral key, one seal.
pub(crate) fn encrypt_with_ephemeral(
    recipient_pub: NoisePublicKey,
    eph_secret: &StaticSecret,
    plaintext: &[u8],
) -> Vec<u8> {
    let eph_public = PublicKey::from(eph_secret);
    let eph_pub_bytes = *eph_public.as_bytes();

    // DH: eph_priv * recipient_pub
    let shared = eph_secret.diffie_hellman(&PublicKey::from(recipient_pub.0));

    // Derive the symmetric key via HKDF-SHA256. The info carries the
    // End-to-End Version (ADR-0022), the ephemeral key and the recipient
    // key (ADR-0031): a blob sealed for one (version, eph, recipient)
    // triple can never be opened under another.
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(&hkdf_info(&eph_pub_bytes, &recipient_pub.0), &mut key)
        .expect("HKDF expand failed");

    // Encrypt with ChaCha20-Poly1305. Zero nonce is safe here because the
    // symmetric key is derived from an ephemeral DH — it is single-use by
    // construction. Reusing the nonce would only be a problem if the key
    // were reused, which it never is.
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("valid key length");
    let nonce = Nonce::default();
    let ct = cipher
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: &aad(&eph_pub_bytes, &recipient_pub.0),
            },
        )
        .expect("encryption failed");

    // Output: ephemeral_pub || nonce || ciphertext+tag
    let mut out = Vec::with_capacity(OVERHEAD + ct.len());
    out.extend_from_slice(&eph_pub_bytes);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    out
}

/// Open a sealed blob. Returns the plaintext on success.
pub fn decrypt(my_priv: [u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < OVERHEAD {
        return Err(CryptoError::DecryptionFailed);
    }

    // Parse wire layout
    let eph_pub_bytes: [u8; 32] = ciphertext[..EPH_PUB_LEN]
        .try_into()
        .expect("invariant: ciphertext.len() >= OVERHEAD checked above");
    let nonce_bytes: [u8; NONCE_LEN] = ciphertext[EPH_PUB_LEN..OVERHEAD]
        .try_into()
        .expect("invariant: ciphertext.len() >= OVERHEAD checked above");
    let ct = &ciphertext[OVERHEAD..];

    // DH: my_priv * eph_pub
    let secret = StaticSecret::from(my_priv);
    let my_pub = *PublicKey::from(&secret).as_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(eph_pub_bytes));

    // Derive the same symmetric key (version + ephemeral + recipient bound
    // into the info, ADR-0031). The recipient key in the derivation is MY
    // public key — a blob re-addressed after sealing derives a different
    // key for the real recipient and fails to open for me.
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(&hkdf_info(&eph_pub_bytes, &my_pub), &mut key)
        .expect("HKDF expand failed");

    // Decrypt (version + ephemeral + recipient bound into the AAD).
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("valid key length");
    let nonce = Nonce::from(nonce_bytes);
    cipher
        .decrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: ct,
                aad: &aad(&eph_pub_bytes, &my_pub),
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::NoisePublicKey;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn generate_keypair() -> ([u8; 32], NoisePublicKey) {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        (*secret.as_bytes(), NoisePublicKey(*public.as_bytes()))
    }

    /// Tracer bullet: a blob sealed to a recipient opens for that recipient.
    #[test]
    fn sealed_blob_round_trips() {
        let (priv_b, pub_b) = generate_keypair();
        let plaintext = b"hello trueseal-sync";

        let ciphertext = encrypt(pub_b, plaintext);
        let recovered = decrypt(priv_b, &ciphertext).expect("decryption should succeed");

        assert_eq!(recovered, plaintext);
    }

    /// Empty plaintext seals and opens correctly.
    #[test]
    fn empty_plaintext_round_trips() {
        let (priv_b, pub_b) = generate_keypair();
        let ciphertext = encrypt(pub_b, b"");
        let recovered = decrypt(priv_b, &ciphertext).expect("empty plaintext should open");
        assert_eq!(recovered, b"");
    }

    /// Large plaintext (1MB) seals and opens correctly.
    #[test]
    fn large_plaintext_round_trips() {
        let (priv_b, pub_b) = generate_keypair();
        let plaintext = vec![0xabu8; 1024 * 1024];

        let ciphertext = encrypt(pub_b, &plaintext);
        let recovered = decrypt(priv_b, &ciphertext).expect("large plaintext should open");

        assert_eq!(recovered, plaintext);
    }

    /// Opening with the wrong private key returns CryptoError::DecryptionFailed.
    #[test]
    fn wrong_key_decrypt_returns_error() {
        let (_priv_a, pub_b) = generate_keypair();
        let (priv_wrong, _pub_wrong) = generate_keypair();

        let ciphertext = encrypt(pub_b, b"secret");
        let result = decrypt(priv_wrong, &ciphertext);

        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "wrong key should fail"
        );
    }

    /// ADR-0031: the recipient key is bound into the key derivation. A blob
    /// sealed to B, re-addressed by swapping the OUTER routing field, still
    /// carries B in its KDF — but the sharper check is the inverse: sealing
    /// the same plaintext to A and to B must produce blobs that do not open
    /// cross-recipient even though the plaintext is identical.
    #[test]
    fn blob_sealed_to_one_recipient_does_not_open_for_another() {
        let (priv_a, pub_a) = generate_keypair();
        let (priv_b, pub_b) = generate_keypair();
        let plaintext = b"same body, two recipients";

        let ct_a = encrypt(pub_a, plaintext);
        let ct_b = encrypt(pub_b, plaintext);

        assert!(decrypt(priv_a, &ct_a).is_ok());
        assert!(decrypt(priv_b, &ct_b).is_ok());
        assert!(
            decrypt(priv_a, &ct_b).is_err(),
            "B's blob must not open for A"
        );
        assert!(
            decrypt(priv_b, &ct_a).is_err(),
            "A's blob must not open for B"
        );
    }

    /// ADR-0031: the ephemeral key is bound into the AAD. Swapping the
    /// ephemeral public key bytes in transit fails the AEAD check (and the
    /// DH), it does not just decrypt to garbage.
    #[test]
    fn ephemeral_swap_fails() {
        let (priv_b, pub_b) = generate_keypair();
        let mut ciphertext = encrypt(pub_b, b"secret");
        let other_eph: [u8; 32] = {
            let s = StaticSecret::random_from_rng(rand::thread_rng());
            *PublicKey::from(&s).as_bytes()
        };
        ciphertext[..EPH_PUB_LEN].copy_from_slice(&other_eph);

        assert!(
            matches!(
                decrypt(priv_b, &ciphertext),
                Err(CryptoError::DecryptionFailed)
            ),
            "an ephemeral-swapped blob must fail"
        );
    }

    /// Two seals of the same plaintext to the same recipient share nothing
    /// but the layout: the ephemeral key (and so the whole blob) differs.
    #[test]
    fn two_seals_share_no_bytes() {
        let (_priv_b, pub_b) = generate_keypair();
        let a = encrypt(pub_b, b"same");
        let b = encrypt(pub_b, b"same");
        assert_ne!(a, b, "fresh ephemeral per seal");
        assert_ne!(
            ephemeral_pub_of(&a),
            ephemeral_pub_of(&b),
            "ephemeral keys differ"
        );
    }

    /// A blob sealed under the LEGACY scheme (version-bound info and AAD
    /// WITHOUT the ephemeral and recipient keys — the pre-ADR-0031 format)
    /// must fail to open now. Pins the ADR-0031 binding in the scheme
    /// itself: reverting hkdf_info/aad to the version-only strings makes
    /// this test fail even though round-trips would still pass. Stopgap
    /// until the SYNC-2 JSON test vectors pin the bytes cross-repo.
    #[test]
    fn legacy_version_only_binding_fails_to_open() {
        let (priv_b, pub_b) = generate_keypair();
        let plaintext = b"sealed before the keys were bound";

        // Reproduce the legacy seal, self-contained: ephemeral DH, HKDF with
        // the version-only info string, AEAD with the version-only AAD.
        let eph_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let eph_public = PublicKey::from(&eph_secret);
        let shared = eph_secret.diffie_hellman(&PublicKey::from(pub_b.0));
        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(&version::addressed_encryption_hkdf_info(), &mut key)
            .expect("HKDF expand failed");
        let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("valid key length");
        let nonce = Nonce::default();
        let ct = cipher
            .encrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: &version::addressed_encryption_aad(),
                },
            )
            .expect("encryption");
        let mut legacy_blob = Vec::new();
        legacy_blob.extend_from_slice(eph_public.as_bytes());
        legacy_blob.extend_from_slice(nonce.as_slice());
        legacy_blob.extend_from_slice(&ct);

        assert!(
            matches!(
                decrypt(priv_b, &legacy_blob),
                Err(CryptoError::DecryptionFailed)
            ),
            "a blob sealed without the ephemeral/recipient binding must not open"
        );
    }

    /// A blob sealed under the LEGACY-unversioned scheme (the pre-ADR-0022
    /// `trueseal-sync addressed encryption v0` info, no AAD) must also fail.
    #[test]
    fn legacy_unversioned_blob_fails_to_decrypt() {
        let (priv_b, pub_b) = generate_keypair();
        let plaintext = b"sealed before versions existed";

        let eph_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let eph_public = PublicKey::from(&eph_secret);
        let shared = eph_secret.diffie_hellman(&PublicKey::from(pub_b.0));
        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(b"trueseal-sync addressed encryption v0", &mut key)
            .expect("HKDF expand failed");
        let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("valid key length");
        let nonce = Nonce::default();
        let ct = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .expect("encryption");
        let mut legacy_blob = Vec::new();
        legacy_blob.extend_from_slice(eph_public.as_bytes());
        legacy_blob.extend_from_slice(nonce.as_slice());
        legacy_blob.extend_from_slice(&ct);

        assert!(
            matches!(
                decrypt(priv_b, &legacy_blob),
                Err(CryptoError::DecryptionFailed)
            ),
            "a blob sealed under the legacy v0 scheme must not open"
        );
    }

    /// Truncated ciphertext (too short) returns CryptoError::DecryptionFailed.
    #[test]
    fn truncated_ciphertext_returns_error() {
        let (priv_b, pub_b) = generate_keypair();
        let ciphertext = encrypt(pub_b, b"secret");
        let truncated = &ciphertext[..4];
        let result = decrypt(priv_b, truncated);

        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "truncated ciphertext should fail"
        );
    }

    /// Sealing with a caller-supplied ephemeral key exposes that key on the
    /// wire (the two-phase seal signs it before encrypting).
    #[test]
    fn seal_with_ephemeral_carries_that_ephemeral_key() {
        let (_priv, pub_b) = generate_keypair();
        let (eph, eph_pub) = ephemeral_keypair();
        let ct = encrypt_with_ephemeral(pub_b, &eph, b"two-phase");
        assert_eq!(ephemeral_pub_of(&ct), Some(eph_pub));
    }
}
