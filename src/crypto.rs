use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::keys::NoisePublicKey;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("decryption failed")]
    DecryptionFailed,
}

// Wire layout: [ephemeral_pub (32)] [nonce (12)] [ciphertext+tag]
const EPH_PUB_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const OVERHEAD: usize = EPH_PUB_LEN + NONCE_LEN;

pub fn encrypt(recipient_pub: NoisePublicKey, author_pub: [u8; 32], plaintext: &[u8]) -> Vec<u8> {
    // Prepend author_pub to plaintext so the relay learns no stable sender identity.
    // The recipient extracts it after decryption.
    let mut inner = Vec::with_capacity(32 + plaintext.len());
    inner.extend_from_slice(&author_pub);
    inner.extend_from_slice(plaintext);
    encrypt_raw(recipient_pub, &inner)
}

fn encrypt_raw(recipient_pub: NoisePublicKey, plaintext: &[u8]) -> Vec<u8> {
    // Generate ephemeral keypair
    let eph_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let eph_public = PublicKey::from(&eph_secret);

    // DH: eph_priv * recipient_pub
    let shared = eph_secret.diffie_hellman(&PublicKey::from(recipient_pub.0));

    // Derive symmetric key via HKDF-SHA256
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"hush-sync addressed encryption v0", &mut key)
        .expect("HKDF expand failed");

    // Encrypt with ChaCha20-Poly1305. Zero nonce is safe here because the
    // symmetric key is derived from an ephemeral DH — it is single-use by
    // construction. Reusing the nonce would only be a problem if the key
    // were reused, which it never is.
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("valid key length");
    let nonce = Nonce::default();
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .expect("encryption failed");

    // Output: ephemeral_pub || nonce || ciphertext+tag
    let mut out = Vec::with_capacity(OVERHEAD + ct.len());
    out.extend_from_slice(eph_public.as_bytes());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    out
}

/// Returns `(author_pub, message_bytes)` on success.
pub fn decrypt(my_priv: [u8; 32], ciphertext: &[u8]) -> Result<([u8; 32], Vec<u8>), CryptoError> {
    let inner = decrypt_raw(my_priv, ciphertext)?;
    if inner.len() < 32 {
        return Err(CryptoError::DecryptionFailed);
    }
    let author_pub: [u8; 32] = inner[..32].try_into().unwrap();
    let message = inner[32..].to_vec();
    Ok((author_pub, message))
}

fn decrypt_raw(my_priv: [u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < OVERHEAD {
        return Err(CryptoError::DecryptionFailed);
    }

    // Parse wire layout
    let eph_pub_bytes: [u8; 32] = ciphertext[..EPH_PUB_LEN].try_into().unwrap();
    let nonce_bytes: [u8; NONCE_LEN] = ciphertext[EPH_PUB_LEN..OVERHEAD].try_into().unwrap();
    let ct = &ciphertext[OVERHEAD..];

    // DH: my_priv * eph_pub
    let secret = StaticSecret::from(my_priv);
    let shared = secret.diffie_hellman(&PublicKey::from(eph_pub_bytes));

    // Derive same symmetric key
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"hush-sync addressed encryption v0", &mut key)
        .expect("HKDF expand failed");

    // Decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("valid key length");
    let nonce = Nonce::from(nonce_bytes);
    cipher
        .decrypt(&nonce, ct)
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

    /// Tracer bullet: encrypt with author_pub embedded; decrypt returns (author_pub, plaintext).
    #[test]
    fn encrypted_blob_with_author_pub_round_trips() {
        let (priv_b, pub_b) = generate_keypair();
        let author_pub = [0x42u8; 32];
        let plaintext = b"hello hush-sync";

        let ciphertext = encrypt(pub_b, author_pub, plaintext);
        let (got_author, got_plain) = decrypt(priv_b, &ciphertext).expect("decryption should succeed");

        assert_eq!(got_author, author_pub);
        assert_eq!(got_plain, plaintext);
    }

    /// Tracer bullet: a blob encrypted to a recipient can be decrypted by that recipient.
    #[test]
    fn encrypted_blob_round_trips() {
        let (priv_b, pub_b) = generate_keypair();
        let author_pub = [0x01u8; 32];
        let plaintext = b"hello hush-sync";

        let ciphertext = encrypt(pub_b, author_pub, plaintext);
        let (_, recovered) = decrypt(priv_b, &ciphertext).expect("decryption should succeed");

        assert_eq!(recovered, plaintext);
    }

    /// Empty plaintext encrypts and decrypts correctly.
    #[test]
    fn empty_plaintext_round_trips() {
        let (priv_b, pub_b) = generate_keypair();
        let author_pub = [0x02u8; 32];

        let ciphertext = encrypt(pub_b, author_pub, b"");
        let (got_author, recovered) = decrypt(priv_b, &ciphertext).expect("empty plaintext should decrypt");

        assert_eq!(got_author, author_pub);
        assert_eq!(recovered, b"");
    }

    /// Large plaintext (1MB) encrypts and decrypts correctly.
    #[test]
    fn large_plaintext_round_trips() {
        let (priv_b, pub_b) = generate_keypair();
        let author_pub = [0x03u8; 32];
        let plaintext = vec![0xabu8; 1024 * 1024];

        let ciphertext = encrypt(pub_b, author_pub, &plaintext);
        let (_, recovered) = decrypt(priv_b, &ciphertext).expect("large plaintext should decrypt");

        assert_eq!(recovered, plaintext);
    }

    /// Decrypting with the wrong private key returns CryptoError::DecryptionFailed.
    #[test]
    fn wrong_key_decrypt_returns_error() {
        let (_priv_a, pub_b) = generate_keypair();
        let (priv_wrong, _pub_wrong) = generate_keypair();

        let ciphertext = encrypt(pub_b, [0x04u8; 32], b"secret");
        let result = decrypt(priv_wrong, &ciphertext);

        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "wrong key should fail"
        );
    }

    /// Truncated ciphertext (too short) returns CryptoError::DecryptionFailed.
    #[test]
    fn truncated_ciphertext_returns_error() {
        let (priv_b, pub_b) = generate_keypair();
        let ciphertext = encrypt(pub_b, [0x05u8; 32], b"secret");
        // Cut off all but the first 4 bytes (less than nonce+tag overhead).
        let truncated = &ciphertext[..4];
        let result = decrypt(priv_b, truncated);

        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "truncated ciphertext should fail"
        );
    }
}
