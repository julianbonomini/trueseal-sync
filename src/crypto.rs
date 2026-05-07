use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("decryption failed")]
    DecryptionFailed,
}

// Wire layout: [ephemeral_pub (32)] [nonce (12)] [ciphertext+tag]
const EPH_PUB_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const OVERHEAD: usize = EPH_PUB_LEN + NONCE_LEN;

pub fn encrypt(recipient_pub: [u8; 32], plaintext: &[u8]) -> Vec<u8> {
    // Generate ephemeral keypair
    let eph_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let eph_public = PublicKey::from(&eph_secret);

    // DH: eph_priv * recipient_pub
    let shared = eph_secret.diffie_hellman(&PublicKey::from(recipient_pub));

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

pub fn decrypt(my_priv: [u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
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
    use x25519_dalek::{PublicKey, StaticSecret};

    fn generate_keypair() -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        (*secret.as_bytes(), *public.as_bytes())
    }

    /// Tracer bullet: a blob encrypted to a recipient can be decrypted by that recipient.
    #[test]
    fn encrypted_blob_round_trips() {
        let (priv_b, pub_b) = generate_keypair();
        let plaintext = b"hello hush-sync";

        let ciphertext = encrypt(pub_b, plaintext);
        let recovered = decrypt(priv_b, &ciphertext).expect("decryption should succeed");

        assert_eq!(recovered, plaintext);
    }

    /// Empty plaintext encrypts and decrypts correctly.
    #[test]
    fn empty_plaintext_round_trips() {
        let (priv_b, pub_b) = generate_keypair();

        let ciphertext = encrypt(pub_b, b"");
        let recovered = decrypt(priv_b, &ciphertext).expect("empty plaintext should decrypt");

        assert_eq!(recovered, b"");
    }

    /// Large plaintext (1MB) encrypts and decrypts correctly.
    #[test]
    fn large_plaintext_round_trips() {
        let (priv_b, pub_b) = generate_keypair();
        let plaintext = vec![0xabu8; 1024 * 1024];

        let ciphertext = encrypt(pub_b, &plaintext);
        let recovered = decrypt(priv_b, &ciphertext).expect("large plaintext should decrypt");

        assert_eq!(recovered, plaintext);
    }
}
