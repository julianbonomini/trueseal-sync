use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::keys::{NoisePublicKey, SigningPublicKey};

// Include the prost-generated types from proto/envelope.proto
mod proto {
    include!(concat!(env!("OUT_DIR"), "/hush.sync.v0.rs"));
}

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("decode failed: {0}")]
    DecodeFailed(String),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid key length")]
    InvalidKeyLength,
}

/// A device's Ed25519 signing keypair, used to sign and verify Envelopes.
pub struct SigningKeypair(SigningKey);

impl SigningKeypair {
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut rand::thread_rng()))
    }

    /// Wrap an existing `SigningKey` — used by `DeviceKeypair::signing_keypair()`.
    pub fn from_signing_key(key: SigningKey) -> Self {
        Self(key)
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Returns the Ed25519 verifying key as a typed `SigningPublicKey`.
    pub fn public_key(&self) -> SigningPublicKey {
        SigningPublicKey(self.0.verifying_key().to_bytes())
    }
}

/// An Envelope is the wire unit of sync. Wraps an encrypted payload with
/// routing metadata the Relay can read, plus a signature only recipients verify.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    pub sequence: u64,
    pub parents: Vec<[u8; 32]>,
    pub recipient_pub: [u8; 32],
    pub author_pub: [u8; 32],
    pub signature: [u8; 64],
    pub payload: Vec<u8>,
}

impl Envelope {
    /// Build and sign a new Envelope.
    pub fn build(
        sequence: u64,
        parents: Vec<[u8; 32]>,
        recipient_pub: NoisePublicKey,
        author_keypair: &SigningKeypair,
        payload: Vec<u8>,
    ) -> Self {
        let author_pub = author_keypair.public_key_bytes();
        let sig_bytes = sign(
            &author_keypair.0,
            sequence,
            &parents,
            &recipient_pub.0,
            &author_pub,
        );
        Self {
            sequence,
            parents,
            recipient_pub: recipient_pub.0,
            author_pub,
            signature: sig_bytes,
            payload,
        }
    }

    /// Compute SHA-256 of this Envelope's encoded bytes — used as a parent hash.
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }

    /// Build a new Envelope chained to `parent`.
    /// Sets `sequence = parent.sequence + 1` and `parents = [parent.hash()]`.
    /// For the standard v0 linear chain; use `Envelope::build` for DAG merges
    /// with multiple parents or root envelopes with sequence 0.
    pub fn build_chained(
        parent: &Envelope,
        recipient_pub: NoisePublicKey,
        author_keypair: &SigningKeypair,
        payload: Vec<u8>,
    ) -> Self {
        Self::build(
            parent.sequence + 1,
            vec![parent.hash()],
            recipient_pub,
            author_keypair,
            payload,
        )
    }

    /// Verify the author signature over the envelope's signed fields.
    /// Called by recipients — never by the Relay.
    pub fn verify(&self) -> Result<(), EnvelopeError> {
        let vk = VerifyingKey::from_bytes(&self.author_pub)
            .map_err(|_| EnvelopeError::InvalidKeyLength)?;
        let msg = signing_message(
            self.sequence,
            &self.parents,
            &self.recipient_pub,
            &self.author_pub,
        );
        let sig = ed25519_dalek::Signature::from_bytes(&self.signature);
        vk.verify(&msg, &sig)
            .map_err(|_| EnvelopeError::InvalidSignature)
    }

    /// Encode to Protobuf bytes.
    pub fn encode(&self) -> Vec<u8> {
        let proto = proto::Envelope {
            sequence: self.sequence,
            parents: self.parents.iter().map(|p| p.to_vec()).collect(),
            recipient_pub: self.recipient_pub.to_vec(),
            author_pub: self.author_pub.to_vec(),
            signature: self.signature.to_vec(),
            payload: self.payload.clone(),
        };
        proto.encode_to_vec()
    }

    /// Decode from Protobuf bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let proto = proto::Envelope::decode(bytes)
            .map_err(|e| EnvelopeError::DecodeFailed(e.to_string()))?;

        let recipient_pub = proto
            .recipient_pub
            .try_into()
            .map_err(|_| EnvelopeError::DecodeFailed("recipient_pub must be 32 bytes".into()))?;
        let author_pub = proto
            .author_pub
            .try_into()
            .map_err(|_| EnvelopeError::DecodeFailed("author_pub must be 32 bytes".into()))?;
        let signature = proto
            .signature
            .try_into()
            .map_err(|_| EnvelopeError::DecodeFailed("signature must be 64 bytes".into()))?;
        let parents = proto
            .parents
            .iter()
            .map(|p| {
                p.as_slice()
                    .try_into()
                    .map_err(|_| EnvelopeError::DecodeFailed("parent hash must be 32 bytes".into()))
            })
            .collect::<Result<Vec<[u8; 32]>, _>>()?;

        Ok(Self {
            sequence: proto.sequence,
            parents,
            recipient_pub,
            author_pub,
            signature,
            payload: proto.payload,
        })
    }
}

/// The canonical message bytes that are signed/verified.
/// sequence (8 LE) || each parent (32) || recipient_pub (32) || author_pub (32)
fn signing_message(
    sequence: u64,
    parents: &[[u8; 32]],
    recipient_pub: &[u8; 32],
    author_pub: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&sequence.to_le_bytes());
    for p in parents {
        msg.extend_from_slice(p);
    }
    msg.extend_from_slice(recipient_pub);
    msg.extend_from_slice(author_pub);
    msg
}

fn sign(
    key: &SigningKey,
    sequence: u64,
    parents: &[[u8; 32]],
    recipient_pub: &[u8; 32],
    author_pub: &[u8; 32],
) -> [u8; 64] {
    let msg = signing_message(sequence, parents, recipient_pub, author_pub);
    key.sign(&msg).to_bytes()
}

/// Compute SHA-256 of an Envelope's encoded bytes — used as a parent hash.
///
/// # Deprecated
/// Use `envelope.hash()` instead.
#[deprecated(since = "0.1.0", note = "Use Envelope::hash() instead")]
pub fn envelope_hash(encoded: &[u8]) -> [u8; 32] {
    Sha256::digest(encoded).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::NoisePublicKey;

    fn make_envelope() -> (Envelope, SigningKeypair) {
        let author = SigningKeypair::generate();
        // Use an arbitrary 32-byte value as a fake noise public key for tests
        let recipient_pub = NoisePublicKey(SigningKeypair::generate().public_key_bytes());
        let payload = b"hello".to_vec();
        let env = Envelope::build(1, vec![], recipient_pub, &author, payload);
        (env, author)
    }

    /// Tracer bullet: encode → decode produces an identical Envelope.
    #[test]
    fn envelope_round_trips() {
        let (env, _) = make_envelope();
        let encoded = env.encode();
        let decoded = Envelope::decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded, env);
    }

    /// A freshly built Envelope has a valid signature.
    #[test]
    fn built_envelope_verifies() {
        let (env, _) = make_envelope();
        env.verify().expect("signature should be valid");
    }

    /// Tampering with any signed field (e.g. sequence) invalidates the signature.
    /// This catches man-in-the-middle modification and messages from unknown senders.
    #[test]
    fn tampered_sequence_fails_verification() {
        let (mut env, _) = make_envelope();
        env.sequence += 1; // tamper with a signed field
        assert!(
            env.verify().is_err(),
            "tampered envelope should fail verification"
        );
    }

    /// Unknown author_pub fails verification —
    /// the signature was made by a different key than claimed.
    #[test]
    fn unknown_author_fails_verification() {
        let (mut env, _) = make_envelope();
        let impostor = SigningKeypair::generate();
        env.author_pub = impostor.public_key_bytes();
        assert!(
            env.verify().is_err(),
            "unknown author should fail verification"
        );
    }

    /// Decoding garbage bytes returns an error rather than panicking.
    #[test]
    fn garbage_bytes_return_error() {
        let result = Envelope::decode(b"not protobuf");
        assert!(result.is_err(), "garbage input should return an error");
    }

    /// Decoding empty bytes returns an error.
    #[test]
    fn empty_bytes_return_error() {
        let result = Envelope::decode(b"");
        assert!(result.is_err(), "empty input should return an error");
    }

    /// Tracer bullet for #11: build_chained sets sequence and parent hash correctly.
    #[test]
    fn build_chained_links_to_parent() {
        let author = SigningKeypair::generate();
        let recipient_pub = NoisePublicKey(SigningKeypair::generate().public_key_bytes());

        let root = Envelope::build(0, vec![], recipient_pub, &author, b"root".to_vec());
        let child = Envelope::build_chained(&root, recipient_pub, &author, b"child".to_vec());

        assert_eq!(child.sequence, 1, "sequence should be parent.sequence + 1");
        assert_eq!(child.parents.len(), 1, "child should have one parent");
        assert_eq!(
            child.parents[0],
            root.hash(),
            "parent hash should match root.hash()"
        );
        assert!(
            child.verify().is_ok(),
            "child should have a valid signature"
        );
    }

    /// A chain of 3 envelopes built with build_chained has correct sequence numbers.
    #[test]
    fn build_chained_three_deep_has_correct_sequences() {
        let author = SigningKeypair::generate();
        let recipient_pub = NoisePublicKey(SigningKeypair::generate().public_key_bytes());

        let e0 = Envelope::build(0, vec![], recipient_pub, &author, b"0".to_vec());
        let e1 = Envelope::build_chained(&e0, recipient_pub, &author, b"1".to_vec());
        let e2 = Envelope::build_chained(&e1, recipient_pub, &author, b"2".to_vec());

        assert_eq!(e0.sequence, 0);
        assert_eq!(e1.sequence, 1);
        assert_eq!(e2.sequence, 2);
        assert_eq!(e2.parents[0], e1.hash());
        assert!(e0.verify().is_ok());
        assert!(e1.verify().is_ok());
        assert!(e2.verify().is_ok());
    }
    #[test]
    fn parents_accepts_zero_one_and_many() {
        let author = SigningKeypair::generate();
        let recipient_pub = NoisePublicKey(SigningKeypair::generate().public_key_bytes());

        // Root: no parents
        let root = Envelope::build(0, vec![], recipient_pub, &author, vec![]);
        assert!(root.verify().is_ok());

        // v0 standard: one parent (use build_chained)
        let child = Envelope::build_chained(&root, recipient_pub, &author, vec![]);
        assert!(child.verify().is_ok());

        // v1 DAG: two parents (merge point) — use build directly
        let other_hash = child.hash();
        let merge = Envelope::build(
            2,
            vec![root.hash(), other_hash],
            recipient_pub,
            &author,
            vec![],
        );
        assert!(merge.verify().is_ok());

        // All round-trip through encode/decode
        for env in [&root, &child, &merge] {
            let decoded = Envelope::decode(&env.encode()).expect("should decode");
            assert_eq!(&decoded, env);
        }
    }
}
