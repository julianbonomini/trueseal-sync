use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;

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

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
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
        recipient_pub: [u8; 32],
        author_keypair: &SigningKeypair,
        payload: Vec<u8>,
    ) -> Self {
        let author_pub = author_keypair.public_key_bytes();
        let sig_bytes = sign(
            &author_keypair.0,
            sequence,
            &parents,
            &recipient_pub,
            &author_pub,
        );
        Self {
            sequence,
            parents,
            recipient_pub,
            author_pub,
            signature: sig_bytes,
            payload,
        }
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
pub fn envelope_hash(encoded: &[u8]) -> [u8; 32] {
    Sha256::digest(encoded).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_envelope() -> (Envelope, SigningKeypair) {
        let author = SigningKeypair::generate();
        let recipient_pub = SigningKeypair::generate().public_key_bytes();
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

    /// parents accepts 0 entries (root Envelope), 1 (v0 standard), and N (v1 DAG).
    #[test]
    fn parents_accepts_zero_one_and_many() {
        let author = SigningKeypair::generate();
        let recipient_pub = SigningKeypair::generate().public_key_bytes();

        // Root: no parents
        let root = Envelope::build(0, vec![], recipient_pub, &author, vec![]);
        assert!(root.verify().is_ok());

        // v0 standard: one parent
        let parent_hash = envelope_hash(&root.encode());
        let child = Envelope::build(1, vec![parent_hash], recipient_pub, &author, vec![]);
        assert!(child.verify().is_ok());

        // v1 DAG: two parents (merge point)
        let other_hash = envelope_hash(&child.encode());
        let merge = Envelope::build(
            2,
            vec![parent_hash, other_hash],
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
