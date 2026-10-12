use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::version;

// Include the prost-generated types from proto/envelope.proto
mod proto {
    include!(concat!(env!("OUT_DIR"), "/trueseal.sync.v0.rs"));
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
/// author_pub is NOT in the clear header — it is embedded inside the encrypted
/// payload so the relay learns no stable sender identity (ADR-0018 / #49).
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    /// End-to-End Version (ADR-0022). Signed, and readable by the Relay.
    /// Always `version::END_TO_END_VERSION` on envelopes this build creates;
    /// 0 on decode means the refused pre-version format.
    pub version: u32,
    pub sequence: u64,
    pub parents: Vec<[u8; 32]>,
    pub recipient_pub: [u8; 32],
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
        let sig_bytes = sign(
            &author_keypair.0,
            version::END_TO_END_VERSION,
            sequence,
            &parents,
            &recipient_pub.0,
            &payload,
        );
        Self {
            version: version::END_TO_END_VERSION,
            sequence,
            parents,
            recipient_pub: recipient_pub.0,
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

    /// Verify the author signature using the author_pub extracted from the
    /// decrypted payload. Called by recipients after decryption — never by the Relay.
    /// Signing message: domain || version || sequence || parents || recipient_pub || ciphertext.
    pub fn verify_with(&self, author_pub: [u8; 32]) -> Result<(), EnvelopeError> {
        let vk =
            VerifyingKey::from_bytes(&author_pub).map_err(|_| EnvelopeError::InvalidKeyLength)?;
        let msg = signing_message(
            self.version,
            self.sequence,
            &self.parents,
            &self.recipient_pub,
            &self.payload,
        );
        let sig = ed25519_dalek::Signature::from_bytes(&self.signature);
        vk.verify(&msg, &sig)
            .map_err(|_| EnvelopeError::InvalidSignature)
    }

    /// Encode to Protobuf bytes.
    pub fn encode(&self) -> Vec<u8> {
        let proto = proto::Envelope {
            version: self.version,
            sequence: self.sequence,
            parents: self.parents.iter().map(|p| p.to_vec()).collect(),
            recipient_pub: self.recipient_pub.to_vec(),
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
            // proto3 defaults a missing field to 0 — the reserved version of
            // the refused pre-version format (ADR-0022).
            version: proto.version,
            sequence: proto.sequence,
            parents,
            recipient_pub,
            signature,
            payload: proto.payload,
        })
    }
}

/// The canonical message bytes that are signed/verified.
/// domain || version (4 LE) || sequence (8 LE) || each parent (32) || recipient_pub (32) || ciphertext
/// The domain separator carries the End-to-End Version (ADR-0022), and the
/// version field is itself signed, so neither can be altered in transit.
fn signing_message(
    e2e_version: u32,
    sequence: u64,
    parents: &[[u8; 32]],
    recipient_pub: &[u8; 32],
    payload: &[u8],
) -> Vec<u8> {
    let mut msg = version::envelope_signing_domain();
    msg.extend_from_slice(&e2e_version.to_le_bytes());
    msg.extend_from_slice(&sequence.to_le_bytes());
    for p in parents {
        msg.extend_from_slice(p);
    }
    msg.extend_from_slice(recipient_pub);
    msg.extend_from_slice(payload);
    msg
}

fn sign(
    key: &SigningKey,
    e2e_version: u32,
    sequence: u64,
    parents: &[[u8; 32]],
    recipient_pub: &[u8; 32],
    payload: &[u8],
) -> [u8; 64] {
    let msg = signing_message(e2e_version, sequence, parents, recipient_pub, payload);
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
        let (env, author) = make_envelope();
        env.verify_with(author.public_key_bytes())
            .expect("signature should be valid");
    }

    /// Tampering with any signed field (e.g. sequence) invalidates the signature.
    #[test]
    fn tampered_sequence_fails_verification() {
        let (mut env, author) = make_envelope();
        env.sequence += 1;
        assert!(
            env.verify_with(author.public_key_bytes()).is_err(),
            "tampered envelope should fail verification"
        );
    }

    /// verify_with a wrong key fails — the signature was made by a different key.
    #[test]
    fn wrong_author_key_fails_verification() {
        let (env, _) = make_envelope();
        let impostor = SigningKeypair::generate();
        assert!(
            env.verify_with(impostor.public_key_bytes()).is_err(),
            "wrong author key should fail verification"
        );
    }

    /// Attribution forgery (#49): device B signs an envelope whose ciphertext encodes
    /// author_pub = A. Recipient decrypts → gets author_pub = A → verifies B's sig
    /// using A's key → FAILS. The relay cannot fake sender identity.
    #[test]
    fn attribution_forgery_is_rejected() {
        use crate::crypto;
        use x25519_dalek::{PublicKey, StaticSecret};

        // Device A — the claimed sender
        let author_a = SigningKeypair::generate();

        // Device B — the actual signer (the forger)
        let author_b = SigningKeypair::generate();

        // Recipient noise keypair
        let recv_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let recv_pub = NoisePublicKey(*PublicKey::from(&recv_secret).as_bytes());
        let recv_priv = *recv_secret.as_bytes();

        // B encrypts a payload that claims author_pub = A
        let plaintext = b"forged message";
        let payload = crypto::encrypt(recv_pub, author_a.public_key_bytes(), plaintext);

        // B builds and signs the envelope over the ciphertext
        let env = Envelope::build(1, vec![], recv_pub, &author_b, payload);

        // Recipient decrypts → extracts author_pub = A
        let (extracted_author, _msg) =
            crypto::decrypt(recv_priv, &env.payload).expect("decryption should succeed");
        assert_eq!(
            extracted_author,
            author_a.public_key_bytes(),
            "extracted author_pub should be A's key"
        );

        // Verify using A's key — must FAIL because B signed, not A
        assert!(
            env.verify_with(extracted_author).is_err(),
            "B's signature must not verify under A's key"
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
            child.verify_with(author.public_key_bytes()).is_ok(),
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
        assert!(e0.verify_with(author.public_key_bytes()).is_ok());
        assert!(e1.verify_with(author.public_key_bytes()).is_ok());
        assert!(e2.verify_with(author.public_key_bytes()).is_ok());
    }
    #[test]
    fn parents_accepts_zero_one_and_many() {
        let author = SigningKeypair::generate();
        let recipient_pub = NoisePublicKey(SigningKeypair::generate().public_key_bytes());

        // Root: no parents
        let root = Envelope::build(0, vec![], recipient_pub, &author, vec![]);
        assert!(root.verify_with(author.public_key_bytes()).is_ok());

        // v0 standard: one parent (use build_chained)
        let child = Envelope::build_chained(&root, recipient_pub, &author, vec![]);
        assert!(child.verify_with(author.public_key_bytes()).is_ok());

        // v1 DAG: two parents (merge point) — use build directly
        let other_hash = child.hash();
        let merge = Envelope::build(
            2,
            vec![root.hash(), other_hash],
            recipient_pub,
            &author,
            vec![],
        );
        assert!(merge.verify_with(author.public_key_bytes()).is_ok());

        // All round-trip through encode/decode
        for env in [&root, &child, &merge] {
            let decoded = Envelope::decode(&env.encode()).expect("should decode");
            assert_eq!(&decoded, env);
        }
    }

    /// Tampering with the payload invalidates the signature — the relay is zero-trust.
    #[test]
    fn tampered_payload_fails_verification() {
        let (mut env, author) = make_envelope();
        env.payload = b"swapped payload".to_vec();
        assert!(
            env.verify_with(author.public_key_bytes()).is_err(),
            "tampered payload should fail verification"
        );
    }

    // ── SYNC-1: End-to-End Version binding (ADR-0022) ─────────────────────────

    /// Every envelope this build creates carries the End-to-End Version.
    #[test]
    fn built_envelope_carries_the_end_to_end_version() {
        let (env, _) = make_envelope();
        assert_eq!(env.version, crate::version::END_TO_END_VERSION);
        // ... through encode/decode too.
        let decoded = Envelope::decode(&env.encode()).expect("decode");
        assert_eq!(decoded.version, crate::version::END_TO_END_VERSION);
    }

    /// The version field is signed: tampering with it invalidates the
    /// signature, so it cannot be altered in transit.
    #[test]
    fn tampered_version_fails_verification() {
        let (mut env, author) = make_envelope();
        env.version += 1;
        assert!(
            env.verify_with(author.public_key_bytes()).is_err(),
            "a relabelled version must fail verification"
        );
    }

    /// A pre-version-format envelope (no version field on the wire) decodes
    /// with version 0 — the reserved version the receiver refuses.
    #[test]
    fn pre_version_format_decodes_as_version_zero() {
        // Hand-encode the old shape: same fields, version field absent.
        // prost omits zero-valued scalar fields, so any envelope whose proto
        // encoding lacks field 7 decodes with version 0.
        let (env, _) = make_envelope();
        let mut raw = Vec::new();
        // sequence (field 1) omitted — defaults to 0, like the old format.
        prost::encoding::bytes::encode(3, &env.recipient_pub.to_vec(), &mut raw);
        prost::encoding::bytes::encode(5, &env.signature.to_vec(), &mut raw);
        prost::encoding::bytes::encode(6, &env.payload, &mut raw);
        let decoded = Envelope::decode(&raw).expect("old-format bytes still decode");
        assert_eq!(
            decoded.version, 0,
            "absent version field decodes as 0 (reserved)"
        );
    }
}
