use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::crypto;
use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::version;

// Include the prost-generated types from proto/envelope.proto
mod proto {
    include!(concat!(env!("OUT_DIR"), "/trueseal.sync.v0.rs"));
}

/// The Replay Window (ADR-0031): a message whose signed Sender Timestamp is
/// more than this far behind the receiver's clock is rejected as
/// `unreadable(expired)` and acked. Sixty days — twice the 30-day Relay TTL
/// and the 30-day Outbox expiry (both capped, ADR-0034 §2), so an honest
/// message is never lost to the window and a hostile Relay can never replay
/// a copy after its dedup record has expired.
pub const REPLAY_WINDOW_MS: u64 = 60 * 24 * 60 * 60 * 1000;

/// True when `sender_timestamp_ms` falls outside the Replay Window relative
/// to `now_ms`. Future timestamps are NOT rejected (a fast sender clock
/// still gets through; the dedup record is clamped forward instead,
/// ADR-0034 §2).
pub fn is_expired(sender_timestamp_ms: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(sender_timestamp_ms) > REPLAY_WINDOW_MS
}

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("decode failed: {0}")]
    DecodeFailed(String),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid key length")]
    InvalidKeyLength,
    /// The sealed payload did not open, parse or verify (ADR-0031: all of
    /// these are `unreadable(malformed)` on the receive path).
    #[error("sealed envelope did not open")]
    OpenFailed,
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

/// An Envelope is the wire unit of sync (ADR-0031). The Relay can read only
/// three things: the End-to-End Version, the recipient public key, and the
/// sealed payload. Everything a recipient needs — the author's signing key,
/// the Sequence, the parent hashes, the Sender Timestamp, the message and
/// the signature — is inside the Addressed Encryption.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    /// End-to-End Version (ADR-0022). Plaintext so a Device can reject an
    /// unsupported version before decrypting; 0 on decode means the refused
    /// pre-version format.
    pub version: u32,
    pub recipient_pub: [u8; 32],
    /// Addressed Encryption output: ephemeral_pub || nonce || ciphertext.
    pub payload: Vec<u8>,
}

/// The sealed plaintext inside an Envelope's payload (ADR-0031). None of it
/// is Relay-readable; all of it is signature-covered.
///
/// Wire layout (pinned cross-repo by the SYNC-2 test vectors):
///
/// ```text
/// author_pub (32) || sequence (8 LE) || parents_len (2 LE) || parents (32*n)
///   || sender_timestamp_ms (8 LE, unix) || message (rest) || signature (64)
/// ```
///
/// The signature covers `domain || version || recipient_pub || eph_pub ||
/// <everything above except the signature>`: the End-to-End Version, the
/// recipient key, the ephemeral key and every sealed field (ADR-0031). A
/// blob cannot be re-addressed, re-keyed or have its body swapped without
/// the signature failing.
#[derive(Debug, Clone, PartialEq)]
pub struct SealedContent {
    pub author_pub: [u8; 32],
    pub sequence: u64,
    pub parents: Vec<[u8; 32]>,
    /// Unix milliseconds. A `Sync` message is stamped once at `send()` and
    /// keeps the stamp through every re-seal; a control message is stamped
    /// at each seal (ADR-0034 §2).
    pub sender_timestamp_ms: u64,
    /// The encoded `Message` (type tag + body).
    pub message: Vec<u8>,
    pub signature: [u8; 64],
}

const SIG_LEN: usize = 64;
const PREFIX_FIXED_LEN: usize = 32 + 8 + 2 + 8; // author_pub + sequence + parents_len + timestamp

impl Envelope {
    /// Build, sign and seal a new Envelope (ADR-0031).
    ///
    /// Two-phase: the ephemeral key is generated first so the signature can
    /// bind it; then the sealed plaintext (signature included) is encrypted
    /// with that ephemeral key.
    pub fn build_sealed(
        sequence: u64,
        parents: Vec<[u8; 32]>,
        recipient_pub: NoisePublicKey,
        author_keypair: &SigningKeypair,
        sender_timestamp_ms: u64,
        message: &[u8],
    ) -> Self {
        let (eph_secret, eph_pub) = crypto::ephemeral_keypair();
        let author_pub = author_keypair.public_key_bytes();

        let mut prefix = Vec::with_capacity(PREFIX_FIXED_LEN + parents.len() * 32 + message.len());
        prefix.extend_from_slice(&author_pub);
        prefix.extend_from_slice(&sequence.to_le_bytes());
        prefix.extend_from_slice(&(parents.len() as u16).to_le_bytes());
        for p in &parents {
            prefix.extend_from_slice(p);
        }
        prefix.extend_from_slice(&sender_timestamp_ms.to_le_bytes());
        prefix.extend_from_slice(message);

        let sig = sign(
            &author_keypair.0,
            version::END_TO_END_VERSION,
            &recipient_pub.0,
            &eph_pub,
            &prefix,
        );

        let mut sealed = prefix;
        sealed.extend_from_slice(&sig);

        let payload = crypto::encrypt_with_ephemeral(recipient_pub, &eph_secret, &sealed);
        Self {
            version: version::END_TO_END_VERSION,
            recipient_pub: recipient_pub.0,
            payload,
        }
    }

    /// Open the seal: decrypt with the recipient's private key, parse the
    /// sealed content and verify the author's signature over the full
    /// signing input. Any failure is `OpenFailed` — the receive path maps
    /// all of them to `unreadable(malformed)` (ADR-0034 §3).
    pub fn open_sealed(&self, my_noise_priv: [u8; 32]) -> Result<SealedContent, EnvelopeError> {
        let sealed =
            crypto::decrypt(my_noise_priv, &self.payload).map_err(|_| EnvelopeError::OpenFailed)?;
        if sealed.len() < PREFIX_FIXED_LEN + SIG_LEN {
            return Err(EnvelopeError::OpenFailed);
        }
        let (prefix, sig_bytes) = sealed.split_at(sealed.len() - SIG_LEN);
        let signature: [u8; SIG_LEN] = sig_bytes
            .try_into()
            .expect("invariant: sig_bytes is SIG_LEN by split_at");

        let author_pub: [u8; 32] = prefix[..32]
            .try_into()
            .expect("invariant: prefix.len() >= PREFIX_FIXED_LEN checked above");
        let eph_pub = crypto::ephemeral_pub_of(&self.payload).ok_or(EnvelopeError::OpenFailed)?;

        // Verify BEFORE parsing further: the signature covers the exact
        // prefix bytes, so a tampered field fails here regardless of how it
        // would have parsed. verify_strict: the author key is
        // attacker-controlled bytes, so small-order keys (e.g. all-zero,
        // for which a zero signature satisfies the verification equation)
        // and non-canonical encodings are rejected outright.
        let vk =
            VerifyingKey::from_bytes(&author_pub).map_err(|_| EnvelopeError::InvalidKeyLength)?;
        let msg = signing_message(self.version, &self.recipient_pub, &eph_pub, prefix);
        vk.verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&signature))
            .map_err(|_| EnvelopeError::OpenFailed)?;

        let sequence = u64::from_le_bytes(
            prefix[32..40]
                .try_into()
                .expect("invariant: prefix.len() >= 40"),
        );
        let parents_len = u16::from_le_bytes(
            prefix[40..42]
                .try_into()
                .expect("invariant: prefix.len() >= 42"),
        ) as usize;
        let parents_end = 42 + parents_len * 32;
        if prefix.len() < parents_end + 8 {
            return Err(EnvelopeError::OpenFailed);
        }
        let parents = prefix[42..parents_end].as_chunks::<32>().0.to_vec();
        let sender_timestamp_ms = u64::from_le_bytes(
            prefix[parents_end..parents_end + 8]
                .try_into()
                .expect("invariant: bounds checked above"),
        );
        let message = prefix[parents_end + 8..].to_vec();

        Ok(SealedContent {
            author_pub,
            sequence,
            parents,
            sender_timestamp_ms,
            message,
            signature,
        })
    }

    /// Compute SHA-256 of this Envelope's encoded bytes — used as a parent hash.
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }

    /// Encode to Protobuf bytes.
    pub fn encode(&self) -> Vec<u8> {
        let proto = proto::Envelope {
            version: self.version,
            recipient_pub: self.recipient_pub.to_vec(),
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

        Ok(Self {
            // proto3 defaults a missing field to 0 — the reserved version of
            // the refused pre-version format (ADR-0022).
            version: proto.version,
            recipient_pub,
            payload: proto.payload,
        })
    }
}

/// The canonical signing input (ADR-0031):
/// `domain || version (4 LE) || recipient_pub (32) || eph_pub (32) || sealed prefix`.
/// The domain separator carries the End-to-End Version (ADR-0022) and the
/// version field is itself signed, so neither can be altered in transit;
/// the recipient and ephemeral keys are bound, so the blob cannot be
/// re-addressed or re-keyed; every sealed field is covered.
fn signing_message(
    e2e_version: u32,
    recipient_pub: &[u8; 32],
    eph_pub: &[u8; 32],
    sealed_prefix: &[u8],
) -> Vec<u8> {
    let mut msg = version::envelope_signing_domain();
    msg.extend_from_slice(&e2e_version.to_le_bytes());
    msg.extend_from_slice(recipient_pub);
    msg.extend_from_slice(eph_pub);
    msg.extend_from_slice(sealed_prefix);
    msg
}

fn sign(
    key: &SigningKey,
    e2e_version: u32,
    recipient_pub: &[u8; 32],
    eph_pub: &[u8; 32],
    sealed_prefix: &[u8],
) -> [u8; 64] {
    let msg = signing_message(e2e_version, recipient_pub, eph_pub, sealed_prefix);
    key.sign(&msg).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::NoisePublicKey;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn noise_keypair() -> ([u8; 32], NoisePublicKey) {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        (*secret.as_bytes(), NoisePublicKey(*public.as_bytes()))
    }

    fn make_envelope() -> (Envelope, SigningKeypair, [u8; 32]) {
        let author = SigningKeypair::generate();
        let (recv_priv, recv_pub) = noise_keypair();
        let env = Envelope::build_sealed(1, vec![], recv_pub, &author, 1_700_000_000_000, b"hello");
        (env, author, recv_priv)
    }

    /// Round-trip: seal → open recovers every field.
    #[test]
    fn sealed_envelope_round_trips() {
        let author = SigningKeypair::generate();
        let (recv_priv, recv_pub) = noise_keypair();
        let parents = vec![[0xAB; 32]];
        let env = Envelope::build_sealed(
            7,
            parents.clone(),
            recv_pub,
            &author,
            1_700_000_000_123,
            b"payload",
        );
        let sc = env.open_sealed(recv_priv).expect("opens");
        assert_eq!(sc.author_pub, author.public_key_bytes());
        assert_eq!(sc.sequence, 7);
        assert_eq!(sc.parents, parents);
        assert_eq!(sc.sender_timestamp_ms, 1_700_000_000_123);
        assert_eq!(sc.message, b"payload");
    }

    /// Encode → decode produces an identical Envelope.
    #[test]
    fn envelope_round_trips() {
        let (env, _, _) = make_envelope();
        let decoded = Envelope::decode(&env.encode()).expect("decode should succeed");
        assert_eq!(decoded, env);
    }

    /// Every envelope this build creates carries the End-to-End Version.
    #[test]
    fn built_envelope_carries_the_end_to_end_version() {
        let (env, _, _) = make_envelope();
        assert_eq!(env.version, crate::version::END_TO_END_VERSION);
        let decoded = Envelope::decode(&env.encode()).expect("decode");
        assert_eq!(decoded.version, crate::version::END_TO_END_VERSION);
    }

    /// Re-addressing: swapping the outer recipient_pub fails the signature
    /// AND the key derivation — the blob opens for nobody.
    #[test]
    fn readdressed_envelope_fails() {
        let author = SigningKeypair::generate();
        let (recv_priv, recv_pub) = noise_keypair();
        let (other_priv, other_pub) = noise_keypair();
        let env = Envelope::build_sealed(1, vec![], recv_pub, &author, 1, b"addressed");

        let mut tampered = env.clone();
        tampered.recipient_pub = other_pub.0;
        // The swapped-in "recipient" cannot open it (the payload was sealed
        // to the real recipient's key — wrong DH).
        assert!(tampered.open_sealed(other_priv).is_err());
        // The REAL recipient detects the tamper: the payload still opens,
        // but the signature input names the tampered recipient_pub, so
        // verification fails.
        assert!(
            tampered.open_sealed(recv_priv).is_err(),
            "re-addressing must be detected by the real recipient"
        );
        // Sanity: the untampered envelope opens.
        assert!(env.open_sealed(recv_priv).is_ok());
    }

    /// Ephemeral-swap: replacing the ephemeral key bytes fails.
    #[test]
    fn ephemeral_swapped_envelope_fails() {
        let author = SigningKeypair::generate();
        let (recv_priv, recv_pub) = noise_keypair();
        let mut env = Envelope::build_sealed(1, vec![], recv_pub, &author, 1, b"body");
        let other_eph: [u8; 32] = {
            let s = StaticSecret::random_from_rng(rand::thread_rng());
            *PublicKey::from(&s).as_bytes()
        };
        env.payload[..32].copy_from_slice(&other_eph);
        assert!(env.open_sealed(recv_priv).is_err());
    }

    /// Body-swap: the signature covers the sealed prefix, so a ciphertext
    /// bit-flip fails the AEAD, and any prefix tampering fails verification.
    #[test]
    fn tampered_payload_fails() {
        let (mut env, _, recv_priv) = make_envelope();
        let last = env.payload.len() - 1;
        env.payload[last] ^= 0x01;
        assert!(env.open_sealed(recv_priv).is_err());
    }

    /// The version is signed: a relabelled version fails verification.
    #[test]
    fn tampered_version_fails() {
        let (mut env, _, recv_priv) = make_envelope();
        env.version += 1;
        assert!(
            env.open_sealed(recv_priv).is_err(),
            "a relabelled version must fail verification"
        );
    }

    /// Attribution forgery (#49, sealed form): device B seals content whose
    /// author_pub field claims A, signed by B. open_sealed verifies the
    /// signature under the CLAIMED author key — B's signature over a prefix
    /// naming A does not verify under A's key, so the forgery is rejected.
    #[test]
    fn attribution_forgery_is_rejected() {
        use ed25519_dalek::SigningKey;
        let author_a = SigningKeypair::generate();
        // Build B from raw bytes so the test can sign with B's key directly.
        let b_bytes: [u8; 32] = rand::random();
        let b_signing = SigningKey::from_bytes(&b_bytes);
        let (recv_priv, recv_pub) = noise_keypair();

        // B hand-builds a sealed blob whose prefix names A as the author.
        let (eph_secret, eph_pub) = crypto::ephemeral_keypair();
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&author_a.public_key_bytes()); // claims A
        prefix.extend_from_slice(&1u64.to_le_bytes());
        prefix.extend_from_slice(&0u16.to_le_bytes());
        prefix.extend_from_slice(&1u64.to_le_bytes());
        prefix.extend_from_slice(b"forged");
        let sig = sign(
            &b_signing,
            version::END_TO_END_VERSION,
            &recv_pub.0,
            &eph_pub,
            &prefix,
        );
        let mut sealed = prefix;
        sealed.extend_from_slice(&sig);
        let payload = crypto::encrypt_with_ephemeral(recv_pub, &eph_secret, &sealed);
        let env = Envelope {
            version: version::END_TO_END_VERSION,
            recipient_pub: recv_pub.0,
            payload,
        };

        assert!(
            env.open_sealed(recv_priv).is_err(),
            "B's signature must not verify under A's claimed key"
        );
    }

    /// A zero author key with a zero signature satisfies the naïve
    /// Ed25519 verification equation — the weak-key forgery. verify_strict
    /// rejects the small-order key, so the blob does not open.
    #[test]
    fn weak_author_key_forgery_fails() {
        let (recv_priv, recv_pub) = noise_keypair();
        let mut sealed = Vec::new();
        sealed.extend_from_slice(&[0u8; 32]); // author_pub: the zero key
        sealed.extend_from_slice(&1u64.to_le_bytes());
        sealed.extend_from_slice(&0u16.to_le_bytes());
        sealed.extend_from_slice(&1_700_000_000_000u64.to_le_bytes());
        sealed.extend_from_slice(b"forged");
        sealed.extend_from_slice(&[0u8; 64]); // the zero signature
        let env = Envelope {
            version: version::END_TO_END_VERSION,
            recipient_pub: recv_pub.0,
            payload: crypto::encrypt(recv_pub, &sealed),
        };
        assert!(
            env.open_sealed(recv_priv).is_err(),
            "a small-order author key must be rejected (verify_strict)"
        );
    }

    /// Garbage sealed content (right shape, no valid signature) fails.
    #[test]
    fn garbage_sealed_content_fails() {
        let (recv_priv, recv_pub) = noise_keypair();
        let payload = crypto::encrypt(recv_pub, &[0u8; 200]);
        let env = Envelope {
            version: version::END_TO_END_VERSION,
            recipient_pub: recv_pub.0,
            payload,
        };
        assert!(env.open_sealed(recv_priv).is_err());
    }

    /// Decoding garbage bytes returns an error rather than panicking. An
    /// empty/fieldless proto fails the recipient_pub length check — and a
    /// versionless (pre-version) envelope decodes as version 0, the
    /// reserved refusal (pinned by pre_version_format_decodes_as_version_zero).
    #[test]
    fn garbage_bytes_return_error() {
        assert!(Envelope::decode(b"not protobuf").is_err());
        assert!(Envelope::decode(b"").is_err());
    }

    /// A pre-version-format envelope (no version field on the wire) decodes
    /// with version 0 — the reserved version the receiver refuses.
    #[test]
    fn pre_version_format_decodes_as_version_zero() {
        let (env, _, _) = make_envelope();
        let mut raw = Vec::new();
        prost::encoding::bytes::encode(3, &env.recipient_pub.to_vec(), &mut raw);
        prost::encoding::bytes::encode(6, &env.payload, &mut raw);
        let decoded = Envelope::decode(&raw).expect("old-shape bytes still decode");
        assert_eq!(decoded.version, 0, "absent version field decodes as 0");
    }

    /// Two sends from one device to the SAME recipient share only the
    /// version and the recipient key; to DIFFERENT recipients, only the
    /// version (ADR-0031 Consequences).
    #[test]
    fn two_sends_share_only_version_and_recipient() {
        let author = SigningKeypair::generate();
        let (_pa, pub_a) = noise_keypair();
        let (_pb, pub_b) = noise_keypair();
        let e1 = Envelope::build_sealed(9, vec![], pub_a, &author, 1, b"x");
        let e2 = Envelope::build_sealed(9, vec![], pub_a, &author, 1, b"x");
        let e3 = Envelope::build_sealed(9, vec![], pub_b, &author, 1, b"x");

        // Same recipient: version + recipient match, payload differs.
        assert_eq!(e1.version, e2.version);
        assert_eq!(e1.recipient_pub, e2.recipient_pub);
        assert_ne!(e1.payload, e2.payload);
        // Different recipients: only the version matches.
        assert_eq!(e1.version, e3.version);
        assert_ne!(e1.recipient_pub, e3.recipient_pub);
        assert_ne!(e1.payload, e3.payload);
    }

    /// is_expired boundary: exactly 60 days is inside, 60 days + 1 ms is out.
    #[test]
    fn replay_window_boundary() {
        let now = 1_800_000_000_000u64;
        assert!(!is_expired(now - REPLAY_WINDOW_MS, now));
        assert!(is_expired(now - REPLAY_WINDOW_MS - 1, now));
        assert!(
            !is_expired(now + REPLAY_WINDOW_MS, now),
            "future is accepted"
        );
    }
}
