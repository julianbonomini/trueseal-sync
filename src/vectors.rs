//! SYNC-2 (#94): the Sync JSON test vectors (ADR-0022, release gate G5).
//!
//! One checked-in file — `docs/test-vectors/sync-v1.json` — pins the preview
//! wire format byte-for-byte so the relay (Go, RELAY-5) and the three SDKs
//! (SDK-2) can prove they agree with the Rust core instead of inferring
//! compatibility from package versions. The consumption contract lives in
//! `docs/test-vectors/README.md`.
//!
//! Everything here is generated from the real code paths with fixed inputs —
//! never hand-written bytes:
//!
//! - keys are fixed 32-byte seeds (Ed25519, X25519 and the AEAD are all
//!   deterministic, so fixed inputs give fixed wire bytes);
//! - the sealed envelope uses [`Envelope::build_sealed_with_ephemeral`] with
//!   a fixed ephemeral key (single-use invariant respected: one ephemeral,
//!   one seal — the standalone encryption vector uses a second fixed key);
//! - signing inputs come from the same functions the signer calls
//!   ([`crate::envelope::signing_message`],
//!   [`crate::manifest::signing_message_for`]) and the sealed prefix is the
//!   decrypted payload itself, not a reconstruction;
//! - frames come from [`crate::relay::frame`] and the push blob from
//!   [`crate::relay::push_frame_for_envelope`] — the same function
//!   production pushes use.
//!
//! Two tests enforce the contract in CI: the checked-in file must be
//! byte-identical to a fresh in-memory generation (drift fails the build),
//! and every generated value is verified semantically against the code
//! (signatures verify, blobs open, frames parse, rejections classify as
//! named). Regenerate deliberately — a version bump changes these bytes:
//!
//! ```sh
//! cargo test --lib vectors -- --ignored   # rewrites the checked-in file
//! ```

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto;
use crate::envelope::{self, Envelope, SigningKeypair};
use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::limits;
use crate::manifest::{self, GroupManifest, ManifestMember};
use crate::message::{self, Message};
use crate::relay;
use crate::session::MAX_GROUP_SIZE;
use crate::version;

/// Where the checked-in vectors live (repo-relative).
const VECTORS_PATH: &str = "docs/test-vectors/sync-v1.json";

// ── Fixed inputs ──────────────────────────────────────────────────────────────
//
// Arbitrary but fixed: vectors must be identical on every machine and every
// run. These are test-only values; nothing here is valid on a live network.
// Each seed fills 32 bytes as seed, seed+1, …, seed+31.

fn seq32(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, slot) in b.iter_mut().enumerate() {
        *slot = seed.wrapping_add(i as u8);
    }
    b
}

/// Ed25519 seed of the envelope author and manifest issuer ("VectorAlpha").
const AUTHOR_SIGNING_SEED: u8 = 0x01;
/// Ed25519 seed of the second manifest member ("VectorBeta").
const MEMBER2_SIGNING_SEED: u8 = 0x21;
/// X25519 seed of the envelope recipient.
const RECIPIENT_NOISE_SEED: u8 = 0xA1;
/// X25519 seed of the second manifest member.
const MEMBER2_NOISE_SEED: u8 = 0xC1;
/// X25519 ephemeral seed for the sealed-envelope vector. SINGLE-USE.
const EPH_SEAL_SEED: u8 = 0x51;
/// X25519 ephemeral seed for the standalone addressed-encryption vector.
/// Distinct from EPH_SEAL_SEED: one ephemeral key, one seal, ever.
const EPH_ENC_SEED: u8 = 0x71;
/// The Group ID.
const GROUP_ID_SEED: u8 = 0xE0;
/// The Pairing Secret carried by the Pair message vector (ADR-0023).
const PAIRING_SECRET_SEED: u8 = 0x31;

/// Fixed clock: the receiver's "now" for the replay vectors.
const NOW_MS: u64 = 1_800_000_000_000;
/// Fixed Sender Timestamp on the sealed-envelope vector.
const SENDER_TS_MS: u64 = 1_799_865_432_100;

/// Opaque relay-assigned Blob ID for the Deliver/DeliverAck vectors. The
/// client treats it as 8 opaque bytes and echoes it verbatim.
const BLOB_ID: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 42];

// ── The generated material ────────────────────────────────────────────────────

struct Vectors {
    // Keys
    author_signing: SigningKey,
    author_signing_pub: [u8; 32],
    member2_signing_pub: [u8; 32],
    recipient_noise_secret: [u8; 32],
    recipient_noise_pub: NoisePublicKey,
    member2_noise_pub: NoisePublicKey,
    eph_seal_pub: [u8; 32],
    eph_enc_pub: [u8; 32],
    group_id: [u8; 32],
    pairing_secret: [u8; 32],

    // Signing inputs
    envelope_signing_message: Vec<u8>,
    envelope_signature: [u8; 64],
    manifest_genesis_signing_message: Vec<u8>,
    manifest_update_signing_message: Vec<u8>,

    // Addressed encryption (standalone)
    enc_plaintext: Vec<u8>,
    enc_blob: Vec<u8>,

    // Messages
    msg_pair: Vec<u8>,
    msg_sync: Vec<u8>,
    msg_revoke: Vec<u8>,
    msg_manifest: Vec<u8>,
    /// The pre-SYNC-3 65-byte Pair body (no Pairing Secret) — must NOT
    /// decode (ADR-0022 clean break, ADR-0023).
    pair_without_secret: Vec<u8>,
    /// A frame with an unknown MsgType — must NOT parse (ADR-0034 §3).
    unknown_frame: Vec<u8>,

    // Manifests
    genesis: GroupManifest,
    update: GroupManifest,

    // Sealed envelope
    sealed_prefix: Vec<u8>,
    envelope: Envelope,
    envelope_proto: Vec<u8>,

    // Frames
    frame_push: Vec<u8>,
    frame_deliver: Vec<u8>,
    frame_heartbeat: Vec<u8>,
    frame_ack: Vec<u8>,
    frame_error: Vec<u8>,
    frame_deliver_ack: Vec<u8>,

    message_id: String,
}

fn build() -> Vectors {
    let author_signing = SigningKey::from_bytes(&seq32(AUTHOR_SIGNING_SEED));
    let author_signing_pub = author_signing.verifying_key().to_bytes();
    let author_keypair = SigningKeypair::from_signing_key(author_signing.clone());

    let member2_signing = SigningKey::from_bytes(&seq32(MEMBER2_SIGNING_SEED));
    let member2_signing_pub = member2_signing.verifying_key().to_bytes();

    let recipient_noise_secret = seq32(RECIPIENT_NOISE_SEED);
    let recipient_noise_pub =
        NoisePublicKey(*PublicKey::from(&StaticSecret::from(recipient_noise_secret)).as_bytes());
    let member2_noise_pub =
        NoisePublicKey(*PublicKey::from(&StaticSecret::from(seq32(MEMBER2_NOISE_SEED))).as_bytes());

    let eph_seal = StaticSecret::from(seq32(EPH_SEAL_SEED));
    let eph_seal_pub = *PublicKey::from(&eph_seal).as_bytes();
    let eph_enc = StaticSecret::from(seq32(EPH_ENC_SEED));
    let eph_enc_pub = *PublicKey::from(&eph_enc).as_bytes();

    let group_id = seq32(GROUP_ID_SEED);
    let pairing_secret = seq32(PAIRING_SECRET_SEED);

    // Messages (Message layer: 1-byte tag + body).
    let msg_pair = Message::Pair {
        noise_pub: member2_noise_pub.0,
        signing_pub: member2_signing_pub,
        secret: pairing_secret,
    }
    .encode();
    let msg_sync = Message::Sync {
        body: b"hello vectors".to_vec(),
    }
    .encode();
    let msg_revoke = Message::Revoke.encode();
    // The refused pre-SYNC-3 Pair: tag || noise_pub || signing_pub, no
    // secret (65 bytes total).
    let mut pair_without_secret = vec![0x01u8];
    pair_without_secret.extend_from_slice(&member2_noise_pub.0);
    pair_without_secret.extend_from_slice(&member2_signing_pub);
    // An unknown MsgType (0x7F), zero-length body.
    let unknown_frame = vec![0x7Fu8, 0, 0, 0, 0];

    // Manifests: genesis (no parent) and an update naming genesis as parent
    // (ADR-0027 — the parent field + hash the vectors must cover).
    let alpha = ManifestMember {
        noise_pub: NoisePublicKey(*PublicKey::from(&StaticSecret::from(seq32(0x81))).as_bytes()),
        signing_pub: SigningPublicKey(author_signing_pub),
        name: "VectorAlpha".into(),
    };
    let beta = ManifestMember {
        noise_pub: member2_noise_pub,
        signing_pub: SigningPublicKey(member2_signing_pub),
        name: "VectorBeta".into(),
    };
    let genesis = GroupManifest::new(group_id, 1, vec![alpha.clone()], &author_signing);
    let update =
        GroupManifest::update(&genesis, vec![alpha, beta], &author_signing).expect("v1 is not MAX");
    let msg_manifest = Message::GroupManifest {
        manifest: genesis.clone(),
    }
    .encode();

    // The sealed envelope (ADR-0031): fixed inputs, fixed ephemeral.
    let envelope = Envelope::build_sealed_with_ephemeral(
        7,
        vec![[0xEE; 32]],
        recipient_noise_pub,
        &author_keypair,
        SENDER_TS_MS,
        &msg_sync,
        &eph_seal,
    );
    let envelope_proto = envelope.encode();

    // The sealed prefix is the decrypted payload minus the trailing
    // signature — the exact bytes the code signed, not a reconstruction.
    let sealed = crypto::decrypt(recipient_noise_secret, &envelope.payload).expect("opens");
    let sealed_prefix = sealed[..sealed.len() - 64].to_vec();
    let envelope_signature: [u8; 64] = sealed[sealed.len() - 64..]
        .try_into()
        .expect("64-byte signature");
    let envelope_signing_message = envelope::signing_message(
        version::END_TO_END_VERSION,
        &envelope.recipient_pub,
        &eph_seal_pub,
        &sealed_prefix,
    );

    // Standalone addressed encryption (second fixed ephemeral — single-use).
    let enc_plaintext = b"addressed encryption vector plaintext".to_vec();
    let enc_blob = crypto::encrypt_with_ephemeral(recipient_noise_pub, &eph_enc, &enc_plaintext);

    // Frames ([type:u8][len:u32 BE][body]); the push blob through the same
    // function production pushes use.
    let frame_push = relay::push_frame_for_envelope(&envelope).expect("fits one frame");
    let mut deliver_body = BLOB_ID.to_vec();
    deliver_body.extend_from_slice(&envelope_proto);
    let frame_deliver = relay::frame(relay::MsgType::Deliver, &deliver_body);
    let frame_heartbeat = relay::frame(relay::MsgType::Heartbeat, &[]);
    let frame_ack = relay::frame(relay::MsgType::Ack, &[]);
    let frame_error = relay::frame(relay::MsgType::Error, &[]);
    let frame_deliver_ack = relay::frame(relay::MsgType::DeliverAck, &BLOB_ID);

    let manifest_domain = version::manifest_signing_domain();
    let manifest_genesis_signing_message = manifest::signing_message_for(
        &manifest_domain,
        &genesis.group_id,
        genesis.version,
        &genesis.members,
        &genesis.parent,
    );
    let manifest_update_signing_message = manifest::signing_message_for(
        &manifest_domain,
        &update.group_id,
        update.version,
        &update.members,
        &update.parent,
    );

    let message_id = message::message_id(&author_signing_pub, 7);

    Vectors {
        author_signing,
        author_signing_pub,
        member2_signing_pub,
        recipient_noise_secret,
        recipient_noise_pub,
        member2_noise_pub,
        eph_seal_pub,
        eph_enc_pub,
        group_id,
        pairing_secret,
        envelope_signing_message,
        envelope_signature,
        manifest_genesis_signing_message,
        manifest_update_signing_message,
        enc_plaintext,
        enc_blob,
        msg_pair,
        msg_sync,
        msg_revoke,
        msg_manifest,
        pair_without_secret,
        unknown_frame,
        genesis,
        update,
        sealed_prefix,
        envelope,
        envelope_proto,
        frame_push,
        frame_deliver,
        frame_heartbeat,
        frame_ack,
        frame_error,
        frame_deliver_ack,
        message_id,
    }
}

// ── Semantic verification ─────────────────────────────────────────────────────
//
// Every generated value is checked against the real code paths. Combined
// with the byte-identical drift check on the checked-in file, this proves
// the file pins what the code does today.

fn verify(v: &Vectors) {
    // Signing inputs verify under the author's key.
    let vk = VerifyingKey::from_bytes(&v.author_signing_pub).expect("valid key");
    vk.verify_strict(
        &v.envelope_signing_message,
        &Signature::from_bytes(&v.envelope_signature),
    )
    .expect("envelope signature verifies over the pinned signing input");
    vk.verify_strict(
        &v.manifest_genesis_signing_message,
        &Signature::from_bytes(&v.genesis.signature),
    )
    .expect("genesis manifest signature verifies over the pinned signing input");
    vk.verify_strict(
        &v.manifest_update_signing_message,
        &Signature::from_bytes(&v.update.signature),
    )
    .expect("update manifest signature verifies over the pinned signing input");

    // The update names the genesis hash as its parent (ADR-0027), and both
    // pass the real acceptance path.
    assert_eq!(v.update.parent, Some(v.genesis.hash()));
    v.genesis.verify(None).expect("genesis verifies");
    v.update
        .verify(Some(&v.genesis))
        .expect("update verifies against genesis");

    // The standalone addressed-encryption blob opens for the recipient only.
    let opened = crypto::decrypt(v.recipient_noise_secret, &v.enc_blob).expect("opens");
    assert_eq!(opened, v.enc_plaintext);
    assert_eq!(crypto::ephemeral_pub_of(&v.enc_blob), Some(v.eph_enc_pub));

    // The sealed envelope opens end-to-end and recovers every field.
    let sc = v
        .envelope
        .open_sealed(v.recipient_noise_secret)
        .expect("sealed envelope opens");
    assert_eq!(sc.author_pub, v.author_signing_pub);
    assert_eq!(sc.sequence, 7);
    assert_eq!(sc.parents, vec![[0xEE; 32]]);
    assert_eq!(sc.sender_timestamp_ms, SENDER_TS_MS);
    assert_eq!(sc.message, v.msg_sync);
    assert_eq!(sc.signature, v.envelope_signature);
    assert_eq!(
        crypto::ephemeral_pub_of(&v.envelope.payload),
        Some(v.eph_seal_pub)
    );

    // Messages round-trip through the real codec.
    assert_eq!(
        Message::decode(&v.msg_pair).expect("pair decodes"),
        Message::Pair {
            noise_pub: v.member2_noise_pub.0,
            signing_pub: v.member2_signing_pub,
            secret: v.pairing_secret,
        }
    );
    assert!(matches!(
        Message::decode(&v.msg_sync).expect("sync decodes"),
        Message::Sync { ref body } if body == b"hello vectors"
    ));
    assert_eq!(
        Message::decode(&v.msg_revoke).expect("revoke decodes"),
        Message::Revoke
    );
    match Message::decode(&v.msg_manifest).expect("manifest decodes") {
        Message::GroupManifest { manifest } => assert_eq!(manifest, v.genesis),
        other => panic!("expected GroupManifest, got {other:?}"),
    }

    // Frames parse back through the real framer.
    for (bytes, want) in [
        (&v.frame_push, relay::MsgType::Push),
        (&v.frame_deliver, relay::MsgType::Deliver),
        (&v.frame_heartbeat, relay::MsgType::Heartbeat),
        (&v.frame_ack, relay::MsgType::Ack),
        (&v.frame_error, relay::MsgType::Error),
        (&v.frame_deliver_ack, relay::MsgType::DeliverAck),
    ] {
        let (got, _) = relay::parse(bytes).expect("frame parses");
        assert_eq!(got, want);
    }
    // The push body is routing prefix || envelope proto (ADR-0019).
    let (_, push_body) = relay::parse(&v.frame_push).expect("push parses");
    assert_eq!(&push_body[..32], &v.recipient_noise_pub.0);
    assert_eq!(&push_body[32..], v.envelope_proto.as_slice());
    // The deliver body is blob_id || envelope proto (ADR-0020).
    let (_, deliver_body) = relay::parse(&v.frame_deliver).expect("deliver parses");
    assert_eq!(&deliver_body[..8], &BLOB_ID);
    assert_eq!(&deliver_body[8..], v.envelope_proto.as_slice());
    let (_, ack_body) = relay::parse(&v.frame_deliver_ack).expect("deliverack parses");
    assert_eq!(ack_body, &BLOB_ID);

    // Rejection vectors behave as named (one per layer).
    // Transport: an `unsupported min..max` line parses to the typed refusal.
    assert_eq!(
        version::parse_unsupported_reply(b"unsupported 2..4\n"),
        Some((2, 4))
    );
    // Envelope: a one-byte payload flip fails to open (→ unreadable/malformed).
    let mut tampered = v.envelope.clone();
    let last = tampered.payload.len() - 1;
    tampered.payload[last] ^= 0x01;
    assert!(tampered.open_sealed(v.recipient_noise_secret).is_err());
    // Size: the public limit is 61,440 and 61,441 is refused (ADR-0025).
    assert_eq!(limits::PROTOCOL_SIZE_LIMIT, 61_440);
    assert_eq!(limits::MAX_ENVELOPE_BYTES, 65_482);
    // End-to-End Version: newer is held unacked, older (incl. 0, the
    // pre-version format) is acked and dropped (ADR-0022).
    let newer = Envelope {
        version: version::END_TO_END_VERSION + 1,
        ..v.envelope.clone()
    };
    assert!(
        Envelope::decode(&newer.encode()).expect("decodes").version > version::END_TO_END_VERSION
    );
    let older = Envelope {
        version: 0,
        ..v.envelope.clone()
    };
    assert_eq!(
        Envelope::decode(&older.encode()).expect("decodes").version,
        0
    );
    // Replay: a Sender Timestamp beyond the 60-day window is expired.
    let expired_ts = NOW_MS - envelope::REPLAY_WINDOW_MS - 1_000;
    assert!(envelope::is_expired(expired_ts, NOW_MS));
    assert!(!envelope::is_expired(SENDER_TS_MS, NOW_MS));
    // Message: an unknown tag is malformed.
    assert!(matches!(
        Message::decode(&[0x7F]),
        Err(message::MessageError::UnknownType(0x7F))
    ));
    // Message: a pre-SYNC-3 Pair (no secret) must NOT decode — the clean
    // break of ADR-0022 makes the unversioned pairing format unreadable.
    assert_eq!(v.pair_without_secret.len(), 65);
    assert!(matches!(
        Message::decode(&v.pair_without_secret),
        Err(message::MessageError::InvalidPairingPayload)
    ));
    // Frame: an unknown MsgType does not parse (→ malformed, ADR-0034 §3;
    // with no blob id there is nothing to ack).
    assert!(relay::parse(&v.unknown_frame).is_none());

    // The Message ID is the stable tsm1_ derivation.
    assert_eq!(v.message_id, message::message_id(&v.author_signing_pub, 7));
    assert!(v.message_id.starts_with("tsm1_"));

    // Determinism: building again from the fixed inputs yields identical bytes.
    let again = build();
    assert_eq!(again.envelope_proto, v.envelope_proto);
    assert_eq!(again.enc_blob, v.enc_blob);
    assert_eq!(again.genesis, v.genesis);
    assert_eq!(again.update, v.update);
    assert_eq!(again.frame_push, v.frame_push);
}

// ── JSON rendering ────────────────────────────────────────────────────────────
//
// Hand-rolled: the crate deliberately has no serde dependency (same pattern
// as gen-shared-facts). Objects keep insertion order; two-space indent; no
// floats — all numbers are u64. Hex is lowercase.

enum J {
    S(String),
    N(u64),
    B(bool),
    A(Vec<J>),
    O(Vec<(&'static str, J)>),
}

fn s(text: impl Into<String>) -> J {
    J::S(text.into())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).expect("0..16"));
        out.push(char::from_digit((b & 0xf) as u32, 16).expect("0..16"));
    }
    out
}

fn render(j: &J, indent: usize) -> String {
    let pad = "  ".repeat(indent);
    let pad_in = "  ".repeat(indent + 1);
    match j {
        J::S(text) => format!("\"{}\"", escape(text)),
        J::N(n) => n.to_string(),
        J::B(b) => b.to_string(),
        J::A(items) => {
            if items.is_empty() {
                return "[]".to_string();
            }
            let mut out = String::from("[\n");
            for (i, item) in items.iter().enumerate() {
                out.push_str(&pad_in);
                out.push_str(&render(item, indent + 1));
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push(']');
            out
        }
        J::O(entries) => {
            if entries.is_empty() {
                return "{}".to_string();
            }
            let mut out = String::from("{\n");
            for (i, (key, value)) in entries.iter().enumerate() {
                out.push_str(&pad_in);
                out.push_str(&format!("\"{key}\": "));
                out.push_str(&render(value, indent + 1));
                if i + 1 < entries.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push('}');
            out
        }
    }
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

fn to_json(v: &Vectors) -> String {
    let doc = J::O(vec![
        ("format", s("trueseal-sync-vectors")),
        ("formatVersion", J::N(1)),
        (
            "description",
            s(
                "Sync JSON test vectors (ADR-0022, gate G5). Generated from the trueseal-sync \
               code paths with fixed test-only inputs — never hand-written. Consumers verify \
               they reproduce or accept exactly these bytes. See README.md in this directory.",
            ),
        ),
        (
            "regenerate",
            s(
                "cargo test --lib vectors -- --ignored   (rewrites this file; do so only on a \
               deliberate protocol change — the drift test fails CI otherwise)",
            ),
        ),
        (
            "protocol",
            J::O(vec![
                ("transportVersion", J::N(version::TRANSPORT_VERSION as u64)),
                ("endToEndVersion", J::N(version::END_TO_END_VERSION as u64)),
                ("storeVersion", J::N(version::STORE_VERSION as u64)),
                (
                    "protocolSizeLimit",
                    J::N(limits::PROTOCOL_SIZE_LIMIT as u64),
                ),
                ("maxEnvelopeBytes", J::N(limits::MAX_ENVELOPE_BYTES as u64)),
                (
                    "noiseFramePlaintextMax",
                    J::N(limits::NOISE_FRAME_PLAINTEXT_MAX as u64),
                ),
                ("maxGroupSize", J::N(MAX_GROUP_SIZE as u64)),
                (
                    "maxManifestVersionJump",
                    J::N(manifest::MAX_MANIFEST_VERSION_JUMP),
                ),
                ("maxHeldBlobs", J::N(version::MAX_HELD_BLOBS as u64)),
                ("replayWindowMs", J::N(envelope::REPLAY_WINDOW_MS)),
            ]),
        ),
        (
            "keys",
            J::O(vec![
                (
                    "note",
                    s(
                        "test-only fixed inputs; none of this key material is valid on any live \
                       network. Seeds are 32-byte ramps (seed, seed+1, …, seed+31).",
                    ),
                ),
                ("authorSigningSecret", s(hex(v.author_signing.as_bytes()))),
                ("authorSigningPub", s(hex(&v.author_signing_pub))),
                ("member2SigningPub", s(hex(&v.member2_signing_pub))),
                ("recipientNoiseSecret", s(hex(&v.recipient_noise_secret))),
                ("recipientNoisePub", s(hex(&v.recipient_noise_pub.0))),
                ("member2NoisePub", s(hex(&v.member2_noise_pub.0))),
                ("ephemeralSealPub", s(hex(&v.eph_seal_pub))),
                ("ephemeralEncPub", s(hex(&v.eph_enc_pub))),
                ("groupId", s(hex(&v.group_id))),
                ("pairingSecret", s(hex(&v.pairing_secret))),
            ]),
        ),
        (
            "domains",
            J::O(vec![
                (
                    "hkdfInfo",
                    s(String::from_utf8(version::addressed_encryption_hkdf_info()).expect("utf8")),
                ),
                (
                    "aeadAad",
                    s(String::from_utf8(version::addressed_encryption_aad()).expect("utf8")),
                ),
                (
                    "hkdfInfoLayout",
                    s("hkdfInfo || ephemeral_pub(32) || recipient_pub(32)"),
                ),
                (
                    "aeadAadLayout",
                    s("aeadAad || ephemeral_pub(32) || recipient_pub(32)"),
                ),
                (
                    "envelopeSigningDomainHex",
                    s(hex(&version::envelope_signing_domain())),
                ),
                (
                    "manifestSigningDomainHex",
                    s(hex(&version::manifest_signing_domain())),
                ),
                ("note", s("the signing domains end in a NUL byte (0x00)")),
            ]),
        ),
        (
            "transportVersionPrefix",
            J::O(vec![
                (
                    "layout",
                    s(
                        "client→relay: \"TSP\" || version:u16 BE (5 bytes, plaintext); \
                       relay→client: 0x01 (supported — the 5 prefix bytes become the Noise \
                       prologue) | \"unsupported <min>..<max>\\n\" (refused — then close)",
                    ),
                ),
                ("clientPrefixHex", s(hex(&version::transport_prefix()))),
                ("acceptReplyHex", s("01")),
                (
                    "refusalExample",
                    J::O(vec![
                        ("line", s("unsupported 2..4\n")),
                        ("min", J::N(2)),
                        ("max", J::N(4)),
                        ("surfacesAs", s("connectionState relayVersionUnsupported")),
                    ]),
                ),
                (
                    "preVersionRelay",
                    s(
                        "a relay speaking the pre-version format never replies; the exchange \
                       times out (10 s deadline) and surfaces as a connection failure — that \
                       format is refused by design (ADR-0022)",
                    ),
                ),
            ]),
        ),
        (
            "signing",
            J::O(vec![
                (
                    "envelope",
                    J::O(vec![
                        (
                            "layout",
                            s(
                                "envelopeSigningDomain || version(4 LE) || recipient_pub(32) || \
                               ephemeral_pub(32) || sealedPrefix  (ADR-0031)",
                            ),
                        ),
                        ("signingMessageHex", s(hex(&v.envelope_signing_message))),
                        ("signatureHex", s(hex(&v.envelope_signature))),
                        ("signerPub", s(hex(&v.author_signing_pub))),
                    ]),
                ),
                (
                    "manifestGenesis",
                    J::O(vec![
                        (
                            "layout",
                            s("manifestSigningDomain || group_id(32) || version(8 LE) || \
                               per-member [noise_pub(32) || signing_pub(32) || name || 0x00] \
                               || parentFlag(0x00 = genesis)  (ADR-0022/0027)"),
                        ),
                        (
                            "signingMessageHex",
                            s(hex(&v.manifest_genesis_signing_message)),
                        ),
                        ("signatureHex", s(hex(&v.genesis.signature))),
                        ("manifestProtoHex", s(hex(&v.genesis.encode()))),
                        ("hashHex", s(hex(&v.genesis.hash()))),
                        (
                            "hashNote",
                            s("SHA-256 over the canonical protobuf encoding"),
                        ),
                    ]),
                ),
                (
                    "manifestUpdate",
                    J::O(vec![
                        (
                            "layout",
                            s(
                                "as genesis, but parentFlag 0x01 || parentHash(32) — the parent \
                               is covered by the signature (ADR-0027)",
                            ),
                        ),
                        (
                            "signingMessageHex",
                            s(hex(&v.manifest_update_signing_message)),
                        ),
                        ("signatureHex", s(hex(&v.update.signature))),
                        ("manifestProtoHex", s(hex(&v.update.encode()))),
                        ("hashHex", s(hex(&v.update.hash()))),
                        (
                            "parentHex",
                            s(hex(&v.update.parent.expect("update has a parent"))),
                        ),
                        (
                            "versionJumpBound",
                            J::N(manifest::MAX_MANIFEST_VERSION_JUMP),
                        ),
                    ]),
                ),
            ]),
        ),
        (
            "addressedEncryption",
            J::O(vec![
                (
                    "layout",
                    s(
                        "ephemeral_pub(32) || nonce(12, all zero) || ciphertext+tag — \
                       X25519 DH → HKDF-SHA256 (no salt) → ChaCha20-Poly1305 with the \
                       versioned info/AAD above (ADR-0031)",
                    ),
                ),
                ("plaintextHex", s(hex(&v.enc_plaintext))),
                ("blobHex", s(hex(&v.enc_blob))),
                ("recipientNoisePub", s(hex(&v.recipient_noise_pub.0))),
                ("ephemeralPub", s(hex(&v.eph_enc_pub))),
            ]),
        ),
        (
            "messageId",
            J::O(vec![
                (
                    "derivation",
                    s(
                        "tsm1_ || base64url(SHA-256(\"trueseal-message-id-v1\\0\" || \
                       author_signing_pub(32) || sequence:u64 BE))",
                    ),
                ),
                ("authorSigningPub", s(hex(&v.author_signing_pub))),
                ("sequence", J::N(7)),
                ("id", s(&v.message_id)),
            ]),
        ),
        (
            "messages",
            J::O(vec![
                (
                    "layout",
                    s(
                        "1-byte type tag + body; the tag lives inside the addressed encryption, \
                       the relay never sees it. Pair body = noise_pub(32) || signing_pub(32) \
                       || secret(32) — exactly 97 bytes total (ADR-0023)",
                    ),
                ),
                (
                    "pair",
                    J::O(vec![("tag", J::N(0x01)), ("bytesHex", s(hex(&v.msg_pair)))]),
                ),
                (
                    "sync",
                    J::O(vec![
                        ("tag", J::N(0x02)),
                        ("bodyUtf8", s("hello vectors")),
                        ("bytesHex", s(hex(&v.msg_sync))),
                    ]),
                ),
                (
                    "revoke",
                    J::O(vec![
                        ("tag", J::N(0x03)),
                        ("bytesHex", s(hex(&v.msg_revoke))),
                    ]),
                ),
                (
                    "groupManifest",
                    J::O(vec![
                        ("tag", J::N(0x04)),
                        ("bytesHex", s(hex(&v.msg_manifest))),
                    ]),
                ),
            ]),
        ),
        (
            "sealedEnvelope",
            J::O(vec![
                (
                    "sealedContentLayout",
                    s(
                        "author_pub(32) || sequence(8 LE) || parents_len(2 LE) || parents(32*n) \
                       || sender_timestamp_ms(8 LE) || message || signature(64)  (ADR-0031)",
                    ),
                ),
                (
                    "envelopeProtoLayout",
                    s("protobuf Envelope { version: field 7 (signed plaintext), \
                       recipient_pub: field 3, payload: field 6 } — the relay reads only \
                       these three"),
                ),
                (
                    "inputs",
                    J::O(vec![
                        ("sequence", J::N(7)),
                        ("parentsHex", J::A(vec![s(hex(&[0xEE; 32]))])),
                        ("senderTimestampMs", J::N(SENDER_TS_MS)),
                        ("messageHex", s(hex(&v.msg_sync))),
                        ("recipientNoisePub", s(hex(&v.recipient_noise_pub.0))),
                        ("authorSigningPub", s(hex(&v.author_signing_pub))),
                        ("ephemeralPub", s(hex(&v.eph_seal_pub))),
                    ]),
                ),
                ("sealedPrefixHex", s(hex(&v.sealed_prefix))),
                ("payloadHex", s(hex(&v.envelope.payload))),
                ("envelopeProtoHex", s(hex(&v.envelope_proto))),
                ("envelopeHashHex", s(hex(&v.envelope.hash()))),
                (
                    "hashNote",
                    s("SHA-256 over envelopeProto — the parents[] entries of later envelopes"),
                ),
            ]),
        ),
        (
            "frames",
            J::O(vec![
                (
                    "layout",
                    s("[msg_type:u8][len:u32 BE][body] inside one Noise transport frame"),
                ),
                (
                    "push",
                    J::O(vec![
                        ("type", J::N(0x01)),
                        (
                            "bodyLayout",
                            s("recipient_pub(32, the routing prefix) || envelope_proto"),
                        ),
                        ("frameHex", s(hex(&v.frame_push))),
                    ]),
                ),
                (
                    "deliver",
                    J::O(vec![
                        ("type", J::N(0x02)),
                        (
                            "bodyLayout",
                            s("blob_id(8, opaque, relay-assigned) || envelope_proto"),
                        ),
                        ("blobIdHex", s(hex(&BLOB_ID))),
                        ("frameHex", s(hex(&v.frame_deliver))),
                    ]),
                ),
                (
                    "heartbeat",
                    J::O(vec![
                        ("type", J::N(0x03)),
                        ("bodyLayout", s("empty")),
                        ("frameHex", s(hex(&v.frame_heartbeat))),
                    ]),
                ),
                (
                    "ack",
                    J::O(vec![
                        ("type", J::N(0x04)),
                        ("bodyLayout", s("empty")),
                        ("frameHex", s(hex(&v.frame_ack))),
                    ]),
                ),
                (
                    "error",
                    J::O(vec![
                        ("type", J::N(0x05)),
                        ("bodyLayout", s("empty")),
                        ("frameHex", s(hex(&v.frame_error))),
                    ]),
                ),
                (
                    "deliverAck",
                    J::O(vec![
                        ("type", J::N(0x06)),
                        (
                            "bodyLayout",
                            s("blob_id(8) — echoes the Deliver's id verbatim"),
                        ),
                        ("frameHex", s(hex(&v.frame_deliver_ack))),
                    ]),
                ),
            ]),
        ),
        (
            "rejections",
            J::A(vec![
                J::O(vec![
                    ("layer", s("transport")),
                    ("case", s("unsupportedTransportVersion")),
                    ("input", J::O(vec![("replyLine", s("unsupported 2..4\n"))])),
                    (
                        "expect",
                        J::O(vec![
                            ("kind", s("connectionState")),
                            ("name", s("relayVersionUnsupported")),
                            ("min", J::N(2)),
                            ("max", J::N(4)),
                            (
                                "detail",
                                s("ADR-0028: surfaces as a Connection State, not an Error — \
                                   the object stays usable with a relay that speaks its \
                                   version"),
                            ),
                        ]),
                    ),
                ]),
                J::O(vec![
                    ("layer", s("transport")),
                    ("case", s("preVersionRelaySilent")),
                    (
                        "input",
                        J::O(vec![("replyBytes", s("<none — the relay never replies>"))]),
                    ),
                    (
                        "expect",
                        J::O(vec![
                            ("kind", s("connectionFailure")),
                            (
                                "detail",
                                s("the version exchange times out (10 s deadline); the \
                                   pre-version format is refused by design"),
                            ),
                        ]),
                    ),
                ]),
                J::O(vec![
                    ("layer", s("frame")),
                    ("case", s("unknownFrameType")),
                    ("input", J::O(vec![("frameHex", s(hex(&v.unknown_frame)))])),
                    (
                        "expect",
                        J::O(vec![
                            ("kind", s("deliveryIssue")),
                            ("name", s("unreadable")),
                            ("reason", s("malformed")),
                            ("acked", J::B(false)),
                            (
                                "detail",
                                s("an unknown MsgType does not parse; with no blob id there \
                                   is nothing to ack (ADR-0034 §3)"),
                            ),
                        ]),
                    ),
                ]),
                J::O(vec![
                    ("layer", s("envelope")),
                    ("case", s("badSignature")),
                    (
                        "input",
                        J::O(vec![
                            (
                                "envelopeProtoHex",
                                s(hex(&{
                                    let mut t = v.envelope.clone();
                                    let last = t.payload.len() - 1;
                                    t.payload[last] ^= 0x01;
                                    t.encode()
                                })),
                            ),
                            ("recipientNoiseSecret", s(hex(&v.recipient_noise_secret))),
                        ]),
                    ),
                    (
                        "expect",
                        J::O(vec![
                            ("kind", s("deliveryIssue")),
                            ("name", s("unreadable")),
                            ("reason", s("malformed")),
                            ("acked", J::B(true)),
                            ("reachesHandler", J::B(false)),
                        ]),
                    ),
                ]),
                J::O(vec![
                    ("layer", s("size")),
                    ("case", s("bodyOverProtocolLimit")),
                    (
                        "input",
                        J::O(vec![
                            ("bodyLen", J::N(limits::PROTOCOL_SIZE_LIMIT as u64 + 1)),
                            ("limit", J::N(limits::PROTOCOL_SIZE_LIMIT as u64)),
                        ]),
                    ),
                    (
                        "expect",
                        J::O(vec![
                            ("kind", s("typedError")),
                            ("name", s("payloadTooLarge")),
                            ("max", J::N(limits::PROTOCOL_SIZE_LIMIT as u64)),
                            (
                                "detail",
                                s("refused synchronously in send(); never enters the outbox \
                                   (ADR-0025). The relay enforces the same ceiling and may \
                                   only be configured lower."),
                            ),
                        ]),
                    ),
                ]),
                J::O(vec![
                    ("layer", s("endToEndVersion")),
                    ("case", s("newerVersionHeld")),
                    (
                        "input",
                        J::O(vec![(
                            "envelopeProtoHex",
                            s(hex(&Envelope {
                                version: version::END_TO_END_VERSION + 1,
                                ..v.envelope.clone()
                            }
                            .encode())),
                        )]),
                    ),
                    (
                        "expect",
                        J::O(vec![
                            ("kind", s("deliveryIssue")),
                            ("name", s("heldForUpgrade")),
                            ("version", J::N(version::END_TO_END_VERSION as u64 + 1)),
                            ("acked", J::B(false)),
                            (
                                "detail",
                                s("held unacked up to maxHeldBlobs per device so an upgrade \
                                   recovers it; cap overflow acks and drops the oldest with \
                                   unreadable(droppedWhileHeld)"),
                            ),
                        ]),
                    ),
                ]),
                J::O(vec![
                    ("layer", s("endToEndVersion")),
                    ("case", s("olderVersionDropped")),
                    (
                        "input",
                        J::O(vec![(
                            "envelopeProtoHex",
                            s(hex(&Envelope {
                                version: 0,
                                ..v.envelope.clone()
                            }
                            .encode())),
                        )]),
                    ),
                    (
                        "expect",
                        J::O(vec![
                            ("kind", s("deliveryIssue")),
                            ("name", s("unreadable")),
                            ("reason", s("senderOutdated")),
                            ("acked", J::B(true)),
                            ("reachesHandler", J::B(false)),
                            ("detail", s("version 0 is the reserved pre-version format")),
                        ]),
                    ),
                ]),
                J::O(vec![
                    ("layer", s("replay")),
                    ("case", s("expiredSenderTimestamp")),
                    (
                        "input",
                        J::O(vec![
                            (
                                "senderTimestampMs",
                                J::N(NOW_MS - envelope::REPLAY_WINDOW_MS - 1_000),
                            ),
                            ("nowMs", J::N(NOW_MS)),
                            ("replayWindowMs", J::N(envelope::REPLAY_WINDOW_MS)),
                        ]),
                    ),
                    (
                        "expect",
                        J::O(vec![
                            ("kind", s("deliveryIssue")),
                            ("name", s("unreadable")),
                            ("reason", s("expired")),
                            ("acked", J::B(true)),
                        ]),
                    ),
                ]),
                J::O(vec![
                    ("layer", s("message")),
                    ("case", s("unknownMessageTag")),
                    ("input", J::O(vec![("messageHex", s("7f"))])),
                    (
                        "expect",
                        J::O(vec![
                            ("kind", s("deliveryIssue")),
                            ("name", s("unreadable")),
                            ("reason", s("malformed")),
                            ("acked", J::B(true)),
                        ]),
                    ),
                ]),
                J::O(vec![
                    ("layer", s("message")),
                    ("case", s("pairMissingSecret")),
                    (
                        "input",
                        J::O(vec![
                            ("messageHex", s(hex(&v.pair_without_secret))),
                            (
                                "detail",
                                s("the pre-SYNC-3 65-byte Pair body (tag || noise_pub || \
                                   signing_pub, no Pairing Secret) — the clean break of \
                                   ADR-0022 makes the unversioned pairing format unreadable \
                                   (ADR-0023)"),
                            ),
                        ]),
                    ),
                    (
                        "expect",
                        J::O(vec![
                            ("kind", s("deliveryIssue")),
                            ("name", s("unreadable")),
                            ("reason", s("malformed")),
                            ("acked", J::B(true)),
                            ("reachesHandler", J::B(false)),
                        ]),
                    ),
                ]),
            ]),
        ),
    ]);
    let mut out = render(&doc, 0);
    out.push('\n');
    out
}

fn generate_json() -> String {
    let v = build();
    verify(&v);
    to_json(&v)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The checked-in file must be byte-identical to a fresh in-memory
    /// generation (the drift gate): a wire-format change without a deliberate
    /// regeneration fails CI.
    #[test]
    fn checked_in_vectors_match_generated() {
        let generated = generate_json();
        let path = format!("{}/{VECTORS_PATH}", env!("CARGO_MANIFEST_DIR"));
        let checked_in = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("read {path}: {e} — regenerate with `cargo test --lib vectors -- --ignored`")
        });
        assert_eq!(
            generated, checked_in,
            "test vectors drifted from the code — if this change is a deliberate protocol \
             change, regenerate with `cargo test --lib vectors -- --ignored` and review the \
             diff; anything else is a bug"
        );
    }

    /// Every generated value verifies against the real code paths
    /// (signatures verify, blobs open, frames parse, rejections classify).
    #[test]
    fn generated_vectors_verify_against_the_code() {
        let v = build();
        verify(&v);
    }

    /// Deliberate regeneration: rewrites the checked-in file. Run explicitly:
    /// `cargo test --lib vectors -- --ignored`. Ignored by default so normal
    /// test runs only VERIFY (above), never write.
    #[test]
    #[ignore]
    fn regenerate_sync_vectors() {
        let path = format!("{}/{VECTORS_PATH}", env!("CARGO_MANIFEST_DIR"));
        std::fs::write(&path, generate_json()).expect("write vectors");
        eprintln!("wrote {path}");
    }
}
