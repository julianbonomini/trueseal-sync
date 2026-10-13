//! SYNC-12 (#104), ADR-0031 + ADR-0034 — the Sealed Envelope and the
//! 60-day Replay Window.
//!
//! The Relay reads only the End-to-End Version, the recipient public key and
//! the sealed payload. The signature, sequence, parent hashes and Sender
//! Timestamp live inside the Addressed Encryption. A message is never
//! handled twice, even from a malicious Relay: the Replay Window rejects
//! anything older than 60 days, and each handled Message ID is kept until
//! 60 days after the LATER of the handling time and the Sender Timestamp.

/// Walk a protobuf wire encoding and return the field numbers present.
/// Format-stable across the envelope reshape — this is how the red tests
/// inspect what the Relay can read without depending on either API shape.
fn wire_fields(bytes: &[u8]) -> Vec<u64> {
    let mut fields = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let (tag, n) = read_varint(&bytes[i..]);
        i += n;
        let field = tag >> 3;
        let wire = tag & 0x7;
        fields.push(field);
        match wire {
            0 => {
                let (_, n) = read_varint(&bytes[i..]);
                i += n;
            }
            1 => i += 8,
            2 => {
                let (len, n) = read_varint(&bytes[i..]);
                i += n + len as usize;
            }
            5 => i += 4,
            _ => panic!("unsupported wire type {wire}"),
        }
    }
    fields
}

fn read_varint(bytes: &[u8]) -> (u64, usize) {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (idx, b) in bytes.iter().enumerate() {
        value |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return (value, idx + 1);
        }
        shift += 7;
    }
    panic!("truncated varint");
}

/// Extract the envelope bytes from a framed Push body
/// ([recipient_pub: 32][envelope_proto], ADR-0019).
fn envelope_bytes_from_push(framed: &[u8]) -> Vec<u8> {
    let (t, body) = crate::relay::parse(framed).expect("a framed Push");
    assert!(
        matches!(t, crate::relay::MsgType::Push),
        "expected a Push frame"
    );
    body[32..].to_vec()
}

/// First occurrence of a field's raw bytes.
fn raw_field(bytes: &[u8], want: u64) -> Option<Vec<u8>> {
    let mut i = 0;
    while i < bytes.len() {
        let (tag, n) = read_varint(&bytes[i..]);
        i += n;
        let field = tag >> 3;
        match tag & 0x7 {
            0 => {
                let (v, n) = read_varint(&bytes[i..]);
                i += n;
                if field == want {
                    return Some(v.to_be_bytes().to_vec());
                }
            }
            1 => {
                if field == want {
                    return Some(bytes[i..i + 8].to_vec());
                }
                i += 8;
            }
            2 => {
                let (len, n) = read_varint(&bytes[i..]);
                i += n;
                if field == want {
                    return Some(bytes[i..i + len as usize].to_vec());
                }
                i += len as usize;
            }
            5 => {
                if field == want {
                    return Some(bytes[i..i + 4].to_vec());
                }
                i += 4;
            }
            _ => panic!("unsupported wire type"),
        }
    }
    None
}

// ── What the Relay reads (ADR-0031) — RED on the pre-SYNC-12 wire ────────────

/// The outer Envelope must carry ONLY the End-to-End Version (field 7), the
/// recipient public key (field 3) and the sealed payload (field 6). Today
/// the sequence (1), parents (2) and signature (5) are cleartext — RED.
#[test]
fn outer_envelope_carries_only_version_recipient_and_payload() {
    let sender = crate::envelope::SigningKeypair::generate();
    let recipient =
        crate::keys::NoisePublicKey(crate::envelope::SigningKeypair::generate().public_key_bytes());
    let framed = crate::relay::build_push_blob(
        &crate::message::Message::Sync {
            body: b"wire shape".to_vec(),
        },
        recipient,
        7,
        vec![],
        &sender,
        1_000,
    )
    .expect("build_push_blob");
    let env_bytes = envelope_bytes_from_push(&framed);
    let mut fields = wire_fields(&env_bytes);
    fields.sort_unstable();
    fields.dedup();
    assert_eq!(
        fields,
        vec![3, 6, 7],
        "the Relay must read only recipient_pub, payload and the End-to-End Version"
    );
}

/// The cleartext sequence is a sender pseudonym: one send() fans out with
/// the same sequence to every recipient, so the Relay can link all of a
/// sender's envelopes. Two envelopes from one Device must share NO
/// Relay-readable value apart from the End-to-End Version — RED today.
#[test]
fn two_sends_share_no_relay_readable_sender_pseudonym() {
    let sender = crate::envelope::SigningKeypair::generate();
    let recip_a =
        crate::keys::NoisePublicKey(crate::envelope::SigningKeypair::generate().public_key_bytes());
    let recip_b =
        crate::keys::NoisePublicKey(crate::envelope::SigningKeypair::generate().public_key_bytes());
    let msg = crate::message::Message::Sync {
        body: b"pseudonym check".to_vec(),
    };
    // The fan-out case: the SAME sequence goes to every recipient.
    let fa =
        crate::relay::build_push_blob(&msg, recip_a, 42, vec![], &sender, 1_000).expect("blob a");
    let fb =
        crate::relay::build_push_blob(&msg, recip_b, 42, vec![], &sender, 1_000).expect("blob b");
    let ea = envelope_bytes_from_push(&fa);
    let eb = envelope_bytes_from_push(&fb);

    // Field-by-field: nothing but the version (7) may match across
    // recipients. An absent field satisfies the property; a SHARED
    // cleartext value (the pre-SYNC-12 sequence pseudonym) fails it.
    for field in [1u64, 2, 3, 5] {
        if let (Some(va), Some(vb)) = (raw_field(&ea, field), raw_field(&eb, field)) {
            assert_ne!(
                va, vb,
                "field {field} must not carry a shared cleartext value across recipients"
            );
        }
    }
}
