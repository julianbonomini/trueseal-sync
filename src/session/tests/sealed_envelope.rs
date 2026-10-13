//! SYNC-12 (#104), ADR-0031 + ADR-0034 — the Sealed Envelope and the
//! 60-day Replay Window.
//!
//! The Relay reads only the End-to-End Version, the recipient public key and
//! the sealed payload. The signature, sequence, parent hashes and Sender
//! Timestamp live inside the Addressed Encryption. A message is never
//! handled twice, even from a malicious Relay: the Replay Window rejects
//! anything older than 60 days, and each handled Message ID is kept until
//! 60 days after the LATER of the handling time and the Sender Timestamp.

use super::super::test_helpers::*;

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

// ── Replay Window (ADR-0031, ADR-0034 §2) ────────────────────────────────────

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

fn now_ms() -> u64 {
    crate::operation_log::now_secs() * 1000
}

/// A connected two-member session against a scripted relay, with a Delivery
/// Issue collector. Returns (relay, session, issues, sender, device_pub).
fn window_session(
    on_sync: impl Fn() + Send + 'static,
) -> (
    ScriptedRelay,
    super::super::TruesealSession<MemPipe>,
    std::sync::Arc<std::sync::Mutex<Vec<crate::delivery_issue::DeliveryIssue>>>,
    crate::envelope::SigningKeypair,
    crate::keys::NoisePublicKey,
) {
    let relay_kp = make_relay_kp();
    let device = crate::device::DeviceKeypair::generate();
    let sender = crate::envelope::SigningKeypair::generate();

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
    let manifest = membership(&device, &sender);
    let device_pub = device.public_key();

    let session = super::super::TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        move |msg, _author, _seq| {
            if matches!(msg, crate::message::Message::Sync { .. }) {
                on_sync();
            }
        },
        Box::new(crate::operation_log::MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    session.set_manifest(manifest);
    let issues: std::sync::Arc<std::sync::Mutex<Vec<crate::delivery_issue::DeliveryIssue>>> =
        std::sync::Arc::new(std::sync::Mutex::new(vec![]));
    let issues_cb = issues.clone();
    session.subscribe_delivery_issues(move |i| issues_cb.lock().unwrap().push(i));
    (relay, session, issues, sender, device_pub)
}

/// Boundary, both sides of the 60-day Replay Window: a blob stamped 59 days
/// ago is accepted and handled; one stamped 61 days ago is acked and dropped
/// as `unreadable(expired)` and never reaches the handler.
#[test]
fn replay_window_accepts_59_days_and_rejects_61_days() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let handled = Arc::new(AtomicUsize::new(0));
    let h = handled.clone();
    let (relay, _session, issues, sender, device_pub) = window_session(move || {
        h.fetch_add(1, Ordering::SeqCst);
    });

    relay.deliver_at(
        1,
        &crate::message::Message::Sync {
            body: b"59 days old".to_vec(),
        },
        device_pub,
        &sender,
        1,
        now_ms() - 59 * DAY_MS,
    );
    wait_for(
        || handled.load(Ordering::SeqCst) == 1,
        std::time::Duration::from_secs(5),
    );
    wait_for(
        || relay.deliver_acks() == vec![1],
        std::time::Duration::from_secs(5),
    );

    relay.deliver_at(
        2,
        &crate::message::Message::Sync {
            body: b"61 days old".to_vec(),
        },
        device_pub,
        &sender,
        2,
        now_ms() - 61 * DAY_MS,
    );
    wait_for(
        || relay.deliver_acks() == vec![1, 2],
        std::time::Duration::from_secs(5),
    );
    assert_eq!(
        handled.load(Ordering::SeqCst),
        1,
        "the 61-day-old blob never reaches the handler"
    );
    wait_for(
        || {
            issues.lock().unwrap().iter().any(|i| {
                matches!(
                    i,
                    crate::delivery_issue::DeliveryIssue::Unreadable(
                        crate::delivery_issue::UnreadableReason::Expired
                    )
                )
            })
        },
        std::time::Duration::from_secs(5),
    );
}

/// A byte-identical replay (the SAME envelope bytes, new blob id — the
/// hostile-Relay case) runs the handler exactly once.
#[test]
fn byte_identical_replay_delivers_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let handled = Arc::new(AtomicUsize::new(0));
    let h = handled.clone();
    let (relay, _session, _issues, sender, device_pub) = window_session(move || {
        h.fetch_add(1, Ordering::SeqCst);
    });

    let env = crate::envelope::Envelope::build_sealed(
        5,
        vec![],
        device_pub,
        &sender,
        now_ms(),
        &crate::message::Message::Sync {
            body: b"raw replay".to_vec(),
        }
        .encode(),
    );
    relay.deliver_raw(1, env.encode());
    relay.deliver_raw(2, env.encode());

    wait_for(
        || relay.deliver_acks().len() == 2,
        std::time::Duration::from_secs(5),
    );
    assert_eq!(
        handled.load(Ordering::SeqCst),
        1,
        "a byte-identical re-delivery is deduped by Message ID"
    );
}

/// A `Sync` entry re-sealed on day 30 keeps its day-0 Sender Timestamp
/// (ADR-0034 §2), so the copy a Hostile Relay delivers on day 75 is
/// rejected as `unreadable(expired)` and never reaches the handler.
#[test]
fn resealed_sync_replayed_after_window_is_rejected() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let handled = Arc::new(AtomicUsize::new(0));
    let h = handled.clone();
    let (relay, _session, issues, sender, device_pub) = window_session(move || {
        h.fetch_add(1, Ordering::SeqCst);
    });

    // Stamped at "send()" 75 days ago; the re-sealed copy arrives today.
    relay.deliver_at(
        1,
        &crate::message::Message::Sync {
            body: b"old sync".to_vec(),
        },
        device_pub,
        &sender,
        1,
        now_ms() - 75 * DAY_MS,
    );
    wait_for(
        || relay.deliver_acks() == vec![1],
        std::time::Duration::from_secs(5),
    );
    assert_eq!(handled.load(Ordering::SeqCst), 0);
    wait_for(
        || {
            issues.lock().unwrap().iter().any(|i| {
                matches!(
                    i,
                    crate::delivery_issue::DeliveryIssue::Unreadable(
                        crate::delivery_issue::UnreadableReason::Expired
                    )
                )
            })
        },
        std::time::Duration::from_secs(5),
    );
}

/// Future timestamps are accepted (a fast sender clock still gets through),
/// and the dedup record is clamped FORWARD to the Sender Timestamp: it
/// lives until 60 days after the later of handling time and the stamp
/// (ADR-0034 §2), so a replay can never arrive after its record expired.
#[test]
fn future_dated_message_is_accepted_and_dedup_record_is_clamped_forward() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let handled = Arc::new(AtomicUsize::new(0));
    let h = handled.clone();
    let (relay, session, _issues, sender, device_pub) = window_session(move || {
        h.fetch_add(1, Ordering::SeqCst);
    });

    let future = now_ms() + 30 * DAY_MS;
    relay.deliver_at(
        1,
        &crate::message::Message::Sync {
            body: b"from the future".to_vec(),
        },
        device_pub,
        &sender,
        7,
        future,
    );
    wait_for(
        || handled.load(Ordering::SeqCst) == 1,
        std::time::Duration::from_secs(5),
    );

    let mid = crate::message::message_id(&sender.public_key_bytes(), 7);
    let log = session.op_log.lock().unwrap_or_else(|e| e.into_inner());
    assert!(log.is_handled(&mid), "the future-dated message is recorded");
    assert_eq!(
        log.handled_at(&mid),
        Some(future / 1000),
        "the record is clamped to the Sender Timestamp — kept until stamp + 60d"
    );
}

/// A re-addressed blob (outer routing field swapped) or an
/// ephemeral-swapped blob fails and is reported `unreadable(malformed)`.
#[test]
fn readdressed_or_ephemeral_swapped_blob_fails() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let handled = Arc::new(AtomicUsize::new(0));
    let h = handled.clone();
    let (relay, _session, issues, sender, device_pub) = window_session(move || {
        h.fetch_add(1, Ordering::SeqCst);
    });

    let env = crate::envelope::Envelope::build_sealed(
        1,
        vec![],
        device_pub,
        &sender,
        now_ms(),
        &crate::message::Message::Sync {
            body: b"addressed".to_vec(),
        }
        .encode(),
    );

    // Re-addressed: outer recipient_pub swapped for another key.
    let other =
        crate::keys::NoisePublicKey(crate::envelope::SigningKeypair::generate().public_key_bytes());
    let mut tampered = env.clone();
    tampered.recipient_pub = other.0;
    relay.deliver_raw(1, tampered.encode());

    // Ephemeral-swapped: the first 32 payload bytes replaced.
    let mut swapped = env.clone();
    let eph: [u8; 32] = crate::envelope::SigningKeypair::generate().public_key_bytes();
    swapped.payload[..32].copy_from_slice(&eph);
    relay.deliver_raw(2, swapped.encode());

    wait_for(
        || relay.deliver_acks().len() == 2,
        std::time::Duration::from_secs(5),
    );
    assert_eq!(
        handled.load(Ordering::SeqCst),
        0,
        "neither tampered copy reaches the handler"
    );
    wait_for(
        || {
            issues
                .lock()
                .unwrap()
                .iter()
                .filter(|i| {
                    matches!(
                        i,
                        crate::delivery_issue::DeliveryIssue::Unreadable(
                            crate::delivery_issue::UnreadableReason::Malformed
                        )
                    )
                })
                .count()
                == 2
        },
        std::time::Duration::from_secs(5),
    );
}

/// Replaying a Revoke after the group is destroyed changes no state
/// (ADR-0034 §2: "a Revoke for a group that is already destroyed does
/// nothing"). The device wiped and rotated — the replayed copy is dropped
/// by the manifestless filter and the destroyed callback does not re-fire.
#[test]
fn replayed_revoke_after_destroy_does_nothing() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let relay_kp = make_relay_kp();
    let device = crate::device::DeviceKeypair::generate();
    let sender = crate::envelope::SigningKeypair::generate();

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
    let manifest = membership(&device, &sender);
    let device_pub = device.public_key();

    let destroyed = Arc::new(AtomicUsize::new(0));
    let d = destroyed.clone();
    let session = super::super::TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        move |_msg, _author, _seq| {},
        Box::new(crate::operation_log::MemLog::new()),
        || {},
        |_| {},
        move || {
            d.fetch_add(1, Ordering::SeqCst);
        },
        || Err("push factory unused".into()),
    )
    .expect("session");
    session.set_manifest(manifest);

    relay.deliver(1, &crate::message::Message::Revoke, device_pub, &sender, 1);
    wait_for(
        || destroyed.load(Ordering::SeqCst) == 1,
        std::time::Duration::from_secs(5),
    );

    // The hostile replay: same content, fresh seal, new blob id.
    relay.deliver(2, &crate::message::Message::Revoke, device_pub, &sender, 2);
    wait_for(
        || relay.deliver_acks() == vec![1, 2],
        std::time::Duration::from_secs(5),
    );
    assert_eq!(
        destroyed.load(Ordering::SeqCst),
        1,
        "a replayed Revoke changes no state"
    );
}

/// Replaying a Group Manifest changes no state (ADR-0034 §2: "an old Group
/// Manifest loses on (version, hash)"). The same v2 delivered twice —
/// re-sealed, new blob id, the hostile-Relay case — installs once: no
/// second manifest-changed callback, no member events, no Delivery Issue.
#[test]
fn replayed_manifest_is_a_harmless_no_op() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let relay_kp = make_relay_kp();
    let device = crate::device::DeviceKeypair::generate();
    let issuer = crate::device::DeviceKeypair::generate();
    let issuer_sk = ed25519_dalek::SigningKey::from_bytes(&issuer.signing.to_bytes());
    let issuer_signing = crate::envelope::SigningKeypair::from_signing_key(
        ed25519_dalek::SigningKey::from_bytes(&issuer.signing.to_bytes()),
    );

    let gid = crate::manifest::new_group_id();
    let members = vec![
        crate::manifest::ManifestMember {
            noise_pub: device.public_key(),
            signing_pub: device.signing_public_key(),
            name: "Me".into(),
        },
        crate::manifest::ManifestMember {
            noise_pub: issuer.public_key(),
            signing_pub: issuer.signing_public_key(),
            name: "Issuer".into(),
        },
    ];
    let v1 = crate::manifest::GroupManifest::new(gid, 1, members.clone(), &issuer_sk);
    let v2 = crate::manifest::GroupManifest::new(gid, 2, members, &issuer_sk);

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
    let device_pub = device.public_key();

    let manifest_changes = Arc::new(AtomicUsize::new(0));
    let mc = manifest_changes.clone();
    let session = super::super::TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(crate::operation_log::MemLog::new()),
        || {},
        move |_| {
            mc.fetch_add(1, Ordering::SeqCst);
        },
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    session.set_manifest(v1);
    let issues: std::sync::Arc<std::sync::Mutex<Vec<crate::delivery_issue::DeliveryIssue>>> =
        std::sync::Arc::new(std::sync::Mutex::new(vec![]));
    let issues_cb = issues.clone();
    session.subscribe_delivery_issues(move |i| issues_cb.lock().unwrap().push(i));

    let update = crate::message::Message::GroupManifest {
        manifest: v2.clone(),
    };
    relay.deliver(1, &update, device_pub, &issuer_signing, 1);
    wait_for(
        || manifest_changes.load(Ordering::SeqCst) == 1,
        std::time::Duration::from_secs(5),
    );

    // The hostile replay: identical content, fresh seal, new blob id.
    relay.deliver(2, &update, device_pub, &issuer_signing, 2);
    relay.deliver(3, &update, device_pub, &issuer_signing, 3);
    wait_for(
        || relay.deliver_acks() == vec![1, 2, 3],
        std::time::Duration::from_secs(5),
    );

    assert_eq!(
        manifest_changes.load(Ordering::SeqCst),
        1,
        "the replayed manifest installs nothing twice"
    );
    assert_eq!(
        session.manifest.lock().unwrap().as_ref().map(|m| m.version),
        Some(2),
        "still v2 — no regression, no re-install"
    );
    assert!(
        issues.lock().unwrap().is_empty(),
        "a benign-stale replay raises no Delivery Issue"
    );
}

/// Replaying a Pair after the window has closed changes no state
/// (ADR-0034 §2: "a Pair for a closed Pairing Window is dropped"). The
/// accept path is pinned by pairing_trust_anchor's
/// `pair_replaying_spent_secret_is_rejected`; this pins the cancel path:
/// a valid-secret Pair that DID raise a request, re-delivered after
/// cancel_pairing(), raises nothing and reports nothing.
#[test]
fn replayed_pair_after_window_closed_is_a_harmless_no_op() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let relay_kp = make_relay_kp();
    let device = crate::device::DeviceKeypair::generate();
    let joiner = crate::envelope::SigningKeypair::generate();

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay = ScriptedRelay::spawn(pipe_relay, &relay_kp);
    let device_pub = device.public_key();

    let session = super::super::TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(crate::operation_log::MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused".into()),
    )
    .expect("session");
    let requests = Arc::new(AtomicUsize::new(0));
    let rq = requests.clone();
    session.set_on_member_request(move |_, _| {
        rq.fetch_add(1, Ordering::SeqCst);
    });
    let issues: std::sync::Arc<std::sync::Mutex<Vec<crate::delivery_issue::DeliveryIssue>>> =
        std::sync::Arc::new(std::sync::Mutex::new(vec![]));
    let issues_cb = issues.clone();
    session.subscribe_delivery_issues(move |i| issues_cb.lock().unwrap().push(i));

    let token = session.pairing_token().expect("pairing window opens");
    let (_, _, secret, _) = crate::message::decode_pairing_token(&token).expect("token");
    let pair = crate::message::Message::Pair {
        noise_pub: [0xC3; 32],
        signing_pub: joiner.public_key_bytes(),
        secret,
    };

    // The live Pair raises exactly one Join Request.
    relay.deliver(1, &pair, device_pub, &joiner, 1);
    wait_for(
        || requests.load(Ordering::SeqCst) == 1,
        std::time::Duration::from_secs(5),
    );

    // The window closes; the replayed Pair must be a harmless no-op.
    session.cancel_pairing();
    relay.deliver(2, &pair, device_pub, &joiner, 2);
    relay.deliver(3, &pair, device_pub, &joiner, 3);
    wait_for(
        || relay.deliver_acks() == vec![1, 2, 3],
        std::time::Duration::from_secs(5),
    );

    assert_eq!(
        requests.load(Ordering::SeqCst),
        1,
        "a replayed Pair after the window closed raises no request"
    );
    assert!(
        issues.lock().unwrap().is_empty(),
        "a replayed Pair is dropped silently — no Delivery Issue"
    );
}
