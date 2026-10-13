//! SYNC-7 (#99): a restarted session must have its persisted manifest in
//! place BEFORE the connection starts. Today `connect_background` spawns
//! the reconnect loop with an empty manifest slot and the FFI/CLI call
//! `set_manifest` only afterwards (`ffi.rs`, `trueseal-cli.rs`). Blobs
//! delivered in that window are judged with no manifest:
//!
//! - the member filter is a no-op on `None`, so a `Sync` from a non-member
//!   reaches the handler;
//! - a `set_manifest` issued after the window overwrites a newer manifest
//!   that arrived during it, so memory and store diverge.
//!
//! The relays in these tests deliver immediately after the handshake —
//! there is no grace period for the manifest to be restored.
//!
//! The red commits show both defects against the old seam; the tests below
//! now run against the fixed seam, where the caller seeds the manifest slot
//! at construction and passes it to `connect_background`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::device::DeviceKeypair;
use crate::envelope::Envelope;
use crate::manifest::{GroupManifest, ManifestMember};
use crate::message::Message;
use crate::operation_log::MemLog;
use crate::relay::{frame, MsgType};

use super::super::test_helpers::*;
use super::super::TruesealSession;

/// Build the Deliver frame body ([blob_id: 8][envelope]) for a Sync message
/// addressed to `device`, signed by `sender`.
fn deliver_body(
    blob_id: u64,
    body: &[u8],
    device: &DeviceKeypair,
    sender: &DeviceKeypair,
) -> Vec<u8> {
    let plaintext = Message::Sync {
        body: body.to_vec(),
    }
    .encode();
    let _ = &plaintext;
    let env = Envelope::build_sealed(
        1,
        vec![],
        device.public_key(),
        &sender.signing_keypair(),
        crate::operation_log::now_secs() * 1000,
        &plaintext,
    );
    let mut framed = blob_id.to_be_bytes().to_vec();
    framed.extend_from_slice(&env.encode());
    framed
}

/// Relay that delivers `frames` the moment the XX session comes up, then
/// drains so the pipe does not EOF.
fn spawn_immediate_relay(
    pipe: MemPipe,
    relay_kp: &trueseal_noise::keypair::Keypair,
    frames: Vec<Vec<u8>>,
) {
    let kp = trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        let sess =
            crate::version::testutil::xx_accept_after_prefix(pipe, kp).expect("relay accept");
        for f in frames {
            sess.send(&f).unwrap();
        }
        while sess.receive().is_ok() {}
    });
}

/// The manifest device A persisted before the restart: members A and B,
/// issued and signed by A.
fn persisted_manifest(device_a: &DeviceKeypair, device_b: &DeviceKeypair) -> GroupManifest {
    super::make_two_member_manifest(
        device_a.public_key(),
        device_a.signing_public_key(),
        &SigningKey::from_bytes(&device_a.signing.to_bytes()),
        device_b.public_key(),
        device_b.signing_public_key(),
    )
}

fn one_shot_pipe_factory(pipe: MemPipe) -> impl Fn() -> Result<MemPipe, String> {
    let pipes = Arc::new(Mutex::new(vec![pipe]));
    move || {
        let mut v = pipes.lock().unwrap();
        if v.is_empty() {
            Err("exhausted".into())
        } else {
            Ok(v.remove(0))
        }
    }
}

/// A restarted member must never behave like an unjoined device: a `Sync`
/// pushed by a non-member the moment the session connects is discarded,
/// because the persisted manifest is already in place.
///
/// Red against the old seam (manifest restored after connect): the intruder's
/// Sync passed the no-op `None` filter and reached the handler.
#[test]
fn non_member_sync_during_restart_window_is_discarded() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    // C is NOT in the group.
    let device_c = DeviceKeypair::generate();

    let persisted = persisted_manifest(&device_a, &device_b);

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let body = deliver_body(1, b"intruder", &device_a, &device_c);
    spawn_immediate_relay(pipe_relay, &relay_kp, vec![frame(MsgType::Deliver, &body)]);

    let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(vec![]));
    let rc = received.clone();

    let _session = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device_a,
        move |msg, _author, _seq| {
            rc.lock().unwrap().push(msg);
        },
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(Some(persisted))),
        || {},
        |_| {},
        || {},
        one_shot_pipe_factory(pipe_client),
        || Err("push factory unused".into()),
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session");

    // Give the receive loop ample time, then assert the intruder's Sync
    // never reached the handler.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        received.lock().unwrap().is_empty(),
        "SYNC-7: a Sync from a non-member delivered in the restore window \
         must be discarded, not handled"
    );
}

/// A `Sync` from a group member, waiting in the inbox at restart, is judged
/// against the persisted manifest on first delivery and reaches the handler.
#[test]
fn member_sync_is_judged_against_persisted_manifest_on_first_delivery() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();

    let persisted = persisted_manifest(&device_a, &device_b);

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let body = deliver_body(1, b"from member", &device_a, &device_b);
    spawn_immediate_relay(pipe_relay, &relay_kp, vec![frame(MsgType::Deliver, &body)]);

    let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(vec![]));
    let rc = received.clone();

    let _session = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device_a,
        move |msg, _author, _seq| {
            rc.lock().unwrap().push(msg);
        },
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(Some(persisted))),
        || {},
        |_| {},
        || {},
        one_shot_pipe_factory(pipe_client),
        || Err("push factory unused".into()),
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session");

    wait_for(
        || {
            matches!(
                received.lock().unwrap().first(),
                Some(Message::Sync { body }) if body == b"from member"
            )
        },
        Duration::from_secs(3),
    );
}

/// A `Sync` delivered right after restart carries the correct sender noise
/// key: the FFI's attribution closure shares the seeded manifest slot, so
/// the lookup succeeds from the very first Deliver.
#[test]
fn sender_noise_key_resolves_from_seeded_manifest_after_restart() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();

    let persisted = persisted_manifest(&device_a, &device_b);
    let b_noise = device_b.public_key().0;

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let body = deliver_body(1, b"attributed", &device_a, &device_b);
    spawn_immediate_relay(pipe_relay, &relay_kp, vec![frame(MsgType::Deliver, &body)]);

    // Mirror the FFI wiring (ffi.rs create): one shared, pre-seeded slot;
    // the closure resolves the sender's noise pub through it.
    let manifest_slot: Arc<Mutex<Option<GroupManifest>>> = Arc::new(Mutex::new(Some(persisted)));
    let manifest_cb = manifest_slot.clone();
    let sender_pubs: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(vec![]));
    let sp = sender_pubs.clone();

    let _session = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device_a,
        move |msg, author_signing_pub, _seq| {
            if matches!(msg, Message::Sync { .. }) {
                let sender_noise_pub = manifest_cb
                    .lock()
                    .unwrap()
                    .as_ref()
                    .and_then(|m| m.noise_pub_for_signing(&author_signing_pub))
                    .map(|k| k.0.to_vec())
                    .unwrap_or_default();
                sp.lock().unwrap().push(sender_noise_pub);
            }
        },
        Box::new(MemLog::new()),
        manifest_slot,
        || {},
        |_| {},
        || {},
        one_shot_pipe_factory(pipe_client),
        || Err("push factory unused".into()),
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session");

    wait_for(
        || !sender_pubs.lock().unwrap().is_empty(),
        Duration::from_secs(3),
    );
    assert_eq!(
        sender_pubs.lock().unwrap()[0],
        b_noise.to_vec(),
        "SYNC-7: a Sync delivered right after restart must carry the sender's \
         noise key resolved from the persisted manifest"
    );
}

/// A newer valid manifest delivered right after restart is kept — with the
/// slot seeded at construction there is no later `set_manifest` of the stale
/// persisted copy that could overwrite it.
///
/// Red against the old seam: the FFI's `set_manifest(persisted v1)` ran after
/// the window and regressed memory to v1.
#[test]
fn newer_manifest_delivered_during_restart_window_is_kept() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());

    let v1 = persisted_manifest(&device_a, &device_b);
    // v2: same group, issued by a current member (A) — a legitimate later
    // version, e.g. a membership change committed while A was offline.
    let v2 = GroupManifest::new(
        v1.group_id,
        2,
        v1.members
            .iter()
            .map(|m| ManifestMember {
                noise_pub: m.noise_pub,
                signing_pub: m.signing_pub,
                name: m.name.clone(),
            })
            .collect(),
        &a_sk,
    );

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let plaintext = Message::GroupManifest {
        manifest: v2.clone(),
    }
    .encode();
    let env = Envelope::build_sealed(
        1,
        vec![],
        device_a.public_key(),
        &device_a.signing_keypair(),
        crate::operation_log::now_secs() * 1000,
        &plaintext,
    );
    let mut body = 1u64.to_be_bytes().to_vec();
    body.extend_from_slice(&env.encode());
    spawn_immediate_relay(pipe_relay, &relay_kp, vec![frame(MsgType::Deliver, &body)]);

    let session = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device_a,
        |_, _, _| {},
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(Some(v1))),
        || {},
        |_| {},
        || {},
        one_shot_pipe_factory(pipe_client),
        || Err("push factory unused".into()),
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session");

    // v2 arrives the moment the session connects and is verified against the
    // seeded v1 (issuer is a current member, version increments).
    wait_for(
        || session.manifest.lock().unwrap().as_ref().map(|m| m.version) == Some(2),
        Duration::from_secs(3),
    );

    // It stays v2 — nothing restores the stale persisted copy afterwards.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        session.manifest.lock().unwrap().as_ref().map(|m| m.version),
        Some(2),
        "SYNC-7: a newer manifest delivered during the restart window must \
         not be overwritten by the stale persisted copy"
    );
}
