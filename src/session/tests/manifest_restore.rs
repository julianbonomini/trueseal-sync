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
    let payload = crate::crypto::encrypt(
        device.public_key(),
        sender.signing_public_key().0,
        &plaintext,
    );
    let env = Envelope::build(
        1,
        vec![],
        device.public_key(),
        &sender.signing_keypair(),
        payload,
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

/// A restarted member briefly has NO manifest: a `Sync` pushed by a
/// non-member in that window passes the (no-op) filter and reaches the
/// handler. It must be discarded — the device is a member of a group that
/// does not contain the sender.
///
/// RED against the current seam: `connect_background` starts with
/// `manifest == None` and the persisted manifest is set only afterwards
/// (here: after the Deliver has been processed — exactly the `ffi.rs`
/// order), so the non-member's Sync is delivered.
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

    let session = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device_a,
        move |msg, _author, _seq| {
            rc.lock().unwrap().push(msg);
        },
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        one_shot_pipe_factory(pipe_client),
        || Err("push factory unused".into()),
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session");

    // Current FFI/CLI order: the manifest is restored only AFTER the
    // reconnect loop (and the first Deliver) has started.
    std::thread::sleep(Duration::from_millis(300)); // let the Deliver be processed
    session.set_manifest(persisted);

    // Give the receive loop ample time, then assert the intruder's Sync
    // never reached the handler.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        received.lock().unwrap().is_empty(),
        "SYNC-7: a Sync from a non-member delivered in the restore window \
         must be discarded, not handled"
    );
}

/// A newer valid manifest delivered right after restart must be kept — the
/// stale persisted copy must NOT overwrite it.
///
/// RED against the current seam: the FFI's `set_manifest(persisted)` runs
/// after the window and overwrites the v2 that already arrived, so memory
/// (and, via `on_manifest_changed`, potentially the store) regresses to v1.
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
    let payload = crate::crypto::encrypt(
        device_a.public_key(),
        device_a.signing_public_key().0,
        &plaintext,
    );
    let env = Envelope::build(
        1,
        vec![],
        device_a.public_key(),
        &device_a.signing_keypair(),
        payload,
    );
    let mut body = 1u64.to_be_bytes().to_vec();
    body.extend_from_slice(&env.encode());
    spawn_immediate_relay(pipe_relay, &relay_kp, vec![frame(MsgType::Deliver, &body)]);

    let session = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device_a,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        one_shot_pipe_factory(pipe_client),
        || Err("push factory unused".into()),
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session");

    // Wait for v2 to arrive and be applied (genesis accept: slot is None).
    wait_for(
        || {
            session
                .manifest
                .lock()
                .unwrap()
                .as_ref()
                .map(|m| m.version)
                == Some(2)
        },
        Duration::from_secs(3),
    );

    // Current FFI/CLI order: restore the persisted v1 AFTER connect.
    session.set_manifest(v1);

    assert_eq!(
        session
            .manifest
            .lock()
            .unwrap()
            .as_ref()
            .map(|m| m.version),
        Some(2),
        "SYNC-7: a newer manifest delivered during the restart window must \
         not be overwritten by the stale persisted copy"
    );
}
