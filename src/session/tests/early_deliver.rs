//! SYNC-6 (#98): a Blob queued in the inbox while the device was offline
//! must reach the handler on first connect and on reconnect. The relays in
//! these tests deliver immediately after the handshake — there is no grace
//! period for handler registration, so the tests only pass if the handler
//! is attached before the receive loop starts reading.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::device::DeviceKeypair;
use crate::envelope::{Envelope, SigningKeypair};
use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::member::member_name;
use crate::message::Message;
use crate::operation_log::MemLog;
use crate::relay::{frame, MsgType};

use super::super::test_helpers::*;
use super::super::TruesealSession;

/// ADR-0023: a manifestless device drops every Sync. Build the two-member
/// genesis (device + scripted sender) so these plumbing tests run as group
/// members — they are about early delivery, not pairing.
fn membership(device: &DeviceKeypair, sender: &SigningKeypair) -> GroupManifest {
    let sk = ed25519_dalek::SigningKey::from_bytes(&device.signing.to_bytes());
    let self_sp = device.signing_public_key();
    let sender_sp = sender.public_key();
    GroupManifest::new(
        new_group_id(),
        1,
        vec![
            ManifestMember {
                noise_pub: device.public_key(),
                signing_pub: self_sp,
                name: member_name(&self_sp),
            },
            ManifestMember {
                noise_pub: NoisePublicKey([9u8; 32]),
                signing_pub: SigningPublicKey(sender.public_key_bytes()),
                name: member_name(&sender_sp),
            },
        ],
        &sk,
    )
}

/// Build the Deliver frame body ([blob_id: 8][envelope]) for a Sync message
/// addressed to `device`, signed by `sender`.
fn deliver_body(
    blob_id: u64,
    body: &[u8],
    device: &DeviceKeypair,
    sender: &SigningKeypair,
) -> Vec<u8> {
    let env = Envelope::build_sealed(
        1,
        vec![],
        device.public_key(),
        sender,
        crate::operation_log::now_secs() * 1000,
        &Message::Sync {
            body: body.to_vec(),
        }
        .encode(),
    );
    let mut framed = blob_id.to_be_bytes().to_vec();
    framed.extend_from_slice(&env.encode());
    framed
}

/// A Blob waiting in the inbox reaches the handler on first connect.
#[test]
fn queued_blob_reaches_handler_on_first_connect() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device = DeviceKeypair::generate();
    let sender = SigningKeypair::generate();

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    {
        let relay_kp2 =
            trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        let body = deliver_body(1, b"offline inbox", &device, &sender);
        std::thread::spawn(move || {
            let sess = crate::version::testutil::xx_accept_after_prefix(pipe_relay, relay_kp2)
                .expect("relay accept");
            // Deliver the moment the session is up — the offline-inbox case.
            sess.send(&frame(MsgType::Deliver, &body)).unwrap();
            // Stay alive and drain so the pipe does not EOF.
            while sess.receive().is_ok() {}
        });
    }

    let manifest = membership(&device, &sender);

    let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(vec![]));
    let rc = received.clone();

    let session = TruesealSession::<MemPipe>::connect_full(
        pipe_client,
        relay_pub,
        device,
        move |msg, _author, _seq| {
            rc.lock().unwrap().push(msg);
        },
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
        || Err("push factory unused in early-deliver test".into()),
    )
    .expect("session");
    session.set_manifest(manifest);

    wait_for(
        || {
            matches!(
                received.lock().unwrap().first(),
                Some(Message::Sync { body }) if body == b"offline inbox"
            )
        },
        Duration::from_secs(3),
    );
}

/// A Blob queued while the device was disconnected reaches the handler after
/// the session reconnects.
#[test]
fn queued_blob_reaches_handler_after_reconnect() {
    use std::sync::atomic::Ordering;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device = DeviceKeypair::generate();
    let sender = SigningKeypair::generate();

    // First connection: plain relay that just holds the session open.
    let (pipe1_client, pipe1_relay, _close_relay1, close_client1) = mem_pipe_pair_with_close();
    {
        let relay_kp2 =
            trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            if let Ok(sess) =
                crate::version::testutil::xx_accept_after_prefix(pipe1_relay, relay_kp2)
            {
                while sess.receive().is_ok() {}
            }
        });
    }

    // Second connection (the reconnect): delivers the queued Blob at once.
    let (pipe2_client, pipe2_relay) = mem_pipe_pair();
    {
        let relay_kp3 =
            trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        let body = deliver_body(2, b"queued during outage", &device, &sender);
        std::thread::spawn(move || {
            let sess = crate::version::testutil::xx_accept_after_prefix(pipe2_relay, relay_kp3)
                .expect("relay accept");
            // Deliver the moment the reconnect completes — no grace period.
            sess.send(&frame(MsgType::Deliver, &body)).unwrap();
            while sess.receive().is_ok() {}
        });
    }

    let pipes: Arc<Mutex<Vec<MemPipe>>> = Arc::new(Mutex::new(vec![pipe1_client, pipe2_client]));
    let pipes2 = pipes.clone();

    let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(vec![]));
    let rc = received.clone();

    let manifest = membership(&device, &sender);

    let _session = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device,
        move |msg, _author, _seq| {
            rc.lock().unwrap().push(msg);
        },
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(Some(manifest))),
        || {},
        |_| {},
        || {},
        move || {
            let mut v = pipes2.lock().unwrap();
            if v.is_empty() {
                Err("exhausted".into())
            } else {
                Ok(v.remove(0))
            }
        },
        || Err("push factory unused in early-deliver test".into()),
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("session");

    // Let the first connection establish, then kill it.
    std::thread::sleep(Duration::from_millis(400));
    close_client1.store(true, Ordering::Release);

    // Reconnect backoff restarts at 1 s after a successful connect; allow 4 s.
    wait_for(
        || {
            matches!(
                received.lock().unwrap().first(),
                Some(Message::Sync { body }) if body == b"queued during outage"
            )
        },
        Duration::from_secs(4),
    );
}
