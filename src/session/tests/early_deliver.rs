//! SYNC-6 (#98): a Blob queued in the inbox while the device was offline
//! must reach the handler on first connect and on reconnect. The relays in
//! these tests deliver immediately after the handshake — there is no grace
//! period for handler registration, so the tests only pass if the handler
//! is attached before the receive loop starts reading.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::device::DeviceKeypair;
use crate::envelope::{Envelope, SigningKeypair};
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
    sender: &SigningKeypair,
) -> Vec<u8> {
    let plaintext = Message::Sync {
        body: body.to_vec(),
    }
    .encode();
    let payload =
        crate::crypto::encrypt(device.public_key(), sender.public_key_bytes(), &plaintext);
    let env = Envelope::build(1, vec![], device.public_key(), sender, payload);
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

    let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(vec![]));
    let rc = received.clone();

    let _session = TruesealSession::<MemPipe>::connect_full(
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

    let _session = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device,
        move |msg, _author, _seq| {
            rc.lock().unwrap().push(msg);
        },
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(None)),
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
