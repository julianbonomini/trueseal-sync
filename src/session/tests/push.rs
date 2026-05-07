use std::sync::{Arc, Mutex};
use std::time::Duration;

use hush_noise::{keypair::Keypair, session::accept};

use crate::device::DeviceKeypair;
use crate::envelope::Envelope;
use crate::message::Message;
use crate::relay::{parse, MsgType};

use super::super::test_helpers::*;
use super::super::HushSession;

#[test]
fn two_sessions_can_exchange_sync_message() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_b_relay, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let b_pub = device_b.public_key();

    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _| {}).expect("session A");

    let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    let rx = received.clone();
    let _session_b = HushSession::connect(pipe_b_client, relay_pub, device_b, move |msg, _| {
        rx.lock().unwrap().push(msg);
    })
    .expect("session B");

    session_a
        .push_sync(b_pub, b"hello from A".to_vec())
        .expect("push_sync");
    std::thread::sleep(Duration::from_millis(100));

    let got = received.lock().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0],
        Message::Sync {
            body: b"hello from A".to_vec()
        }
    );
}

#[test]
fn push_sync_increments_sequence() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();

    let received_envs: Arc<Mutex<Vec<Envelope>>> = Arc::new(Mutex::new(Vec::new()));
    let rx = received_envs.clone();
    {
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let session = accept(pipe_relay, relay_kp2).unwrap();
            loop {
                let raw = match session.receive() {
                    Ok(r) => r,
                    Err(_) => break,
                };
                if let Some((MsgType::Push, body)) = parse(&raw) {
                    if let Ok(env) = Envelope::decode(body) {
                        rx.lock().unwrap().push(env);
                    }
                }
            }
        });
    }

    let device = DeviceKeypair::generate();
    let recipient = DeviceKeypair::generate();
    let session = HushSession::connect(pipe_client, relay_pub, device, |_, _| {}).expect("connect");

    session
        .push_sync(recipient.public_key(), b"first".to_vec())
        .expect("first");
    session
        .push_sync(recipient.public_key(), b"second".to_vec())
        .expect("second");
    std::thread::sleep(Duration::from_millis(200));

    let envs = received_envs.lock().unwrap();
    assert_eq!(envs.len(), 2);
    assert_eq!(envs[0].sequence, 0);
    assert_eq!(envs[1].sequence, 1);
}

/// When A sends a Sync message to B, B's on_message receives A's signing public key.
#[test]
fn on_message_receives_sender_signing_pub() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_b_relay, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_signing_pub = device_a.signing_public_key();
    let b_pub = device_b.public_key();

    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _| {}).expect("session A");

    let received: Arc<Mutex<Vec<[u8; 32]>>> = Arc::new(Mutex::new(Vec::new()));
    let rx = received.clone();
    let _session_b = HushSession::connect(
        pipe_b_client,
        relay_pub,
        device_b,
        move |_msg, author_signing_pub| {
            rx.lock().unwrap().push(author_signing_pub);
        },
    )
    .expect("session B");

    session_a.push_sync(b_pub, b"hello".to_vec()).expect("push");
    std::thread::sleep(Duration::from_millis(100));

    let got = received.lock().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0], a_signing_pub.0,
        "B should receive A's signing public key"
    );
}
