use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use hush_noise::{keypair::Keypair, session_xx::accept};

use crate::device::DeviceKeypair;
use crate::envelope::Envelope;
use crate::message::Message;
use crate::relay::{parse, MsgType};

use super::super::test_helpers::*;
use super::super::HushSession;
use super::make_two_member_manifest;

#[test]
fn two_sessions_can_exchange_sync_message() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_b_relay, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();

    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _| {}).expect("session A");
    session_a.set_manifest(make_two_member_manifest(
        a_noise, a_signing, &a_sk, b_noise, b_signing,
    ));

    let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    let rx = received.clone();
    let _session_b = HushSession::connect(pipe_b_client, relay_pub, device_b, move |msg, _| {
        rx.lock().unwrap().push(msg);
    })
    .expect("session B");

    session_a
        .push_sync(b"hello from A".to_vec())
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
    use crate::keys::{NoisePublicKey, SigningPublicKey};
    use crate::manifest::{new_group_id, GroupManifest, ManifestMember};

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
    let noise = device.public_key();
    let signing = device.signing_public_key();
    let sk = SigningKey::from_bytes(&device.signing.to_bytes());
    // One peer so push_sync sends one message.
    let peer_noise = NoisePublicKey([0xCCu8; 32]);
    let peer_signing = SigningPublicKey([0xDDu8; 32]);
    let manifest = GroupManifest::new(
        new_group_id(),
        1,
        vec![
            ManifestMember {
                noise_pub: noise,
                signing_pub: signing,
                name: "Self".into(),
            },
            ManifestMember {
                noise_pub: peer_noise,
                signing_pub: peer_signing,
                name: "Peer".into(),
            },
        ],
        &sk,
    );

    let session = HushSession::connect(pipe_client, relay_pub, device, |_, _| {}).expect("connect");
    session.set_manifest(manifest);

    session.push_sync(b"first".to_vec()).expect("first");
    session.push_sync(b"second".to_vec()).expect("second");
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
    let a_noise = device_a.public_key();
    let a_signing_pub = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();

    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _| {}).expect("session A");
    session_a.set_manifest(make_two_member_manifest(
        a_noise,
        a_signing_pub,
        &a_sk,
        b_noise,
        b_signing,
    ));

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

    session_a.push_sync(b"hello".to_vec()).expect("push");
    std::thread::sleep(Duration::from_millis(100));

    let got = received.lock().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0], a_signing_pub.0,
        "B should receive A's signing public key"
    );
}

/// An envelope encrypted to B's noise key, mis-delivered to A's session,
/// must be silently dropped — A's on_message must not fire.
/// Zero-trust property: mis-routed or maliciously addressed blobs are garbage
/// to the wrong recipient.
#[test]
fn envelope_addressed_to_wrong_key_is_silently_dropped() {
    use hush_noise::session_xx::accept;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    // Two pipes: one for A, one for the sender.
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_sender_client, pipe_sender_relay) = mem_pipe_pair();

    // Raw relay: accepts sender first, A second. Routes ALL of sender's pushes to A.
    {
        let relay_kp_s = hush_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        let relay_kp_a = hush_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let sess_sender = accept(pipe_sender_relay, relay_kp_s).unwrap();
            let sess_a = accept(pipe_a_relay, relay_kp_a).unwrap();
            loop {
                let raw = match sess_sender.receive() {
                    Ok(r) => r,
                    Err(_) => break,
                };
                if let Some((MsgType::Push, body)) = parse(&raw) {
                    let _ = sess_a.send(&crate::relay::frame(MsgType::Deliver, body));
                }
            }
        });
    }

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate(); // B is the intended recipient
    let device_sender = DeviceKeypair::generate();
    let b_noise = device_b.public_key(); // envelope will be encrypted for B

    let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    let rx = received.clone();

    // Sender connects first (relay accepts sender first).
    let session_sender =
        HushSession::connect(pipe_sender_client, relay_pub, device_sender, |_, _| {})
            .expect("sender");
    // A connects second.
    let _session_a = HushSession::connect(pipe_a_client, relay_pub, device_a, move |msg, _| {
        rx.lock().unwrap().push(msg);
    })
    .expect("session A");

    // Sender pushes a Sync message encrypted for B's noise_pub — wrong key for A.
    session_sender
        .push_message(&Message::Sync { body: b"misdirected".to_vec() }, b_noise)
        .expect("push");

    std::thread::sleep(Duration::from_millis(200));

    // A must not have received anything.
    assert!(
        received.lock().unwrap().is_empty(),
        "A must not receive an envelope addressed to B"
    );
}
