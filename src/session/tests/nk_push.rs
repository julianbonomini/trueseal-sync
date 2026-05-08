use std::sync::{Arc, Mutex};
use std::time::Duration;

use hush_noise::keypair::Keypair;

use crate::device::DeviceKeypair;
use crate::message::Message;
use crate::relay::{frame, parse, push_send, MsgType, RelayClient};

use super::super::test_helpers::*;

// ── Relay observer test (ADR-0018 / #51) ─────────────────────────────────────

/// Two consecutive push_send calls must produce different ephemeral keys at
/// the relay; neither must match the device's stable noise public key.
/// Confirms the relay learns no stable identity from the push path.
#[test]
fn relay_observer_confirms_different_ephemeral_keys_per_push() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_kp.public_key;

    let device = DeviceKeypair::generate();
    let stable_noise_pub = device.public_key().0;

    // Two relay-side NK endpoints (one per push call)
    let (pipe1_c, pipe1_r) = mem_pipe_pair_simple();
    let (pipe2_c, pipe2_r) = mem_pipe_pair_simple();

    let relay_kp1 = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);

    // Relay accepts each NK session (static key = relay_kp, which push_send dials to)
    std::thread::spawn(move || {
        let _ = hush_noise::session_nk::accept(pipe1_r, relay_kp1);
    });
    std::thread::spawn(move || {
        let _ = hush_noise::session_nk::accept(pipe2_r, relay_kp2);
    });

    // Device pushes twice — each call must use a fresh ephemeral
    let blob = frame(MsgType::Push, b"hello");
    let eph1 = push_send(pipe1_c, relay_pub, blob.clone()).expect("push 1 failed");
    let eph2 = push_send(pipe2_c, relay_pub, blob).expect("push 2 failed");

    assert_ne!(eph1, eph2, "each push must use a different ephemeral key");
    assert_ne!(
        eph1, stable_noise_pub,
        "ephemeral 1 must not match stable noise key"
    );
    assert_ne!(
        eph2, stable_noise_pub,
        "ephemeral 2 must not match stable noise key"
    );
}

/// on_message fires on the RelayClient (XX receive) after a push_send (NK push) from another device.
/// Tests the split-session flow end-to-end at the relay/crypto layer.
#[test]
fn on_message_fires_via_xx_receive_after_nk_push() {
    let relay_kp = make_relay_kp();
    let relay_pub_key = relay_kp.public_key;
    let relay_pub = relay_pub(&relay_kp);

    // Device A: one XX pipe for subscribe (receive)
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair_simple();
    // NK push pipe (one push call)
    let (push_pipe_client, push_pipe_relay) = mem_pipe_pair_simple();

    let relay_kp_xx = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp_nk = Keypair::new(relay_kp.private(), relay_kp.public_key);

    // Fake relay: accepts A's XX, then NK push; routes Push → Deliver to A's XX
    std::thread::spawn(move || {
        let xx_sess = Arc::new(
            hush_noise::session_xx::accept(pipe_a_relay, relay_kp_xx).expect("XX accept"),
        );
        let nk_sess =
            hush_noise::session_nk::accept(push_pipe_relay, relay_kp_nk).expect("NK accept");
        loop {
            let raw = match nk_sess.receive() {
                Ok(r) => r,
                Err(_) => break,
            };
            if let Some((MsgType::Push, body)) = parse(&raw) {
                let deliver = frame(MsgType::Deliver, body);
                let _ = xx_sess.send(&deliver);
            }
        }
    });

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();

    let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    let rx = received.clone();

    // Device A subscribes via XX receive session
    let client_a = RelayClient::connect(
        pipe_a_client,
        relay_pub,
        hush_noise::keypair::Keypair::new(device_a.noise.private(), device_a.noise.public_key),
    )
    .expect("A XX connect");
    client_a.subscribe(move |msg, _| {
        rx.lock().unwrap().push(msg);
    });

    // Build a Sync envelope from B → A (encrypted to A's noise key, signed by B)
    let msg = Message::Sync {
        body: b"hello via NK".to_vec(),
    };
    let plaintext = msg.encode();
    let author_pub = device_b.signing_public_key().0;
    let payload = crate::crypto::encrypt(device_a.public_key(), author_pub, &plaintext);
    let env = crate::envelope::Envelope::build(
        1,
        vec![],
        device_a.public_key(),
        &device_b.signing_keypair(),
        payload,
    );
    let blob = frame(MsgType::Push, &env.encode());

    // Device B pushes via NK (anonymous, ephemeral)
    push_send(push_pipe_client, relay_pub_key, blob).expect("NK push failed");

    std::thread::sleep(Duration::from_millis(100));

    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 1, "A should receive one message via XX subscribe");
    assert_eq!(
        msgs[0],
        Message::Sync {
            body: b"hello via NK".to_vec()
        }
    );
}
