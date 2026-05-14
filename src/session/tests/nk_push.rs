use std::sync::{Arc, Mutex};
use std::time::Duration;

use trueseal_noise::keypair::Keypair;

use crate::device::DeviceKeypair;
use crate::message::Message;
use crate::relay::{frame, parse, push_send, MsgType, RelayClient, RelayError};

use super::super::test_helpers::*;

// ── Relay observer test (ADR-0018 / #51) ─────────────────────────────────────

/// Two consecutive push_send calls must succeed without error.
/// The relay-observer anonymity property (unique ephemeral keys per push, no
/// stable key exposure) is verified by push_does_not_expose_stable_noise_key_to_relay
/// in push.rs (ADR-0018).
#[test]
fn relay_observer_confirms_different_ephemeral_keys_per_push() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_kp.public_key;

    let (pipe1_c, pipe1_r) = mem_pipe_pair_simple();
    let (pipe2_c, pipe2_r) = mem_pipe_pair_simple();

    let relay_kp1 = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);

    // Stub relays: accept NK, receive Push, send Ack.
    for (pipe_r, kp) in [(pipe1_r, relay_kp1), (pipe2_r, relay_kp2)] {
        std::thread::spawn(move || {
            let sess = trueseal_noise::session_nk::accept(pipe_r, kp).expect("NK accept");
            if let Ok(raw) = sess.receive() {
                if let Some((MsgType::Push, _)) = parse(&raw) {
                    let _ = sess.send(&frame(MsgType::Ack, &[]));
                }
            }
        });
    }

    let blob = frame(MsgType::Push, b"hello");
    push_send(pipe1_c, relay_pub, blob.clone()).expect("push 1 failed");
    push_send(pipe2_c, relay_pub, blob).expect("push 2 failed");
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

    // Fake relay: accepts A's XX, then NK push; routes Push → Deliver to A's XX; sends Ack back.
    std::thread::spawn(move || {
        let xx_sess = Arc::new(
            trueseal_noise::session_xx::accept(pipe_a_relay, relay_kp_xx).expect("XX accept"),
        );
        let nk_sess =
            trueseal_noise::session_nk::accept(push_pipe_relay, relay_kp_nk).expect("NK accept");
        loop {
            let raw = match nk_sess.receive() {
                Ok(r) => r,
                Err(_) => break,
            };
            if let Some((MsgType::Push, body)) = parse(&raw) {
                if body.len() >= 32 {
                    // ADR-0020: Deliver body = [blob_id: 8 bytes][envelope_proto]
                    let mut deliver_body = 0u64.to_be_bytes().to_vec();
                    deliver_body.extend_from_slice(&body[32..]);
                    let deliver = frame(MsgType::Deliver, &deliver_body);
                    let _ = xx_sess.send(&deliver);
                }
                let _ = nk_sess.send(&frame(MsgType::Ack, &[]));
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
        trueseal_noise::keypair::Keypair::new(device_a.noise.private(), device_a.noise.public_key),
    )
    .expect("A XX connect");
    client_a.subscribe(move |msg, _, _seq| {
        rx.lock().unwrap().push(msg);
    });

    // Build a Sync envelope from B → A using build_push_blob (includes recipient_pub prefix).
    let msg = Message::Sync {
        body: b"hello via NK".to_vec(),
    };
    let blob = crate::relay::build_push_blob(
        &msg,
        device_a.public_key(),
        1,
        vec![],
        &device_b.signing_keypair(),
    ).expect("build_push_blob should succeed");

    // Device B pushes via NK (anonymous, ephemeral)
    push_send(push_pipe_client, relay_pub_key, blob).expect("NK push failed");

    wait_for(|| !received.lock().unwrap().is_empty(), Duration::from_secs(5));

    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 1, "A should receive one message via XX subscribe");
    assert_eq!(
        msgs[0],
        Message::Sync {
            body: b"hello via NK".to_vec()
        }
    );
}

// ── Ack round-trip (ADR-0019 / #72) ──────────────────────────────────────────

/// push_send returns Ok(()) when the relay sends a well-formed Ack.
#[test]
fn push_send_returns_ok_when_relay_acks() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_kp.public_key;
    let (pipe_c, pipe_r) = mem_pipe_pair_simple();
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);

    // Stub relay: accepts NK, receives Push, sends Ack with sequence 0.
    std::thread::spawn(move || {
        let sess = trueseal_noise::session_nk::accept(pipe_r, relay_kp2).expect("NK accept");
        if let Ok(raw) = sess.receive() {
            if let Some((MsgType::Push, _)) = parse(&raw) {
                let seq: u64 = 0;
                let _ = sess.send(&frame(MsgType::Ack, &seq.to_be_bytes()));
            }
        }
    });

    let blob = frame(MsgType::Push, b"test blob");
    let result = push_send(pipe_c, relay_pub, blob);
    assert!(result.is_ok(), "push_send must return Ok(()) after relay Ack");
}

/// push_send returns Err when the relay sends an unexpected response instead of Ack.
#[test]
fn push_send_errors_on_missing_ack() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_kp.public_key;
    let (pipe_c, pipe_r) = mem_pipe_pair_simple();
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);

    // Stub relay: accepts NK, receives Push, sends wrong response type (not Ack).
    std::thread::spawn(move || {
        let sess = trueseal_noise::session_nk::accept(pipe_r, relay_kp2).expect("NK accept");
        if let Ok(_) = sess.receive() {
            // Send Deliver instead of Ack — wrong type.
            let _ = sess.send(&frame(MsgType::Deliver, b"wrong"));
        }
    });

    let blob = frame(MsgType::Push, b"test blob");
    let result = push_send(pipe_c, relay_pub, blob);
    assert!(
        matches!(result, Err(RelayError::PushFailed(_))),
        "push_send must return Err(PushFailed) when relay sends unexpected response"
    );
}

// ── Push body layout + Ack body (ADR-0019 corrections) ───────────────────────

/// Push body must start with recipient_pub as a raw 32-byte prefix so the
/// relay can route without proto decoding (ADR-0019).
#[test]
fn push_body_starts_with_recipient_pub() {
    use crate::device::DeviceKeypair;
    use crate::message::Message;
    use crate::operation_log::MemLog;
    use crate::relay::build_push_blob;

    let device = DeviceKeypair::generate();
    let recipient = DeviceKeypair::generate();
    let recipient_pub = recipient.public_key();

    let signing = device.signing_keypair();
    let blob = build_push_blob(
        &Message::Sync { body: b"hello".to_vec() },
        recipient_pub,
        0,
        vec![],
        &signing,
    ).expect("build_push_blob should succeed");

    // blob = [type:u8][len:u32 BE][recipient_pub:32][envelope_proto:...]
    assert!(blob.len() > 5 + 32, "blob too short");
    let body = &blob[5..]; // strip frame header
    let prefix: [u8; 32] = body[0..32].try_into().unwrap();
    assert_eq!(prefix, recipient_pub.0, "first 32 bytes of body must be recipient_pub");
}

/// Ack body must be 0 bytes — relay sends empty Ack, client accepts any body.
#[test]
fn push_send_accepts_zero_byte_ack() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_kp.public_key;
    let (pipe_c, pipe_r) = mem_pipe_pair_simple();
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);

    // Stub relay: sends 0-byte Ack (ADR-0019 locked body length).
    std::thread::spawn(move || {
        let sess = trueseal_noise::session_nk::accept(pipe_r, relay_kp2).expect("NK accept");
        if let Ok(_) = sess.receive() {
            let _ = sess.send(&frame(MsgType::Ack, &[]));
        }
    });

    let blob = frame(MsgType::Push, b"test");
    assert!(push_send(pipe_c, relay_pub, blob).is_ok(),
        "push_send must accept 0-byte Ack body");
}

// ── Heartbeat + Ack silent drop on XX Receive Session (ADR-0019 / #73) ───────

/// run_loop echoes Heartbeat back when the relay sends one on the XX session.
#[test]
fn run_loop_echoes_heartbeat_on_receive_session() {
    use std::time::Duration;
    use crate::relay::{RelayClient};
    use crate::operation_log::MemLog;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair_simple();

    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let echo_received: std::sync::Arc<std::sync::Mutex<bool>> =
        std::sync::Arc::new(std::sync::Mutex::new(false));
    let echo_clone = echo_received.clone();

    // Relay: accepts XX, sends Heartbeat, waits for echo back.
    std::thread::spawn(move || {
        let sess = trueseal_noise::session_xx::accept(pipe_relay, relay_kp2).expect("XX accept");
        let _ = sess.send(&frame(MsgType::Heartbeat, &[]));
        if let Ok(raw) = sess.receive() {
            if let Some((MsgType::Heartbeat, _)) = parse(&raw) {
                *echo_clone.lock().unwrap() = true;
            }
        }
    });

    let device = crate::device::DeviceKeypair::generate();
    let _client = RelayClient::connect(
        pipe_client,
        relay_pub,
        trueseal_noise::keypair::Keypair::new(device.noise.private(), device.noise.public_key),
    )
    .expect("connect");

    wait_for(|| *echo_received.lock().unwrap(), Duration::from_secs(5));
    assert!(*echo_received.lock().unwrap(), "run_loop must echo Heartbeat back");
}

/// run_loop silently drops Ack on the XX Receive Session — session continues.
#[test]
fn run_loop_silently_drops_ack_on_receive_session() {
    use std::time::Duration;
    use crate::relay::RelayClient;
    use crate::message::Message;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair_simple();
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
    let device_a = crate::device::DeviceKeypair::generate();
    let device_b = crate::device::DeviceKeypair::generate();
    let device_a_noise_priv = device_a.noise.private();
    let device_a_noise_pub = device_a.noise.public_key;
    let device_a_pub = device_a.public_key();

    let received: std::sync::Arc<std::sync::Mutex<Vec<Message>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let rx = received.clone();

    std::thread::spawn(move || {
        let sess = trueseal_noise::session_xx::accept(pipe_relay, relay_kp2).expect("XX accept");
        // Send a spurious Ack — run_loop must not crash or close.
        let _ = sess.send(&frame(MsgType::Ack, &[]));
        // Then deliver a real message — proves session is still alive.
        let msg = Message::Sync { body: b"still alive".to_vec() };
        let blob = crate::relay::build_push_blob(
            &msg,
            device_a_pub,
            1,
            vec![],
            &device_b.signing_keypair(),
        ).expect("build_push_blob should succeed");
        // Deliver = [blob_id: 8 bytes][proto only] (ADR-0020)
        let mut deliver_body = 0u64.to_be_bytes().to_vec();
        deliver_body.extend_from_slice(&blob[5 + 32..]);
        let _ = sess.send(&frame(MsgType::Deliver, &deliver_body));
    });

    let client = RelayClient::connect(
        pipe_client,
        relay_pub,
        trueseal_noise::keypair::Keypair::new(device_a_noise_priv, device_a_noise_pub),
    )
    .expect("connect");
    client.subscribe(move |msg, _, _seq| { rx.lock().unwrap().push(msg); });

    wait_for(|| !received.lock().unwrap().is_empty(), Duration::from_secs(5));
    assert_eq!(received.lock().unwrap()[0], Message::Sync { body: b"still alive".to_vec() });
}

// ── DeliverAck + sequence in callback (ADR-0020) ─────────────────────────────

/// Relay sends Deliver with blob_id prefix — run_loop must send DeliverAck
/// back immediately (before decryption), echoing the blob_id.
#[test]
fn run_loop_sends_deliver_ack_before_decryption() {
    use crate::relay::RelayClient;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair_simple();
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);

    let ack_received: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
    let ack_clone = ack_received.clone();

    std::thread::spawn(move || {
        let sess = trueseal_noise::session_xx::accept(pipe_relay, relay_kp2).expect("XX accept");
        // Send a Deliver frame with blob_id prefix — garbage envelope bytes
        // (decryption will fail, but DeliverAck must still arrive).
        let blob_id: u64 = 0xDEAD_BEEF_1234_5678;
        let mut body = Vec::new();
        body.extend_from_slice(&blob_id.to_be_bytes());
        body.extend_from_slice(b"not a real envelope");
        let _ = sess.send(&frame(MsgType::Deliver, &body));
        // Wait for DeliverAck
        if let Ok(raw) = sess.receive() {
            if let Some((MsgType::DeliverAck, ack_body)) = parse(&raw) {
                if ack_body.len() == 8 {
                    let echoed = u64::from_be_bytes(ack_body.try_into().unwrap());
                    *ack_clone.lock().unwrap() = Some(echoed);
                }
            }
        }
    });

    let device = DeviceKeypair::generate();
    let _client = RelayClient::connect(
        pipe_client,
        relay_pub,
        trueseal_noise::keypair::Keypair::new(device.noise.private(), device.noise.public_key),
    )
    .expect("connect");

    wait_for(|| ack_received.lock().unwrap().is_some(), Duration::from_secs(5));
    assert_eq!(
        *ack_received.lock().unwrap(),
        Some(0xDEAD_BEEF_1234_5678),
        "DeliverAck must echo blob_id verbatim"
    );
}

/// subscribe callback receives sequence as third argument — relay delivers
/// an envelope with sequence=42, callback must see 42.
#[test]
fn subscribe_callback_receives_sequence() {
    use crate::relay::RelayClient;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair_simple();
    let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let device_a_pub = device_a.public_key();
    let device_a_noise_priv = device_a.noise.private();
    let device_a_noise_pub = device_a.noise.public_key;

    let seq_received: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
    let seq_clone = seq_received.clone();

    std::thread::spawn(move || {
        let sess = trueseal_noise::session_xx::accept(pipe_relay, relay_kp2).expect("XX accept");

        let msg = Message::Sync { body: b"hello".to_vec() };
        let blob = crate::relay::build_push_blob(
            &msg, device_a_pub, 42, vec![], &device_b.signing_keypair(),
        ).expect("build_push_blob");
        // Deliver body: [blob_id: 8 bytes][envelope_proto: blob[5+32..]]
        let blob_id: u64 = 99;
        let mut body = Vec::new();
        body.extend_from_slice(&blob_id.to_be_bytes());
        body.extend_from_slice(&blob[5 + 32..]); // strip frame header + recipient_pub prefix
        let _ = sess.send(&frame(MsgType::Deliver, &body));
        // consume DeliverAck so relay stub doesn't block
        let _ = sess.receive();
    });

    let client = RelayClient::connect(
        pipe_client,
        relay_pub,
        trueseal_noise::keypair::Keypair::new(device_a_noise_priv, device_a_noise_pub),
    )
    .expect("connect");

    client.subscribe(move |_msg, _author_pub, seq| {
        *seq_clone.lock().unwrap() = Some(seq);
    });

    wait_for(|| seq_received.lock().unwrap().is_some(), Duration::from_secs(5));
    assert_eq!(*seq_received.lock().unwrap(), Some(42), "callback must receive sequence=42");
}
