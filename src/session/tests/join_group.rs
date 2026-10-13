use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::device::DeviceKeypair;

use super::super::test_helpers::*;
use super::super::TruesealSession;

/// B calls join_group(A.pairing_token()) — A's pairing handler receives B's Pair.
/// Pair messages are consumed by the pairing handler (not forwarded to on_message),
/// so we verify via set_on_member_request + accept_member → manifest.
#[test]
fn join_group_sends_pair_message_to_initiator() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    // Relay routes B→A: accepts B's pipe (pipe_b_relay) first, then A's (pipe_a_relay).
    spawn_routing_relay(&relay_kp, pipe_b_relay, pipe_a_relay, nk_rx, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let b_noise_pub = device_b.public_key();
    let b_signing_pub = device_b.signing_public_key();

    // B connects first — matches relay accept order.
    let session_b = TruesealSession::connect(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _, _| {},
        nk.factory(),
    )
    .expect("session B");
    let session_a = TruesealSession::connect(
        pipe_a_client,
        relay_pub,
        device_a,
        |_, _, _| {},
        nk.factory(),
    )
    .expect("session A");

    // Capture the opaque token issued when B's Pair arrives.
    let req_token: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let rt = req_token.clone();
    session_a.set_on_member_request(move |token, _name| {
        *rt.lock().unwrap() = Some(token);
    });

    let token = session_a.pairing_token().expect("pairing window opens");
    let result = session_b.join_group(&token);
    assert!(result.is_ok(), "join_group failed: {:?}", result);

    wait_for(
        || req_token.lock().unwrap().is_some(),
        Duration::from_secs(5),
    );

    // A's pairing handler must have fired exactly once.
    let issued = req_token.lock().unwrap().clone();
    assert!(issued.is_some(), "A should receive a member request from B");

    // Accept B via the issued token — this consumes pending_members and builds a manifest.
    // Verifies B's noise_pub and signing_pub were correctly delivered.
    let admitted = session_a.accept_member(&issued.unwrap()).expect("accept");
    assert!(admitted, "accept_member must succeed");

    let manifest = session_a.manifest.lock().unwrap();
    let m = manifest.as_ref().expect("manifest must exist after accept");
    assert_eq!(m.members.len(), 2, "manifest must contain A and B");
    let b_member = m
        .members
        .iter()
        .find(|mb| mb.noise_pub == b_noise_pub)
        .expect("B must be in manifest");
    assert_eq!(
        b_member.signing_pub, b_signing_pub,
        "B signing_pub must match"
    );
}

/// join_group with a malformed token returns InvalidToken.
#[test]
fn join_group_invalid_token_returns_error() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay_kp2 = trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
    let (nk_rx2, nk2) = nk_push_channel();
    std::thread::spawn(move || {
        let _ = crate::version::testutil::xx_accept_after_prefix(pipe_relay, relay_kp2);
        while let Ok(p) = nk_rx2.recv() {
            let kp = trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
            std::thread::spawn(move || {
                if let Ok(sess) = crate::version::testutil::nk_accept_after_prefix(p, kp) {
                    if sess.receive().is_ok() {
                        let _ = sess.send(&crate::relay::frame(crate::relay::MsgType::Ack, &[]));
                    }
                }
            });
        }
    });

    let device = DeviceKeypair::generate();
    let session =
        TruesealSession::connect(pipe_client, relay_pub, device, |_, _, _| {}, nk2.factory())
            .expect("connect");

    let result = session.join_group("not-a-valid-token!!!!");
    assert!(
        matches!(result, Err(super::super::SessionError::InvalidToken)),
        "bad token should return InvalidToken, got {:?}",
        result
    );
}

/// A relay that refuses the push's Transport Version leaves the queued Pair
/// in the outbox — an unsupported Transport Version affects the whole
/// connection, not one entry, and entries stay queued until the library or
/// relay is upgraded (ADR-0022, ADR-0026). Before SYNC-5 moved the control
/// plane through the outbox, this surfaced synchronously as the typed
/// `RelayVersionUnsupported`; now `join_group` returns Ok after durably
/// queueing and the refusal is the pump's to retry.
#[test]
fn join_group_queues_the_pair_when_the_relay_refuses_our_version() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    // Receive session: a normal XX accept so connect succeeds and the
    // background receive loop has a live relay.
    std::thread::spawn(move || {
        let kp = trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        if let Ok(sess) = crate::version::testutil::xx_accept_after_prefix(pipe_relay, kp) {
            while sess.receive().is_ok() {}
        }
    });
    // Push sessions: the relay reads the prefix and refuses the Transport
    // Version, exactly as a pre-version relay would.
    let refusing_factory = move || {
        let (client, mut relay) = mem_pipe_pair();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut prefix = [0u8; crate::version::TRANSPORT_PREFIX_LEN];
            let mut filled = 0;
            while filled < prefix.len() {
                match relay.read(&mut prefix[filled..]) {
                    Ok(0) => return,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => return,
                }
            }
            let _ = relay.write_all(b"unsupported 1..1\n");
        });
        Ok(client)
    };

    let device = DeviceKeypair::generate();
    let session = TruesealSession::connect(
        pipe_client,
        relay_pub,
        device,
        |_, _, _| {},
        refusing_factory,
    )
    .expect("connect");

    let token = session.pairing_token().expect("pairing window opens");
    session
        .join_group(&token)
        .expect("join_group queues the Pair durably and returns Ok");

    // The pump keeps attempting (temporary class) and the entry never
    // leaves the outbox: give it several backoff cycles, then verify.
    std::thread::sleep(Duration::from_millis(500));
    let entries = session
        .op_log
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .undelivered_entries();
    assert_eq!(entries.len(), 1, "the Pair stays queued, undelivered");
    assert_eq!(
        entries[0].kind,
        crate::operation_log::OutboxKind::Control,
        "the queued Pair is a control-plane entry that never expires"
    );
}
