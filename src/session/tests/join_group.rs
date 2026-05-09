use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::device::DeviceKeypair;

use super::super::test_helpers::*;
use super::super::HushSession;

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
    let session_b =
        HushSession::connect(pipe_b_client, relay_pub, device_b, |_, _, _| {}, nk.factory()).expect("session B");
    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _, _| {}, nk.factory()).expect("session A");

    // Capture the opaque token issued when B's Pair arrives.
    let req_token: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let rt = req_token.clone();
    session_a.set_on_member_request(move |token, _name| {
        *rt.lock().unwrap() = Some(token);
    });

    let token = session_a.pairing_token();
    let result = session_b.join_group(&token);
    assert!(result.is_ok(), "join_group failed: {:?}", result);

    wait_for(|| req_token.lock().unwrap().is_some(), Duration::from_secs(5));

    // A's pairing handler must have fired exactly once.
    let issued = req_token.lock().unwrap().clone();
    assert!(issued.is_some(), "A should receive a member request from B");

    // Accept B via the issued token — this consumes pending_members and builds a manifest.
    // Verifies B's noise_pub and signing_pub were correctly delivered.
    let admitted = session_a.accept_member(&issued.unwrap());
    assert!(admitted, "accept_member must succeed");

    let manifest = session_a.manifest.lock().unwrap();
    let m = manifest.as_ref().expect("manifest must exist after accept");
    assert_eq!(m.members.len(), 2, "manifest must contain A and B");
    let b_member = m
        .members
        .iter()
        .find(|mb| mb.noise_pub == b_noise_pub)
        .expect("B must be in manifest");
    assert_eq!(b_member.signing_pub, b_signing_pub, "B signing_pub must match");
}

/// join_group with a malformed token returns InvalidToken.
#[test]
fn join_group_invalid_token_returns_error() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay_kp2 = hush_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
    let (nk_rx2, nk2) = nk_push_channel();
    std::thread::spawn(move || {
        let _ = hush_noise::session_xx::accept(pipe_relay, relay_kp2);
        while let Ok(p) = nk_rx2.recv() {
            let kp = hush_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
            std::thread::spawn(move || {
                if let Ok(sess) = hush_noise::session_nk::accept(p, kp) {
                    if sess.receive().is_ok() {
                        let _ = sess.send(&crate::relay::frame(crate::relay::MsgType::Ack, &[]));
                    }
                }
            });
        }
    });

    let device = DeviceKeypair::generate();
    let session = HushSession::connect(pipe_client, relay_pub, device, |_, _, _| {}, nk2.factory()).expect("connect");

    let result = session.join_group("not-a-valid-token!!!!");
    assert!(
        matches!(result, Err(super::super::SessionError::InvalidToken)),
        "bad token should return InvalidToken, got {:?}",
        result
    );
}
