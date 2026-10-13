//! SYNC-4 regression tests (trueseal-sync#96): the `Pair` body's `signing_pub`
//! must be bound to the Envelope signer. An unbound `signing_pub` lets a
//! requester get a signing key it does not control admitted, or pair a
//! victim's signing key with an attacker's routing address (joiner
//! manifest-trust hijack, repro variant 5 — trueseal-roadmap#4).
//!
//! The check must survive SYNC-3's Pairing Secret proof; both are required
//! (ADR-0023 Consequences).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::device::DeviceKeypair;
use crate::message::Message;

use super::super::test_helpers::*;

/// Extract the Pairing Secret from a Pairing Token (ADR-0023) so a
/// hand-built Pair passes the admitter's secret check.
fn token_secret(token: &str) -> [u8; 32] {
    let (_, _, secret, _) = crate::message::decode_pairing_token(token).expect("token decodes");
    secret
}
use super::super::TruesealSession;

/// Repro variant 5, ported from `repro/joiner-manifest-hijack`:
/// M pushes `Pair{noise_pub: M, signing_pub: X}` — signed by M but claiming
/// victim X's signing key. The admitter must raise no Join Request and change
/// no state, so X's key can never be admitted on the strength of M's
/// signature.
#[test]
fn pair_signing_pub_must_match_envelope_signer() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pa_c, pa_r) = mem_pipe_pair();
    let (pm_c, pm_r) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_bidirectional_relay(&relay_kp, pa_r, pm_r, nk_rx);

    let device_a = DeviceKeypair::generate();
    let device_m = DeviceKeypair::generate();
    let victim_x = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let m_noise = device_m.public_key();
    let x_signing = victim_x.signing_public_key();

    let session_a =
        TruesealSession::connect(pa_c, relay_pub, device_a, |_, _, _| {}, nk.factory()).expect("A");
    let session_m =
        TruesealSession::connect(pm_c, relay_pub, device_m, |_, _, _| {}, nk.factory()).expect("M");

    let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let r = requests.clone();
    session_a.set_on_member_request(move |token, _| r.lock().unwrap().push(token));
    let token = session_a.pairing_token();

    session_m
        .push_message(
            &Message::Pair {
                noise_pub: m_noise.0,
                signing_pub: x_signing.0,
                secret: token_secret(&token),
            },
            a_noise,
        )
        .expect("push");

    // Give the relay + A's dispatch loop time to (mis)handle the Pair.
    std::thread::sleep(Duration::from_millis(300));

    assert!(
        requests.lock().unwrap().is_empty(),
        "a Pair whose signing_pub differs from the Envelope signer must raise no Join Request"
    );
    assert!(
        session_a
            .pending_members
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "a mismatched Pair must not create a pending member"
    );
    assert!(
        session_a.manifest.lock().unwrap().is_none(),
        "a mismatched Pair must not change manifest state"
    );
}

/// Swapped-payload variant: M captures B's legitimate Pair payload (B's own
/// keys) and re-seals it inside an Envelope M signs. The body is internally
/// consistent but the signer is wrong — it must be dropped exactly like a
/// mismatched body.
#[test]
fn replayed_pair_payload_under_different_signer_is_dropped() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pa_c, pa_r) = mem_pipe_pair();
    let (pm_c, pm_r) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_bidirectional_relay(&relay_kp, pa_r, pm_r, nk_rx);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate(); // the "captured" Pair's real owner
    let device_m = DeviceKeypair::generate(); // the replaying attacker
    let a_noise = device_a.public_key();
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();

    let session_a =
        TruesealSession::connect(pa_c, relay_pub, device_a, |_, _, _| {}, nk.factory()).expect("A");
    let session_m =
        TruesealSession::connect(pm_c, relay_pub, device_m, |_, _, _| {}, nk.factory()).expect("M");

    let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let r = requests.clone();
    session_a.set_on_member_request(move |token, _| r.lock().unwrap().push(token));
    let token = session_a.pairing_token();

    // M replays B's Pair payload inside an Envelope signed by M.
    session_m
        .push_message(
            &Message::Pair {
                noise_pub: b_noise.0,
                signing_pub: b_signing.0,
                secret: token_secret(&token),
            },
            a_noise,
        )
        .expect("push");

    std::thread::sleep(Duration::from_millis(300));

    assert!(
        requests.lock().unwrap().is_empty(),
        "a Pair replayed under a different signer must raise no Join Request"
    );
    assert!(
        session_a.manifest.lock().unwrap().is_none(),
        "a replayed Pair must not change manifest state"
    );
}

/// Happy path: a Pair whose body keys match the Envelope signer still raises
/// a Join Request, and admission adds exactly those keys to the manifest.
/// (Existing coverage: `accept_member::pair_inside_window_fires_on_member_request`,
/// `join_group::join_group_sends_pair_message_to_initiator` — this test pins
/// the same path end-to-end through `accept_member`.)
#[test]
fn matched_pair_still_raises_join_request_and_admits() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pa_c, pa_r) = mem_pipe_pair();
    let (pm_c, pm_r) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_bidirectional_relay(&relay_kp, pa_r, pm_r, nk_rx);

    let device_a = DeviceKeypair::generate();
    let device_m = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let m_noise = device_m.public_key();
    let m_signing = device_m.signing_public_key();

    let session_a =
        TruesealSession::connect(pa_c, relay_pub, device_a, |_, _, _| {}, nk.factory()).expect("A");
    let session_m =
        TruesealSession::connect(pm_c, relay_pub, device_m, |_, _, _| {}, nk.factory()).expect("M");

    let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let r = requests.clone();
    session_a.set_on_member_request(move |token, _| r.lock().unwrap().push(token));
    let token = session_a.pairing_token();

    session_m
        .push_message(
            &Message::Pair {
                noise_pub: m_noise.0,
                signing_pub: m_signing.0,
                secret: token_secret(&token),
            },
            a_noise,
        )
        .expect("push");

    wait_for(
        || !requests.lock().unwrap().is_empty(),
        Duration::from_secs(5),
    );

    let token = requests.lock().unwrap()[0].clone();
    assert!(
        session_a.accept_member(&token).expect("accept"),
        "accept_member must succeed for a matched Pair"
    );
    let manifest = session_a.manifest.lock().unwrap();
    let m = manifest.as_ref().expect("manifest after admission");
    assert!(
        m.contains_signing_pub(&m_signing.0),
        "manifest must contain M's signing key"
    );
    assert!(
        m.members.iter().any(|mb| mb.noise_pub == m_noise),
        "manifest must contain M's noise key"
    );
}
