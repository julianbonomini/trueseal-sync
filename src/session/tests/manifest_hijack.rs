//! Repro for the joiner manifest-trust hijack (trueseal-roadmap#4).
//!
//! Each test asserts the SECURE behaviour. A failing test means the variant
//! reproduces against the current code.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use trueseal_noise::{keypair::Keypair, session_xx::accept};

use crate::device::DeviceKeypair;
use crate::envelope::SigningKeypair;
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::message::Message;
use crate::operation_log::MemLog;
use crate::relay::{build_push_blob, frame, parse, MsgType};

use super::super::test_helpers::*;
use super::super::TruesealSession;

fn attacker_manifest(
    attacker: &DeviceKeypair,
    victim_noise: crate::keys::NoisePublicKey,
    victim_signing: crate::keys::SigningPublicKey,
) -> GroupManifest {
    let sk = SigningKey::from_bytes(&attacker.signing.to_bytes());
    GroupManifest::new(
        new_group_id(),
        1,
        vec![
            ManifestMember {
                noise_pub: attacker.public_key(),
                signing_pub: attacker.signing_public_key(),
                name: "Attacker".into(),
            },
            ManifestMember {
                noise_pub: victim_noise,
                signing_pub: victim_signing,
                name: "Victim".into(),
            },
        ],
        &sk,
    )
}

/// Variant 1: a joiner that scanned A's token must only accept a first
/// manifest issued by A. Today it accepts any self-signed manifest that
/// arrives first, and then rejects A's legitimate one (GroupIdMismatch).
#[test]
fn joiner_accepts_only_initiator_manifest() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pa_c, pa_r) = mem_pipe_pair();
    let (pb_c, pb_r) = mem_pipe_pair();
    let (pm_c, pm_r) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_tripartite_relay(&relay_kp, pa_r, pb_r, pm_r, nk_rx);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let device_m = DeviceKeypair::generate();
    let a_signing = device_a.signing_public_key();
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let forged = attacker_manifest(&device_m, b_noise, b_signing);

    let session_a = TruesealSession::connect(pa_c, relay_pub, device_a, |_, _, _| {}, nk.factory())
        .expect("A");
    let session_b = TruesealSession::connect(pb_c, relay_pub, device_b, |_, _, _| {}, nk.factory())
        .expect("B");
    let session_m = TruesealSession::connect(pm_c, relay_pub, device_m, |_, _, _| {}, nk.factory())
        .expect("M");

    let pending: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let p = pending.clone();
    session_a.set_on_member_request(move |token, _| p.lock().unwrap().push(token));

    let token = session_a.pairing_token();
    session_b.join_group(&token).expect("join");
    wait_for(|| !pending.lock().unwrap().is_empty(), Duration::from_secs(5));

    // Attacker races A's manifest.
    session_m
        .push_message(&Message::GroupManifest { manifest: forged }, b_noise)
        .expect("attacker push");
    std::thread::sleep(Duration::from_millis(200));

    let t = pending.lock().unwrap()[0].clone();
    assert!(session_a.accept_member(&t), "A admits B");
    std::thread::sleep(Duration::from_millis(300));

    let a_group = session_a.manifest.lock().unwrap().as_ref().unwrap().group_id;
    let b_manifest = session_b.manifest.lock().unwrap().clone();
    let b_manifest = b_manifest.expect("B must hold a manifest");
    assert_eq!(
        b_manifest.issued_by, a_signing.0,
        "B installed a manifest not issued by the initiator it paired with"
    );
    assert_eq!(b_manifest.group_id, a_group, "B must be in A's group");
}

/// Variant 2: a device that never called `join_group` must not accept any
/// manifest. Today an unsolicited self-signed manifest is installed.
#[test]
fn device_that_never_joined_rejects_unsolicited_manifest() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pm_c, pm_r) = mem_pipe_pair();
    let (pb_c, pb_r) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_bidirectional_relay(&relay_kp, pm_r, pb_r, nk_rx);

    let device_m = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let b_noise = device_b.public_key();
    let forged = attacker_manifest(&device_m, b_noise, device_b.signing_public_key());

    let changed = Arc::new(Mutex::new(0usize));
    let c = changed.clone();
    let session_m = TruesealSession::connect(pm_c, relay_pub, device_m, |_, _, _| {}, nk.factory())
        .expect("M");
    let session_b = TruesealSession::connect_full(
        pb_c,
        relay_pub,
        device_b,
        |_, _, _| {},
        Box::new(MemLog::new()),
        || {},
        move |_| *c.lock().unwrap() += 1,
        || {},
        nk.factory(),
    )
    .expect("B");

    session_m
        .push_message(&Message::GroupManifest { manifest: forged }, b_noise)
        .expect("attacker push");
    std::thread::sleep(Duration::from_millis(300));

    assert!(
        session_b.manifest.lock().unwrap().is_none(),
        "a device with no pending join installed an unsolicited manifest"
    );
    assert_eq!(*changed.lock().unwrap(), 0, "on_manifest_changed must not fire");
}

/// Variant 3: the relay itself (no client involved) can inject a manifest,
/// because the envelope author key is self-asserted inside the payload and
/// any key verifies against itself.
#[test]
fn relay_cannot_inject_manifest() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pb_c, pb_r) = mem_pipe_pair();

    let device_b = DeviceKeypair::generate();
    let b_noise = device_b.public_key();
    let relay_device = DeviceKeypair::generate();
    let forged = attacker_manifest(&relay_device, b_noise, device_b.signing_public_key());
    let relay_signer =
        SigningKeypair::from_signing_key(SigningKey::from_bytes(&relay_device.signing.to_bytes()));

    let kp = Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        let sess = accept(pb_r, kp).unwrap();
        let push = build_push_blob(
            &Message::GroupManifest { manifest: forged },
            b_noise,
            1,
            vec![],
            &relay_signer,
        )
        .unwrap();
        let (_, body) = parse(&push).unwrap();
        let mut deliver = 7u64.to_be_bytes().to_vec();
        deliver.extend_from_slice(&body[32..]);
        sess.send(&frame(MsgType::Deliver, &deliver)).unwrap();
        while sess.receive().is_ok() {}
    });

    let session_b = TruesealSession::connect(
        pb_c,
        relay_pub,
        device_b,
        |_, _, _| {},
        || Err("no push".into()),
    )
    .expect("B");
    std::thread::sleep(Duration::from_millis(300));

    assert!(
        session_b.manifest.lock().unwrap().is_none(),
        "relay-injected manifest was installed"
    );
}

/// Variant 4: before any manifest exists, the member filter is skipped, so a
/// Sync from anyone reaches the application.
#[test]
fn manifestless_device_drops_sync_from_non_member() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pm_c, pm_r) = mem_pipe_pair();
    let (pb_c, pb_r) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_bidirectional_relay(&relay_kp, pm_r, pb_r, nk_rx);

    let device_m = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let b_noise = device_b.public_key();

    let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(vec![]));
    let r = received.clone();
    let session_m = TruesealSession::connect(pm_c, relay_pub, device_m, |_, _, _| {}, nk.factory())
        .expect("M");
    let _session_b = TruesealSession::connect(
        pb_c,
        relay_pub,
        device_b,
        move |msg, _, _| r.lock().unwrap().push(msg),
        nk.factory(),
    )
    .expect("B");

    session_m
        .push_message(&Message::Sync { body: b"injected".to_vec() }, b_noise)
        .expect("push");
    std::thread::sleep(Duration::from_millis(300));

    assert!(
        received.lock().unwrap().is_empty(),
        "Sync from a non-member reached on_message on a device with no manifest"
    );
}

/// Variant 5: the Pair body's `signing_pub` is not bound to the envelope
/// signer. M can request admission under X's signing key with M's noise key,
/// and the admitter is shown X's name.
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

    let session_a = TruesealSession::connect(pa_c, relay_pub, device_a, |_, _, _| {}, nk.factory())
        .expect("A");
    let session_m = TruesealSession::connect(pm_c, relay_pub, device_m, |_, _, _| {}, nk.factory())
        .expect("M");

    let pending: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let p = pending.clone();
    session_a.set_on_member_request(move |token, _| p.lock().unwrap().push(token));
    let _ = session_a.pairing_token();

    session_m
        .push_message(
            &Message::Pair {
                noise_pub: m_noise.0,
                signing_pub: x_signing.0,
            },
            a_noise,
        )
        .expect("push");
    std::thread::sleep(Duration::from_millis(300));

    if let Some(t) = pending.lock().unwrap().first().cloned() {
        session_a.accept_member(&t);
    }
    let admitted_x = session_a
        .manifest
        .lock()
        .unwrap()
        .as_ref()
        .map(|m| m.contains_signing_pub(&x_signing.0))
        .unwrap_or(false);
    assert!(
        !admitted_x,
        "A admitted X's signing key on the strength of a Pair signed by M"
    );
}
