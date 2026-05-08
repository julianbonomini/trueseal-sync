use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::device::DeviceKeypair;
use crate::message::Message;
use crate::operation_log::MemLog;

use super::super::test_helpers::*;
use super::super::HushSession;
use super::{make_one_member_manifest, make_two_member_manifest};

/// A admits B into an empty group → both have a 2-member manifest.
#[test]
fn accept_pair_creates_genesis_manifest() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    // A→B routing: relay accepts A (pipe_a_relay) first as src, then B (pipe_b_relay) as dst.
    spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_b_relay, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();

    // A connects first (relay accepts pipe_a_relay first).
    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _| {}).expect("session A");
    // B connects second, collects inbound GroupManifest.
    let b_manifests: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    let bm = b_manifests.clone();
    let _session_b = HushSession::connect(pipe_b_client, relay_pub, device_b, move |msg, _| {
        bm.lock().unwrap().push(msg);
    })
    .expect("session B");

    // A opens a pairing window then accepts B.
    let _token = session_a.pairing_token();
    let admitted = session_a.accept_pair(b_noise, b_signing);
    assert!(admitted, "accept_pair must return true when window is open");

    std::thread::sleep(Duration::from_millis(150));

    // A's manifest should have 2 members.
    let a_manifest = session_a.manifest.lock().unwrap();
    assert!(
        a_manifest.is_some(),
        "A must have a manifest after accept_pair"
    );
    let m = a_manifest.as_ref().unwrap();
    assert_eq!(m.members.len(), 2, "genesis manifest must have 2 members");
    assert_eq!(m.version, 1);
}

/// accept_pair sends GroupManifest to the new member.
#[test]
fn accept_pair_sends_manifest_to_new_member() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_b_relay, true);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();

    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _| {}).expect("session A");

    let b_manifest_received: Arc<Mutex<Option<crate::manifest::GroupManifest>>> =
        Arc::new(Mutex::new(None));
    let bmr = b_manifest_received.clone();
    let _session_b = HushSession::connect_full(
        pipe_b_client,
        relay_pub,
        device_b,
        |_, _| {},
        Box::new(MemLog::new()),
        || {},
        |_| {},
        || {},
    )
    .expect("session B");
    // Watch B's manifest directly.
    let b_manifest_arc = _session_b.manifest.clone();

    let _token = session_a.pairing_token();
    session_a.accept_pair(b_noise, b_signing);

    std::thread::sleep(Duration::from_millis(150));

    // B should have received and stored the GroupManifest.
    let b_m = b_manifest_arc.lock().unwrap();
    assert!(b_m.is_some(), "B must have a manifest after accept_pair");
    let m = b_m.as_ref().unwrap();
    assert_eq!(m.members.len(), 2);
}

/// accept_pair when no window is open returns false and no manifest is issued.
#[test]
fn accept_pair_without_window_returns_false() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let relay_kp2 = hush_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
    std::thread::spawn(move || {
        let _ = hush_noise::session::accept(pipe_relay, relay_kp2);
    });

    let device = DeviceKeypair::generate();
    let session = HushSession::connect(pipe_client, relay_pub, device, |_, _| {}).expect("connect");

    let dummy_noise = crate::keys::NoisePublicKey([0xAA; 32]);
    let dummy_signing = crate::keys::SigningPublicKey([0xBB; 32]);

    let result = session.accept_pair(dummy_noise, dummy_signing);
    assert!(!result, "no window → must return false");
    assert!(
        session.manifest.lock().unwrap().is_none(),
        "no manifest should be created when window is closed"
    );
}

/// A admits C into existing {A,B} group → all three have a 3-member manifest.
#[test]
fn accept_pair_extends_existing_manifest() {
    use crate::keys::{NoisePublicKey, SigningPublicKey};

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_c_client, pipe_c_relay) = mem_pipe_pair();
    spawn_routing_relay(&relay_kp, pipe_a_relay, pipe_c_relay, true);

    let device_a = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());

    let device_c = DeviceKeypair::generate();
    let c_noise = device_c.public_key();
    let c_signing = device_c.signing_public_key();

    // Give A an existing {A, dummy_B} manifest (version 1).
    let dummy_b_noise = NoisePublicKey([0xBB; 32]);
    let dummy_b_signing = SigningPublicKey([0xCC; 32]);
    let v1 = make_two_member_manifest(a_noise, a_signing, &a_sk, dummy_b_noise, dummy_b_signing);

    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _| {}).expect("session A");
    session_a.set_manifest(v1);

    let c_manifest_arc = {
        let _session_c = HushSession::connect_full(
            pipe_c_client,
            relay_pub,
            device_c,
            |_, _| {},
            Box::new(MemLog::new()),
            || {},
            |_| {},
            || {},
        )
        .expect("session C");
        _session_c.manifest.clone()
    };

    let _token = session_a.pairing_token();
    session_a.accept_pair(c_noise, c_signing);

    std::thread::sleep(Duration::from_millis(150));

    let a_m = session_a.manifest.lock().unwrap();
    assert_eq!(a_m.as_ref().unwrap().members.len(), 3, "A: 3 members");
    assert_eq!(a_m.as_ref().unwrap().version, 2, "A: version incremented");
    drop(a_m);

    let c_m = c_manifest_arc.lock().unwrap();
    assert!(c_m.is_some(), "C must receive the manifest");
    assert_eq!(c_m.as_ref().unwrap().members.len(), 3, "C: 3 members");
}

/// #28 bootstrap: {A, B} exist, A admits C, C immediately sends a blob, B receives it.
#[test]
fn new_member_bootstrap_can_send_to_existing_members() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (pipe_c_client, pipe_c_relay) = mem_pipe_pair();
    spawn_tripartite_relay(&relay_kp, pipe_a_relay, pipe_b_relay, pipe_c_relay);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let device_c = DeviceKeypair::generate();
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let b_sk = SigningKey::from_bytes(&device_b.signing.to_bytes());
    let c_noise = device_c.public_key();
    let c_signing = device_c.signing_public_key();

    // A and B already form a 2-member group.
    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _| {}).expect("session A");
    let v1 = make_two_member_manifest(a_noise, a_signing, &a_sk, b_noise, b_signing);
    session_a.set_manifest(v1.clone());

    let b_received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let br = b_received.clone();
    let session_b = HushSession::connect(pipe_b_client, relay_pub, device_b, move |msg, _| {
        if let crate::message::Message::Sync { body } = msg {
            br.lock().unwrap().push(body);
        }
    })
    .expect("session B");
    session_b.set_manifest(v1);

    // C connects; no manifest yet.
    let session_c =
        HushSession::connect(pipe_c_client, relay_pub, device_c, |_, _| {}).expect("session C");

    // A opens pairing window and admits C.
    let _token = session_a.pairing_token();
    session_a.accept_pair(c_noise, c_signing);

    // Give C time to receive the bootstrap GroupManifest from A.
    std::thread::sleep(Duration::from_millis(200));

    // C should now have a 3-member manifest.
    assert_eq!(
        session_c
            .manifest
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .members
            .len(),
        3,
        "C must have 3-member manifest after bootstrap"
    );

    // C sends a blob — should fan out to A and B.
    session_c
        .push_sync(b"hello from C".to_vec())
        .expect("C push_sync");

    std::thread::sleep(Duration::from_millis(500));

    let got = b_received.lock().unwrap();
    assert_eq!(got.len(), 1, "B must receive C's blob");
    assert_eq!(got[0], b"hello from C");
}
