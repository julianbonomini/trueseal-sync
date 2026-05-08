use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use hush_noise::{keypair::Keypair, session_xx::accept};

use crate::device::DeviceKeypair;
use crate::message::Message;
use crate::operation_log::MemLog;
use crate::session::SessionError;

use super::super::test_helpers::*;
use super::super::HushSession;

/// push_sync with no manifest returns NotInGroup.
#[test]
fn push_sync_no_manifest_returns_not_in_group() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    {
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _ = accept(pipe_relay, relay_kp2);
            while let Ok(p) = nk_rx.recv() {
                let kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
                std::thread::spawn(move || { let _ = hush_noise::session_nk::accept(p, kp2); });
            }
        });
    }
    let device = DeviceKeypair::generate();
    let session = HushSession::connect(pipe_client, relay_pub, device, |_, _| {}, nk.factory()).expect("connect");
    let result = session.push_sync(b"hello".to_vec());
    assert!(
        matches!(result, Err(SessionError::NotInGroup)),
        "expected NotInGroup, got {:?}",
        result
    );
}

/// push_sync fans out to all members except self; both B and C receive the blob.
/// Topology: single tripartite relay routes A's push to both B and C.
#[test]
fn push_sync_fans_out_to_all_members() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (pipe_c_client, pipe_c_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_tripartite_relay(&relay_kp, pipe_a_relay, pipe_b_relay, pipe_c_relay, nk_rx);

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
    let c_sk = SigningKey::from_bytes(&device_c.signing.to_bytes());

    use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
    let group_id = new_group_id();
    let members = vec![
        ManifestMember { noise_pub: a_noise, signing_pub: a_signing, name: "A".into() },
        ManifestMember { noise_pub: b_noise, signing_pub: b_signing, name: "B".into() },
        ManifestMember { noise_pub: c_noise, signing_pub: c_signing, name: "C".into() },
    ];
    let manifest_a = GroupManifest::new(group_id, 1, members.clone(), &a_sk);
    let manifest_b = GroupManifest::new(group_id, 1, members.clone(), &b_sk);
    let manifest_c = GroupManifest::new(group_id, 1, members.clone(), &c_sk);

    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _| {}, nk.factory()).expect("session A");

    let received_b: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    let rx_b = received_b.clone();
    let session_b = HushSession::connect(pipe_b_client, relay_pub, device_b, move |msg, _| {
        rx_b.lock().unwrap().push(msg);
    }, nk.factory())
    .expect("session B");
    session_b.set_manifest(manifest_b);

    let received_c: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    let rx_c = received_c.clone();
    let session_c = HushSession::connect(pipe_c_client, relay_pub, device_c, move |msg, _| {
        rx_c.lock().unwrap().push(msg);
    }, nk.factory())
    .expect("session C");
    session_c.set_manifest(manifest_c);

    session_a.set_manifest(manifest_a);

    // A pushes — should fan out to B and C (skip self)
    session_a
        .push_sync(b"broadcast".to_vec())
        .expect("push_sync");

    wait_for(|| received_b.lock().unwrap().len() >= 1, Duration::from_secs(5));
    wait_for(|| received_c.lock().unwrap().len() >= 1, Duration::from_secs(5));

    let got_b = received_b.lock().unwrap();
    assert_eq!(got_b.len(), 1, "B should receive 1 message");
    assert_eq!(got_b[0], Message::Sync { body: b"broadcast".to_vec() });

    let got_c = received_c.lock().unwrap();
    assert_eq!(got_c.len(), 1, "C should receive 1 message");
    assert_eq!(got_c[0], Message::Sync { body: b"broadcast".to_vec() });
}

/// One sequence number is consumed per push_sync call regardless of member count.
#[test]
fn push_sync_consumes_one_sequence_per_call() {
    use std::sync::atomic::Ordering;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay, _close_relay, close_client) = mem_pipe_pair_with_close();
    let (nk_rx, nk) = nk_push_channel();
    {
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let s = accept(pipe_relay, relay_kp2).unwrap();
            // drain nk connections (pushes go offline in this test but drain for safety)
            let _ = nk_rx;
            loop {
                if s.receive().is_err() {
                    break;
                }
            }
        });
    }

    let device = DeviceKeypair::generate();
    let noise = device.public_key();
    let signing = device.signing_public_key();
    let sk = SigningKey::from_bytes(&device.signing.to_bytes());

    use crate::keys::NoisePublicKey;
    use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
    // Two-member manifest: self + one peer (peer has a dummy noise pub)
    let peer_noise = NoisePublicKey([0xAAu8; 32]);
    let peer_signing = crate::keys::SigningPublicKey([0xBBu8; 32]);
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

    let session = HushSession::connect_with_log(
        pipe_client,
        relay_pub,
        device,
        |_, _| {},
        Box::new(MemLog::new()),
        nk.factory(),
    )
    .expect("connect");
    session.set_manifest(manifest);

    // Disconnect so pushes go to the undelivered outbox path.
    close_client.store(true, Ordering::Release);
    std::thread::sleep(Duration::from_millis(100));

    // Two push_sync calls → two outbox entries, sequence numbers 0 and 1.
    session.push_sync(b"first".to_vec()).ok();
    session.push_sync(b"second".to_vec()).ok();

    let undelivered = session.op_log.lock().unwrap().undelivered_entries();
    // 1 peer × 2 calls = 2 outbox entries, sequence numbers 0 and 1
    assert_eq!(undelivered.len(), 2, "expected 2 outbox entries");
    assert!(
        undelivered[0].sequence < undelivered[1].sequence,
        "sequence numbers must be strictly increasing"
    );
}

/// 4-member group {A, B, C, D}: A pushes once; B, C, and D all receive exactly
/// 1 message with the correct blob and identical sequence number.
#[test]
fn push_sync_fans_out_to_n_recipients() {
    use std::sync::{Arc, Condvar, Mutex};

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (pipe_c_client, pipe_c_relay) = mem_pipe_pair();
    let (pipe_d_client, pipe_d_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_quadpartite_relay(&relay_kp, pipe_a_relay, pipe_b_relay, pipe_c_relay, pipe_d_relay, nk_rx);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let device_c = DeviceKeypair::generate();
    let device_d = DeviceKeypair::generate();

    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = ed25519_dalek::SigningKey::from_bytes(&device_a.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let b_sk = ed25519_dalek::SigningKey::from_bytes(&device_b.signing.to_bytes());
    let c_noise = device_c.public_key();
    let c_signing = device_c.signing_public_key();
    let c_sk = ed25519_dalek::SigningKey::from_bytes(&device_c.signing.to_bytes());
    let d_noise = device_d.public_key();
    let d_signing = device_d.signing_public_key();
    let d_sk = ed25519_dalek::SigningKey::from_bytes(&device_d.signing.to_bytes());

    use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
    let group_id = new_group_id();
    let members = vec![
        ManifestMember { noise_pub: a_noise, signing_pub: a_signing, name: "A".into() },
        ManifestMember { noise_pub: b_noise, signing_pub: b_signing, name: "B".into() },
        ManifestMember { noise_pub: c_noise, signing_pub: c_signing, name: "C".into() },
        ManifestMember { noise_pub: d_noise, signing_pub: d_signing, name: "D".into() },
    ];
    let manifest_a = GroupManifest::new(group_id, 1, members.clone(), &a_sk);
    let manifest_b = GroupManifest::new(group_id, 1, members.clone(), &b_sk);
    let manifest_c = GroupManifest::new(group_id, 1, members.clone(), &c_sk);
    let manifest_d = GroupManifest::new(group_id, 1, members.clone(), &d_sk);

    // Helper: condvar-based collector for received messages.
    type Received = Arc<(Mutex<Vec<Message>>, Condvar)>;
    fn make_received() -> Received { Arc::new((Mutex::new(Vec::new()), Condvar::new())) }
    fn make_cb(r: Received) -> impl Fn(Message, [u8; 32]) + Send + 'static {
        move |msg, _| {
            let (lock, cvar) = &*r;
            lock.lock().unwrap().push(msg);
            cvar.notify_all();
        }
    }

    let received_b = make_received();
    let received_c = make_received();
    let received_d = make_received();

    let session_a =
        HushSession::connect(pipe_a_client, relay_pub, device_a, |_, _| {}, nk.factory()).expect("A");
    let session_b = HushSession::connect(pipe_b_client, relay_pub, device_b, make_cb(received_b.clone()), nk.factory()).expect("B");
    let session_c = HushSession::connect(pipe_c_client, relay_pub, device_c, make_cb(received_c.clone()), nk.factory()).expect("C");
    let session_d = HushSession::connect(pipe_d_client, relay_pub, device_d, make_cb(received_d.clone()), nk.factory()).expect("D");

    session_a.set_manifest(manifest_a);
    session_b.set_manifest(manifest_b);
    session_c.set_manifest(manifest_c);
    session_d.set_manifest(manifest_d);

    session_a.push_sync(b"broadcast4".to_vec()).expect("push_sync");

    // Wait for all three recipients.
    for (label, r) in [("B", &received_b), ("C", &received_c), ("D", &received_d)] {
        let (lock, cvar) = r.as_ref();
        let result = cvar
            .wait_timeout_while(lock.lock().unwrap(), std::time::Duration::from_secs(5), |v| v.is_empty())
            .unwrap();
        assert!(!result.1.timed_out(), "{label} must receive the blob within 5s");
        assert_eq!(result.0.len(), 1, "{label} must receive exactly 1 message");
        assert_eq!(
            result.0[0],
            Message::Sync { body: b"broadcast4".to_vec() },
            "{label} blob must match"
        );
    }
}
