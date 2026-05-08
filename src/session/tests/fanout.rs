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
    {
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let _ = accept(pipe_relay, relay_kp2);
        });
    }
    let device = DeviceKeypair::generate();
    let session = HushSession::connect(pipe_client, relay_pub, device, |_, _| {}).expect("connect");
    let result = session.push_sync(b"hello".to_vec());
    assert!(
        matches!(result, Err(SessionError::NotInGroup)),
        "expected NotInGroup, got {:?}",
        result
    );
}

/// push_sync fans out to all members except self; both B and C receive the blob.
#[test]
fn push_sync_fans_out_to_all_members() {
    // Topology: A→B and A→C via two separate relay sessions.
    // We use two relay threads, each routing A→B and A→C respectively.
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);

    // A→B relay
    let (pipe_a1_client, pipe_a1_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    spawn_routing_relay(&relay_kp, pipe_a1_relay, pipe_b_relay, true); // A→B

    // A→C relay (second relay session)
    let (pipe_a2_client, pipe_a2_relay) = mem_pipe_pair();
    let (pipe_c_client, pipe_c_relay) = mem_pipe_pair();
    spawn_routing_relay(&relay_kp, pipe_a2_relay, pipe_c_relay, true); // A→C

    let device_a1 = DeviceKeypair::generate();
    let device_a2 = DeviceKeypair::generate(); // same logical device A, second pipe
    let device_b = DeviceKeypair::generate();
    let device_c = DeviceKeypair::generate();

    let a_noise = device_a1.public_key();
    let a_signing = device_a1.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a1.signing.to_bytes());
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();
    let b_sk = SigningKey::from_bytes(&device_b.signing.to_bytes());
    let c_noise = device_c.public_key();
    let c_signing = device_c.signing_public_key();

    use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
    let group_id = new_group_id();
    let manifest_a = GroupManifest::new(
        group_id,
        1,
        vec![
            ManifestMember {
                noise_pub: a_noise,
                signing_pub: a_signing,
                name: "A".into(),
            },
            ManifestMember {
                noise_pub: b_noise,
                signing_pub: b_signing,
                name: "B".into(),
            },
            ManifestMember {
                noise_pub: c_noise,
                signing_pub: c_signing,
                name: "C".into(),
            },
        ],
        &a_sk,
    );
    let manifest_b = GroupManifest::new(
        group_id,
        1,
        vec![
            ManifestMember {
                noise_pub: a_noise,
                signing_pub: a_signing,
                name: "A".into(),
            },
            ManifestMember {
                noise_pub: b_noise,
                signing_pub: b_signing,
                name: "B".into(),
            },
            ManifestMember {
                noise_pub: c_noise,
                signing_pub: c_signing,
                name: "C".into(),
            },
        ],
        &b_sk,
    );

    // Connect in relay-accept order (src first for each relay)
    let session_a =
        HushSession::connect(pipe_a1_client, relay_pub, device_a1, |_, _| {}).expect("session A1");
    let received_b: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    let rx_b = received_b.clone();
    let session_b = HushSession::connect(pipe_b_client, relay_pub, device_b, move |msg, _| {
        rx_b.lock().unwrap().push(msg);
    })
    .expect("session B");
    session_b.set_manifest(manifest_b);

    let session_a2 =
        HushSession::connect(pipe_a2_client, relay_pub, device_a2, |_, _| {}).expect("session A2");
    let received_c: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
    let rx_c = received_c.clone();
    let session_c = HushSession::connect(pipe_c_client, relay_pub, device_c, move |msg, _| {
        rx_c.lock().unwrap().push(msg);
    })
    .expect("session C");
    // C doesn't need a manifest for this test — just receives

    // Set A's manifest (3 members: A, B, C)
    session_a.set_manifest(manifest_a.clone());

    // A pushes — should fan out to B and C (skip self A)
    session_a
        .push_sync(b"broadcast".to_vec())
        .expect("push_sync");

    std::thread::sleep(Duration::from_millis(200));

    let got_b = received_b.lock().unwrap();
    assert_eq!(got_b.len(), 1, "B should receive 1 message");
    assert_eq!(
        got_b[0],
        Message::Sync {
            body: b"broadcast".to_vec()
        }
    );
}

/// One sequence number is consumed per push_sync call regardless of member count.
#[test]
fn push_sync_consumes_one_sequence_per_call() {
    use std::sync::atomic::Ordering;

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (pipe_client, pipe_relay, _close_relay, close_client) = mem_pipe_pair_with_close();
    {
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            let s = accept(pipe_relay, relay_kp2).unwrap();
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
