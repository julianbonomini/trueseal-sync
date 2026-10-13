//! SYNC-17 (#109): every connection the session opens flows through the
//! injected factories — there is no hidden socket-open path. These factories
//! count their calls; an initial receive connect, a reconnect, and a push
//! must each be observed. `scripts/check-connection-factory.sh` (CI) is the
//! structural half of the guarantee: production code cannot open a socket
//! outside src/connection.rs at all.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::device::DeviceKeypair;
use crate::envelope::SigningKeypair;
use crate::keys::{NoisePublicKey, SigningPublicKey};
use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
use crate::member::member_name;
use crate::operation_log::MemLog;

use super::super::test_helpers::*;
use super::super::TruesealSession;

/// Two-member genesis (device + one peer) so `push_sync` has a fan-out target.
fn membership(device: &DeviceKeypair, peer: &SigningKeypair) -> GroupManifest {
    let sk = ed25519_dalek::SigningKey::from_bytes(&device.signing.to_bytes());
    let self_sp = device.signing_public_key();
    let peer_sp = peer.public_key();
    GroupManifest::new(
        new_group_id(),
        1,
        vec![
            ManifestMember {
                noise_pub: device.public_key(),
                signing_pub: self_sp,
                name: member_name(&self_sp),
            },
            ManifestMember {
                noise_pub: NoisePublicKey([9u8; 32]),
                signing_pub: SigningPublicKey(peer.public_key_bytes()),
                name: member_name(&peer_sp),
            },
        ],
        &sk,
    )
}

/// A custom factory observes the initial receive connection AND every push
/// connection.
#[test]
fn every_receive_and_push_connection_flows_through_the_injected_factories() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device = DeviceKeypair::generate();
    let peer = SigningKeypair::generate();

    let manifest = membership(&device, &peer);

    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_single_relay(&relay_kp, pipe_relay, nk_rx);

    let receive_calls = Arc::new(AtomicUsize::new(0));
    let push_calls = Arc::new(AtomicUsize::new(0));

    let rc = receive_calls.clone();
    let pipe_slot: Arc<Mutex<Option<MemPipe>>> = Arc::new(Mutex::new(Some(pipe_client)));
    let receive_factory = move || {
        rc.fetch_add(1, Ordering::SeqCst);
        pipe_slot
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| "no more receive pipes".to_string())
    };
    let pc = push_calls.clone();
    let inner_push = nk.factory();
    let push_factory = move || {
        pc.fetch_add(1, Ordering::SeqCst);
        inner_push()
    };

    let connected = Arc::new(AtomicBool::new(false));
    let cc = connected.clone();
    let session = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        || {},
        receive_factory,
        push_factory,
        None,
        Some(Box::new(move |change| {
            if matches!(change, crate::session::ConnectionChange::Connected) {
                cc.store(true, Ordering::SeqCst);
            }
        })),
    )
    .expect("session");

    wait_for(
        || connected.load(Ordering::SeqCst),
        Duration::from_secs(5),
    );
    assert!(
        receive_calls.load(Ordering::SeqCst) >= 1,
        "the receive connection must come from the injected receive factory"
    );

    // A send must drive its push through the injected push factory.
    session.set_manifest(manifest);
    session
        .push_sync(b"factory observability".to_vec())
        .expect("push_sync durably queues");
    wait_for(
        || push_calls.load(Ordering::SeqCst) >= 1,
        Duration::from_secs(5),
    );
}

/// A reconnect also flows through the injected receive factory — the
/// reconnect loop has no socket-open path of its own.
#[test]
fn reconnect_flows_through_the_injected_receive_factory() {
    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let device = DeviceKeypair::generate();

    // Two receive connections: the first is severed, the reconnect loop must
    // obtain the second from the factory.
    let (pipe1_client, pipe1_relay, _close_relay1, close_client1) = mem_pipe_pair_with_close();
    let (pipe2_client, pipe2_relay) = mem_pipe_pair();
    for pipe in [pipe1_relay, pipe2_relay] {
        let relay_kp2 =
            trueseal_noise::keypair::Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            if let Ok(sess) = crate::version::testutil::xx_accept_after_prefix(pipe, relay_kp2) {
                while sess.receive().is_ok() {}
            }
        });
    }

    let receive_calls = Arc::new(AtomicUsize::new(0));
    let rc = receive_calls.clone();
    let pipes: Arc<Mutex<Vec<MemPipe>>> = Arc::new(Mutex::new(vec![pipe2_client, pipe1_client]));
    let receive_factory = move || {
        rc.fetch_add(1, Ordering::SeqCst);
        pipes
            .lock()
            .unwrap()
            .pop()
            .ok_or_else(|| "no more receive pipes".to_string())
    };
    // ^ vec![pipe2, pipe1] with pop(): first call serves pipe1, the reconnect
    // serves pipe2.

    let connected_count = Arc::new(AtomicUsize::new(0));
    let cc = connected_count.clone();
    let _session = TruesealSession::<MemPipe>::connect_background(
        relay_pub,
        device,
        |_, _, _| {},
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        || {},
        receive_factory,
        || Err("push unused in this test".to_string()),
        Some(Duration::from_millis(50)), // fast reconnect
        Some(Box::new(move |change| {
            if matches!(change, crate::session::ConnectionChange::Connected) {
                cc.fetch_add(1, Ordering::SeqCst);
            }
        })),
    )
    .expect("session");

    wait_for(
        || connected_count.load(Ordering::SeqCst) >= 1,
        Duration::from_secs(5),
    );
    // Sever the first connection: the client must detect the dead link and
    // reconnect through the factory.
    close_client1.store(true, Ordering::Release);
    wait_for(
        || connected_count.load(Ordering::SeqCst) >= 2,
        Duration::from_secs(5),
    );
    assert!(
        receive_calls.load(Ordering::SeqCst) >= 2,
        "both the initial connect and the reconnect must come from the injected factory"
    );
}
