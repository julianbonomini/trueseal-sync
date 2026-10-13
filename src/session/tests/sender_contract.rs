//! SYNC-5 (#97), ADR-0026 — the sender half of the delivery contract: the
//! outbox pump's retry classes, head-of-line per recipient, expiry,
//! delivered-row deletion, and control plane through the outbox.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use trueseal_noise::keypair::Keypair;

use crate::delivery_issue::{DeliveryIssue, SendFailedReason};
use crate::device::DeviceKeypair;
use crate::envelope::Envelope;
use crate::manifest::{GroupManifest, ManifestMember};
use crate::member::member_name;
use crate::message::{message_id, Message};
use crate::operation_log::{now_secs, LogEntry, MemLog, OutboxKind};
use crate::relay::{frame, parse, MsgType};
use crate::store::{PersistentLog, Store};

use super::super::test_helpers::*;
use super::super::TruesealSession;
use super::make_two_member_manifest;

/// What the scripted push relay does with one NK push.
#[derive(Clone, Copy)]
enum Verdict {
    /// Record the push and confirm persistence (ADR-0019).
    Ack,
    /// Record the push and refuse it with a relay Error frame. `None` is
    /// the legacy reasonless body (pre-RELAY-5 relays, kept well-formed by
    /// the ADR-0008 amendment); `Some(code)` is a typed reason byte — bit
    /// 7 set marks a temporary refusal (0x81 inboxFull, 0x82 rateLimited,
    /// 0x83 unavailable, 0x84 internal).
    Error(Option<u8>),
    /// Record the push, then drop the connection WITHOUT an ack — the
    /// "crash after the relay persisted but before the ack" case: the
    /// sender must retry and the recipient dedups the re-delivery.
    Close,
}

/// A relay that holds the client's Receive Session open and answers NK
/// pushes from a script (falling back to a default verdict once the script
/// is exhausted), recording every push it receives.
struct ScriptedPushRelay {
    /// (recipient_pub, sealed envelope) per received push, in order. The
    /// sequence is inside the seal (ADR-0031) — assertions open it with
    /// `open_seq` and the recipient key they own.
    pushes: Arc<Mutex<Vec<([u8; 32], Envelope)>>>,
}

impl ScriptedPushRelay {
    fn spawn(
        pipe: MemPipe,
        relay_kp: &Keypair,
        nk_rx: mpsc::Receiver<MemPipe>,
        script: Vec<Verdict>,
        default: Verdict,
    ) -> Self {
        // The sequence is sealed (ADR-0031): the relay records the raw
        // envelope; assertions open it with the recipient key they own.
        let pushes: Arc<Mutex<Vec<([u8; 32], Envelope)>>> = Arc::new(Mutex::new(Vec::new()));
        let pushes_clone = pushes.clone();
        let verdicts: Arc<Mutex<VecDeque<Verdict>>> =
            Arc::new(Mutex::new(script.into_iter().collect()));
        let kp_xx = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let relay_priv = relay_kp.private();
        let relay_pub_key = relay_kp.public_key;
        std::thread::spawn(move || {
            // Hold the Receive Session open and drain it, like a real relay.
            let session = crate::version::testutil::xx_accept_after_prefix(pipe, kp_xx)
                .expect("relay accept");
            std::thread::spawn(move || while session.receive().is_ok() {});
            // NK push loop.
            while let Ok(nk_pipe) = nk_rx.recv() {
                let kp = Keypair::new(relay_priv, relay_pub_key);
                let pushes = pushes_clone.clone();
                let verdicts = verdicts.clone();
                std::thread::spawn(move || {
                    let sess = match crate::version::testutil::nk_accept_after_prefix(nk_pipe, kp) {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let raw = match sess.receive() {
                        Ok(r) => r,
                        Err(_) => return,
                    };
                    if let Some((MsgType::Push, body)) = parse(&raw) {
                        if body.len() >= 32 {
                            let recipient: [u8; 32] =
                                body[0..32].try_into().expect("32-byte recipient");
                            if let Ok(env) = Envelope::decode(&body[32..]) {
                                pushes.lock().unwrap().push((recipient, env));
                            }
                        }
                    }
                    let verdict = verdicts.lock().unwrap().pop_front().unwrap_or(default);
                    match verdict {
                        Verdict::Ack => {
                            let _ = sess.send(&frame(MsgType::Ack, &[]));
                        }
                        Verdict::Error(code) => {
                            let body = code.map(|c| vec![c]).unwrap_or_default();
                            let _ = sess.send(&frame(MsgType::Error, &body));
                        }
                        Verdict::Close => {
                            // Drop without a word.
                        }
                    }
                });
            }
        });
        ScriptedPushRelay { pushes }
    }

    fn pushes(&self) -> Vec<([u8; 32], Envelope)> {
        self.pushes.lock().unwrap().clone()
    }
}

/// Open a sealed push envelope as its recipient and return the sequence
/// (ADR-0031: the sequence is inside the seal — the relay stubs in this
/// file record raw envelopes and the TEST, which owns the recipient keys,
/// opens them).
fn open_seq(env: &Envelope, recipient: &DeviceKeypair) -> u64 {
    env.open_sealed(recipient.noise.private())
        .expect("sealed to the test recipient")
        .sequence
}

fn member_of(device: &DeviceKeypair) -> ManifestMember {
    ManifestMember {
        noise_pub: device.public_key(),
        signing_pub: device.signing_public_key(),
        name: member_name(&device.signing_public_key()),
    }
}

/// Backoff progression (ADR-0026): 1 s base, doubling per consecutive
/// failure, capped at 5 minutes — and saturating at extreme failure counts
/// (no overflow panic). Pure-function coverage for the delay the pump
/// applies between retries.
#[test]
fn backoff_progression_doubles_and_caps_at_five_minutes() {
    use crate::session::sender::{backoff_delay, SenderConfig};

    let config = SenderConfig::default();
    let delay = |failures| backoff_delay(&config, failures);
    assert_eq!(delay(1), Duration::from_secs(1), "base on first failure");
    assert_eq!(delay(2), Duration::from_secs(2));
    assert_eq!(delay(3), Duration::from_secs(4));
    assert_eq!(delay(4), Duration::from_secs(8));
    assert_eq!(delay(9), Duration::from_secs(256));
    assert_eq!(
        delay(10),
        Duration::from_secs(300),
        "512 s would exceed the cap: clamped at 5 min"
    );
    assert_eq!(delay(20), Duration::from_secs(300));
    assert_eq!(
        delay(u32::MAX),
        Duration::from_secs(300),
        "saturating arithmetic — no overflow panic at extreme counts"
    );

    // A custom base/cap are honoured (operators and tests can retune).
    let custom = SenderConfig {
        retry_base: Duration::from_millis(100),
        retry_cap: Duration::from_millis(450),
        ..SenderConfig::default()
    };
    let d = |failures| backoff_delay(&custom, failures);
    assert_eq!(d(1), Duration::from_millis(100));
    assert_eq!(d(2), Duration::from_millis(200));
    assert_eq!(d(3), Duration::from_millis(400));
    assert_eq!(d(4), Duration::from_millis(450), "custom cap clamps");
}

/// Reconnect clears per-recipient backoffs (ADR-0026: "retried while
/// connected ... and immediately on reconnect"). After a temporary failure
/// sets a backoff, swapping in a reconnected client makes the pump retry AT
/// ONCE — not after the backoff deadline.
///
/// The pump is driven directly with a slow 5 s base so the instant-retry
/// path is unambiguous: through `connect_background` the reconnect loop's
/// own ~1 s redial backoff lands at almost exactly the default 1 s retry
/// base, and the two paths cannot be told apart.
#[test]
fn reconnect_clears_backoff_and_retries_immediately() {
    use crate::operation_log::OperationLog;
    use crate::relay::RelayClient;
    use crate::session::sender::{spawn_sender, Kick, SenderConfig};
    use crate::session::{IssueSink, KeyState};

    let relay_kp = make_relay_kp();
    let relay_pub = relay_pub(&relay_kp);
    let (nk_rx, nk) = nk_push_channel();

    // NK relay: the FIRST push is dropped without an ack (temporary
    // failure), the rest acked. Records (envelope, receive time) per push —
    // the sequence is sealed (ADR-0031) and opened at assert time.
    let pushes: Arc<Mutex<Vec<(Envelope, Instant)>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let pushes = pushes.clone();
        let relay_priv = relay_kp.private();
        let relay_pub_key = relay_kp.public_key;
        let first = Arc::new(AtomicBool::new(true));
        std::thread::spawn(move || {
            while let Ok(nk_pipe) = nk_rx.recv() {
                let kp = Keypair::new(relay_priv, relay_pub_key);
                let pushes = pushes.clone();
                let first = first.clone();
                std::thread::spawn(move || {
                    let sess = match crate::version::testutil::nk_accept_after_prefix(nk_pipe, kp) {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let raw = match sess.receive() {
                        Ok(r) => r,
                        Err(_) => return,
                    };
                    if let Some((MsgType::Push, body)) = parse(&raw) {
                        if body.len() >= 32 {
                            if let Ok(env) = Envelope::decode(&body[32..]) {
                                pushes.lock().unwrap().push((env, Instant::now()));
                            }
                        }
                    }
                    if first.swap(false, Ordering::SeqCst) {
                        // Drop without a word: the ack never arrives.
                    } else {
                        let _ = sess.send(&frame(MsgType::Ack, &[]));
                    }
                });
            }
        });
    }

    // A relay that holds one XX Receive Session open and drains it.
    let hold_xx = |pipe: MemPipe| {
        let kp = Keypair::new(relay_kp.private(), relay_kp.public_key);
        std::thread::spawn(move || {
            if let Ok(sess) = crate::version::testutil::xx_accept_after_prefix(pipe, kp) {
                while sess.receive().is_ok() {}
            }
        });
    };

    let device = DeviceKeypair::generate();
    let recipient = DeviceKeypair::generate();
    let noise_kp = || Keypair::new(device.noise.private(), device.public_key().0);

    // Start the pump against a connected client.
    let (pipe1_client, pipe1_relay) = mem_pipe_pair();
    hold_xx(pipe1_relay);
    let client1 = RelayClient::connect(pipe1_client, relay_pub, noise_kp()).expect("connect 1");
    let client_slot: Arc<Mutex<RelayClient<MemPipe>>> = Arc::new(Mutex::new(client1));

    let keys = Arc::new(Mutex::new(KeyState::from_keypair(&device)));
    let op_log: Arc<Mutex<Box<dyn OperationLog>>> = Arc::new(Mutex::new(Box::new(MemLog::new())));
    let issue_sink = Arc::new(Mutex::new(IssueSink::new()));
    let kick = Arc::new(Kick::new());
    spawn_sender(
        client_slot.clone(),
        op_log.clone(),
        keys,
        relay_pub.0,
        Arc::new(nk.factory()),
        issue_sink,
        Arc::new(Mutex::new(None)),
        kick.clone(),
        SenderConfig {
            retry_base: Duration::from_secs(5),
            retry_cap: Duration::from_secs(10),
            poll: Duration::from_millis(20),
            ..SenderConfig::default()
        },
        Arc::new(Mutex::new(None)),
        Arc::new(AtomicBool::new(false)),
        Box::new(|| {}),
        Box::new(|| {}),
        Arc::new(AtomicBool::new(false)),
    );

    // Queue one entry and kick the pump: the first attempt fails (no ack)
    // and a 5 s backoff starts.
    op_log.lock().unwrap_or_else(|e| e.into_inner()).append(
        &recipient.public_key().0,
        0,
        b"retry on reconnect".to_vec(),
    );
    kick.kick();
    wait_for(
        || !pushes.lock().unwrap().is_empty(),
        Duration::from_secs(3),
    );
    let t1 = pushes.lock().unwrap()[0].1;

    // Simulate the disconnect first — the slot reports not-connected for a
    // few pump polls (this is what the dead client reports while the
    // reconnect loop is still dialling).
    *client_slot.lock().unwrap_or_else(|e| e.into_inner()) = RelayClient::disconnected();
    std::thread::sleep(Duration::from_millis(150));

    // Then the reconnect: swap in a fresh connected client — exactly what
    // the reconnect loop does.
    let (pipe2_client, pipe2_relay) = mem_pipe_pair();
    hold_xx(pipe2_relay);
    let client2 = RelayClient::connect(pipe2_client, relay_pub, noise_kp()).expect("connect 2");
    *client_slot.lock().unwrap_or_else(|e| e.into_inner()) = client2;

    // The pump notices the transition within one poll and retries AT ONCE —
    // long before the 5 s backoff deadline.
    wait_for(|| pushes.lock().unwrap().len() == 2, Duration::from_secs(3));
    let pushes = pushes.lock().unwrap();
    let gap = pushes[1].1 - t1;
    assert!(
        gap < Duration::from_secs(2),
        "the retry after reconnect must not wait out the 5 s backoff — gap was {gap:?}"
    );
    assert_eq!(
        open_seq(&pushes[0].0, &recipient),
        open_seq(&pushes[1].0, &recipient),
        "the same entry is retried (same sequence)"
    );
}

/// A permanent refusal raises `sendFailed` and is never retried (issue
/// completion criterion): the entry is deleted, so nothing is left to retry.
/// This stub sends the LEGACY reasonless Error body — the pre-RELAY-5 relay
/// layout — so it also pins the backward-compatible mapping (ADR-0026: an
/// untyped refusal reports `sendFailed(malformed)`).
#[test]
fn permanent_refusal_raises_send_failed_and_is_never_retried() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    // Every push is refused with the legacy reasonless Error body.
    let relay =
        ScriptedPushRelay::spawn(pipe_relay, &relay_kp, nk_rx, vec![], Verdict::Error(None));

    let device = DeviceKeypair::generate();
    let recipient = DeviceKeypair::generate();
    let d_noise = device.public_key();
    let d_signing = device.signing_public_key();
    let d_signing_pub = d_signing.0;
    let d_sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let session = TruesealSession::connect(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        nk.factory(),
    )
    .expect("connect");
    session.set_manifest(make_two_member_manifest(
        d_noise,
        d_signing,
        &d_sk,
        recipient.public_key(),
        recipient.signing_public_key(),
    ));
    let issues: Arc<Mutex<Vec<DeliveryIssue>>> = Arc::new(Mutex::new(vec![]));
    let issues_cb = issues.clone();
    session.subscribe_delivery_issues(move |i| issues_cb.lock().unwrap().push(i));

    // First send on a fresh log consumes sequence 0.
    session.push_sync(b"refused".to_vec()).expect("queued");

    let expected_mid = message_id(&d_signing_pub, 0);
    wait_for(
        || {
            issues.lock().unwrap().iter().any(|i| {
                matches!(
                    i,
                    DeliveryIssue::SendFailed {
                        message_id,
                        reason: SendFailedReason::Malformed,
                    } if *message_id == expected_mid
                )
            })
        },
        Duration::from_secs(3),
    );
    // Past several backoff cycles: the push happened exactly once — the
    // entry was deleted, so there is nothing to retry.
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        relay.pushes().len(),
        1,
        "a permanently refused entry is never retried"
    );
    assert!(
        session
            .op_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .undelivered_entries()
            .unwrap()
            .is_empty(),
        "the failed entry is deleted"
    );
}

/// A temporary failure (relay persisted but the ack never arrived) is
/// retried WHILE CONNECTED — no reconnect needed — and the retry re-sends
/// the same entry (the sender half of the crash point; the recipient
/// dedups the duplicate).
#[test]
fn temporary_failure_retries_while_connected() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    // First push: dropped without ack. Then default: Ack.
    let relay = ScriptedPushRelay::spawn(
        pipe_relay,
        &relay_kp,
        nk_rx,
        vec![Verdict::Close],
        Verdict::Ack,
    );

    let device = DeviceKeypair::generate();
    let recipient = DeviceKeypair::generate();
    let d_noise = device.public_key();
    let d_signing = device.signing_public_key();
    let d_sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let session = TruesealSession::connect(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        nk.factory(),
    )
    .expect("connect");
    session.set_manifest(make_two_member_manifest(
        d_noise,
        d_signing,
        &d_sk,
        recipient.public_key(),
        recipient.signing_public_key(),
    ));

    session.push_sync(b"retry me".to_vec()).expect("queued");

    // The first retry lands after one backoff interval (~1 s).
    wait_for(
        || {
            session
                .op_log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .undelivered_entries()
                .unwrap()
                .is_empty()
        },
        Duration::from_secs(5),
    );
    let pushes = relay.pushes();
    assert_eq!(
        pushes.len(),
        2,
        "the same entry was pushed twice: lost ack, then retry"
    );
    assert_eq!(
        open_seq(&pushes[0].1, &recipient),
        open_seq(&pushes[1].1, &recipient),
        "both pushes carry the same sequence — one message, two attempts"
    );
}

/// A TYPED temporary refusal (relay Error with reason 0x84 internal — bit
/// 7 set, relay ADR-0008 amended by RELAY-5) is NOT a message-loss event:
/// the pump backs off and retries while connected, the entry survives, and
/// no `sendFailed` fires (ADR-0026 retry classes; B20b — the pre-typed
/// mapping dropped the entry permanently).
#[test]
fn temporary_refusal_backs_off_and_retries() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    // First push: typed temporary refusal (0x84 internal). Then default: Ack.
    let relay = ScriptedPushRelay::spawn(
        pipe_relay,
        &relay_kp,
        nk_rx,
        vec![Verdict::Error(Some(0x84))],
        Verdict::Ack,
    );

    let device = DeviceKeypair::generate();
    let recipient = DeviceKeypair::generate();
    let d_noise = device.public_key();
    let d_signing = device.signing_public_key();
    let d_sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let session = TruesealSession::connect(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        nk.factory(),
    )
    .expect("connect");
    session.set_manifest(make_two_member_manifest(
        d_noise,
        d_signing,
        &d_sk,
        recipient.public_key(),
        recipient.signing_public_key(),
    ));
    let issues: Arc<Mutex<Vec<DeliveryIssue>>> = Arc::new(Mutex::new(vec![]));
    let issues_cb = issues.clone();
    session.subscribe_delivery_issues(move |i| issues_cb.lock().unwrap().push(i));

    session.push_sync(b"retry me".to_vec()).expect("queued");

    // The retry lands after one backoff interval and the entry is delivered.
    wait_for(
        || {
            session
                .op_log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .undelivered_entries()
                .unwrap()
                .is_empty()
        },
        Duration::from_secs(5),
    );
    let pushes = relay.pushes();
    assert_eq!(
        pushes.len(),
        2,
        "the entry was retried after the temporary refusal, then delivered"
    );
    assert_eq!(
        open_seq(&pushes[0].1, &recipient),
        open_seq(&pushes[1].1, &recipient),
        "both pushes carry the same sequence — one message, two attempts"
    );
    assert!(
        !issues
            .lock()
            .unwrap()
            .iter()
            .any(|i| matches!(i, DeliveryIssue::SendFailed { .. })),
        "a temporary refusal never raises sendFailed"
    );
}

/// A TYPED permanent refusal for size (relay Error with reason 0x01
/// tooLarge, relay ADR-0008 amended by RELAY-5) reports
/// `sendFailed(tooLarge)` — the same reason the client-side size check
/// reports — not the generic `malformed` (ADR-0026: a size refusal is
/// permanent and typed, ADR-0025).
#[test]
fn permanent_too_large_refusal_reports_too_large() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    // Every push is refused with the typed tooLarge reason.
    let relay = ScriptedPushRelay::spawn(
        pipe_relay,
        &relay_kp,
        nk_rx,
        vec![],
        Verdict::Error(Some(0x01)),
    );

    let device = DeviceKeypair::generate();
    let recipient = DeviceKeypair::generate();
    let d_noise = device.public_key();
    let d_signing = device.signing_public_key();
    let d_signing_pub = d_signing.0;
    let d_sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let session = TruesealSession::connect(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        nk.factory(),
    )
    .expect("connect");
    session.set_manifest(make_two_member_manifest(
        d_noise,
        d_signing,
        &d_sk,
        recipient.public_key(),
        recipient.signing_public_key(),
    ));
    let issues: Arc<Mutex<Vec<DeliveryIssue>>> = Arc::new(Mutex::new(vec![]));
    let issues_cb = issues.clone();
    session.subscribe_delivery_issues(move |i| issues_cb.lock().unwrap().push(i));

    // First send on a fresh log consumes sequence 0.
    session.push_sync(b"refused".to_vec()).expect("queued");

    let expected_mid = message_id(&d_signing_pub, 0);
    wait_for(
        || {
            issues.lock().unwrap().iter().any(|i| {
                matches!(
                    i,
                    DeliveryIssue::SendFailed {
                        message_id,
                        reason: SendFailedReason::TooLarge,
                    } if *message_id == expected_mid
                )
            })
        },
        Duration::from_secs(3),
    );
    // Past several backoff cycles: pushed exactly once — the entry is gone.
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        relay.pushes().len(),
        1,
        "a permanently refused entry is never retried"
    );
}

/// Head-of-line per recipient (ADR-0026): a later entry never overtakes an
/// earlier one still being retried, and one recipient's failing line never
/// blocks another recipient's.
#[test]
fn head_of_line_per_recipient_with_isolation() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();

    let device = DeviceKeypair::generate();
    let b = DeviceKeypair::generate();
    let c = DeviceKeypair::generate();
    let b_noise = b.public_key().0;
    let c_noise = c.public_key().0;

    // Custom relay: B's pushes are dropped (temporary failure) UNTIL C's
    // line has fully drained; everything else acks. Records (recipient,
    // sequence) per ACKED push, in order. The sequence is sealed
    // (ADR-0031), so the relay opens each envelope with the recipient key
    // the test hands it (a colluding-relay vantage is NOT needed — the
    // test owns every key).
    //
    // B12b flake fix: the drop used to cover only B's FIRST push, so the
    // isolation assertion implicitly assumed C's second push beats B's ~1 s
    // retry backoff — under full-suite CI load a single NK handshake can
    // exceed that window and the order flipped. Gating B on C's drain makes
    // the tested property (B's failing line never holds C's up)
    // deterministic at any machine speed. No assertion weakened.
    let b_priv = b.noise.private();
    let c_priv = c.noise.private();
    let acked: Arc<Mutex<Vec<([u8; 32], u64)>>> = Arc::new(Mutex::new(vec![]));
    {
        let acked = acked.clone();
        let kp_xx = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let relay_priv = relay_kp.private();
        let relay_pub_key = relay_kp.public_key;
        let c_drained = Arc::new(AtomicBool::new(false));
        std::thread::spawn(move || {
            let session = crate::version::testutil::xx_accept_after_prefix(pipe_relay, kp_xx)
                .expect("relay accept");
            std::thread::spawn(move || while session.receive().is_ok() {});
            while let Ok(nk_pipe) = nk_rx.recv() {
                let kp = Keypair::new(relay_priv, relay_pub_key);
                let acked = acked.clone();
                let c_drained = c_drained.clone();
                std::thread::spawn(move || {
                    let sess = match crate::version::testutil::nk_accept_after_prefix(nk_pipe, kp) {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let raw = match sess.receive() {
                        Ok(r) => r,
                        Err(_) => return,
                    };
                    let Some((MsgType::Push, body)) = parse(&raw) else {
                        return;
                    };
                    if body.len() < 32 {
                        return;
                    }
                    let recipient: [u8; 32] = body[0..32].try_into().expect("32-byte recipient");
                    let priv_key = if recipient == b_noise {
                        b_priv
                    } else if recipient == c_noise {
                        c_priv
                    } else {
                        return;
                    };
                    let seq = Envelope::decode(&body[32..])
                        .ok()
                        .and_then(|e| e.open_sealed(priv_key).ok())
                        .map(|sc| sc.sequence)
                        .unwrap_or(u64::MAX);
                    // B's pushes are lost (no ack) until C has fully
                    // drained — a temporary failure on B's line only.
                    if recipient == b_noise && !c_drained.load(Ordering::SeqCst) {
                        return; // drop session without ack
                    }
                    acked.lock().unwrap().push((recipient, seq));
                    if recipient == c_noise && seq == 1 {
                        c_drained.store(true, Ordering::SeqCst);
                    }
                    let _ = sess.send(&frame(MsgType::Ack, &[]));
                });
            }
        });
    }

    let d_sk = SigningKey::from_bytes(&device.signing.to_bytes());
    let self_member = member_of(&device);
    let session = TruesealSession::connect(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        nk.factory(),
    )
    .expect("connect");
    let mut members = vec![self_member, member_of(&b), member_of(&c)];
    members.sort_by_key(|m| m.noise_pub.0);
    session.set_manifest(GroupManifest::new(
        crate::manifest::new_group_id(),
        1,
        members,
        &d_sk,
    ));

    session.push_sync(b"one".to_vec()).expect("queued");
    session.push_sync(b"two".to_vec()).expect("queued");

    // Everything drains: B after its retry (~1 s backoff), C immediately.
    // CI-scaled budget (the suite runs ~5x slower under CI load; the wait
    // reacts to the drain, so a generous budget costs nothing when fast).
    wait_for(
        || {
            session
                .op_log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .undelivered_entries()
                .unwrap()
                .is_empty()
        },
        Duration::from_secs(20),
    );

    let acked = acked.lock().unwrap();
    let b_seqs: Vec<u64> = acked
        .iter()
        .filter(|(r, _)| *r == b_noise)
        .map(|(_, s)| *s)
        .collect();
    let c_seqs: Vec<u64> = acked
        .iter()
        .filter(|(r, _)| *r == c_noise)
        .map(|(_, s)| *s)
        .collect();
    assert_eq!(b_seqs, vec![0, 1], "B's entries arrive in sequence order");
    assert_eq!(c_seqs, vec![0, 1], "C's entries arrive in sequence order");
    // Isolation: C's SECOND entry was acked before B's FIRST retry — B's
    // failing line never held C's up.
    let c1_pos = acked
        .iter()
        .position(|&(r, s)| r == c_noise && s == 1)
        .expect("C seq 1 acked");
    let b0_pos = acked
        .iter()
        .position(|&(r, s)| r == b_noise && s == 0)
        .expect("B seq 0 acked");
    assert!(
        c1_pos < b0_pos,
        "C's line drains while B's is still backing off: {acked:?}"
    );
}

/// A `Sync` entry still undelivered 30 days after send() is failed
/// permanently (`sendFailed(expired)`) and never pushed (ADR-0026).
#[test]
fn sync_entry_expires_after_30_days() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    let relay = ScriptedPushRelay::spawn(pipe_relay, &relay_kp, nk_rx, vec![], Verdict::Ack);

    let device = DeviceKeypair::generate();
    let d_signing_pub = device.signing_public_key().0;
    let recipient = DeviceKeypair::generate();
    let session = TruesealSession::connect(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        nk.factory(),
    )
    .expect("connect");
    let issues: Arc<Mutex<Vec<DeliveryIssue>>> = Arc::new(Mutex::new(vec![]));
    let issues_cb = issues.clone();
    session.subscribe_delivery_issues(move |i| issues_cb.lock().unwrap().push(i));

    // Inject a Sync entry queued 31 days ago (as an outbox replayed after a
    // long offline stretch would be).
    let thirty_one_days = 31 * 24 * 60 * 60;
    session
        .op_log
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .append_entry(LogEntry {
            object_id: recipient.public_key().0,
            sequence: 0,
            kind: OutboxKind::Sync,
            created_at: now_secs() - thirty_one_days,
            blob: b"too old".to_vec(),
        });

    let expected_mid = message_id(&d_signing_pub, 0);
    wait_for(
        || {
            issues.lock().unwrap().iter().any(|i| {
                matches!(
                    i,
                    DeliveryIssue::SendFailed {
                        message_id,
                        reason: SendFailedReason::Expired,
                    } if *message_id == expected_mid
                )
            })
        },
        Duration::from_secs(3),
    );
    assert!(
        relay.pushes().is_empty(),
        "an expired entry is never pushed"
    );
    assert!(
        session
            .op_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .undelivered_entries()
            .unwrap()
            .is_empty(),
        "the expired entry is deleted"
    );
}

/// Control-plane entries NEVER expire (ADR-0026, ADR-0034 §2): a Leave or
/// Destroy Group queued offline for months must still reach every peer.
#[test]
fn control_entry_never_expires() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    let relay = ScriptedPushRelay::spawn(pipe_relay, &relay_kp, nk_rx, vec![], Verdict::Ack);

    let device = DeviceKeypair::generate();
    let recipient = DeviceKeypair::generate();
    let session = TruesealSession::connect(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        nk.factory(),
    )
    .expect("connect");
    let issues: Arc<Mutex<Vec<DeliveryIssue>>> = Arc::new(Mutex::new(vec![]));
    let issues_cb = issues.clone();
    session.subscribe_delivery_issues(move |i| issues_cb.lock().unwrap().push(i));

    let thirty_one_days = 31 * 24 * 60 * 60;
    let pair = Message::Pair {
        noise_pub: [1u8; 32],
        signing_pub: [2u8; 32],
        secret: [3u8; 32],
    };
    session
        .op_log
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .append_entry(LogEntry {
            object_id: recipient.public_key().0,
            sequence: 0,
            kind: OutboxKind::Control,
            created_at: now_secs() - thirty_one_days,
            blob: pair.encode(),
        });

    wait_for(
        || {
            session
                .op_log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .undelivered_entries()
                .unwrap()
                .is_empty()
        },
        Duration::from_secs(3),
    );
    assert_eq!(
        relay.pushes().len(),
        1,
        "the 31-day-old control entry is still delivered"
    );
    assert!(
        issues.lock().unwrap().is_empty(),
        "no sendFailed for control entries"
    );
}

/// The Sender Timestamp rule (ADR-0034 §2), pinned at the seal: a `Sync`
/// entry keeps the time it was queued (`send()`), through every re-seal —
/// every copy leaves the Replay Window at the same moment. A control entry
/// is stamped at EACH seal, so a long-queued Leave or Revoke is fresh when
/// it lands and peers do not reject it as expired.
#[test]
fn sync_keeps_send_time_stamp_control_is_stamped_at_each_seal() {
    let relay_kp = make_relay_kp();
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    let relay = ScriptedPushRelay::spawn(pipe_relay, &relay_kp, nk_rx, vec![], Verdict::Ack);

    let device = DeviceKeypair::generate();
    let recipient = DeviceKeypair::generate();
    let session = TruesealSession::connect(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        nk.factory(),
    )
    .expect("connect");

    let ten_days = 10 * 24 * 60 * 60;
    let ninety_days = 90 * 24 * 60 * 60;
    let sync_queued_at = now_secs() - ten_days;
    {
        let mut log = session.op_log.lock().unwrap_or_else(|e| e.into_inner());
        log.append_entry(LogEntry {
            object_id: recipient.public_key().0,
            sequence: 0,
            kind: OutboxKind::Sync,
            created_at: sync_queued_at,
            blob: b"stamped at send".to_vec(),
        });
        log.append_entry(LogEntry {
            object_id: recipient.public_key().0,
            sequence: 1,
            kind: OutboxKind::Control,
            created_at: now_secs() - ninety_days,
            blob: Message::Revoke.encode(),
        });
    }
    let before = now_secs();
    wait_for(|| relay.pushes().len() == 2, Duration::from_secs(3));
    let after = now_secs();

    let sync_ts = relay.pushes()[0]
        .1
        .open_sealed(recipient.noise.private())
        .expect("sealed to the recipient")
        .sender_timestamp_ms;
    assert_eq!(
        sync_ts,
        sync_queued_at * 1000,
        "a Sync entry keeps its send() stamp through the seal"
    );

    let control_ts = relay.pushes()[1]
        .1
        .open_sealed(recipient.noise.private())
        .expect("sealed to the recipient")
        .sender_timestamp_ms;
    assert!(
        before.saturating_sub(60) * 1000 <= control_ts && control_ts <= (after + 60) * 1000,
        "a control entry is stamped at each seal (≈ now), not at queue time: {control_ts}"
    );
}

/// Delivered rows are DELETED (ADR-0026), and the sequence high-water mark
/// keeps numbers unique across a restart anyway: a re-used sequence would
/// collide in the recipient's dedup table.
#[test]
fn delivered_rows_are_deleted_and_sequence_survives_restart() {
    let dir = tempfile::TempDir::new().expect("tmp dir");
    let relay_kp = make_relay_kp();

    let device = DeviceKeypair::generate();
    let recipient = DeviceKeypair::generate();
    let r_noise = recipient.public_key();
    let r_signing = recipient.signing_public_key();
    let d_noise = device.public_key();
    let d_signing = device.signing_public_key();
    let d_sk = SigningKey::from_bytes(&device.signing.to_bytes());

    // First "process": send one message; it is delivered and its row deleted.
    let first_max_seq;
    {
        let (pipe_client, pipe_relay) = mem_pipe_pair();
        let (nk_rx, nk) = nk_push_channel();
        let relay = ScriptedPushRelay::spawn(pipe_relay, &relay_kp, nk_rx, vec![], Verdict::Ack);
        let store = Store::open(dir.path(), "ns").expect("store");
        let device1 = DeviceKeypair::from_bytes(device.noise.private(), device.signing.to_bytes())
            .expect("keypair bytes");
        let session = TruesealSession::connect_with_log(
            pipe_client,
            relay_pub(&relay_kp),
            device1,
            |_, _, _| {},
            Box::new(PersistentLog::new(store)),
            nk.factory(),
        )
        .expect("connect");
        session.set_manifest(make_two_member_manifest(
            d_noise, d_signing, &d_sk, r_noise, r_signing,
        ));
        session.push_sync(b"first".to_vec()).expect("queued");
        wait_for(
            || {
                session
                    .op_log
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .undelivered_entries()
                    .unwrap()
                    .is_empty()
            },
            Duration::from_secs(3),
        );
        // The delivered row is GONE — not marked, deleted.
        assert!(
            session
                .op_log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entries_from(&r_noise.0, 0)
                .unwrap()
                .is_empty(),
            "delivered rows are deleted, not kept"
        );
        assert_eq!(relay.pushes().len(), 1);
        first_max_seq = open_seq(&relay.pushes()[0].1, &recipient);
        // End the first "process". (ADR-0029 note: destroy_group is no
        // longer usable as teardown here — a completed Destroy wipes the
        // store, sequence state included, by design.)
        drop(session);
    }

    // Second "process" over the same store: the next send must NOT re-use
    // an earlier sequence number even though every delivered row is gone.
    let (pipe_client, pipe_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    let relay2 = ScriptedPushRelay::spawn(pipe_relay, &relay_kp, nk_rx, vec![], Verdict::Ack);
    let store = Store::open(dir.path(), "ns").expect("store");
    let session2 = TruesealSession::connect_with_log(
        pipe_client,
        relay_pub(&relay_kp),
        device,
        |_, _, _| {},
        Box::new(PersistentLog::new(store)),
        nk.factory(),
    )
    .expect("connect");
    session2.set_manifest(make_two_member_manifest(
        d_noise, d_signing, &d_sk, r_noise, r_signing,
    ));
    session2.push_sync(b"second".to_vec()).expect("queued");
    wait_for(|| !relay2.pushes().is_empty(), Duration::from_secs(3));
    let second_seq = open_seq(&relay2.pushes()[0].1, &recipient);
    assert!(
        second_seq > first_max_seq,
        "sequence must never be re-used after restart: first process used {first_max_seq}, second sent {second_seq}"
    );
    drop(session2);
}

/// The full crash point, end to end (ADR-0026): the relay persisted the
/// Blob but the ack was lost, so the sender retries; the recipient receives
/// the duplicate, recognises the Message ID, runs the handler ONCE and acks
/// both copies.
#[test]
fn lost_ack_replays_and_recipient_dedups_end_to_end() {
    let relay_kp = make_relay_kp();
    let relay_pub_key = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();

    // Relay: hold A's and B's Receive Sessions; first NK push routes the
    // Deliver to B but closes WITHOUT the push ack; later pushes route + ack.
    let b_deliver_acks: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    {
        let kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let relay_priv = relay_kp.private();
        let relay_pubk = relay_kp.public_key;
        let b_deliver_acks = b_deliver_acks.clone();
        std::thread::spawn(move || {
            let sess_a = crate::version::testutil::xx_accept_after_prefix(pipe_a_relay, kp_a)
                .expect("accept A");
            let sess_b = crate::version::testutil::xx_accept_after_prefix(pipe_b_relay, kp_b)
                .expect("accept B");
            let sess_b = Arc::new(sess_b);
            // Hold A open; count B's DeliverAcks.
            std::thread::spawn(move || while sess_a.receive().is_ok() {});
            let sess_b_read = sess_b.clone();
            std::thread::spawn(move || {
                while let Ok(raw) = sess_b_read.receive() {
                    if let Some((MsgType::DeliverAck, _)) = parse(&raw) {
                        b_deliver_acks.fetch_add(1, Ordering::SeqCst);
                    }
                }
            });
            let first = AtomicBool::new(false);
            let first = Arc::new(first);
            while let Ok(nk_pipe) = nk_rx.recv() {
                let kp = Keypair::new(relay_priv, relay_pubk);
                let sess_b = sess_b.clone();
                let first = first.clone();
                std::thread::spawn(move || {
                    let sess = match crate::version::testutil::nk_accept_after_prefix(nk_pipe, kp) {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let Ok(raw) = sess.receive() else { return };
                    let Some((MsgType::Push, body)) = parse(&raw) else {
                        return;
                    };
                    if body.len() < 32 {
                        return;
                    }
                    // Persist: deliver to the recipient's inbox (B is online).
                    let mut deliver = 7u64.to_be_bytes().to_vec();
                    deliver.extend_from_slice(&body[32..]);
                    let _ = sess_b.send(&frame(MsgType::Deliver, &deliver));
                    if !first.swap(true, Ordering::SeqCst) {
                        return; // crash: persisted and delivered, ack never sent
                    }
                    let _ = sess.send(&frame(MsgType::Ack, &[]));
                });
            }
        });
    }

    // The relay accepts A's session first, so connect A before B.
    let a_noise = device_a.public_key();
    let a_signing = device_a.signing_public_key();
    let a_sk = SigningKey::from_bytes(&device_a.signing.to_bytes());
    let session_a = TruesealSession::connect(
        pipe_a_client,
        relay_pub_key,
        device_a,
        |_, _, _| {},
        nk.factory(),
    )
    .expect("A connects");
    session_a.set_manifest(make_two_member_manifest(
        a_noise, a_signing, &a_sk, b_noise, b_signing,
    ));

    let b_received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(vec![]));
    let br = b_received.clone();
    let session_b = TruesealSession::connect(
        pipe_b_client,
        relay_pub_key,
        device_b,
        move |msg, _a, _s| {
            if let Message::Sync { body } = msg {
                br.lock().unwrap().push(body);
            }
        },
        nk.factory(),
    )
    .expect("B connects");
    // ADR-0023: B must hold the manifest or it drops the Sync.
    session_b.set_manifest(make_two_member_manifest(
        a_noise, a_signing, &a_sk, b_noise, b_signing,
    ));

    session_a
        .push_sync(b"exactly once".to_vec())
        .expect("queued");

    // A's first push is dropped after persist; the retry lands ~1 s later.
    wait_for(
        || {
            session_a
                .op_log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .undelivered_entries()
                .unwrap()
                .is_empty()
        },
        Duration::from_secs(6),
    );
    wait_for(
        || b_deliver_acks.load(Ordering::SeqCst) == 2,
        Duration::from_secs(3),
    );
    let received = b_received.lock().unwrap();
    assert_eq!(
        received.len(),
        1,
        "the handler ran exactly once across the duplicate delivery"
    );
    assert_eq!(received[0], b"exactly once");
}

/// Control plane through the outbox (ADR-0026): `accept_pair` persists the
/// manifest and QUEUES it before returning true (ADR-0023); the pump
/// delivers it once the relay is reachable — even though the session was
/// offline when the admission happened.
#[test]
fn accept_pair_offline_queues_manifest_and_delivers_on_reconnect() {
    let relay_kp = make_relay_kp();
    let relay_pub_key = relay_pub(&relay_kp);
    let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
    let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();
    let (nk_rx, nk) = nk_push_channel();
    spawn_bidirectional_relay_parallel(&relay_kp, pipe_a_relay, pipe_b_relay, nk_rx);

    let device_a = DeviceKeypair::generate();
    let device_b = DeviceKeypair::generate();
    let b_noise = device_b.public_key();
    let b_signing = device_b.signing_public_key();

    // B is online from the start.
    let _session_b = TruesealSession::connect(
        pipe_b_client,
        relay_pub_key,
        device_b,
        |_, _, _| {},
        nk.factory(),
    )
    .expect("B connects");

    // A starts OFFLINE: the transport gate is closed.
    let gate = Arc::new(AtomicBool::new(false));
    let pipe_slot: Arc<Mutex<Option<MemPipe>>> = Arc::new(Mutex::new(Some(pipe_a_client)));
    let gate_factory = {
        let gate = gate.clone();
        let pipe_slot = pipe_slot.clone();
        move || {
            if !gate.load(Ordering::Acquire) {
                return Err("offline".to_string());
            }
            pipe_slot
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| "exhausted".to_string())
        }
    };

    let session_a = TruesealSession::<MemPipe>::connect_background(
        relay_pub_key,
        device_a,
        |_, _, _| {},
        Box::new(MemLog::new()),
        Arc::new(Mutex::new(None)),
        || {},
        |_| {},
        || {},
        gate_factory,
        nk.factory(),
        Some(Duration::from_millis(50)),
        None,
    )
    .expect("A session");

    // Offline admission: window opens, accept_pair persists + queues.
    let _token = session_a.pairing_token().expect("pairing window opens");
    assert!(session_a.accept_pair(b_noise, b_signing).expect("accept"));
    {
        let entries = session_a
            .op_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .undelivered_entries()
            .unwrap();
        assert_eq!(entries.len(), 1, "the manifest is queued before connect");
        assert_eq!(entries[0].kind, OutboxKind::Control);
        assert_eq!(entries[0].object_id, b_noise.0);
    }

    // The relay becomes reachable: the pump drains and B learns the group.
    gate.store(true, Ordering::Release);
    wait_for(
        || {
            session_a
                .op_log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .undelivered_entries()
                .unwrap()
                .is_empty()
        },
        Duration::from_secs(6),
    );
}
