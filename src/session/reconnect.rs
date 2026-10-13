use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use trueseal_noise::keypair::Keypair as NoiseKeypair;

use crate::keys::NoisePublicKey;
use crate::manifest::GroupManifest;
use crate::message::Message;
use crate::operation_log::OperationLog;
use crate::relay::RelayClient;

use super::{
    EventSink, IssueSink, KeyState, LeavingRecord, PendingChange, PendingJoin, PendingMember,
};

/// Polls for relay disconnect, backs off, reconnects, and replays the outbox.
/// Runs in a background thread spawned by `connect_with_reconnect`.
#[allow(clippy::too_many_arguments)]
pub(super) fn reconnect_loop<T: Read + Write + Send + 'static>(
    client: Arc<Mutex<RelayClient<T>>>,
    op_log: Arc<Mutex<Box<dyn OperationLog>>>,
    relay_pub: NoisePublicKey,
    keys: Arc<Mutex<KeyState>>,
    manifest: Arc<Mutex<Option<GroupManifest>>>,
    on_message: impl Fn(Message, [u8; 32], u64) + Send + 'static + Clone,
    on_removed_from_group: Arc<dyn Fn() + Send + Sync + 'static>,
    on_manifest_changed: Arc<dyn Fn(&GroupManifest) + Send + Sync + 'static>,
    on_group_destroyed: Arc<dyn Fn() + Send + Sync + 'static>,
    destroyed: Arc<AtomicBool>,
    pairing: Arc<Mutex<Option<super::PairingWindow>>>,
    pending_members: Arc<Mutex<HashMap<String, PendingMember>>>,
    on_member_request: Arc<Mutex<EventSink>>,
    on_member_joined: Arc<Mutex<EventSink>>,
    on_member_left: Arc<Mutex<EventSink>>,
    issue_sink: Arc<Mutex<IssueSink>>,
    pending_join: Arc<Mutex<Option<PendingJoin>>>,
    sequence: Arc<Mutex<u64>>,
    pending_changes: Arc<Mutex<Vec<PendingChange>>>,
    leaving: Arc<Mutex<Option<LeavingRecord>>>,
    on_identity_rotated: Arc<dyn Fn(crate::device::DeviceKeypair) + Send + Sync + 'static>,
    rotation_pending: Arc<AtomicBool>,
    factory: Arc<dyn Fn() -> Result<T, String> + Send + Sync>,
    cap: Duration,
    on_connection_changed: Arc<dyn Fn(bool) + Send + Sync + 'static>,
) {
    let mut backoff = cap.min(Duration::from_secs(1));
    let mut was_connected = false; // track last-known state to detect transitions
    loop {
        std::thread::sleep(Duration::from_millis(50));
        // Exit the reconnect loop if the group has been destroyed.
        if destroyed.load(Ordering::Acquire) {
            break;
        }
        let connected = client
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_connected();
        if connected {
            backoff = Duration::from_secs(1);
            if !was_connected {
                was_connected = true;
                (on_connection_changed)(true);
            }
            continue;
        }

        // Transition: was connected, now disconnected.
        if was_connected {
            was_connected = false;
            (on_connection_changed)(false);
        }

        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(cap);

        let transport = match (factory)() {
            Ok(t) => t,
            Err(_) => continue,
        };

        let (noise_priv, noise_pub_key) = {
            let ks = keys.lock().unwrap_or_else(|e| e.into_inner());
            (ks.noise_priv, ks.noise_pub_key)
        };

        let noise_kp = NoiseKeypair::new(noise_priv, noise_pub_key);
        // SYNC-6 (#98): build the full manifest-aware handler first and
        // register it inside connect, before the receive loop starts
        // reading — a Blob queued while this device was down arrives the
        // moment the new session comes up.
        let handler = super::build_subscribe_handler(
            keys.clone(),
            manifest.clone(),
            pending_join.clone(),
            on_removed_from_group.clone(),
            on_manifest_changed.clone(),
            on_group_destroyed.clone(),
            destroyed.clone(),
            pairing.clone(),
            pending_members.clone(),
            on_member_request.clone(),
            on_member_joined.clone(),
            on_member_left.clone(),
            issue_sink.clone(),
            op_log.clone(),
            sequence.clone(),
            pending_changes.clone(),
            leaving.clone(),
            on_identity_rotated.clone(),
            rotation_pending.clone(),
            on_message.clone(),
        );
        // SYNC-5: receive-path Delivery Issues forward into the session sink
        // from the first frame of the new session.
        let issue_forwarder = {
            let sink = issue_sink.clone();
            move |issue: crate::delivery_issue::DeliveryIssue| {
                sink.lock().unwrap_or_else(|e| e.into_inner()).fire(issue);
            }
        };
        let new_client = match RelayClient::connect_subscribed(
            transport,
            relay_pub,
            noise_kp,
            handler,
            Some(Box::new(issue_forwarder)),
        ) {
            Ok(c) => c,
            Err(crate::relay::RelayError::RelayVersionUnsupported { min, max }) => {
                // The relay refuses our Transport Version (ADR-0022). Keep
                // retrying — the relay may be upgraded — and leave every
                // outbox entry queued.
                log::warn!(
                    "relay supports Transport Version {min}..={max}, \
                     this build speaks {}; outbox stays queued",
                    crate::version::TRANSPORT_VERSION
                );
                continue;
            }
            Err(_) => continue,
        };

        *client.lock().unwrap_or_else(|e| e.into_inner()) = new_client;
        backoff = Duration::from_secs(1);

        // SYNC-5: no outbox replay here. The sender pump owns the whole
        // outbox state machine (ADR-0026) — it notices the reconnection,
        // clears its per-recipient backoffs and retries immediately.
    }
}
