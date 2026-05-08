use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use hush_noise::keypair::Keypair as NoiseKeypair;

use crate::envelope::SigningKeypair;
use crate::keys::NoisePublicKey;
use crate::manifest::GroupManifest;
use crate::message::Message;
use crate::operation_log::OperationLog;
use crate::relay::RelayClient;

use super::{KeyState, PendingMember};

/// Polls for relay disconnect, backs off, reconnects, and replays the outbox.
/// Runs in a background thread spawned by `connect_with_reconnect`.
pub(super) fn reconnect_loop<T: Read + Write + Send + 'static>(
    client: Arc<Mutex<RelayClient<T>>>,
    op_log: Arc<Mutex<Box<dyn OperationLog>>>,
    relay_pub: NoisePublicKey,
    keys: Arc<Mutex<KeyState>>,
    manifest: Arc<Mutex<Option<GroupManifest>>>,
    on_message: impl Fn(Message, [u8; 32]) + Send + 'static + Clone,
    on_removed_from_group: Arc<dyn Fn() + Send + Sync + 'static>,
    on_manifest_changed: Arc<dyn Fn(&GroupManifest) + Send + Sync + 'static>,
    on_group_destroyed: Arc<dyn Fn() + Send + Sync + 'static>,
    destroyed: Arc<AtomicBool>,
    pairing: Arc<Mutex<Option<super::PairingWindow>>>,
    pending_members: Arc<Mutex<HashMap<String, PendingMember>>>,
    on_member_request: Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + Sync>>>>,
    on_member_joined: Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + Sync>>>>,
    on_member_left: Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + Sync>>>>,
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
        let connected = client.lock().unwrap_or_else(|e| e.into_inner()).is_connected();
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

        let (noise_priv, noise_pub_key, signing_priv) = {
            let ks = keys.lock().unwrap_or_else(|e| e.into_inner());
            (ks.noise_priv, ks.noise_pub_key, ks.signing_priv)
        };

        let noise_kp = NoiseKeypair::new(noise_priv, noise_pub_key);
        let new_client = match RelayClient::connect(transport, relay_pub, noise_kp) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Reinstall the full manifest-aware subscription using the shared handler.
        {
            new_client.subscribe(super::build_subscribe_handler(
                keys.clone(),
                manifest.clone(),
                on_removed_from_group.clone(),
                on_manifest_changed.clone(),
                on_group_destroyed.clone(),
                destroyed.clone(),
                pairing.clone(),
                pending_members.clone(),
                on_member_request.clone(),
                on_member_joined.clone(),
                on_member_left.clone(),
                on_message.clone(),
            ));
        }

        *client.lock().unwrap_or_else(|e| e.into_inner()) = new_client;
        backoff = Duration::from_secs(1);

        // Replay undelivered outbox in ascending sequence order.
        let signing = SigningKeypair::from_signing_key(SigningKey::from_bytes(&signing_priv));
        let entries = op_log.lock().unwrap_or_else(|e| e.into_inner()).undelivered_entries();
        for entry in entries {
            let oid = entry.object_id;
            let recipient_pub = NoisePublicKey(oid);
            let msg = crate::message::Message::Sync { body: entry.blob };
            let result =
                client
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(&msg, recipient_pub, entry.sequence, vec![], &signing);
            if result.is_ok() {
                op_log.lock().unwrap_or_else(|e| e.into_inner()).mark_delivered(&oid, entry.sequence);
            }
        }
    }
}
