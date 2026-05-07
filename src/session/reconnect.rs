use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use hush_noise::keypair::Keypair as NoiseKeypair;

use crate::device::DeviceKeypair;
use crate::envelope::SigningKeypair;
use crate::keys::NoisePublicKey;
use crate::manifest::GroupManifest;
use crate::message::Message;
use crate::operation_log::OperationLog;
use crate::relay::RelayClient;

use super::KeyState;

/// Polls for relay disconnect, backs off, reconnects, and replays the outbox.
/// Runs in a background thread spawned by `connect_with_reconnect`.
pub(super) fn reconnect_loop<T: Read + Write + Send + 'static>(
    client: Arc<Mutex<RelayClient<T>>>,
    op_log: Arc<Mutex<Box<dyn OperationLog>>>,
    relay_pub: NoisePublicKey,
    keys: Arc<Mutex<KeyState>>,
    manifest: Arc<Mutex<Option<GroupManifest>>>,
    on_message: impl Fn(Message, [u8; 32]) + Send + 'static + Clone,
    on_keypair_rotated: Arc<dyn Fn([u8; 64]) + Send + Sync + 'static>,
    on_removed_from_group: Arc<dyn Fn() + Send + Sync + 'static>,
    factory: Arc<dyn Fn() -> Result<T, String> + Send + Sync>,
    cap: Duration,
) {
    let mut backoff = cap.min(Duration::from_secs(1));
    loop {
        std::thread::sleep(Duration::from_millis(50));
        let connected = client.lock().unwrap().is_connected();
        if connected {
            backoff = Duration::from_secs(1);
            continue;
        }

        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(cap);

        let transport = match (factory)() {
            Ok(t) => t,
            Err(_) => continue,
        };

        let (noise_priv, noise_pub_key, signing_priv) = {
            let ks = keys.lock().unwrap();
            (ks.noise_priv, ks.noise_pub_key, ks.signing_priv)
        };

        let noise_kp = NoiseKeypair::new(noise_priv, noise_pub_key);
        let new_client = match RelayClient::connect(transport, relay_pub, noise_kp) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Reinstall the full manifest-aware subscription — mirrors connect_full.
        {
            let keys_cb = keys.clone();
            let manifest_cb = manifest.clone();
            let on_kpr_cb = on_keypair_rotated.clone();
            let on_rfg_cb = on_removed_from_group.clone();
            let on_message = on_message.clone();
            new_client.subscribe(move |msg, author_signing_pub| {
                // Manifest-based inbound filtering.
                {
                    let guard = manifest_cb.lock().unwrap();
                    if let Some(ref m) = *guard {
                        if !m.contains_signing_pub(&author_signing_pub) {
                            return;
                        }
                    }
                }

                if let Message::Revoke = &msg {
                    let maybe_kp = {
                        let guard = manifest_cb.lock().unwrap();
                        if let Some(ref m) = *guard {
                            if m.contains_signing_pub(&author_signing_pub) {
                                Some(DeviceKeypair::generate())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    };
                    if let Some(new_kp) = maybe_kp {
                        *manifest_cb.lock().unwrap() = None;
                        let mut rotated = [0u8; 64];
                        rotated[..32].copy_from_slice(&new_kp.noise.private());
                        rotated[32..].copy_from_slice(&new_kp.signing.to_bytes());
                        *keys_cb.lock().unwrap() = KeyState::from_keypair(&new_kp);
                        (on_kpr_cb)(rotated);
                    }
                    return;
                }

                if let Message::GroupManifest { manifest: incoming } = &msg {
                    let local_signing_pub = keys_cb.lock().unwrap().signing_pub.0;
                    let mut guard = manifest_cb.lock().unwrap();
                    let accept = match *guard {
                        None => incoming.verify(None).is_ok(),
                        Some(ref current) => incoming.verify(Some(current)).is_ok(),
                    };
                    if accept {
                        let excluded = !incoming.contains_signing_pub(&local_signing_pub);
                        *guard = Some(incoming.clone());
                        drop(guard);
                        if excluded {
                            (on_rfg_cb)();
                        }
                    }
                    return;
                }

                on_message(msg, author_signing_pub);
            });
        }

        *client.lock().unwrap() = new_client;
        backoff = Duration::from_secs(1);

        // Replay undelivered outbox in ascending sequence order.
        let signing = SigningKeypair::from_signing_key(SigningKey::from_bytes(&signing_priv));
        let entries = op_log.lock().unwrap().undelivered_entries();
        for entry in entries {
            let oid = entry.object_id;
            let recipient_pub = NoisePublicKey(oid);
            let msg = crate::message::Message::Sync { body: entry.blob };
            let result =
                client
                    .lock()
                    .unwrap()
                    .push(&msg, recipient_pub, entry.sequence, vec![], &signing);
            if result.is_ok() {
                op_log.lock().unwrap().mark_delivered(&oid, entry.sequence);
            }
        }
    }
}
