//! The sender half of the delivery contract (SYNC-5, #97; ADR-0026).
//!
//! One background pump per session owns the outbox state machine:
//!
//! `Queued → InFlight → Delivered (row deleted) | Queued (retry) | Failed (row deleted)`
//!
//! - Entries are pushed in Sequence order, head-of-line PER RECIPIENT: a
//!   later entry never overtakes an earlier one still being retried, and one
//!   recipient's failures never block another recipient.
//! - Temporary failures (network, handshake, an unsupported Transport
//!   Version) return the entry to `Queued`; the pump retries while
//!   connected with exponential backoff from `retry_base` to `retry_cap`,
//!   and immediately on reconnect (backoff state clears when the connection
//!   returns).
//! - Permanent refusals (the relay's Error frame; an Envelope that cannot
//!   fit one Noise frame) delete the entry and raise
//!   `sendFailed(messageId, malformed | tooLarge)`.
//! - A `Sync` entry still undelivered `sync_expiry` after it was queued is
//!   deleted with `sendFailed(messageId, expired)`. Control entries never
//!   expire (ADR-0026, ADR-0034 §2).
//! - Delivered rows are DELETED (ADR-0026); the sequence high-water mark in
//!   the log keeps sequence numbers unique across restarts regardless.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;

use crate::delivery_issue::{DeliveryIssue, SendFailedReason};
use crate::envelope::SigningKeypair;
use crate::keys::NoisePublicKey;
use crate::message::{message_id, Message};
use crate::operation_log::{now_secs, LogEntry, OperationLog, OutboxKind};
use crate::relay::{build_push_blob, push_send, RelayClient, RelayError};

use super::{IssueSink, KeyState};

/// Tunables for the sender pump. Defaults follow ADR-0026: backoff from
/// 1 s to a 5 min cap, and a 30-day expiry on `Sync` entries.
pub(super) struct SenderConfig {
    pub retry_base: Duration,
    pub retry_cap: Duration,
    /// How often the pump wakes without a kick, to notice reconnects and
    /// backoff deadlines.
    pub poll: Duration,
    pub sync_expiry: Duration,
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self {
            retry_base: Duration::from_secs(1),
            retry_cap: Duration::from_secs(300),
            poll: Duration::from_millis(50),
            sync_expiry: Duration::from_secs(30 * 24 * 60 * 60),
        }
    }
}

/// A wake-up signal for the pump: `send()` and control-plane queueing kick
/// it so a fresh entry is attempted promptly instead of on the next poll.
pub(super) struct Kick {
    lock: Mutex<()>,
    cond: Condvar,
}

impl Kick {
    pub fn new() -> Self {
        Self {
            lock: Mutex::new(()),
            cond: Condvar::new(),
        }
    }

    pub fn kick(&self) {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.cond.notify_all();
    }

    fn wait(&self, timeout: Duration) {
        let guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self
            .cond
            .wait_timeout(guard, timeout)
            .unwrap_or_else(|e| e.into_inner());
    }
}

/// Per-recipient backoff state.
struct RecipientBackoff {
    failures: u32,
    next_attempt: Instant,
}

/// Spawn the sender pump. Runs until the group is destroyed AND the outbox
/// has drained (a Destroy Group queues its Revokes first; the pump's last
/// job is to push them while connected — the durable Destroying state that
/// survives a restart is SYNC-11 scope).
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_sender<T: Read + Write + Send + 'static>(
    client: Arc<Mutex<RelayClient<T>>>,
    op_log: Arc<Mutex<Box<dyn OperationLog>>>,
    keys: Arc<Mutex<KeyState>>,
    relay_pub_bytes: [u8; 32],
    push_factory: Arc<dyn Fn() -> Result<T, String> + Send + Sync>,
    issue_sink: Arc<Mutex<IssueSink>>,
    destroyed: Arc<AtomicBool>,
    kick: Arc<Kick>,
    config: SenderConfig,
) {
    std::thread::spawn(move || {
        sender_loop(
            client,
            op_log,
            keys,
            relay_pub_bytes,
            push_factory,
            issue_sink,
            destroyed,
            kick,
            config,
        );
    });
}

#[allow(clippy::too_many_arguments)]
fn sender_loop<T: Read + Write + Send + 'static>(
    client: Arc<Mutex<RelayClient<T>>>,
    op_log: Arc<Mutex<Box<dyn OperationLog>>>,
    keys: Arc<Mutex<KeyState>>,
    relay_pub_bytes: [u8; 32],
    push_factory: Arc<dyn Fn() -> Result<T, String> + Send + Sync>,
    issue_sink: Arc<Mutex<IssueSink>>,
    destroyed: Arc<AtomicBool>,
    kick: Arc<Kick>,
    config: SenderConfig,
) {
    let mut backoffs: HashMap<[u8; 32], RecipientBackoff> = HashMap::new();
    let mut was_connected = false;
    loop {
        let connected = client
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_connected();
        if connected && !was_connected {
            // Reconnected: retry immediately (ADR-0026).
            backoffs.clear();
        }
        was_connected = connected;

        if !connected {
            kick.wait(config.poll);
            continue;
        }

        let entries = op_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .undelivered_entries();

        // The pump's exit condition: destroyed AND nothing left to send.
        // (The Revokes destroy_group queued are pushed first, while the
        // session is still connected.)
        if entries.is_empty() && destroyed.load(Ordering::Acquire) {
            break;
        }
        if entries.is_empty() {
            kick.wait(config.poll);
            continue;
        }

        let local_signing_pub = keys.lock().unwrap_or_else(|e| e.into_inner()).signing_pub.0;

        // Expiry sweep: a Sync entry still undelivered 30 days after send()
        // can never be delivered inside the Replay Window (the Relay TTL is
        // capped at 30 days, ADR-0034 §2) — fail it permanently. Control
        // entries never expire.
        let now = now_secs();
        let mut pending: Vec<LogEntry> = Vec::with_capacity(entries.len());
        for entry in entries {
            let expired = entry.kind == OutboxKind::Sync
                && now.saturating_sub(entry.created_at) > config.sync_expiry.as_secs();
            if expired {
                op_log
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&entry.object_id, entry.sequence);
                issue_sink.lock().unwrap_or_else(|e| e.into_inner()).fire(
                    DeliveryIssue::SendFailed {
                        message_id: message_id(&local_signing_pub, entry.sequence),
                        reason: SendFailedReason::Expired,
                    },
                );
            } else {
                pending.push(entry);
            }
        }

        // Group by recipient, preserving ascending Sequence order within
        // each recipient (undelivered_entries is globally sequence-sorted,
        // so grouping preserves per-recipient order).
        let mut order: Vec<[u8; 32]> = Vec::new();
        let mut by_recipient: HashMap<[u8; 32], Vec<LogEntry>> = HashMap::new();
        for entry in pending {
            by_recipient
                .entry(entry.object_id)
                .or_insert_with(|| {
                    order.push(entry.object_id);
                    Vec::new()
                })
                .push(entry);
        }

        let signing = SigningKeypair::from_signing_key(SigningKey::from_bytes(
            &keys.lock().unwrap_or_else(|e| e.into_inner()).signing_priv,
        ));

        for recipient in order {
            // Head-of-line per recipient: respect the backoff deadline.
            if let Some(b) = backoffs.get(&recipient) {
                if Instant::now() < b.next_attempt {
                    continue;
                }
            }
            let entries = by_recipient.remove(&recipient).unwrap_or_default();
            for entry in entries {
                let msg = match entry.kind {
                    OutboxKind::Sync => Message::Sync {
                        body: entry.blob.clone(),
                    },
                    OutboxKind::Control => match Message::decode(&entry.blob) {
                        Ok(m) => m,
                        Err(_) => {
                            // We wrote this entry with Message::encode — a
                            // decode failure means store corruption. It can
                            // never succeed: fail it permanently.
                            op_log
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&entry.object_id, entry.sequence);
                            issue_sink.lock().unwrap_or_else(|e| e.into_inner()).fire(
                                DeliveryIssue::SendFailed {
                                    message_id: message_id(&local_signing_pub, entry.sequence),
                                    reason: SendFailedReason::Malformed,
                                },
                            );
                            continue;
                        }
                    },
                };
                let result = build_push_blob(
                    &msg,
                    NoisePublicKey(entry.object_id),
                    entry.sequence,
                    vec![],
                    &signing,
                )
                .and_then(|framed| {
                    (push_factory)()
                        .map_err(RelayError::PushFailed)
                        .and_then(|transport| push_send(transport, relay_pub_bytes, framed))
                });
                match result {
                    Ok(()) => {
                        // Delivered: the row is DELETED (ADR-0026) and the
                        // recipient's backoff resets for the entries behind.
                        op_log
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .remove(&entry.object_id, entry.sequence);
                        backoffs.remove(&recipient);
                    }
                    Err(e @ (RelayError::PushRejected | RelayError::EnvelopeTooLarge)) => {
                        // Permanent refusal: delete the entry and report.
                        let reason = match e {
                            RelayError::PushRejected => SendFailedReason::Malformed,
                            RelayError::EnvelopeTooLarge => SendFailedReason::TooLarge,
                            _ => unreachable!("matched above"),
                        };
                        op_log
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .remove(&entry.object_id, entry.sequence);
                        issue_sink.lock().unwrap_or_else(|e| e.into_inner()).fire(
                            DeliveryIssue::SendFailed {
                                message_id: message_id(&local_signing_pub, entry.sequence),
                                reason,
                            },
                        );
                        // A permanent refusal says nothing about the
                        // connection — the next entry may still succeed.
                    }
                    Err(_) => {
                        // Temporary failure (network, handshake, an
                        // unsupported Transport Version — a whole-connection
                        // condition, not a per-entry one): back to Queued.
                        // Back off this recipient and stop at the head of
                        // its line: no later entry overtakes this one.
                        let failures =
                            backoffs.get(&recipient).map(|b| b.failures).unwrap_or(0) + 1;
                        let shift = failures.saturating_sub(1).min(20);
                        let delay = config
                            .retry_base
                            .saturating_mul(1u32 << shift)
                            .min(config.retry_cap);
                        backoffs.insert(
                            recipient,
                            RecipientBackoff {
                                failures,
                                next_attempt: Instant::now() + delay,
                            },
                        );
                        break;
                    }
                }
            }
        }

        kick.wait(config.poll);
    }
}
