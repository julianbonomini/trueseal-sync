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

use super::{
    leaving_refs_drained, refs_drained, DestroyingRecord, IssueSink, KeyState, LeavingRecord,
};

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

/// Exponential backoff for a recipient after `failures` consecutive
/// temporary failures: `retry_base * 2^(failures-1)`, saturating, capped at
/// `retry_cap` (ADR-0026: 1 s doubling up to a 5-minute cap).
pub(super) fn backoff_delay(config: &SenderConfig, failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(20);
    config
        .retry_base
        .saturating_mul(1u32 << shift)
        .min(config.retry_cap)
}

/// Spawn the sender pump. Runs for the session's lifetime.
///
/// Three duties on top of the outbox state machine:
/// - complete a Leaving once the Relay has accepted every Leave push
///   (`on_leave_complete` wipes and rotates, ADR-0027);
/// - complete a Destroying once the Relay has accepted every queued Revoke
///   (`on_destroy_complete` wipes, rotates and reports — ADR-0029);
/// - rebind the Receive Session after an identity rotation: the client is
///   swapped for the disconnected stub and the reconnect loop redials with
///   the fresh keys.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_sender<T: crate::relay::Severable>(
    client: Arc<Mutex<RelayClient<T>>>,
    op_log: Arc<Mutex<Box<dyn OperationLog>>>,
    keys: Arc<Mutex<KeyState>>,
    relay_pub_bytes: [u8; 32],
    push_factory: Arc<dyn Fn() -> Result<T, String> + Send + Sync>,
    issue_sink: Arc<Mutex<IssueSink>>,
    destroying: Arc<Mutex<Option<DestroyingRecord>>>,
    kick: Arc<Kick>,
    config: SenderConfig,
    leaving: Arc<Mutex<Option<LeavingRecord>>>,
    rotation_pending: Arc<AtomicBool>,
    on_leave_complete: Box<dyn Fn() + Send>,
    on_destroy_complete: Box<dyn Fn() + Send>,
    shutdown: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        sender_loop(
            client,
            op_log,
            keys,
            relay_pub_bytes,
            push_factory,
            issue_sink,
            destroying,
            kick,
            config,
            leaving,
            rotation_pending,
            on_leave_complete,
            on_destroy_complete,
            shutdown,
        );
    });
}

#[allow(clippy::too_many_arguments)]
fn sender_loop<T: crate::relay::Severable>(
    client: Arc<Mutex<RelayClient<T>>>,
    op_log: Arc<Mutex<Box<dyn OperationLog>>>,
    keys: Arc<Mutex<KeyState>>,
    relay_pub_bytes: [u8; 32],
    push_factory: Arc<dyn Fn() -> Result<T, String> + Send + Sync>,
    issue_sink: Arc<Mutex<IssueSink>>,
    destroying: Arc<Mutex<Option<DestroyingRecord>>>,
    kick: Arc<Kick>,
    config: SenderConfig,
    leaving: Arc<Mutex<Option<LeavingRecord>>>,
    rotation_pending: Arc<AtomicBool>,
    on_leave_complete: Box<dyn Fn() + Send>,
    on_destroy_complete: Box<dyn Fn() + Send>,
    shutdown: Arc<AtomicBool>,
) {
    let mut backoffs: HashMap<[u8; 32], RecipientBackoff> = HashMap::new();
    let mut was_connected = false;
    loop {
        // close() (SYNC-15, ADR-0028): the pump exits on the shutdown flag.
        // close() kicks, so this is observed immediately, not on the next
        // poll; entries in the outbox stay queued for the next session.
        if shutdown.load(Ordering::Acquire) {
            return;
        }
        // ADR-0027: the identity rotated (deliberate removal or a completed
        // Leave) — drop the old-key Receive Session so the reconnect loop
        // rebinds with the fresh keys. The old client drops here; its Drop
        // EOFs the receive loop.
        if rotation_pending.swap(false, Ordering::AcqRel) {
            *client.lock().unwrap_or_else(|e| e.into_inner()) = RelayClient::disconnected();
            was_connected = false;
        }

        // ADR-0027: a Leaving completes when the Relay has accepted every
        // Leave push (delivered rows are deleted). Runs before the
        // not-connected skip: the refs may have drained just before a
        // disconnect, and the wipe must not wait for a reconnect.
        let leaving_rec = leaving.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(rec) = leaving_rec {
            if leaving_refs_drained(&op_log, &rec) {
                (on_leave_complete)();
                // The wipe dropped every outbox entry; fall through to the
                // (now empty) idle path.
            }
        }

        // ADR-0029: a Destroying completes when the Relay has accepted
        // every queued Revoke — then wipe, rotate and report. The device
        // stays connected until then (there is no timeout). Same placement
        // as Leaving: a drain that happened just before a disconnect still
        // completes.
        let destroying_rec = destroying.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(rec) = destroying_rec {
            if refs_drained(&op_log, &rec.refs) {
                (on_destroy_complete)();
            }
        }

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
        // SYNC-14 (#106): any pass that removes rows (acceptance, expiry,
        // permanent refusal, undecodable control) truncates the WAL
        // afterwards, so the removed bodies stop existing on disk promptly.
        let mut removed_any = false;
        let mut pending: Vec<LogEntry> = Vec::with_capacity(entries.len());
        for entry in entries {
            let expired = entry.kind == OutboxKind::Sync
                && now.saturating_sub(entry.created_at) > config.sync_expiry.as_secs();
            if expired {
                op_log
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&entry.object_id, entry.sequence);
                removed_any = true;
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
                            removed_any = true;
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
                // The Sender Timestamp rule (ADR-0034 §2): a `Sync` entry is
                // stamped ONCE at send() — its outbox `created_at` — and
                // keeps that stamp through every re-seal, so every copy of
                // the message leaves the Replay Window at the same moment
                // and a replay can never outlive the dedup record. A
                // control entry is stamped at EACH seal: it never expires
                // from the outbox, so a long-offline Leave or Revoke must
                // be fresh when it finally lands.
                let sender_timestamp_ms = match entry.kind {
                    OutboxKind::Sync => entry.created_at.saturating_mul(1000),
                    OutboxKind::Control => crate::operation_log::now_secs().saturating_mul(1000),
                };
                let result = build_push_blob(
                    &msg,
                    NoisePublicKey(entry.object_id),
                    entry.sequence,
                    vec![],
                    &signing,
                    sender_timestamp_ms,
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
                        removed_any = true;
                        backoffs.remove(&recipient);
                    }
                    Err(e) => {
                        // Classify the refusal: permanent (the relay's Error
                        // frame; an Envelope that cannot fit one Noise
                        // frame) deletes the entry and reports; anything
                        // else is temporary.
                        let permanent = match e {
                            RelayError::PushRejected => Some(SendFailedReason::Malformed),
                            RelayError::EnvelopeTooLarge => Some(SendFailedReason::TooLarge),
                            _ => None,
                        };
                        match permanent {
                            Some(reason) => {
                                // Permanent refusal: delete the entry and
                                // report.
                                op_log
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .remove(&entry.object_id, entry.sequence);
                                removed_any = true;
                                issue_sink.lock().unwrap_or_else(|e| e.into_inner()).fire(
                                    DeliveryIssue::SendFailed {
                                        message_id: message_id(&local_signing_pub, entry.sequence),
                                        reason,
                                    },
                                );
                                // A permanent refusal says nothing about the
                                // connection — the next entry may still
                                // succeed.
                            }
                            None => {
                                // Temporary failure (network, handshake, an
                                // unsupported Transport Version — a
                                // whole-connection condition, not a
                                // per-entry one): back to Queued. Back off
                                // this recipient and stop at the head of its
                                // line: no later entry overtakes this one.
                                let failures =
                                    backoffs.get(&recipient).map(|b| b.failures).unwrap_or(0) + 1;
                                let delay = backoff_delay(&config, failures);
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
            }
        }

        if removed_any {
            // Best-effort (logged on failure): rows are already deleted
            // logically; this only hurries the physical erasure.
            op_log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .checkpoint_wal();
        }

        kick.wait(config.poll);
    }
}
