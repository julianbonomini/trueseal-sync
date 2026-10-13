use std::collections::BTreeMap;

/// How long a handled Message ID is kept for dedup: 60 days (ADR-0026).
/// A message can wait up to 30 days in the sender's outbox and then up to
/// 30 days on the Relay, so a copy always arrives within 60 days of
/// `send()`. (ADR-0034 §2 refines this to "the later of handling time and
/// the Sender Timestamp" — the sealed Sender Timestamp lands with SYNC-12;
/// until then the retention runs from the handling time.)
pub const DEDUP_RETENTION_SECS: u64 = 60 * 24 * 60 * 60;

/// Current time in whole Unix seconds. Outbox timestamps are coarse — the
/// 30-day expiry and 60-day dedup retention never need sub-second precision.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What an outbox entry carries (ADR-0026).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxKind {
    /// An application `Sync` body (raw bytes, no type tag). Expires 30 days
    /// after `send()` — the Relay TTL cap is 30 days, so an older entry
    /// could never be delivered inside the Replay Window.
    Sync,
    /// A control-plane message (Pair, Group Manifest, Revoke): the blob is
    /// the full `Message::encode()`. Never expires — a Leave or Destroy
    /// Group queued offline for months must still reach every peer
    /// (ADR-0034 §2).
    Control,
}

/// One atomic membership commit (ADR-0027): an issued or accepted Group
/// Manifest, the held-manifest record for deliberate-removal detection, the
/// full replacement Pending Membership Change set, optionally the Leaving
/// record, and the control-plane outbox entries that carry the manifest to
/// the other members — all committed as ONE unit, so a crash leaves either
/// the whole prior state or the whole new state.
///
/// The encoding of `pending_changes` and `leaving` is owned by the session;
/// the log treats them as opaque blobs.
pub struct MembershipCommit {
    /// The encoded GroupManifest being installed as the current view.
    pub manifest: Vec<u8>,
    /// `(hash of the installed manifest, includes_self)` — recorded in the
    /// held-manifest history (ADR-0027: a device counts itself removed only
    /// when the excluding manifest's `parent` is a manifest it holds or has
    /// held that includes it).
    pub held: ([u8; 32], bool),
    /// The full replacement Pending Membership Change set; empty = none.
    pub pending_changes: Vec<u8>,
    /// `Some(record)` sets/replaces the Leaving record (entering Leaving or
    /// updating its outbox refs on a re-applied Leave); `None` leaves it
    /// untouched.
    pub leaving: Option<Vec<u8>>,
    /// Control-plane outbox entries carrying the manifest to members:
    /// `(recipient noise_pub, sequence, encoded Message)`.
    pub outbox: Vec<([u8; 32], u64, Vec<u8>)>,
}

/// A named entry returned from the operation log.
/// Replaces positional tuple returns in the trait — callers use field names instead
/// of destructuring by position, which is both more readable and refactor-safe.
pub struct LogEntry {
    pub object_id: [u8; 32],
    pub sequence: u64,
    pub kind: OutboxKind,
    /// Unix seconds when the entry was queued (`send()` time for `Sync`).
    pub created_at: u64,
    pub blob: Vec<u8>,
}

/// A log of (sequence, blob) entries keyed by object_id.
/// The Relay is unaware of object_ids — they live only inside encrypted payloads.
/// The caller maps Envelope.payload → object_id + blob after decryption.
///
/// # Design notes
/// - `sequence` is the sender Device's **global** counter — it increments once
///   per Envelope sent, across all Objects. It is not scoped per Object.
///   See ADR-0011.
/// - `append` is idempotent for the same (object_id, sequence) pair: a second
///   write with the same sequence is silently ignored (first-write wins —
///   conflict resolution is the caller's concern, not the log's).
/// - `entries_from` returns all entries for an Object with sequence >= the given
///   value, in ascending sequence order.
/// - `mark_delivered` marks an entry as confirmed delivered to the Relay.
///   Entries start as undelivered. The session calls this after a successful push.
/// - `undelivered_entries` returns all entries not yet confirmed delivered,
///   sorted by global sequence ascending — the correct replay order for the outbox.
/// - v0 uses an in-memory backend (`MemLog`).
///   A `SqliteLog` (persisted) is the obvious next backend.
pub trait OperationLog: Send {
    /// Append a fully-described entry. Implementations must stay idempotent
    /// for the same (object_id, sequence) pair: first-write wins.
    fn append_entry(&mut self, entry: LogEntry);
    /// Queue an application `Sync` body, stamped now.
    fn append(&mut self, object_id: &[u8; 32], sequence: u64, blob: Vec<u8>) {
        self.append_entry(LogEntry {
            object_id: *object_id,
            sequence,
            kind: OutboxKind::Sync,
            created_at: now_secs(),
            blob,
        });
    }
    /// Queue a control-plane message (its full `Message::encode()`),
    /// stamped now. Control entries never expire (ADR-0026).
    fn append_control(&mut self, object_id: &[u8; 32], sequence: u64, encoded_message: Vec<u8>) {
        self.append_entry(LogEntry {
            object_id: *object_id,
            sequence,
            kind: OutboxKind::Control,
            created_at: now_secs(),
            blob: encoded_message,
        });
    }
    fn mark_delivered(&mut self, object_id: &[u8; 32], sequence: u64);
    /// Permanently delete one entry. Used to drop entries that can never be
    /// delivered (e.g. over the Protocol Size Limit, ADR-0025) — unlike
    /// `mark_delivered`, the entry is gone, not just confirmed.
    fn remove(&mut self, object_id: &[u8; 32], sequence: u64);
    /// Returns undelivered entries sorted by global sequence ascending.
    fn undelivered_entries(&self) -> Vec<LogEntry>;
    fn entries_from(&self, object_id: &[u8; 32], sequence: u64) -> Vec<LogEntry>;
    /// Returns the highest sequence number ever consumed across all
    /// objects, or `None` if the log is empty. Used to restore the sequence
    /// counter after a process restart so it never re-uses a sequence
    /// number. Delivered rows are deleted once the Relay accepts them
    /// (ADR-0026), so implementations fold in the high-water mark recorded
    /// by [`OperationLog::record_sequence`], not just surviving rows.
    fn max_sequence(&self) -> Option<u64>;
    /// Record that `sequence` has been consumed. The high-water mark
    /// survives deletion of the entry that used it, so a restart never
    /// re-uses a sequence number after delivered rows are deleted (ADR-0026):
    /// a re-used sequence would collide in the recipient's dedup table and
    /// the new message would be silently dropped as a duplicate.
    fn record_sequence(&mut self, sequence: u64);
    /// Dedup table (ADR-0026 recipient step 3): has this Message ID already
    /// been handled?
    fn is_handled(&self, message_id: &str) -> bool;
    /// Record a handled Message ID, stamped `now` (Unix seconds), and prune
    /// records older than [`DEDUP_RETENTION_SECS`] relative to `now`.
    fn record_handled(&mut self, message_id: &str, now: u64);

    /// Persist the Pending Join record AND queue its `Pair` control entry
    /// as one unit (ADR-0023: "`joinGroup` persists the Pending Join in
    /// Session State and queues `Pair` in the durable outbox, in one
    /// transaction"). A second call replaces the record — a second
    /// `joinGroup` replaces the Pending Join. The Pair from a replaced
    /// Pending Join stays queued: if delivered, the old initiator's
    /// manifest fails the new anchor's checks and is dropped.
    ///
    /// `pending` is the opaque serialised record (the session owns the
    /// encoding). Implementations with transactions (SQLite) must make the
    /// two writes atomic; a crash leaves either the whole prior state or
    /// the whole new state.
    ///
    /// Fallible (B8 review F3): a durable implementation can fail. The
    /// caller (`join_group`) must NOT set its in-memory Pending Join on
    /// error — without the durable record and the queued Pair the join
    /// would hang forever. The error is a description; the session maps
    /// it to a typed `SessionError`.
    fn begin_pending_join(
        &mut self,
        pending: &[u8],
        recipient: &[u8; 32],
        sequence: u64,
        encoded_pair: Vec<u8>,
    ) -> Result<(), String>;
    /// The persisted Pending Join record, if any. Loaded at session
    /// construction so the anchor survives restarts (ADR-0023: a Pending
    /// Join has no timer and survives restarts).
    fn pending_join(&self) -> Option<Vec<u8>>;
    /// Clear the Pending Join — on `cancelJoin()` and when the first
    /// manifest is accepted (ADR-0023).
    fn clear_pending_join(&mut self);

    // ── Membership convergence (ADR-0027) ───────────────────────────────────

    /// Commit an issued or accepted manifest with its held record, Pending
    /// Membership Change set, optional Leaving record and outbox entries as
    /// ONE unit. Implementations with transactions (SQLite) must make the
    /// whole commit atomic — the ADR's crash points depend on it: after the
    /// commit the manifest is redelivered from the outbox and the pending
    /// change is re-checked on the next accepted manifest; before it, the
    /// change never happened.
    ///
    /// Fallible like `begin_pending_join`: the caller must not update
    /// in-memory state on error.
    fn commit_membership(&mut self, commit: MembershipCommit) -> Result<(), String>;
    /// The persisted Pending Membership Change set (opaque encoding), if
    /// any. Loaded at construction so pending changes survive restarts and
    /// an offline issuer re-applies after reconnecting.
    fn pending_membership_changes(&self) -> Option<Vec<u8>>;
    /// Was `hash` a manifest this device holds or has held that included
    /// it? The deliberate-removal test (ADR-0027): an excluding manifest
    /// counts as a deliberate removal only when its `parent` passes this.
    fn is_held_including_self(&self, hash: &[u8; 32]) -> bool;
    /// The persisted Leaving record (opaque encoding of the outbox refs the
    /// Leave waits on), if any. Loaded at construction so a crash during
    /// Leaving resumes Leaving (ADR-0027).
    fn leaving(&self) -> Option<Vec<u8>>;
    /// Wipe all group state this log owns: outbox, dedup table, sequence
    /// high-water mark, Pending Join, Pending Membership Changes,
    /// held-manifest history and the Leaving record. Identity and manifest
    /// rows live on the Store side and are wiped by the caller (the FFI's
    /// store handle). Used on deliberate removal and completed Leave
    /// (ADR-0027): the device starts over with a fresh identity, so nothing
    /// from the old group may carry over.
    fn wipe_group_state(&mut self);
}

/// A single entry in the log.
struct Entry {
    kind: OutboxKind,
    created_at: u64,
    blob: Vec<u8>,
    delivered: bool,
}

/// In-memory operation log. Not persisted across restarts.
/// Key: object_id bytes. Value: BTreeMap<sequence, Entry>.
pub struct MemLog {
    inner: BTreeMap<[u8; 32], BTreeMap<u64, Entry>>,
    /// Highest sequence ever consumed — survives deletion of delivered rows.
    high_water: Option<u64>,
    /// Handled Message IDs → handling time (Unix seconds). The dedup table.
    handled: BTreeMap<String, u64>,
    /// The Pending Join record (ADR-0023). In-memory like the rest of MemLog.
    pending_join: Option<Vec<u8>>,
    /// The Pending Membership Change set (ADR-0027). Empty = none.
    pending_changes: Vec<u8>,
    /// Held-manifest history: hash → included_self (ADR-0027).
    held: BTreeMap<[u8; 32], bool>,
    /// The Leaving record (ADR-0027).
    leaving: Option<Vec<u8>>,
}

impl MemLog {
    pub fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
            high_water: None,
            handled: BTreeMap::new(),
            pending_join: None,
            pending_changes: Vec::new(),
            held: BTreeMap::new(),
            leaving: None,
        }
    }
}

impl Default for MemLog {
    fn default() -> Self {
        Self::new()
    }
}

impl OperationLog for MemLog {
    fn append_entry(&mut self, entry: LogEntry) {
        self.inner
            .entry(entry.object_id)
            .or_default()
            .entry(entry.sequence)
            .or_insert(Entry {
                kind: entry.kind,
                created_at: entry.created_at,
                blob: entry.blob,
                delivered: false,
            });
    }

    fn mark_delivered(&mut self, object_id: &[u8; 32], sequence: u64) {
        if let Some(map) = self.inner.get_mut(object_id) {
            if let Some(entry) = map.get_mut(&sequence) {
                entry.delivered = true;
            }
        }
    }

    fn remove(&mut self, object_id: &[u8; 32], sequence: u64) {
        if let Some(map) = self.inner.get_mut(object_id) {
            map.remove(&sequence);
            if map.is_empty() {
                self.inner.remove(object_id);
            }
        }
    }

    fn undelivered_entries(&self) -> Vec<LogEntry> {
        // Collect all undelivered entries, then sort by global sequence ascending
        // so the session replays the outbox in the original send order.
        let mut out: Vec<LogEntry> = self
            .inner
            .iter()
            .flat_map(|(object_id, map)| {
                map.iter()
                    .filter(|(_, entry)| !entry.delivered)
                    .map(move |(seq, entry)| LogEntry {
                        object_id: *object_id,
                        sequence: *seq,
                        kind: entry.kind,
                        created_at: entry.created_at,
                        blob: entry.blob.clone(),
                    })
            })
            .collect();
        out.sort_by_key(|e| e.sequence);
        out
    }

    fn entries_from(&self, object_id: &[u8; 32], sequence: u64) -> Vec<LogEntry> {
        match self.inner.get(object_id) {
            None => vec![],
            Some(map) => map
                .range(sequence..)
                .map(|(seq, entry)| LogEntry {
                    object_id: *object_id,
                    sequence: *seq,
                    kind: entry.kind,
                    created_at: entry.created_at,
                    blob: entry.blob.clone(),
                })
                .collect(),
        }
    }

    fn max_sequence(&self) -> Option<u64> {
        self.inner
            .values()
            .flat_map(|map| map.keys().copied())
            .max()
            .into_iter()
            .chain(self.high_water)
            .max()
    }

    fn record_sequence(&mut self, sequence: u64) {
        self.high_water = Some(self.high_water.map_or(sequence, |hw| hw.max(sequence)));
    }

    fn is_handled(&self, message_id: &str) -> bool {
        self.handled.contains_key(message_id)
    }

    fn record_handled(&mut self, message_id: &str, now: u64) {
        self.handled.insert(message_id.to_string(), now);
        let cutoff = now.saturating_sub(DEDUP_RETENTION_SECS);
        self.handled.retain(|_, handled_at| *handled_at >= cutoff);
    }

    fn begin_pending_join(
        &mut self,
        pending: &[u8],
        recipient: &[u8; 32],
        sequence: u64,
        encoded_pair: Vec<u8>,
    ) -> Result<(), String> {
        self.pending_join = Some(pending.to_vec());
        self.append_control(recipient, sequence, encoded_pair);
        Ok(())
    }

    fn pending_join(&self) -> Option<Vec<u8>> {
        self.pending_join.clone()
    }

    fn clear_pending_join(&mut self) {
        self.pending_join = None;
    }

    fn commit_membership(&mut self, commit: MembershipCommit) -> Result<(), String> {
        let MembershipCommit {
            manifest: _,
            held,
            pending_changes,
            leaving,
            outbox,
        } = commit;
        // MemLog owns no manifest row (persistence is the Store's job);
        // the held record, change set and entries are the in-memory state.
        self.held.insert(held.0, held.1);
        self.pending_changes = pending_changes;
        if let Some(record) = leaving {
            self.leaving = Some(record);
        }
        for (object_id, sequence, blob) in outbox {
            self.append_control(&object_id, sequence, blob);
        }
        Ok(())
    }

    fn pending_membership_changes(&self) -> Option<Vec<u8>> {
        if self.pending_changes.is_empty() {
            None
        } else {
            Some(self.pending_changes.clone())
        }
    }

    fn is_held_including_self(&self, hash: &[u8; 32]) -> bool {
        self.held.get(hash).copied().unwrap_or(false)
    }

    fn leaving(&self) -> Option<Vec<u8>> {
        self.leaving.clone()
    }

    fn wipe_group_state(&mut self) {
        self.inner.clear();
        self.high_water = None;
        self.handled.clear();
        self.pending_join = None;
        self.pending_changes = Vec::new();
        self.held.clear();
        self.leaving = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// MemLog honours the Pending Join contract: begin persists and queues,
    /// a second begin replaces, clear removes (ADR-0023).
    #[test]
    fn memlog_pending_join_begin_replace_clear() {
        let mut log = MemLog::new();
        assert!(log.pending_join().is_none());
        log.begin_pending_join(b"anchor-a", &oid(7), 0, b"pair-a".to_vec())
            .unwrap();
        assert_eq!(log.pending_join().as_deref(), Some(b"anchor-a".as_slice()));
        log.begin_pending_join(b"anchor-b", &oid(8), 1, b"pair-b".to_vec())
            .unwrap();
        assert_eq!(log.pending_join().as_deref(), Some(b"anchor-b".as_slice()));
        assert_eq!(log.undelivered_entries().len(), 2);
        log.clear_pending_join();
        assert!(log.pending_join().is_none());
        assert_eq!(
            log.undelivered_entries().len(),
            2,
            "cancel keeps queued Pairs"
        );
    }

    /// Tracer bullet: append one entry and retrieve it via LogEntry fields.
    #[test]
    fn append_and_retrieve_single_entry() {
        let mut log = MemLog::new();
        log.append(&oid(1), 0, b"hello".to_vec());
        let entries = log.entries_from(&oid(1), 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sequence, 0);
        assert_eq!(entries[0].blob, b"hello");
        assert_eq!(entries[0].object_id, oid(1));
    }

    /// entries_from(seq) returns only entries with sequence >= seq.
    #[test]
    fn entries_from_filters_by_sequence() {
        let mut log = MemLog::new();
        log.append(&oid(1), 0, b"first".to_vec());
        log.append(&oid(1), 1, b"second".to_vec());
        log.append(&oid(1), 2, b"third".to_vec());

        let entries = log.entries_from(&oid(1), 1);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sequence, 1);
        assert_eq!(entries[0].blob, b"second");
        assert_eq!(entries[1].sequence, 2);
        assert_eq!(entries[1].blob, b"third");
    }

    /// entries_from on an unknown object_id returns empty.
    #[test]
    fn unknown_object_id_returns_empty() {
        let log = MemLog::new();
        let entries = log.entries_from(&oid(99), 0);
        assert!(entries.is_empty());
    }

    /// Objects are stored independently — different object_ids don't interfere.
    #[test]
    fn different_object_ids_are_independent() {
        let mut log = MemLog::new();
        log.append(&oid(1), 0, b"obj1".to_vec());
        log.append(&oid(2), 0, b"obj2".to_vec());

        let e1 = log.entries_from(&oid(1), 0);
        let e2 = log.entries_from(&oid(2), 0);
        assert_eq!(e1.len(), 1);
        assert_eq!(e1[0].blob, b"obj1");
        assert_eq!(e2.len(), 1);
        assert_eq!(e2[0].blob, b"obj2");
    }

    /// Second append with the same (object_id, sequence) is silently ignored
    /// (first-write wins — conflict resolution is the caller's concern).
    #[test]
    fn duplicate_sequence_is_ignored() {
        let mut log = MemLog::new();
        log.append(&oid(1), 5, b"original".to_vec());
        log.append(&oid(1), 5, b"overwrite attempt".to_vec());

        let entries = log.entries_from(&oid(1), 5);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].blob, b"original");
    }

    /// entries_from returns entries in ascending sequence order.
    #[test]
    fn entries_are_ordered_by_sequence() {
        let mut log = MemLog::new();
        log.append(&oid(1), 3, b"c".to_vec());
        log.append(&oid(1), 1, b"a".to_vec());
        log.append(&oid(1), 2, b"b".to_vec());

        let entries = log.entries_from(&oid(1), 0);
        let seqs: Vec<u64> = entries.iter().map(|e| e.sequence).collect();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    /// Freshly appended entries are undelivered.
    #[test]
    fn appended_entries_start_as_undelivered() {
        let mut log = MemLog::new();
        log.append(&oid(1), 0, b"hello".to_vec());

        let undelivered = log.undelivered_entries();
        assert_eq!(undelivered.len(), 1);
        assert_eq!(undelivered[0].object_id, oid(1));
        assert_eq!(undelivered[0].sequence, 0);
        assert_eq!(undelivered[0].blob, b"hello");
    }

    /// mark_delivered removes an entry from undelivered_entries.
    #[test]
    fn mark_delivered_clears_from_outbox() {
        let mut log = MemLog::new();
        log.append(&oid(1), 0, b"hello".to_vec());
        log.mark_delivered(&oid(1), 0);

        assert!(log.undelivered_entries().is_empty());
    }

    /// mark_delivered does not affect entries_from — delivery status is orthogonal.
    #[test]
    fn mark_delivered_does_not_affect_entries_from() {
        let mut log = MemLog::new();
        log.append(&oid(1), 0, b"hello".to_vec());
        log.mark_delivered(&oid(1), 0);

        let entries = log.entries_from(&oid(1), 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].blob, b"hello");
    }

    /// undelivered_entries spans all object_ids.
    #[test]
    fn undelivered_entries_spans_all_objects() {
        let mut log = MemLog::new();
        log.append(&oid(1), 0, b"a".to_vec());
        log.append(&oid(2), 0, b"b".to_vec());
        log.append(&oid(1), 1, b"c".to_vec());
        log.mark_delivered(&oid(1), 0);

        let undelivered = log.undelivered_entries();
        assert_eq!(undelivered.len(), 2);
        let keys: Vec<([u8; 32], u64)> = undelivered
            .iter()
            .map(|e| (e.object_id, e.sequence))
            .collect();
        assert!(keys.contains(&(oid(1), 1)));
        assert!(keys.contains(&(oid(2), 0)));
    }

    /// undelivered_entries are sorted by global sequence ascending —
    /// the correct replay order for the outbox (ADR-0011).
    #[test]
    fn undelivered_entries_sorted_by_global_sequence() {
        let mut log = MemLog::new();
        // Interleaved sends across two objects — global sequence order is 0,1,2,3
        log.append(&oid(1), 0, b"obj1-first".to_vec());
        log.append(&oid(2), 1, b"obj2-first".to_vec());
        log.append(&oid(1), 2, b"obj1-second".to_vec());
        log.append(&oid(2), 3, b"obj2-second".to_vec());

        let undelivered = log.undelivered_entries();
        let seqs: Vec<u64> = undelivered.iter().map(|e| e.sequence).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3], "must be sorted by global sequence");
    }

    /// mark_delivered on unknown (object_id, sequence) is a no-op.
    #[test]
    fn mark_delivered_unknown_entry_is_noop() {
        let mut log = MemLog::new();
        log.mark_delivered(&oid(99), 42);
        assert!(log.undelivered_entries().is_empty());
    }

    /// The high-water mark survives deletion of the row that consumed the
    /// sequence — a restart must never re-use a sequence number after
    /// delivered rows are deleted (ADR-0026); a re-used sequence would
    /// collide in the recipient's dedup table and be dropped as a duplicate.
    #[test]
    fn max_sequence_survives_deletion_of_delivered_rows() {
        let mut log = MemLog::new();
        log.append(&oid(1), 0, b"a".to_vec());
        log.record_sequence(0);
        log.remove(&oid(1), 0); // delivered rows are deleted, not kept
        assert_eq!(log.max_sequence(), Some(0));
        assert!(log.undelivered_entries().is_empty());
    }

    /// record_sequence only ever moves the high-water mark up.
    #[test]
    fn record_sequence_never_regresses() {
        let mut log = MemLog::new();
        log.record_sequence(7);
        log.record_sequence(3);
        assert_eq!(log.max_sequence(), Some(7));
    }

    /// Control entries keep their kind and timestamp; Sync bodies appended
    /// through the shorthand are Sync kind stamped ~now.
    #[test]
    fn append_control_marks_kind_and_timestamp() {
        let mut log = MemLog::new();
        let before = now_secs();
        log.append_control(&oid(1), 0, b"\x04manifest".to_vec());
        log.append(&oid(1), 1, b"raw body".to_vec());
        let entries = log.entries_from(&oid(1), 0);
        assert_eq!(entries[0].kind, OutboxKind::Control);
        assert_eq!(entries[0].blob, b"\x04manifest");
        assert!(entries[0].created_at >= before);
        assert_eq!(entries[1].kind, OutboxKind::Sync);
    }

    /// A constructed entry with an explicit timestamp round-trips — this is
    /// how tests stage old entries for the 30-day expiry rule.
    #[test]
    fn append_entry_preserves_explicit_created_at() {
        let mut log = MemLog::new();
        log.append_entry(LogEntry {
            object_id: oid(1),
            sequence: 0,
            kind: OutboxKind::Sync,
            created_at: 1_000_000,
            blob: b"old".to_vec(),
        });
        let entries = log.undelivered_entries();
        assert_eq!(entries[0].created_at, 1_000_000);
    }

    /// Dedup: a recorded Message ID is handled; records older than the
    /// 60-day retention are pruned on the next record.
    #[test]
    fn handled_ids_are_recorded_and_pruned() {
        let mut log = MemLog::new();
        assert!(!log.is_handled("tsm1_x"));
        // An old record at t=1000.
        log.record_handled("tsm1_old", 1_000);
        assert!(log.is_handled("tsm1_old"));
        // Recording at t=1000+60d+1 prunes the old one.
        log.record_handled("tsm1_new", 1_000 + DEDUP_RETENTION_SECS + 1);
        assert!(log.is_handled("tsm1_new"));
        assert!(
            !log.is_handled("tsm1_old"),
            "records older than the retention window are pruned"
        );
    }

    /// max_sequence returns None on empty log, max across all objects otherwise.
    #[test]
    fn max_sequence_empty_and_nonempty() {
        let mut log = MemLog::new();
        assert_eq!(log.max_sequence(), None);

        log.append(&oid(1), 3, b"a".to_vec());
        log.append(&oid(2), 7, b"b".to_vec());
        log.append(&oid(1), 5, b"c".to_vec());
        assert_eq!(log.max_sequence(), Some(7));

        log.mark_delivered(&oid(2), 7);
        // Delivered entries still count toward max_sequence.
        assert_eq!(log.max_sequence(), Some(7));
    }
}
