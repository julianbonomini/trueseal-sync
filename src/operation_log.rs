use std::collections::BTreeMap;

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
    fn append(&mut self, object_id: &[u8; 32], sequence: u64, blob: Vec<u8>);
    fn mark_delivered(&mut self, object_id: &[u8; 32], sequence: u64);
    /// Returns undelivered entries sorted by global sequence ascending.
    fn undelivered_entries(&self) -> Vec<([u8; 32], u64, Vec<u8>)>;
    fn entries_from(&self, object_id: &[u8; 32], sequence: u64) -> Vec<(u64, Vec<u8>)>;
}

/// A single entry in the log.
struct Entry {
    blob: Vec<u8>,
    delivered: bool,
}

/// In-memory operation log. Not persisted across restarts.
/// Key: object_id bytes. Value: BTreeMap<sequence, Entry>.
pub struct MemLog {
    inner: BTreeMap<[u8; 32], BTreeMap<u64, Entry>>,
}

impl MemLog {
    pub fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
        }
    }
}

impl Default for MemLog {
    fn default() -> Self {
        Self::new()
    }
}

impl OperationLog for MemLog {
    fn append(&mut self, object_id: &[u8; 32], sequence: u64, blob: Vec<u8>) {
        self.inner
            .entry(*object_id)
            .or_default()
            .entry(sequence)
            .or_insert(Entry {
                blob,
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

    fn undelivered_entries(&self) -> Vec<([u8; 32], u64, Vec<u8>)> {
        // Collect all undelivered entries, then sort by global sequence ascending
        // so the session replays the outbox in the original send order.
        let mut out: Vec<([u8; 32], u64, Vec<u8>)> = self
            .inner
            .iter()
            .flat_map(|(object_id, map)| {
                map.iter()
                    .filter(|(_, entry)| !entry.delivered)
                    .map(move |(seq, entry)| (*object_id, *seq, entry.blob.clone()))
            })
            .collect();
        out.sort_by_key(|(_, seq, _)| *seq);
        out
    }

    fn entries_from(&self, object_id: &[u8; 32], sequence: u64) -> Vec<(u64, Vec<u8>)> {
        match self.inner.get(object_id) {
            None => vec![],
            Some(map) => map
                .range(sequence..)
                .map(|(seq, entry)| (*seq, entry.blob.clone()))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// Tracer bullet: append one entry and retrieve it.
    #[test]
    fn append_and_retrieve_single_entry() {
        let mut log = MemLog::new();
        log.append(&oid(1), 0, b"hello".to_vec());
        let entries = log.entries_from(&oid(1), 0);
        assert_eq!(entries, vec![(0, b"hello".to_vec())]);
    }

    /// entries_from(seq) returns only entries with sequence >= seq.
    #[test]
    fn entries_from_filters_by_sequence() {
        let mut log = MemLog::new();
        log.append(&oid(1), 0, b"first".to_vec());
        log.append(&oid(1), 1, b"second".to_vec());
        log.append(&oid(1), 2, b"third".to_vec());

        let entries = log.entries_from(&oid(1), 1);
        assert_eq!(
            entries,
            vec![(1, b"second".to_vec()), (2, b"third".to_vec())]
        );
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

        assert_eq!(log.entries_from(&oid(1), 0), vec![(0, b"obj1".to_vec())]);
        assert_eq!(log.entries_from(&oid(2), 0), vec![(0, b"obj2".to_vec())]);
    }

    /// Second append with the same (object_id, sequence) is silently ignored
    /// (first-write wins — conflict resolution is the caller's concern).
    #[test]
    fn duplicate_sequence_is_ignored() {
        let mut log = MemLog::new();
        log.append(&oid(1), 5, b"original".to_vec());
        log.append(&oid(1), 5, b"overwrite attempt".to_vec());

        let entries = log.entries_from(&oid(1), 5);
        assert_eq!(entries, vec![(5, b"original".to_vec())]);
    }

    /// entries_from returns entries in ascending sequence order.
    #[test]
    fn entries_are_ordered_by_sequence() {
        let mut log = MemLog::new();
        log.append(&oid(1), 3, b"c".to_vec());
        log.append(&oid(1), 1, b"a".to_vec());
        log.append(&oid(1), 2, b"b".to_vec());

        let entries = log.entries_from(&oid(1), 0);
        let seqs: Vec<u64> = entries.iter().map(|(s, _)| *s).collect();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    /// Freshly appended entries are undelivered.
    #[test]
    fn appended_entries_start_as_undelivered() {
        let mut log = MemLog::new();
        log.append(&oid(1), 0, b"hello".to_vec());

        let undelivered = log.undelivered_entries();
        assert_eq!(undelivered.len(), 1);
        assert_eq!(undelivered[0], (oid(1), 0, b"hello".to_vec()));
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
        assert_eq!(entries, vec![(0, b"hello".to_vec())]);
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
        let keys: Vec<([u8; 32], u64)> = undelivered.iter().map(|(o, s, _)| (*o, *s)).collect();
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
        let seqs: Vec<u64> = undelivered.iter().map(|(_, s, _)| *s).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3], "must be sorted by global sequence");
    }

    /// mark_delivered on unknown (object_id, sequence) is a no-op.
    #[test]
    fn mark_delivered_unknown_entry_is_noop() {
        let mut log = MemLog::new();
        log.mark_delivered(&oid(99), 42);
        assert!(log.undelivered_entries().is_empty());
    }
}
