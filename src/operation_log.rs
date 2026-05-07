use std::collections::BTreeMap;

/// A log of (sequence, blob) entries keyed by object_id.
/// The Relay is unaware of object_ids — they live only inside encrypted payloads.
/// The caller maps Envelope.payload → object_id + blob after decryption.
///
/// # Design notes
/// - `append` is idempotent for the same (object_id, sequence) pair: a second
///   write with the same sequence is silently ignored (last-write semantics
///   are the caller's concern, not the log's).
/// - `entries_from` returns all entries with sequence >= the given value,
///   in ascending sequence order.
/// - v0 uses an in-memory backend (`MemLog`).
///   A `SqliteLog` (persisted) is the obvious next backend.
pub trait OperationLog: Send {
    fn append(&mut self, object_id: &[u8; 32], sequence: u64, blob: Vec<u8>);
    fn entries_from(&self, object_id: &[u8; 32], sequence: u64) -> Vec<(u64, Vec<u8>)>;
}

/// In-memory operation log. Not persisted across restarts.
/// Key: object_id bytes. Value: BTreeMap<sequence, blob>.
pub struct MemLog {
    inner: BTreeMap<[u8; 32], BTreeMap<u64, Vec<u8>>>,
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
            .or_insert(blob);
    }

    fn entries_from(&self, object_id: &[u8; 32], sequence: u64) -> Vec<(u64, Vec<u8>)> {
        match self.inner.get(object_id) {
            None => vec![],
            Some(map) => map
                .range(sequence..)
                .map(|(seq, blob)| (*seq, blob.clone()))
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
}
