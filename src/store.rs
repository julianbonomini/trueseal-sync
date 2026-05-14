use std::path::Path;
use log::warn;
use thiserror::Error;

use crate::device::DeviceKeypair;
use crate::manifest::GroupManifest;
use crate::operation_log::{LogEntry, OperationLog};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Persistent local state for a single hush-sync session.
///
/// All group state — identity keypair, current GroupManifest, and outbox
/// entries — lives in a single SQLite database at `{base_dir}/hush_{namespace}.db`.
/// The caller never touches storage; the Store owns it entirely.
pub struct Store {
    conn: rusqlite::Connection,
}

impl Store {
    /// Open (or create) the database for `namespace` under `base_dir`.
    ///
    /// Idempotent: calling twice with the same args returns equivalent stores.
    /// Runs all schema migrations in a single transaction on first open.
    pub fn open(base_dir: &Path, namespace: &str) -> Result<Self, StoreError> {
        let path = base_dir.join(format!("hush_{}.db", namespace));
        let conn = rusqlite::Connection::open(path)?;

        // WAL mode for better concurrent read performance
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        // Schema — all in one transaction
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE IF NOT EXISTS identity (
                 id      INTEGER PRIMARY KEY CHECK (id = 1),
                 noise_secret  BLOB NOT NULL,
                 signing_secret BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS manifest (
                 id      INTEGER PRIMARY KEY CHECK (id = 1),
                 data    BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS outbox (
                 object_id  BLOB    NOT NULL,
                 sequence   INTEGER NOT NULL,
                 blob       BLOB    NOT NULL,
                 delivered  INTEGER NOT NULL DEFAULT 0,
                 UNIQUE(object_id, sequence) ON CONFLICT IGNORE
             );
             COMMIT;",
        )?;

        Ok(Self { conn })
    }

    /// Wipe all data from all tables.
    ///
    /// Leaves the schema intact. Used by destroyGroup() and tests.
    pub fn wipe(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "BEGIN;
             DELETE FROM identity;
             DELETE FROM manifest;
             DELETE FROM outbox;
             COMMIT;",
        )?;
        Ok(())
    }

    // --- identity ---

    /// Persist the identity keypair. Overwrites any existing entry (singleton row).
    pub fn save_identity(
        &self,
        noise_secret: &[u8; 32],
        signing_secret: &[u8; 32],
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO identity (id, noise_secret, signing_secret) VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET noise_secret=excluded.noise_secret,
                                           signing_secret=excluded.signing_secret",
            rusqlite::params![noise_secret.as_slice(), signing_secret.as_slice()],
        )?;
        Ok(())
    }

    /// Load the identity keypair. Returns `None` if no identity has been saved yet.
    pub fn load_identity(&self) -> Result<Option<([u8; 32], [u8; 32])>, StoreError> {
        let result = self.conn.query_row(
            "SELECT noise_secret, signing_secret FROM identity WHERE id = 1",
            [],
            |row| {
                let noise: Vec<u8> = row.get(0)?;
                let signing: Vec<u8> = row.get(1)?;
                Ok((noise, signing))
            },
        );
        match result {
            Ok((noise, signing)) => {
                let noise: [u8; 32] = noise.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        0,
                        "noise_secret".into(),
                        rusqlite::types::Type::Blob,
                    )
                })?;
                let signing: [u8; 32] = signing.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        1,
                        "signing_secret".into(),
                        rusqlite::types::Type::Blob,
                    )
                })?;
                Ok(Some((noise, signing)))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // --- keypair (typed) ---

    /// Persist a `DeviceKeypair`. Overwrites any existing entry (singleton row).
    pub fn save_keypair(&self, kp: &DeviceKeypair) -> Result<(), StoreError> {
        let noise_priv: [u8; 32] = kp.noise.private()
            .try_into()
            .expect("invariant: noise private key is always 32 bytes");
        let signing_priv: [u8; 32] = kp.signing.to_bytes();
        self.save_identity(&noise_priv, &signing_priv)
    }

    /// Load the `DeviceKeypair`. Returns `None` if no identity has been saved yet.
    pub fn load_keypair(&self) -> Result<Option<DeviceKeypair>, StoreError> {
        match self.load_identity()? {
            None => Ok(None),
            Some((noise_priv, signing_priv)) => {
                let kp = DeviceKeypair::from_bytes(noise_priv, signing_priv).map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        0,
                        "identity".into(),
                        rusqlite::types::Type::Blob,
                    )
                })?;
                Ok(Some(kp))
            }
        }
    }

    // --- manifest ---

    /// Persist a serialised GroupManifest blob. Overwrites any existing entry.
    pub fn save_manifest(&self, data: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO manifest (id, data) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET data=excluded.data",
            rusqlite::params![data],
        )?;
        Ok(())
    }

    /// Load the raw GroupManifest blob. Returns `None` if none has been saved yet.
    pub fn load_manifest(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let result = self
            .conn
            .query_row("SELECT data FROM manifest WHERE id = 1", [], |row| {
                row.get(0)
            });
        match result {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // --- manifest (typed) ---

    /// Persist a `GroupManifest`. Overwrites any existing entry.
    pub fn save_group_manifest(&self, manifest: &GroupManifest) -> Result<(), StoreError> {
        let data = manifest.encode();
        self.save_manifest(&data)
    }

    /// Load the `GroupManifest`. Returns `None` if none has been saved yet.
    pub fn load_group_manifest(&self) -> Result<Option<GroupManifest>, StoreError> {
        match self.load_manifest()? {
            None => Ok(None),
            Some(data) => {
                let m = GroupManifest::decode(&data).map_err(|e| {
                    rusqlite::Error::InvalidColumnType(
                        0,
                        format!("manifest decode: {e}").into(),
                        rusqlite::types::Type::Blob,
                    )
                })?;
                Ok(Some(m))
            }
        }
    }
}

// ── PersistentLog ─────────────────────────────────────────────────────────────

/// SQLite-backed `OperationLog`. Wraps a `Store` and persists all outbox
/// entries across process restarts.
pub struct PersistentLog {
    store: Store,
}

impl PersistentLog {
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

impl OperationLog for PersistentLog {
    fn append(&mut self, object_id: &[u8; 32], sequence: u64, blob: Vec<u8>) {
        // UNIQUE(object_id, sequence) ON CONFLICT IGNORE — duplicate is a no-op.
        if let Err(e) = self.store.conn.execute(
            "INSERT INTO outbox (object_id, sequence, blob, delivered)
             VALUES (?1, ?2, ?3, 0)",
            rusqlite::params![object_id.as_slice(), sequence as i64, blob.as_slice()],
        ) {
            warn!("[hush-sync] outbox append failed (seq={sequence}): {e}");
        }
    }

    fn mark_delivered(&mut self, object_id: &[u8; 32], sequence: u64) {
        if let Err(e) = self.store.conn.execute(
            "UPDATE outbox SET delivered = 1
             WHERE object_id = ?1 AND sequence = ?2",
            rusqlite::params![object_id.as_slice(), sequence as i64],
        ) {
            warn!("[hush-sync] outbox mark_delivered failed (seq={sequence}): {e}");
        }
    }

    fn undelivered_entries(&self) -> Vec<LogEntry> {
        let mut stmt = self
            .store
            .conn
            .prepare(
                "SELECT object_id, sequence, blob FROM outbox
                 WHERE delivered = 0 ORDER BY sequence ASC",
            )
            .expect("prepare undelivered");
        let rows = stmt
            .query_map([], |row| {
                let oid: Vec<u8> = row.get(0)?;
                let seq: i64 = row.get(1)?;
                let blob: Vec<u8> = row.get(2)?;
                Ok((oid, seq as u64, blob))
            })
            .expect("query undelivered");
        rows.filter_map(|r| r.ok())
            .filter_map(|(oid, sequence, blob)| {
                let object_id: [u8; 32] = oid.try_into().ok()?;
                Some(LogEntry {
                    object_id,
                    sequence,
                    blob,
                })
            })
            .collect()
    }

    fn entries_from(&self, object_id: &[u8; 32], sequence: u64) -> Vec<LogEntry> {
        let mut stmt = self
            .store
            .conn
            .prepare(
                "SELECT sequence, blob FROM outbox
                 WHERE object_id = ?1 AND sequence >= ?2
                 ORDER BY sequence ASC",
            )
            .expect("prepare entries_from");
        let oid_slice: &[u8] = object_id.as_slice();
        let rows = stmt
            .query_map(rusqlite::params![oid_slice, sequence as i64], |row| {
                let seq: i64 = row.get(0)?;
                let blob: Vec<u8> = row.get(1)?;
                Ok((seq as u64, blob))
            })
            .expect("query entries_from");
        rows.filter_map(|r| r.ok())
            .map(|(seq, blob)| LogEntry {
                object_id: *object_id,
                sequence: seq,
                blob,
            })
            .collect()
    }

    fn max_sequence(&self) -> Option<u64> {
        self.store
            .conn
            .query_row("SELECT MAX(sequence) FROM outbox", [], |row| {
                let v: Option<i64> = row.get(0)?;
                Ok(v)
            })
            .ok()
            .flatten()
            .map(|v| v as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tmp_dir() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("tmp dir")
    }

    /// Opening the store twice with the same namespace is idempotent.
    #[test]
    fn open_twice_is_idempotent() {
        let dir = tmp_dir();
        let _s1 = Store::open(dir.path(), "alpha").expect("first open");
        let _s2 = Store::open(dir.path(), "alpha").expect("second open");
        // Both succeed; the DB file exists once
        assert!(dir.path().join("hush_alpha.db").exists());
    }

    /// Different namespaces produce separate database files.
    #[test]
    fn different_namespaces_are_isolated() {
        let dir = tmp_dir();
        let _sa = Store::open(dir.path(), "alpha").expect("alpha");
        let _sb = Store::open(dir.path(), "beta").expect("beta");
        assert!(dir.path().join("hush_alpha.db").exists());
        assert!(dir.path().join("hush_beta.db").exists());
    }

    /// wipe() removes all data but leaves schema intact.
    #[test]
    fn wipe_clears_all_data() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        s.save_identity(&[1u8; 32], &[2u8; 32]).expect("save id");
        s.save_manifest(b"some manifest bytes")
            .expect("save manifest");
        // Add an outbox entry via PersistentLog
        let s2 = Store::open(dir.path(), "ns").expect("open2");
        let mut log = PersistentLog::new(s2);
        log.append(&[0u8; 32], 0, b"msg1".to_vec());
        drop(log);

        s.wipe().expect("wipe");

        assert!(s.load_identity().expect("load id").is_none());
        assert!(s.load_manifest().expect("load manifest").is_none());
        // Reopen and check outbox is empty
        let s3 = Store::open(dir.path(), "ns").expect("open3");
        let log2 = PersistentLog::new(s3);
        assert!(log2.undelivered_entries().is_empty());
    }

    /// Identity round-trips through save and load.
    #[test]
    fn identity_round_trips() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let noise = [3u8; 32];
        let signing = [7u8; 32];
        s.save_identity(&noise, &signing).expect("save");
        let (n, sg) = s.load_identity().expect("load").expect("should exist");
        assert_eq!(n, noise);
        assert_eq!(sg, signing);
    }

    /// Saving identity twice overwrites the first entry (singleton).
    #[test]
    fn identity_overwrites_on_second_save() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        s.save_identity(&[1u8; 32], &[2u8; 32]).expect("first save");
        s.save_identity(&[9u8; 32], &[8u8; 32])
            .expect("second save");
        let (n, sg) = s.load_identity().expect("load").expect("should exist");
        assert_eq!(n, [9u8; 32]);
        assert_eq!(sg, [8u8; 32]);
    }

    /// Manifest round-trips through save and load.
    #[test]
    fn manifest_round_trips() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let data = b"protobuf bytes here";
        s.save_manifest(data).expect("save");
        let loaded = s.load_manifest().expect("load").expect("should exist");
        assert_eq!(loaded, data);
    }

    /// Outbox entries are returned in insertion order.
    #[test]
    fn outbox_preserves_insertion_order() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.append(&[1u8; 32], 0, b"first".to_vec());
        log.append(&[1u8; 32], 1, b"second".to_vec());
        log.append(&[1u8; 32], 2, b"third".to_vec());
        let entries = log.undelivered_entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].blob, b"first");
        assert_eq!(entries[1].blob, b"second");
        assert_eq!(entries[2].blob, b"third");
    }

    /// Marking an entry delivered removes it from undelivered but keeps it in entries_from.
    #[test]
    fn remove_outbox_entry_leaves_others() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.append(&[1u8; 32], 0, b"keep".to_vec());
        log.append(&[1u8; 32], 1, b"deliver".to_vec());
        log.mark_delivered(&[1u8; 32], 1);
        let undelivered = log.undelivered_entries();
        assert_eq!(undelivered.len(), 1);
        assert_eq!(undelivered[0].blob, b"keep");
        // entries_from still returns both
        let all = log.entries_from(&[1u8; 32], 0);
        assert_eq!(all.len(), 2);
    }

    /// undelivered_entries on an empty store returns an empty vec.
    #[test]
    fn drain_empty_outbox_returns_empty() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let log = PersistentLog::new(s);
        assert!(log.undelivered_entries().is_empty());
    }

    // ── PersistentLog tests ────────────────────────────────────────────────────

    use crate::operation_log::OperationLog;

    fn oid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// Tracer bullet: append one entry and retrieve it via entries_from.
    #[test]
    fn persistent_log_append_and_retrieve() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.append(&oid(1), 0, b"hello".to_vec());
        let entries = log.entries_from(&oid(1), 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sequence, 0);
        assert_eq!(entries[0].blob, b"hello");
        assert_eq!(entries[0].object_id, oid(1));
    }

    /// Duplicate (object_id, sequence) append is silently ignored — first-write wins.
    #[test]
    fn persistent_log_duplicate_sequence_ignored() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.append(&oid(1), 5, b"original".to_vec());
        log.append(&oid(1), 5, b"overwrite attempt".to_vec());
        let entries = log.entries_from(&oid(1), 5);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].blob, b"original");
    }

    /// Freshly appended entries appear in undelivered_entries.
    #[test]
    fn persistent_log_appended_entries_are_undelivered() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.append(&oid(1), 0, b"a".to_vec());
        log.append(&oid(2), 1, b"b".to_vec());
        let undelivered = log.undelivered_entries();
        assert_eq!(undelivered.len(), 2);
    }

    /// undelivered_entries are sorted by global sequence ascending.
    #[test]
    fn persistent_log_undelivered_sorted_by_sequence() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.append(&oid(1), 3, b"c".to_vec());
        log.append(&oid(2), 1, b"a".to_vec());
        log.append(&oid(1), 2, b"b".to_vec());
        let seqs: Vec<u64> = log
            .undelivered_entries()
            .iter()
            .map(|e| e.sequence)
            .collect();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    /// mark_delivered removes an entry from undelivered_entries.
    #[test]
    fn persistent_log_mark_delivered_clears_from_outbox() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.append(&oid(1), 0, b"msg".to_vec());
        log.mark_delivered(&oid(1), 0);
        assert!(log.undelivered_entries().is_empty());
    }

    /// mark_delivered does not remove entry from entries_from.
    #[test]
    fn persistent_log_mark_delivered_does_not_affect_entries_from() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.append(&oid(1), 0, b"msg".to_vec());
        log.mark_delivered(&oid(1), 0);
        let entries = log.entries_from(&oid(1), 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].blob, b"msg");
    }

    /// entries_from filters by sequence >= given value.
    #[test]
    fn persistent_log_entries_from_filters_by_sequence() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.append(&oid(1), 0, b"first".to_vec());
        log.append(&oid(1), 1, b"second".to_vec());
        log.append(&oid(1), 2, b"third".to_vec());
        let entries = log.entries_from(&oid(1), 1);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sequence, 1);
        assert_eq!(entries[1].sequence, 2);
    }

    /// Undelivered entries survive a Store reopen (persistence across restarts).
    #[test]
    fn persistent_log_survives_reopen() {
        let dir = tmp_dir();
        {
            let s = Store::open(dir.path(), "ns").expect("open");
            let mut log = PersistentLog::new(s);
            log.append(&oid(1), 0, b"persisted".to_vec());
            // log + store drop here
        }
        let s2 = Store::open(dir.path(), "ns").expect("reopen");
        let log2 = PersistentLog::new(s2);
        let undelivered = log2.undelivered_entries();
        assert_eq!(undelivered.len(), 1);
        assert_eq!(undelivered[0].blob, b"persisted");
    }

    // ── Keypair (typed) tests ──────────────────────────────────────────────────

    /// Keypair round-trips through typed save/load.
    #[test]
    fn keypair_save_and_load_round_trips() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let kp = crate::device::DeviceKeypair::generate();
        let noise_pub = kp.public_key();
        s.save_keypair(&kp).expect("save");
        let loaded = s.load_keypair().expect("load").expect("should exist");
        assert_eq!(loaded.public_key(), noise_pub, "keypair must round-trip");
    }

    /// No keypair on first open returns None.
    #[test]
    fn keypair_absent_on_fresh_store() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        assert!(s.load_keypair().expect("load").is_none());
    }

    // ── Manifest (typed) tests ─────────────────────────────────────────────────

    /// GroupManifest round-trips through typed save/load.
    #[test]
    fn manifest_typed_save_and_load_round_trips() {
        use crate::keys::{NoisePublicKey, SigningPublicKey};
        use crate::manifest::{new_group_id, GroupManifest, ManifestMember};
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");

        let sk = SigningKey::generate(&mut OsRng);
        let manifest = GroupManifest::new(
            new_group_id(),
            1,
            vec![ManifestMember {
                noise_pub: NoisePublicKey([1u8; 32]),
                signing_pub: SigningPublicKey([2u8; 32]),
                name: "Alice".into(),
            }],
            &sk,
        );
        s.save_group_manifest(&manifest).expect("save");
        let loaded = s
            .load_group_manifest()
            .expect("load")
            .expect("should exist");
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.members.len(), 1);
    }

    /// No manifest on fresh store returns None.
    #[test]
    fn manifest_absent_on_fresh_store() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        assert!(s.load_group_manifest().expect("load").is_none());
    }

    /// max_sequence returns None on an empty log, the highest sequence otherwise.
    /// Used to restore the sequence counter after a process restart (ADR-0011).
    #[test]
    fn persistent_log_max_sequence() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);

        // Empty log → None
        assert_eq!(log.max_sequence(), None);

        log.append(&oid(1), 3, b"a".to_vec());
        log.append(&oid(2), 7, b"b".to_vec());
        log.append(&oid(1), 5, b"c".to_vec());

        // Max across all objects, delivered or not
        assert_eq!(log.max_sequence(), Some(7));

        log.mark_delivered(&oid(2), 7);
        // Still 7 even after marking delivered
        assert_eq!(log.max_sequence(), Some(7));
    }
}
