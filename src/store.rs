use log::warn;
use std::path::Path;
use thiserror::Error;

use crate::device::DeviceKeypair;
use crate::manifest::GroupManifest;
use crate::operation_log::{
    now_secs, LogEntry, MembershipCommit, OperationLog, OutboxKind, DEDUP_RETENTION_SECS,
};

/// Outbox `kind` column values. `Sync` is 0 so rows written by builds from
/// before the column existed (all application `Sync` bodies) migrate to the
/// right kind via the column default.
const KIND_SYNC: i64 = 0;
const KIND_CONTROL: i64 = 1;

fn kind_to_db(kind: OutboxKind) -> i64 {
    match kind {
        OutboxKind::Sync => KIND_SYNC,
        OutboxKind::Control => KIND_CONTROL,
    }
}

fn kind_from_db(v: i64) -> OutboxKind {
    match v {
        KIND_CONTROL => OutboxKind::Control,
        _ => OutboxKind::Sync,
    }
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Persistent local state for a single trueseal-sync session.
///
/// All group state — identity keypair, current GroupManifest, and outbox
/// entries — lives in a single SQLite database at `{base_dir}/trueseal_{namespace}.db`.
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
        let path = base_dir.join(format!("trueseal_{}.db", namespace));
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
                 kind       INTEGER NOT NULL DEFAULT 0,
                 created_at INTEGER NOT NULL DEFAULT 0,
                 UNIQUE(object_id, sequence) ON CONFLICT IGNORE
             );
             -- Handled Message IDs kept for the dedup retention window
             -- (ADR-0026). The library drops re-deliveries itself.
             CREATE TABLE IF NOT EXISTS handled_messages (
                 message_id TEXT PRIMARY KEY,
                 handled_at INTEGER NOT NULL
             );
             -- Singleton metadata. `seq_high_water`: the highest sequence
             -- ever consumed — survives deletion of delivered outbox rows,
             -- so a restart never re-uses a sequence number (ADR-0026).
             CREATE TABLE IF NOT EXISTS meta (
                 key   TEXT PRIMARY KEY,
                 value INTEGER NOT NULL
             );
             -- The Pending Join (ADR-0023): the joiner's durable record that
             -- it asked to join via a specific Pairing Token. Singleton row;
             -- the opaque record encodes initiator keys and the Pairing
             -- Secret. Survives restarts; cleared on admission, cancelJoin
             -- and wipe.
             CREATE TABLE IF NOT EXISTS pending_join (
                 id      INTEGER PRIMARY KEY CHECK (id = 1),
                 data    BLOB NOT NULL
             );
             -- The Pending Membership Change set (ADR-0027): singleton
             -- blob, session-owned encoding. Replaced wholesale on every
             -- membership commit; survives restarts so an offline issuer
             -- re-applies after reconnecting.
             CREATE TABLE IF NOT EXISTS pending_changes (
                 id      INTEGER PRIMARY KEY CHECK (id = 1),
                 data    BLOB NOT NULL
             );
             -- Held-manifest history (ADR-0027): every manifest this
             -- device installed, with whether it included the device. The
             -- deliberate-removal test: an excluding manifest counts only
             -- when its parent is a held manifest that included the device.
             CREATE TABLE IF NOT EXISTS held_manifests (
                 hash          BLOB PRIMARY KEY,
                 included_self INTEGER NOT NULL
             );
             -- The Leaving record (ADR-0027): the outbox refs the Leave
             -- waits on before the wipe. Survives restarts — a crash in
             -- Leaving resumes Leaving.
             CREATE TABLE IF NOT EXISTS leaving (
                 id      INTEGER PRIMARY KEY CHECK (id = 1),
                 data    BLOB NOT NULL
             );
             COMMIT;",
        )?;

        // Dev-preview schema drift, handled without migration machinery
        // (Store Versions and chained migrations are SYNC-13 scope): stores
        // written by builds from before SYNC-5 have an outbox table without
        // `kind`/`created_at`. Add the columns; rows they contain are all
        // application `Sync` bodies, and their real queue time is unknown,
        // so they get a fresh 30-day lease stamped at this open rather than
        // an instant expiry.
        let has_kind: bool = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('outbox') WHERE name = 'kind'",
            [],
            |row| row.get::<_, i64>(0),
        )? != 0;
        if !has_kind {
            conn.execute_batch(
                "ALTER TABLE outbox ADD COLUMN kind INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE outbox ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;",
            )?;
            conn.execute(
                "UPDATE outbox SET created_at = ?1 WHERE created_at = 0",
                rusqlite::params![now_secs() as i64],
            )?;
        }

        Ok(Self { conn })
    }

    /// Wipe all data from all tables.
    ///
    /// Leaves the schema intact. Used by destroyGroup() and tests.
    /// Clears the dedup table and sequence high-water mark too: after a
    /// Destroy Group every device starts over with a fresh identity, so no
    /// Message ID or sequence from the old group may carry over.
    pub fn wipe(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "BEGIN;
             DELETE FROM identity;
             DELETE FROM manifest;
             DELETE FROM outbox;
             DELETE FROM handled_messages;
             DELETE FROM meta;
             DELETE FROM pending_join;
             DELETE FROM pending_changes;
             DELETE FROM held_manifests;
             DELETE FROM leaving;
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
        let noise_priv: [u8; 32] = kp.noise.private();
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
                        format!("manifest decode: {e}"),
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
    fn append_entry(&mut self, entry: LogEntry) {
        // UNIQUE(object_id, sequence) ON CONFLICT IGNORE — duplicate is a no-op.
        if let Err(e) = self.store.conn.execute(
            "INSERT INTO outbox (object_id, sequence, blob, delivered, kind, created_at)
             VALUES (?1, ?2, ?3, 0, ?4, ?5)",
            rusqlite::params![
                entry.object_id.as_slice(),
                entry.sequence as i64,
                entry.blob.as_slice(),
                kind_to_db(entry.kind),
                entry.created_at as i64,
            ],
        ) {
            warn!(
                "[trueseal-sync] outbox append failed (seq={}): {e}",
                entry.sequence
            );
        }
    }

    fn mark_delivered(&mut self, object_id: &[u8; 32], sequence: u64) {
        if let Err(e) = self.store.conn.execute(
            "UPDATE outbox SET delivered = 1
             WHERE object_id = ?1 AND sequence = ?2",
            rusqlite::params![object_id.as_slice(), sequence as i64],
        ) {
            warn!("[trueseal-sync] outbox mark_delivered failed (seq={sequence}): {e}");
        }
    }

    fn remove(&mut self, object_id: &[u8; 32], sequence: u64) {
        if let Err(e) = self.store.conn.execute(
            "DELETE FROM outbox WHERE object_id = ?1 AND sequence = ?2",
            rusqlite::params![object_id.as_slice(), sequence as i64],
        ) {
            warn!("[trueseal-sync] outbox remove failed (seq={sequence}): {e}");
        }
    }

    fn undelivered_entries(&self) -> Vec<LogEntry> {
        let mut stmt = self
            .store
            .conn
            .prepare(
                "SELECT object_id, sequence, blob, kind, created_at FROM outbox
                 WHERE delivered = 0 ORDER BY sequence ASC",
            )
            .expect("prepare undelivered");
        let rows = stmt
            .query_map([], |row| {
                let oid: Vec<u8> = row.get(0)?;
                let seq: i64 = row.get(1)?;
                let blob: Vec<u8> = row.get(2)?;
                let kind: i64 = row.get(3)?;
                let created_at: i64 = row.get(4)?;
                Ok((oid, seq as u64, blob, kind, created_at as u64))
            })
            .expect("query undelivered");
        rows.filter_map(|r| r.ok())
            .filter_map(|(oid, sequence, blob, kind, created_at)| {
                let object_id: [u8; 32] = oid.try_into().ok()?;
                Some(LogEntry {
                    object_id,
                    sequence,
                    kind: kind_from_db(kind),
                    created_at,
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
                "SELECT sequence, blob, kind, created_at FROM outbox
                 WHERE object_id = ?1 AND sequence >= ?2
                 ORDER BY sequence ASC",
            )
            .expect("prepare entries_from");
        let oid_slice: &[u8] = object_id.as_slice();
        let rows = stmt
            .query_map(rusqlite::params![oid_slice, sequence as i64], |row| {
                let seq: i64 = row.get(0)?;
                let blob: Vec<u8> = row.get(1)?;
                let kind: i64 = row.get(2)?;
                let created_at: i64 = row.get(3)?;
                Ok((seq as u64, blob, kind, created_at as u64))
            })
            .expect("query entries_from");
        rows.filter_map(|r| r.ok())
            .map(|(seq, blob, kind, created_at)| LogEntry {
                object_id: *object_id,
                sequence: seq,
                kind: kind_from_db(kind),
                created_at,
                blob,
            })
            .collect()
    }

    fn max_sequence(&self) -> Option<u64> {
        let entries_max: Option<u64> = self
            .store
            .conn
            .query_row("SELECT MAX(sequence) FROM outbox", [], |row| {
                let v: Option<i64> = row.get(0)?;
                Ok(v)
            })
            .ok()
            .flatten()
            .map(|v| v as u64);
        let high_water: Option<u64> = self
            .store
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'seq_high_water'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .ok()
            .map(|v| v as u64);
        entries_max.into_iter().chain(high_water).max()
    }

    fn record_sequence(&mut self, sequence: u64) {
        // Monotonic: the high-water mark never regresses.
        if let Err(e) = self.store.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('seq_high_water', ?1)
             ON CONFLICT(key) DO UPDATE SET value = MAX(value, excluded.value)",
            rusqlite::params![sequence as i64],
        ) {
            warn!("[trueseal-sync] record_sequence failed (seq={sequence}): {e}");
        }
    }

    fn is_handled(&self, message_id: &str) -> bool {
        self.store
            .conn
            .query_row(
                "SELECT 1 FROM handled_messages WHERE message_id = ?1",
                rusqlite::params![message_id],
                |_| Ok(()),
            )
            .is_ok()
    }

    fn record_handled(&mut self, message_id: &str, now: u64) {
        if let Err(e) = self.store.conn.execute(
            "INSERT INTO handled_messages (message_id, handled_at) VALUES (?1, ?2)
             ON CONFLICT(message_id) DO UPDATE SET handled_at = excluded.handled_at",
            rusqlite::params![message_id, now as i64],
        ) {
            warn!("[trueseal-sync] record_handled failed: {e}");
        }
        let cutoff = now.saturating_sub(DEDUP_RETENTION_SECS);
        if let Err(e) = self.store.conn.execute(
            "DELETE FROM handled_messages WHERE handled_at < ?1",
            rusqlite::params![cutoff as i64],
        ) {
            warn!("[trueseal-sync] dedup prune failed: {e}");
        }
    }

    fn begin_pending_join(
        &mut self,
        pending: &[u8],
        recipient: &[u8; 32],
        sequence: u64,
        encoded_pair: Vec<u8>,
    ) -> Result<(), String> {
        // ADR-0023: the Pending Join record and the queued Pair commit in
        // ONE transaction. A crash leaves either the whole prior state
        // (NotJoined — the caller retries joinGroup) or the whole new state
        // (PendingJoin with its Pair queued). A store failure propagates
        // (B8 review F3): the caller leaves the in-memory state untouched
        // and reports a typed error instead of hanging in PendingJoin.
        let result = (|| -> Result<(), rusqlite::Error> {
            let tx = self.store.conn.transaction()?;
            tx.execute(
                "INSERT INTO pending_join (id, data) VALUES (1, ?1)
                 ON CONFLICT(id) DO UPDATE SET data=excluded.data",
                rusqlite::params![pending],
            )?;
            tx.execute(
                "INSERT INTO outbox (object_id, sequence, blob, delivered, kind, created_at)
                 VALUES (?1, ?2, ?3, 0, ?4, ?5)",
                rusqlite::params![
                    recipient.as_slice(),
                    sequence as i64,
                    encoded_pair,
                    KIND_CONTROL,
                    now_secs() as i64,
                ],
            )?;
            tx.commit()
        })();
        result.map_err(|e| format!("begin_pending_join failed (seq={sequence}): {e}"))
    }

    fn pending_join(&self) -> Option<Vec<u8>> {
        self.store
            .conn
            .query_row("SELECT data FROM pending_join WHERE id = 1", [], |row| {
                row.get(0)
            })
            .ok()
    }

    fn clear_pending_join(&mut self) {
        if let Err(e) = self.store.conn.execute("DELETE FROM pending_join", []) {
            warn!("[trueseal-sync] clear_pending_join failed: {e}");
        }
    }

    fn commit_membership(&mut self, commit: MembershipCommit) -> Result<(), String> {
        // ADR-0027: the manifest, the held record, the Pending Membership
        // Change set, the Leaving record and the outbox entries commit in
        // ONE transaction. A crash leaves either the whole prior state or
        // the whole new state — the delivery of the manifest and the
        // re-check of pending changes are driven by the outbox after it.
        let MembershipCommit {
            manifest,
            held,
            pending_changes,
            leaving,
            outbox,
        } = commit;
        let result = (|| -> Result<(), rusqlite::Error> {
            let tx = self.store.conn.transaction()?;
            tx.execute(
                "INSERT INTO manifest (id, data) VALUES (1, ?1)
                 ON CONFLICT(id) DO UPDATE SET data=excluded.data",
                rusqlite::params![manifest],
            )?;
            tx.execute(
                "INSERT INTO held_manifests (hash, included_self) VALUES (?1, ?2)
                 ON CONFLICT(hash) DO UPDATE SET included_self=excluded.included_self",
                rusqlite::params![held.0.as_slice(), held.1 as i64],
            )?;
            if pending_changes.is_empty() {
                tx.execute("DELETE FROM pending_changes", [])?;
            } else {
                tx.execute(
                    "INSERT INTO pending_changes (id, data) VALUES (1, ?1)
                     ON CONFLICT(id) DO UPDATE SET data=excluded.data",
                    rusqlite::params![pending_changes],
                )?;
            }
            if let Some(record) = leaving {
                tx.execute(
                    "INSERT INTO leaving (id, data) VALUES (1, ?1)
                     ON CONFLICT(id) DO UPDATE SET data=excluded.data",
                    rusqlite::params![record],
                )?;
            }
            for (object_id, sequence, blob) in outbox {
                tx.execute(
                    "INSERT INTO outbox (object_id, sequence, blob, delivered, kind, created_at)
                     VALUES (?1, ?2, ?3, 0, ?4, ?5)",
                    rusqlite::params![
                        object_id.as_slice(),
                        sequence as i64,
                        blob,
                        KIND_CONTROL,
                        now_secs() as i64,
                    ],
                )?;
            }
            tx.commit()
        })();
        result.map_err(|e| format!("commit_membership failed: {e}"))
    }

    fn pending_membership_changes(&self) -> Option<Vec<u8>> {
        self.store
            .conn
            .query_row("SELECT data FROM pending_changes WHERE id = 1", [], |row| {
                row.get(0)
            })
            .ok()
    }

    fn is_held_including_self(&self, hash: &[u8; 32]) -> bool {
        self.store
            .conn
            .query_row(
                "SELECT included_self FROM held_manifests WHERE hash = ?1",
                rusqlite::params![hash.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .map(|v| v != 0)
            .unwrap_or(false)
    }

    fn leaving(&self) -> Option<Vec<u8>> {
        self.store
            .conn
            .query_row("SELECT data FROM leaving WHERE id = 1", [], |row| row.get(0))
            .ok()
    }

    fn wipe_group_state(&mut self) {
        // Everything the log owns; identity and manifest rows are wiped by
        // the caller (the FFI's Store handle) as part of the same removal /
        // completed-Leave flow.
        if let Err(e) = self.store.conn.execute_batch(
            "BEGIN;
             DELETE FROM outbox;
             DELETE FROM handled_messages;
             DELETE FROM meta;
             DELETE FROM pending_join;
             DELETE FROM pending_changes;
             DELETE FROM held_manifests;
             DELETE FROM leaving;
             COMMIT;",
        ) {
            warn!("[trueseal-sync] wipe_group_state failed: {e}");
        }
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
        assert!(dir.path().join("trueseal_alpha.db").exists());
    }

    /// Different namespaces produce separate database files.
    #[test]
    fn different_namespaces_are_isolated() {
        let dir = tmp_dir();
        let _sa = Store::open(dir.path(), "alpha").expect("alpha");
        let _sb = Store::open(dir.path(), "beta").expect("beta");
        assert!(dir.path().join("trueseal_alpha.db").exists());
        assert!(dir.path().join("trueseal_beta.db").exists());
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

    /// wipe() also clears the ADR-0027 tables (changes, held history,
    /// Leaving) — after a Destroy Group nothing from the old group survives.
    #[test]
    fn wipe_clears_membership_tables() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.commit_membership(MembershipCommit {
            manifest: b"m".to_vec(),
            held: ([1u8; 32], true),
            pending_changes: b"changes".to_vec(),
            leaving: Some(b"refs".to_vec()),
            outbox: vec![],
        })
        .expect("commit");
        drop(log);
        let s2 = Store::open(dir.path(), "ns").expect("open2");
        s2.wipe().expect("wipe");
        let s3 = Store::open(dir.path(), "ns").expect("open3");
        let log3 = PersistentLog::new(s3);
        assert!(log3.pending_membership_changes().is_none());
        assert!(!log3.is_held_including_self(&[1u8; 32]));
        assert!(log3.leaving().is_none());
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

    /// The sequence high-water mark survives deletion of delivered rows and
    /// a store reopen — a restarted device must never re-use a sequence
    /// number (ADR-0026): the recipient's dedup table would drop the new
    /// message as a duplicate of the old one.
    #[test]
    fn persistent_log_high_water_survives_deletion_and_reopen() {
        let dir = tmp_dir();
        {
            let s = Store::open(dir.path(), "ns").expect("open");
            let mut log = PersistentLog::new(s);
            log.append(&oid(1), 0, b"a".to_vec());
            log.record_sequence(0);
            log.remove(&oid(1), 0); // delivered rows are deleted
            assert_eq!(log.max_sequence(), Some(0));
        }
        let s2 = Store::open(dir.path(), "ns").expect("reopen");
        let log2 = PersistentLog::new(s2);
        assert_eq!(log2.max_sequence(), Some(0), "high-water mark persists");
        assert!(log2.undelivered_entries().is_empty());
    }

    /// Kind and created_at round-trip through SQLite; a Sync entry staged
    /// with an old timestamp comes back old (the 30-day expiry input).
    #[test]
    fn persistent_log_kind_and_created_at_round_trip() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.append_control(&oid(1), 0, b"\x04manifest".to_vec());
        log.append_entry(LogEntry {
            object_id: oid(1),
            sequence: 1,
            kind: OutboxKind::Sync,
            created_at: 1_000_000,
            blob: b"old".to_vec(),
        });
        let entries = log.undelivered_entries();
        assert_eq!(entries[0].kind, OutboxKind::Control);
        assert!(entries[0].created_at > 1_000_000);
        assert_eq!(entries[1].kind, OutboxKind::Sync);
        assert_eq!(entries[1].created_at, 1_000_000);
    }

    /// Handled Message IDs persist across a reopen and prune past the
    /// 60-day retention window (ADR-0026).
    #[test]
    fn handled_messages_persist_and_prune() {
        let dir = tmp_dir();
        {
            let s = Store::open(dir.path(), "ns").expect("open");
            let mut log = PersistentLog::new(s);
            log.record_handled("tsm1_a", 1_000_000);
            assert!(log.is_handled("tsm1_a"));
            assert!(!log.is_handled("tsm1_b"));
        }
        let s2 = Store::open(dir.path(), "ns").expect("reopen");
        let mut log2 = PersistentLog::new(s2);
        assert!(log2.is_handled("tsm1_a"), "dedup records survive restart");
        // Recording past the retention window prunes the old record.
        log2.record_handled("tsm1_b", 1_000_000 + DEDUP_RETENTION_SECS + 1);
        assert!(log2.is_handled("tsm1_b"));
        assert!(!log2.is_handled("tsm1_a"));
    }

    /// A store written before SYNC-5 (outbox without kind/created_at, no
    /// handled_messages/meta tables) opens cleanly: the columns are added,
    /// legacy rows become Sync entries with a fresh lease, and the dedup and
    /// meta tables exist. Store Versions and chained migrations are SYNC-13
    /// scope; this is the dev-preview drift bridge.
    #[test]
    fn legacy_outbox_schema_is_upgraded_on_open() {
        let dir = tmp_dir();
        let path = dir.path().join("trueseal_ns.db");
        {
            let conn = rusqlite::Connection::open(&path).expect("create legacy db");
            conn.execute_batch(
                "CREATE TABLE outbox (
                     object_id  BLOB    NOT NULL,
                     sequence   INTEGER NOT NULL,
                     blob       BLOB    NOT NULL,
                     delivered  INTEGER NOT NULL DEFAULT 0,
                     UNIQUE(object_id, sequence) ON CONFLICT IGNORE
                 );
                 INSERT INTO outbox (object_id, sequence, blob, delivered)
                 VALUES (X'0101010101010101010101010101010101010101010101010101010101010101', 0, X'AABB', 0);",
            )
            .expect("legacy schema");
        }
        let before = now_secs();
        let s = Store::open(dir.path(), "ns").expect("open upgrades schema");
        let log = PersistentLog::new(s);
        let entries = log.undelivered_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, OutboxKind::Sync, "legacy rows are Sync");
        assert_eq!(entries[0].blob, vec![0xAA, 0xBB]);
        assert!(
            entries[0].created_at >= before,
            "legacy rows get a fresh lease, not an instant expiry"
        );
        // Dedup and meta tables exist and work.
        let mut log = log;
        log.record_handled("tsm1_x", now_secs());
        assert!(log.is_handled("tsm1_x"));
        log.record_sequence(5);
        assert_eq!(log.max_sequence(), Some(5));
    }

    /// ADR-0023 crash point: after begin_pending_join commits, a restart
    /// sees the Pending Join AND its queued Pair — the joiner stays
    /// PendingJoin and the outbox retries the Pair (Pair is not re-sent on
    /// restart; retries follow the outbox).
    #[test]
    fn pending_join_and_pair_commit_together_and_survive_reopen() {
        let dir = tmp_dir();
        {
            let s = Store::open(dir.path(), "ns").expect("open");
            let mut log = PersistentLog::new(s);
            assert!(log.pending_join().is_none(), "fresh store: no pending join");
            log.begin_pending_join(b"pending-record", &oid(7), 3, b"\x01pair".to_vec())
                .unwrap();
        }
        let s2 = Store::open(dir.path(), "ns").expect("reopen");
        let log2 = PersistentLog::new(s2);
        assert_eq!(
            log2.pending_join().as_deref(),
            Some(b"pending-record".as_slice())
        );
        let undelivered = log2.undelivered_entries();
        assert_eq!(undelivered.len(), 1);
        assert_eq!(undelivered[0].kind, OutboxKind::Control);
        assert_eq!(undelivered[0].sequence, 3);
        assert_eq!(undelivered[0].object_id, oid(7));
        assert_eq!(undelivered[0].blob, b"\x01pair");
    }

    /// A second joinGroup replaces the Pending Join (ADR-0023) and queues
    /// the new Pair alongside any still-undelivered old one.
    #[test]
    fn second_begin_replaces_pending_join() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.begin_pending_join(b"old-anchor", &oid(7), 3, b"pair-old".to_vec())
            .unwrap();
        log.begin_pending_join(b"new-anchor", &oid(8), 4, b"pair-new".to_vec())
            .unwrap();
        assert_eq!(
            log.pending_join().as_deref(),
            Some(b"new-anchor".as_slice())
        );
        let undelivered = log.undelivered_entries();
        assert_eq!(
            undelivered.len(),
            2,
            "both Pairs remain queued in sequence order"
        );
        assert_eq!(undelivered[0].blob, b"pair-old");
        assert_eq!(undelivered[1].blob, b"pair-new");
    }

    /// cancelJoin clears the record; a restart then shows NotJoined.
    #[test]
    fn clear_pending_join_survives_reopen() {
        let dir = tmp_dir();
        {
            let s = Store::open(dir.path(), "ns").expect("open");
            let mut log = PersistentLog::new(s);
            log.begin_pending_join(b"pending", &oid(7), 3, b"pair".to_vec())
                .unwrap();
            log.clear_pending_join();
        }
        let s2 = Store::open(dir.path(), "ns").expect("reopen");
        let log2 = PersistentLog::new(s2);
        assert!(log2.pending_join().is_none());
        // The queued Pair is NOT removed by cancelJoin — the outbox owns it.
        assert_eq!(log2.undelivered_entries().len(), 1);
    }

    /// wipe() clears the Pending Join — after Destroy Group the device
    /// starts over, so no anchor from the destroyed group may survive.
    #[test]
    fn wipe_clears_pending_join() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.begin_pending_join(b"pending", &oid(7), 3, b"pair".to_vec())
            .unwrap();
        assert!(log.pending_join().is_some());
        drop(log);
        let s2 = Store::open(dir.path(), "ns").expect("open2");
        s2.wipe().expect("wipe");
        let s3 = Store::open(dir.path(), "ns").expect("open3");
        let log3 = PersistentLog::new(s3);
        assert!(log3.pending_join().is_none());
    }

    /// wipe() clears the dedup table and high-water mark too — after Destroy
    /// Group the device starts over with a fresh identity (ADR-0029).
    #[test]
    fn wipe_clears_dedup_and_high_water() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.record_handled("tsm1_a", now_secs());
        log.record_sequence(9);
        drop(log);
        let s2 = Store::open(dir.path(), "ns").expect("open2");
        s2.wipe().expect("wipe");
        let s3 = Store::open(dir.path(), "ns").expect("open3");
        let log3 = PersistentLog::new(s3);
        assert!(!log3.is_handled("tsm1_a"));
        assert_eq!(log3.max_sequence(), None);
    }

    /// ADR-0027: a membership commit lands the manifest, the held record,
    /// the Pending Membership Change set, the Leaving record and the outbox
    /// entries as one unit — all visible after a reopen.
    #[test]
    fn commit_membership_commits_everything_and_survives_reopen() {
        let dir = tmp_dir();
        {
            let s = Store::open(dir.path(), "ns").expect("open");
            let mut log = PersistentLog::new(s);
            log.commit_membership(MembershipCommit {
                manifest: b"manifest-v2".to_vec(),
                held: ([7u8; 32], true),
                pending_changes: b"change-set".to_vec(),
                leaving: Some(b"leave-refs".to_vec()),
                outbox: vec![(oid(9), 3, b"\x04m".to_vec())],
            })
            .expect("commit");
        }
        let s2 = Store::open(dir.path(), "ns").expect("reopen");
        let log2 = PersistentLog::new(s2);
        assert_eq!(
            log2.pending_membership_changes().as_deref(),
            Some(b"change-set".as_slice())
        );
        assert!(log2.is_held_including_self(&[7u8; 32]));
        assert!(!log2.is_held_including_self(&[8u8; 32]));
        assert_eq!(log2.leaving().as_deref(), Some(b"leave-refs".as_slice()));
        let undelivered = log2.undelivered_entries();
        assert_eq!(undelivered.len(), 1);
        assert_eq!(undelivered[0].kind, OutboxKind::Control);
        // The manifest row landed too (same DB the FFI reads).
        let s3 = Store::open(dir.path(), "ns").expect("open3");
        assert_eq!(
            s3.load_manifest().expect("load").as_deref(),
            Some(b"manifest-v2".as_slice())
        );
    }

    /// An empty change set clears the row; a commit without a Leaving
    /// record leaves the existing record untouched.
    #[test]
    fn commit_membership_empty_changes_clear_and_leaving_is_sticky() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.commit_membership(MembershipCommit {
            manifest: b"m1".to_vec(),
            held: ([1u8; 32], true),
            pending_changes: b"changes".to_vec(),
            leaving: Some(b"refs".to_vec()),
            outbox: vec![],
        })
        .expect("commit 1");
        log.commit_membership(MembershipCommit {
            manifest: b"m2".to_vec(),
            held: ([2u8; 32], false),
            pending_changes: Vec::new(),
            leaving: None,
            outbox: vec![],
        })
        .expect("commit 2");
        assert!(log.pending_membership_changes().is_none());
        assert_eq!(
            log.leaving().as_deref(),
            Some(b"refs".as_slice()),
            "leaving untouched by a commit that does not mention it"
        );
        // A held record that excluded self is not "held including self".
        assert!(!log.is_held_including_self(&[2u8; 32]));
    }

    /// wipe_group_state clears everything the log owns — outbox, dedup,
    /// high-water, Pending Join, changes, held history, Leaving — so a
    /// removed or departed device starts over clean (ADR-0027).
    #[test]
    fn wipe_group_state_clears_all_log_owned_state() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.begin_pending_join(b"pending", &oid(7), 3, b"pair".to_vec())
            .unwrap();
        log.record_handled("tsm1_a", now_secs());
        log.commit_membership(MembershipCommit {
            manifest: b"m".to_vec(),
            held: ([1u8; 32], true),
            pending_changes: b"changes".to_vec(),
            leaving: Some(b"refs".to_vec()),
            outbox: vec![(oid(2), 4, b"ctrl".to_vec())],
        })
        .expect("commit");
        log.wipe_group_state();
        assert!(log.undelivered_entries().is_empty());
        assert!(!log.is_handled("tsm1_a"));
        assert_eq!(log.max_sequence(), None);
        assert!(log.pending_join().is_none());
        assert!(log.pending_membership_changes().is_none());
        assert!(!log.is_held_including_self(&[1u8; 32]));
        assert!(log.leaving().is_none());
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
