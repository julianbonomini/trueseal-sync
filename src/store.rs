use std::path::Path;
use thiserror::Error;

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
                 seq     INTEGER PRIMARY KEY AUTOINCREMENT,
                 payload BLOB NOT NULL
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

    // --- outbox ---

    /// Append a payload to the outbox. Returns the assigned sequence number.
    pub fn push_outbox(&self, payload: &[u8]) -> Result<i64, StoreError> {
        self.conn.execute(
            "INSERT INTO outbox (payload) VALUES (?1)",
            rusqlite::params![payload],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Return all outbox entries in insertion order as `(seq, payload)` pairs.
    pub fn drain_outbox(&self) -> Result<Vec<(i64, Vec<u8>)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq, payload FROM outbox ORDER BY seq ASC")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Remove a single outbox entry by sequence number (after successful delivery).
    pub fn remove_outbox_entry(&self, seq: i64) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM outbox WHERE seq = ?1", rusqlite::params![seq])?;
        Ok(())
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
        s.push_outbox(b"msg1").expect("push");

        s.wipe().expect("wipe");

        assert!(s.load_identity().expect("load id").is_none());
        assert!(s.load_manifest().expect("load manifest").is_none());
        assert!(s.drain_outbox().expect("drain").is_empty());
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
        s.push_outbox(b"first").expect("push 1");
        s.push_outbox(b"second").expect("push 2");
        s.push_outbox(b"third").expect("push 3");
        let entries = s.drain_outbox().expect("drain");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].1, b"first");
        assert_eq!(entries[1].1, b"second");
        assert_eq!(entries[2].1, b"third");
    }

    /// Removing an outbox entry by seq leaves the rest intact.
    #[test]
    fn remove_outbox_entry_leaves_others() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let seq1 = s.push_outbox(b"keep").expect("push");
        let seq2 = s.push_outbox(b"remove").expect("push");
        s.remove_outbox_entry(seq2).expect("remove");
        let entries = s.drain_outbox().expect("drain");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, seq1);
        assert_eq!(entries[0].1, b"keep");
    }

    /// drain_outbox on an empty store returns an empty vec.
    #[test]
    fn drain_empty_outbox_returns_empty() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        assert!(s.drain_outbox().expect("drain").is_empty());
    }
}
