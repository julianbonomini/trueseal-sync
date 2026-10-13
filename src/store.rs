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
    /// The store was written by a newer release (a rollback): its Store
    /// Version is above what this build supports. Refused — the store is
    /// not modified, so rolling forward again loses nothing (ADR-0032;
    /// `storeTooNew` in ADR-0028's error list).
    #[error("store was written by a newer release (store version {found}, this build supports up to {supported})")]
    StoreTooNew { found: u32, supported: u32 },
    /// A migration step failed outright. The old store is intact (the
    /// step's transaction rolled back); the error surfaces as `storage`
    /// (ADR-0032).
    #[error("store migration from version {from} failed: {msg}")]
    MigrationFailed { from: u32, msg: String },
    /// The End-to-End Version bump re-seal failed. The transaction rolled
    /// back: every outbox entry is still at the old version (ADR-0034 §1
    /// crash behaviour).
    #[error("outbox re-seal for the End-to-End Version bump failed: {0}")]
    ResealFailed(String),
}

/// What [`Store::open_with_outcome`] did to get the store ready (ADR-0032).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OpenOutcome {
    /// The database was created by this open (no prior tables).
    pub created: bool,
    /// Chained migrations ran from this Store Version.
    pub migrated_from: Option<u32>,
    /// The store was unmigratable — unversioned (a development build) or
    /// below the migration floor — and was reset: every table wiped, fresh
    /// Store Version recorded. The caller reports
    /// `statusChanged(notJoined, storeReset)`; the object stays usable and
    /// can pair again (ADR-0032).
    pub reset: bool,
    /// An End-to-End Version bump re-seal ran from this version
    /// (ADR-0034 §1): every queued entry re-sealed, `Sync` included.
    pub resealed_from_e2e: Option<u32>,
}

/// One migration step: migrates Store Version `from` to `from + 1`. Every
/// step runs in ONE database transaction (ADR-0032 Crash behaviour): a
/// crash leaves the old store intact and the next open retries. Steps stay
/// in the code for the whole preview, so a release that skips versions
/// still migrates through every step.
pub type Migration = fn(&rusqlite::Transaction<'_>) -> Result<(), rusqlite::Error>;

/// The chained migrations, one entry per Store Version step
/// (`(from_version, step)`). Empty: Store Version 1 is the first preview
/// format (ADR-0032). When a step is added it never leaves the code.
const MIGRATIONS: &[(u32, Migration)] = &[];

/// Meta keys for the store's own versioning (ADR-0032). Both survive group
/// wipes — they describe the store format, not group state.
const META_STORE_VERSION: &str = "store_version";
const META_E2E_VERSION: &str = "e2e_version";

/// Deletes every group-state row. The Store Version keys in `meta` are
/// preserved; the sequence high-water mark is not (a wiped group never
/// re-uses a sequence number — and a wiped store starts at none).
const WIPE_DATA_SQL: &str = "
    DELETE FROM identity;
    DELETE FROM manifest;
    DELETE FROM outbox;
    DELETE FROM handled_messages;
    DELETE FROM pending_join;
    DELETE FROM pending_changes;
    DELETE FROM held_manifests;
    DELETE FROM leaving;
    DELETE FROM meta WHERE key NOT IN ('store_version', 'e2e_version');";

/// Drops every table. The Store Reset uses this — a dev-build store can
/// predate columns added later, and a reset should produce exactly the
/// current schema, not a wiped legacy shape.
const DROP_ALL_SQL: &str = "
    DROP TABLE IF EXISTS identity;
    DROP TABLE IF EXISTS manifest;
    DROP TABLE IF EXISTS outbox;
    DROP TABLE IF EXISTS handled_messages;
    DROP TABLE IF EXISTS meta;
    DROP TABLE IF EXISTS pending_join;
    DROP TABLE IF EXISTS pending_changes;
    DROP TABLE IF EXISTS held_manifests;
    DROP TABLE IF EXISTS leaving;";

/// The schema, created if absent. Plain batch: every statement is
/// idempotent (`IF NOT EXISTS`), so a crash anywhere leaves a consistent
/// next open.
fn ensure_schema(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS identity (
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
         -- `store_version` / `e2e_version`: what wrote this store
         -- (ADR-0032); both survive group wipes.
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
         );",
    )
}

fn table_exists(conn: &rusqlite::Connection, name: &str) -> Result<bool, rusqlite::Error> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |row| row.get::<_, i64>(0),
    )? != 0)
}

fn any_table_exists(conn: &rusqlite::Connection) -> Result<bool, rusqlite::Error> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get::<_, i64>(0),
    )? != 0)
}

fn meta_get(conn: &rusqlite::Connection, key: &str) -> Result<Option<i64>, rusqlite::Error> {
    use rusqlite::OptionalExtension;
    if !table_exists(conn, "meta")? {
        return Ok(None);
    }
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
        row.get::<_, i64>(0)
    })
    .optional()
}

fn meta_set(conn: &rusqlite::Connection, key: &str, value: u32) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, value as i64],
    )?;
    Ok(())
}

/// Run the chained migration steps from `from` up to `target`, ONE
/// transaction per step, bumping the recorded Store Version inside the
/// step's own transaction (ADR-0032 Crash behaviour): a crash mid-step
/// rolls the step back — the old store is intact and the next open
/// retries; a crash between steps leaves a valid intermediate store the
/// next open resumes from. A step that fails outright rolls back and
/// raises `storage`.
fn run_migrations(
    conn: &mut rusqlite::Connection,
    from: u32,
    target: u32,
    steps: &[(u32, Migration)],
) -> Result<(), StoreError> {
    let mut v = from;
    while v < target {
        let step = steps
            .iter()
            .find(|(step_from, _)| *step_from == v)
            .map(|(_, step)| *step)
            .ok_or_else(|| StoreError::MigrationFailed {
                from: v,
                msg: format!("no migration path from store version {v} to {target}"),
            })?;
        let fail = |e: rusqlite::Error| StoreError::MigrationFailed {
            from: v,
            msg: e.to_string(),
        };
        let tx = conn.transaction().map_err(fail)?;
        step(&tx).map_err(fail)?;
        meta_set(&tx, META_STORE_VERSION, v + 1).map_err(fail)?;
        tx.commit().map_err(fail)?;
        v += 1;
    }
    Ok(())
}

/// Re-seal every queued outbox entry for an End-to-End Version bump, in one
/// transaction (ADR-0034 §1; ADR-0032's crash table applies: a crash leaves
/// every entry at the old version or every entry at the new one).
///
/// What \"re-seal\" means per entry kind, given this build seals Envelopes at
/// push time from the stored body/message:
///
/// - **`Sync`** entries store the application body; the Envelope is sealed at
///   every push under the current version, stamped at `created_at` — the
///   `send()` time (ADR-0034 §2). The bump needs no row change: the next
///   push seals under the new version and the original Sender Timestamp
///   (and therefore the Message ID and the dedup guarantee) survives.
/// - **Pair** and **Revoke** carry no inner signature; their Envelope is
///   sealed at push. No row change.
/// - **Group Manifest** entries carry the issuer's signature over a domain
///   that includes the End-to-End Version (ADR-0022), so a queued manifest
///   must be RE-SIGNED under the new version or upgraded peers reject it.
///   Re-signing changes the manifest hash, so the old→new remap propagates
///   to later queued manifests' `parent` links, to the stored current
///   manifest (only when it is itself one of the re-signed queued
///   issuances — a delivered manifest's bytes stay, because peers hold
///   them), and to the held-manifest history rows. Ed25519 is
///   deterministic, so the stored copy re-signs to identical bytes.
///
/// Only UNDELIVERED rows are re-signed: a delivered row's hash may already
/// be installed at peers. (A crash between relay-accept and the delivered
/// flag can leave an accepted row flagged undelivered; re-signing it costs
/// a duplicate-hash race the (version, hash) tie-break and the issuer's
/// bounded re-application converge — accepted edge.)
///
/// Pending Membership Change carriers are deliberately NOT remapped: their
/// encoding is session-owned, and a stale carrier costs at worst one
/// redundant re-application (bounded, ADR-0027) in a window peers cannot
/// actually produce — they never saw the pre-bump hash of an undelivered
/// manifest.
fn reseal_outbox_for_e2e_bump(
    conn: &mut rusqlite::Connection,
    to_e2e: u32,
) -> Result<usize, StoreError> {
    let tx = conn.transaction()?;
    let resealed = reseal_outbox_rows(&tx, to_e2e)?;
    meta_set(&tx, META_E2E_VERSION, to_e2e)?;
    tx.commit()?;
    Ok(resealed)
}

fn reseal_outbox_rows(conn: &rusqlite::Connection, to_e2e: u32) -> Result<usize, StoreError> {
    use crate::message::Message;
    use std::collections::HashMap;

    let signing_key: Option<ed25519_dalek::SigningKey> = {
        use rusqlite::OptionalExtension;
        conn.query_row(
            "SELECT signing_secret FROM identity WHERE id = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        .map(|bytes| ed25519_dalek::SigningKey::from_bytes(&bytes))
    };

    // Snapshot the queued control rows in sequence order.
    let mut stmt = conn.prepare(
        "SELECT object_id, sequence, blob FROM outbox
         WHERE delivered = 0 AND kind = ?1 ORDER BY sequence ASC",
    )?;
    let rows: Vec<(Vec<u8>, i64, Vec<u8>)> = stmt
        .query_map([KIND_CONTROL], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<Result<_, rusqlite::Error>>()?;

    // old manifest hash → (new hash, new encoded Message bytes)
    let mut remap: HashMap<[u8; 32], ([u8; 32], Vec<u8>)> = HashMap::new();
    let mut resealed = 0usize;
    for (oid, seq, blob) in &rows {
        let msg = match Message::decode(blob) {
            Ok(m) => m,
            // Not decodable: the pump already fails such a row permanently
            // (sendFailed malformed). Not this migration's problem.
            Err(_) => continue,
        };
        let Message::GroupManifest { manifest } = msg else {
            continue;
        };
        let Some(key) = &signing_key else {
            // Queued manifests without an identity cannot exist through any
            // code path; skip defensively rather than fail the open.
            continue;
        };
        let old_hash = manifest.hash();
        // Fan-out queues the SAME manifest bytes to every member. A row
        // whose manifest was already re-signed for an earlier row still
        // needs its own UPDATE — skipping it would leave the duplicate
        // signed under the old version, and upgraded peers would reject it
        // (an admission queued for N members during an upgrade must reach
        // all N). Ed25519 is deterministic: the remapped bytes are exactly
        // the ones the first re-sign produced.
        if let Some((_, new_bytes)) = remap.get(&old_hash) {
            conn.execute(
                "UPDATE outbox SET blob = ?3 WHERE object_id = ?1 AND sequence = ?2",
                rusqlite::params![oid, seq, new_bytes],
            )?;
            resealed += 1;
            continue;
        }
        let parent = manifest
            .parent
            .map(|p| remap.get(&p).map(|(h, _)| *h).unwrap_or(p));
        let re = manifest
            .resign_for_version(parent, to_e2e, key)
            .map_err(|e| StoreError::ResealFailed(e.to_string()))?;
        let new_hash = re.hash();
        let new_bytes = Message::GroupManifest { manifest: re }.encode();
        conn.execute(
            "UPDATE outbox SET blob = ?3 WHERE object_id = ?1 AND sequence = ?2",
            rusqlite::params![oid, seq, new_bytes],
        )?;
        remap.insert(old_hash, (new_hash, new_bytes));
        resealed += 1;
    }

    if remap.is_empty() {
        return Ok(0);
    }

    // The stored current manifest: re-write it only when it is one of the
    // re-signed queued issuances (issued offline, never accepted). Ed25519
    // is deterministic, so the queued re-sign's bytes are exactly right.
    {
        use rusqlite::OptionalExtension;
        let stored: Option<Vec<u8>> = conn
            .query_row("SELECT data FROM manifest WHERE id = 1", [], |row| {
                row.get(0)
            })
            .optional()?;
        if let Some(data) = stored {
            if let Ok(m) = crate::manifest::GroupManifest::decode(&data) {
                if let Some((_, new_bytes)) = remap.get(&m.hash()) {
                    // new_bytes is the encoded Message; the manifest table
                    // stores the bare manifest encoding.
                    if let Message::GroupManifest { manifest } = Message::decode(new_bytes)
                        .map_err(|e| StoreError::ResealFailed(format!("re-decode: {e}")))?
                    {
                        conn.execute(
                            "INSERT INTO manifest (id, data) VALUES (1, ?1)
                             ON CONFLICT(id) DO UPDATE SET data = excluded.data",
                            rusqlite::params![manifest.encode()],
                        )?;
                    }
                }
            }
        }
    }

    // Held-manifest history: move rows onto the new hashes, preserving
    // included_self.
    for (old_hash, (new_hash, _)) in &remap {
        use rusqlite::OptionalExtension;
        let included: Option<i64> = conn
            .query_row(
                "SELECT included_self FROM held_manifests WHERE hash = ?1",
                rusqlite::params![old_hash.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(included) = included {
            conn.execute(
                "DELETE FROM held_manifests WHERE hash = ?1",
                rusqlite::params![old_hash.as_slice()],
            )?;
            conn.execute(
                "INSERT OR REPLACE INTO held_manifests (hash, included_self) VALUES (?1, ?2)",
                rusqlite::params![new_hash.as_slice(), included],
            )?;
        }
    }

    Ok(resealed)
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
    /// Runs the version check, any chained migrations, a Store Reset when the
    /// store is unmigratable, and the End-to-End bump re-seal (ADR-0032,
    /// ADR-0034 §1). Discards the outcome; callers that must react to a
    /// Store Reset or a migration use [`Store::open_with_outcome`].
    pub fn open(base_dir: &Path, namespace: &str) -> Result<Self, StoreError> {
        Self::open_with_outcome(base_dir, namespace).map(|(store, _)| store)
    }

    /// [`Store::open`] that also reports what the open did (ADR-0032).
    pub fn open_with_outcome(
        base_dir: &Path,
        namespace: &str,
    ) -> Result<(Self, OpenOutcome), StoreError> {
        Self::open_inner(
            base_dir,
            namespace,
            crate::version::STORE_VERSION,
            crate::version::END_TO_END_VERSION,
            MIGRATIONS,
        )
    }

    /// The open state machine (ADR-0032):
    ///
    /// 1. **Probe read-only.** The Store Version decides before any byte is
    ///    written — a store we refuse (`storeTooNew`) keeps its exact bytes,
    ///    so rolling forward again loses nothing.
    /// 2. **Fresh**: no tables — create the schema and record Store Version
    ///    and the End-to-End Version.
    /// 3. **Unversioned or below the migration floor** (any development-build
    ///    store): automatic Store Reset — wipe every table and record the
    ///    versions, in one transaction. A crash mid-wipe rolls back, so the
    ///    store is still unmigratable and the reset simply runs again.
    /// 4. **Older but migratable**: run the chained migration steps, each in
    ///    its own transaction.
    /// 5. **End-to-End Version bump** (independent of Store Version): re-seal
    ///    every queued outbox entry in one transaction (ADR-0034 §1).
    pub(crate) fn open_inner(
        base_dir: &Path,
        namespace: &str,
        target_store_version: u32,
        current_e2e: u32,
        migrations: &[(u32, Migration)],
    ) -> Result<(Self, OpenOutcome), StoreError> {
        let path = base_dir.join(format!("trueseal_{}.db", namespace));
        let mut outcome = OpenOutcome::default();

        // ── 1. Read-only probe. Nothing here may write. ────────────────────
        enum Decision {
            Fresh,
            Reset,
            Migrate(u32),
            Current,
        }
        let decision = if !path.exists() {
            Decision::Fresh
        } else {
            // Read-only, and deliberately so (ADR-0032): a store we refuse
            // keeps its exact bytes. Known edge (accepted): if the previous
            // process was a NEWER install that died leaving an
            // uncheckpointed WAL holding the meta row, this read-only probe
            // cannot see that row and the open surfaces as StoreFailed
            // (a `storage` error) instead of StoreTooNew — the bytes are
            // still unchanged, and rolling forward again loses nothing.
            let probe = rusqlite::Connection::open_with_flags(
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            let versioned = table_exists(&probe, "meta")?;
            let found: Option<u32> = if versioned {
                // A negative or overflowing stored version is nonsense; read
                // it as u32::MAX so the store is REFUSED, never reset.
                meta_get(&probe, META_STORE_VERSION)?.map(|v| u32::try_from(v).unwrap_or(u32::MAX))
            } else {
                None
            };
            match found {
                _ if !versioned && !any_table_exists(&probe)? => Decision::Fresh,
                None => Decision::Reset, // tables exist but no Store Version: dev-build store
                Some(v) if v > target_store_version => {
                    // Refused. The probe wrote nothing; return before the
                    // read-write open so the file's bytes are untouched.
                    return Err(StoreError::StoreTooNew {
                        found: v,
                        supported: target_store_version,
                    });
                }
                Some(v) if v < crate::version::STORE_MIGRATION_FLOOR => Decision::Reset,
                Some(v) if v < target_store_version => Decision::Migrate(v),
                Some(_) => Decision::Current,
            }
        };

        // ── 2. Read-write open; every change below is transactional. ───────
        let mut conn = rusqlite::Connection::open(&path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        match decision {
            Decision::Fresh => {
                outcome.created = true;
                ensure_schema(&conn)?;
                let tx = conn.transaction()?;
                meta_set(&tx, META_STORE_VERSION, target_store_version)?;
                meta_set(&tx, META_E2E_VERSION, current_e2e)?;
                tx.commit()?;
            }
            Decision::Reset => {
                // Automatic Store Reset (ADR-0032): wipe every table and
                // record the versions, atomically. The session layer
                // regenerates the identity on the next load and reports
                // `storeReset`.
                outcome.reset = true;
                let tx = conn.transaction()?;
                // Drop + recreate: the reset produces exactly the current
                // schema even when the old store predates later columns.
                tx.execute_batch(DROP_ALL_SQL)?;
                ensure_schema(&tx)?;
                meta_set(&tx, META_STORE_VERSION, target_store_version)?;
                meta_set(&tx, META_E2E_VERSION, current_e2e)?;
                tx.commit()?;
            }
            Decision::Migrate(from) => {
                // Deliberately NO ensure_schema here: the store has an older
                // shape, and creating current-shape tables before the steps
                // run would defeat them. The steps own the schema.
                outcome.migrated_from = Some(from);
                run_migrations(&mut conn, from, target_store_version, migrations)?;
            }
            Decision::Current => {
                // Defensive no-op for a current store (every statement is
                // IF NOT EXISTS); guards against a partially created file.
                ensure_schema(&conn)?;
            }
        }

        // ── 5. End-to-End Version bump: re-seal the outbox (ADR-0034 §1). ──
        let stored_e2e = meta_get(&conn, META_E2E_VERSION)?
            .map(|v| u32::try_from(v).unwrap_or(current_e2e))
            .unwrap_or(current_e2e);
        if stored_e2e < current_e2e {
            outcome.resealed_from_e2e = Some(stored_e2e);
            reseal_outbox_for_e2e_bump(&mut conn, current_e2e)?;
        }

        Ok((Self { conn }, outcome))
    }

    /// Wipe all data from all tables.
    ///
    /// Leaves the schema intact. Used by destroyGroup() and tests.
    /// Clears the dedup table and sequence high-water mark too: after a
    /// Destroy Group every device starts over with a fresh identity, so no
    /// Message ID or sequence from the old group may carry over.
    pub fn wipe(&self) -> Result<(), StoreError> {
        // Destroy Group / removal wipe group data but keep the store
        // versioned: the Store Version keys survive (they describe the
        // format, not the group). Everything else, the dedup table and the
        // sequence high-water mark included, goes.
        self.conn
            .execute_batch(&format!("BEGIN; {WIPE_DATA_SQL} COMMIT;"))?;
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

    fn record_handled(&mut self, message_id: &str, stamp: u64) {
        if let Err(e) = self.store.conn.execute(
            "INSERT INTO handled_messages (message_id, handled_at) VALUES (?1, ?2)
             ON CONFLICT(message_id) DO UPDATE SET handled_at = excluded.handled_at",
            rusqlite::params![message_id, stamp as i64],
        ) {
            warn!("[trueseal-sync] record_handled failed: {e}");
        }
        // Prune against the REAL WALL CLOCK, never the stored stamp (see
        // the trait docs): a far-future Sender Timestamp must not delete
        // existing dedup records.
        let cutoff = now_secs().saturating_sub(DEDUP_RETENTION_SECS);
        if let Err(e) = self.store.conn.execute(
            "DELETE FROM handled_messages WHERE handled_at < ?1",
            rusqlite::params![cutoff as i64],
        ) {
            warn!("[trueseal-sync] dedup prune failed: {e}");
        }
    }

    fn handled_at(&self, message_id: &str) -> Option<u64> {
        self.store
            .conn
            .query_row(
                "SELECT handled_at FROM handled_messages WHERE message_id = ?1",
                rusqlite::params![message_id],
                |row| row.get::<_, i64>(0),
            )
            .ok()
            .map(|v| v as u64)
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
            for (hash, included_self) in &held {
                tx.execute(
                    "INSERT INTO held_manifests (hash, included_self) VALUES (?1, ?2)
                     ON CONFLICT(hash) DO UPDATE SET included_self=excluded.included_self",
                    rusqlite::params![hash.as_slice(), *included_self as i64],
                )?;
            }
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
            .query_row("SELECT data FROM leaving WHERE id = 1", [], |row| {
                row.get(0)
            })
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
            held: vec![([1u8; 32], true)],
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
    /// 60-day retention window, measured from the REAL wall clock
    /// (ADR-0026; the clamp-poisons-pruning fix).
    #[test]
    fn handled_messages_persist_and_prune() {
        let dir = tmp_dir();
        {
            let s = Store::open(dir.path(), "ns").expect("open");
            let mut log = PersistentLog::new(s);
            log.record_handled("tsm1_a", now_secs());
            assert!(log.is_handled("tsm1_a"));
            assert!(!log.is_handled("tsm1_b"));
        }
        let s2 = Store::open(dir.path(), "ns").expect("reopen");
        let mut log2 = PersistentLog::new(s2);
        assert!(log2.is_handled("tsm1_a"), "dedup records survive restart");
        // An expired row (61 days behind the wall clock, inserted directly)
        // is pruned when the next record lands; the fresh row survives.
        log2.store
            .conn
            .execute(
                "INSERT INTO handled_messages (message_id, handled_at) VALUES ('tsm1_old', ?1)",
                rusqlite::params![(now_secs() - DEDUP_RETENTION_SECS - 1) as i64],
            )
            .expect("seed expired row");
        log2.record_handled("tsm1_b", now_secs());
        assert!(log2.is_handled("tsm1_b"));
        assert!(log2.is_handled("tsm1_a"), "fresh records survive the prune");
        assert!(!log2.is_handled("tsm1_old"), "expired records are pruned");
    }

    /// The clamp-poisons-pruning attack (review P1), persistent backend:
    /// a far-future stored stamp must not prune existing records.
    #[test]
    fn far_future_stamp_does_not_prune_existing_records_persistent() {
        let dir = tmp_dir();
        let s = Store::open(dir.path(), "ns").expect("open");
        let mut log = PersistentLog::new(s);
        log.record_handled("m1", now_secs());
        log.record_handled("m2", now_secs());
        log.record_handled("evil", now_secs() + 10 * 365 * 24 * 60 * 60);
        assert!(log.is_handled("m1"), "existing records survive the clamp");
        assert!(log.is_handled("m2"), "existing records survive the clamp");
        assert!(log.is_handled("evil"));
        // And the future-stamped record persists across a reopen.
        let s2 = Store::open(dir.path(), "ns").expect("reopen");
        let log2 = PersistentLog::new(s2);
        assert!(log2.is_handled("evil"), "the clamped record persists");
        assert!(log2.is_handled("m1"));
    }

    /// A store written before SYNC-5 (outbox without kind/created_at, no
    /// handled_messages/meta tables) opens cleanly: the columns are added,
    /// legacy rows become Sync entries with a fresh lease, and the dedup and
    /// meta tables exist. Store Versions and chained migrations are SYNC-13
    /// scope; this is the dev-preview drift bridge.
    #[test]
    /// ADR-0032: an UNVERSIONED store — anything a development build wrote
    /// before Store Versions existed, including the pre-SYNC-5 outbox
    /// schema — is unmigratable. Open resets it automatically: every table
    /// wiped, Store Version recorded, the store usable again (the object
    /// reports `storeReset` and can pair again). Before SYNC-13 this test
    /// expected an ad-hoc in-place schema upgrade; the versioned world
    /// replaces that with the reset.
    fn legacy_unversioned_store_is_reset_on_open() {
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
        let (s, outcome) = Store::open_with_outcome(dir.path(), "ns").expect("open resets");
        assert!(outcome.reset, "unversioned store → automatic Store Reset");
        assert!(!outcome.created);
        let log = PersistentLog::new(s);
        assert!(
            log.undelivered_entries().is_empty(),
            "the reset wiped the legacy rows"
        );
        // The store is fully usable: schema complete, versioned, working.
        let mut log = log;
        log.record_handled("tsm1_x", now_secs());
        assert!(log.is_handled("tsm1_x"));
        log.record_sequence(5);
        assert_eq!(log.max_sequence(), Some(5));
        // A second open sees a current, versioned store.
        let (_s2, outcome2) = Store::open_with_outcome(dir.path(), "ns").expect("reopen");
        assert_eq!(outcome2, OpenOutcome::default(), "reopen: nothing to do");
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
                held: vec![([7u8; 32], true)],
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
            held: vec![([1u8; 32], true)],
            pending_changes: b"changes".to_vec(),
            leaving: Some(b"refs".to_vec()),
            outbox: vec![],
        })
        .expect("commit 1");
        log.commit_membership(MembershipCommit {
            manifest: b"m2".to_vec(),
            held: vec![([2u8; 32], false)],
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
            held: vec![([1u8; 32], true)],
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

#[cfg(test)]
mod versioning_tests {
    //! ADR-0032 / ADR-0034 §1: Store Versions, chained migrations, the
    //! automatic Store Reset, storeTooNew, crash behaviour, and the
    //! End-to-End bump re-seal (SYNC-13, #105).

    use super::*;
    use crate::device::DeviceKeypair;
    use crate::manifest::{GroupManifest, ManifestMember};
    use crate::message::Message;

    fn tmp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn oid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn member(kp: &DeviceKeypair, name: &str) -> ManifestMember {
        ManifestMember {
            noise_pub: kp.public_key(),
            signing_pub: kp.signing_public_key(),
            name: name.to_string(),
        }
    }

    fn sha256_file(path: &Path) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(std::fs::read(path).expect("read db")).into()
    }

    /// A v1 store with one marker row, closed.
    fn make_v1_store(dir: &Path, ns: &str) -> DeviceKeypair {
        let kp = DeviceKeypair::generate();
        let s = Store::open(dir, ns).expect("open");
        s.save_keypair(&kp).expect("save keypair");
        drop(s);
        kp
    }

    fn raw_meta_get(dir: &Path, ns: &str, key: &str) -> Option<i64> {
        let conn = rusqlite::Connection::open(dir.join(format!("trueseal_{ns}.db"))).unwrap();
        conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| {
            r.get::<_, i64>(0)
        })
        .ok()
    }

    // ── Fresh store ──────────────────────────────────────────────────────────

    #[test]
    fn fresh_store_records_store_version_1_and_reopen_is_idempotent() {
        let dir = tmp_dir();
        let (s, outcome) = Store::open_with_outcome(dir.path(), "ns").expect("open");
        assert!(outcome.created);
        assert!(!outcome.reset);
        assert_eq!(outcome.migrated_from, None);
        assert_eq!(outcome.resealed_from_e2e, None);
        assert_eq!(
            meta_get(&s.conn, META_STORE_VERSION).unwrap(),
            Some(crate::version::STORE_VERSION as i64)
        );
        assert_eq!(
            meta_get(&s.conn, META_E2E_VERSION).unwrap(),
            Some(crate::version::END_TO_END_VERSION as i64)
        );
        drop(s);
        let (_s2, outcome2) = Store::open_with_outcome(dir.path(), "ns").expect("reopen");
        assert_eq!(outcome2, OpenOutcome::default(), "reopen: nothing to do");
    }

    // ── Chained migrations ───────────────────────────────────────────────────

    fn step_1_to_2(tx: &rusqlite::Transaction<'_>) -> Result<(), rusqlite::Error> {
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('step_1_to_2', 1)",
            [],
        )?;
        Ok(())
    }
    fn step_2_to_3(tx: &rusqlite::Transaction<'_>) -> Result<(), rusqlite::Error> {
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('step_2_to_3', 1)",
            [],
        )?;
        Ok(())
    }

    #[test]
    fn synthetic_older_store_migrates_through_every_chained_step() {
        let dir = tmp_dir();
        make_v1_store(dir.path(), "ns");
        let steps: &[(u32, Migration)] = &[(1, step_1_to_2), (2, step_2_to_3)];
        let (s, outcome) = Store::open_inner(
            dir.path(),
            "ns",
            3,
            crate::version::END_TO_END_VERSION,
            steps,
        )
        .expect("migrate");
        assert_eq!(outcome.migrated_from, Some(1));
        assert_eq!(meta_get(&s.conn, META_STORE_VERSION).unwrap(), Some(3));
        // Every step ran, in order.
        assert_eq!(raw_meta_get(dir.path(), "ns", "step_1_to_2"), Some(1));
        assert_eq!(raw_meta_get(dir.path(), "ns", "step_2_to_3"), Some(1));
        // Identity survived the chain.
        assert!(s.load_keypair().expect("load").is_some());
    }

    #[test]
    fn migration_without_a_path_fails_and_leaves_the_store_intact() {
        let dir = tmp_dir();
        make_v1_store(dir.path(), "ns");
        // No steps registered: v1 -> v2 has no path.
        let err =
            match Store::open_inner(dir.path(), "ns", 2, crate::version::END_TO_END_VERSION, &[]) {
                Ok(_) => panic!("no migration path should fail"),
                Err(e) => e,
            };
        assert!(matches!(err, StoreError::MigrationFailed { from: 1, .. }));
        assert_eq!(raw_meta_get(dir.path(), "ns", META_STORE_VERSION), Some(1));
    }

    fn step_writes_then_fails(tx: &rusqlite::Transaction<'_>) -> Result<(), rusqlite::Error> {
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('partial_step', 1)",
            [],
        )?;
        Err(rusqlite::Error::InvalidQuery)
    }

    /// ADR-0032 crash table, row 1: a migration that dies before its
    /// transaction commits leaves the old store intact, and the next open
    /// retries the migration.
    #[test]
    fn killed_migration_leaves_old_store_intact_and_next_open_retries() {
        let dir = tmp_dir();
        make_v1_store(dir.path(), "ns");
        let crashy: &[(u32, Migration)] = &[(1, step_writes_then_fails)];
        let err = match Store::open_inner(
            dir.path(),
            "ns",
            2,
            crate::version::END_TO_END_VERSION,
            crashy,
        ) {
            Ok(_) => panic!("step should fail"),
            Err(e) => e,
        };
        assert!(matches!(err, StoreError::MigrationFailed { from: 1, .. }));
        // The step's writes rolled back with its transaction.
        assert_eq!(raw_meta_get(dir.path(), "ns", META_STORE_VERSION), Some(1));
        assert_eq!(raw_meta_get(dir.path(), "ns", "partial_step"), None);
        // The next open retries — with a working step it completes.
        let fixed: &[(u32, Migration)] = &[(1, step_1_to_2)];
        let (s, outcome) = Store::open_inner(
            dir.path(),
            "ns",
            2,
            crate::version::END_TO_END_VERSION,
            fixed,
        )
        .expect("retry succeeds");
        assert_eq!(outcome.migrated_from, Some(1));
        assert_eq!(meta_get(&s.conn, META_STORE_VERSION).unwrap(), Some(2));
    }

    // ── Store Reset ──────────────────────────────────────────────────────────

    /// A versioned store whose version keys were lost (a dev-build artifact)
    /// is unversioned for open's purposes: reset, and the group state is
    /// gone — the session layer regenerates a fresh identity and reports
    /// `statusChanged(notJoined, storeReset)` (ADR-0032).
    #[test]
    fn store_with_lost_version_keys_is_reset() {
        let dir = tmp_dir();
        make_v1_store(dir.path(), "ns");
        {
            let conn = rusqlite::Connection::open(dir.path().join("trueseal_ns.db")).unwrap();
            conn.execute(
                "DELETE FROM meta WHERE key IN ('store_version', 'e2e_version')",
                [],
            )
            .unwrap();
        }
        let (s, outcome) = Store::open_with_outcome(dir.path(), "ns").expect("open resets");
        assert!(outcome.reset);
        assert!(s.load_keypair().expect("load").is_none(), "identity wiped");
        assert_eq!(
            meta_get(&s.conn, META_STORE_VERSION).unwrap(),
            Some(crate::version::STORE_VERSION as i64)
        );
    }

    // ── storeTooNew ──────────────────────────────────────────────────────────

    /// ADR-0032: a store written by a newer release is refused with
    /// `storeTooNew`, and its file bytes are UNCHANGED — rolling forward
    /// again loses nothing.
    #[test]
    fn newer_store_fails_with_store_too_new_and_bytes_unchanged() {
        let dir = tmp_dir();
        make_v1_store(dir.path(), "ns");
        let path = dir.path().join("trueseal_ns.db");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute("UPDATE meta SET value = 99 WHERE key = 'store_version'", [])
                .unwrap();
            // Checkpoint so the main file holds every byte, then hash it.
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .unwrap();
        }
        let before = sha256_file(&path);
        let err = match Store::open_with_outcome(dir.path(), "ns") {
            Ok(_) => panic!("a newer store must be refused"),
            Err(e) => e,
        };
        match err {
            StoreError::StoreTooNew { found, supported } => {
                assert_eq!(found, 99);
                assert_eq!(supported, crate::version::STORE_VERSION);
            }
            other => panic!("expected StoreTooNew, got {other}"),
        }
        assert_eq!(sha256_file(&path), before, "refused store: bytes unchanged");
        // Rolling "forward" again (a build that understands v99) is not
        // simulated — the byte check above is the promise that it can.
    }

    // ── End-to-End bump re-seal (ADR-0034 §1) ────────────────────────────────

    /// Queue one of each kind: Sync (seq 1), Pair (seq 2), a genesis
    /// manifest (seq 3), a child manifest built on it (seq 4), Revoke
    /// (seq 5). The stored current manifest is the child (issued offline);
    /// the held history covers both. Returns the keypair and the original
    /// row bytes for later comparison.
    fn queue_all_kinds(dir: &Path, ns: &str) -> (DeviceKeypair, GroupManifest, GroupManifest) {
        let kp = DeviceKeypair::generate();
        let s = Store::open(dir, ns).expect("open");
        s.save_keypair(&kp).expect("save");
        let group_id = oid(9);
        let genesis = GroupManifest::new(group_id, 0, vec![member(&kp, "me")], &kp.signing);
        let child =
            GroupManifest::update(&genesis, vec![member(&kp, "me")], &kp.signing).expect("update");
        let mut log = PersistentLog::new(s);
        log.append(&oid(1), 1, b"hello sync body".to_vec());
        log.append_control(
            &oid(2),
            2,
            Message::Pair {
                noise_pub: oid(3),
                signing_pub: oid(4),
                secret: oid(5),
            }
            .encode(),
        );
        log.append_control(
            &oid(1),
            3,
            Message::GroupManifest {
                manifest: genesis.clone(),
            }
            .encode(),
        );
        log.append_control(
            &oid(1),
            4,
            Message::GroupManifest {
                manifest: child.clone(),
            }
            .encode(),
        );
        log.append_control(&oid(1), 5, Message::Revoke.encode());
        // Stored current manifest = the child; held history covers both.
        drop(log);
        let s2 = Store::open(dir, ns).expect("reopen");
        s2.save_group_manifest(&child).expect("save manifest");
        let mut log2 = PersistentLog::new(s2);
        let _ = log2.commit_membership(crate::operation_log::MembershipCommit {
            manifest: child.encode(),
            held: vec![(genesis.hash(), true), (child.hash(), true)],
            pending_changes: vec![],
            leaving: None,
            outbox: vec![],
        });
        (kp, genesis, child)
    }

    fn outbox_row(dir: &Path, ns: &str, seq: i64) -> (Vec<u8>, i64, i64) {
        let conn = rusqlite::Connection::open(dir.join(format!("trueseal_{ns}.db"))).unwrap();
        conn.query_row(
            "SELECT blob, created_at, delivered FROM outbox WHERE sequence = ?1",
            [seq],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
    }

    /// The headline criterion: a simulated End-to-End bump re-seals every
    /// queued entry. Manifests are re-signed under the new version with the
    /// hash remap propagated; Sync/Pair/Revoke rows are byte-identical, so
    /// the Sync message keeps its original Message ID (signing_pub +
    /// sequence, unchanged) and Sender Timestamp (created_at, unchanged) —
    /// and is delivered exactly once, pinned end-to-end in the session
    /// tests.
    #[test]
    fn e2e_bump_reseals_queued_entries_and_preserves_sync_identity() {
        let dir = tmp_dir();
        let (_kp, genesis, child) = queue_all_kinds(dir.path(), "ns");
        let (sync_blob, sync_created_at, _) = outbox_row(dir.path(), "ns", 1);
        let (pair_blob, _, _) = outbox_row(dir.path(), "ns", 2);
        let (revoke_blob, _, _) = outbox_row(dir.path(), "ns", 5);

        let (s, outcome) = Store::open_inner(
            dir.path(),
            "ns",
            crate::version::STORE_VERSION,
            crate::version::END_TO_END_VERSION + 1,
            MIGRATIONS,
        )
        .expect("open reseals");
        assert_eq!(
            outcome.resealed_from_e2e,
            Some(crate::version::END_TO_END_VERSION)
        );
        assert_eq!(
            meta_get(&s.conn, META_E2E_VERSION).unwrap(),
            Some(crate::version::END_TO_END_VERSION as i64 + 1)
        );

        // Sync / Pair / Revoke rows: byte-identical (sealed at push).
        assert_eq!(outbox_row(dir.path(), "ns", 1).0, sync_blob);
        assert_eq!(outbox_row(dir.path(), "ns", 1).1, sync_created_at);
        assert_eq!(outbox_row(dir.path(), "ns", 2).0, pair_blob);
        assert_eq!(outbox_row(dir.path(), "ns", 5).0, revoke_blob);

        // Manifests: re-signed under v2, hash remap propagated.
        let new_e2e = crate::version::END_TO_END_VERSION + 1;
        let (genesis_blob, _, _) = outbox_row(dir.path(), "ns", 3);
        let (child_blob, _, _) = outbox_row(dir.path(), "ns", 4);
        let Message::GroupManifest {
            manifest: new_genesis,
        } = Message::decode(&genesis_blob).unwrap()
        else {
            panic!("seq 3 is a manifest");
        };
        let Message::GroupManifest {
            manifest: new_child,
        } = Message::decode(&child_blob).unwrap()
        else {
            panic!("seq 4 is a manifest");
        };
        new_genesis
            .verify_signature_for_version(new_e2e)
            .expect("genesis verifies under the new version");
        new_child
            .verify_signature_for_version(new_e2e)
            .expect("child verifies under the new version");
        new_genesis
            .verify_signature_for_version(crate::version::END_TO_END_VERSION)
            .expect_err("genesis no longer verifies under the old version");
        assert_ne!(
            new_genesis.hash(),
            genesis.hash(),
            "re-sign changes the hash"
        );
        assert_eq!(
            new_child.parent,
            Some(new_genesis.hash()),
            "child parent remapped to the new genesis hash"
        );
        assert_eq!(
            new_child.version, child.version,
            "logical version unchanged"
        );
        assert_eq!(new_child.members, child.members, "members unchanged");

        // Stored current manifest: re-written to the re-signed child.
        let stored = s.load_group_manifest().expect("load").expect("some");
        assert_eq!(stored.hash(), new_child.hash());
        stored
            .verify_signature_for_version(new_e2e)
            .expect("stored manifest verifies under the new version");

        // Held history: new hashes, included_self preserved.
        let held_new_genesis: Option<i64> = s
            .conn
            .query_row(
                "SELECT included_self FROM held_manifests WHERE hash = ?1",
                rusqlite::params![new_genesis.hash().as_slice()],
                |r| r.get(0),
            )
            .ok();
        let held_old_genesis: Option<i64> = s
            .conn
            .query_row(
                "SELECT included_self FROM held_manifests WHERE hash = ?1",
                rusqlite::params![genesis.hash().as_slice()],
                |r| r.get(0),
            )
            .ok();
        assert_eq!(held_new_genesis, Some(1));
        assert_eq!(held_old_genesis, None, "old hash replaced");

        // Nothing lost: every queued entry is still there, same sequences.
        let count: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 5);
    }

    /// A delivered row's hash may be installed at peers — re-signing it
    /// would fork the chain. Delivered rows are not re-signed.
    #[test]
    fn e2e_bump_does_not_touch_delivered_rows() {
        let dir = tmp_dir();
        let (_kp, genesis, _child) = queue_all_kinds(dir.path(), "ns");
        {
            let conn = rusqlite::Connection::open(dir.path().join("trueseal_ns.db")).unwrap();
            conn.execute("UPDATE outbox SET delivered = 1 WHERE sequence = 3", [])
                .unwrap();
        }
        let (_s, _outcome) = Store::open_inner(
            dir.path(),
            "ns",
            crate::version::STORE_VERSION,
            crate::version::END_TO_END_VERSION + 1,
            MIGRATIONS,
        )
        .expect("open");
        let (blob, _, delivered) = outbox_row(dir.path(), "ns", 3);
        assert_eq!(delivered, 1);
        let Message::GroupManifest { manifest } = Message::decode(&blob).unwrap() else {
            panic!("seq 3 is a manifest");
        };
        assert_eq!(manifest.hash(), genesis.hash(), "delivered row untouched");
        manifest
            .verify_signature_for_version(crate::version::END_TO_END_VERSION)
            .expect("still under the old version");
    }

    /// ADR-0034 §1 crash behaviour: a re-seal that fails rolls its
    /// transaction back — every entry is still at the old version and the
    /// recorded e2e version is unchanged.
    #[test]
    fn failed_reseal_rolls_back_everything() {
        let dir = tmp_dir();
        let (kp, genesis, _child) = queue_all_kinds(dir.path(), "ns");
        // Corrupt the queued genesis: re-sign it with a DIFFERENT device's
        // key, so the migration's resign_for_version refuses (UnknownIssuer).
        {
            let conn = rusqlite::Connection::open(dir.path().join("trueseal_ns.db")).unwrap();
            let other = DeviceKeypair::generate();
            let foreign = GroupManifest::new(
                genesis.group_id,
                genesis.version,
                vec![member(&other, "other")],
                &other.signing,
            );
            let _ = kp; // identity in the store is kp; the queued manifest is not its issuance
            conn.execute(
                "UPDATE outbox SET blob = ?1 WHERE sequence = 3",
                rusqlite::params![Message::GroupManifest { manifest: foreign }.encode()],
            )
            .unwrap();
        }
        let err = match Store::open_inner(
            dir.path(),
            "ns",
            crate::version::STORE_VERSION,
            crate::version::END_TO_END_VERSION + 1,
            MIGRATIONS,
        ) {
            Ok(_) => panic!("re-seal must refuse a foreign manifest"),
            Err(e) => e,
        };
        assert!(matches!(err, StoreError::ResealFailed(_)));
        // Everything is still at the old version.
        assert_eq!(
            raw_meta_get(dir.path(), "ns", META_E2E_VERSION),
            Some(crate::version::END_TO_END_VERSION as i64)
        );
        let (child_blob, _, _) = outbox_row(dir.path(), "ns", 4);
        let Message::GroupManifest { manifest } = Message::decode(&child_blob).unwrap() else {
            panic!("seq 4 is a manifest");
        };
        manifest
            .verify_signature_for_version(crate::version::END_TO_END_VERSION)
            .expect("child still verifies under the old version — nothing re-sealed");
        // The store is still usable: a retry at the real version opens fine.
        let (_s, outcome) = Store::open_with_outcome(dir.path(), "ns").expect("still opens");
        assert_eq!(outcome, OpenOutcome::default());
    }

    /// Fan-out queues the same manifest bytes to every member (one row per
    /// recipient). A bump must re-seal EVERY duplicate row — a row skipped
    /// because another copy was already re-signed keeps an old-domain
    /// signature, and upgraded peers reject it: an admission queued for N
    /// members during the upgrade would reach only one.
    #[test]
    fn e2e_bump_reseals_fan_out_duplicates_on_every_row() {
        let dir = tmp_dir();
        let kp = DeviceKeypair::generate();
        let s = Store::open(dir.path(), "ns").expect("open");
        s.save_keypair(&kp).expect("save");
        let genesis = GroupManifest::new(oid(9), 0, vec![member(&kp, "me")], &kp.signing);
        // The same manifest to two recipients — fan-out's row shape.
        let encoded = Message::GroupManifest {
            manifest: genesis.clone(),
        }
        .encode();
        let mut log = PersistentLog::new(s);
        log.append_control(&oid(1), 1, encoded.clone());
        log.append_control(&oid(2), 2, encoded.clone());

        let (_s, outcome) = Store::open_inner(
            dir.path(),
            "ns",
            crate::version::STORE_VERSION,
            crate::version::END_TO_END_VERSION + 1,
            MIGRATIONS,
        )
        .expect("open reseals");
        assert!(outcome.resealed_from_e2e.is_some());

        let new_e2e = crate::version::END_TO_END_VERSION + 1;
        let mut new_hashes = Vec::new();
        for seq in [1i64, 2] {
            let (blob, _, _) = outbox_row(dir.path(), "ns", seq);
            let Message::GroupManifest { manifest } = Message::decode(&blob).unwrap() else {
                panic!("seq {seq} is a manifest");
            };
            manifest
                .verify_signature_for_version(new_e2e)
                .unwrap_or_else(|_| panic!("row seq {seq} verifies under the new version"));
            assert!(
                manifest
                    .verify_signature_for_version(crate::version::END_TO_END_VERSION)
                    .is_err(),
                "row seq {seq} no longer verifies under the old version"
            );
            new_hashes.push(manifest.hash());
        }
        assert_eq!(
            new_hashes[0], new_hashes[1],
            "deterministic re-sign: identical bytes on both rows"
        );
        assert_ne!(new_hashes[0], genesis.hash());
    }

    /// destroyGroup()/removal wipe group data but keep the store VERSIONED:
    /// a reopen after a wipe is a plain current store — no phantom
    /// `storeReset` from losing the version keys with the group state.
    #[test]
    fn wipe_preserves_version_keys_so_reopen_is_not_a_reset() {
        let dir = tmp_dir();
        let kp = make_v1_store(dir.path(), "ns");
        {
            let s = Store::open(dir.path(), "ns").expect("open");
            s.wipe().expect("wipe");
            // Group state gone, versions kept.
            assert!(s.load_keypair().expect("load").is_none());
            assert_eq!(
                meta_get(&s.conn, META_STORE_VERSION).unwrap(),
                Some(crate::version::STORE_VERSION as i64),
                "wipe preserves the Store Version"
            );
            assert_eq!(
                meta_get(&s.conn, META_E2E_VERSION).unwrap(),
                Some(crate::version::END_TO_END_VERSION as i64),
            );
            let _ = kp;
        }
        let (_s, outcome) = Store::open_with_outcome(dir.path(), "ns").expect("reopen");
        assert_eq!(
            outcome,
            OpenOutcome::default(),
            "post-wipe reopen: current store, no phantom storeReset"
        );
    }

    #[test]
    fn resign_for_version_refuses_another_devices_issuance() {
        let me = DeviceKeypair::generate();
        let other = DeviceKeypair::generate();
        let m = GroupManifest::new(oid(1), 0, vec![member(&other, "o")], &other.signing);
        m.resign_for_version(None, 2, &me.signing)
            .expect_err("only the issuer may re-sign");
    }
}
