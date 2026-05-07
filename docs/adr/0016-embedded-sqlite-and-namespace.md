# Embedded SQLite for fully-managed session state; namespace parameter for multi-group apps

## Context

The library needs to persist three pieces of state across process restarts: the device identity (64-byte keypair), the current Group Manifest (membership list), and the Operation Log (outbox of undelivered blobs). Without persistence, every app restart loses group membership and drops undelivered messages.

The obvious alternative is to make the caller responsible for persisting this state — give them the bytes via callbacks, have them pass them back at construction. This is the pattern used in the early API design. It was rejected because it leaks cryptographic concerns to the caller, requires platform-specific secure storage knowledge the library shouldn't assume, and makes correct implementation non-trivial (atomic writes, crash safety, migration).

## Decision

The library embeds SQLite (via `rusqlite`) and owns all session state internally. The caller provides nothing for storage. The library derives the database path from the platform's conventional app data directory and a caller-supplied `namespace` string.

### Namespace

`namespace` is an optional string parameter on `HushFfiSession.create()` that defaults to `"default"`. The library names the database file `hush_{namespace}.db` in the platform's app data directory. Each namespace is a fully independent session with its own identity, manifest, and outbox.

This makes multi-group apps (spaces) trivially composable: the caller creates one `HushFfiSession` per namespace. The library does not need to know about spaces. Most callers pass no namespace and never think about it.

### Schema

The library owns a three-table schema:

- `identity` — one row: the 64-byte keypair. Written once on first launch (or after `destroyGroup`). Never modified in place.
- `manifest` — one row: the current Group Manifest as encoded bytes. Replaced atomically on every membership change.
- `outbox` — one row per undelivered blob: `(recipient_noise_pub, sequence, blob, created_at)`. Entries are deleted on confirmed delivery. Replayed in sequence order on reconnect.

All writes are wrapped in SQLite transactions. The database is opened with `journal_mode=WAL` for crash safety.

### Identity generation

On `create()`, if no identity row exists in the database, the library generates a fresh keypair and writes it before connecting to the relay. The caller is never asked to generate, supply, or persist identity bytes — the library manages the full lifecycle.

On `destroyGroup()`, the library wipes the entire database for that namespace — identity, manifest, and outbox. The namespace is returned to a blank state. The next `create()` call on that namespace generates a fresh identity. There is no concept of an identity surviving group destruction — identity and group membership are the same thing.

### Caller-visible surface

The caller can read group membership via `session.members() -> [(id, name)]` — a derived view over the manifest. They cannot read the raw identity or manifest bytes. They cannot write to the database directly.

## Consequences

- The caller implements zero storage code. The entire persistence concern is inside the library.
- The Operation Log (outbox) survives crashes and OS kills — undelivered blobs are replayed automatically on next connect.
- `onIdentityCreated` and `onManifestChanged` callbacks are removed from the API — they are no longer needed.
- Multi-group apps (spaces) are supported by creating multiple `HushFfiSession` instances with different namespaces.
- The library binary is larger due to the SQLite dependency. This is acceptable — SQLite is ~600KB, well within mobile app norms.
- Database migration is the library's responsibility. Callers are insulated from schema changes.

## Considered alternatives

**Caller-managed storage via a `HushStorage` callback interface**
Rejected. Requires the caller to implement platform-specific secure storage, understand the semantics of each persisted value, and handle atomic writes. Violates the "black box" principle. Puts crash-safety and migration burden on the caller.

**Platform-specific storage adapters (keychain on iOS, EncryptedSharedPreferences on Android)**
Rejected. Requires platform-specific code in the library, complicates the Rust/UniFFI boundary, and still requires the caller to configure storage. SQLite is cross-platform and already available as a Rust crate.

**In-memory only (no persistence)**
Rejected. Undelivered blobs are lost on process exit. Group membership must be rebuilt from scratch on every launch. Not viable for any real use case.
