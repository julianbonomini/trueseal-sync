# hush-sync exposes two layers: primitives and an opinionated session

## Decision

hush-sync exposes two distinct API layers:

**Primitives** (`hush_sync::*`) — `DeviceKeypair`, `RelayClient`, `GroupManifest`, `OperationLog`, `Message`, `Envelope`. Pure Rust. No lifecycle management. Available for advanced callers: Go via C FFI, custom relay implementations, testing harnesses, and future protocol extensions.

**Session** (`HushFfiSession` via UniFFI; `HushSession` in Rust) — an opinionated facade that wires the primitives together. Owns: session state persistence (identity, manifest, outbox via SQLite — ADR-0016), relay connection lifecycle, reconnection with backoff, group manifest maintenance, message dispatch, soft removal, and destroy group. The caller provides nothing for storage.

UniFFI exposes **only the session layer** to Swift and Kotlin. The primitives are Rust-only and not part of the cross-language surface.

## Session contract

```swift
// Construction — always succeeds; relay connects in background (ADR-0017)
HushFfiSession.create(
    baseDir: String,                              // platform app data directory
    namespace: String,                            // scopes SQLite DB; defaults to "default"
    relayAddr: String,                            // "host:port"
    relayPub: Data,                               // 32-byte relay X25519 public key
    onMessage: MessageCallback,                   // fired on inbound Sync blob
    onRemovedFromGroup: RemovedFromGroupCallback, // fired when local device is excluded from a manifest
    onGroupDestroyed: GroupDestroyedCallback,     // fired on destroyGroup() local or remote
    onConnectionChanged: ConnectionChangedCallback? // optional; fired on relay connect/disconnect
) throws -> HushFfiSession

// Errors from create(): InvalidKeyLength, InvalidRelayPublicKey, InvalidNamespace
// Runtime errors (from operations below): PushFailed, NotInGroup, InvalidToken,
//   MemberNotFound, GroupDestroyed

// Pairing flow
session.pairingToken() -> String          // encode as QR; single-use, expires after use or timeout
session.joinGroup(token: String)          // joiner calls this with the initiator's pairing token
session.setOnMemberRequest(callback)      // initiator receives: (token: String, name: String)
session.acceptMember(token: String) -> Bool  // initiator calls with the token from onMemberRequest
session.cancelPairing()                   // close pairing window early

// Group membership
session.members() -> [Member]             // current manifest view; always available offline
session.removeMember(memberId: String)    // soft removal: issues new manifest version (ADR-0015)
session.destroyGroup()                    // full reset: Revoke + wipe + fresh identity (ADR-0015)

// Late-registered membership event callbacks
session.setOnMemberJoined(callback)       // (memberId: String, memberName: String)
session.setOnMemberLeft(callback)         // (memberId: String, memberName: String)

// Data sync
session.send(blob: Data)                  // fans out to all manifest members; outbox if offline
```

On `destroyGroup()`, the session:
1. Pushes `REVOKE` to every current manifest member.
2. Fires `onGroupDestroyed()` locally.
3. Wipes the local SQLite database for that namespace (identity, manifest, outbox).

The next `create()` call on that namespace auto-generates a fresh identity. The caller never handles or persists keypair bytes — the library owns the full identity lifecycle (ADR-0016).

## Rationale

A single-layer API (primitives only) forces every caller to re-implement session management — relay reconnection, group manifest maintenance, message dispatch. A single-layer opinionated API (session only) blocks advanced callers who need direct access to envelope construction or custom transport adapters.

The two-layer pattern gives both: a sharp tool for protocol-level work, and a safe default for app developers.

## Consequences

- `src/ffi.rs` exposes only `HushFfiSession` (and its error/callback types) via UniFFI. The primitives remain `pub` in Rust but are not in the UniFFI surface.
- The primitives must remain public Rust API (not `pub(crate)`) so that advanced callers can use them directly.
- All session state is managed by the library. The caller implements zero storage code.
- Documentation must clearly distinguish the two layers. The session docs are the primary entry point; the primitives docs are the advanced reference.

## Revision history

- Original (pre-ADR-0014): session owned a flat `PairedList`; caller managed keypair bytes via `on_keypair_rotated`; `start_pairing()` / `accept_pair(noise_pub)` API.
- Updated after ADR-0014 (Group Manifest), ADR-0015 (two removal operations), ADR-0016 (embedded SQLite), ADR-0017 (local-first background connection): `PairedList` replaced by `GroupManifest`; keypair storage moved into the library; `on_keypair_rotated` removed; pairing API updated to `pairingToken()` / `acceptMember(token)`; `onConnectionChanged` added.
