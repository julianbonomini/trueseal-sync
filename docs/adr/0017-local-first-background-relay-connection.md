# Local-first: create() never fails on connectivity; relay connects in background

## Context

The library needs a relay connection to deliver blobs to other devices. The question is whether that connection is a prerequisite for the session to be usable, or whether the session is fully functional offline and the relay is background infrastructure.

Two approaches were considered:

1. **Fail-fast**: `create()` attempts a relay connection synchronously. If the relay is unreachable, `create()` returns an error. The caller must handle this and retry.
2. **Local-first**: `create()` always succeeds immediately by restoring state from SQLite. The relay connection is established in the background. The session is fully functional offline.

## Decision

`create()` is infallible with respect to connectivity. It restores session state from the local SQLite database and returns a live session object immediately, regardless of relay availability. The relay connection is attempted in the background by the existing reconnect loop.

All operations work offline:
- `send(blob:)` — appends to the outbox. Delivered when the relay connects.
- `members()` — reads from the local manifest. Always available.
- `pairingToken()` — generates from the local keypair. Always available.
- `removeMember()` / `destroyGroup()` — updates local state immediately, propagates when connected.

A new `onConnectionChanged(connected: Bool)` callback notifies the caller of relay connectivity changes. This is informational — the library behaves correctly whether or not the caller listens to it.

The relay URL and public key are passed at every `create()` call. They are not persisted in SQLite. This means a relay migration requires only a new app build with the updated values — no database migration, no user action.

## Consequences

- `create()` returns a non-optional session on all platforms. No connectivity error to handle at construction time.
- Blobs sent while offline are guaranteed to be delivered on reconnect via the outbox (ADR-0012, ADR-0016).
- The only errors `create()` can return are programmer errors: invalid `relayPublicKey` length, invalid `namespace` characters. Not runtime conditions.
- Callers who want to show a "syncing" or "offline" indicator use `onConnectionChanged`. Callers who don't care ignore it.
- Relay switchover is the caller's responsibility. The library uses whatever URL and key are passed at construction — always current, never stale.

## Considered alternatives

**Fail-fast on connectivity**
Rejected. Forces the caller to handle a connectivity error at app launch — a common condition on mobile (airplane mode, poor signal, cold start before network is available). Pushes retry logic to the caller. Incompatible with the local-first principle. Makes the library useless on first launch in poor connectivity conditions despite having valid local state.
