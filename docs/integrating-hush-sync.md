# Integrating hush-sync — Concepts & Implementation Guide

A living document. Captures every design decision, edge case, and hard-won
lesson from the macOS reference integration. Platform-specific notes are
isolated in §12 so the conceptual sections remain usable from any client
(Swift/iOS, Swift/macOS, Kotlin, TypeScript, etc.).

Update this file whenever a new integration question is resolved.

---

## 1. What hush-sync is (and isn't)

hush-sync is a **group messaging primitive**. It gives you:

- A stable device identity (X25519 + Ed25519 keypair, persisted to SQLite)
- Encrypted delivery of arbitrary binary blobs to all group members via a relay
- A pairing ceremony to add devices to a group
- Outbox replay — messages sent offline are delivered when the relay reconnects
- Deterministic, human-readable device names derived from public keys

It does **not** give you:

- Knowledge of whether a peer device is online
- Message history on the relay (TTL-based delivery only)
- Multi-group management (one namespace = one group per session)
- A "leave group" protocol message (see §9)
- Payload typing, ordering guarantees beyond FIFO per sender, or deduplication
  (all of these are the caller's responsibility)

---

## 2. Device identity

Every hush-sync session has a **permanent identity** consisting of two keypairs:

| Keypair | Algorithm | Purpose |
|---------|-----------|---------|
| Noise keypair | X25519 | Transport encryption (Noise XX / NK handshakes) |
| Signing keypair | Ed25519 | Message authentication, member identification |

Both keypairs are generated once and persisted to SQLite under the storage
directory. They survive app restarts and relay reconnections. They are destroyed
only by `destroyGroup()` or manual storage deletion.

### Device name

Every device has a **human-readable name** derived deterministically from the
first two bytes of its Ed25519 signing public key:

```
name = ADJECTIVES[signing_pub[0] % len(ADJECTIVES)]
     + NOUNS[signing_pub[1]      % len(NOUNS)]
```

Example outputs: `FreeMap`, `SwiftHorizon`, `AmberFalcon`.

The word lists live in `hush-sync/src/member.rs`. The name is stable for the
lifetime of the keypair — it changes only if the keypair is rotated
(i.e. after `destroyGroup()`).

### Node ID

The opaque stable identifier for a member is base64url(signing_pub[0..8])
— 11 characters, no padding. Used to key membership maps and remove requests.

### Accessing local identity

The SDK exposes the local device's name and ID directly via `localDeviceName`
and `localNodeId`. For remote members both fields come from the member manifest.

**Do not re-implement the name derivation in your app.** Expose it from the SDK
so all clients stay in sync with the word lists.

---

## 3. The relay

### Architecture

The relay is a stateless message broker. It does not store messages beyond
a short TTL. It authenticates devices via the Noise protocol and forwards
encrypted blobs to group members.

The relay listens on **two ports** for different Noise handshake patterns:

| Port | Pattern | Used for |
|------|---------|----------|
| `:7700` | XX (mutual auth) | Device ↔ relay sessions |
| `:7701` | NK (server-only auth) | Internal hush-sync push channel |

**Your `relayURL` should always point to `:7700`.** The `:7701` port is managed
internally by hush-sync; never reference it in app code.

### Relay public key

The relay's X25519 public key is derived from its private key in `keypair.hex`.
To obtain it, run the relay binary with `-genkey`:

```
relay public key (share with clients): <64-hex-chars>
```

Decode the 64-char hex string into 32 bytes and pass it to the SDK constructor.
This is a **build-time constant** for the app — it never changes at runtime and
should not be user-configurable.

### Relay is a no-op when offline

If the relay is unreachable at launch or drops mid-session:
- The SDK emits a disconnected connection state event
- Outbound messages queue in the local SQLite outbox
- The SDK reconnects automatically — **write no reconnect logic**
- The app shows `RELAY: OFFLINE` and does nothing else

The relay being offline is a normal operating condition, not an error.

---

## 4. Session lifecycle

### Initialisation

Construct one session per app lifecycle. Initialisation:
1. Reads or generates the keypair from storage
2. Begins connecting to the relay in the background
3. Returns immediately — does not block on relay connectivity

**A throw at init time is a developer/deployment error** (bad arguments, corrupt
storage, permission denied). Treat it as fatal — there is no meaningful recovery
path. Do not wrap in a retry loop.

### The session is a singleton

Instantiate once at app startup and keep it for the app's lifetime. There is no
meaningful "restart session" other than `destroyGroup()` + reinit (see §9).

### Startup sequence

On every boot, before connecting to the relay:

1. Seed your member list from the session's `members()` snapshot — these are
   devices that were already in the group when the app last ran
2. Start listening to the member events stream
3. Start listening to the connection state stream
4. Start listening to the blobs stream
5. Start listening to the pairing requests stream (if offering pairing)

The order matters: seed first so you never show an empty member list when you
already have members.

### Disposal

Sessions do not need explicit cleanup in normal operation. On app exit the
OS reclaims the connection. The only reason to dispose a session explicitly is
before calling `destroyGroup()` (see §9).

---

## 5. Pairing

### The token

The pairing token is a base64url string encoding the device's permanent public
keys:

```
base64url(noise_pub[32] || signing_pub[32] || device_name_utf8)
```

It is **stable for the lifetime of the keypair**. Generate it once and cache it.
Showing the token in a QR code, displaying it as text, or copying it to the
clipboard has no side effects.

> **Note:** Early hush-sync documentation described `pairingToken()` as
> "opening a 60-second pairing window". This is misleading. The token is
> deterministic and stateless. The acceptance window (if any) is a UX concern
> on the accepting side, not tied to token generation.

### Roles

| Role | Action | Also called |
|------|--------|-------------|
| **Host (A)** | Generates and shares the token | "accepts requests" |
| **Joiner (B)** | Receives the token OOB and calls `joinGroup(token)` | "knocks" |

In a macOS + iOS scenario where the macOS app shows a QR and the iOS app scans
it: **macOS is A, iOS is B**.

In a macOS + macOS scenario where device B pastes A's token: same roles.

### Ceremony sequence

```
Device A (host)               relay             Device B (joiner)
─────────────────────────────────────────────────────────────────
generatePairingToken()
  → show QR / share OOB
                                                joinGroup(token)
                                                  → Pair message →
← pairingRequest event
  (deviceName, token)
acceptPairingRequest(request)
  → manifest update →
← memberJoined(id, name)                       ← memberJoined(id, name)
```

### Acceptance window UX

The acceptance window (the period during which A can accept B's knock) is
**caller-controlled in the app layer**, not enforced by the protocol.
Design recommendations from the macOS integration:

- **Open on demand**: show a "ACCEPTING PAIR REQUESTS" state with an explicit
  OPEN/CLOSE button. Never auto-open without user intent.
- **No auto-expiry**: do not auto-close the window on a timer. The user should
  decide when to stop accepting. Auto-expiry causes silent drops where B knocks
  but A's window closed before the user could respond.
- **Single-use**: once a request is accepted, call `cancelPairing()` to close
  the window. The next pairing requires a fresh token call.
- **Incoming request UI**: show a prominent banner with the device name and
  ACCEPT / IGNORE. A countdown timer is a useful visual affordance but should
  not auto-dismiss — let the user decide.

### Cancelling

`cancelPairing()` closes the acceptance window without accepting. Call it:
- When the user explicitly closes the pairing UI
- When the view that shows the pairing UI disappears
- Immediately after accepting a request (single-use semantic)

---

## 6. Publishing and receiving

### Publishing

Send arbitrary binary blobs to all group members:

```
session.publish(blob)   // raw bytes
session.publish(text)   // convenience: UTF-8 encode then publish
```

Publishing is fire-and-forget from the app's perspective. If the relay is
offline, the message queues in the outbox and delivers automatically on
reconnection. There is no per-message delivery confirmation.

### Receiving

Incoming blobs arrive on the blob stream as events containing:
- `data`: the raw payload bytes
- `senderNoisePub`: the sender's X25519 public key (32 bytes)

**The blob stream may fire for your own messages** depending on relay
implementation. Implement deduplication at the app layer (e.g. content hash
check against local storage) rather than relying on the transport to filter
self-sent messages.

### Sync semantics: broadcast-each

The recommended pattern for clipboard sync and similar single-value streams:

- On every new item, broadcast it immediately to the group
- **Do not diff** — broadcast the full item every time
- **Dedup at the receiver** — if the content already exists in local storage, drop it
- The outbox replay handles out-of-order / late delivery

This is simpler and more robust than delta-sync or last-write-wins schemes for
the access patterns of a clipboard manager.

---

## 7. Member management

### The member manifest

`session.members()` returns a snapshot of current group membership.
**It excludes the local device** — you will never see yourself in this list.

The manifest is the source of truth for membership. On every member event
(joined or left), re-snapshot from `members()` rather than maintaining a
local delta. This avoids missed events from race conditions.

### Member events

| Event | Meaning |
|-------|---------|
| `memberJoined(id, name)` | A new device joined the group |
| `memberLeft(id, name)` | A member was removed |
| `removedFromGroup` | **You** were removed from the group by another member |
| `groupDestroyed` | The group was destroyed by a member calling `destroyGroup()` |

`removedFromGroup` and `groupDestroyed` require special handling — see §9.

### Removing a member

```
session.removeMember(memberId)
```

The removed device receives a `removedFromGroup` event. The removal is
immediately reflected in `members()`.

### Local identity in the UI

Since the local device is excluded from `members()`, display it separately in
the UI with explicit "THIS DEVICE" / local labelling. Use `localDeviceName` and
`localNodeId` from the SDK — do not re-derive them.

---

## 8. Connection and group state

Model these as **two independent signals**. Never conflate them.

| Signal | Source | UI representation |
|--------|--------|-------------------|
| Relay connectivity | connection state stream | `RELAY: CONNECTED` / `RELAY: OFFLINE` |
| Group membership | `members()` count | `GROUP: SOLO` / `GROUP: N DEVICES` |

`RELAY: CONNECTED` + `GROUP: SOLO` is a valid steady state (the app is working,
just not paired with anyone).

`RELAY: OFFLINE` + `GROUP: N DEVICES` is also valid (paired, relay temporarily
unreachable, outbox will replay on reconnection).

**Never show "you cannot sync" based on relay state alone.** The relay being
offline is transient; the group relationship is persistent.

---

## 9. Group exit

### Destroy group

`destroyGroup()` is a **first-class protocol primitive**:
1. Sends a `Revoke` message to all members via the relay
2. All devices (including caller) receive a `groupDestroyed` event
3. All sessions wipe their local state
4. The session becomes terminal — all subsequent publish calls fail

After `groupDestroyed` fires on any device:
1. Stop all stream listeners
2. Delete the storage directory
3. Reinitialise the session — fresh keypair, new identity, SOLO mode

### Leave group (no protocol primitive)

There is no "leave quietly" message. To remove yourself without destroying the
group for others:
1. Delete local storage + reinit (rotate your keypair)
2. Your old ID becomes a ghost member in other devices' manifests
3. Other devices must manually remove the ghost entry

This is a known limitation. A graceful leave protocol may be added in a future
hush-sync version.

---

## 10. Testing

### Never use the real session in unit tests

The real session opens TCP connections, runs a Rust runtime, and has a
known global destructor double-free bug at test process teardown. Unit tests
must use a **null implementation** of the sync service protocol.

The pattern:
1. Define a `SyncServiceProtocol` interface covering every method and property
   the app touches (`publish`, `members`, `isRelayConnected`, `localDeviceName`,
   `localNodeId`, etc.)
2. Implement `NullSyncService` conforming to the protocol — in-memory,
   synchronous, no threads, no FFI
3. Inject the protocol at construction time for all ViewModels and services
4. Inject `NullSyncService` in unit tests; inject the real implementation in
   the live app

This pattern also enables UI previews and simulator runs without a running relay.

### Integration tests

Tests that actually exercise the FFI should run as separate processes or with
careful teardown, due to the global destructor crash. Document this prominently
so future contributors do not add FFI calls to the unit test suite.

---

## 11. Storage

### Always scope to your app

Never use the SDK's default storage path — it may be shared across all hush-sync
consumers on the same machine. Two apps using the same storage path would share
a group identity.

Recommended path pattern:

```
<platform app support dir>/<your-app-bundle-id>/HushSync/
```

Create the directory before passing it to the SDK constructor.

### Key rotation

Deleting the storage directory and reinitialising the session gives the device a
fresh keypair and a new identity. This is the correct implementation of both
"destroy group + rejoin" and "leave group quietly" flows.

---

## 12. Platform-specific notes

### Swift (iOS + macOS)

#### SDK structure

The Swift SDK (`hush-sync-swift`) wraps the Rust FFI (`HushSyncFFI.xcframework`)
behind a clean public module `HushSync`. Never import `HushSyncBindings` directly
from app code.

#### Construction

```swift
let client = try HushSyncClient(
    relayURL: URL(string: "tcp://relay-host:7700")!,
    relayPublicKey: Data([/* 32-byte key */]),
    storageDirectory: appScopedStorageURL,
    namespace: "default"
)
```

#### Consuming streams

Async streams must be consumed on `Task` instances. Bridge to `@MainActor` /
`@Published` for UI updates:

```swift
Task {
    for await state in client.connectionState {
        await MainActor.run { self.isRelayConnected = (state == .connected) }
    }
}
```

#### Local identity

```swift
client.localDeviceName   // e.g. "FreeMap"
client.localNodeId       // e.g. "aB3xK9qR2mN"
```

Both are synchronous computed properties — safe to call on any thread.

#### Non-blocking sockets (critical)

The Rust TCP transport factories must have non-blocking mode enabled. If you
build hush-sync from source and sockets are blocking, the connection mutex will
be held during `read()`, starving concurrent sends — manifesting as pairing
messages that never arrive. The fix is `set_nonblocking(true)` on both transport
factory implementations in `ffi.rs`. This was the root cause of all pairing
failures in the macOS integration.

#### Entitlements

```xml
<key>com.apple.security.network.client</key>
<true/>
```

Required for any outbound TCP connection on both macOS (sandboxed) and iOS.
Without it the relay connection silently fails with no useful error message.

#### iOS-specific: background connectivity

On iOS, TCP connections are suspended when the app backgrounds. Plan for:
- `connectionState` emitting `.disconnected` on background
- The outbox replaying on next foreground + reconnection
- Not surfacing `RELAY: OFFLINE` as a user-facing error while backgrounded

Use `beginBackgroundTask` if you need a short window to finish an in-flight
publish before suspension.

#### macOS-specific: menu bar apps

For a `LSUIElement = YES` menu bar app that also has a main window:
- Use `NSApp.setActivationPolicy(.regular)` when the main window opens
- Use `NSApp.setActivationPolicy(.accessory)` when it closes
- This gives a Dock icon only while the window is visible

#### Known issues

**Rust global destructor double-free**: the Rust runtime crashes at test process
teardown when the static FFI object is freed twice. This is a known issue in the
xcframework binary. Do not use real `HushSyncClient` instances in unit tests
(see §10).

### ADRs from the macOS reference integration

Recorded in `hush-clip-macos/docs/adr/` — relevant to any client:

| ADR | Decision |
|-----|----------|
| 0001 | SQLite directly for local storage (no ORM) |
| 0002 | Broadcast-each-clip; outbox replay handles delivery |
| 0003 | Dedup at view/receive layer; sync always broadcasts |
| 0004 | Relay URL + pubkey are build-time constants, not user-configurable |
| 0005 | Click-to-copy only; no auto-paste on selection |
| 0006 | Session init failure is fatal; storage scoped to app |
| 0021 | Pairing window is caller-controlled; no auto-expiry |
