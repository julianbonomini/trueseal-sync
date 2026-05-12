# Integrating hush-sync into a client app

A living guide. Each section captures decisions made during real integration work.
Update this file whenever a new integration question is resolved.

---

## 1. What hush-sync is (and isn't)

hush-sync is a **group messaging primitive**. It gives you:

- A stable device identity (X25519 + Ed25519 keypair, persisted to SQLite)
- Encrypted delivery of arbitrary blobs to all group members via a relay
- A pairing ceremony to add devices to the group
- Outbox replay so messages sent offline are delivered when the relay reconnects

It does **not** give you:

- Knowledge of whether a peer device is online
- Message history on the relay (TTL-based delivery only)
- Multi-group management (one namespace = one group)
- A "leave group" protocol message (see §6)

---

## 2. Swift SDK surface (hush-sync-swift)

The public API is `HushSyncClient`. All FFI types are hidden behind
`@_implementationOnly import HushSyncBindings`. Never import `HushSyncBindings`
directly from your app.

### Construction

```swift
let client = try HushSyncClient(
    relayURL: URL(string: "tcp://localhost:7700")!,
    relayPublicKey: Data([/* 32-byte X25519 pubkey from relay keypair.hex */]),
    storageDirectory: appScopedStorageURL,  // see §3
    namespace: "default"                    // see §4
)
```

**Construction is infallible with respect to relay connectivity.** The client
starts offline and reconnects automatically. A throw here means bad arguments or
corrupt storage — treat it as a fatal developer error (`fatalError()`), not a
runtime condition.

### Async streams (consume on a background Task, update UI on MainActor)

```swift
client.blobs            // AsyncStream<ReceivedBlob>  — incoming payloads
client.connectionState  // AsyncStream<ConnectionState> — .connected / .disconnected
client.memberEvents     // AsyncStream<MemberEvent>   — joined / left / removedSelf / groupDestroyed
client.pairingRequests  // AsyncStream<PairingRequest> — incoming pair requests
```

### Key methods

```swift
client.generatePairingToken() -> String        // stable — see §5
client.joinGroup(token: String) throws         // join side of pairing
client.acceptPairingRequest(_ r: PairingRequest) // host side of pairing
client.removeMember(_ m: SyncMember) throws    // kick a device
client.destroyGroup()                          // nuclear exit — see §6
client.publish(text: String) async throws      // send a UTF-8 blob
client.members -> [SyncMember]                 // current manifest snapshot
```

---

## 3. Storage: always scope to your app

**Never use the default `storageDirectory`** (`Application Support/HushSync/`).
It is shared across all hush-sync consumers on the same machine. Two apps using
the default would share a group identity and clip history.

```swift
// Correct
let storage = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)
    .first!
    .appendingPathComponent("your-app-name/HushSync", isDirectory: true)
try FileManager.default.createDirectory(at: storage, withIntermediateDirectories: true)

let client = try HushSyncClient(relayURL: ..., relayPublicKey: ..., storageDirectory: storage)
```

---

## 4. Namespace: one group per namespace

`namespace: "default"` is the right choice for single-group apps. A device
belongs to exactly one group per namespace. Multi-group requires multiple
`HushSyncClient` instances with different namespaces — manage that yourself.

---

## 5. The pairing token is stable — do not regenerate it

The FFI docstring for `pairing_token()` says "opens a 60-second pairing window"
— **this is misleading.** The token is a deterministic base64url encoding of the
device's permanent public keys:

```
base64url(noise_pub[32] || signing_pub[32] || device_name_utf8)
```

It never changes for a given device. Call `generatePairingToken()` once (e.g. on
`SyncService` init) and cache it. You can show it in a QR code or copy it to the
clipboard any time without side effects.

**The 60-second window is acceptance-side only.** It opens when another device
calls `joinGroup(token:)` — i.e. when a `Pair` message arrives at your session.
You then have 60 seconds to call `acceptPairingRequest`. The window has nothing
to do with token generation.

### Pairing ceremony — roles and sequence

```
Device A (host)          relay          Device B (joiner)
─────────────────────────────────────────────────────────
generatePairingToken()
  → share token OOB (QR, copy/paste)
                                         joinGroup(token)
                                           → Pair message →
← onMemberRequest(token, name)
acceptPairingRequest(request)
  → manifest update →
← .joined(member)                       ← .joined(member)
```

**A = the device whose QR was scanned / token was pasted.**
**B = the device that initiated by calling `joinGroup`.**

In a macOS app where you show a QR for an iOS device to scan: macOS is A, iOS is B.
In a macOS-to-macOS scenario where device B pastes A's token: same roles.

---

## 6. Group exit: destroy vs leave

### Destroy group (first-class protocol primitive)

```swift
client.destroyGroup()
```

Sends a `Revoke` message to all members via the relay, wipes local state, and
makes the session terminal (all subsequent `send()` calls return `GroupDestroyed`).
All devices receive a `.groupDestroyed` MemberEvent and their sessions wipe too.

**After `destroyGroup()`, the session is dead.** Auto-reinit by:
1. Cancelling all listener Tasks
2. Deleting the storage directory (`FileManager.default.removeItem(at: storage)`)
3. Reconstructing `HushSyncClient` — fresh keys, SOLO mode

### Leave group (no protocol primitive in v1)

There is no "leave quietly" message. If you want to remove yourself without
destroying the group for others, your only option is a local key rotation:
delete storage + reinit. Your old ID remains as a ghost member in other devices'
manifests — they see you in the member list but will never receive a message from
your new identity. This is a known limitation; a graceful leave protocol may be
added in a future hush-sync version.

---

## 7. Connection state: two signals, not one

`ConnectionState` is TCP-only. `.connected` means the relay is reachable.
It says **nothing** about peer reachability — you never know if another device
is online. The relay handles delivery; the app should never gate on peer state.

Model connection state as two independent signals in your UI:

| Signal | Source | Values |
|--------|--------|--------|
| Relay status | `connectionState` stream | `RELAY: CONNECTED` / `RELAY: OFFLINE` |
| Group status | `members.count` | `GROUP: SOLO` / `GROUP: N DEVICES` |

Never conflate them into a single "SYNC: OK" indicator — they answer different
questions.

---

## 8. Relay offline is a no-op for the app

If the relay is unreachable at launch or drops mid-session:
- `connectionState` emits `.disconnected`
- hush-sync queues outbound messages in the SQLite outbox
- hush-sync reconnects automatically — no app-level retry logic needed
- The app shows `RELAY: OFFLINE` and does nothing else

**Do not write reconnect logic.** The library owns reconnection.

---

## 9. Relay public key

The relay's X25519 public key is derived from its private key in `keypair.hex`.
To get it: run the relay binary with `-genkey` and it prints:

```
relay public key (share with clients): <64-hex-chars>
```

Decode the 64-char hex string into 32 bytes for `relayPublicKey: Data`.

The relay listens on two ports:
- `:7700` — XX receive sessions (device ↔ relay) — **use this as your relay URL**
- `:7701` — NK push sessions (internal hush-sync → relay push)

Your `relayURL` should be `tcp://host:7700`.

---

## 10. SDK source fixes (v0.0.5 xcframework)

The hush-sync-swift v0.0.5 Swift wrapper has three mismatches against the actual
FFI bindings in `HushSyncFFI.xcframework`. Apply these fixes if building from
source:

### `CallbackBridges.swift` — `onMessage` signature

```swift
// Wrong (v0.0.5 source):
func onMessage(blob: [UInt8], senderNoisePub: [UInt8])

// Correct (matches xcframework FFI):
func onMessage(blob: Data, senderNoisePub: Data)
// Also remove the Data(...) wrappers in the body — they're already Data
```

### `HushSyncClient.swift` — `send(blob:)` signature

```swift
// Wrong:
let bytes: [UInt8] = Array(data)
try session.send(blob: bytes)

// Correct:
try session.send(blob: data)
```

### `HushSyncError.swift` — missing import

```swift
// Add at the top:
@_implementationOnly import HushSyncBindings
// (Required for SessionError to be in scope for the init(from:) converter)
```

### `HushSyncClient.swift` — `defaultHushSyncStorage` visibility

```swift
// Change:
private extension URL {
// To:
public extension URL {
// (Required because it's used as a default argument value in a public initialiser)
```
