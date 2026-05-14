# hush-sync

E2EE sync engine for trusted device groups. Handles device identity, pairing, group membership, encrypted fan-out to all members, and guaranteed delivery across disconnects — without a server that can read any of it.

```
your app → hush-sync → hush-relay (dumb router; sees only ciphertext)
```

**Used by:** [hush-clip](../hush-clip-macos) (macOS) · [hush-clip iOS](../hush-clip-ios)  
**Part of:** [hush ecosystem](../docs)

---

## What you get

| | |
|---|---|
| **Device identity** | X25519 + Ed25519 keypair, auto-generated on first launch, persisted to SQLite. You never handle key bytes. |
| **Pairing** | Token-based ceremony. One device generates a token (encode as QR or share as text); the other calls `joinGroup(token)`. Library manages the Noise handshake. |
| **Group membership** | Signed, versioned `GroupManifest`. Any member can add or remove devices. Recipients verify the signature — the relay never sees it. |
| **Encrypted fan-out** | One envelope per recipient. ECDH + ChaCha20-Poly1305. Relay sees `recipient_pub` + ciphertext; sender identity is inside the ciphertext. |
| **Guaranteed delivery** | Outbox survives crashes and relay disconnects. Blobs queued offline replay automatically on reconnect — `send()` never silently drops. |
| **Auto-generated names** | Each device gets a deterministic two-word name (`AmberFalcon`, `SwiftHorizon`) derived from its public key. No configuration. |

**What you're responsible for:** what the bytes mean, conflict resolution, bootstrapping new members with historical state, and any permission hierarchy above "any current member can do anything."

---

## API surface

Two layers (ADR-0010):

### Session — use this

The opinionated facade. Wires everything together; owns relay connection, reconnect loop, manifest, and message dispatch. Exposed to Swift/Kotlin via UniFFI as `HushFfiSession`.

```
create(baseDir, namespace, relayHost, relayPub, callbacks)
  → always succeeds; relay connects in background

pairingToken()            → base64url string encoding your public keys
                            encode as QR or share as text; hand to the other device
joinGroup(token)          → joining device: decode initiator's token, push Pair message
setOnMemberRequest(cb)    → host: fires with (token, name) when a Pair message arrives
acceptMember(token)       → host: admit the pending device; issues a new GroupManifest
cancelPairing()           → close the pairing window without admitting anyone

send(blob)                → fan-out to all current group members
members()                 → [(id, name)] excluding the local device
localNodeId()             → stable opaque id for this device (base64url, 11 chars)
localDeviceName()         → auto-generated name for this device

removeMember(memberId)    → soft removal: issues new manifest excluding the device
destroyGroup()            → full reset: Revoke pushed to all members, local state wiped,
                            next create() generates a fresh identity
```

`namespace` scopes the SQLite database — one namespace, one group, one session. For multiple independent groups, create one session per namespace.

### Primitives — for advanced use

`DeviceKeypair`, `RelayClient`, `GroupManifest`, `OperationLog`, `Message`, `Envelope` — direct Rust, no lifecycle management. Useful for custom transports, testing harnesses, or integrations that can't use the session facade.

---

## Relay

You need a running [hush-relay](../hush-relay) instance and its static public key. Pass the hostname (no port — the session manages ports internally) and the 32-byte public key to `create()`. The relay is zero-knowledge: it routes ciphertext, holds blobs for offline recipients (30-day TTL), and learns nothing about group membership or message content. Self-host or use a shared instance.

---

## Swift / iOS / macOS

Use [hush-sync-swift](../hush-sync-swift). It wraps the compiled xcframework — no Rust toolchain required in your app project.

To rebuild the xcframework from this repo:

```sh
./scripts/build-xcframework.sh
```

---

## Build and test

```sh
cargo build
cargo test
```

The test suite runs fully in-process with in-memory transports — no relay or network required.

---

## Integration guide

[docs/integrating-hush-sync.md](docs/integrating-hush-sync.md) — concepts, edge cases, and hard-won platform notes from the macOS reference integration. Read this before building.

Full protocol documentation and architecture → [hush ecosystem docs](../docs)

---

## License

MIT
