# trueseal-sync

E2EE sync engine for trusted device groups. Handles device identity, pairing, group membership, encrypted fan-out to all members, and guaranteed delivery across disconnects — without a server that can read any of it.

```
your app → trueseal-sync → trueseal-relay (dumb router; sees only ciphertext)
```

---

## SDKs

| Platform | Repo | Status |
|---|---|---|
| Swift (iOS + macOS) | [trueseal-sync-swift](../trueseal-sync-swift) | ✅ Available |
| Kotlin (Android) | [trueseal-sync-kotlin](../trueseal-sync-kotlin) | ✅ Available |
| TypeScript / Node | [trueseal-sync-ts](../trueseal-sync-ts) | ✅ Available |
| Rust (direct) | this repo | ✅ Available |

The SDKs wrap the compiled native library via UniFFI — no Rust toolchain required in your app project.

---

## What you get

- **Device identity** — X25519 + Ed25519 keypair, auto-generated on first launch, persisted to SQLite. You never handle key bytes.
- **Pairing** — one device generates a token (QR or text); the other calls `joinGroup(token)`. Library manages the Noise handshake underneath.
- **Group membership** — signed, versioned `GroupManifest`. Any current member can add or remove devices.
- **Encrypted fan-out** — one envelope per recipient. ECDH + ChaCha20-Poly1305. The relay sees `recipient_pub` + ciphertext; sender identity is inside the ciphertext.
- **Guaranteed delivery** — outbox survives crashes and relay disconnects. Blobs queued offline replay on reconnect. `send()` never silently drops.
- **Auto-generated device names** — deterministic two-word name (`AmberFalcon`, `SwiftHorizon`) derived from the device's public key. No configuration needed.

**You're responsible for:** what the bytes mean, conflict resolution, and bootstrapping new members with historical state.

---

## API surface

```
create(baseDir, namespace, relayHost, relayPub, callbacks)
  → always succeeds; relay connects in the background

pairingToken()            → base64url token encoding your public keys
                            encode as QR or share as text
joinGroup(token)          → joining device: decode and push Pair message to initiator
setOnMemberRequest(cb)    → host: fires (token, name) when a joining device is waiting
acceptMember(token)       → host: admit the device; issues a new GroupManifest
cancelPairing()           → close the window without admitting anyone

send(blob)                → fan-out encrypted to all current members
members()                 → [(id, name)] excluding the local device
localNodeId()             → stable opaque id for this device (11-char base64url)
localDeviceName()         → auto-generated name for this device

removeMember(memberId)    → soft removal; issues new manifest excluding the device
destroyGroup()            → full reset: Revoke to all members, local state wiped,
                            next create() auto-generates a fresh identity
```

`namespace` scopes the SQLite database — one namespace, one group, one session. For multiple independent groups, create one session per namespace.

---

## Relay

You need a running [trueseal-relay](../trueseal-relay) and its static public key. Pass the hostname and the 32-byte public key to `create()`. The relay is zero-knowledge: it routes ciphertext, holds blobs for offline recipients (30-day TTL), and has no concept of group membership.

---

## Building from source

```sh
cargo build
cargo test        # runs fully in-process; no relay or network required
```

To build the xcframework for Swift:

```sh
cd ../trueseal-sync-swift
./scripts/build-xcframework.sh
```

---

## Integration guide

[docs/integrating-trueseal-sync.md](docs/integrating-trueseal-sync.md) — design decisions, edge cases, and platform notes from the reference integration.

Ecosystem overview and full protocol documentation → **[trueseal-docs](../docs)**

---

## License

MIT
