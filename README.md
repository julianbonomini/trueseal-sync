# trueseal-sync

End-to-end encrypted sync engine for trusted device groups. Handles device identity, pairing, group membership, encrypted fan-out to all members, and at-least-once delivery across disconnects — the relay can't read or forge messages.

```
your app → trueseal-sync → trueseal-relay (stores and forwards ciphertext it cannot read)
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
- **Pairing** — one device opens a window and generates a Pairing Token (QR or text); the other calls `join(token)`. The token carries a single-use Pairing Secret, so the relay cannot raise join requests (ADR-0023). The library manages the Noise handshake underneath.
- **Group membership** — signed, versioned `GroupManifest`. Any current member can add or remove devices.
- **Encrypted fan-out** — one envelope per recipient. ECDH + ChaCha20-Poly1305. The relay sees `recipient_pub` + ciphertext; sender identity is inside the ciphertext.
- **At-least-once transport, with stated bounds** — the sender outbox survives crashes and relay disconnects and retries while connected; messages live up to 30 days (the relay TTL cap). Delivery is per-sender ordered and acked only after your handler finishes; the library deduplicates, so your handler never sees the same message twice. The bounds are real: a payload over 61,440 bytes is refused, a handler that keeps failing is eventually given up on, and every failure surfaces as a typed Delivery Issue — there is no silent loss, and there is no unconditional "guaranteed delivery".
- **Auto-generated device names** — deterministic two-word name (`AmberFalcon`, `SwiftHorizon`) derived from the device's public key. No configuration needed. Names are display **labels, not authentication** — never confirm a device by its name (ADR-0023).
- **Data at rest** — protected only by the OS sandbox, so the library keeps the footprint small: on iOS/macOS the store files are marked excluded from device/cloud backups at open (`store_is_excluded_from_backup`; Android and Node exclusion is SDK-side work tracked under SYNC-14 / the SDK-1 tasks — **not yet shipped**), and a sealed outbox body is deleted — zeroed and WAL-truncated — the moment the Relay accepts it (`accepted_outbox_entry_leaves_no_body_bytes_on_disk`, `unaccepted_entries_replay_after_restart`, `secure_delete_pragma_is_on`).

**You're responsible for:** what the bytes mean, conflict resolution, persisting received message IDs with application state, and bootstrapping new members with historical state.

---

## API surface

One canonical `TrueSeal` shape across the core and all three SDKs (ADR-0028). The SDKs add platform-idiomatic syntax over exactly these calls:

```
TrueSeal.open(relay, baseDir, namespace?, maxPayloadBytes?)
  → relay is one Relay Address string: trueseal://<relay public key hex>@host[:7700][?push=7701]
  → returns immediately; the relay connects in the background and send() works at once

onMessage(handler)        → THE awaited async message handler; registering starts receiving.
                            A blob is acked only after the handler completes
onEvent(listener)         → statusChanged, membersChanged, joinRequest, connectionChanged, …
onDeliveryIssue(listener) → optional typed reports (unreadable(reason), sendFailed, handlerGaveUp, …)
send(bytes)               → fan-out sealed + encrypted to all current members; returns a message ID

startPairing()            → base64url Pairing Token (keys + single-use Pairing Secret + name);
                            encode as QR or share as text. Opens the caller-controlled window
join(token)               → joining device: persists Pending Join and sends Pair via the outbox
accept(requestId)         → host: admit the requesting device; issues a new Group Manifest
cancelPairing() / cancelJoin()

status() / me() / members() / connection()
remove(memberId)          → issues a new manifest excluding the device
leave()                   → soft removal of this device; wipes group state, fresh identity
destroyGroup()            → durable forwarded Revoke to all members; local state wiped,
                            next open() starts over with a fresh identity
close()                   → stop connection and handlers; session state is kept
```

Errors are 14 typed cases — no catch-all. `namespace` scopes the SQLite database — one namespace, one group, one session. For multiple independent groups, open one session per namespace. The full reference with events, statuses and error cases is the generated [api-surface.json](docs/api-surface.json) and [shared-facts.json](docs/shared-facts.json).

---

## Security at a glance

- **End-to-end encrypted.** The relay can't read or forge messages: payloads are sealed and encrypted device-to-device, and every envelope is signed; the signature, sequence and sender timestamp sit inside the ciphertext (ADR-0031).
- **Here is exactly what the relay does see:** which device keys are online and when, the recipient key and size of each blob, timing, fan-out shape (one send reaches all members together — the relay can infer likely co-membership, ADR-0024), and the End-to-End Version. It never logs, stores or uses IP addresses; the server it runs on still sees the connection, as with any internet service.
- **Pairing trust:** the joiner trusts only the signing key inside the token; a single-use Pairing Secret means the relay cannot raise join requests; the first Group Manifest is gated on the token's key (ADR-0023). Member **names are labels, not authentication** — there is no SAS yet, so a photographed token can be used while the window is open; confirm the device in front of you before accepting.
- **Data at rest:** protected only by the OS sandbox (encryption at rest is 1.0 work). The library keeps the footprint small — see "What you get" above for exactly what is tested.
- **Not defended against / not yet:** end-to-end forward secrecy (2.0 candidate), an independent audit, network-level IP hiding.

Every claim above is backed by tests; the canonical claims table with its evidence lives on the Threat Model page at [trueseal.dev](https://trueseal.dev) ([trueseal-docs](../trueseal-docs)).

## Relay

You need a running [trueseal-relay](../trueseal-relay). Name it with one Relay Address string — `trueseal://<relay public key hex>@host` — and pass it to `open()`. The relay stores and forwards ciphertext it cannot read, holds blobs for offline recipients (30-day TTL cap), and has no concept of group membership.

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

Apache-2.0
