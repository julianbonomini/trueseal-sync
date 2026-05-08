# hush-sync Scout Report

**Date:** 2026-05-09  
**Verdict:** Near-complete, but one real gap vs. the Manifesto (ADR-0018 partial wiring) and one piece of unfiled housekeeping. Not production-ready yet.

---

## 1. What Is Implemented

### Core modules

| File | What it does |
|------|-------------|
| `src/crypto.rs` | X25519 + HKDF-SHA256 + ChaCha20-Poly1305 addressed encryption. `author_pub` embedded in plaintext so relay never sees sender identity. |
| `src/envelope.rs` | Wire envelope: sequence, parents (DAG-ready), recipient_pub, Ed25519 signature over `(seq‖parents‖recipient_pub‖ciphertext)`. Protobuf encode/decode. |
| `src/manifest.rs` | `GroupManifest` with group_id, version, members, issuer, Ed25519 signature. `verify()` enforces version monotonicity and that issuer was a previous member. |
| `src/relay.rs` | `RelayClient<T>` — Noise XX receive session, push via channel to run loop. `push_send<T>` — standalone Noise NK anonymous push primitive (ADR-0018). |
| `src/session/mod.rs` | `HushSession<T>` — full opinionated facade: pairing, accept_pair, push_sync, remove_member, destroy_group, manifest filter, reconnect, callbacks. |
| `src/session/reconnect.rs` | Exponential backoff reconnect loop (cap 30 s), outbox replay on reconnect. |
| `src/store.rs` | SQLite-backed `Store` (identity + manifest + outbox) and `PersistentLog`. WAL mode. `wipe()` for destroy-group. |
| `src/ffi.rs` | UniFFI `HushFfiSession` — wraps `HushSession<TcpStream>`. Full callback surface: `onMessage`, `onRemovedFromGroup`, `onGroupDestroyed`, `onConnectionChanged`, `onMemberRequest`, `onMemberJoined`, `onMemberLeft`. Namespace validation. Auto keypair generation. Manifest restore on reopen. |
| `src/keys.rs` | Newtype wrappers `NoisePublicKey`, `SigningPublicKey`. |
| `src/device.rs` | `DeviceKeypair` (X25519 noise + Ed25519 signing). `generate()`, `from_bytes()`. |
| `src/member.rs` | Deterministic `member_id` and `member_name` from signing public key. |
| `src/message.rs` | Four message variants: `Pair`, `Sync`, `Revoke`, `GroupManifest`. Pairing token encode/decode. |
| `src/operation_log.rs` | `OperationLog` trait + `MemLog`. Outbox semantics. |
| `src/revocation.rs` | (Exists, helper logic around Revoke.) |

### Key exports (lib.rs pub use)
- `NoisePublicKey`, `SigningPublicKey`, `LogEntry`
- All modules public

### FFI surface (UniFFI → Swift / Kotlin)
`HushFfiSession` exposes: `create`, `pairing_token`, `join_group`, `set_on_member_request`, `accept_member`, `set_on_member_joined`, `set_on_member_left`, `cancel_pairing`, `members`, `remove_member`, `send`, `destroy_group`.

---

## 2. What Is Missing, Stubbed, or TODO'd

### Real gap — ADR-0018 not wired into session pushes

`push_send()` (Noise NK anonymous push, ADR-0018) exists in `relay.rs` and is tested in isolation (`nk_push.rs`). But `HushSession::push_sync` and `push_message` still call `self.client.push()` — which sends through the **same Noise XX receive session** used for subscribing. This means:

- The relay can observe that the device performing the receive handshake (identified by stable noise pub) is the same device sending the push blobs.
- ADR-0018's central promise — "the relay cannot link a Push Session to any Receive Session" — is **not met** in the session facade.

The primitive is implemented; the wiring is not. `push_send` is only called from tests, not from production code paths.

### Prototype notes file not cleaned up

`src/bin/NOTES.md` — a prototype for mutex error handling strategy — was never filled in (Decision section blank) and not deleted. The session itself does use `unwrap_or_else(|e| e.into_inner())` consistently (approach B), so the decision was made in practice but never documented. The file should be deleted.

### No blob size limit enforcement

ADR-0006 says the relay enforces a hard size limit (64KB–1MB TBD at implementation time). There is no enforcement in the library code. The relay (separate repo `hush-relay`) may enforce it, but the client does not validate blob size before push. If the relay enforces it, the client will see a push error with no meaningful error variant — no `BlobTooLarge` error variant exists.

### DAG multi-parent envelopes (v0 → v1 boundary)

The `Envelope` struct has a `parents: Vec<[u8;32]>` field and `build_chained` helper. ADR-0004 explicitly defers multi-parent DAG to v1. This is intentional and documented, not a bug. Every outbox replay passes `vec![]` as parents.

### No integration test against a real relay

All session tests use in-memory pipes (`MemPipe`) and a fake relay stub. There is no end-to-end test connecting to the actual `hush-relay` Go server. Correctness of the full NK push path (relay routing a NK-pushed envelope to an XX subscriber) is tested only via the fake relay in `nk_push.rs`.

---

## 3. Test Coverage

### Results
**175 tests, 0 failed** (2.5 s).

### What is covered

| Area | Coverage |
|------|----------|
| `crypto` | round-trip, wrong key, truncation, empty/large plaintext, author_pub embedding |
| `envelope` | build, verify, chain, tamper (payload + sequence), forgery rejection, multi-parent |
| `manifest` | create, sign, verify, version regression, unknown issuer, encode/decode |
| `store` / `PersistentLog` | open, wipe, identity, manifest, outbox CRUD, reopen persistence, max_sequence |
| `ffi` | namespace validation, invalid relay pub, independent namespaces |
| `session/push` | fanout to all members, drop if wrong key, envelope addressed correctly |
| `session/pairing` | `pairing_token`, `join_group`, `accept_pair`, cancel, window expiry |
| `session/accept_member` | token round-trip, `accept_member` admits and issues manifest |
| `session/manifest_filter` | discard from non-members, accept from members, version filter |
| `session/manifest_persist` | manifest restored across `connect_background` reopen |
| `session/outbox` | offline queue, replay on reconnect, survive crash, sequence not reused (ADR-0011) |
| `session/offline` | push while disconnected returns Ok, queues |
| `session/remove_member` | new manifest issued, removed device still receives it, future blobs discarded |
| `session/revocation` | `destroy_group` fires callback, stops outbox replay, unknown device revoke ignored |
| `session/connection` | `onConnectionChanged` fires true on connect, fires false then true on reconnect |
| `session/nk_push` | NK ephemeral keys differ per push, don't match stable key; on_message fires via XX after NK push |
| `session/member_events` | `onMemberJoined`, `onMemberLeft` |
| `session/panic_safety` | callback panic doesn't poison manifest mutex |

### What is not covered

- Session facade using NK push (wiring gap above) — no test exercises `push_sync` through an NK channel.
- No test validates that the relay *cannot* associate a push session with the receive session (the test in `nk_push.rs` validates the primitive only).
- No test for concurrent pushes from multiple threads.
- No test for pairing token expiry at the exact boundary (only "window closed" cases).
- No test for `set_on_member_request` callback not set when Pair arrives.
- No integration test against `hush-relay`.

---

## 4. Open GitHub Issues

```
gh issue list --repo julianbonomini/hush-sync
```

No output — either the repo is private/inaccessible, or there are no open issues.

---

## 5. Gaps vs. Manifesto Promises

| Manifesto promise | Status |
|-------------------|--------|
| **Zero trust / E2EE** | ✅ Addressed encryption via X25519+HKDF+ChaCha20-Poly1305. Relay sees only ciphertext. Author pub hidden inside ciphertext (ADR-0018 payload change done). |
| **Anonymity** | ⚠️ **Partial.** Author pub is correctly inside the ciphertext; the relay cannot read it. But push blobs are sent through the XX receive session — the relay still correlates the sender's stable noise key with every push. The NK primitive (`push_send`) exists but is not wired into the session. |
| **Fault tolerant / no single device is load-bearing** | ✅ Outbox replay on reconnect. PersistentLog survives crashes. Reconnect loop with backoff. `connect_background` starts offline. No device required to be online. |
| **Guaranteed delivery** | ✅ Outbox + replay on reconnect. Sequence counter not reused (ADR-0011). Blob queued if offline, replayed when connected. |
| **Embedded local storage** | ✅ SQLite via `Store` / `PersistentLog`. Caller writes zero storage code. Identity, manifest, outbox all managed. |
| **Outbox replay** | ✅ Tested end-to-end including simulated crash/restart. |
| **Dumb relay** | ✅ Relay stores/forwards encrypted blobs. Knows only `recipient_pub` per envelope and connected noise keys. No group knowledge. |
| **Identity = keypair** | ✅ Auto-generated on first launch, persisted to SQLite, never registered. |
| **No accounts / no registration** | ✅ |
| **Any member can remove / update manifest** | ✅ Any member can call `remove_member` or `destroy_group`. |
| **Soft Removal + Destroy Group** | ✅ Both implemented, tested, and documented (ADR-0015). |

---

## 6. Clarification Questions / Open Items

1. **ADR-0018 wiring**: Is wiring `push_send` (NK) into `HushSession::push_sync` / `push_message` a planned next step, or is this deliberately deferred? The primitive exists and is tested — it needs a second transport factory in the session for the push path. This is the most significant gap vs. the Manifesto's anonymity principle.

2. **Blob size limit**: When and where is the size limit enforced? Should the client validate before push and return a typed `BlobTooLarge` error? Or is this entirely the relay's responsibility?

3. **`src/bin/NOTES.md` cleanup**: The prototype notes file was never completed. Should it be deleted? The implementation chose approach B (`unwrap_or_else`) but the decision isn't recorded.

4. **UniFFI Swift/Kotlin bindings**: The `uniffi-bindgen.rs` binary exists. Have the generated Swift/Kotlin bindings been tested on device? The test surface is pure Rust.

5. **hush-relay compatibility**: Has the wire protocol been validated against the actual Go relay? The `push_send` NK path in particular depends on the relay implementing Noise NK acceptor logic — is that deployed?

6. **`revocation.rs`**: This file exists but its role isn't clear from a quick scan. Is it dead code, a helper, or a future primitive?

---

## Files Retrieved

1. `src/lib.rs` (full) — module declarations, pub exports
2. `src/ffi.rs` (full) — UniFFI surface, `HushFfiSession`, callback interfaces, storage bootstrap
3. `src/session/mod.rs` (full) — `HushSession`, `build_subscribe_handler`, reconnect wiring
4. `src/session/reconnect.rs` (full) — backoff loop, outbox replay
5. `src/crypto.rs` (full) — addressed encryption
6. `src/store.rs` (full) — SQLite store, PersistentLog
7. `src/relay.rs` (lines 1–340) — `RelayClient`, `push_send` NK primitive
8. `src/manifest.rs` (lines 1–80) — GroupManifest, verify
9. `src/session/tests/mod.rs`, `outbox.rs`, `nk_push.rs` — test coverage
10. `docs/adr/0018-anonymous-push-sessions-and-hidden-sender-identity.md` — ADR detail
11. `Cargo.toml`, `CONTEXT.md` — dependencies and domain language
