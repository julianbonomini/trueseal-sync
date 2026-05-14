# Ecosystem Scout — trueseal

## 1. Ecosystem Map

### Components and Roles

| Component | Language | Role | Build State |
|---|---|---|---|
| **trueseal-noise** | Rust (+ UniFFI) | Noise Protocol transport layer. Implements `Noise_XX` (mutual auth) and `Noise_NK` (anonymous sender). Standalone lib, spec-verified against cacophony test vectors. | **Built** — `rust/src/` has full implementation (cipher, framing, session_xx, session_nk, keypair, handshake) |
| **trueseal-sync** | Rust (+ UniFFI + C FFI) | E2EE sync engine. Protocol authority: owns Envelope format, addressed encryption, pairing, Group Manifest, Operation Log, outbox replay. Two-layer API: primitives + `TruesealSession` facade. UniFFI exposes to Swift/Kotlin. | **Built** — `src/` has crypto, device, envelope, manifest, member, message, operation_log, relay, revocation, session/ (with reconnect, tests) |
| **trueseal-relay** | Go | Dumb blob router. Accepts Noise XX sessions, routes encrypted blobs to recipient Inboxes, defers delivery for offline devices, TTL-reaps undelivered blobs. Never decrypts. | **Documented only** — repo has CONTEXT.md + 5 ADRs, zero Go source files |
| **trueseal-clip** | Unknown | First consumer app (cross-platform clipboard). Proof the stack works end-to-end. Origin of the whole ecosystem. | **Placeholder only** — repo has only `mempalace.yaml` |
| **trueseal-secrets** | Unknown | Secret-sharing consumer app. Mempalace room defined. | **Placeholder only** — repo has only `mempalace.yaml` |

### Dependency Graph

```
trueseal-clip / trueseal-secrets
        ↓ (imports)
    trueseal-sync  ←──────── (wire format authority)
        ↓                              ↓
   trueseal-noise                     trueseal-relay
   (transport)                    (infrastructure)
```

- `trueseal-relay` has no trueseal-sync dependency at code level — it implements against the wire format (Protobuf Envelopes) that trueseal-sync owns.
- `trueseal-noise` is embedded inside trueseal-sync as a Rust re-implementation (the Go original powers trueseal-relay).
- All application-layer consumers (trueseal-clip, trueseal-secrets, third-party) sit above trueseal-sync.

---

## 2. trueseal-sync's Defined Contract / Interface

### Session API (UniFFI surface — Swift / Kotlin)

```swift
TruesealFfiSession.create(
    baseDir: String,
    namespace: String,            // default "default"
    relayAddr: String,            // "host:port"
    relayPub: Data,               // 32-byte X25519
    onMessage: MessageCallback,
    onRemovedFromGroup: callback,
    onGroupDestroyed: callback,
    onConnectionChanged: callback?
) throws -> TruesealFfiSession

// Pairing
session.pairingToken() -> String
session.joinGroup(token: String)
session.setOnMemberRequest(callback)           // fires (token, name)
session.acceptMember(token: String) -> Bool
session.cancelPairing()

// Membership
session.members() -> [Member]
session.removeMember(memberId: String)         // soft removal
session.destroyGroup()                         // cryptographic reset

// Sync
session.send(blob: Data)                       // fans out to all members
```

### What callers receive
- Inbound blobs decrypted and verified before `onMessage` fires
- `onMemberJoined` / `onMemberLeft` / `onRemovedFromGroup` / `onGroupDestroyed` lifecycle callbacks
- `create()` is infallible w.r.t. connectivity (ADR-0017); relay connects in background
- Zero storage code for the caller — library manages identity, manifest, outbox in embedded SQLite

### Protocol guarantees trueseal-sync makes
- Every `send()` blob reaches every current group member, eventually (outbox replay + relay deferred delivery)
- Blobs are signed by sender's Ed25519 key; signature covers `sequence || parents || recipient_pub || ciphertext`
- Sender identity (`author_pub`) is hidden inside the encrypted payload — invisible to relay
- Push sessions use fresh ephemeral keypairs → relay cannot link sender to any Receive Session
- Group Manifest is the authority for membership; blobs from non-members are silently discarded post-decryption

---

## 3. Components Described But Not Yet Built

| Component | Evidence | State |
|---|---|---|
| **trueseal-relay** | Full CONTEXT.md, 5 ADRs, referenced throughout all docs | **Zero code** — documented architecture, no Go source |
| **trueseal-clip** | Described as "first real consumer", "proof the primitive works end to end" | **Placeholder** — empty repo |
| **trueseal-secrets** | Described as a planned consumer app | **Placeholder** — empty repo |
| **SAS (Short Authentication String) for pairing** | Explicitly called out in pairing docs as a "future version" improvement | Not started |
| **Targeted key rotation** (single-device cryptographic removal without destroying the group) | Noted in revocation docs as "explicitly deferred — requires distributed key agreement sub-protocol" | Not started |
| **DAG envelope support (v1)** | ADR-0004: `parents` field exists in v0 wire format to avoid breaking change when v1 adds multi-parent DAG merges | v0 linear only |
| **LAN sync** | Principles doc: "LAN sync may bypass the relay in a future version" | Not started |

---

## 4. Logical 'Next' Component After trueseal-sync

**trueseal-relay** is the clear next component.

Evidence:
1. trueseal-sync is substantially implemented (full `src/` with session management, reconnect, pairing, manifest, encryption, outbox tests). trueseal-relay has no source code at all.
2. Without a relay, trueseal-sync cannot deliver blobs to any other device — it queues in the outbox indefinitely with nowhere to send.
3. The docs position trueseal-relay as co-equal infrastructure: the ecosystem cannot function end-to-end without it.
4. The relay's design is fully specified: Noise XX for Receive Sessions, Noise NK for anonymous Push Sessions, Inbox-per-recipient-pub, TTL reaping, immediate delivery on reconnect, no group-level knowledge.
5. trueseal-sync already has relay client code (`src/relay.rs`, `src/session/reconnect.rs`) — the client side is waiting for a server to talk to.
6. The trueseal-sync CONTEXT.md references trueseal-relay's GitHub repo as the counterpart: trueseal-sync is "the protocol authority", trueseal-relay "implements against it."

After trueseal-relay: **trueseal-clip** is the proof-of-concept consumer that validates the full stack end-to-end. trueseal-secrets is a secondary consumer.

---

## 5. Readiness / Graduation Signals for trueseal-sync

No explicit "graduation criteria" document exists, but signals from the docs and ADR history:

### Signs trueseal-sync is feature-complete at v0
- All 18 ADRs are decided and stable (no open/revisit flags observed)
- ADR-0010 explicitly describes the final two-layer API shape, including revision history showing prior iterations were superseded
- ADR-0017 finalises the local-first connection model
- ADR-0018 finalises anonymous push session model
- Wire format (Protobuf Envelopes) is described as stable — v0 linear parent-hash included specifically to avoid future breaking changes at v1
- `src/session/tests/` has 20 test files covering pairing, manifest filter, outbox, fanout, revocation, offline, push, reconnect, etc.

### Known explicit v0 limitations (documented non-goals, not bugs)
- No history backfill for new members — caller responsibility
- No per-object sequence continuity guarantee (global counter)
- No recipient-side gap detection (ADR-0012)
- Soft removal is cooperative, not cryptographic
- Max message size 65535 bytes (Noise framing cap) — chunking is caller's responsibility
- Relay TTL is the only condition where delivery is not guaranteed

### Open future work deferred to v1 or v2
- DAG parents (multi-parent envelopes)
- Targeted key rotation (single-device cryptographic removal)
- SAS pairing confirmation

---

## 6. Clarification Questions

1. **trueseal-relay code status**: Is there a private or in-progress trueseal-relay repo elsewhere, or is trueseal-relay genuinely zero-source-code and needs to be started from scratch?

2. **trueseal-sync completeness**: Does trueseal-sync currently compile and pass its full test suite against a real relay, or only against mock transports / in-memory fakes?

3. **Relay wire format**: Is the Protobuf definition in `trueseal-sync/proto/` the single source of truth for trueseal-relay to implement against? Is it considered frozen for v0?

4. **trueseal-clip scope**: Is trueseal-clip an iOS/macOS native app (Swift via UniFFI), a cross-platform Rust CLI, or something else? This determines which UniFFI binding surface gets exercised first.

5. **Public relay**: Is there a plan for a public trueseal relay for testing / early consumers, or is self-hosting the only option at launch?

6. **trueseal-secrets relationship to trueseal-sync**: Is trueseal-secrets a distinct app from trueseal-clip (secrets manager vs clipboard), or are they the same codebase targeting different use cases? The original `trueseal` (in CONTEXT.md) was a PAKE-based secret-sharing CLI — is trueseal-secrets the evolution of that?

7. **Graduation gate**: What is the explicit trigger for moving to trueseal-clip? Is it "trueseal-relay passes its own test suite" or "trueseal-sync + trueseal-relay pass an end-to-end integration test"?
