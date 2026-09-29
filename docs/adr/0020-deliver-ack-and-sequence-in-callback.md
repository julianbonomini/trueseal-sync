# DeliverAck and Sequence in Callback

## Status

Accepted. DeliverAck timing and caller-owned dedup are superseded by [ADR-0026](0026-delivery-contract.md); the Message ID derivation still stands.

## Context

The trueseal-relay wire protocol introduced two changes to the Receive Session flow:

1. **Deliver frame body gains an 8-byte prefix** — `[blob_id: 8 bytes u64 BE][proto Envelope]`. The relay uses `blob_id` to track which blobs have been acknowledged.

2. **New frame type `DeliverAck = 0x06`** — after a Device receives a Deliver frame, it must echo the `blob_id` back. Until the relay receives this Ack, it holds the blob and will re-deliver it on reconnect. This makes the delivery guarantee at-least-once rather than at-most-once.

Two design questions arise:

**When to send DeliverAck.** The relay's contract says "after durably persisting." trueseal-sync does not persist received Envelopes — the Operation Log is the sender's outbox only. The caller owns received-data persistence. Should trueseal-sync ACK on successful decryption, or on receipt?

**How callers deduplicate.** Because delivery is at-least-once, callers need a stable key to detect re-deliveries. The relay provides `blob_id`, but it is a relay-internal concept. Should it be exposed to callers?

## Decision

### DeliverAck timing: on receipt, not on success

trueseal-sync sends DeliverAck immediately after parsing `blob_id` from the Deliver frame body — before decryption, before signature verification, before firing callbacks.

Rationale: zero trust. If trueseal-sync ACKed only on successful decryption, a compromised relay could infer whether decryption succeeded from the presence or absence of an Ack. That is information the relay must never have. ACK means "bytes received" — nothing more.

A blob that fails decryption or verification is discarded silently. Re-delivery would not help — the same failure recurs. ACKing on receipt prevents infinite re-delivery loops without leaking any decryption outcome.

### blob_id: internal only

`blob_id` is read from the Deliver frame, stored on the stack, echoed in DeliverAck, then discarded. It never surfaces to the caller. It is a relay implementation detail — a different relay could assign IDs differently or not at all. Callers must not depend on it.

### Message identity: `(author_pub, sequence)` as the canonical dedup key

At-least-once delivery means callers may receive the same Envelope twice (relay re-delivers if it reconnects before receiving DeliverAck). Callers who need exactly-once semantics must deduplicate.

The domain already defines the right key: `(author_pub, sequence)`. `sequence` is a per-Device monotonically increasing counter — the pair uniquely identifies any Envelope without any relay concept involved.

The `subscribe` callback on `RelayClient` is extended from:
```
Fn(Message, [u8; 32])           // message, author_pub
```
to:
```
Fn(Message, [u8; 32], u64)      // message, author_pub, sequence
```

`sequence` is threaded through `TruesealSession::on_message` for direct Rust callers. The FFI derives a versioned opaque `message_id` from `(author_pub, sequence)` and passes that ID through every public SDK. This prevents SDKs from depending on relay IDs or reconstructing identity differently. trueseal-sync does not persist received IDs or suppress callbacks — durable deduplication remains the caller's responsibility.

The v1 SDK Message ID is `tsm1_` followed by unpadded base64url of:

```
SHA-256("trueseal-message-id-v1\\0" || author_pub[32] || sequence_u64_be)
```

Callers compare it as an opaque string and must not parse or reproduce it.

### DeliverAck send path

DeliverAck is sent from the `run_loop` dispatch thread via `session.send()` directly — the same pattern as Heartbeat echo. It is sent before the decrypt/verify/callback block, so a panic or error inside that block does not prevent the Ack from being sent.

## Consequences

- Relay can delete blobs promptly after a well-behaved client acknowledges them.
- A crash between receiving the Deliver frame and sending DeliverAck causes re-delivery on reconnect. Callers must be idempotent.
- `(author_pub, sequence)` is the domain dedup key; SDKs expose its opaque Message ID.
- Exactly-once application processing is not promised. Callers get at-least-once events and make application writes idempotent.
- `RelayClient::subscribe` and `TruesealSession::on_message` signatures change — breaking. Acceptable: nothing is in production.
- `blob_id` never leaks past `run_loop`. Relay implementation details stay invisible to callers.
- A compromised relay learns nothing from DeliverAck timing — ACK carries no decryption signal.

## Alternatives considered

**ACK only on successful decrypt/verify.** Rejected: leaks decryption outcome to the relay, violating zero trust. Also causes infinite re-delivery loops for unprocessable blobs.

**Expose blob_id to callers for dedup.** Rejected: relay implementation detail, not a domain concept. A future relay or a self-hosted relay might generate IDs differently. `(author_pub, sequence)` is relay-agnostic and already in the domain model.

**trueseal-sync owns dedup via an in-memory `(author_pub, sequence)` set.** Rejected: does not survive process restarts. A crash between receiving and persisting resets the set, so re-deliveries after reconnect would still fire callbacks twice. The caller's persistent storage is the only durable dedup layer.

**trueseal-sync owns dedup via SQLite (received-message log).** Rejected: scope expansion. trueseal-sync would need to persist received Envelopes, decide what "processed" means, and expose a deletion API. That is the caller's data model, not trueseal-sync's.
