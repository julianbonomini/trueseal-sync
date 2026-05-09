# Heartbeat, Push Ack, and Push Body Layout

## Status

Accepted

## Context

Three independent problems share a single wire-level change.

**Heartbeat.** Receive Sessions are persistent TCP connections (hush-relay ADR-0006). NAT and firewall middleboxes silently drop idle TCP connections — typically after 30–300 seconds. Without application-level keepalives, a Device may believe its Receive Session is live when the relay has already discarded it. The Device misses incoming Envelopes until it reconnects. hush-sync has no mechanism today to detect a silently-dead connection.

**Push Ack.** `push_sync` currently calls `mark_delivered` as soon as `push_send` returns `Ok` — meaning "bytes were written to the NK session." The relay may still lose the Envelope between receiving the bytes and persisting it to the InboxStore (crash, OOM, network teardown mid-write). The outbox correctly survives crashes and replays on reconnect, but `mark_delivered` fires too early: if the process crashes between the successful `send` and the relay persisting, the entry is marked delivered and will not be replayed. The guarantee should be "relay confirmed persistence," not "bytes written."

**Push body routing key.** The relay needs exactly one piece of information from a Push body: the recipient's public key, to know which Inbox to write to. Today that key lives inside a proto-encoded Envelope, requiring the relay to import and run a full proto decode on every Push. The relay is infrastructure — it should be structurally incapable of understanding content, not just policy-forbidden from reading it. Proto decode couples the relay to the Envelope schema unnecessarily.

All three problems are fixed by adding two new type tags and changing the Push body layout.

## Decision

### MsgType extensions

Two new type tags, extending the existing `MsgType` enum in `relay.rs`:

```
Heartbeat = 0x03   body: empty (0 bytes)
Ack       = 0x04   body: empty (0 bytes)
```

The wire framing (`[type:u8][len:u32 BE][body]`) is unchanged. hush-sync owns this type tag table as the protocol authority (hush-relay ADR-0005).

### Push body layout

The Push body gains a fixed 32-byte routing prefix before the proto-encoded Envelope:

```
Push body (inside the Noise NK message, after the [type][len] frame header):
  [recipient_pub: 32 bytes]     raw X25519 public key — inbox routing key
  [envelope:     variable]      proto-encoded Envelope — opaque to the relay
```

The relay reads `body[0:32]` as the inbox key. It stores and delivers `body[32:]` verbatim. It never decodes the proto. No Envelope schema knowledge required on the relay.

The Deliver body (relay → client on XX session) is `body[32:]` — identical to what the relay stored. The receive path (`run_loop`) calls `Envelope::decode` on the Deliver body as before. No change to the receive side.

`build_push_blob` in `relay.rs` prepends `recipient_pub.0` (32 raw bytes) before `envelope.encode()`.

### Heartbeat

The relay sends `Heartbeat` on idle Receive Sessions (XX) to prevent NAT timeout. The client echoes `Heartbeat` back from the receive dispatch loop. No payload. No application semantics — pure keepalive.

The dispatch loop (`run_loop`) handles `MsgType::Heartbeat` by calling `session.send(&frame(MsgType::Heartbeat, &[]))` directly. Two send paths exist (push send thread + dispatch thread), both serialised on the conn Mutex in hush-noise Session. No ordering guarantee between heartbeat echoes and push frames — not required.

### Push Ack

After the relay persists a pushed Envelope to the InboxStore, it sends `Ack` on the NK Push Session. The Ack body is **empty (0 bytes)** — it is a 1-bit "persisted" signal. The relay never reads sequence and has no value to echo back.

The relay does not use `sequence` for any purpose:
- Delivery ordering is the recipient's responsibility — every delivered Envelope carries `sequence` in the clear, and the recipient re-orders locally.
- Deduplication by `(sender, sequence)` is impossible — NK push hides sender identity.

`push_send` change:
1. Send the framed Push blob.
2. Call `session.receive()` — blocks until Ack arrives.
3. Parse: must be `MsgType::Ack`. Body length is not checked — any body is accepted.
4. Close session. Return `Ok(())`.

`mark_delivered` is now called only after `push_send` returns `Ok`, which now means "relay confirmed persistence" — not "bytes written."

`push_send` return type changes from `Result<[u8; 32], RelayError>` (ephemeral pub, unused by all callers) to `Result<(), RelayError>`.

### Ack in run_loop (XX Receive Session)

`run_loop` parses `MsgType::Ack` and silently drops it. All pushes use NK sessions; no Ack is expected on the XX Receive Session in the current protocol. The arm is defensive only.

## Relay implementation contract

The relay team needs to know exactly three things about the wire format:

**Push Session (Noise NK):**
- Receive one message: `[0x01][len][recipient_pub: 32 bytes][envelope_proto: variable]`
- Route on `body[0:32]` (raw X25519 key — inbox key)
- Store `body[32:]` opaquely
- Send: `[0x04][0x00 0x00 0x00 0x00]` (Ack, 0-byte body)
- Close session

**Receive Session (Noise XX):**
- Send Deliver: `[0x02][len][envelope_proto]` (the stored `body[32:]`)
- Send Heartbeat on idle: `[0x03][0x00 0x00 0x00 0x00]`
- Accept Heartbeat echo from client: same frame, ignore body

**No proto decode required anywhere on the relay.**

## Consequences

- `mark_delivered` now has "relay persisted" semantics. The outbox replay safety window closes.
- Heartbeat prevents silent connection death.
- Relay has zero Envelope schema knowledge. It is structurally incapable of reading content — not just policy-forbidden.
- One extra round-trip per push (NK send → Ack receive). Acceptable.
- `push_message` (Revoke, GroupManifest, PairAccept) also waits for Ack. Rare control messages. Accepted.
- `push_send` return type: `Result<[u8; 32], RelayError>` → `Result<(), RelayError>`.
- `build_push_blob` output changes: proto comment on `sequence` field ("Used by the Relay to order Envelopes") is now incorrect — to be removed.
- All test relay helpers updated to: strip `body[0:32]` prefix for routing, send 0-byte Ack.

## Alternatives considered

**Ack body carries sequence (8 bytes, u64 BE).** Initial plan. Rejected: relay doesn't use sequence for anything (ordering is recipient-side, dedup is impossible without sender identity). Client discards the sequence on receipt. The 8 bytes are pure overhead for a value nobody reads.

**Proto decode for recipient_pub extraction.** Current behaviour. Rejected: couples relay to Envelope schema, violates the "structurally dumb relay" principle. Fixed prefix costs nothing and removes the dependency entirely.

**Ack sequence validation on client.** Verify Ack sequence matches what was sent. Rejected: NK session authenticates the relay; a well-formed Ack from an authenticated relay is sufficient.

**TCP keepalives (SO_KEEPALIVE).** Rejected: not portable, not configurable at application layer.
