# Delivery contract: ack after handling, library dedup, per-sender order

Status: accepted (decided 2026-09-29 in [trueseal-roadmap#7](https://github.com/julianbonomini/trueseal-roadmap/issues/7); not yet implemented). This supersedes the DeliverAck timing and caller-owned dedup of ADR-0020. The Message ID derivation in ADR-0020 stands.

A Device acks a Blob to the Relay only after the app's message handler has finished with it, or after the library has decided the Blob is unusable. The library runs handlers one at a time and drops duplicates itself, using a table of handled Message IDs. Senders retry while connected, never let a later message overtake one still being retried, and learn about every message they give up on. Pair and every Group Manifest use the same durable outbox as `Sync`.

The promise to app developers is:

> Messages from one Device reach each recipient's handler in the order that Device sent them, at least once, within the TTL. A handler runs twice for the same message only if the app crashed while handling it. There is no ordering across different senders.

Two documented exceptions apply. Blobs in a newer End-to-End Version are held unacked on the Relay (ADR-0022) and are handled out of order after an upgrade. A message the sender gave up on leaves a gap.

We need this because the old contract kept the at-least-once promise only as far as the library. DeliverAck went out before decryption and before the app callback. A crash in the handler lost the message, and so did a Deliver that arrived before `subscribe()`. Failed pushes retried only on reconnect, so they could be overtaken, and a permanently rejected push retried forever. Control-plane messages were fire-and-forget. Apps also had to build durable dedup themselves to be correct, which is the kind of primitive that is easy to get wrong.

## Guiding rule

Every primitive must be simple for the app developer: correct defaults, the least possible wiring, and nothing the app must get right for correctness. Observing failures is optional.

## Sender state machine (per outbox entry, per recipient)

`Queued → InFlight → Delivered (deleted) | Queued (retry) | Failed (deleted)`

- `send()` checks the Protocol Size Limit locally (ADR-0025) and refuses an oversize message immediately, without queuing it. Otherwise it writes the entry to the outbox before returning.
- An entry is marked delivered only when the Relay's persisted ack (ADR-0019) arrives. Delivered rows are deleted.
- **Temporary refusal or network failure:** back to `Queued`. The entry is retried while connected, with exponential backoff from 1 s to a 5 min cap, and immediately on reconnect. A success to that recipient resets the backoff for the entries behind it.
- **Head of line:** entries for one recipient are pushed in Sequence order, and a later entry never goes out while an earlier one is still queued for retry.
- **Permanent refusal:** `Failed`. The entry is removed and the app gets `SendFailed{messageId, reason}` on the delivery-issue stream.
- **Expiry:** a `Sync` entry still undelivered 30 days after `send()` is removed with `SendFailed{Expired}`. Pair and Group Manifest entries never expire.
- An unsupported Transport Version affects the whole connection, not one entry. Entries stay queued until the library is upgraded.

**Crash points.** A crash before the outbox write means `send()` never returned, so the app knows the send did not happen. A crash after the write replays the entry on the next start. A crash after the Relay persisted the Blob but before the ack arrived causes a duplicate push, and recipient dedup removes it.

## Relay contract

- Persist each push durably (fsync) before sending the push ack.
- Deliver each inbox in arrival order, sending each Blob once per Receive Session. Re-send un-acked Blobs only on a new Receive Session, never on every notify.
- On DeliverAck, delete a Blob only if it belongs to the acking Device's inbox.
- Refuse a push with a typed code:
  - **Permanent:** too large, malformed.
  - **Temporary:** inbox full, rate limited, unavailable or internal error.

  The codes carry no content. Size limits are set by ADR-0025; quotas and rate limits belong to the relay-baseline decision.

## Recipient state machine (per Blob, handled serially)

1. Nothing is pulled from the inbox until the app registers a message handler. Member events are buffered until their handlers exist. This removes the connect/subscribe race by construction.
2. Check the End-to-End Version (ADR-0022). A newer version stays unacked, up to about 100 per Device.
3. Decrypt, verify the signature, and apply the membership and pairing rules (ADR-0023), then look the Message ID up in the dedup table. On any failure, ack and drop the Blob and raise a delivery-issue event. A duplicate is acked silently.
4. Run the handler, which is async, and wait for it to finish. If it throws, retry in memory with backoff, 5 attempts in total. Then ack and drop, and raise `HandlerGaveUp{messageId, error}`. The library sets no timeout: a handler that never finishes stalls delivery for that session. Apps that want a timeout put one in their handler.
5. Record the Message ID in the dedup table, then send DeliverAck.

Control-plane messages follow the same path, with the library as the handler.

**Crash points.** A crash before step 5 commits means the Blob is re-delivered on the next session, and the handler runs again. That is the only way an app sees a duplicate. A crash between the dedup write and the ack means the Blob is re-delivered, recognised as a duplicate, and acked.

**Dedup table.** It lives in Session State. Entries are kept for 60 days: a message can wait up to 30 days in the sender's outbox and then up to 30 days on the Relay. A per-sender high-water mark was rejected because it would wrongly skip newer-version Blobs released after an upgrade.

## Delivery-issue stream

There is one optional stream of typed events, each with a Message ID where one exists and a reason. Cases include unreadable or unauthorised Blobs, held newer-version Blobs, `HandlerGaveUp`, `SendFailed` and `UndeliverableAfterUpgrade` (ADR-0022). Ignoring the stream is safe. Exact names and syntax belong to the SDK API shape prototype.

## Control plane

Pair and every Group Manifest go through the outbox under this contract. `acceptMember` persists the manifest and queues it before it returns true (ADR-0023). Revoke durability is left to the Destroy Group decision, with one requirement: a Revoke must not be lost to the wipe it triggers.

## Metadata

As in ADR-0020, the ack carries no outcome signal: every Blob the library can't use is acked too. The Relay can now observe handling latency, because the ack waits for the handler, and it can infer the End-to-End Version from held Blobs (ADR-0022). Both are documented limitations.

## Considered alternatives

- **Keep ack on receipt (ADR-0020).** Rejected: a crash in the handler loses the message, and the published at-least-once promise then stops at the library.
- **A local durable inbox, where the library stores the message, acks, and then hands it to the app until the app confirms.** Rejected: a second state machine and a confirm API, for little gain over waiting on the handler.
- **An explicit `ack(messageId)` from the app.** Rejected: easy to misuse, since a forgotten ack grows the inbox without limit.
- **Caller-owned dedup (ADR-0020).** Rejected: every app would need atomic storage of processed IDs to be correct.
- **No ordering promise.** Rejected: apps would rebuild ordering without access to Sequence. Serial handling was needed anyway.
- **Handler throw means never ack.** Rejected: one poison message would loop forever and block the inbox.
