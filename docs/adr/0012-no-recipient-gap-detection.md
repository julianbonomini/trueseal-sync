# No recipient-side gap detection in v0; sender outbox is the reliability mechanism

## Decision

hush-sync does not buffer or reorder Envelopes on the recipient side. Envelopes are delivered to the caller in arrival order. Gaps (missing sequence numbers from a given sender) are not detected or reported by the recipient.

## Rationale

### The sender outbox is the right reliability mechanism

When a Device is offline, new blobs are appended to its local Operation Log as undelivered entries. On reconnect, the session replays them to the Relay in global sequence order. The recipient eventually receives all blobs in the correct order — not because the recipient buffered them, but because the sender guaranteed delivery.

### Recipient buffering adds latency and complexity for unclear benefit

If the recipient detects a gap (sequence 5 then sequence 7 from Device A), it could buffer sequence 7 and wait for sequence 6. But sequence 6 is almost certainly in Device A's outbox and will arrive when Device A reconnects. Holding sequence 7 indefinitely adds latency with no correctness benefit. Adding a timeout to flush the buffer introduces a new failure mode: the caller receives out-of-order delivery after the timeout, which it must handle anyway.

### Gap notification (without buffering) tells the caller something they cannot act on

hush-sync has no request/retransmit mechanism. If the caller is told "you missed sequence 6", there is nothing they can do except wait. This is noise, not signal.

### Parent hashes preserve causal ordering without sequence buffering

The DAG parent hash chain (ADR-0004) lets the caller detect causal ordering independently of arrival order. If a blob references a parent the recipient hasn't seen, the caller knows the blob is causally dependent on missing state — without hush-sync needing to buffer anything.

## Consequences

- The session delivers Messages to `on_message` in arrival order, which may differ from send order if the sender was offline.
- The caller is responsible for interpreting causal ordering via parent hashes if ordering matters for their data model.
- If recipient-side gap detection or reordering is needed in a future version, it requires a new protocol mechanism (e.g. explicit ACKs from recipient to sender, or a request/retransmit flow). That is a breaking protocol change.
