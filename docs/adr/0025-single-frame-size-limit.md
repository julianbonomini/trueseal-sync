# Every message fits in one frame; the Protocol Size Limit is 60 KiB of application data

Status: accepted (decided 2026-09-29 in [trueseal-roadmap#8](https://github.com/julianbonomini/trueseal-roadmap/issues/8)). This sets the value ADR-0006 left open and replaces the 1 MiB `MAX_ENVELOPE_BYTES`, which was never reachable.

A Noise transport frame has a u16 length prefix, so no Envelope can be larger than about 65,482 bytes. The declared 1 MiB limit was wrong. A send of more than about 64 KB was accepted and then retried forever from the Outbox. We keep single-frame messages and publish a **Protocol Size Limit of 61,440 bytes (60 KiB)** for the body of a `Sync` Message, the bytes the caller passes to `send()`. The roughly 4 KB of headroom below the frame ceiling lets Envelope fields grow without changing the public limit. The Envelope and frame limits are internal values derived from it.

- `send()` checks the limit synchronously, before anything is written to the Operation Log, and returns a typed `PayloadTooLarge { max }` error. An oversize body never enters the Outbox.
- Each SDK exposes the limit as a constant. A caller may pass a lower `maxPayloadBytes` when creating a session, for example to match a stricter relay; values above the Protocol Size Limit are clamped to it.
- Every Message type (`Pair`, `Sync`, `GroupManifest`, `Revoke`) must fit in one frame. A test sends a body of exactly the Protocol Size Limit and checks that it fits in a frame. The largest allowed Group Manifest must also fit, which needs a maximum group size; that is decided in the membership decision ([trueseal-roadmap#9](https://github.com/julianbonomini/trueseal-roadmap/issues/9)).
- A Relay operator may set a lower **Relay Size Limit**, but never a higher one. A relay configured above the protocol ceiling refuses to start instead of silently ignoring the value.
- An oversize rejection from the Relay is permanent. The relay `Error` frame gains a reason code so the client can tell "too large" apart from other rejections; the code reveals size class only, never content. The client never retries such a Blob and surfaces a typed permanent-failure event. The shape of that event is set by the delivery contract ([trueseal-roadmap#7](https://github.com/julianbonomini/trueseal-roadmap/issues/7)).
- Outbox entries already over the limit (only in development stores) are dropped on load and raise the same permanent-failure event. This is a clean break, consistent with ADR-0022.

Large payloads stay the caller's job until the content-addressed filestore of ADR-0006 exists.

## Considered alternatives

- **Chunk one message across several frames.** Rejected. It needs a reassembly state machine (partial chunks, a crash mid-reassembly, chunks expiring separately under TTL), gives abusers an amplification path, and turns the Relay from a log transport into something closer to a file store.
- **Widen the frame length to u32 with a cap of about 1 MiB.** Rejected for the preview. It would multiply per-Blob relay memory and storage by about 16×, which raises both abuse exposure and the cost of running a relay, and it would enlarge the size leak. Raising the limit later takes a Transport Version bump (ADR-0022). That direction is cheap, whereas lowering a limit callers depend on is not.
- **The Relay advertises its limit when a session starts.** Deferred. It adds a Transport field and a cached value that can go stale. Offline sends would still need the rejection path. We add it only if self-hosters actually run with low limits.
- **A fixed limit that operators can't configure.** Rejected. Self-hosters may reasonably want a lower limit; the client enforces the protocol ceiling either way.

## Consequences

- trueseal-noise, trueseal-sync, trueseal-relay, all three SDKs and the docs must state the same numbers. The docs' 1 MiB claims (the envelope size limit in `wire-format`, the relay's `deploying` default) are wrong and must be corrected.
- The relay's `Error` frame body is no longer always empty (this amends trueseal-relay ADR-0008).
- The Relay still sees Blob sizes. Capping them doesn't hide them; size visibility stays a documented limitation.
