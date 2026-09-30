# Fixed, cryptographically bound protocol versions with no negotiation

Status: accepted (decided 2026-09-29 in [trueseal-roadmap#3](https://github.com/julianbonomini/trueseal-roadmap/issues/3); not yet implemented) Amended by ADR-0034.

TrueSeal carries two independent protocol versions: a **Transport Version** (Device↔Relay: Noise handshake and frames) and an **End-to-End Version** (Device↔Device: Envelope, signatures, addressed encryption). Each is bound into the cryptography — the Transport Version into the Noise prologue via a short plaintext version prefix, the End-to-End Version into HKDF info, AEAD associated data, and domain-separated Envelope and Manifest signing inputs — and also carried as a signed plaintext field. There is no negotiation: a component speaks exactly one version of each, and anything else is explicitly rejected. The preview promises no mixed-version operation. Versions start at 1 (0 reserved), and today's unversioned format is refused with no compatibility decoder.

We chose this over a Signal-style accepted range because a store-and-forward sender cannot learn what offline recipients support, and over an MLS-style per-group version in the Group Manifest because it couples versioning to membership logic with open defects. Pre-launch, with one Rust core behind every SDK, a coordinated bump is cheap. The signed version field keeps a later move to per-group versions possible without a second format break.

## Consequences

- A Device checks the End-to-End Version before DeliverAck. Newer-than-supported Blobs stay unacked on the Relay (capped at about 100 per Device; beyond that the oldest are acked and dropped) so an upgrade recovers them. Older or malformed Blobs are acked and dropped. Every case raises a typed, device-local event; nothing is sent back to the sender.
- The Relay replies to an unsupported Transport Version with a plaintext `unsupported min..max` and closes; the SDK surfaces `RelayVersionUnsupported{min,max}`. Unknown frame types get a generic `Error` code with no echoed bytes.
- Outbox entries sealed under an old End-to-End Version cannot be re-sealed (the outbox keeps no plaintext). On startup they are removed and reported as `UndeliverableAfterUpgrade{messageIds}` in one transaction. (Refined by ADR-0032: only `Sync` entries are removed; library-built Pair, Group Manifest and Revoke entries are re-sealed under the new version, and the report is persisted until a delivery-issue handler receives it. Superseded by ADR-0034: the outbox does keep `Sync` plaintext, so every entry is re-sealed, nothing is removed, and `UndeliverableAfterUpgrade` no longer exists.)
- Unknown protobuf fields are ignored and must never carry meaning; any semantic change bumps a version.
- The Relay can infer a Device's End-to-End Version from which Blobs it leaves unacked. This is a documented metadata limitation.
- Sync-level JSON test vectors (signing inputs, addressed encryption, Message ID, frames, version prefix, rejection cases) become a release gate for the core, the Relay and every SDK.
