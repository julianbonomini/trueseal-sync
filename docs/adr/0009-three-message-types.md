# Three message types: PAIR, SYNC, REVOKE

hush-sync defines exactly three message types as a typed protocol layer on top of hush-relay:

- `PAIR` — a Device requesting to join a Sync Group. Body: initiator's noise public key + signing public key. Only possible if the recipient shared their public key out-of-band (e.g. via QR code).
- `SYNC` — an opaque application blob. Body is caller-defined bytes. hush-sync delivers them verbatim; conflict resolution, schema, and versioning are the caller's responsibility (ADR-0003).
- `REVOKE` — a full Sync Group reset. Empty body. Any paired Device may send this; all recipients wipe their paired list and rotate keypairs (ADR-0007).

The message type is encoded as a 1-byte tag at the start of the plaintext payload, before addressed encryption. The Relay never sees it — the type tag is entirely inside the ciphertext from the Relay's perspective.

hush-sync is one opinionated client protocol built on hush-relay. It is not the only possible protocol. Third-party developers may use hush-relay directly with their own message taxonomy — the Relay is agnostic to payload content. This separation is deliberate: the Relay is infrastructure, hush-sync is a protocol.

The alternative — making message type visible in the Envelope envelope (as an unencrypted field) — was rejected because it would expose communication patterns to the Relay, violating the zero-knowledge property.
