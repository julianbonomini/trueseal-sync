# Four message types: PAIR, SYNC, REVOKE, GROUP_MANIFEST

trueseal-sync defines four message types as a typed protocol layer on top of trueseal-relay:

- `PAIR` (tag `0x01`) — a Device requesting to join a Sync Group. Body: initiator's noise public key + signing public key (Pairing Payload). Only possible if the recipient shared their public key out-of-band (e.g. via QR code from `pairingToken()`).
- `SYNC` (tag `0x02`) — an opaque application blob. Body is caller-defined bytes. trueseal-sync delivers them verbatim; conflict resolution, schema, and versioning are the caller's responsibility (ADR-0003).
- `REVOKE` (tag `0x03`) — a full Sync Group reset / Destroy Group. Empty body. Any current member may send this; all recipients wipe their Group Manifest, rotate keypairs, and fire `onGroupDestroyed()` (ADR-0007, superseded by ADR-0015 for semantics).
- `GROUP_MANIFEST` (tag `0x04`) — a signed, versioned membership update (ADR-0014). Pushed to every current member on every membership change: new device admitted, member removed, group bootstrapped. Recipients validate the signature and issuer membership before applying.

The message type is encoded as a 1-byte tag at the start of the plaintext payload, before addressed encryption. The Relay never sees it — the type tag is entirely inside the ciphertext from the Relay's perspective.

Soft removal (ADR-0015) does not introduce a fifth message type. It is implemented entirely as a `GROUP_MANIFEST` update that excludes the removed device. The removed device, on receiving a manifest that excludes itself, fires `onRemovedFromGroup()`. No separate `MEMBER_REMOVED` message is needed or exists.

trueseal-sync is one opinionated client protocol built on trueseal-relay. It is not the only possible protocol. Third-party developers may use trueseal-relay directly with their own message taxonomy — the Relay is agnostic to payload content. This separation is deliberate: the Relay is infrastructure, trueseal-sync is a protocol.

The alternative — making message type visible in the Envelope (as an unencrypted field) — was rejected because it would expose communication patterns to the Relay, violating the zero-knowledge property.
