# Sync JSON test vectors

`sync-v1.json` pins the preview wire format byte-for-byte. It exists so the
relay (Go) and the three SDKs can **prove** they agree with the Rust core —
release gate G5 — instead of inferring compatibility from package versions
(ADR-0022).

Every byte is generated from the real trueseal-sync code paths with fixed,
test-only inputs (Ed25519, X25519 and ChaCha20-Poly1305 are deterministic, so
fixed seeds produce fixed wire bytes). Nothing in the file is hand-written,
and none of the key material is valid on any live network.

## What is covered

| Section | Pins |
|---|---|
| `protocol` | Transport / End-to-End / Store Versions, the size limits, Maximum Group Size, Maximum Manifest Version Jump, the held-blob cap, the Replay Window |
| `domains` | HKDF info, AEAD AAD and the two signing domains (with the ephemeral/recipient binding layout of ADR-0031) |
| `transportVersionPrefix` | The exact `"TSP" \|\| u16 BE` client bytes, the `0x01` accept reply, the `unsupported min..max` refusal and its typed surface (ADR-0022) |
| `signing` | The canonical signing inputs and signatures for the Envelope (ADR-0031) and for genesis + parent-linked update Group Manifests (ADR-0022/0027), plus manifest hashes |
| `addressedEncryption` | A full seal/open: layout `ephemeral_pub(32) ‖ nonce(12, zero) ‖ ciphertext+tag` |
| `messageId` | The `tsm1_` derivation for a fixed (author, sequence) |
| `messages` | All four message types (Pair carries the ADR-0023 Pairing Secret; a 65-byte pre-SYNC-3 Pair must NOT decode) |
| `sealedEnvelope` | A complete sealed Envelope: inputs, sealed prefix, payload, protobuf bytes, hash |
| `frames` | All six relay frame types (`[type:u8][len:u32 BE][body]`), including a full Push blob built by the production assembly |
| `rejections` | One rejection per layer — transport (×2), envelope signature, size, End-to-End Version (newer held / older dropped), replay expiry, unknown message tag — each naming the expected typed error or Delivery Issue from the canonical taxonomy (`docs/shared-facts.json`) |

## Consuming the vectors

- **Relay (Go) — RELAY-5:** parse `transportVersionPrefix`, `frames` and the
  `rejections` entries for the layers the relay speaks (transport, size).
  The relay must emit/accept exactly these bytes and refuse the rejection
  inputs as named.
- **SDKs — SDK-2:** through the bindings, reproduce the `signing`,
  `addressedEncryption`, `messageId`, `messages` and `sealedEnvelope`
  sections from the same `keys` inputs, and classify the `rejections` as
  named.
- **Conventions:** hex is lowercase; multi-byte integers in layouts say
  their endianness (LE = little-endian, BE = big-endian); JSON numbers are
  unsigned 64-bit; strings with `\n` are byte-exact. `blob_id` is 8 opaque
  relay-assigned bytes — a client echoes it verbatim in DeliverAck.

## Regenerating (deliberate changes only)

The file is a build gate: CI fails if it drifts from what the code
generates. Regenerate only when a protocol change is **deliberate** (a
version bump per ADR-0022), then review the diff as wire-format evidence:

```sh
cargo test --lib vectors -- --ignored     # rewrites sync-v1.json
cargo test --lib vectors                  # verifies + drift check
```

An unexpected drift failure means the wire format changed accidentally —
treat it as a bug, not a prompt to regenerate.
