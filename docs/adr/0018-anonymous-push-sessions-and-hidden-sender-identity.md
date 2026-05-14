# ADR-0018: Anonymous push sessions and sender identity hidden inside payload

## Status

Accepted

## Context

Two independent signals allow the relay to build a sender→recipient communication graph:

**1. `author_pub` in the clear Envelope header.**
Every Envelope carries the sender's Ed25519 signing key as an unencrypted proto field. The relay observes `(author_pub → recipient_pub)` pairs for every push — a stable, persistent graph keyed on the device's long-term identity.

**2. Sender noise key from the Noise XX push handshake.**
Every `RelayClient::connect` performs a Noise XX handshake, which transmits the client's static X25519 public key to the relay. The relay learns which device (by noise key) established each push session and which recipients it addressed.

ADR-0001 claims "the relay learns only recipient public keys." This is false under the current design. The relay learns the sender's signing key and the sender's noise key for every push.

The Manifesto states: *"The relay can be self-hosted, replaced, or run by an adversary. The security model does not change."* Under the current design, an adversarial relay can reconstruct the full group communication graph. This violates the Anonymity principle. Note: the relay cannot read content (E2EE) or tamper with envelopes without detection (ADR-0013). The gap is metadata only.

These two signals must both be closed. Closing only one leaves the other intact.

## Decision

Two changes, required together.

### 1. Push sessions use Noise NK with a fresh ephemeral client keypair per push

Devices maintain two distinct session types:

**Receive session** — Noise XX, long-lived, identified. The device's stable noise keypair authenticates to the relay. The relay maintains a `noise_pub → active connection` map used for push-on-arrival delivery to online devices. Behaviour and lifecycle are unchanged from the current design.

**Push session** — Noise NK, short-lived, anonymous. A fresh ephemeral X25519 keypair is generated for each push connection. Noise NK authenticates the relay to the client (the client verifies `relay_pub`) but transmits no static client key. The relay sees an unlinkable ephemeral identity per push. The session is closed immediately after all blobs for that push are sent.

Push-on-arrival is fully preserved. The relay receives a blob addressed to `recipient_pub`, checks whether that recipient has an active receive session, and delivers immediately if online. Offline blobs are stored per the existing TTL. The relay requires no knowledge of the sender to route — consistent with ADR-0001.

### 2. `author_pub` moves inside the encrypted payload

The Envelope proto removes `author_pub` as a top-level field. The encrypted payload now encodes:

```
plaintext = author_pub (32 bytes) || message_tag (1 byte) || message_body (N bytes)
```

The signing message changes to:

```
sequence (8 LE) || each parent (32) || recipient_pub (32) || ciphertext (N)
```

`author_pub` is no longer a standalone signed field — it is bound cryptographically through the ciphertext. Any change to `author_pub` in the plaintext changes the ciphertext, which changes the signing message, which invalidates the signature.

**Recipient verification sequence:**
1. Verify the envelope signature over `sequence || parents || recipient_pub || ciphertext`.
2. Decrypt the payload.
3. Extract `author_pub` from the first 32 bytes of plaintext.
4. Verify the signature again using the extracted `author_pub` — if it does not match the signer, discard.
5. Apply manifest filter: discard if `author_pub` is not in the current manifest.
6. Decode the message from the remaining bytes.

**Attribution forgery is prevented.** Device B cannot impersonate device A:
- B could encrypt `(A_pub || message)` addressed to recipient R.
- B signs the envelope with B's key.
- Recipient decrypts, extracts `A_pub`, then verifies the signature using `A_pub` — the signature was made by B, not A. Verification fails.

The protocol is: decrypt first to learn who claims to be the author; verify the signature using that claimed key; the two must agree or the envelope is discarded.

### Caller transparency

These changes are entirely below the `TruesealSession` facade. The caller-facing API is unchanged:

- `send(blob)` — unchanged
- `on_message(blob, sender_noise_pub)` — unchanged; sender identity is still resolved by looking up the extracted `author_pub` (signing key) in the current manifest to find the corresponding noise pub
- `members()`, `pairing_token()`, `accept_member()`, `remove_member()`, `destroy_group()` — all unchanged

The session manages both session types internally. The caller never handles session lifecycle, keypair generation for push, or payload layout.

## Consequences

- **Breaking wire format change.** `author_pub` is removed from the Envelope proto. All existing envelopes are invalid. No migration is needed — the project has not launched.
- **Two RelayClient roles.** `RelayClient` is split or parameterised to support both Noise XX (receive) and Noise NK (push). The session facade holds one of each and selects by operation.
- **Relay metadata is minimal and honest.** After this change, the relay learns: which noise keys are actively receiving (unavoidable for push-on-arrival), and `recipient_pub` per envelope (required for routing). It learns nothing about senders. ADR-0001 can be corrected.
- **Ephemeral keypair cost.** Each push generates one X25519 keypair. This is negligible — X25519 key generation is ~10μs.
- **Residual known metadata.** The relay still knows which noise keys are connected and receiving. This is an unavoidable consequence of push-on-arrival delivery and is documented explicitly. The relay cannot determine group membership from this alone — it only knows that device R is online.
- **Signing message change.** The canonical `signing_message` no longer includes `author_pub` as an explicit field. It is bound implicitly through the ciphertext. Implementations must be updated to match.
