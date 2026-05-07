# QR code pairing for v0; PAKE and SAS deferred

## Decision

v0 pairing uses QR codes only, with explicit accept. PAKE and SAS are deferred.

## Why QR + explicit accept is secure for v0

The QR encodes the initiating device's public key. Key exchange happens as follows:

1. A displays QR (A's public key, out-of-band — relay not involved)
2. B scans QR, obtains A's public key physically
3. B pushes a `Pair` message encrypted to A's public key via the relay
4. A's `on_message(Pair)` fires — A explicitly calls `accept_pair()` to add B

The relay sees only ciphertext. The shared secret (A's public key) is exchanged with full entropy via physical proximity. PAKE adds nothing on this path because the threat PAKE defends against — a low-entropy shared secret that can be brute-forced — does not apply when the secret is a 256-bit public key.

The explicit `accept_pair()` requirement closes the residual attack surface: an attacker who photographs the QR can push a `Pair` message, but A must still accept it. A should only accept a `Pair` message during an active pairing window initiated by A.

## Why PAKE is deferred, not skipped

PAKE (e.g. SPAKE2) is required for the keyboard/phrase pairing path — where the shared secret is low entropy (e.g. a 6-digit code, ~20 bits). An attacker can brute-force 20 bits online without a commitment scheme. Shipping a keyboard pairing path without PAKE would be genuinely insecure.

v0 has no keyboard pairing path. If a future version needs to pair devices without cameras (headless servers, devices in different rooms), PAKE must be implemented at that point — it is not optional for that path.

## SAS (Short Authentication String) is also deferred

SAS (the "both devices show the same 6-digit code, user confirms visually" mechanism used in Bluetooth) is a separate mechanism from PAKE. SAS is for visual confirmation of a DH exchange — not for low-entropy input. It would strengthen the QR path by adding a confirmation step after key exchange. Also deferred to v1.

## Consequences

- `start_pairing()` returns raw QR bytes (the initiator's public key + signing key, 64 bytes). Caller is responsible for QR encoding.
- The session enforces a pairing window (opened by `start_pairing()`, closed by timeout, successful accept, or `cancel_pairing()`).
- `accept_pair()` is only valid inside an open pairing window.
- If keyboard/phrase pairing is needed in future, PAKE must be implemented — it cannot be bolted on as a cosmetic change.
