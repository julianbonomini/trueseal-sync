# hush-sync exposes two layers: primitives and an opinionated session

## Decision

hush-sync exposes two distinct API layers:

**Primitives** (`hush_sync::*`) — `DeviceKeypair`, `RelayClient`, `PairedList`, `OperationLog`, `Message`, `Envelope`. Pure Rust. No lifecycle management. Available for advanced callers: Go via C FFI, custom relay implementations, testing harnesses, and future protocol extensions.

**Session** (`hush_sync::session::HushSession`) — an opinionated facade that wires the primitives together. Owns: relay connection lifecycle, reconnection, in-memory paired list, message dispatch, and revocation execution (keypair rotation + reconnect). Does not own: keypair storage, op log persistence, relay address configuration — those are caller responsibilities.

UniFFI exposes **only the session layer** to Swift and Kotlin. The primitives are Rust-only and not part of the cross-language surface.

## Session contract

```rust
HushSession::new(
    keypair_bytes: [u8; 64],               // caller loaded from storage
    relay_addr: &str,
    relay_pub: [u8; 32],
    on_message: impl Fn(Message),
    on_keypair_rotated: impl Fn([u8; 64]), // fired after revocation; caller must re-persist
    on_paired: impl Fn([u8; 32]),          // fired after accept_pair(); caller bootstraps new device
)

// Pairing flow
session.start_pairing() -> Vec<u8>        // returns Pairing Payload bytes for QR encoding
session.accept_pair(noise_pub: [u8; 32])  // caller calls this after reviewing on_message(Pair)

// The session fires on_message(Message::Pair { noise_pub, signing_pub }) when a Pair
// message arrives. The caller decides whether to accept — explicit accept_pair() is
// required before the device is added to the paired list. Auto-accept is intentionally
// not provided: the Pairing Payload encodes the initiator's public key (a delivery
// address, not a secret), so any device that knows it could push a Pair message.
//
// After accept_pair(), the session fires on_paired(noise_pub) so the caller can
// bootstrap the new device with historical state. What to send is entirely the
// caller's decision — hush-sync does not define a bootstrap protocol.
//
// Pairing window: opened by start_pairing(), closed by timeout (default 60s),
// successful accept_pair(), or explicit cancel_pairing(). accept_pair() is a
// no-op outside an open window. The timeout is caller-configurable.
```

On revocation, the session:
1. Wipes the in-memory paired list
2. Generates a fresh `DeviceKeypair`
3. Reconnects to the relay with the new keypair
4. Fires `on_keypair_rotated` with the new keypair bytes for the caller to persist

## Rationale

A single-layer API (primitives only) forces every caller to re-implement session management — relay reconnection, revocation keypair rotation, message dispatch. A single-layer opinionated API (session only) blocks advanced callers who need direct access to envelope construction or custom transport adapters.

The two-layer pattern (analogous to `hyper`/`reqwest` in the Rust ecosystem) gives both: a sharp tool for protocol-level work, and a safe default for app developers.

## Consequences

- `src/ffi.rs` currently exposes primitives via UniFFI. This should be replaced by a `src/session.rs` + updated `src/ffi.rs` that exposes only `HushSession`.
- The primitives must remain public Rust API (not `pub(crate)`) so that advanced callers can use them directly.
- Documentation must clearly distinguish the two layers. The session docs are the primary entry point; the primitives docs are the advanced reference.
