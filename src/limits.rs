//! Protocol Size Limit and the internal frame limits derived from it (ADR-0025).
//!
//! Every Message must fit in one Noise transport frame. The **Protocol Size
//! Limit** is the public number — the largest `Sync` Message body a Device may
//! send — and every other limit here is derived from the frame ceiling so the
//! public number never has to move. `send()` checks the Protocol Size Limit
//! synchronously, before anything is written to the Operation Log, and refuses
//! a larger body with a typed `PayloadTooLarge` error; an oversize body never
//! enters the Outbox.
//!
//! These constants are the single source of truth: the SDKs expose them
//! generated from this crate (SYNC-21), and the relay enforces the same
//! ceiling (it may only be configured lower — RELAY-8).

/// The largest `Sync` Message body a Device may send: 61,440 bytes (60 KiB)
/// of caller data — the bytes passed to `send()` (ADR-0025).
///
/// Fixed by the protocol. The roughly 4 KB of headroom below the frame
/// ceiling lets Envelope fields grow without changing this public limit.
pub const PROTOCOL_SIZE_LIMIT: usize = 61_440;

/// The largest plaintext that fits in one trueseal-noise transport frame:
/// 65,535 (the u16 length-prefix maximum) − 16 (the ChaCha20-Poly1305 tag).
///
/// The number is protocol-fixed by the u16 frame format. trueseal-noise keeps
/// it crate-private (`framing::MAX_PLAINTEXT_SIZE`); it is restated here
/// because the Envelope limit below is derived from it.
pub const NOISE_FRAME_PLAINTEXT_MAX: usize = 65_519;

/// Per-Blob overhead of the Push frame around a serialised Envelope:
/// 1 byte (MsgType) + 4 bytes (u32 body length) + 32 bytes (the recipient
/// routing prefix the relay reads without decoding, ADR-0019).
pub(crate) const PUSH_FRAME_OVERHEAD: usize = 1 + 4 + 32;

/// The largest serialised Envelope that still fits in one Noise frame as a
/// Push: 65,519 − 37 = 65,482 (the "about 65,482" of ADR-0025).
///
/// Internal backstop, checked in `build_push_blob` after serialisation — it
/// guards control messages (`Pair`, `GroupManifest`, `Revoke`), which do not
/// go through the `send()` body check. Callers only ever see
/// `PROTOCOL_SIZE_LIMIT`.
pub const MAX_ENVELOPE_BYTES: usize = NOISE_FRAME_PLAINTEXT_MAX - PUSH_FRAME_OVERHEAD;

// Protocol invariants, checked at compile time: the derived Envelope limit
// is the number ADR-0025 states, a Push frame carrying it lands exactly on
// the Noise frame ceiling, and the public limit keeps roughly 4 KB of
// headroom for Envelope fields to grow without changing the public number.
const _: () = {
    assert!(MAX_ENVELOPE_BYTES == 65_482, "ADR-0025: about 65,482 bytes");
    assert!(MAX_ENVELOPE_BYTES + PUSH_FRAME_OVERHEAD == NOISE_FRAME_PLAINTEXT_MAX);
    assert!(PROTOCOL_SIZE_LIMIT < MAX_ENVELOPE_BYTES);
    assert!(MAX_ENVELOPE_BYTES - PROTOCOL_SIZE_LIMIT >= 4_000);
};
