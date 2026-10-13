//! Delivery Issues — typed, device-local reports that the library could not
//! deliver or handle a message (ADR-0026, ADR-0028, amended by ADR-0034).
//!
//! A Delivery Issue is never sent to the other Device or to the Relay.
//! Observing them is optional; the library already does the right thing.
//!
//! SYNC-1 introduced the rejection paths ADR-0022 needs; SYNC-5 (the
//! delivery contract) added `unauthorized`, `handlerGaveUp` and the
//! `malformed`/`expired` send-failure reasons. SYNC-15 (canonical FFI)
//! owns the public event surface.

/// Why an incoming Blob was rejected as unreadable (ADR-0034 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreadableReason {
    /// Undecodable or unauthenticated bytes, an unknown frame type, or an
    /// unknown message tag. This includes the refused unversioned format
    /// failing to decrypt or verify.
    Malformed,
    /// The Blob carries an older End-to-End Version than this device
    /// supports — including version 0, the refused pre-version format.
    /// The one reason an app can act on: "one of your devices needs an update".
    SenderOutdated,
    /// The message is older than the Replay Window (produced by SYNC-12).
    Expired,
    /// The oldest held newer-version Blob, acked and dropped when the hold
    /// cap (`MAX_HELD_BLOBS`) overflowed.
    DroppedWhileHeld,
}

/// Why the library gave up sending an outgoing message (ADR-0034 §3).
/// Every reason is permanent — the message is never retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendFailedReason {
    /// The body exceeds the Protocol Size Limit (ADR-0025). Reachable for
    /// outbox entries written by a build from before the `send()` check, or
    /// when the serialised Envelope cannot fit one Noise frame.
    TooLarge,
    /// The relay permanently refused the push (Error frame, ADR-0026). The
    /// relay's Error codes are untyped today; RELAY-5 adds reason codes and
    /// this reason may then split.
    Malformed,
    /// A `Sync` entry still undelivered 30 days after `send()` (ADR-0026).
    /// Control-plane entries never expire.
    Expired,
}

/// A typed, device-local report from the library (ADR-0034 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryIssue {
    /// An incoming Blob was rejected and will never reach a handler.
    Unreadable(UnreadableReason),
    /// A Blob carries a newer End-to-End Version than this build supports.
    /// It is held unacked on the Relay (up to the cap) so an upgrade
    /// recovers it.
    HeldForUpgrade(u32),
    /// An outgoing message was dropped without delivery. Carries the
    /// Message ID the send would have had, so the app can correlate.
    SendFailed {
        message_id: String,
        reason: SendFailedReason,
    },
    /// An incoming Blob was authenticated and decodable, but the library
    /// refused to apply it on authorisation grounds (ADR-0034 §3 keeps this
    /// a separate case from `unreadable`): a Group Manifest from an unknown
    /// issuer, with an over-bound version jump, at u64::MAX, or for a
    /// different group (ADR-0027, SYNC-10). Acked and dropped; a *benign*
    /// stale manifest (a relay re-delivery or a concurrent-issuer loser)
    /// raises nothing at all.
    Unauthorized,
    /// The app's message handler failed on all 5 attempts (ADR-0026
    /// recipient step 4). The Blob was then acked and dropped — it will not
    /// be delivered again. Carries the Message ID and the last error.
    HandlerGaveUp { message_id: String, error: String },
}
