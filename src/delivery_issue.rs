//! Delivery Issues — typed, device-local reports that the library could not
//! deliver or handle a message (ADR-0026, ADR-0028, amended by ADR-0034).
//!
//! A Delivery Issue is never sent to the other Device or to the Relay.
//! Observing them is optional; the library already does the right thing.
//!
//! SYNC-1 introduces the type with the rejection paths ADR-0022 needs.
//! SYNC-5 (delivery contract) and SYNC-15 (canonical FFI) complete the
//! variant set and the public event surface.

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
    /// The body exceeds the Protocol Size Limit (ADR-0025). Only reachable
    /// for outbox entries written by a build from before the `send()` check.
    TooLarge,
    // SYNC-5 and SYNC-12 add `Malformed` and `Expired` (30-day `Sync` expiry).
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
}
