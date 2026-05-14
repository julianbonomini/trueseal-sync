# Pairing window is caller-controlled, not timer-based

The pairing window (the period during which an incoming `Pair` message is accepted) used to auto-expire after 60 seconds from the moment `pairingToken()` was called. This caused silent failures in real pairing flows: users spending more than 60 seconds switching between devices or scanning a QR code would have their `Pair` message delivered and ack'd by the relay but silently dropped by trueseal-sync, with no error and no feedback.

The 60-second timer is not a security requirement. Security comes from the explicit `acceptMember()` call — the human decides who to admit. The window only gates whether `onMemberRequest` fires; without an explicit accept, no one joins regardless of window state. Auto-expiry was a safety net, not a cryptographic control.

The window is now open from when `pairingToken()` is called until either `acceptMember()` succeeds (single-use: window closes on first accept) or the caller explicitly calls `cancelPairing()`. This matches every real-world pairing UX: the window is open while the user is actively in the pairing UI and closed when they leave it.

## Considered alternatives

**Keep the timer but make it longer (e.g. 5 minutes).** Rejected — any fixed timer still causes the same class of silent failures under different conditions. The root issue is that the timer is not the right lifecycle owner; the caller's UI is.

**Keep the timer, add an error/callback on expiry.** Rejected — adds complexity without fixing the design. The caller already has `cancelPairing()` for explicit lifecycle control.
