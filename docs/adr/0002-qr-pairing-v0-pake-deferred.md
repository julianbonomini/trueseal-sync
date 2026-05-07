# QR code pairing for v0; PAKE deferred

The v0 pairing ceremony uses QR codes only. The QR encodes the initiating device's public key directly. The joining device scans it, obtains the public key out-of-band (no relay involvement, no interception window), then sends its own public key back via the relay encrypted to the initiator's public key. No PAKE ceremony is needed for the QR path because trust is established by physical possession of the QR display.

PAKE (e.g. SPAKE2) is explicitly deferred to a later version to support keyboard-based pairing (short phrase) for devices without cameras. The QR shortcut is acceptable for v0 because the threat it doesn't cover (low-entropy phrase interception) doesn't apply when the shared secret is a full public key encoded in a QR.
