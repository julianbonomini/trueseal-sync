# hush-sync is written in Rust; Go is not used for the client library

hush-sync is implemented in Rust. The client library must run on iOS, Android, macOS, and Linux — Rust is the only language that compiles to all of these as a native static library without runtime embedding restrictions.

Go was the natural first choice (hush-noise is Go, hush-relay is Go) but cannot target iOS: CGo is required for non-trivial Go libraries, and Apple's App Store prohibits dynamic linking of non-system runtimes. A Go daemon + IPC approach works for macOS and Linux but is not viable for iOS background sync.

Rust with UniFFI (Mozilla's cross-language binding generator) produces native Swift bindings for iOS/macOS and Kotlin bindings for Android from a single Rust codebase. This is proven in production at Mozilla (Firefox), 1Password, and others.

hush-noise is reimplemented in Rust as part of this work — the same spec (`Noise_XX_25519_ChaChaPoly_BLAKE2s`), the same official test vectors, raw primitives from `ring` or `RustCrypto`. The Go hush-noise implementation remains the reference and continues to power hush-relay.

hush-relay stays in Go — it is a server binary, never ported, and has no platform portability requirement.

All code is AI-written and TDD-driven. The borrow checker review cost is accepted as the tradeoff for true platform reach.
