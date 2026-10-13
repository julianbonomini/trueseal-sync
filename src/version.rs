//! Protocol versions and the Transport Version exchange (ADR-0022).
//!
//! TrueSeal carries two independent, fixed protocol versions:
//!
//! - **Transport Version** — Device↔Relay (Noise handshake and relay frames).
//!   Sent as a short plaintext prefix at the start of every connection and
//!   bound into the Noise prologue, so a tampered prefix breaks the handshake.
//! - **End-to-End Version** — Device↔Device (Envelope, signatures, addressed
//!   encryption). Bound into HKDF info, AEAD associated data and the
//!   domain-separated signing inputs, and carried as a signed plaintext field
//!   on every Envelope.
//!
//! There is no negotiation and no mixed-version operation. Versions start at
//! 1 (0 is reserved and means "the refused unversioned format"). These
//! constants are the single source for every binding above.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// The one Transport Version this build speaks (ADR-0022).
pub const TRANSPORT_VERSION: u32 = 1;

/// The one End-to-End Version this build speaks (ADR-0022).
pub const END_TO_END_VERSION: u32 = 1;

/// Cap on newer-End-to-End-Version Blobs held unacked per Device, awaiting a
/// library upgrade (ADR-0022). Beyond the cap the oldest held Blob is acked
/// and dropped with `unreadable(droppedWhileHeld)` (ADR-0034).
pub const MAX_HELD_BLOBS: usize = 100;

// ── Store versions (ADR-0032) ─────────────────────────────────────────────────
//
// Store Versions are independent of protocol versions: they version the local
// Session State format, not the wire. The first preview release (0.6.0)
// writes Store Version 1.

/// The Store Version this build writes (ADR-0032). Session State records it;
/// every later release migrates forward in chains from any version at or
/// above the floor.
pub const STORE_VERSION: u32 = 1;

/// The migration floor (ADR-0032): the oldest Store Version this build will
/// migrate. Anything older — including the unversioned stores development
/// builds left behind — is unmigratable and reset automatically with the
/// `storeReset` status reason. A Store Reset release moves the floor to
/// itself and needs the product owner's explicit approval.
pub const STORE_MIGRATION_FLOOR: u32 = 1;

// ── Domain-separated cryptographic bindings ───────────────────────────────────
//
// Every string below is derived from END_TO_END_VERSION so the constants above
// are the single source. A blob sealed under one version can never be opened,
// verified or re-interpreted under another.

/// HKDF-SHA256 info for addressed encryption (was the unversioned
/// `trueseal-sync addressed encryption v0`).
pub fn addressed_encryption_hkdf_info() -> Vec<u8> {
    format!("trueseal-sync addressed encryption v{END_TO_END_VERSION}").into_bytes()
}

/// AEAD associated data for addressed encryption. Binds the ciphertext to the
/// End-to-End Version so the bytes cannot be re-labelled cross-version.
pub fn addressed_encryption_aad() -> Vec<u8> {
    format!("trueseal-sync addressed encryption aad v{END_TO_END_VERSION}").into_bytes()
}

/// Domain separator prepended to the Envelope signing input.
pub fn envelope_signing_domain() -> Vec<u8> {
    format!("trueseal-sync envelope v{END_TO_END_VERSION}\0").into_bytes()
}

/// Domain separator prepended to the Group Manifest signing input.
pub fn manifest_signing_domain() -> Vec<u8> {
    manifest_signing_domain_for(END_TO_END_VERSION)
}

/// The manifest signing domain for an explicit End-to-End Version. The
/// migration re-seal (ADR-0034 §1, SYNC-13) re-signs queued manifests under
/// the version being migrated TO, which is not this build's constant while a
/// bump is simulated in tests.
pub fn manifest_signing_domain_for(version: u32) -> Vec<u8> {
    format!("trueseal-sync manifest v{version}\0").into_bytes()
}

// ── Transport Version prefix ──────────────────────────────────────────────────
//
// Wire layout (ADR-0022; the byte-level contract RELAY-5 implements and the
// SYNC-2 test vectors pin):
//
//   client → relay : "TSP" || version:u16 BE          (5 bytes, plaintext)
//   relay → client : 0x01                             (supported — proceed)
//                  | "unsupported <min>..<max>\n"      (refused — then close)
//
// On 0x01 both sides run the Noise handshake with the exact 5 prefix bytes as
// the prologue, binding the Transport Version into the handshake hash.
// A relay speaking the pre-version format never replies; the exchange times
// out and surfaces as a connection failure — that format is refused by design.

const PREFIX_MAGIC: [u8; 3] = *b"TSP";

/// Length of the plaintext Transport Version prefix.
pub const TRANSPORT_PREFIX_LEN: usize = 5;

/// Byte the relay sends to accept the offered Transport Version.
const REPLY_SUPPORTED: u8 = 0x01;

/// Longest `unsupported <min>..<max>` reply line the client will read.
const MAX_REPLY_LEN: usize = 64;

/// Deadline for the whole prefix exchange. A silent (pre-version) relay
/// surfaces as a connection timeout, not a hang.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// The plaintext Transport Version prefix this client sends.
pub fn transport_prefix() -> [u8; TRANSPORT_PREFIX_LEN] {
    [
        PREFIX_MAGIC[0],
        PREFIX_MAGIC[1],
        PREFIX_MAGIC[2],
        (TRANSPORT_VERSION >> 8) as u8,
        (TRANSPORT_VERSION & 0xff) as u8,
    ]
}

/// Why a Transport Version exchange failed.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum TransportVersionError {
    /// The relay refused our Transport Version and reported the range it
    /// supports. Surfaced as `RelayVersionUnsupported{min,max}`.
    #[error(
        "relay supports Transport Version {min}..={max}, this build speaks {TRANSPORT_VERSION}"
    )]
    Unsupported { min: u32, max: u32 },
    /// The exchange itself failed (I/O, timeout, or an unparseable reply).
    #[error("transport version exchange failed: {0}")]
    Exchange(String),
}

/// Parse a relay refusal line of the form `unsupported <min>..<max>`.
/// Returns `(min, max)` when well-formed.
pub fn parse_unsupported_reply(line: &[u8]) -> Option<(u32, u32)> {
    let text = std::str::from_utf8(line).ok()?.trim();
    let range = text.strip_prefix("unsupported ")?;
    let (min, max) = range.split_once("..")?;
    Some((min.trim().parse().ok()?, max.trim().parse().ok()?))
}

/// Perform the client half of the Transport Version exchange on a fresh
/// transport. On success returns the prefix bytes to use as the Noise
/// prologue. Tolerates non-blocking transports (`WouldBlock`) up to the
/// exchange deadline.
pub fn exchange_transport_version<T: Read + Write>(
    transport: &mut T,
) -> Result<[u8; TRANSPORT_PREFIX_LEN], TransportVersionError> {
    let deadline = Instant::now() + EXCHANGE_TIMEOUT;
    let prefix = transport_prefix();
    write_all_retry(transport, &prefix, deadline)?;

    // First reply byte: 0x01 = supported, 'u' = start of an `unsupported` line.
    let mut first = [0u8; 1];
    read_exact_retry(transport, &mut first, deadline)?;
    match first[0] {
        REPLY_SUPPORTED => Ok(prefix),
        b'u' => {
            let mut line = vec![b'u'];
            while line.len() < MAX_REPLY_LEN {
                let mut byte = [0u8; 1];
                read_exact_retry(transport, &mut byte, deadline)?;
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            match parse_unsupported_reply(&line) {
                Some((min, max)) => Err(TransportVersionError::Unsupported { min, max }),
                None => Err(TransportVersionError::Exchange(format!(
                    "unparseable refusal: {line:?}"
                ))),
            }
        }
        other => Err(TransportVersionError::Exchange(format!(
            "unexpected reply byte 0x{other:02x}"
        ))),
    }
}

fn write_all_retry<T: Write>(
    transport: &mut T,
    mut buf: &[u8],
    deadline: Instant,
) -> Result<(), TransportVersionError> {
    while !buf.is_empty() {
        match transport.write(buf) {
            Ok(0) => {
                return Err(TransportVersionError::Exchange("write returned 0".into()));
            }
            Ok(n) => buf = &buf[n..],
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::Interrupted =>
            {
                check_deadline(deadline)?;
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(TransportVersionError::Exchange(e.to_string())),
        }
    }
    transport
        .flush()
        .map_err(|e| TransportVersionError::Exchange(e.to_string()))
}

fn read_exact_retry<T: Read>(
    transport: &mut T,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<(), TransportVersionError> {
    let mut filled = 0;
    while filled < buf.len() {
        match transport.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(TransportVersionError::Exchange(
                    "connection closed during version exchange".into(),
                ));
            }
            Ok(n) => filled += n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::Interrupted =>
            {
                check_deadline(deadline)?;
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(TransportVersionError::Exchange(e.to_string())),
        }
    }
    Ok(())
}

fn check_deadline(deadline: Instant) -> Result<(), TransportVersionError> {
    if Instant::now() >= deadline {
        return Err(TransportVersionError::Exchange(
            "timed out waiting for the relay's version reply".into(),
        ));
    }
    Ok(())
}

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Server half of the prefix exchange, shared by every in-repo fake relay.
/// Reads and validates the prefix, replies `0x01`, and returns the prefix
/// bytes to use as the Noise prologue.
///
/// The read deadline is the generous HARNESS constant, not the production
/// EXCHANGE_TIMEOUT: a fake relay's accept thread starts waiting the moment
/// the relay is SET UP, and in reconnect tests the client only dials the
/// replacement pipe after the first pipe's failure is detected and the
/// reconnect loop polls — legitimately far later. Under full-suite CI load
/// (hundreds of relay/client threads) that gap exceeded 10 s and the relay
/// thread panicked mid-test, cascading into lost deliveries (the
/// `post_reconnect_destroy` flake class, #55 — diagnosed in the B12b PR).
/// Timing expectations in tests are enforced by each test's own wait
/// budgets, not by the harness plumbing.
#[cfg(test)]
const HARNESS_ACCEPT_TIMEOUT: Duration = Duration::from_secs(120);

#[cfg(test)]
pub(crate) fn fake_relay_accept_prefix<T: Read + Write>(transport: &mut T) -> [u8; 5] {
    let deadline = Instant::now() + HARNESS_ACCEPT_TIMEOUT;
    let mut prefix = [0u8; TRANSPORT_PREFIX_LEN];
    read_exact_retry(transport, &mut prefix, deadline).expect("fake relay reads the prefix");
    assert_eq!(
        &prefix[..3],
        PREFIX_MAGIC,
        "fake relay expects the TSP magic"
    );
    transport
        .write_all(&[REPLY_SUPPORTED])
        .expect("fake relay writes the supported byte");
    transport.flush().expect("fake relay flushes");
    prefix
}

/// Fake-relay Noise accepts that speak the Transport Version exchange first,
/// exactly as RELAY-5 will. Every in-repo fake relay goes through these so the
/// version binding is exercised in every test.
#[cfg(test)]
pub(crate) mod testutil {
    use super::fake_relay_accept_prefix;
    use std::io::{Read, Write};
    use trueseal_noise::keypair::Keypair;

    /// XX accept: prefix exchange, then the handshake with the prefix as prologue.
    pub(crate) fn xx_accept_after_prefix<T: Read + Write + Send>(
        mut transport: T,
        keypair: Keypair,
    ) -> Result<trueseal_noise::session_xx::Session<T>, String> {
        let prologue = fake_relay_accept_prefix(&mut transport);
        trueseal_noise::session_xx::accept(transport, keypair, &prologue)
    }

    /// NK accept: prefix exchange, then the handshake with the prefix as prologue.
    pub(crate) fn nk_accept_after_prefix<T: Read + Write + Send>(
        mut transport: T,
        keypair: Keypair,
    ) -> Result<trueseal_noise::session_nk::Session<T>, String> {
        let prologue = fake_relay_accept_prefix(&mut transport);
        trueseal_noise::session_nk::accept(transport, keypair, &prologue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io;
    use std::sync::{Arc, Mutex};

    /// Scriptable in-memory transport: reads come from `script`, writes are recorded.
    struct FakeIo {
        script: VecDeque<u8>,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl Read for FakeIo {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.script.is_empty() {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "script empty"));
            }
            let n = buf.len().min(self.script.len());
            for slot in &mut buf[..n] {
                *slot = self.script.pop_front().expect("checked non-empty");
            }
            Ok(n)
        }
    }

    impl Write for FakeIo {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn fake_io(script: &[u8]) -> (FakeIo, Arc<Mutex<Vec<u8>>>) {
        let written = Arc::new(Mutex::new(Vec::new()));
        (
            FakeIo {
                script: script.iter().copied().collect(),
                written: written.clone(),
            },
            written,
        )
    }

    /// The versions start at 1; 0 is reserved for the refused unversioned format.
    #[test]
    fn versions_start_at_one() {
        assert_eq!(TRANSPORT_VERSION, 1);
        assert_eq!(END_TO_END_VERSION, 1);
        assert!(TRANSPORT_VERSION <= u16::MAX as u32, "prefix encodes u16");
    }

    /// The prefix is "TSP" + u16 BE version.
    #[test]
    fn transport_prefix_layout() {
        assert_eq!(transport_prefix(), [0x54, 0x53, 0x50, 0x00, 0x01]);
    }

    /// Every cryptographic binding carries the End-to-End Version.
    #[test]
    fn bindings_carry_the_end_to_end_version() {
        let v = END_TO_END_VERSION.to_string();
        assert!(String::from_utf8(addressed_encryption_hkdf_info())
            .expect("utf8")
            .ends_with(&format!("v{v}")));
        assert!(String::from_utf8(addressed_encryption_aad())
            .expect("utf8")
            .ends_with(&format!("v{v}")));
        assert!(String::from_utf8(envelope_signing_domain())
            .expect("utf8")
            .ends_with(&format!("v{v}\0")));
        assert!(String::from_utf8(manifest_signing_domain())
            .expect("utf8")
            .ends_with(&format!("v{v}\0")));
        // Distinct domains — a signature or key stream from one context can
        // never be replayed into another.
        assert_ne!(envelope_signing_domain(), manifest_signing_domain());
        assert_ne!(addressed_encryption_hkdf_info(), addressed_encryption_aad());
    }

    /// The exact binding bytes are pinned, so a revert to the legacy
    /// unversioned info string or a dropped AAD domain fails this test even
    /// though every encrypt/decrypt round-trip would still pass. Stopgap
    /// until the SYNC-2 JSON test vectors pin these bytes cross-repo.
    #[test]
    fn binding_bytes_are_pinned() {
        assert_eq!(
            addressed_encryption_hkdf_info(),
            b"trueseal-sync addressed encryption v1"
        );
        assert_eq!(
            addressed_encryption_aad(),
            b"trueseal-sync addressed encryption aad v1"
        );
        assert_eq!(envelope_signing_domain(), b"trueseal-sync envelope v1\0");
        assert_eq!(manifest_signing_domain(), b"trueseal-sync manifest v1\0");
    }

    #[test]
    fn parse_unsupported_reply_accepts_the_documented_form() {
        assert_eq!(parse_unsupported_reply(b"unsupported 1..1\n"), Some((1, 1)));
        assert_eq!(parse_unsupported_reply(b"unsupported 2..4"), Some((2, 4)));
        assert_eq!(
            parse_unsupported_reply(b"unsupported 1..65535"),
            Some((1, 65535))
        );
    }

    #[test]
    fn parse_unsupported_reply_rejects_garbage() {
        assert_eq!(parse_unsupported_reply(b""), None);
        assert_eq!(parse_unsupported_reply(b"supported 1..1"), None);
        assert_eq!(parse_unsupported_reply(b"unsupported 1"), None);
        assert_eq!(parse_unsupported_reply(b"unsupported a..b"), None);
        assert_eq!(parse_unsupported_reply(b"\xff\xfe"), None);
    }

    /// A `0x01` reply completes the exchange and returns the exact prefix
    /// bytes the Noise prologue must use.
    #[test]
    fn exchange_succeeds_on_supported_byte() {
        let (mut io, written) = fake_io(&[REPLY_SUPPORTED]);
        let prefix = exchange_transport_version(&mut io).expect("exchange should succeed");
        assert_eq!(prefix, transport_prefix());
        assert_eq!(
            *written.lock().unwrap_or_else(|e| e.into_inner()),
            transport_prefix(),
            "client sends exactly the prefix"
        );
    }

    /// An `unsupported min..max` line surfaces as a typed refusal.
    #[test]
    fn exchange_surfaces_typed_unsupported() {
        let (mut io, _w) = fake_io(b"unsupported 1..1\n");
        let err = exchange_transport_version(&mut io).expect_err("should be refused");
        assert_eq!(err, TransportVersionError::Unsupported { min: 1, max: 1 });
    }

    /// A different supported range is reported verbatim.
    #[test]
    fn exchange_reports_the_relays_range() {
        let (mut io, _w) = fake_io(b"unsupported 2..3\n");
        let err = exchange_transport_version(&mut io).expect_err("should be refused");
        assert_eq!(err, TransportVersionError::Unsupported { min: 2, max: 3 });
    }

    /// Garbage replies and truncated lines are exchange errors, not panics.
    #[test]
    fn exchange_rejects_garbage_reply() {
        let (mut io, _w) = fake_io(&[0x99]);
        assert!(matches!(
            exchange_transport_version(&mut io),
            Err(TransportVersionError::Exchange(_))
        ));

        let (mut io2, _w2) = fake_io(b"unsupported banana\n");
        assert!(matches!(
            exchange_transport_version(&mut io2),
            Err(TransportVersionError::Exchange(_))
        ));
    }

    /// EOF mid-exchange (a pre-version relay that closes) is an exchange error.
    #[test]
    fn exchange_eof_is_an_error_not_a_hang() {
        struct Eof;
        impl Read for Eof {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Ok(0)
            }
        }
        impl Write for Eof {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut io = Eof;
        assert!(matches!(
            exchange_transport_version(&mut io),
            Err(TransportVersionError::Exchange(_))
        ));
    }

    /// The fake-relay helper round-trips with the client exchange.
    #[test]
    fn fake_relay_prefix_round_trip() {
        use std::os::unix::net::UnixStream;
        use std::sync::mpsc;
        let (mut a, mut b) = UnixStream::pair().expect("socket pair");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let prefix = fake_relay_accept_prefix(&mut b);
            tx.send(prefix).expect("send");
        });
        let client_prefix = exchange_transport_version(&mut a).expect("client exchange");
        let relay_prefix = rx.recv().expect("relay prefix");
        assert_eq!(client_prefix, relay_prefix);
    }
}
