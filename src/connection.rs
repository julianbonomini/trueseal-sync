//! The connection factory — the only place production code opens sockets
//! (SYNC-17, issue #109; decision trueseal-roadmap#26).
//!
//! The IP-hiding decision defers network-level hiding (Tor, a third-party
//! CONNECT/MASQUE hop) and names this seam as the single place to add it
//! later: every receive (XX) and push (NK) connection the core opens flows
//! through [`ConnectionFactory`], so a future proxy transport is a local
//! change here rather than a hunt through socket call sites — and no code
//! path can quietly bypass it. `scripts/check-connection-factory.sh` runs in
//! CI and fails if a direct `TcpStream::connect` appears anywhere else in
//! production code.
//!
//! The factory produces a plain non-blocking `TcpStream`. Everything else a
//! session needs — the Transport Version exchange deadline, the handshake and
//! Ack deadlines, the liveness machinery and the sever handles (SYNC-1 /
//! SYNC-15 / SYNC-16, ADR-0019) — composes downstream inside
//! `RelayClient::connect` and the push path for ANY transport, so there is
//! exactly one construction path and no parallel path can forget a wrapper.
//!
//! Tests inject their own factories (in-memory pipes) through the session
//! constructors; that is the supported seam for harness transports and does
//! not open sockets.

use std::net::TcpStream;
use std::sync::Arc;

/// Opens the sockets a session needs: the long-lived XX receive connection
/// and one NK connection per push.
pub struct ConnectionFactory {
    receive_addr: String,
    push_addr: String,
}

impl ConnectionFactory {
    pub fn new(receive_addr: impl Into<String>, push_addr: impl Into<String>) -> Self {
        Self {
            receive_addr: receive_addr.into(),
            push_addr: push_addr.into(),
        }
    }

    /// The one socket-open in production code: TCP connect, then non-blocking
    /// mode. Non-blocking is required before the stream enters `RelayClient`:
    /// the Transport Version exchange's deadline only fires on a non-blocking
    /// stream (a silent pre-version relay surfaces as a typed timeout instead
    /// of hanging a blocking `read()` forever), and a blocking receive would
    /// hold the session lock for the whole `read()` syscall, starving
    /// concurrent sends.
    pub fn open(addr: &str) -> Result<TcpStream, String> {
        let stream = TcpStream::connect(addr).map_err(|e| e.to_string())?;
        stream.set_nonblocking(true).map_err(|e| e.to_string())?;
        Ok(stream)
    }

    /// Open the receive (XX) connection.
    pub fn open_receive(&self) -> Result<TcpStream, String> {
        Self::open(&self.receive_addr)
    }

    /// Open one push (NK) connection.
    pub fn open_push(&self) -> Result<TcpStream, String> {
        Self::open(&self.push_addr)
    }

    /// The `(receive_factory, push_factory)` closure pair the session
    /// constructors (`connect_background`, `connect_background_rotating`)
    /// take. The factories are cheap to call: every reconnect and every push
    /// opens a fresh socket through [`ConnectionFactory::open`].
    pub fn into_factories(
        self,
    ) -> (
        impl Fn() -> Result<TcpStream, String> + Send + Sync + 'static,
        impl Fn() -> Result<TcpStream, String> + Send + Sync + 'static,
    ) {
        let factory = Arc::new(self);
        let receive = {
            let factory = factory.clone();
            move || factory.open_receive()
        };
        let push = move || factory.open_push();
        (receive, push)
    }
}
