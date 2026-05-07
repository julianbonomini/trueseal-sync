use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use hush_noise::{
    keypair::Keypair as NoiseKeypair,
    session::{dial, Session},
};
use thiserror::Error;

use crate::envelope::Envelope;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("push failed: {0}")]
    PushFailed(String),
    #[error("receive failed: {0}")]
    ReceiveFailed(String),
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
}

/// Wire protocol framing over the Noise session.
/// Each message: [msg_type: u8][len: u32 BE][body: bytes]
#[repr(u8)]
#[derive(PartialEq)]
pub(crate) enum MsgType {
    Push = 0x01,
    Deliver = 0x02,
}

impl MsgType {
    pub(crate) fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Push),
            0x02 => Some(Self::Deliver),
            _ => None,
        }
    }
}

/// Frame a typed message into bytes for sending over a Noise session.
pub(crate) fn frame(msg_type: MsgType, body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(5 + body.len());
    msg.push(msg_type as u8);
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes());
    msg.extend_from_slice(body);
    msg
}

/// Parse a framed message received from a Noise session.
pub(crate) fn parse(raw: &[u8]) -> Option<(MsgType, &[u8])> {
    if raw.len() < 5 {
        return None;
    }
    let msg_type = MsgType::from_u8(raw[0])?;
    let len = u32::from_be_bytes(raw[1..5].try_into().ok()?) as usize;
    if raw.len() < 5 + len {
        return None;
    }
    Some((msg_type, &raw[5..5 + len]))
}

/// Client-side connection to a hush-relay server.
/// Transport-generic: uses any Read+Write+Send stream (TCP in production,
/// in-memory pipes in tests).
pub struct RelayClient<T: Read + Write + Send + 'static> {
    session: Arc<Session<T>>,
    callbacks: Arc<Mutex<Vec<Box<dyn Fn(Envelope) + Send + 'static>>>>,
}

impl<T: Read + Write + Send + 'static> RelayClient<T> {
    /// Perform a Noise XX handshake over `transport` and verify the relay's identity.
    pub fn connect(
        transport: T,
        relay_pub: [u8; 32],
        my_keypair: NoiseKeypair,
    ) -> Result<Self, RelayError> {
        let session = dial(transport, my_keypair).map_err(|e| RelayError::HandshakeFailed(e))?;

        if session.remote_public_key() != relay_pub {
            return Err(RelayError::HandshakeFailed(
                "relay public key mismatch".into(),
            ));
        }

        Ok(Self {
            session: Arc::new(session),
            callbacks: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Push an Envelope to the relay (addressed to envelope.recipient_pub).
    pub fn push(&self, envelope: &Envelope) -> Result<(), RelayError> {
        let body = envelope.encode();
        let msg = frame(MsgType::Push, &body);
        self.session
            .send(&msg)
            .map_err(|e| RelayError::PushFailed(e))
    }

    /// Register a callback invoked when the relay delivers an Envelope to this device.
    pub fn subscribe(&self, callback: impl Fn(Envelope) + Send + 'static) {
        self.callbacks.lock().unwrap().push(Box::new(callback));
    }

    /// Blocking receive loop — delivers incoming envelopes to registered callbacks.
    /// Returns when the session closes.
    pub fn run(&self) -> Result<(), RelayError> {
        loop {
            let raw = self
                .session
                .receive()
                .map_err(|e| RelayError::ReceiveFailed(e))?;
            if let Some((MsgType::Deliver, body)) = parse(&raw) {
                if let Ok(env) = Envelope::decode(body) {
                    let cbs = self.callbacks.lock().unwrap();
                    for cb in cbs.iter() {
                        cb(env.clone());
                    }
                }
            }
        }
    }
}

// ── Convenience constructor for TCP connections ──────────────────────────────

use std::net::TcpStream;

impl RelayClient<TcpStream> {
    /// Connect to a relay over TCP at `addr`.
    pub fn connect_tcp(
        addr: &str,
        relay_pub: [u8; 32],
        my_keypair: NoiseKeypair,
    ) -> Result<Self, RelayError> {
        let stream =
            TcpStream::connect(addr).map_err(|e| RelayError::ConnectionFailed(e.to_string()))?;
        Self::connect(stream, relay_pub, my_keypair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceKeypair;
    use crate::envelope::{Envelope, SigningKeypair};
    use hush_noise::{
        keypair::{generate_keypair, Keypair},
        session::accept,
    };
    use std::io;
    use std::sync::{Arc, Mutex};

    // ── In-memory bidirectional pipe (mirrors hush-noise's test pattern) ──────

    struct MemPipe {
        read_buf: Arc<Mutex<Vec<u8>>>,
        write_buf: Arc<Mutex<Vec<u8>>>,
    }

    impl Read for MemPipe {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            loop {
                let mut rb = self.read_buf.lock().unwrap();
                if !rb.is_empty() {
                    let n = buf.len().min(rb.len());
                    buf[..n].copy_from_slice(&rb[..n]);
                    rb.drain(..n);
                    return Ok(n);
                }
                drop(rb);
                std::thread::sleep(std::time::Duration::from_micros(100));
            }
        }
    }

    impl Write for MemPipe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_buf.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn mem_pipe_pair() -> (MemPipe, MemPipe) {
        let ab = Arc::new(Mutex::new(Vec::new()));
        let ba = Arc::new(Mutex::new(Vec::new()));
        (
            MemPipe {
                read_buf: ba.clone(),
                write_buf: ab.clone(),
            },
            MemPipe {
                read_buf: ab.clone(),
                write_buf: ba.clone(),
            },
        )
    }

    // ── Minimal fake relay ────────────────────────────────────────────────────

    /// Spawns a fake relay on a MemPipe. Accepts one Noise XX connection,
    /// receives Push messages, stores decoded envelopes.
    fn spawn_fake_relay(relay_pipe: MemPipe, relay_keypair: Keypair) -> Arc<Mutex<Vec<Envelope>>> {
        let received = Arc::new(Mutex::new(Vec::<Envelope>::new()));
        let received_clone = received.clone();
        std::thread::spawn(move || {
            let session = accept(relay_pipe, relay_keypair).unwrap();
            loop {
                let raw = match session.receive() {
                    Ok(r) => r,
                    Err(_) => break,
                };
                if let Some((MsgType::Push, body)) = parse(&raw) {
                    if let Ok(env) = Envelope::decode(body) {
                        received_clone.lock().unwrap().push(env);
                    }
                }
            }
        });
        received
    }

    /// Tracer bullet: a device connects to the fake relay and pushes an Envelope.
    /// The fake relay receives and stores it.
    #[test]
    fn device_can_push_envelope_to_relay() {
        let relay_kp = generate_keypair();
        let relay_pub = relay_kp.public_key;
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);

        let (client_pipe, relay_pipe) = mem_pipe_pair();
        let received = spawn_fake_relay(relay_pipe, relay_kp2);

        let device = DeviceKeypair::generate();
        let client = RelayClient::connect(
            client_pipe,
            relay_pub,
            Keypair::new(device.noise.private(), device.noise.public_key),
        )
        .expect("connect should succeed");

        let signing = SigningKeypair::generate();
        let recipient_pub = DeviceKeypair::generate().noise.public_key;
        let envelope = Envelope::build(1, vec![], recipient_pub, &signing, b"hello relay".to_vec());

        client.push(&envelope).expect("push should succeed");

        std::thread::sleep(std::time::Duration::from_millis(50));

        let stored = received.lock().unwrap();
        assert_eq!(stored.len(), 1, "relay should have received one envelope");
        assert_eq!(stored[0], envelope);
    }

    /// Connecting with a wrong relay public key is rejected.
    #[test]
    fn wrong_relay_key_is_rejected() {
        let relay_kp = generate_keypair();
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let wrong_pub = generate_keypair().public_key; // a different key

        let (client_pipe, relay_pipe) = mem_pipe_pair();
        // Relay accepts the handshake (it doesn't know client expects a specific key)
        std::thread::spawn(move || {
            let _ = accept(relay_pipe, relay_kp2);
        });

        let device = DeviceKeypair::generate();
        let result = RelayClient::connect(
            client_pipe,
            wrong_pub,
            Keypair::new(device.noise.private(), device.noise.public_key),
        );

        assert!(result.is_err(), "wrong relay key should be rejected");
        assert!(
            matches!(result.err().unwrap(), RelayError::HandshakeFailed(_)),
            "error should be HandshakeFailed"
        );
    }

    /// Push-on-arrival: subscribe callback fires when the fake relay delivers an Envelope.
    #[test]
    fn subscribe_callback_fires_on_delivery() {
        let relay_kp = generate_keypair();
        let relay_pub = relay_kp.public_key;
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);

        let (client_pipe, relay_pipe) = mem_pipe_pair();

        // Fake relay that delivers an envelope immediately after handshake
        let signing = SigningKeypair::generate();
        let device = DeviceKeypair::generate();
        let recipient_pub = device.noise.public_key;
        let envelope_to_deliver =
            Envelope::build(1, vec![], recipient_pub, &signing, b"delivered!".to_vec());
        let env_clone = envelope_to_deliver.clone();

        std::thread::spawn(move || {
            let session = accept(relay_pipe, relay_kp2).unwrap();
            // Deliver an envelope to the client
            let body = env_clone.encode();
            let msg = frame(MsgType::Deliver, &body);
            session.send(&msg).unwrap();
        });

        let client = RelayClient::connect(
            client_pipe,
            relay_pub,
            Keypair::new(device.noise.private(), device.noise.public_key),
        )
        .expect("connect should succeed");

        let delivered: Arc<Mutex<Vec<Envelope>>> = Arc::new(Mutex::new(Vec::new()));
        let delivered_clone = delivered.clone();
        client.subscribe(move |env| {
            delivered_clone.lock().unwrap().push(env);
        });

        // Run the receive loop in a thread
        let client = Arc::new(client);
        let client_clone = client.clone();
        std::thread::spawn(move || {
            let _ = client_clone.run();
        });

        std::thread::sleep(std::time::Duration::from_millis(50));

        let got = delivered.lock().unwrap();
        assert_eq!(got.len(), 1, "callback should have fired once");
        assert_eq!(got[0], envelope_to_deliver);
    }
}
