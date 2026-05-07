use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use hush_noise::{
    keypair::Keypair as NoiseKeypair,
    session::{dial, Session},
};
use thiserror::Error;

use crate::crypto;
use crate::envelope::Envelope;
use crate::message::Message;

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
///
/// Holds the device's noise private key to decrypt incoming Envelope payloads.
/// The subscribe callback receives a decoded Message — decryption and type
/// parsing happen inside RelayClient, never in caller code.
pub struct RelayClient<T: Read + Write + Send + 'static> {
    session: Arc<Session<T>>,
    my_noise_priv: [u8; 32],
    callbacks: Arc<Mutex<Vec<Box<dyn Fn(Message) + Send + 'static>>>>,
}

impl<T: Read + Write + Send + 'static> RelayClient<T> {
    /// Perform a Noise XX handshake over `transport` and verify the relay's identity.
    pub fn connect(
        transport: T,
        relay_pub: [u8; 32],
        my_keypair: NoiseKeypair,
    ) -> Result<Self, RelayError> {
        let my_noise_priv = my_keypair.private();
        let session = dial(transport, my_keypair).map_err(RelayError::HandshakeFailed)?;

        if session.remote_public_key() != relay_pub {
            return Err(RelayError::HandshakeFailed(
                "relay public key mismatch".into(),
            ));
        }

        Ok(Self {
            session: Arc::new(session),
            my_noise_priv,
            callbacks: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Encrypt a Message for `recipient_pub` and push the resulting Envelope to the relay.
    pub fn push(
        &self,
        message: &Message,
        recipient_pub: [u8; 32],
        sequence: u64,
        parents: Vec<[u8; 32]>,
        author_signing: &crate::envelope::SigningKeypair,
    ) -> Result<(), RelayError> {
        let plaintext = message.encode();
        let payload = crypto::encrypt(recipient_pub, &plaintext);
        let envelope = Envelope::build(sequence, parents, recipient_pub, author_signing, payload);
        let body = envelope.encode();
        let msg = frame(MsgType::Push, &body);
        self.session.send(&msg).map_err(RelayError::PushFailed)
    }

    /// Register a callback invoked when the relay delivers a Message to this device.
    /// Decryption and type parsing happen inside — callers receive a clean Message.
    pub fn subscribe(&self, callback: impl Fn(Message) + Send + 'static) {
        self.callbacks.lock().unwrap().push(Box::new(callback));
    }

    /// Blocking receive loop — decrypts and dispatches incoming Messages to callbacks.
    /// Returns when the session closes.
    pub fn run(&self) -> Result<(), RelayError> {
        loop {
            let raw = self.session.receive().map_err(RelayError::ReceiveFailed)?;
            if let Some((MsgType::Deliver, body)) = parse(&raw) {
                if let Ok(env) = Envelope::decode(body) {
                    // Decrypt payload — silently discard if decryption or parsing fails
                    if let Ok(plaintext) = crypto::decrypt(self.my_noise_priv, &env.payload) {
                        if let Ok(msg) = Message::decode(&plaintext) {
                            // Verify envelope signature before delivering
                            if env.verify().is_ok() {
                                let cbs = self.callbacks.lock().unwrap();
                                for cb in cbs.iter() {
                                    cb(msg.clone());
                                }
                            }
                        }
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
    use crate::envelope::SigningKeypair;
    use crate::message::Message;
    use hush_noise::{
        keypair::{generate_keypair, Keypair},
        session::accept,
    };
    use std::io;
    use std::sync::{Arc, Mutex};

    // ── In-memory bidirectional pipe ──────────────────────────────────────────

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

    /// Spawns a fake relay. Receives Push messages and records raw envelope bytes.
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

    /// Helper: connect a device client to a fake relay, return (client, received_envelopes)
    fn connect_device(
        device: &DeviceKeypair,
        relay_pub: [u8; 32],
        client_pipe: MemPipe,
    ) -> RelayClient<MemPipe> {
        RelayClient::connect(
            client_pipe,
            relay_pub,
            Keypair::new(device.noise.private(), device.noise.public_key),
        )
        .expect("connect should succeed")
    }

    /// Tracer bullet: a device pushes a Sync message; the fake relay receives the envelope.
    #[test]
    fn device_can_push_sync_message_to_relay() {
        let relay_kp = generate_keypair();
        let relay_pub = relay_kp.public_key;
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);

        let (client_pipe, relay_pipe) = mem_pipe_pair();
        let received = spawn_fake_relay(relay_pipe, relay_kp2);

        let sender = DeviceKeypair::generate();
        let recipient = DeviceKeypair::generate();
        let client = connect_device(&sender, relay_pub, client_pipe);

        let msg = Message::Sync {
            body: b"clipboard entry".to_vec(),
        };
        client
            .push(
                &msg,
                recipient.noise.public_key,
                1,
                vec![],
                &sender.signing_keypair(),
            )
            .expect("push should succeed");

        std::thread::sleep(std::time::Duration::from_millis(50));

        let stored = received.lock().unwrap();
        assert_eq!(stored.len(), 1, "relay should have received one envelope");
    }

    /// Connecting with the wrong relay public key is rejected.
    #[test]
    fn wrong_relay_key_is_rejected() {
        let relay_kp = generate_keypair();
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);
        let wrong_pub = generate_keypair().public_key;

        let (client_pipe, relay_pipe) = mem_pipe_pair();
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
        assert!(matches!(
            result.err().unwrap(),
            RelayError::HandshakeFailed(_)
        ));
    }

    /// Subscribe callback receives a decoded Message when the relay delivers an envelope.
    #[test]
    fn subscribe_callback_receives_decoded_message() {
        let relay_kp = generate_keypair();
        let relay_pub = relay_kp.public_key;
        let relay_kp2 = Keypair::new(relay_kp.private(), relay_kp.public_key);

        let (client_pipe, relay_pipe) = mem_pipe_pair();

        let recipient = DeviceKeypair::generate();
        let sender_signing = SigningKeypair::generate();
        let msg_to_deliver = Message::Sync {
            body: b"hello!".to_vec(),
        };

        // Fake relay: deliver one envelope to the client after handshake
        {
            let recipient_pub = recipient.noise.public_key;
            let plaintext = msg_to_deliver.encode();
            let payload = crate::crypto::encrypt(recipient_pub, &plaintext);
            let env = Envelope::build(1, vec![], recipient_pub, &sender_signing, payload);
            let env_bytes = env.encode();

            std::thread::spawn(move || {
                let session = accept(relay_pipe, relay_kp2).unwrap();
                let msg = frame(MsgType::Deliver, &env_bytes);
                session.send(&msg).unwrap();
            });
        }

        let client = connect_device(&recipient, relay_pub, client_pipe);

        let delivered: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
        let delivered_clone = delivered.clone();
        client.subscribe(move |msg| {
            delivered_clone.lock().unwrap().push(msg);
        });

        let client = Arc::new(client);
        let client_clone = client.clone();
        std::thread::spawn(move || {
            let _ = client_clone.run();
        });

        std::thread::sleep(std::time::Duration::from_millis(50));

        let got = delivered.lock().unwrap();
        assert_eq!(got.len(), 1, "callback should have fired once");
        assert_eq!(got[0], msg_to_deliver);
    }

    /// Full pairing ceremony: A generates a pairing payload, B decodes it, pushes
    /// a Pair message addressed to A. A's subscribe callback receives B's public keys.
    ///
    /// This is an end-to-end integration test: message → crypto → envelope → relay
    /// → relay routes Push as Deliver → relay → crypto → envelope → message.
    #[test]
    fn pairing_ceremony_delivers_pair_message_to_initiator() {
        use crate::message::{decode_pairing_payload, pairing_payload};

        // ── Relay setup: two pipes (A↔relay, B↔relay) ──────────────────────
        let relay_kp = generate_keypair();
        let relay_pub = relay_kp.public_key;

        // Two pipe pairs — one per device
        let (pipe_a_client, pipe_a_relay) = mem_pipe_pair();
        let (pipe_b_client, pipe_b_relay) = mem_pipe_pair();

        // Routing relay: accepts A then B, receives Push from B, delivers to A.
        // Uses raw Noise sessions directly (no RelayClient).
        {
            let relay_kp_a = Keypair::new(relay_kp.private(), relay_kp.public_key);
            let relay_kp_b = Keypair::new(relay_kp.private(), relay_kp.public_key);
            std::thread::spawn(move || {
                let sess_a = accept(pipe_a_relay, relay_kp_a).unwrap();
                let sess_b = accept(pipe_b_relay, relay_kp_b).unwrap();
                // Receive Push from B, route as Deliver to A
                loop {
                    let raw = match sess_b.receive() {
                        Ok(r) => r,
                        Err(_) => break,
                    };
                    if let Some((MsgType::Push, body)) = parse(&raw) {
                        let deliver = frame(MsgType::Deliver, body);
                        let _ = sess_a.send(&deliver);
                    }
                }
            });
        }

        // ── Devices ─────────────────────────────────────────────────────────
        let device_a = DeviceKeypair::generate();
        let device_b = DeviceKeypair::generate();

        // A generates its pairing payload (would be encoded as QR in real life)
        let payload_bytes =
            pairing_payload(&device_a.noise.public_key, &device_a.signing_public_key());

        // B decodes A's pairing payload and obtains A's public keys
        let (a_noise_pub, _a_signing_pub) =
            decode_pairing_payload(&payload_bytes).expect("should decode pairing payload");

        // A connects to the relay and subscribes
        let client_a = connect_device(&device_a, relay_pub, pipe_a_client);
        let received: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
        let received_clone = received.clone();
        client_a.subscribe(move |msg| {
            received_clone.lock().unwrap().push(msg);
        });
        let client_a = Arc::new(client_a);
        let ca_clone = client_a.clone();
        std::thread::spawn(move || {
            let _ = ca_clone.run();
        });

        // B connects and pushes a Pair message addressed to A
        let client_b = connect_device(&device_b, relay_pub, pipe_b_client);
        let pair_msg = Message::Pair {
            noise_pub: device_b.noise.public_key,
            signing_pub: device_b.signing_public_key(),
        };
        client_b
            .push(
                &pair_msg,
                a_noise_pub,
                1,
                vec![],
                &device_b.signing_keypair(),
            )
            .expect("push should succeed");

        std::thread::sleep(std::time::Duration::from_millis(100));

        // A's callback should have received B's Pair message
        let got = received.lock().unwrap();
        assert_eq!(got.len(), 1, "A should have received exactly one message");
        assert_eq!(
            got[0],
            Message::Pair {
                noise_pub: device_b.noise.public_key,
                signing_pub: device_b.signing_public_key(),
            },
            "A should receive B's Pair message with B's public keys"
        );
    }
}
