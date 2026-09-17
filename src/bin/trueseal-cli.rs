//! trueseal-cli — interactive PoC CLI for trueseal-sync
//!
//! Starts a session connected to a live relay and drops into a REPL.
//! All state (keypair, manifest, outbox) is persisted in a SQLite database
//! under --dir so the device survives restarts and can drain its inbox on
//! reconnect — demonstrating guaranteed delivery.
//!
//! Usage:
//!   trueseal-cli --dir ./device-a --relay 127.0.0.1 --relay-pub <64-char-hex>
//!
//! Commands:
//!   token              print your pairing token (share with another device)
//!   pair <tok>         send a join request using a token from another device
//!   accept <tok>       admit a device that sent you a join request
//!   send <text>        push a message to all group members
//!   members            list current group members
//!   remove <id>        remove a member by id (or id prefix)
//!   destroy            destroy the group (cryptographic revocation)
//!   quit               exit

use std::io::{self, BufRead, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// SlowStream: wraps a Read+Write to force partial reads.
/// Caps each read to N bytes and sleeps before each call so segments
/// arrive separately. Reproduces real-network framing on loopback.
/// Activated by env var `TRUESEAL_SLOW_READ=<bytes_per_read>`.
struct SlowStream<T: Read + Write + Send> {
    inner: T,
    cap: usize,
    delay_us: u64,
    counter: std::cell::Cell<u32>,
}

impl<T: Read + Write + Send> Read for SlowStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Every other call, return WouldBlock to force RetryConn path.
        let c = self.counter.get();
        self.counter.set(c.wrapping_add(1));
        if c.is_multiple_of(2) && self.cap != usize::MAX {
            std::thread::sleep(std::time::Duration::from_micros(self.delay_us));
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "slow_stream forced",
            ));
        }
        std::thread::sleep(std::time::Duration::from_micros(self.delay_us));
        let n = buf.len().min(self.cap);
        self.inner.read(&mut buf[..n])
    }
}
impl<T: Read + Write + Send> Write for SlowStream<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        std::thread::sleep(std::time::Duration::from_micros(self.delay_us));
        let n = buf.len().min(self.cap);
        self.inner.write(&buf[..n])
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn slow_cap() -> Option<usize> {
    std::env::var("TRUESEAL_SLOW_READ")
        .ok()
        .and_then(|v| v.parse().ok())
}

use trueseal_sync::{
    device::DeviceKeypair,
    keys::NoisePublicKey,
    message::Message,
    session::TruesealSession,
    store::{PersistentLog, Store},
};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let dir = require_flag(&args, "--dir");
    let relay_host = require_flag(&args, "--relay");
    let relay_pub_hex = require_flag(&args, "--relay-pub");

    let dir = PathBuf::from(dir);
    std::fs::create_dir_all(&dir).expect("create state dir");

    // Two ports: receive (XX handshake) and push (NK handshake).
    let receive_addr = format!("{}:7700", relay_host);
    let push_addr = format!("{}:7701", relay_host);

    // Parse relay public key.
    let relay_pub_bytes = hex_to_32(&relay_pub_hex).unwrap_or_else(|e| {
        eprintln!("invalid --relay-pub: {}", e);
        std::process::exit(1);
    });
    let relay_pub = NoisePublicKey(relay_pub_bytes);

    // ── State ─────────────────────────────────────────────────────────────────

    // Primary store — used to load/save identity and manifest on startup.
    let store = Store::open(&dir, "device").expect("open store");

    let keypair = match store.load_keypair().expect("load keypair") {
        Some(kp) => {
            println!("identity loaded");
            kp
        }
        None => {
            let kp = DeviceKeypair::generate();
            store.save_keypair(&kp).expect("save keypair");
            println!("new identity generated");
            kp
        }
    };

    println!("noise pub: {}", bytes_to_hex(&keypair.public_key().0));

    // Load any previously saved manifest so the device restores its group on
    // restart — essential for guaranteed delivery / offline drain testing.
    let existing_manifest = store.load_group_manifest().expect("load manifest");

    // Separate store connection for the on_manifest_changed callback.
    // SQLite WAL mode allows concurrent connections to the same file.
    let manifest_store: Arc<Mutex<Store>> = Arc::new(Mutex::new(
        Store::open(&dir, "device").expect("open manifest store"),
    ));
    let manifest_store_cb = manifest_store.clone();

    // Persistent op log — separate connection, same db file.
    let op_log = Box::new(PersistentLog::new(
        Store::open(&dir, "device").expect("open oplog store"),
    ));

    // ── Session ───────────────────────────────────────────────────────────────

    let recv_addr = receive_addr.clone();
    let push_addr_cb = push_addr.clone();

    let session = TruesealSession::<SlowStream<TcpStream>>::connect_background(
        relay_pub,
        keypair,
        // on_message — fires for every decrypted Sync blob delivered by the relay.
        move |msg, author_pub, _seq| {
            if let Message::Sync { body } = msg {
                let text = String::from_utf8_lossy(&body);
                let author = &bytes_to_hex(&author_pub)[..8];
                println!("\n  [{}] {}", author, text);
                print!("> ");
                io::stdout().flush().ok();
            }
        },
        op_log,
        // on_removed_from_group
        || {
            println!("\n[removed from group]");
            print!("> ");
            io::stdout().flush().ok();
        },
        // on_manifest_changed — persist every manifest update so the device
        // can restore its group membership after a restart.
        move |manifest| {
            if let Ok(s) = manifest_store_cb.lock() {
                let _ = s.save_group_manifest(manifest);
            }
        },
        // on_group_destroyed
        || {
            println!("\n[group destroyed]");
            print!("> ");
            io::stdout().flush().ok();
        },
        // transport_factory — opens the XX receive session.
        // Non-blocking mode is required: with a blocking TcpStream the conn
        // Mutex would be held for the entire duration of each read() syscall,
        // starving concurrent send() calls (e.g. DeliverAck). In non-blocking
        // mode read() returns WouldBlock immediately when no data is present,
        // the lock is released, and send() can proceed.
        move || {
            eprintln!("[debug] receive: connecting to {}", recv_addr);
            let s = TcpStream::connect(&recv_addr).map_err(|e| {
                eprintln!("[debug] receive: tcp connect failed: {}", e);
                e.to_string()
            })?;
            eprintln!("[debug] receive: tcp connected, starting XX handshake");
            s.set_nonblocking(true).map_err(|e| e.to_string())?;
            let cap = slow_cap().unwrap_or(usize::MAX);
            if cap != usize::MAX {
                eprintln!("[debug] receive: SLOW_READ cap={}", cap);
            }
            Ok(SlowStream {
                inner: s,
                cap,
                delay_us: if cap == usize::MAX { 0 } else { 5000 },
                counter: std::cell::Cell::new(0),
            })
        },
        // push_factory — opens NK push sessions.
        // NK sessions are sequential (send then receive), so blocking mode
        // would also work here, but non-blocking is consistent and harmless.
        move || {
            eprintln!("[debug] push: connecting to {}", push_addr_cb);
            let s = TcpStream::connect(&push_addr_cb).map_err(|e| {
                eprintln!("[debug] push: tcp connect failed: {}", e);
                e.to_string()
            })?;
            eprintln!("[debug] push: tcp connected");
            s.set_nonblocking(true).map_err(|e| e.to_string())?;
            let cap = slow_cap().unwrap_or(usize::MAX);
            Ok(SlowStream {
                inner: s,
                cap,
                delay_us: if cap == usize::MAX { 0 } else { 5000 },
                counter: std::cell::Cell::new(0),
            })
        },
        None, // reconnect_cap: use default (30s)
        // on_connection_changed
        Some(Box::new(|connected| {
            if connected {
                println!("\n[relay: connected]");
            } else {
                println!("\n[relay: disconnected]");
            }
            print!("> ");
            io::stdout().flush().ok();
        })),
    )
    .expect("start session");

    // Restore group manifest — reconnect loop will replay the outbox on connect.
    if let Some(m) = existing_manifest {
        session.set_manifest(m);
        println!("group manifest restored");
    }

    // ── Event callbacks ───────────────────────────────────────────────────────

    session.set_on_member_request(|token, name| {
        println!("\n[pair request from {}]", name);
        println!("  admit with: accept {}", token);
        print!("> ");
        io::stdout().flush().ok();
    });

    session.set_on_member_joined(|id, name| {
        println!("\n[member joined: {} ({})]", name, short(&id));
        print!("> ");
        io::stdout().flush().ok();
    });

    session.set_on_member_left(|id, name| {
        println!("\n[member left: {} ({})]", name, short(&id));
        print!("> ");
        io::stdout().flush().ok();
    });

    // ── REPL ──────────────────────────────────────────────────────────────────

    println!(
        "commands: token | pair <tok> | accept <tok> | send <text> | members | remove <id> | destroy | quit"
    );

    let stdin = io::stdin();
    loop {
        print!("> ");
        io::stdout().flush().ok();

        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => break, // EOF or error
            Ok(_) => {}
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let (cmd, rest) = split_first(line);

        match cmd {
            "token" => {
                println!("{}", session.pairing_token());
            }

            "pair" => {
                if rest.is_empty() {
                    println!("usage: pair <token>");
                    continue;
                }
                match session.join_group(rest) {
                    Ok(()) => println!("join request sent — wait for the other device to accept"),
                    Err(e) => println!("error: {}", e),
                }
            }

            "accept" => {
                if rest.is_empty() {
                    println!("usage: accept <token>");
                    continue;
                }
                if session.accept_member(rest) {
                    println!("accepted");
                } else {
                    println!("no pending request with that token");
                }
            }

            "send" => {
                if rest.is_empty() {
                    println!("usage: send <text>");
                    continue;
                }
                match session.push_sync(rest.as_bytes().to_vec()) {
                    Ok(()) => println!("sent"),
                    Err(e) => println!("error: {}", e),
                }
            }

            "members" => {
                let members = session.members();
                if members.is_empty() {
                    println!("no group (not paired yet)");
                } else {
                    for m in &members {
                        println!("  {} ({})", m.name, m.id);
                    }
                }
            }

            "remove" => {
                if rest.is_empty() {
                    println!("usage: remove <id>");
                    continue;
                }
                match session.remove_member_by_id(rest) {
                    Ok(()) => println!("removed"),
                    Err(e) => println!("error: {}", e),
                }
            }

            "destroy" => {
                session.destroy_group();
                println!("group destroyed");
            }

            "quit" | "exit" => break,

            _ => println!(
                "unknown command — try: token | pair | accept | send | members | remove | destroy | quit"
            ),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn require_flag(args: &[String], flag: &str) -> String {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
        .unwrap_or_else(|| {
            eprintln!("missing required flag: {}", flag);
            eprintln!("usage: trueseal-cli --dir <path> --relay <host> --relay-pub <64-char-hex>");
            std::process::exit(1);
        })
}

fn hex_to_32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("invalid hex at byte {}", i))?;
    }
    Ok(out)
}

fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// First 8 chars of an id string — enough to be recognisable in the REPL.
fn short(id: &str) -> &str {
    &id[..id.len().min(8)]
}

/// Split "cmd rest" into ("cmd", "rest"), handling single-word lines.
fn split_first(line: &str) -> (&str, &str) {
    match line.find(' ') {
        Some(i) => (&line[..i], line[i + 1..].trim()),
        None => (line, ""),
    }
}
