// PROTOTYPE — throwaway
// ─────────────────────────────────────────────────────────────────────────────
// Question: "What is the right mutex error-handling strategy for HushSession?
//
// The session has ~66 Mutex::lock().unwrap() calls. If any thread panics while
// holding a lock, every subsequent .lock().unwrap() on that mutex also panics.
//
// Three strategies are modelled on a MiniSession that mirrors the real one:
//
//   A) .expect("msg")                  — still panics, at least descriptive
//   B) .unwrap_or_else(|e| e.into_inner()) — survives poison; may read stale state
//   C) .map_err(|_| Internal("..."))   — propagates cleanly; requires API change
//
// Background callbacks (subscribe handler, reconnect loop) can never return
// Result — they get approach B regardless.  Foreground public methods CAN
// propagate.  The question is whether they SHOULD.
//
// Drive it:
//   [m] set manifest    [p] push_sync (all three approaches)
//   [x] poison mutex    [r] reset / heal
//   [q] quit
//
// Run: cargo run --bin prototype_error_handling
// Delete or absorb after the decision is recorded in NOTES.md.
// ─────────────────────────────────────────────────────────────────────────────

use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};

// ── Logic module — portable; this is what we're designing ────────────────────

#[derive(Debug, Clone)]
pub enum SessionError {
    NotInGroup,
    PushFailed(String),
    /// Candidate new variant: internal invariant broken (e.g. mutex poisoned).
    /// If we choose approach C this must be added to the real SessionError.
    Internal(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInGroup => write!(f, "NotInGroup"),
            Self::PushFailed(e) => write!(f, "PushFailed({e})"),
            Self::Internal(e) => write!(f, "Internal({e})"),
        }
    }
}

#[derive(Debug, Clone)]
struct Manifest {
    version: u32,
    members: Vec<String>,
}

/// Mirrors HushSession's locking structure.
/// Every Arc<Mutex<_>> here matches a field in the real session.
struct MiniSession {
    manifest: Arc<Mutex<Option<Manifest>>>,
    sequence: Arc<Mutex<u64>>,
}

impl MiniSession {
    fn new() -> Self {
        Self {
            manifest: Arc::new(Mutex::new(None)),
            sequence: Arc::new(Mutex::new(0)),
        }
    }

    fn set_manifest(&self, members: Vec<String>) {
        // Background callbacks use approach B — they can't return Result.
        let mut guard = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
        let version = guard.as_ref().map(|m| m.version + 1).unwrap_or(1);
        *guard = Some(Manifest { version, members });
    }

    fn reset(&self) {
        *self.manifest.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self.sequence.lock().unwrap_or_else(|e| e.into_inner()) = 0;
        // Note: resetting a poisoned mutex is only possible via unwrap_or_else.
        // A subsequent lock() on a healed mutex works normally.
    }

    // ── A) .expect() — better message, still panics ──────────────────────────
    fn push_a(&self, blob: &[u8]) -> Result<String, SessionError> {
        let guard = self.manifest.lock().expect("manifest mutex: poisoned");
        let result = match &*guard {
            None => None,
            Some(m) => Some(m.members.len()),
        };
        drop(guard);
        match result {
            None => Err(SessionError::NotInGroup),
            Some(peer_count) => {
                let mut seq = self.sequence.lock().expect("sequence mutex: poisoned");
                let s = *seq;
                *seq += 1;
                Ok(format!("pushed {} bytes to {} peers, seq={}", blob.len(), peer_count, s))
            }
        }
    }

    // ── B) .unwrap_or_else — recover from poison, no API change ──────────────
    fn push_b(&self, blob: &[u8]) -> Result<String, SessionError> {
        let guard = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
        let result = match &*guard {
            None => None,
            Some(m) => Some(m.members.len()),
        };
        drop(guard);
        match result {
            None => Err(SessionError::NotInGroup),
            Some(peer_count) => {
                let mut seq = self.sequence.lock().unwrap_or_else(|e| e.into_inner());
                let s = *seq;
                *seq += 1;
                Ok(format!("pushed {} bytes to {} peers, seq={}  \x1b[2m(read possibly-stale state)\x1b[0m", blob.len(), peer_count, s))
            }
        }
    }

    // ── C) .map_err → Internal — clean propagation, requires API change ───────
    fn push_c(&self, blob: &[u8]) -> Result<String, SessionError> {
        let guard = self
            .manifest
            .lock()
            .map_err(|e| SessionError::Internal(format!("manifest lock poisoned: {e}")))?;
        let result = match &*guard {
            None => None,
            Some(m) => Some(m.members.len()),
        };
        drop(guard);
        match result {
            None => Err(SessionError::NotInGroup),
            Some(peer_count) => {
                let mut seq = self
                    .sequence
                    .lock()
                    .map_err(|e| SessionError::Internal(format!("sequence lock poisoned: {e}")))?;
                let s = *seq;
                *seq += 1;
                Ok(format!("pushed {} bytes to {} peers, seq={}", blob.len(), peer_count, s))
            }
        }
    }
}

// ── TUI ───────────────────────────────────────────────────────────────────────

fn bold(s: &str) -> String {
    format!("\x1b[1m{s}\x1b[0m")
}
fn dim(s: &str) -> String {
    format!("\x1b[2m{s}\x1b[0m")
}
fn red(s: &str) -> String {
    format!("\x1b[31m{s}\x1b[0m")
}
fn green(s: &str) -> String {
    format!("\x1b[32m{s}\x1b[0m")
}
fn yellow(s: &str) -> String {
    format!("\x1b[33m{s}\x1b[0m")
}

fn render(session: &MiniSession, log: &[String]) {
    // Clear screen
    print!("\x1b[2J\x1b[H");

    println!("{}", bold("━━ hush-sync · error handling prototype ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"));
    println!();

    // ── State ─────────────────────────────────────────────────────────────────
    println!("{}", bold("SESSION STATE"));

    let manifest_poisoned = session.manifest.is_poisoned();
    let seq_poisoned = session.sequence.is_poisoned();

    let manifest_display = if manifest_poisoned {
        red("POISONED")
    } else {
        let guard = session.manifest.lock().unwrap_or_else(|e| e.into_inner());
        match &*guard {
            None => dim("None"),
            Some(m) => green(&format!(
                "v{} · {} members: {}",
                m.version,
                m.members.len(),
                m.members.join(", ")
            )),
        }
    };

    let seq_display = if seq_poisoned {
        red("POISONED")
    } else {
        let guard = session.sequence.lock().unwrap_or_else(|e| e.into_inner());
        dim(&format!("{}", *guard))
    };

    println!("  manifest  {}", manifest_display);
    println!("  sequence  {}", seq_display);
    println!();

    // ── Mutex health ──────────────────────────────────────────────────────────
    println!("{}", bold("MUTEX HEALTH"));
    let health = |poisoned: bool| {
        if poisoned {
            red("⚠  poisoned — a thread panicked while holding this lock")
        } else {
            green("✓  healthy")
        }
    };
    println!("  manifest  {}", health(manifest_poisoned));
    println!("  sequence  {}", health(seq_poisoned));
    println!();

    // ── Approach guide ────────────────────────────────────────────────────────
    println!("{}", bold("APPROACH COMPARISON (when poisoned)"));
    println!(
        "  {} .expect(msg)              → {}",
        bold("A"),
        red("PANICS — thread crashes, process may die")
    );
    println!(
        "  {} .unwrap_or_else(recover)  → {}",
        bold("B"),
        yellow("proceeds — reads state left by panicking thread (may be inconsistent)")
    );
    println!(
        "  {} .map_err → Internal       → {}",
        bold("C"),
        green("returns Err(Internal(..)) — caller decides; requires new SessionError variant")
    );
    println!();

    // ── Operation log ─────────────────────────────────────────────────────────
    println!("{}", bold("OPERATION LOG"));
    let tail: Vec<_> = log.iter().rev().take(12).collect();
    if tail.is_empty() {
        println!("  {}", dim("(no operations yet)"));
    } else {
        for entry in tail.iter().rev() {
            println!("  {entry}");
        }
    }
    println!();

    // ── Menu ──────────────────────────────────────────────────────────────────
    println!("{}", bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"));
    println!(
        "  {} set manifest (2 members)   {} push_sync (all 3 approaches)   {} reset",
        bold("[m]"),
        bold("[p]"),
        bold("[r]")
    );
    println!(
        "  {} poison manifest mutex       {} quit",
        bold("[x]"),
        bold("[q]")
    );
}

fn main() {
    let session = MiniSession::new();
    let mut log: Vec<String> = Vec::new();
    let stdin = io::stdin();

    loop {
        render(&session, &log);
        print!("\n> ");
        io::stdout().flush().unwrap();

        let mut line = String::new();
        if stdin.lock().read_line(&mut line).is_err() {
            break;
        }

        match line.trim() {
            "m" => {
                session.set_manifest(vec!["Alice".into(), "Bob".into()]);
                log.push(green("set_manifest([Alice, Bob]) → Ok"));
            }

            "p" => {
                // Approach A: wrap in catch_unwind so the prototype doesn't crash
                let ra = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    session.push_a(b"hello world")
                }));
                let ra_str = match ra {
                    Ok(Ok(s)) => format!("  A .expect():    {}", green(&format!("Ok({s})"))),
                    Ok(Err(e)) => format!("  A .expect():    {}", yellow(&format!("Err({e})"))),
                    Err(_) => format!(
                        "  A .expect():    {}",
                        red("PANIC — thread would crash in production")
                    ),
                };

                // Approach B: recover
                let rb = session.push_b(b"hello world");
                let rb_str = match rb {
                    Ok(s) => format!("  B .recover():   {}", green(&format!("Ok({s})"))),
                    Err(e) => format!("  B .recover():   {}", yellow(&format!("Err({e})"))),
                };

                // Approach C: propagate
                let rc = session.push_c(b"hello world");
                let rc_str = match rc {
                    Ok(s) => format!("  C .map_err():   {}", green(&format!("Ok({s})"))),
                    Err(e) => format!("  C .map_err():   {}", yellow(&format!("Err({e})"))),
                };

                log.push(bold("push_sync(\"hello world\"):"));
                log.push(ra_str);
                log.push(rb_str);
                log.push(rc_str);
            }

            "x" => {
                // Poison the manifest mutex by panicking while holding it
                let m = session.manifest.clone();
                let _ = std::panic::catch_unwind(|| {
                    let _guard = m.lock().unwrap();
                    panic!("simulated callback panic while holding manifest lock");
                });
                log.push(red(
                    "POISONED manifest mutex (simulated panic inside callback)",
                ));
            }

            "r" => {
                session.reset();
                log.push(dim("reset — manifested cleared, sequence = 0, poison healed via unwrap_or_else"));
            }

            "q" => break,

            other if !other.is_empty() => {
                log.push(dim(&format!("unknown: {other}")));
            }
            _ => {}
        }
    }

    println!("\x1b[2J\x1b[H");
    println!("{}", bold("Prototype done. Record your decision in:"));
    println!("  src/bin/NOTES.md");
    println!();
    println!("Then delete src/bin/prototype_error_handling.rs");
}
