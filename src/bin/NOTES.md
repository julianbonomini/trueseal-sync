# Prototype: error handling strategy

**Question:** What is the right mutex error-handling strategy for HushSession?
The session has ~66 `Mutex::lock().unwrap()` calls. Three approaches are modelled.

**Run:** `cargo run --bin prototype_error_handling`

**Delete:** `src/bin/prototype_error_handling.rs` + this file once decision is recorded.

---

## Decision

<!-- Fill in after driving the prototype -->

- Approach chosen: **A / B / C** (circle one)
- `SessionError::Internal` variant needed: **yes / no**
- Background callbacks (subscribe handler, reconnect loop): **B always** (can't return Result)
- `try_into().unwrap()` after explicit length checks: `.expect("invariant: …")` — not a panic risk

## Notes

<!-- Anything surprising discovered during the prototype session -->
