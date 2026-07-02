# Tasks — Feature 013 — EVM Stack Taint Injection Detection

**Status:** DRAFT — awaiting approval
**Last updated:** 2026-07-02
**Decisions locked:** Hybrid architecture (cmp_linearity extends + new injection_detect middleware); CLI = `--injection-detect` + phase sub-flags.

Build order is the data dependency: Phase 0 fixes the engine → Phase 1 reads taint at CALL boundary → Phase 2 discriminates the chain → Phase 3 persists across iterations → Phase 4 confirms provenance → Phase 5 biases mutation. Each task is independently testable behind its CLI sub-flag; the pre-013 binary (flag off) is the regression floor at every step.

---

## PHASE 1 — ships proxy bugfix + shallow injection detection

## Task 1 — Fix DELEGATECALL push_ctx/pop_ctx bugs
**Files:** `src/evm/middlewares/cmp_linearity.rs:210-234`
**What:** Two coordinated fixes in `push_ctx` and `pop_ctx`:

**push_ctx calldata indices (line 211-213):** Replace the single match arm with opcode-specific peeks:
```rust
fn push_ctx(&mut self, interp: &mut Interpreter) {
    let (arg_offset, arg_len) = match interp.bytecode.opcode() {
        0xf1 | 0xf2 => (interp.stack.peek(3).unwrap(), interp.stack.peek(4).unwrap()),
        0xf4 | 0xfa => (interp.stack.peek(2).unwrap(), interp.stack.peek(3).unwrap()),
        _ => return,
    };
    // ... rest of push_ctx ...
}
```
Also store `opcode` on the `Ctx` struct so `pop_ctx` knows the call type.

**push_ctx storage clear (lines 223-225):** Guard the `self.storage.clear()` behind `if opcode != 0xf4 && opcode != 0xf2` — DELEGATECALL/CALLCODE share caller storage.

**pop_ctx (lines 228-234):** Accept `was_delegatecall: bool`. When true, do NOT restore storage from the saved ctx — the child's SSTORE went into shared storage and must be preserved. Mirror `was_delegatecall` from the Ctx's saved opcode.

**Update `on_return` (line 509-519):** Pass the opcode from `interp.bytecode.opcode()` through to the new `pop_ctx` signature.

**Done when:** Unit test: create a minimal DELEGATECALL proxy, write tainted calldata → DELEGATECALL → SSTORE in impl → SLOAD in proxy. Pre-fix: clean. Post-fix: tainted.
**Blocks:** All downstream tasks

---

## Task 2 — Shallow injection detection at CALL boundary
**Files:** `src/evm/middlewares/cmp_linearity.rs:485-496`
**What:** At the CALL opcode dispatch, BEFORE `popn!` clears the shadow stack, read taint from:
- Shadow stack position n-6 (CALL to address, 0xf1/0xf2 popn!7: gas at n-7, to at n-6)
- Memory vector covering `arg_offset..arg_offset+arg_len` (forwarded calldata)

```rust
0xf1 | 0xf2 => {
    let stack_len = self.stack.len();
    let to_tainted = stack_len >= 6 && self.stack[stack_len - 6].t;
    let (arg_offset, arg_len) = match opcode {
        0xf1 | 0xf2 => (interp.stack.peek(3), interp.stack.peek(4)),
        _ => unreachable!(),
    };
    let calldata_tainted = self.read_mem_tainted(arg_offset, arg_len);
    if to_tainted { INJECTION_TAINTED_CALL_TARGET = true; }
    if calldata_tainted { INJECTION_TAINTED_CALLDATA = true; }
    popn!(7);
    clean!();
    self.push_ctx(interp);
}
```

Same for `0xf4 | 0xfa` (6 stack entries, different peek indices for arg_offset/arg_len).

**Static flags:**
```rust
pub static mut INJECTION_TAINTED_CALL_TARGET: bool = false;
pub static mut INJECTION_TAINTED_CALLDATA: bool = false;
```
Reset in `full_reset()` alongside `LIN_SAW_TAINTED_CMP`.

**Done when:** Unit test: CALL with tainted `to` address → `INJECTION_TAINTED_CALL_TARGET` fires. CALL with clean params → neither flag fires.
**Blocks:** Task 3

---

## Task 3 — Four-link chain middleware (injection_detect.rs)
**Files:** `src/evm/middlewares/injection_detect.rs` (new)
**What:** New middleware `InjectionDetect` that runs AFTER execution and reads Phase 1 static flags. Implements the four-link chain:

1. **TAINT:** `INJECTION_TAINTED_CALL_TARGET || INJECTION_TAINTED_CALLDATA`
2. **GUARD:** Did the CALL succeed (no REVERT)? Revert → GUARD_BLOCKED → stop.
3. **SINK:** Is the CALL target address in `sink_definitions`? (loaded from ABIMap at init: known token/vault/lending-pool addresses)
4. **SELECTOR:** What function selector was called? If `transferFrom` (0x23b872dd), is `from` at offset 4+12 tainted? If `transfer` (0xa9059cbb), is `to` at offset 4+4 tainted?

Static flags:
```rust
pub static mut INJECTION_CONFIRMED_GUARD_BYPASS: bool = false;
pub static mut INJECTION_CONFIRMED_SINK_HIT: bool = false;
pub static mut INJECTION_CONFIRMED_EXPLOIT_PATH: bool = false;
```

**Router filter:** Known routers (multicall, execute, batch functions) suppress non-financial selectors.

**Registration:** Wire into `evm_fuzzer.rs` when `config.injection_detect_chain`. Load sink_definitions from ABIMap at `corpus_initializer.rs` init.

**Done when:** Integration test on known exploit: tainted calldata → execute → transferFrom → all four flags fire. Same calldata → execute → setParam → suppressed.
**Blocks:** Task 6 (Phase 3/4 use the chain flags)

---

## Task 4 — CLI flags
**Files:** `src/evm/config.rs`, CLI arg parsing in `src/bin/` or `evm_fuzzer.rs`
**What:** Add to Config:
```rust
pub injection_detect: bool,           // Phase 1 master
pub injection_detect_chain: bool,     // Phase 2
pub injection_persist: bool,          // Phase 3
pub injection_provenance: bool,       // Phase 4
pub injection_feedback: bool,         // Phase 5
```

CLI flags: `--injection-detect`, `--injection-detect-chain`, `--injection-persist`, `--injection-provenance`, `--injection-feedback`.

Dependency enforcement: enabling a later sub-flag without earlier ones prints a warning and auto-enables the prerequisite.

**Done when:** `--injection-detect` alone enables Phase 1. `--injection-persist` alone auto-enables Phase 1 and prints warning.

---

## PHASE 2 — persistent cross-execution taint

## Task 5 — Persistent storage taint (Phase 3)
**Files:** `src/evm/host.rs`, `src/evm/middlewares/cmp_linearity.rs`
**What:**

**host.rs:** Add field to FuzzHost:
```rust
pub tainted_storage: HashMap<(EVMAddress, EVMU256), bool>,
```
Initialize as empty in `new()`. Verify `init_host!` at `vm.rs:470` does NOT clear it (add explicit note).

**cmp_linearity.rs SLOAD (0x54/0x5c):** Merge host-persistent taint with local shadow:
```rust
0x54 | 0x5c => {
    pop!();
    let key = interp.stack.peek(0).expect("stack");
    let address = interp.input.target_address;
    let persistent = host.tainted_storage.get(&(address, key)).copied().unwrap_or(false);
    let local = *self.storage.get(&key).unwrap_or(&false);
    let merged = persistent || local;
    self.storage.insert(key, merged);
    pushtb!(TB { t: merged, nl: false });
}
```

**cmp_linearity.rs SSTORE (0x55/0x5d):** Write back to host when tainted:
```rust
0x55 | 0x5d => {
    pop!();
    let v = pop!();
    let key = interp.stack.peek(0).expect("stack");
    self.storage.insert(key, v.t);
    if v.t {
        host.tainted_storage.insert((interp.input.target_address, key), true);
    }
}
```

Gated on `config.injection_persist`.

**Done when:** Multi-iteration test: write tainted storage in iter 1, SLOAD in iter 2 → taint persists. No FP when flag off.
**Blocks:** Task 6

---

## Task 6 — Value-confirmed provenance (Phase 4)
**Files:** `src/evm/host.rs`, `src/evm/middlewares/cmp_linearity.rs`
**What:**

**host.rs:** Add `TaintProvenance` struct:
```rust
pub struct TaintProvenance {
    pub tainted: bool,
    pub writer_iteration: u64,
    pub stored_value: EVMU256,
}
```
Upgrade `tainted_storage` value type from `bool` to `TaintProvenance`.

**cmp_linearity.rs SSTORE:** Record the actual stored value:
```rust
// In SSTORE handler:
if v.t {
    host.tainted_storage.insert(
        (interp.input.target_address, key),
        TaintProvenance {
            tainted: true,
            writer_iteration: host.call_count as u64,
            stored_value: /* actual value from interp.stack.peek / memory */,
        },
    );
}
```

**cmp_linearity.rs SLOAD:** Verify value match:
```rust
// In SLOAD handler:
let prov = host.tainted_storage.get(&(address, key));
if let Some(p) = prov {
    if p.tainted && actual_sload_value == p.stored_value {
        INJECTION_CONFIRMED_PROVENANCE = true; // new static flag
    } else if p.tainted {
        // Log as stale — slot was overwritten post-taint
    }
}
```

Gated on `config.injection_provenance`.

**Done when:** Write taint to slot in iter 1, overwrite with clean value in iter 2, SLOAD in iter 3 → stale logged. Same but no overwrite → provenance confirmed.
**Blocks:** Task 7

---

## PHASE 3 — orchestration

## Task 7 — Scheduler wiring (Phase 5)
**Files:** `src/evm/mutator.rs` (or dedicated scheduler module)
**What:** When `INJECTION_CONFIRMED_EXPLOIT_PATH` fires, the hot byte range (calldata bytes that produce the taint at the CALL boundary) is already known from the shadow stack's TB trace — CALLDATALOAD offset maps back to calldata byte position.

Add mutation bias:
```rust
if config.injection_feedback && INJECTION_CONFIRMED_EXPLOIT_PATH {
    if let Some(range) = hot_byte_range {
        mutation_power[range].weight *= 2.0;
    }
}
```

Follows `lin_route_to_secant()` pattern — a boolean consumed post-execution.

**Done when:** A/B test: injection feedback on → converges to drain discovery faster than feedback off.
**Blocks:** None (Phase 3 complete)

---

## Task 8 — Tests: unit, integration, regression
**Files:** `tests/` or existing test infrastructure
**What:**

- **8a unit:** Phase 0 — proxy DELEGATECALL taint propagation before/after fix.
- **8b unit:** Phase 1 — CALL with tainted `to` → flag fires; clean CALL → no flag.
- **8c unit:** Phase 3 — multi-iteration persistent taint across iterations.
- **8d unit:** Phase 4 — provenance match vs stale detection.
- **8e integration:** Yearn V3 proxy fork — Phase 0+1 flags fire on known exploit calldata. AAVE flash loan — Phase 2 four-link chain detects full path.
- **8f regression:** B1 benchmark with `--injection-detect` disabled → bug set byte-equivalent to pre-013 binary. B1 with flag enabled → zero regressions.

**Done when:** All tests pass under `cargo test`. Regression shows no diff.
**Blocks:** None
