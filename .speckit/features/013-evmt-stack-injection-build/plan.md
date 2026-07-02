# Plan — Feature 013 — EVM Stack Taint Injection Detection

**Status:** DRAFT
**Checkpoints resolved:** 013.CP.0 ✓, 013.CP.1 ✓, 013.CP.2 ✓, 013.CP.3 ✓, 013.CP.4 ✓, 013.CP.5 ✓, 013.CP.6 ✓, 013.CP.7 ✓, 013.CP.8 ✓
**Last updated:** 2026-07-02

**Decisions locked:**
- **New middleware vs extend cmp_linearity — hybrid:** Phase 0 (bug fix), Phase 1 (shallow), Phase 3 (persistent), Phase 4 (provenance) extend `cmp_linearity.rs` directly — they modify the taint engine's core dispatch and cannot be cleanly split. Phase 2 (four-link chain) is a new `injection_detect.rs` middleware that reads the static flags set by Phase 1. Phase 5 (scheduler wiring) is in the mutator/fuzzer layer.
- **CLI flag — `--injection-detect`:** Single boolean, disabled by default, follows `impact_eth_gradient` pattern in `config.rs`. Auto-implies nothing; purely a detection flag (unlike 015 which auto-enables dependents). Phase 2-5 are sub-flags of this (`--injection-detect-chain`, `--injection-persist`, `--injection-feedback`) so each phase can be tested independently.
- **Static flag pattern:** Follow `LIN_SAW_TAINTED_CMP` — per-execution bools reset each iteration, consumed by middleware/oracle layer post-execution.
- **Persistent taint location:** `FuzzHost.tainted_storage` (not on EVMState, not on CmpLinearityTaint). FuzzHost lives for campaign lifetime; evmstate deep-cloned per iteration at `vm.rs:534`. Phase 3 adds the field; Phase 4 upgrades the value type.
- **No concolic dependency:** Injection detection never enqueues for Z3. If the secant finds the injection path, it routes there; if not, the detection flag still fires (constitution §2 — Z3 is for concolic only, not taint propagation).

---

## Architecture Decision

No new Cargo feature, no new trait. Phases 0-4 extend the existing `CmpLinearityTaint` middleware and `FuzzHost` struct. One new middleware `InjectionDetect` for Phase 2. Gated by `Config.injection_detect` + phase-level sub-flags.

### Phase 0 — Fix Taint Engine Bugs (cmp_linearity.rs)

**push_ctx calldata indices:** Replace the single match arm at `cmp_linearity.rs:211` with opcode-specific peek indices — CALL/CALLCODE use `(peek(3), peek(4))`, DELEGATECALL/CALLCODE use `(peek(2), peek(3))`. Also store the opcode in `Ctx` so `pop_ctx` knows whether storage is shared.

**Storage clear on push_ctx:** Move the `self.storage.clear()` behind a `if opcode != 0xf4 && opcode != 0xf2` guard (shared storage preserved).

**pop_ctx storage restore:** Add `was_delegatecall: bool` parameter — if true, do NOT restore storage from the saved ctx (child's SSTORE stays in self.storage).

### Phase 1 — Shallow Injection Detection (cmp_linearity.rs)

At the CALL opcode dispatch (`cmp_linearity.rs:485-496`), BEFORE `popn!`:

```rust
0xf1 | 0xf2 => {
    // READ: is the `to` address at stack[-6] tainted? (6 back from top after popn! accounting)
    // Before popn!(7): stack[n-7] = gas, [n-6] = to, [n-5] = value, ... 
    let stack_len = self.stack.len();
    let to_tainted = stack_len >= 6 && self.stack[stack_len - 6].t;
    
    let (arg_offset, arg_len) = match opcode {
        0xf1 | 0xf2 => (interp.stack.peek(3), interp.stack.peek(4)),
        0xf4 | 0xfa => (interp.stack.peek(2), interp.stack.peek(3)),
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

Two static flags: `INJECTION_TAINTED_CALL_TARGET` and `INJECTION_TAINTED_CALLDATA`. Reset per-execution in `full_reset()`. Zero storage involved — pure shadow-stack + memory-vector reads.

### Phase 2 — Four-Link Chain (injection_detect.rs)

New middleware `src/evm/middlewares/injection_detect.rs`, gated by `--injection-detect-chain`. Not wired into `cmp_linearity.rs`'s per-opcode dispatch — instead it's a post-execution consumer that reads:

- `INJECTION_TAINTED_CALL_TARGET` / `INJECTION_TAINTED_CALLDATA` (from Phase 1)
- Execution trace (did the CALL revert?)
- `ABIMap` loaded at init (sink addresses, router addresses)

Chain logic:
```
TAINT detected → GUARD check (did it succeed?) → SINK check (is target a known financial contract?)
→ SELECTOR check (what function was called, which param is tainted?) → FLAG or SUPPRESS
```

Router filter: if the caller is a known router (multi-call, execute, batch), suppress non-financial selectors.

Three new static flags: `INJECTION_CONFIRMED_GUARD_BYPASS`, `INJECTION_CONFIRMED_SINK_HIT`, `INJECTION_CONFIRMED_EXPLOIT_PATH`.

### Phase 3 — Persistent Cross-Execution Taint (host.rs + cmp_linearity.rs)

Add to FuzzHost:
```rust
pub tainted_storage: HashMap<(EVMAddress, EVMU256), bool>,
```

In `cmp_linearity.rs` SLOAD handler (0x54/0x5c): merge host-persistent taint with local:
```rust
0x54 | 0x5c => {
    let key = interp.stack.peek(0);
    let address = interp.input.target_address;
    let persistent = host.tainted_storage.get(&(address, key)).copied().unwrap_or(false);
    let local = *self.storage.get(&key).unwrap_or(&false);
    self.storage.insert(key, persistent || local);
    pushtb!(TB { t: persistent || local, nl: false });
}
```

In SSTORE handler (0x55/0x5d): propagate to host:
```rust
0x55 | 0x5d => {
    let v = pop!();
    let key = interp.stack.peek(0);
    self.storage.insert(key, v.t);
    if v.t && host.call_depth <= MAX_CALL_DEPTH {
        host.tainted_storage.insert((interp.input.target_address, key), true);
    }
}
```

`init_host!` in `vm.rs:470` must NOT reset `tainted_storage`. Explicitly excluded from the macro.

Gated by `--injection-persist`.

### Phase 4 — Value-Confirmed Provenance (host.rs + cmp_linearity.rs)

Upgrade `tainted_storage` value type:
```rust
// Phase 3:
tainted_storage: HashMap<(EVMAddress, EVMU256), bool>

// Phase 4:
pub struct TaintProvenance {
    pub tainted: bool,
    pub writer_iteration: u64,
    pub writer_pc: usize,
    pub stored_value: EVMU256,
}
tainted_storage: HashMap<(EVMAddress, EVMU256), TaintProvenance>
```

At SSTORE: store the written value alongside the taint bit.
At SLOAD: read the actual EVM slot value and compare with `stored_value`. If they match, provenance confirmed. If they differ, the slot was overwritten post-taint-write — log as stale.

Gated by `--injection-provenance`.

### Phase 5 — Feedback → Scheduler Wiring (mutator.rs)

When `INJECTION_CONFIRMED_EXPLOIT_PATH` fires and the hot byte range is known, bias mutation probability for those bytes. Pattern follows `lin_route_to_secant()` — a boolean consumed by the mutation stage to weight byte-level mutation power.

No new Z3 path. No concolic interaction. Pure libafl mutation biasing.

Gated by `--injection-feedback`.

---

## New Types

| Type | Location | Purpose |
|------|----------|---------|
| `INJECTION_TAINTED_CALL_TARGET` | `cmp_linearity.rs` static | Phase 1: CALL `to` taint bit |
| `INJECTION_TAINTED_CALLDATA` | `cmp_linearity.rs` static | Phase 1: CALL calldata taint bit |
| `INJECTION_CONFIRMED_GUARD_BYPASS` | `injection_detect.rs` static | Phase 2: guard passed |
| `INJECTION_CONFIRMED_SINK_HIT` | `injection_detect.rs` static | Phase 2: target is financial sink |
| `INJECTION_CONFIRMED_EXPLOIT_PATH` | `injection_detect.rs` static | Phase 2: full four-link chain |
| `FuzzHost.tainted_storage` | `host.rs` field | Phase 3: persistent taint HashMap |
| `TaintProvenance` | `host.rs` struct | Phase 4: value-verified provenance |

---

## Registration

- **cmp_linearity.rs** — Phase 0: fix push_ctx/pop_ctx. Phase 1: add injection detection reads at CALL boundaries. Phase 3/4: SLOAD/SSTORE read/write host.
- **injection_detect.rs** (new) — Phase 2: four-link chain middleware. Registered in `evm_fuzzer.rs` alongside other middlewares when `config.injection_detect_chain`.
- **host.rs** — Phase 3/4: `tainted_storage` field. Phase 4: `TaintProvenance` struct.
- **mutator.rs** — Phase 5: `bias_mutation_toward_hot_bytes()` conditional on `INJECTION_CONFIRMED_EXPLOIT_PATH`.
- **config.rs** — new fields: `injection_detect`, `injection_detect_chain`, `injection_persist`, `injection_provenance`, `injection_feedback`.
- **evm_fuzzer.rs** — register InjectionDetect middleware when flags enabled.

---

## CLI

- **Flag:** `--injection-detect` (Phase 1 master switch). Sub-flags for Phases 2-5.
- **Config fields:** `injection_detect: bool` (add to `config.rs` near `impact_eth_gradient`).
- **Conflicts:** none.
- **Dependencies:** Phase 3/4/5 depend on Phase 1/2. Design: enabling a later sub-flag without earlier ones prints a warning and auto-enables the prerequisite.

---

## Interaction with Existing Features

| Feature | Interaction |
|---------|------------|
| 009 Concolic/Secant | None — injection flags are separate from linearity dispatch. Phase 1 flags are observ-only. |
| 011 Impact Max | None — 011 is about realized-value objective, not taint provenance. |
| 014 TAINT Oracles | **Depends on 013 Phase 0** (DELEGATECALL bugs fix). 014 Phase 0 extends `on_return` — must be compatible with 013 Phase 0's `pop_ctx` change. |
| 015 Reflexive Lever | Not a dependency (both orthogonal — taint provenance ≠ profit gradient). |

---

## Performance

- **When disabled:** zero code path — `--injection-detect` check skips all injection branches in cmp_linearity. Static flags never set. Phase 2 middleware not registered.
- **When enabled (Phase 1 only):** +2 taint reads per CALL opcode (shadow stack + memory vector). Negligible — same order as existing shadaw stack ops.
- **When enabled (Phase 3 persistent):** +1 HashMap lookup per SLOAD/SSTORE. Bounded by number of storage slots touched per execution.
- **When enabled (Phase 4 provenance):** Full value stored in HashMap instead of bool. Same lookup cost, more memory per slot.

---

## Test Plan

- **Unit test:**
  - Phase 0: Create a minimal proxy (DELEGATECALL forwarder) and vaildate storage taint propagates through the proxy boundary. Pre-fix: SLOAD shows clean. Post-fix: SLOAD is tainted.
  - Phase 1: Test CALL with tainted `to` address — verify `INJECTION_TAINTED_CALL_TARGET` fires. Test with clean internal transfer — verify no FP.
  - Phase 3: Multi-iteration test — write tainted storage in iter 1, SLOAD in iter 2. Verify taint persists.
  - Phase 4: Overwrite tainted slot with clean value — verify provenance check logs as stale.

- **Integration test:**
  - Yearn V3 proxy (yETH) fork — DELEGATECALL-mediated exploit path. Verify Phase 0+1 flags fire on known exploit calldata.
  - AAVE flash loan attack — verify Phase 2 four-link chain detects the full exploit path (tainted `to` → guard pass → sink hit → transferFrom selector).

- **Regression test:**
  - Run entire B1 benchmark with `--injection-detect` disabled. Verify bug set byte-equivalent to pre-013 binary (constitution rule 2).
  - Run B1 with `--injection-detect` enabled — verify zero regressions in baseline bug detection.

---

## Build Staging (task ordering)

**Phase 1 (MVP — ships proxy bugfix + shallow detection):**
1. Phase 0: Fix DELEGATECALL push_ctx/pop_ctx bugs in `cmp_linearity.rs:210-234`.
2. Phase 1: Add injection detection reads at CALL boundaries in `cmp_linearity.rs:485-496`.
3. Phase 2: Write `injection_detect.rs` middleware with four-link chain logic.

**Phase 2 (persistent taint):**
4. Phase 3: Add `tainted_storage` to FuzzHost, modify SLOAD/SSTORE handlers.
5. Phase 4: Upgrade to `TaintProvenance` value-type.

**Phase 3 (orchestration):**
6. Phase 5: Scheduler wiring — biasing mutation toward hot byte ranges.

Each task is independently testable behind its CLI sub-flag with the 2-step regression as the floor.
