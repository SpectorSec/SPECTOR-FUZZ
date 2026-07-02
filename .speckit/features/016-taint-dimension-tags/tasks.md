# Tasks — Feature 016 — Taint Dimension Tags

**Status:** DRAFT
**Last updated:** 2026-07-02
**Depends on:** 013 Phase 3 (host.tainted_storage), 014 Phase 0 (oracle return marking), 015 (LedgerSecantState)

Build order: Phase 0 (core type upgrade) must precede everything. Phases 1-2 can parallel once Phase 0 compiles. Phase 3 depends on 1-2.

---

## PHASE 0 — Core dimension tag upgrade

## Task 1 — Define TaintDim + upgrade TB/mem/storage/input_data

**Files:** `src/evm/middlewares/cmp_linearity.rs` (lines 188-227)

**What:**

Define the enum at module level:
```rust
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
enum TaintDim {
    #[default]
    Generic,
    Price,
    Balance,
    Timestamp,
    Accumulator,
}
```

Upgrade `TB`:
```rust
#[derive(Clone, Copy, Debug, Default)]
struct TB {
    t: bool,
    nl: bool,
    dim: TaintDim,
}
```

Upgrade `Ctx` and `CmpLinearityTaint` struct fields:
- `mem: Vec<bool>` → `Vec<TaintDim>`
- `storage: HashMap<EVMU256, bool>` → `HashMap<EVMU256, TaintDim>`
- `input_data: Vec<bool>` → `Vec<TaintDim>`

**Propagation rule implementations:**

Linear ops macro — OR dims with most-specific wins:
```rust
macro_rules! linear {
    ($n:expr) => {{
        let mut r = TB::default();
        for _ in 0..$n {
            let x = pop!();
            r.t |= x.t;
            r.nl |= x.nl;
            if dim_priority(x.dim) > dim_priority(r.dim) {
                r.dim = x.dim;
            }
        }
        pushtb!(r);
    }};
}
```

Where `dim_priority`:
```rust
fn dim_priority(d: TaintDim) -> u8 {
    match d {
        TaintDim::Price => 5,
        TaintDim::Accumulator => 4,
        TaintDim::Balance => 3,
        TaintDim::Timestamp => 2,
        TaintDim::Generic => 1,
    }
}
```

Non-linear macro — reset dim to Generic:
```rust
pushtb!(TB { t, nl: nl || t, dim: TaintDim::Generic });
```

SLOAD — dim from storage:
```rust
let dim = self.storage.get(&key).copied().unwrap_or(TaintDim::Generic);
pushtb!(TB { t: host_tainted, nl: false, dim });
```

SSTORE — write dim to storage:
```rust
self.storage.insert(key, v.dim);
```

MLOAD — dim from memory:
```rust
let dim = if tainted {
    self.mem.get(offset).copied().unwrap_or(TaintDim::Generic)
} else {
    TaintDim::Generic
};
pushtb!(TB { t: tainted, nl: false, dim });
```

SLOAD host merge — upgrade `TaintProvenance`:
```rust
if let Some(provenance) = host.tainted_storage.get(&(address, key)) {
    let dim = provenance.dim;
    // ...
}
```

**Clean!** macro — reset to default (Generic):
```rust
pushtb!(TB::default())
```

Ensure all `self.mem[...].fill(true)` → `self.mem[...].fill(TaintDim::Generic)` and `self.mem.resize(end, false)` → `self.mem.resize(end, TaintDim::Generic)`.

**Done when:** Build succeeds. Existing test suite passes (126 non-network). Dim field propagates correctly for all opcodes.

---

## Task 2 — Upgrade TaintProvenance with dim field

**Files:** `src/evm/host.rs` (lines 103-109), `src/evm/middlewares/cmp_linearity.rs` (SLOAD/SSTORE sites)

**What:**

```rust
#[derive(Clone, Debug, Default)]
pub struct TaintProvenance {
    pub tainted: bool,
    pub stored_value: EVMU256,
    pub dim: TaintDim,
}
```

Update SSTORE in cmp_linearity.rs:
```rust
host.tainted_storage.insert((address, key), TaintProvenance {
    tainted: v.t,
    stored_value,
    dim: v.dim,
});
```

Update SLOAD host merge:
```rust
if let Some(provenance) = host.tainted_storage.get(&(address, key)) {
    host_tainted = provenance.tainted;
    host_dim = provenance.dim;
    if provenance.tainted && provenance.stored_value == actual_value {
        INJECTION_CONFIRMED_PROVENANCE = true;
    }
}
```

**Done when:** Persistent taint carries dim. Existing `TaintProvenance` users (013 Phase 4) unaffected.

---

## Task 3 — Verify all Vec<bool> fill/resize sites updated

**Files:** `src/evm/middlewares/cmp_linearity.rs`

**What:** Audit every site that touches `self.mem`, `self.storage`, or `self.input_data`:

- `ensure!` macro: `$v.resize($sz, false)` → `$v.resize($sz, TaintDim::Generic)` 
- `self.mem[..end].fill(true)` → `self.mem[..end].fill(TaintDim::Generic)` (all 6 sites from 014 Phase 0 on_return)
- `write_input`: pushes false → pushes `TaintDim::Generic`
- `read_input`: copies bool → copies `TaintDim`
- `read_mem_tainted`: reads bool from mem → reads TaintDim, answers `dim != Generic && dim != TaintDim::Generic`

Also fix `CmpLinearityTaint::new() / default()` — no change needed (`Vec::new()` works for any type).

**Done when:** No remaining `bool` references in `self.mem`/`self.storage`/`self.input_data` operations.

---

## PHASE 1 — Oracle return dimension tagging

## Task 4 — Tag oracle return data per word offset

**Files:** `src/evm/middlewares/cmp_linearity.rs` (on_return, lines 693-707)

**What:** Replace the current blanket `self.mem[..end].fill(true)` with offset-specific dim tagging.

For `latestRoundData` / `getRoundData` (5-word return, word = 32 bytes):
```rust
fn tag_oracle_return(mem: &mut Vec<TaintDim>, ret: &Bytes, selector: &[u8; 4]) {
    let word_layout: &[(usize, TaintDim)] = if *selector == LATEST_ROUND_DATA_SEL || *selector == GET_ROUND_DATA_SEL {
        &[
            (0, TaintDim::Generic),    // roundId
            (32, TaintDim::Price),     // answer
            (64, TaintDim::Timestamp), // startedAt
            (96, TaintDim::Timestamp), // updatedAt
            (128, TaintDim::Generic),  // answeredInRound
        ]
    } else if *selector == LATEST_ANSWER_SEL {
        &[(0, TaintDim::Price)]
    } else {
        &[(0, TaintDim::Generic)]
    };

    for &(offset, dim) in word_layout {
        let start = offset;
        let end = (offset + 32).min(ret.len()).min(MEMORY_LIMIT_BYTES);
        if end > start {
            if mem.len() < end {
                mem.resize(end, TaintDim::Generic);
            }
            mem[start..end].fill(dim);
        }
    }
}
```

Called from `on_return`:
```rust
if let Some(selectors) = host.oracle_selectors.get(&ctx.callee) {
    if selectors.contains(&ctx.callee_selector) {
        tag_oracle_return(&mut self.mem, ret, &ctx.callee_selector);
    }
}
```

**Done when:** Unit: `latestRoundData` with `(0, 100, 0, 500, 0)` return → bytes 0-31: `Generic`, bytes 32-63: `Price`, bytes 64-95: `Timestamp`, bytes 96-127: `Timestamp`. `latestAnswer` → all `Price`.

---

## PHASE 2 — Flow type detection

## Task 5 — Proxy bridge flow detection

**Files:** `src/evm/middlewares/cmp_linearity.rs` (DELEGATECALL push_ctx, on_step)

**What:** At DELEGATECALL (0xf4) boundary, check if any operand has `dim != Generic` AND the value passes through the proxy (i.e., the call returns tainted data).

Detection rule:
```rust
// In DELEGATECALL/CALLCODE handler (0xf4 | 0xfa):
let stack_has_dim_flow = self.stack.iter().any(|tb| tb.dim != TaintDim::Generic);
if stack_has_dim_flow && shared_storage {
    PROXY_TAINT_FLOW = true;
    host.current_typed_bug.push((
        "proxy_taint_flow".to_string(),
        (interp.input.target_address, pc),
    ));
}
```

Add `PROXY_TAINT_FLOW: bool` static flag near the injection flags.

**Done when:** DELEGATECALL through proxy with Price-tainted input → flag fires. Direct CALL (0xf1) with same input → no flag.

---

## Task 6 — Price manipulation flow detection (upgrade oracle_tracker)

**Files:** `src/evm/middlewares/oracle_tracker.rs`

**What:** Replace opcode proximity with dim-precise detection.

Current: 60-opcode window between oracle CALL and comparison.
New: Check `TB.dim == Price` on comparison operands.

This requires reading TB from `cmp_linearity`'s shadow stack. Since `oracle_tracker.rs` runs during normal execution (not reexecution), it can't access `CmpLinearityTaint`'s stack directly. Two options:

- **Option A (recommended):** Add a `DIMENSION_FLOW` global flag in `feedbacks.rs`. Set by `cmp_linearity.rs` on_step when comparison operands have `dim == Price`. Read by the oracle_tracker in on_step.
- **Option B:** Move oracle_tracker into the reexecution path (like 013's CmpLinearityTaint) so it can read the shadow stack.

Option A is simpler — add a write to a static flag in `cmp_linearity.rs` at comparison ops:
```rust
0x10..=0x14 => {
    let a = pop!();
    let b = pop!();
    // ... existing taint logic ...
    if a.dim == TaintDim::Price || b.dim == TaintDim::Price {
        PRICE_DIM_CMP_SEEN = true;
    }
    // ... push result ...
}
```

Then in `oracle_tracker.rs`, check `PRICE_DIM_CMP_SEEN` instead of opcode proximity.

Also add:
```rust
pub static mut PRICE_MANIPULATION_FLOW: bool = false;
```

Set when `PRICE_DIM_CMP_SEEN && value_moving_call_after_cmp`.

**Done when:** Price-dim comparison followed by transfer → flag fires. Timestamp-dim comparison → no flag.

---

## Task 7 — Accumulator inflation flow detection

**Files:** `src/evm/middlewares/cmp_linearity.rs` (SLOAD host merge)

**What:** Detect when a storage slot gets written with `Price`-tagged taint ≥2 times across executions.

Track in `host.tainted_storage` using the `dim` field:
```rust
// In SSTORE handler:
if v.t && v.dim == TaintDim::Price {
    if let Some(existing) = host.tainted_storage.get(&(address, key)) {
        if existing.tainted && existing.dim == TaintDim::Price {
            // Second+ Price write to same slot
            ACCUMULATOR_INFLATION_FLOW = true;
            host.current_typed_bug.push((
                "accumulator_inflation_flow".to_string(),
                (address, pc),
            ));
        }
    }
}
```

Add `ACCUMULATOR_INFLATION_FLOW: bool` static flag.

**Done when:** Same storage slot written with Price taint twice → flag fires. First write only → no flag.

---

## PHASE 3 — Scheduler + mutator wiring

## Task 8 — DIMENSION_FLOW static flag + mutator bias

**Files:** `src/evm/feedbacks.rs`, `src/evm/mutator.rs`

**What:**

Add to `feedbacks.rs`:
```rust
pub static mut DIMENSION_FLOW: TaintDim = TaintDim::Generic;
```

Reset in the reexecution path alongside other static flags.

Add to `mutator.rs` `mutate()`:
```rust
// Bias: if Price-dim flow detected, prioritize mutating Price-dim arguments
unsafe {
    if DIMENSION_FLOW == TaintDim::Price {
        // Increase probability of selecting Price-tagged arg slots
        // by 2× for the next mutation cycle
    }
}
```

The exact bias mechanism: after `apply_ledger_secant` runs, if `located_dim == Price`, increase the mutation energy allocated to the promoted step's args by 50%.

**Done when:** Price-dim flow → mutator allocates more energy to price-adjacent args. Generic dim → normal energy distribution.

---

## Task 9 — LedgerSecantState.located_dim + probe delta

**Files:** `src/feedback.rs`, `src/evm/mutator.rs`

**What:**

Add field to `LedgerSecantState`:
```rust
pub located_dim: TaintDim,  // 1 byte, default Generic
```

In `apply_ledger_secant`, after `Locate` finds the best arg:
```rust
if !located {
    // ... existing locate logic ...
    best_sens = max_sens;
    best_arg = best_arg_idx;
    located_dim = /* read from TB.dim at the locate probe site */;
    located = true;
}
```

In `Amplify`, use `located_dim` for probe delta:
```rust
let probe_delta = match located_dim {
    TaintDim::Price => x1 / 256,
    TaintDim::Balance => x1 / 16,
    TaintDim::Timestamp => x1 / 64,
    _ => x1 / 64,
};
```

**Done when:** Secant uses fine-grained δ for Price levers. Coarse δ for Balance levers. Default δ for Generic.

---

## PHASE 4 — Tests

## Task 10 — Unit tests

- **10a:** `TaintDim` priority ordering. Most-specific wins on mixed ops.
- **10b:** Oracle return tagging (latestRoundData, latestAnswer, getRoundData).
- **10c:** Flow type flags set correctly for each type, no false positives for unrelated patterns.
- **10d:** `LedgerSecantState.located_dim` round-trip serialization.
- **10e:** Mutator bias on `DIMENSION_FLOW` — verify mutation energy distribution changes.

## Task 11 — Integration tests

- **11a:** Three-transaction sequence (add_liquidity → oracle read → withdraw) → all three flow types detected in correct order.
- **11b:** Secant with Price-dim lever → smaller probe delta observed in logs.
- **11c:** Regression: all Phase 0-3 changes with no flags → zero diff from pre-016 test suite.

## Task 12 — Regression verification

```bash
cargo test --release -- --skip network
# Must show: 126 passed, 5 failed (pre-existing network-dependent)
```
