# Feature 013 — EVM Stack Taint Injection Detection: Build

**Status:** Planning
**Owner:** TBD
**Last updated:** 2026-06-30
**Derived from:** Feature 012 (Research)

---

---

## Investigation Checkpoints

Every checkpoint below was resolved against the current source code at commit HEAD of `github.com/fuzzland/ityfuzz`. All are **CONFIRMED** — no unresolved research questions remain. Phase 6 (static kill chain bridge) removed per December spec decision; no static grammar infrastructure exists or is needed.

| # | Question | Source Evidence | Verdict |
|---|---|---|---|
| **013.CP.0** | Does the DELEGATECALL push_ctx bug (same peek indices for all call types) exist in current source? | `cmp_linearity.rs:210-214`: `0xf1 \| 0xf2 \| 0xf4 \| 0xfa => (interp.stack.peek(3).unwrap(), interp.stack.peek(2).unwrap())` — CALL (0xf1) reads `msg.value` as `arg_len`. `pop_ctx` at lines 223-225 clears storage unconditionally — DELEGATECALL shared storage is lost. | **CONFIRMED** — both bugs exist. |
| **013.CP.1** | Is the shadow stack intact at the CALL boundary BEFORE popn! clears it? Can we inject a taint read? | `cmp_linearity.rs:485-496`: `0xf1 \| 0xf2 => { popn!(7); clean!(); self.push_ctx(interp); }` — shadow stack is available for reads before the `popn!`. Taint injection detection can read `self.stack[...]` before `popn!`. | **CONFIRMED** — hook point exists. |
| **013.CP.2** | Does FuzzHost support adding a `tainted_storage` field? What is its lifecycle — Rc<RefCell<>> or cloned? | `host.rs:323-425`: FuzzHost is a plain struct with ~30 fields. Created at `evm_fuzzer.rs:114` as `let mut fuzz_host = FuzzHost::new(...)` and passed as `&mut FuzzHost<SC>` to middlewares. Middlewares stored in `Rc<RefCell<...>>`. The host itself is NOT wrapped in Rc/RefCell at creation — but `host.evmstate` IS deep-cloned at `vm.rs:534`. Adding `tainted_storage` directly to FuzzHost (not evmstate) bypasses the clone. | **CONFIRMED** — FuzzHost lives for campaign duration; mutable ref in all middleware calls. |
| **013.CP.3** | Does `init_host!` reset per-execution state? Will it accidentally clear taint metadata? | `vm.rs:470-483`: `init_host!` resets `current_self_destructs`, `current_arbitrary_calls`, `current_arbitrary_transfers`, `call_count`, `jumpi_trace`, `current_typed_bug`, `randomness`, `transient_storage`. No taint field exists yet. Pattern: add `tainted_storage` to the exclusion list. | **CONFIRMED** — no taint reset in init_host!. Add exclusion explicitly. |
| **013.CP.4** | Does the existing secant feedback pattern (lin_route_to_secant) provide a proven model for Phase 5 scheduler wiring? | `cmp_linearity.rs:71-73`: `pub fn lin_route_to_secant() -> bool { unsafe { LIN_SAW_TAINTED_CMP && !LIN_SAW_NONLINEAR_CMP } }` — reads static flags set during execution, consumed by `ConcolicFeedbackWrapper::append_metadata`. | **CONFIRMED** — static-flag-to-scheduler pattern is proven. |
| **013.CP.5** | Does the codebase have an ABIMap structure suitable for loading sink_definitions and oracle addresses at init? | `corpus_initializer.rs:112-114`: `pub struct ABIMap { pub signature_to_abi: HashMap<[u8; 4], ABIConfig> }`. Also FuzzHost has `hash_to_address` / `address_to_hash` maps for address-based lookups. | **CONFIRMED** — ABIMap available for init-time address/selector loading. |
| **013.CP.6** | Does the shadow stack TB struct have a taint bit we can read at the CALL boundary? | `cmp_linearity.rs:135-139`: `struct TB { t: bool, nl: bool }` — `t` is the taint bit. Shadow stack is `stack: Vec<TB>`. Real-time access via `self.stack[self.stack.len() - n]`. | **CONFIRMED** — TB.t available for injection detection. |
| **013.CP.7** | Do SLOAD/SSTORE handlers operate on local shadow storage only, with no persistent/cross-execution taint? | `cmp_linearity.rs:439-450`: SLOAD reads from `self.storage` (local HashMap), SSTORE writes to `self.storage`. Neither reads nor writes FuzzHost. Cross-execution taint (Phase 3) requires a new host-level field. | **CONFIRMED** — purely per-execution shadow. |
| **013.CP.8** | Does `on_return` do anything besides pop_ctx? Can it be extended for return-value taint marking? | `cmp_linearity.rs:509-519`: `fn on_return(...) { self.pop_ctx(); }` — no return-value taint. `_interp` parameter gives access to opcode for distinguishing call types. `host` parameter gives access to FuzzHost for persistent reads. | **CONFIRMED** — on_return is a clean extension point. |

### Gate Check: All 013 Investigation Checkpoints resolved with concrete source evidence. Proceeding to plan.md.

---

## Dependency Graph

```
Phase 0: Fix Taint Engine Bugs
  │
  ▼
Phase 1: Shallow Injection Detection (byte match at CALL, no storage)
  │
  ▼
Phase 2: Four-Link Chain (TAINT→GUARD→SINK→SELECTOR)
  │
  ▼
Phase 3: Persistent Cross-Execution Taint (FuzzHost.tainted_storage)
  │
  ▼
Phase 4: Value-Confirmed Provenance (TaintProvenance struct)
  │
  ▼
Phase 5: Feedback → Scheduler Wiring (mutation bias)
```

Each phase unlocks the next. Phase 0-2 is the minimum viable injection detector. Phase 3-4 extends it across time. Phase 5 makes it orchestrate.

---

## Phase 0 — Fix the Taint Engine

**Goal:** Fix the two bugs in `cmp_linearity.rs` that break storage taint through proxy calls. Without this, every phase below is wrong for proxy-mediated protocols.

### Bug 1: push_ctx calldata peek indices (cmp_linearity.rs:210-214)

Current:
```rust
0xf1 | 0xf2 | 0xf4 | 0xfa => (interp.stack.peek(3).unwrap(), interp.stack.peek(2).unwrap()),
```

Correct — CALL and DELEGATECALL have different stack layouts:

```rust
fn push_ctx(&mut self, interp: &mut Interpreter) {
    let (arg_offset, arg_len) = match interp.bytecode.opcode() {
       0xf1 | 0xf2 => (interp.stack.peek(3).unwrap(), interp.stack.peek(4).unwrap()),
       0xf4 | 0xfa => (interp.stack.peek(2).unwrap(), interp.stack.peek(3).unwrap()),
       _ => return,
    };
```

**What this fixes:** Cross-call calldata taint propagation for zero-value CALLs. Currently `peek(2)` reads `msg.value` as `argsLength`, producing zero-length `input_data` for the most common case (CALL without ETH). Taint never reaches the child.

### Bug 2: DELEGATECALL storage clear in push_ctx (cmp_linearity.rs:223-225)

Current:
```rust
self.mem.clear();
self.storage.clear();
self.stack.clear();
```

Correct — DELEGATECALL/CALLCODE share the caller's storage:

```rust
pub fn push_ctx(&mut self, interp: &mut Interpreter) {
    // ... arg_offset/arg_len as above ...

    self.ctxs.push(Ctx {
        input_data: self.write_input(arg_offset, arg_len),
        mem: self.mem.clone(),
        storage: self.storage.clone(),
        stack: self.stack.clone(),
    });
    self.mem.clear();
    self.stack.clear();
    // DELEGATECALL/CALLCODE share caller storage — do NOT clear
    let opcode = interp.bytecode.opcode();
    if opcode != 0xf4 && opcode != 0xf2 {
        self.storage.clear();
    }
}
```

And on pop_ctx: DELEGATECALL/CALLCODE should NOT restore storage from the saved ctx — the child's SSTORE went into shared storage and must be preserved:

```rust
fn pop_ctx(&mut self, was_delegatecall: bool) {
    if let Some(ctx) = self.ctxs.pop() {
        self.mem = ctx.mem;
        self.stack = ctx.stack;
        if !was_delegatecall {
            self.storage = ctx.storage;  // restore only for non-shared calls
        }
        // For DELEGATECALL/CALLCODE: child's storage writes STAY in self.storage
    }
}
```

**What this fixes:** Proxy-mediated storage chains. Without it, any taint flowing through a DELEGATECALL (SSTORE in implementation, SLOAD in proxy) is invisible. With it, the engine tracks storage taint through the proxy boundary.

### Files to modify:
- `src/evm/middlewares/cmp_linearity.rs:210-234` — push_ctx/pop_ctx
- `on_return` at line 509-519 — need to pass call type to pop_ctx, or store it on Ctx

### Verification:
After fix, run on a proxy protocol (UUPS/beacon pattern). Verify: tainted calldata → DELEGATECALL → SSTORE in impl → RETURN → SLOAD in proxy → CALL transferFrom. Without fix: SLOAD is clean. With fix: SLOAD is tainted.

### Unlocks:
- Phase 1 (shallow detection doesn't need storage, but Phase 1's own verify runs on proxy targets)
- Phase 3 (persistent taint would accumulate garbage without this fix)
- All downstream phases that involve proxy-mediated drains

---

## Phase 1 — Shallow Injection Detection

**Goal:** Detect when fuzzer-controlled bytes reach the CALL `to` address or calldata at the CALL boundary. No storage tracking needed — byte comparison only.

### Mechanism

At the CALL/DELEGATECALL/STATICCALL opcode in `on_step()`, before `popn!` clears the shadow stack:

```rust
0xf1 | 0xf2 | 0xf4 | 0xfa => {
    // READ TAINT BEFORE POP — shadow stack still intact
    let to_tainted = self.stack[self.stack.len() - stack_entries + 1].t;
    // ... also check calldata taint from memory ...

    if to_tainted {
        INJECTION_TAINTED_CALL_TARGET = true;
    }

    // CALLCALDATA check
    let (arg_offset, arg_len) = match opcode {
        0xf1 | 0xf2 => (interp.stack.peek(3), interp.stack.peek(4)),
        0xf4 | 0xfa => (interp.stack.peek(2), interp.stack.peek(3)),
        _ => unreachable!(),
    };
    let calldata_tainted = self.read_mem_tainted(arg_offset, arg_len);
    if calldata_tainted {
        INJECTION_TAINTED_CALLDATA = true;
    }

    // Then proceed with existing popn! + push_ctx
    popn!(stack_entries);
    clean!();
    self.push_ctx(interp);
}
```

### Static Flags

Same pattern as `LIN_SAW_TAINTED_CMP`:
```rust
pub static mut INJECTION_TAINTED_CALL_TARGET: bool = false;
pub static mut INJECTION_TAINTED_CALLDATA: bool = false;
```

Post-execution oracle reads these and writes `EVMBugResult`.

### No Storage Tracker

This phase does NOT use `self.storage`. It reads taint from:
- Shadow stack (for `to` address taint)
- Memory taint vector (for calldata taint, which was written there by `CALLDATACOPY`)

This is the libafl pattern: "is the parameter literally fuzzer input at the moment of the call?" No propagation through SSTORE/SLOAD needed.

### What It Catches

- Direct calldata injection: `CALL(address = calldata[4..24])`
- Nested calldata: calldata → memory → CALL(to = memory[0..20])
- Zero-value CALLs (the common case)
- DELEGATECALL with tainted `to` or calldata

### What It Misses

- Storage-mediated chains: calldata → SSTORE → SLOAD → CALL `to`
- Cross-execution drains: write in tx 1, trigger in tx 2
- Proxy-mediated: calldata → DELEGATECALL → implementation SSTORE → SLOAD → CALL

These require Phase 3 (persistent storage taint).

### Files to create/modify:
- `src/evm/middlewares/cmp_linearity.rs` — add injection flags to existing CALL handlers
- OR new sibling middleware `InjectionDetect`, modeled on `CmpLinearityTaint` but simpler

### Verification:
Run on a known exploit with direct calldata-to-CALL mapping. Verify `INJECTION_TAINTED_CALL_TARGET` fires. Run on normal protocol operation — verify zero FPs on internal protocol CALLs (pool → token transfers, vault → strategy interactions).

### Unlocks:
- Phase 2 (the four-link chain needs the CALL boundary taint as its first link)

---

## Phase 2 — Four-Link Chain (TAINT → GUARD → SINK → SELECTOR)

**Goal:** Distinguish "data touched the CALL" from "data controlled the sink's critical parameter." Add guard, sink, and selector discrimination at the CALL boundary.

### The Chain

```
TAINT  →  GUARD  →  SINK  →  SELECTOR  →  EXPLOIT
│           │          │          │
byte 12-31  CALL       CALL      calldata matches
reached     didn't     target    transferFrom selector
CALL        revert;    is a      0x23b872dd AND
boundary    guard      known     from param at
            passed or  financial offset 4+12 is
            was absent sink      tainted
```

### Implementation

At the CALL boundary where Phase 1 fires:

```
if INJECTION_TAINTED_CALL_TARGET || INJECTION_TAINTED_CALLDATA:
    1. GUARD_CHECK: Did the CALL succeed (no REVERT)?
       - If succeeded ∧ target has static BLOCKED verdict → GUARD_BYPASS
       - If succeeded ∧ target has static UNBLOCKED verdict → GUARD_PASS
       - If REVERTed → GUARD_BLOCKED → STOP (not an exploit)

    2. SINK_CHECK: Is the CALL target a known financial sink?
       - Check address against sink_definitions (loaded at init from ABIMap):
         known token contracts, vaults, lending pools
       - If not a sink → lower priority (could still be interesting)

    3. SELECTOR_CHECK: What does the calldata call?
       - Read first 4 bytes of forwarded calldata
       - If 0x23b872dd (transferFrom) → check if `from` at offset 4+12 is tainted
       - If 0xa9059cbb (transfer) → check if `to` at offset 4+4 is tainted
       - If other sink selector → check relevant param position
       - If no known sink selector → suppress if caller is known router
```

### Router Filter (Case D Mitigation)

Known routers detected at init from ABIMap: functions taking `(address target, bytes calldata)` or `bytes[]` (multicall).

At CALL boundary where caller is a known router:
- Financial sink selector + tainted critical param → FLAG (router abused)
- Non-financial selector → SUPPRESS (router doing its job)
- Financial sink selector + clean critical param → LOW priority (router used for legitimate transferFrom)

### Files to modify:
- `src/evm/middlewares/injection_detect.rs` (new) — Full four-link middleware
- `src/evm/oracle.rs` — Injection finding type for the exploit chain
- Fuzzer init code — load sink_definitions from ABIMap, label known routers

### Verification:
Run on Yearn V3 fork with known exploit patterns. Verify: calldata through `execute` → `transferFrom` with tainted `from` is flagged. Same calldata through `execute` → `setParam` is suppressed.

### Unlocks:
- Phase 5 (scheduler weighting needs confirmed exploit signal, not raw taint)

---

## Phase 3 — Persistent Cross-Execution Taint

**Goal:** Propagate taint across fuzzer iterations through storage. Catch two-step drains where write and trigger are in different inputs.

### Mechanism

Add `tainted_storage: HashMap<(EVMAddress, EVMU256), bool>` to `FuzzHost`.

`FuzzHost` lives in `Rc<RefCell<>>`, created once at `evm_fuzzer.rs:113`. Never cloned, never replaced. The `init_host!()` macro at `vm.rs:459` resets per-execution fields — exclude `tainted_storage`.

**Persistent SLOAD** — reads from host:
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

**Persistent SSTORE** — writes to host:
```rust
0x55 | 0x5d => {
    let v = pop!();
    let key = interp.stack.peek(0);
    let address = interp.input.target_address;
    self.storage.insert(key, v.t);
    if v.t {
        host.tainted_storage.insert((address, key), true);
    }
}
```

### Additive Merge

Taint bits never clear within a campaign. Only snapshot reset clears `host.tainted_storage.clear()`. A non-tainted SSTORE does NOT clear the bit — "poison then legit overwrite then exploit" patterns need the historical taint to persist.

### Decay Rules

1. **Snapshot boundary**: `host.tainted_storage.clear()` — user resets fork, all taint resets
2. **Campaign end**: taint metadata dies with FuzzHost — no serialization needed
3. **Intra-execution**: `self.storage` (local) resets per execution (existing behavior) — `host.tainted_storage` carries across

### Files to modify:
- `src/evm/host.rs` — add `tainted_storage` field to `FuzzHost`
- `src/evm/middlewares/cmp_linearity.rs` — SLOAD/SSTORE handlers read/write host taint
- `src/evm/vm.rs` — verify `init_host!()` does NOT reset the new field

### What It Unlocks:
- Two-step drains across inputs
- Poison-in-1, trigger-in-5 patterns
- Phase 4 (value confirmation needs persistent storage to compare against)

---

## Phase 4 — Value-Confirmed Provenance

**Goal:** Eliminate the false attribution risk from Phase 3. Instead of just tracking taint bit, track the actual stored value and its origin.

### TaintProvenance Struct

```rust
pub struct TaintProvenance {
    pub tainted: bool,
    pub writer_iteration: u64,
    pub writer_pc: usize,
    pub writer_calldata_offset: Option<Range<usize>>,
    pub stored_value: EVMU256,
}
```

Upgrade `FuzzHost.tainted_storage`:
```rust
// Phase 3:
tainted_storage: HashMap<(EVMAddress, EVMU256), bool>

// Phase 4:
tainted_storage: HashMap<(EVMAddress, EVMU256), TaintProvenance>
```

### Value Confirmation at SLOAD

```rust
0x54 => {
    let key = interp.stack.peek(0);
    let address = interp.input.target_address;
    let slot_value = actual_sload_result;  // from interp or EVM state

    if let Some(prov) = host.tainted_storage.get(&(address, key)) {
        if prov.tainted && slot_value == prov.stored_value {
            // ✅ Confirmed: the bits in this slot are exactly what was written
            // by iteration prov.writer_iteration at PC prov.writer_pc
            CONFIRMED_PROVENANCE = true;
        }
    }
}
```

When the values match, false attribution is impossible — EVM storage is deterministic. The slot holds the exact bytes that a known tainted write placed there.

When values don't match, the taint bit is "stale" — the slot was poisoned before but has been overwritten. Log as stale, don't flag as exploit.

### Files to modify:
- `src/evm/host.rs` — change `tainted_storage` value type, add `TaintProvenance` struct
- `src/evm/middlewares/cmp_linearity.rs` — SSTORE records provenance, SLOAD checks value match

### Verification:
Run multi-iteration campaign. Input 1: SSTORE slot 5 = 0xDEAD with tainted value. Input 2: overwrite slot 5 = 0xBEEF (non-tainted). Input 3: SLOAD slot 5. Verify: value-confirmation check FAILS (0xBEEF ≠ 0xDEAD), logged as stale. Then run with no overwrite: value-confirmation PASSES.

---

## Phase 5 — Feedback → Scheduler Wiring

**Goal:** Feed taint signal into the mutation scheduler. Move from "detection" (flagging after execution) to "orchestration" (biasing mutation toward hot bytes during execution).

### Mechanism

Same pattern as `lin_route_to_secant()` — a taint-derived boolean consumed by the scheduler:

```rust
// In injection_detect.rs, at the CALL boundary after four-link chain:
if confirmed_exploit_path {
    INJECTION_CONFIRMED_HOT_BYTE_RANGE = Some(hot_byte_range);
    // hot_byte_range is derived from: which calldata bytes produce
    // the taint at the CALL to/calldata position?
    // Answer: already tracked by shadow stack — TB traces back to CALLDATALOAD offset.
}
```

The scheduler (`MutationStage` or a custom `Feedback`) reads this:

```rust
// In scheduler/mutation logic:
if let Some(range) = INJECTION_CONFIRMED_HOT_BYTE_RANGE {
    // Increase mutation probability for bytes in this range
    mutation_power[range].weight *= 2.0;
}
```

### LibAFL Pattern

```
Phase 1 (detection):  CALL fires → taint set → EVMBugResult
Phase 5 (direction):  CALL fires → taint set → scheduler.bias_bytes(range)
```

The mutation already has per-byte probability profiles (`havoc_mutations`, `splice_mutations`). The change is: when taint says "byte 12-31 is hot," bump its probability before the next `perform_all()` on this input's children.

### What This Unlocks

Without it: the fuzzer finds the injection path by luck — enough iterations with random mutations eventually hit the right bytes. The finding is recorded but not exploited further.

With it: the fuzzer finds the injection path → knows which bytes control it → spawns children with those bytes aggressively mutated → explores the full drain parameter space (amount, recipient, token) faster.

### Files to modify:
- `src/evm/middlewares/injection_detect.rs` — export hot byte range alongside static flags
- `src/fuzzer.rs` or executor — read hot byte range and apply to mutation power schedule
- Pattern follows `lin_route_to_secant()` at `cmp_linearity.rs:345-353` — proven mechanism

### Verification:
Run A/B test: injection detection with scheduler feedback vs without. On a target with a known exploit path, measure iterations-to-drain-discovery. With feedback: should converge faster because hot bytes are biased.

---

## Phase 6 — Static Kill Chain Bridge

**Goal:** Load TAINT 1-3 output at fuzzer init. Use static kill chains as a grammar to guide mutation before any runtime taint signal exists.

### Mechanism

At fuzzer init, load `kill_chains_guarded` from the static pipeline's DuckDB output:

```
kill_chains.csv:
  entry_id, entry_name, pivot_id, pivot_name, sink_id, sink_name,
  fwd_depth, bwd_depth, total_depth, fwd_path, bwd_path

guard_verdicts.csv:
  function_id, function_name, verdict (BLOCKED|UNBLOCKED), prank_required
```

These are loaded into `FuzzHost` at campaign start:

```rust
pub struct FuzzHost<SC> {
    // ... existing fields ...
    pub kill_chains: Vec<KillChain>,
    pub guard_verdicts: HashMap<EVMAddress, FunctionGuard>,
}

pub struct KillChain {
    pub entry_address: EVMAddress,
    pub entry_selector: [u8; 4],
    pub sink_address: EVMAddress,
    pub sink_selector: [u8; 4],
    pub slots: Vec<EVMU256>,           // state vars on the path
    pub total_depth: u32,
    pub prank_required: bool,
}
```

### Grammar Guidance

Before any execution (cold start), the scheduler uses static kill chains to prioritize:

1. **Entry points**: prefer fuzzing mutators that target functions appearing in kill chains
2. **Slots**: when mutating calldata, prefer values that write to kill chain slots
3. **Prank routing**: if the shortest kill chain requires prank, route pranked inputs there first

```rust
// In mutation strategy selection:
let hot_targets = self.kill_chains.iter()
    .filter(|kc| !kc.prank_required)
    .sorted_by(|a, b| a.total_depth.cmp(&b.total_depth));

// Prefer inputs targeting entry points of unguarded, short kill chains
if !hot_targets.is_empty() {
    let target = hot_targets.first();
    bias_mutation_toward_selector(target.entry_selector);
    bias_mutation_toward_values(target.slots);
}
```

### Cold vs Hot Start

| Start type | Grammar source | Behavior |
|---|---|---|
| Cold (no prior campaign data) | Static kill chains | Fuzzer starts by exploring statically-identified kill chains first |
| Hot (resuming campaign) | Dynamic taint (Phase 3) + static grammar | Phase 5's runtime taint overrides static grammar — the fuzzer follows proven paths, not predicted ones |
| Mixed | Both | Static grammar seeds exploration; dynamic taint takes over as paths are confirmed |

### What This Unlocks

Phase 6 closes the loop started in Phase 0: the static pipeline ("could this be exploited?") directly feeds the dynamic fuzzer ("mutate toward that kill chain"). The fuzzer doesn't need to blindly discover the exploit surface — it starts from a map of the terrain.

### Verification:
Run on a protocol with pre-computed TAINT 1-3 kill chains. Measure: does the fuzzer find the exploit path faster with kill chain guidance vs without? The static grammar should reduce the search space from "all possible calldata" to "calldata that hits kill chain entry points."

---

## Summary: What Unlocks What

```
Phase 0: Fix push_ctx bugs
  └─→ Phase 1 storage taint reliable on proxy targets
Phase 1: Shallow CALL-boundary injection detection
  └─→ Phase 2: TAINT → GUARD → SINK → SELECTOR chain
      │
      ├─→ Phase 5: Scheduler bias from confirmed four-link patterns
      └─→ unblocks router discrimination FP risk
Phase 2: Four-link chain
  └─→ Phase 3: Persistent storage taint across iterations
Phase 3: Cross-execution taint
  ├─→ Phase 4: Value-confirmed provenance (eliminates false attribution)
  └─→ Phase 5: Scheduler bias from persistent taint patterns
Phase 4: Value-confirmed provenance
  └─→ Phase 5: Higher-confidence scheduler bias
Phase 5: Feedback → scheduler wiring
  └─→ All phases above gain orchestration power
```

**Minimum viable injection detector:** Phases 0 + 1 + 2. Catches direct calldata injection with the four-link chain. Zero persistent storage needed. Works on any EVM target.

**Full provenance system:** Phases 0-4. Adds cross-execution, value-confirmed, proxy-mediated detection. Catches the dominant DeFi exploit class.

**Orchestration system:** Phases 0-5. Taint drives mutation, not just detection.
