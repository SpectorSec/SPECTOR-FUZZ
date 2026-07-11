# revm 41 Code Assessment for SpectorFuzz

This is a code-level assessment of the current SpectorFuzz `revm` 41 integration. It replaces the earlier generic risk matrix with concrete findings from the repository implementation.

> Verification note: GitHub raw/HTML access was used to compare against public `fuzzland/ityfuzz` because direct `git clone` from this container returned HTTP 403. The public ItyFuzz fork uses `fuzzland/revm` at rev `1dead51` with the `no_gas_measuring` feature, while this repository uses upstream `revm`/`revm-context`/`revm-primitives`/`revm-interpreter` 41.0.0.

## Executive verdict: mixed upgrade, not a clean win

**Short answer:** the `revm` 41 upgrade was done well enough that the core ItyFuzz/SpectorFuzz capability is still present, but it almost certainly degraded some of the original fuzzland/ItyFuzz performance and ergonomics unless you measure otherwise. It is a **functional compatibility port**, not a fully performance-equivalent replacement for the old fuzzer-tuned engine.

### Capability verdict

| Capability area | Verdict | Why |
| --- | --- | --- |
| Opcode-level coverage | **Preserved** | `FuzzHost::run_inspect` owns the interpreter loop and updates `JMP_MAP` before `interp.step`. |
| Comparison-distance guidance | **Preserved, with global-state caveat** | `LT`/`GT`/`EQ`/`JUMPI` read live stack operands and update `CMP_MAP`/`CMP_PC`, but the maps are process-global. |
| Middleware execution | **Preserved** | Middlewares are invoked before every opcode through `invoke_middlewares!(..., on_step)`. |
| Control-leak modeling | **Mostly preserved but less type-safe** | Old custom `InstructionResult` variants were replaced by side flags that are converted back into the executor path. |
| State snapshot discipline | **Partially preserved** | Important measurement paths explicitly clone/restore `EVMState`, but there is no universal database snapshot wrapper. |
| Gas/throughput behavior | **Likely regressed** | The code refunds forwarded sub-call/create gas and uses huge gas limits, but still calls the normal `revm` 41 gas table on every `interp.step`. |
| Multi-worker isolation | **Still weak / likely regressed if threaded** | LibAFL observers borrow global static maps; safe enough for single-worker or process-isolated workers, risky for same-process threads. |

### Final judgment

The upgrade did **not** obviously destroy the original ItyFuzz bug-finding model: coverage, comparison-distance feedback, middleware hooks, control-leak tracking, onchain lazy loading, and several snapshot/restore paths are still wired into the current code. However, it also did **not** fully reproduce the old fuzzland fork's likely speed profile or custom result-type ergonomics. The most likely regressions are:

1. **Throughput regression** from keeping `revm` 41 static gas accounting in the hot loop.
2. **Type-safety regression** from replacing old custom control-leak results with mutable side flags plus `Revert`.
3. **Parallel execution regression risk** from shared global maps and flags.
4. **Snapshot consistency risk** because isolation is enforced per helper, not centrally.

If your question is "was this upgrade good enough to keep fuzzing?" the answer is **yes, for single-worker or process-isolated campaigns after smoke tests**. If your question is "is it as fast and clean as original ItyFuzz/fuzzland?" the answer is **probably no until EPS benchmarks and dedicated regression tests prove it**.

## Verification against public ItyFuzz/fuzzland

The specific final judgment is now verified against the public `fuzzland/ityfuzz` codebase:

1. **Throughput regression is no longer just a guess.** Public ItyFuzz depends on `fuzzland/revm` rev `1dead51` and enables `no_gas_measuring` on `revm`, `revm-primitives`, and `revm-interpreter`. This repository depends on upstream `revm` 41.0.0 crates and still calls the normal `gas_table()` in `FuzzHost::run_inspect`. SpectorFuzz refunds forwarded sub-call/create gas, but it does not restore the original fork's compile-time no-gas engine.
2. **Control-leak type-safety regression is verified.** Public ItyFuzz imports `InstructionResult::ControlLeak`, treats it as a successful call result, and stores the typed `InstructionResult` in `SinglePostExecution`. This repository no longer has that variant available from upstream `revm` 41, so it replaces the typed result with side flags and maps the event back through `InstructionResult::Revert`.
3. **Core bug-finding model is still present.** Public ItyFuzz's model centers on `run_inspect`, coverage/comparison maps, post-execution contexts, and snapshot-like `EVMState` continuation. This repository still has the custom `run_inspect` loop, `JMP_MAP`/`CMP_MAP`, post-execution routing, and explicit state snapshots in important measurement paths.
4. **Parallel/global-map concern is inherited, not newly invented.** Both designs use global feedback-map style instrumentation. The regression risk is specifically that upstream `revm` 41 did not solve this; if anything, the current port still needs a deliberate worker-isolation decision before same-process threaded workers are trusted.

So the corrected answer is: **yes, the upgrade preserved the main ItyFuzz capability surface, but it did regress or at least weaken two concrete things versus the public fuzzland fork: no-gas execution and typed `ControlLeak` results.** Anything beyond that, such as exact EPS loss, requires a benchmark rather than a document-only claim.

## Code evidence

The current code is not a plain upstream `revm` 41 embed. SpectorFuzz has already re-created much of the old fuzzer-oriented execution model by owning the interpreter loop in `FuzzHost::run_inspect`, invoking middlewares before each opcode, refunding forwarded sub-call gas, and mapping old custom control-leak exits onto per-execution side flags.

The highest-risk remaining issues are not abstract `revm` 41 compliance problems; they are concrete SpectorFuzz integration points:

1. **Global feedback maps are still process-global.** `JMP_MAP`, `CMP_MAP`, read/write maps, and control-leak flags live in statics. This is compatible with the old single-process fuzzland style, but it is the main place to audit before multi-worker execution.
2. **Coverage and comparison capture depend on exact stack operand positions.** The custom loop reads operands before `interp.step`; this is correct for the current code, but every opcode added to the capture set needs a stack-layout audit.
3. **Gas bypass is partial and deliberate.** Top-level interpreters are created with a very large gas limit, host block gas limit returns `u64::MAX`, and sub-call gas is refunded. Static per-op gas still runs inside `revm` 41, so this is a compatibility shim rather than a full no-gas engine.
4. **State isolation is implemented by cloned `EVMState` snapshots in selected measurement paths, not by a universal database snapshot layer.** Code that performs speculative execution must continue to explicitly restore host state.

## Finding 1: Interpreter hook migration is implemented in SpectorFuzz, not delegated to revm inspectors

### Current code

`FuzzHost::run_inspect` replaces the old fork-style `interp.run_inspect::<STATE, HOST, SPEC>(host, state)` call. The loop constructs a `revm` 41 instruction table and gas table, invokes SpectorFuzz middleware before every opcode, then calls `interp.step`.

Concrete evidence:

- `run_inspect` is documented as the replacement for the old `interp.run_inspect` path.
- Middleware execution happens before `interp.step`, while the current opcode and stack are still available.
- Coverage and comparison maps are updated inside this custom loop, not via upstream `revm-inspector`.

### Assessment

This addresses the largest migration breakage: SpectorFuzz does not rely on a removed or renamed upstream inspector trait. It owns the per-opcode loop and therefore still has access to program counter, opcode, stack, memory, call input, and host state.

### Code-level residual risk

Operand capture uses raw stack indexing through `fast_peek`. That is fast, but it assumes each opcode branch has already been audited against EVM stack layout. The currently implemented `JUMPI`, `SSTORE`/`TSTORE`, `SLOAD`/`TLOAD`, `LT`/`GT`/`EQ`, and call/create opcodes appear intentionally mapped, but new opcodes should not be added without a stack-position test.

## Finding 2: Branch and comparison feedback is wired to the current revm 41 interpreter state

### Current code

The feedback path reads `interp.bytecode.opcode()`, `interp.bytecode.pc()`, and `interp.stack` before the instruction executes. It updates:

- `JMP_MAP` for coverage and branch novelty.
- `CMP_MAP` and `CMP_PC` for comparison-distance ownership.
- `CMP_TEMPORAL_*` when timestamp or block-number reads gate a comparison.
- `BRANCH_STATUS` through `add_branch`.

### Assessment

The concern that coverage hooks are silently blind is **not supported by the current code**. The branch and comparison signal is actively produced in `src/evm/host.rs` from the live `revm_interpreter::Interpreter` object.

### Code-level residual risk

`CMP_MAP` is a monotonic process-global map. The code has ownership fingerprints (`CMP_PC`) and reset helpers for some probes, but the map is still shared mutable global state. This is acceptable for the existing LibAFL observer model, but it is the first thing to isolate if multi-worker correctness becomes a requirement.

## Finding 3: Old custom control-leak `InstructionResult` variants were replaced by side flags

### Current code

The repository explicitly documents that control-leak signal flags replace custom `InstructionResult` variants from the old revm fork. `clear_branch_status` resets those flags per execution. During frame handling, `run_inspect` returns `InstructionResult::Revert` if any control-leak flag was raised, and higher-level code treats non-success returns as reverted-or-control-leak.

### Assessment

This is a real migration shim. Since upstream `revm` 41 will not carry fuzzland-specific `InstructionResult` variants, SpectorFuzz now encodes those events out-of-band and maps them back into the existing executor decision path.

### Code-level residual risk

The signal is less type-safe than a dedicated enum variant. Any new caller that sees only `InstructionResult::Revert` must also respect the control-leak side flags and the existing `is_reverted_or_control_leak` routing. If a future path clears flags too early or fails to call `clear_branch_status`, control-leak classification can become stale.

## Finding 4: State isolation exists in important measurement paths but is not universal

### Current code

`value_token_inflow_eth` clones `self.host.evmstate`, runs the liquidation engine for measurement, computes the earned delta, and always restores the cloned state before returning.

### Assessment

The current code contains explicit snapshot/restore logic for at least the valuation path that would otherwise poison later fuzzing state. That directly addresses the state-leak class for this path.

### Code-level residual risk

This is not a generic `revm` database snapshot wrapper. It is a per-helper discipline. Every speculative helper must be audited for the same pattern: clone state, execute, read signal, restore on all exits. The assessment should therefore prioritize call sites that invoke `run_inspect` for measurement or oracle probing.

## Finding 5: Gas bypass is implemented as a compatibility shim, not a complete removal of gas accounting

### Current code

SpectorFuzz creates interpreters with a very large gas limit, returns `u64::MAX` from the host block gas limit, and refunds sub-call/create forwarded gas after nested execution. However, `revm` 41 still charges static per-op gas inside `interp.step` because `run_inspect` passes the normal gas table to the interpreter.

### Assessment

The code intentionally preserves enough gas semantics for `revm` 41 to execute while avoiding the most damaging fuzzer throughput penalty from nested calls consuming parent gas. This is not equivalent to the old stripped fork if that fork fully disabled gas metering.

### Code-level residual risk

Malformed or gas-sensitive bytecode can still stop on `OutOfGas` if the internal interpreter gas counter is exhausted, and per-op gas accounting still costs CPU. If throughput is unacceptable, the next code change should benchmark and then introduce a feature-gated no-gas table or a cheaper gas path rather than assuming gas is already disabled.

## Finding 6: Onchain cache/RPC discipline is partly preserved at middleware level

### Current code

The `OnChain` middleware lazily fills block fields such as timestamp and gas limit only when corresponding opcodes are encountered. It also loads external code on CALL-like and EXTCODE* opcodes and uses cache/force-cache routing before remote setup.

### Assessment

This supports the project constraint that SpectorFuzz should avoid redundant RPC queries. The current code does not eagerly fetch all block/account data up front; it fetches on demand from opcode hooks.

### Code-level residual risk

The code-level risk is not `revm` 41 itself; it is whether cache misses are bounded during campaigns. The high-value audit path is `OnChain::load_code` and endpoint cache behavior, not the upstream interpreter.

## Finding 7: Multi-worker safety remains the weakest area

### Current code

LibAFL observers are constructed over mutable references to global static maps (`JMP_MAP`, `CMP_MAP`, `READ_MAP`, `WRITE_MAP`). Control-leak and temporal comparison state also use statics.

### Assessment

This preserves the old global-map fuzzing architecture, but it is not robust isolation for multi-worker execution in one process. If SpectorFuzz runs workers as separate processes, this is less dangerous. If it runs threads sharing the same address space, map contamination and data races are realistic.

### Recommended code action

Before enabling threaded workers, move these maps into per-worker state or wrap them in a worker-indexed feedback structure. Do not only add locks: locks reduce data races but still merge coverage and comparison ownership across workers unless the scheduler expects shared feedback.

## Priority code-audit checklist

1. **Audit every `run_inspect` call site.** Classify it as committing execution, measurement-only execution, deployment, or replay. Measurement-only paths must restore `EVMState` and relevant metadata.
2. **Add regression tests for comparison capture.** Minimal bytecode fixtures should assert that `EQ`, `LT`, `GT`, and `JUMPI` update `CMP_MAP`/`JMP_MAP` from `revm` 41 stack state.
3. **Add a control-leak regression test.** Trigger the side-flag path and assert that the executor still records post-execution context instead of treating it as an ordinary revert.
4. **Benchmark gas overhead.** Compare the current large-gas/refund shim against a feature-gated no-gas path before changing gas behavior.
5. **Decide worker model.** If workers are threads, global statics need a redesign. If workers are processes, document that assumption and keep shared memory boundaries explicit.
