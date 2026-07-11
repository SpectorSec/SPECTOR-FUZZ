# Feature 040 — Temporal Probe Isolation (EO-03), Narrowed After Deeper Trace

## Status
**Partially refuted by deeper investigation — narrower scope than PR #2's EO-03, not a blind
"isolate everything" rewrite.** PR #2 correctly identified that controlled temporal probes
(`executor.rs:218-262`) run through the same VM/host stack as the real exploit step, before it
executes. I traced further than the PR did — checking whether `self.vm.execute()` mutates one
persistent, cumulative host or reloads an explicit staged state per call — and the answer resolves
most of the specific channels the PR worried about as already safe. What's left is narrower and
lower-confidence, and the fix below reflects that.

## What I verified is SAFE (not a risk, contrary to EO-03's broader framing)

**Storage/state is reloaded per call, not accumulated.** `EVMExecutor::execute`
(`vm.rs:1463,1520,1574`) sets `self.host.evmstate = <the input's embedded sstate>` at the top of
every single call. Each of the two probes and the real exploit step build their input via
`steps.last().unwrap().to_input(current_state.clone())` (`executor.rs:228,238,264`) — the SAME
clean prefix `current_state`, not whatever a prior probe left behind. So the real exploit step
executes against the correct, uncorrupted prefix storage regardless of what the probes wrote —
each call's `evmstate` assignment overwrites the previous call's mutations before that call even
starts.

**`reentrancy_metadata` is part of the reloaded `EVMState`, not a separate persistent field.**
`reentrancy.rs`'s oracle reads it via `ctx.post_state.as_any().downcast_ref::<EVMState>()` — i.e.,
it's carried in the very state object that gets reloaded per-call above. A probe's reentrancy
metadata cannot leak into the real step's for the same reason storage can't.

**Coverage/branch status is cleared at the top of every `execute()` call.**
`EVMExecutor::execute` (`vm.rs:1357-1358`) calls `clear_branch_status()` unconditionally before
doing anything else — this is already a per-call reset, not a run-target-wide accumulation.

**`DIVERGENCE_OBJECTIVE`/`LEDGER_OBJECTIVE`/`TIMESTAMP_DIM_LOCATED` cannot be touched by probes at
all**, because they're only ever written from the **feedback/oracle-evaluation pass**
(`feedbacks.rs:255,469` for `TIMESTAMP_DIM_LOCATED`; `ERC4626Oracle::oracle()` for
`publish_divergence`), which is `OracleFeedback::is_interesting()`/`objective.is_interesting()` in
`fuzzer.rs` — and that runs **after** `run_target()` returns entirely. Probes execute *inside*
`run_target()`, before it returns; they structurally cannot reach the code path that writes these
thread-locals.

**`temporal_reset_all()`** (`host.rs:133`) clears exactly `CMP_TEMPORAL_DIST`/`CMP_TEMPORAL_PC`/
`CMP_TEMPORAL_BN` — the three arrays the controlled-probe measurement itself depends on. Correctly
scoped to its own purpose, not a red herring.

## What remains a real, narrower, lower-confidence risk

The general *pattern* PR #2 raised — "any middleware/global not part of the reloaded `EVMState`
and not explicitly reset could leak between probe and real-step executions within one
`run_target` call" — is not fully closed by the checks above. Those checks covered every SPECIFIC
channel this audit and the 033/034/037 work have touched. They do not constitute a proof that
**no** middleware anywhere in `src/evm/middlewares/` holds execution-scoped state outside
`EVMState` and outside the explicitly-reset arrays. A full audit of every middleware (`sha3_bypass`,
`cmp_linearity`'s non-temporal fields, `oracle_tracker`, `oracle_staleness`, `dos_detector`,
`call_printer`, `value_capture`, `function_auth`) for this property is a larger task than this
feature's scope.

## What changes (scoped to the confirmed-narrower risk)

Rather than the broad "isolated dry-run / cloned fuzzer-VM state" rewrite PR #2 suggested (which
the storage-reload finding above makes unnecessary for state/reentrancy/coverage, and the
post-run_target-only finding makes unnecessary for divergence/timestamp), this feature is scoped
to a verification task plus one concrete, low-risk hardening:

1. **Audit task** (not a code change by itself): grep every file in `src/evm/middlewares/` for
   `static mut` / `thread_local!` declarations, and for each one, determine whether it's written
   during `execute()` (opcode-level, i.e. probe-reachable) or only during the post-run_target
   feedback pass (probe-unreachable, same as `DIVERGENCE_OBJECTIVE` etc.). Produce a table like
   this spec's "verified SAFE" section above, extended to cover every middleware. Anything found
   opcode-scoped and not part of `EVMState` is a genuine finding to spec as its own fix.
2. **Concrete hardening, low-risk**: add a comment at `executor.rs:218` (the start of the
   controlled-probe block) documenting the invariant this feature establishes — "probes are safe
   because `evmstate` reloads per-call and divergence/timestamp writes are post-run_target-only;
   if a new middleware introduces execution-scoped global state, it must be added to the audit
   table above or explicitly reset here" — so this doesn't silently rot as new middlewares are
   added.
3. **Regression test**: add a mock middleware with an execution-counter `static mut`, run a
   temporal-warp campaign, and assert the counter's value at oracle-evaluation time equals exactly
   1 (the real exploit step) not 3 (two probes + real step) — this is the concrete test PR #2
   suggested, and it's still valuable as a canary for exactly the residual risk identified above,
   even though the specific channels checked in this pass came back safe.

## Out of scope

- Rewriting probes to run against a cloned fuzzer/VM state or a dedicated "probe mode" — the
  storage-reload finding makes this unnecessary for the channels checked; revisit only if the
  audit task in item 1 above finds a real opcode-scoped leak that can't be cheaply fixed by adding
  it to a reset list.
- Auditing every middleware exhaustively as part of *this* feature — item 1 is scoped as a
  follow-up task/checklist, not required to close this spec; the value here is narrowing the claim
  to what's actually verified plus leaving a durable trail (comment + audit table) so the next
  person doesn't have to re-derive the same trace.
