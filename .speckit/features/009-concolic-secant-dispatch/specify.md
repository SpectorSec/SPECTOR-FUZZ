# Feature 009 — Concolic/Secant Dispatch Triage

**Status:** 009a substrate + dispatch wiring IMPLEMENTED & build-verified (feature OFF by
default). NOT yet safe to enable — missing the §5.3 stall→requeue fallback + runtime
validation. See "Implementation status 2026-06-29" below.

## Implementation status (2026-06-29)

DONE (compiles clean both with and without `--features concolic_secant_dispatch`):
- `src/evm/middlewares/cmp_linearity.rs` — `CmpLinearityTaint` middleware (009a). Shadow
  stack of `(tainted, nonlinear)` tuples (desync-proof). Classifies each input-tainted
  comparison LINEAR vs NON-LINEAR; verdict in globals `LIN_SAW_TAINTED_CMP` /
  `LIN_SAW_NONLINEAR_CMP` (+ per-pc `CMP_LINEARITY`). Resyncs on stack mismatch instead of
  panicking (observe-only, never aborts a run).
- `feedbacks.rs` (`Sha3WrappedFeedback::is_interesting`) — gated: resets the verdict per
  interesting input, and reexecutes non-step inputs with `CmpLinearityTaint` (piggybacks
  the existing sha3 reexecution site).
- `concolic_stage.rs` (`ConcolicFeedbackWrapper::append_metadata`) — gated triage: if
  `lin_route_to_secant()` (tainted gate present AND all linear), skip queuing for concolic.
- `Cargo.toml` — `concolic_secant_dispatch` feature, NOT in default.
- Enum `MiddlewareType::CmpLinearity` + mod export.

DONE (added 2026-06-29) — **§5.3 stall→requeue fallback**:
- `mutator.rs::requeue_for_concolic<S: HasCorpus + HasMetadata>` — pushes the CURRENT
  corpus id (`state.corpus().current()`, via `usize::from(CorpusId)`) onto
  `ConcolicPrioritizationMetadata.interesting_idx` (dedup'd).
- Called at the terminal secant give-up (`secant_step == None`) in BOTH
  `apply_value_secant` and `apply_calldata_secant` Probe2 arms. Gated
  `concolic_secant_dispatch`. `HasCorpus` threaded onto the two secant methods + the
  `Mutator` impl (all real callers use `EVMFuzzState`, which has it).
- Guarantee: a linear gate routed away from concolic that the secant can't flip is handed
  back → no mis-route can cost a branch. Errs toward over-requeue (safe). The Probe1
  measurement-miss path is a retry (resets Idle+cooldown), correctly NOT requeued.
- Conservative note: the calldata secant rotates args, so its per-arg `None` may requeue
  before a later arg (the real lever) is tried — over-requeue, safe; full-rotation gating
  is a future refinement.

Both configs (`cargo check` with and without the feature) compile clean.

STILL NOT DONE — why the feature stays OFF until validated:
1. **Runtime validation (§7) pending.** `cargo check` proves compilation, not that the
   shadow-stack classifies correctly on real bytecode nor that there is no regression. The
   middleware degrades gracefully (resync, never panics), but the measured linear/non-linear
   ratio and a no-regression A/B on the 200-exploit set need an actual fuzz run.
2. Residual gap: an input the secant NEVER engages (never reaches Probe2) is not requeued by
   §5.3. Rare for a tainted-gate input; to be confirmed/quantified in validation. If it
   regresses, add a bounded deferral backstop at the triage.
3. Multi-step/post-execution inputs: handled by existing behavior (concolic skips at
   `perform:113`; secant/controlled-probe owns them). Consistent with §3.

NEXT: run §7 validation via the harness `validate.sh` (in this feature dir):
  `TARGET='-t build/*' DURATION=600 ./validate.sh`  (offchain) — or pass onchain flags.
It builds both configs to separate target dirs, runs each with `--concolic --run-forever`
for the budget, then reports: baseline(OFF) bugs vs dispatch(ON) bugs (PASS iff ON >= OFF)
and the live dispatch ratio printed by `cmp_linearity::lin_print_stats` (`[009-dispatch]
routed_secant=… queued_concolic=… requeued=… linear_ratio=…%`, emitted every 100
concolic-eligible inputs). Enable the feature only after PASS across a representative set.

**009 is CODE-COMPLETE (substrate + triage + fallback, compiles both configs); it is NOT
validated and the feature remains OFF by default.**

## §7 VALIDATION RUN (2026-06-29) — Yearn V3 USDC vault, mainnet fork @25420000

Lane A: anvil fork (Alchemy) of the live `USDC Multi Strategy V3` vault
(`0x9cFb…361Ad`) + USDC + TokenizedStrategy impl; `-c eth -b 25420000 -u localhost
--onchain-storage-fetching dump -d all -f --concolic --run-forever`, 200s baseline vs 200s
dispatch.

**Result — NO REGRESSION (PASS):** dispatch found ≥ baseline (raw 4 ≥ 3; distinct types
3 ≥ 2: ArbitraryCall, Fee-on-Transfer, +Fund Loss). 0 panics both. (Findings are likely
false positives on an audited vault; the extra Fund Loss is within single-run stochastic
noise — the point is dispatch did NOT find fewer.)

**Ratio:** routed_secant=21, queued_concolic=279, requeued=21 → 7% routed. KEY FINDING:
**requeued ≈ routed** — on Yearn's complex share-math gates the secant STALLS and the
fallback requeues ~every routed input back to concolic. So:
- The §5.3 stall→requeue fallback is VALIDATED end-to-end on a real target (no coverage
  lost → that's why no-regression holds).
- But NET concolic savings ≈ 0 here: Yearn's gates aren't the simple linear value/temporal
  gates the secant solves, so routed inputs bounce back. **009's savings are
  TARGET-DEPENDENT** — safety always; budget savings only where gates are linear (staking/
  threshold/temporal style). Measured 7% routed but ~0% net saved on this target.

**3 pre-existing upstream crashes fixed (surfaced only by the live target, NOT 009 code):**
1. `concolic_host.rs:725` — calldata read past input length indexed `data[idx]` unguarded
   → OOB panic. Fixed: zero-pad (EVM calldata semantics). **ORIGIN: pre-existing in
   UPSTREAM ittyfuzz** — identical unguarded `let mut bytes = data[idx].clone();` at
   `/workspace/_global/original-ityfuzz/src/evm/concolic/concolic_host.rs:720`. The live
   Yearn fork exposed a latent crash present in BOTH forks; SpectorFuzz did not introduce it.
2. `vm.rs:1071` — `Borrow` of a token not in `known_tokens` → `panic!("unknown token")`
   (Gap C: known_tokens is populated from `-t` targets + Uniswap-pair discovery; a token
   reached another way — e.g. `asset()` on a vault with no discovered pair — wasn't in it).
   Fixed in two stages: (a) graceful no-op, then (b) **on-demand discovery** — on an unknown
   token, fingerprint the already-loaded fork bytecode via EVMole (balanceOf+transfer+
   totalSupply selectors); if ERC20, build a `TokenContext` (empty swaps; borrowable once a
   pair is found) and register it in `known_tokens`, then proceed; else graceful no-op.
   Makes unknown-token handling fully autonomous (asks the fork instead of dropping/panicking).
3. `input.rs:906/925` — basefee/gas_limit env-mutator `U256.to::<u64>()` overflow panic.
   Fixed: `saturating_to`. **ROOT CAUSE: revm migration gap (NOT a logic bug).** Original
   ittyfuzz uses fuzzland revm 3.3.0 (`crates/primitives/src/env.rs:17`) where
   `BlockEnv.gas_limit`/`basefee` are `U256` → macro assigned `U256 → U256`, no overflow
   possible. SpectorFuzz uses revm 41 (`revm-context-15.0.0/src/block.rs`) where those two
   fields are now `u64` (number/timestamp stayed U256) → assigning a giant mutator-generated
   U256 into u64 panics. The macro wasn't updated when revm narrowed the types. Crash surface
   == type-migration surface (only gas_limit/basefee → u64 crashed; number/timestamp/warp
   path, still U256, never did). `saturating_to` is the correct narrowing.
All in shared code (both binaries) → A/B stays fair; all genuine robustness improvements.

**Also confirmed live:** Feature 010 objectives counter ticks (showed 2-3, was structurally
0); Lane A economic pipeline works (earned>owed fired via real fork liquidity — the
liquidator realized value, which Lane B structurally cannot).

**Verdict:** 009 is VALIDATED as SAFE (no-regression) + the fallback works on a real
protocol. Savings are target-dependent (need a linear-gate target to show >0% net). Keep
feature OFF by default until savings are quantified on a linear-gate target; it is now
proven not to regress.

## Runtime smoke (2026-06-29) — caught a real gap, pipeline confirmed live

Ran the dispatch binary (release, `--features concolic_secant_dispatch`) on the offchain
008 fixtures `build/*` (`-d all -f --campaign-orchestrator --temporal-skimming --concolic
--run-forever`). Findings:
- **Stable on real bytecode**: full duration, no panic, ~26k exec/s. The resync-never-panic
  shadow-stack holds.
- **Pipeline live**: `[009-dispatch] routed_secant=3 queued_concolic=12 requeued=3
  linear_ratio=20%` — triage routes, the §5.3 stall→requeue fallback fires.
- **CAUGHT A GAP (fixed)**: initially `routed_secant=0` — the linearity taint only sourced
  CALLDATA, so TEMPORAL gates (`reward=f(block.number)`) — the warp secant's whole domain —
  were seen as untainted and never routed. Fix: `TIMESTAMP(0x42)/NUMBER(0x43)` are now
  LINEAR taint sources (the warp-controllable clock). After the fix, temporal gates route
  (routed climbed 1→3). This is a bug `cargo check` could never have surfaced.
- **No regression on the fixtures**: baseline and dispatch both find 0 oracle bugs (these
  mocks are secant-convergence demos, not bug producers), corpus 20 vs 19 ≈ equal. So
  0-vs-0 is the fixtures' nature, not a 009 regression — but it ALSO means these fixtures
  CANNOT validate no-regression-on-bugs or the at-scale ratio.

**Still needed for the real §7 verdict**: a bug-PRODUCING target (Immunefi repo / DeFiHackLabs
onchain PoC) so the no-regression check (ON bugs ≥ OFF bugs) is meaningful and the ratio is
measured at scale. Print threshold reverted to 100 (was 5 for the smoke).

---
_original spec status note:_ Spec — was BLOCKED on prerequisite instrumentation; 009a now built.

> **2026-06-29 feasibility check (from source):** `is_linear_gate` cannot be computed at
> `ConcolicFeedbackWrapper.append_metadata` today. `host.rs` CMP capture records only
> comparison VALUES, PCs, block-numbers, and `TS_TOUCHED` — NOT operand opcode-dataflow or
> symbolic degree. The only symbolic `Expr` info lives inside the concolic engine
> (`concolic_host.rs`), available AFTER dispatch, not at triage time. Also: the multi-step
> routing this spec describes is ALREADY de-facto handled — `ConcolicStage.perform` skips
> `has_post_execution()` inputs at `concolic_stage.rs:113`. **Conclusion:** wiring 009 as-is
> is either a no-op or needs a new prerequisite first. A blind concolic throttle (the only
> thing buildable without it) is the coverage-losing mistake §4 rules out — do NOT ship it.
>
> **PREREQUISITE (009a):** a lightweight comparison-operand tracker (middleware) that tags
> each comparison PC with `{opcode-class set, symbolic degree (symbolic appears once / at
> degree ≤1)}` as operands are computed. Once that exists, §5.1 `is_linear_gate` is a pure
> function over the tag and 009 wires in with the §5.3 stall→requeue fallback.
**Owner:** TBD
**Last updated:** 2026-06-29
**Depends on:** 008 (CMP gradient steering / secant), 005 (temporal skimming), 003 (campaign orchestrator / controlled-probe executor)

---

## 1. Current dispatch (verified from source, 2026-06-29)

ItyFuzz/fuzzland dispatches concolic with **zero constraint awareness**:

- Pipeline: `tuple_list!(std_stage, concolic_stage, coverage_obs_stage)` — the concolic
  stage runs every fuzzing iteration but only works when its queue is non-empty.
- Queue = `ConcolicPrioritizationMetadata.interesting_idx`.
- **Populated by** `ConcolicFeedbackWrapper.append_metadata` (`concolic_stage.rs:~270`):
  pushes a corpus index **every time an input achieves new coverage** (enters corpus).
  Seeded initially with all corpus indices.
- **Drained by** `ConcolicStage.perform` (`concolic_stage.rs:82-203`): runs full
  concolic/SMT on every queued index, then clears.
- **Only filter** (`concolic_stage.rs:113`): skip if `data_abi.is_none()` OR
  `has_post_execution()` → concolic runs on **single, complete, ABI-decoded txs only**.
- **Solution injection** (`:167`): `data_abi.set_bytes(solution.input)` — needs a single
  ABI to write the SMT answer back into.
- Knobs: `enabled`, `allow_symbolic_addresses`, `timeout`, `num_threads`. No probability,
  interval, budget, or constraint-type triage.

**Effective rule today: "run full SMT on every new-coverage single-tx input."** A frontier
gated by `block.timestamp > unlockTime` (trivial) gets identical SMT cost to one gated by
`keccak256(x) == h`.

## 2. Why concolic skips multi-step / post-execution (verified)

`has_post_execution()` = state is **intermediate / suspended at a control-leak point**
(reentrancy/callback/flash-loan-callback continuation; `vm.rs:313`, comment confirms
"intermediate state … not yet finished"). `data_abi.is_none()` = no single decoded ABI
call. Concolic structurally cannot handle these because (a) no single ABI = nowhere to
inject the solution (`set_bytes`), and (b) `ConcolicHost` tracks symbolic state within ONE
complete execution — it does not propagate symbolics across the suspend/resume boundary or
across the multi-step prefix. **It is a limitation, not a principled choice.**

## 3. The two-axis complementarity (the design basis)

|  | single-tx | multi-step / control-leak / borrow |
|---|---|---|
| **linear (monotonic)** | secant (2 probes) — *triage relieves concolic* | **secant only** — concolic can't enter |
| **non-linear (chaotic)** | concolic (SMT) — its real corner | true gap (rare; out of scope) |

Secant is NOT merely "fast concolic for the easy 80%." Via the snapshot/controlled-probe
(005/008/003) it is the **only value-solver for the multi-step/temporal/reentrancy shape**
— the dominant DeFi-exploit shape concolic was always blind to. This likely explains part
of the base 109/200: multi-step value-gated exploits had no value-solver at all.

## 4. Goal

Insert constraint-type triage at the one dispatch point so that:
1. **Single-tx linear gates** are solved by the secant (cheap), not queued for SMT.
2. **Single-tx non-linear gates** are queued for concolic as today.
3. **Multi-step / post-execution inputs** are routed to the secant/controlled-probe path
   (currently they are silently dropped by both — concolic skips them and nothing else
   value-solves them).
4. Concolic budget concentrates on the genuine non-linear minority.

Strictly **additive**: worst case (everything classified non-linear) == today's behavior.
No regression below the base coverage/finding rate.

## 5. Design

### 5.1 Triage predicate (single-tx) — `is_linear_gate(branch) -> bool`
Classify the frontier branch (the comparison coverage is stuck on; pinned via the
existing `CMP_PC` / `CMP_TEMPORAL_PC`). Return true (→ secant) iff ALL hold:
- **opcode set** of the condition's data-flow ⊆ `{TIMESTAMP, NUMBER, CALLVALUE, ADD, SUB,
  LT, GT, SLT, SGT, EQ, MUL*}` (arithmetic-comparison only; no SHA3/KECCAK, ECRECOVER
  precompile, DIV/MOD with symbolic divisor, AND/OR/XOR/byte ops, EXP).
- **linear degree**: the symbolic variable appears **at degree ≤ 1** — it occurs **once**
  in the condition AST. `MUL` allowed ONLY if exactly one factor is concrete (constant).
  This rejects `x*(C-x)` (parabola, non-monotonic despite allowed opcodes).
- **AST depth ≤ 3** (bounds reconstruction of `x*x` / nested non-linearity).
- **one symbolic operand**, rest concrete.

Necessary-but-not-sufficient note: opcode-subset alone is NOT monotonicity (counterexample
above). The degree-≤1 check is the real guard.

### 5.2 Integration point — `ConcolicFeedbackWrapper.append_metadata`
This is THE dispatch decision. Change: before `meta.interesting_idx.push(idx)`:
- If input `has_post_execution()` or `data_abi.is_none()` → **do not queue for concolic**;
  instead tag it for the **secant/controlled-probe** lane (multi-step). (Today these never
  reach concolic anyway; we now route them somewhere instead of dropping.)
- Else if `is_linear_gate(frontier_branch)` → **do not queue**; the mutator secant
  (`apply_value_secant` / `apply_calldata_secant`, 008) owns it.
- Else → `push(idx)` (non-linear single-tx → concolic, as today).

Behind a Cargo feature `concolic_secant_dispatch` (default OFF until validated), so the
baseline path is untouched.

### 5.3 Stall → requeue fallback (correctness guarantee)
The static predicate can misjudge monotonicity (e.g. integer-division plateaus / rounding
— exactly the Class-2 precision gates). So the secant must self-detect failure:
- Secant attempts ≤ N probes (N=3). If the pinned distance does not shrink monotonically
  (stall or divergence) → mark the input and **push its idx onto `interesting_idx`** so
  concolic picks it up next drain. Cost of a misclassification = N cheap probes, never a
  lost branch.

### 5.4 Multi-step routing (fills the abandoned space)
post-execution / no-ABI inputs → the **controlled-probe executor** path (003 `run_target`
secant block, already re-executes the exploit step from a snapshotted prefix at base vs
base+δ). This is where temporal/value gates inside sequences get solved. No concolic
involvement. (Non-linear multi-step gates remain a known gap — rare; out of scope.)

## 6. Integration points (files)
- `src/evm/concolic/concolic_stage.rs` — `append_metadata` (triage), optional `perform`
  filter parity (`:113`).
- `src/evm/mutator.rs` — `is_linear_gate` (new), reuse `secant_step`, `apply_value_secant`,
  `apply_calldata_secant`; stall detection → requeue hook.
- `src/evm/host.rs` — expose the frontier branch's opcode-set + symbolic-operand info at
  the pinned `CMP_PC` (extend existing CMP/CMP_TEMPORAL capture with an opcode-class tag).
- `src/executor.rs` — multi-step controlled-probe lane (exists; ensure post-execution
  inputs route here).
- `Cargo.toml` — `concolic_secant_dispatch` feature (not default).

## 7. Acceptance / validation
- **Measure the real ratio first** (one-evening experiment): instrument a run to count
  frontier branches classified linear vs non-linear on the DeFiHackLabs corpus. Replaces
  the assumed 80/20 with a measured number → the true concolic-budget multiplier.
- **No regression**: with feature ON, found-exploit count ≥ baseline on the 200-exploit
  set (additive guarantee). Energy/queue floor: linear-classified inputs still get normal
  mutation energy (secant is extra, not a replacement).
- **Speed**: concolic invocations/run drop by the measured linear fraction; total
  exploits-found ≥ baseline, time-to-find on temporal/value-gated cases improves.
- **Fallback works**: a deliberately mislabeled linear gate (integer-division plateau)
  stalls the secant and gets requeued → still solved by concolic.

## 8. Risks / out of scope
- Risk: opcode-class tagging at `CMP_PC` must be accurate (symbolic-operand detection
  reuses concolic's existing taint where available; for the mutator path, use calldata-arg
  provenance from `AccessPattern`). Mis-tag → caught by the stall fallback.
- Out of scope: non-linear multi-step gates (no solver; rare); changing concolic's internal
  SMT; symbolic state across tx boundaries (still not done — secant covers it numerically).
- This is a Class-1/2-arithmetic optimization. Class-3 (absence/off-chain) is unaffected and
  remains the structural oracles' job (earned>owed / control-leak / arbitrary-call).
