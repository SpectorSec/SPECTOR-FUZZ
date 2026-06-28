# Feature 008 — CMP_MAP Gradient Steering

**Status:** Investigating (C/E/B implemented; aliasing 8.3 + throughput gate closed; Tier-1 validated)
**Owner:** TBD
**Last updated:** 2026-06-28

---

## Planner recognition — RESOLVED for testing (2026-06-28)

The secant now engages in a live campaign. Root blocker was the **Feature 003
planner** (`plan_campaign` → `pick_prime_and_exploit`) returning `None` for
contracts whose selectors aren't in the hardcoded allowlist. Added a name-heuristic
generic fallback (`find_generic_targets`: ≥2 functions incl. a trigger-named one →
single-contract 2-step campaign), **gated behind the `campaign_generic_fallback`
Cargo feature, OFF by default**. Production/bounty builds stay exact-selector
(machine-truth) only; the fallback compiles in solely for fixture testing. Verified:
with the feature, `[secant-warp] start … probe1 … probe2 …` logs fire on
`AccrualThresholdMock` — the secant runs end-to-end through the planner. Decision
rationale: name matching is NOT machine truth (substrings hit getters like
`claimable`/`withdrawable`, miss attacker-renamed fns), so it must never be in the
production path; the user does bounty work on full forks where standard selectors
already hit.

## Warp-secant live convergence — RESOLVED (2026-06-28)

The warp secant now engages AND converges to the true flip warp on a live run.
Three bugs were fixed in sequence to get there (all machine-truth, no name guessing):

1. **Targeting** — `cmp_argmin` picked the GLOBALLY-closest comparison (always some
   trivial `d=1` check), never the time-dependent threshold (large distance).
   Fix: `CMP_TEMPORAL_DIST` map — comparisons are recorded ONLY when executed after
   a TIMESTAMP/NUMBER opcode (host sets `TS_TOUCHED`), and the warp secant pins via
   `cmp_argmin_temporal` over that map. Machine-truth (observed opcode flow).

2. **Distance direction** — the coverage `abs_diff` is 0 for `x < THRESHOLD`, giving
   NO gradient while accruing up to a `>=` threshold. Fix: `CMP_TEMPORAL_DIST` stores
   the TRUE absolute gap `|v1-v2|`, which shrinks monotonically toward the flip.

3. **Throughput gate strangling it** — the `CmpMetadata.cmp_interesting` start-gate
   keys on global COVERAGE progress (≈always false once coverage saturates), so the
   secant never started. Fix: removed it; cooldown alone bounds throughput.

4. **Probe slope accuracy** — the two probes come from different (uncontrolled)
   executions, so assuming they were at `x1`,`x1+δ` gave a too-steep slope and
   `warp*` undershot (~759 vs true ~5000). Fix: pair each temporal distance with the
   `block.number` it was measured at (`CMP_TEMPORAL_BN`); compute slope from the REAL
   block delta `rate=(d1-d2)/(bn2-bn1)`, `warp* = x2 + d2/rate`.

**Live result** (`AccrualSelfPrimedMock`, reward = elapsed·7, THRESHOLD 35000 →
true flip elapsed 5000): `warp*` values cluster tightly at **4890–5109, centered on
5000** — exact. The secant predicts the precise warp to cross a time-gated accrual
threshold with rate≠1, through the multiplication, live, end-to-end.

Test races fixed along the way: `CMP_*` global-static tests serialized via mutex;
`FUNCTION_SIG` write tests serialized too. `test_cmp_warp_secant_end_to_end` updated
to the block-delta math (passes `--ignored --test-threads=1`).

~~Also deferred: the pre-existing revm-41 panic on low-level value-calls.~~
**FIXED (2026-06-28).** Root cause was the CALLDATA read in `host.rs` `call_internal`:
a low-level `.call("")` arrives as a degenerate `SharedBuffer` range
(`usize::MAX..usize::MAX`); `global_slice_range` sliced it and OOB-panicked revm-41's
SharedMemory. Fix: treat any empty range (`start >= end`) as empty calldata
(`PrimBytes::new()`) instead of slicing; plus a defensive clamp of the return-memory
range to `0..0` on the output side. Verified: a `WithdrawMock` doing
`msg.sender.call{value}("")` now runs clean (was exit 101 panic → now no panic,
54% branch coverage); `test_attacker_contract_callbacks` still passes, so the
intentional attacker-callback injection feature is preserved.

---

## Validation Status (2026-06-28)

**Tier 1 — Rust unit fixtures: PASSING.** `src/evm/mutator.rs` test module, 6 tests,
all green (`cargo test --features cmp,dataflow --bin ityfuzz secant`/`cmp_`):
- `test_secant_step_linear_accrual_exact` — linear accrual recovered exactly in one step
- `test_secant_step_wei_scale_no_truncation` — 1e24-scale distance → exact (proves the u128 fix)
- `test_secant_step_flat_gradient_aborts` — flat / negative gradient → None (self-diagnosis)
- `test_evmu256_to_u128_sat` — width preserved, overflow saturates
- `test_cmp_ownership_validation_and_reset` — owner mismatch → None (aliasing abort), reset clears both arrays
- `test_cmp_owner_fp_nonzero_and_pc_sensitive` — fingerprint never 0, PC-discriminating
The secant arithmetic was extracted to a pure `secant_step()` helper (shared by C/E/B)
so the core method is tested in isolation.

**Tier 2 — Solidity mocks: RUN, partial result (2026-06-28).** `tests/bench/`
(compiled with solc 0.8.26, run offchain `-t build/* -d all -f --campaign-orchestrator
--temporal-skimming`):
- `AccrualThresholdMock.sol` — linear accrual gated by `require(reward >= THRESHOLD)`,
  post-require sets `jackpotHit` (coverage signal; no value transfer — see panic note).
- `SaturatedAccrualMock.sol` — capped accrual, unreachable threshold (flat-gradient case).

Observed:
- **Application A confirmed LIVE** — `Voted for N because of CMP (weight=30)` in run logs;
  proportional voting fires with weights.
- **~1.8k exec/sec** (debug build; release ≈26k). Runs clean (exit 124 timeout) after the
  low-level `.call{value}` was removed from the mocks.
- **Secant does NOT engage end-to-end on these fixtures — root cause traced two layers
  above it (Feature 003 planner).** Instrumented `apply_cmp_warp` (start/probe1/probe2 +
  call-site + gate, now `debug!`); none fired. The campaign block never produces a campaign:
  `plan_campaign` (`src/evm/planner/campaign_planner.rs`) calls `pick_prime_and_exploit`,
  and if it can't identify a prime+exploit pair the result has `steps.len() < 2 → return
  None`. For `AccrualThresholdMock` (deposit + claimJackpot, no topology_report) the pair
  isn't recognized → None → no campaign → no warp → `apply_cmp_warp` never called. The
  wiring is CORRECT: when a campaign IS produced, the planner hardcodes `warps.push((exploit_idx, 10))`
  — precisely the warp the secant is meant to refine. The gap is the planner's
  target-recognition (Feature 003 / topology), NOT the secant. Self-funding the mock
  (`deposit(uint256)` via calldata) raised branch coverage 36%→52.6% but did not change this.
- **To validate the secant end-to-end**, either (a) make `pick_prime_and_exploit` recognize
  the fixture (needs a topology_report or matching ABI heuristics — Feature 003 work), or
  (b) a Rust integration test driving the full state machine with seeded CMP_MAP.

**Tier 1.5 — full state-machine test: DONE, PASSING (2026-06-28).** Chose (b). Extracted
the secant body into a free `cmp_warp_secant(campaign, ts, num, state)` (so it needs no
`FuzzMutator`), and added `test_cmp_warp_secant_end_to_end` driving all three phases over a
simulated linear accrual `distance(w)=600−w`:
- Idle pins via `cmp_argmin`; Probe1 reads D1 (ownership-validated) and advances x1→x1+δ;
  Probe2 reads D2 and converges. Final `campaign.warps[0].1 == 600` = the true flip warp,
  recovered THROUGH the accrual (df/d(warp) measured, not assumed 1).
- Second scenario: a colliding owner takes the pinned slot before Probe2 → `cmp_read_at`
  returns None → secant aborts (warp stays at x2), proving aliasing is NOT blended.
This validates pinning, ownership-validated reads, per-execution reset, the throughput gate,
phase transitions, and warp mutation — the whole machine, not just the arithmetic.
Marked `#[ignore]` (run `--ignored --test-threads=1`): it uses `cmp_argmin` which scans the
whole global CMP_MAP, and the parallel suite writes CMP_MAP via EVM execution in other tests,
so it must run isolated. Passes reliably isolated. The 5 always-on Tier-1 tests remain
parallel-safe (pure `secant_step` / single-slot ownership).

**Regression note (answers "was the panic introduced recently"):** YES. Commit `7ff5b32`
(2026-06-25) replaced the `[0xfd,0x00]` REVERT stub on caller addresses with executable
Attacker.sol bytecode (intentional — unprotected-callback handling, per README). Before it,
`msg.sender.call(...)` hit an inert REVERT (no OOB); after, it executes the injected bytecode
whose return path underflows revm-41's shared-memory window to MAX..MAX. Fix preserves the
feature: clamp the empty return-memory window to `0..0` in the call-return path. Tracked
separately from Feature 008.

**Pre-existing panic (NOT this feature):** the original mocks' `msg.sender.call{value: bal}("")`
triggers `revm-interpreter-41 shared_memory.rs:231 — slice OOB MAX..MAX; len 96`. Reproduced
with the secant fully DISABLED (no campaign/temporal flags), so it is a revm-41/ityfuzz
interaction on low-level value-calls, unrelated to Feature 008. Removing the call removes
the panic.

**Tier 3 — Benchmark (8.4 per-target regression + criterion 6 throughput): NOT RUN.**
Requires the harness + wall-clock run. Remains the only open empirical gap.

Note: the crate's `evm::onchain::endpoints` / `evm::tokens::uniswap` tests fail in any
no-network environment (they fetch live mainnet state) — unrelated to this feature.

---

## Overview

`CMP_MAP` is a per-comparison **distance-to-flip gradient**. For every comparison
opcode executed (`LT/SLT/GT/SGT/EQ`), the host records the minimum absolute
difference seen between the two operands. Small distance = the comparison was
close to flipping = a guard, threshold, or check was nearly satisfied.

This is one of the richest signals in the fuzzer. Today it is collapsed to a
boolean and consumed in exactly one place.

This feature wires the **magnitude** of that gradient into the decision points
that currently make blind or random choices, so the fuzzer **aims** — toward the
check that is closest to breaking — instead of exploring uniformly.

This is the runtime counterpart to Feature 007. Feature 007 supplies the
**prior** (what sequences historically work, per category). CMP_MAP supplies the
**runtime likelihood** (which check, right now, in this specific state, is one
step from flipping). Together they are the prediction engine described in
`.speckit/research/sequence-alignment-mutation-prediction.md` and the detection
architecture in `.speckit/research/machine-primitive-truth.md` (Section 4a).

---

## Verified Current State (source-confirmed, do not re-derive)

`CMP_MAP` is **written** in:
- `src/evm/host.rs:481` — JUMPI (`0x57`) handler: `CMP_MAP[pc % MAP_SIZE] = br` (raw branch condition value)
- `src/evm/host.rs:541, 557, 573` — LT/SLT (`0x10/0x12`), GT/SGT (`0x11/0x13`), and EQ comparison handlers: `if abs_diff < CMP_MAP[idx] { CMP_MAP[idx] = abs_diff }` (minimum distance)

`CMP_MAP` is **read** in exactly one consumer:
- `src/feedback.rs:536` — `CmpFeedback::is_interesting`. Logic:
  ```rust
  if self.current_map[i] < self.min_map[i] {   // new global minimum distance
      self.min_map[i] = self.current_map[i];
      cmp_interesting = true;
  }
  if cmp_interesting {
      self.scheduler.vote(infant_state, idx, INFANT_STATE_INITIAL_VOTES);  // FIXED weight
  }
  ```

**Confirmed gaps:**
- The vote is **binary** with a **fixed weight** (`INFANT_STATE_INITIAL_VOTES`).
  A comparison 1 unit from flipping votes identically to one 10^18 units away,
  as long as it is a new minimum. The magnitude of the gradient is discarded.
- `src/evm/mutator.rs` does **not** import or read `CMP_MAP`. All mutation
  decisions (ABI args, NestedAction targets, caller/identity, env, txn_value,
  liquidation_percent) are made blind to the gradient.
- The campaign planner and Engagement Seeder do not consume it.
- Its only effect today is on **infant-state (snapshot) scheduling votes.**

**Capture limitation (critical for Application B):**
The LT/GT/SLT/SGT handlers store only `abs_diff` (the gap), **not the target
operand value**. True input-to-state replacement (redqueen-style) needs the
actual compared value, not just the distance. This is an investigation
checkpoint, not a settled wire (see Checkpoint 8.2).

---

## Why This Matters

CMP_MAP already tells the fuzzer *which check is closest to breaking*. Every
selection the fuzzer makes — what byte to mutate, which function to inject mid-
flight, which identity to spoof, how far to warp time, which campaign step to add
— is currently made without consulting that signal. The fuzzer knows it is one
unit from flipping a timelock and then warps a random amount. It knows a guard is
nearly satisfied and then mutates a random argument.

The thesis: connecting the gradient magnitude to these decisions converts uniform
exploration into directed search, with the largest gains in the temporal domain
(where distance maps directly to a warp amount) and in campaign step selection
(where it joins the Feature 007 prior to rank the next move).

---

## Core Method — Snapshot-Secant Gradient Descent (read before Applications B, C, D, E)

**The units problem.** `CMP_MAP` distance is measured at the *output* of a
comparison, in the units of the compared values. The action we control (warp
amount, roll amount, txn_value, a calldata scalar) is at the *input*. Between them
sits the contract's arithmetic — a transfer function `f`. Example:

```
distance = threshold − f(timestamp),   where  f(t) = (t − lastUpdate) * rate
```

`abs_diff` is the gap in `f`-space. To act we need the gap in input-space, which
is `abs_diff` divided by the **local derivative** `df/dinput`. For a bare timelock
`f(t) = t`, so `df/dt = 1` and `warp_delta = abs_diff` — that is the only reason
the simple case looked clean. The derivative was hiding as 1. For accrual,
`df/dt = rate`, and using `abs_diff` directly warps by a factor of `rate` wrong.

**Do NOT recover the derivative symbolically.** Taint-tracking `TIMESTAMP` through
the arithmetic and inverting it is exactly the symbolic machinery ItyFuzz avoided.
It kills throughput. Rejected as primary.

**Measure the derivative with snapshots instead (the method):**

```
1. Execute at input X0.            read abs_diff_0 at the target comparison PC
2. Snapshot. Bump input by probe δ. re-execute.  read abs_diff_1
3. slope = (abs_diff_0 − abs_diff_1) / δ          // this IS df/dinput, measured
4. step  = abs_diff_0 / slope                      // input change to flip
5. apply X0 + step   (sign from the comparison opcode: LT vs GT tells direction)
```

This is the **secant method**. Critical property: **reward accrual is linear in
time**, so for the dominant temporal class two points give the EXACT answer in one
step — not an approximation. Newton/secant converges in one step for linear `f`.
Non-linear `f` (compound interest, cliff-then-linear vesting) needs 2–3
iterations; still cheap because each re-execution is a snapshot jump + one env
change, not a fork re-init.

**This sidesteps Checkpoint 8.2 for the arithmetic class.** The secant needs only
the distance (already in CMP_MAP) and the measured slope. It never needs the
target operand value. So input-to-state aiming for arithmetic-threshold
comparisons (timelocks, accrual, ratios, value gates) requires NO operand capture.
8.2 shrinks to the magic-value/hash class only, where the gradient is meaningless:

| Comparison class | Method | Needs 8.2 operand capture? |
|---|---|---|
| Arithmetic threshold (timelock, accrual, ratio, value) | snapshot-secant | **No** |
| Magic value / hash / opaque equality | operand capture | Yes |

**Self-diagnosing saturation (free robustness).** If probing yields `slope ≈ 0`
(bumping the input did not move the distance), the input is **not the lever** for
this check — e.g. `min(elapsed, maxPeriod) * rate` past the cap. Detect flat
gradient, do not divide by zero, do not warp/mutate randomly, move on. This is
strictly better than today's blind-random behavior: the method tells you when to
give up on a lever.

**Generalization.** With snapshots the gradient-blind fuzzer becomes a
gradient-descent optimizer over ANY scalar input it controls — timestamp (C),
block.number (roll), txn_value/msg.value (E), a scalar calldata arg (B) — at a
cost of one extra snapshot-execution per aimed comparison. CMP_MAP is the loss;
snapshots make re-evaluation cheap; the secant recovers the step.

**Required gating (keeps probing rare).** Probe only when BOTH: (a) the comparison
is already near-flip in CMP_MAP, AND (b) `AccessPattern` flags the relevant input
as read *directly this execution* (`timestamp`/`number`/`call_value` — all already
tracked in `src/evm/mutator.rs:60`). Both flags exist today. Without gating,
probing doubles execution count.

**Method failure modes (must handle):**
- **Integer truncation.** EVM math is integer; tiny `rate` means `δ=1` may move
  `abs_diff` by 0, faking a flat gradient. Use an **adaptive probe**: start small,
  double `δ` until distance moves measurably or a ceiling is hit (then conclude
  flat). Bracketing step precedes the secant.
- **Indirect-through-storage.** If time was written to a slot in a prior step and
  this comparison reads the slot, warping now changes nothing — `AccessPattern`
  will report timestamp NOT read this run, so gating (b) correctly skips it. That
  case belongs to Application G (warp at the step that ingests time).
- **Index aliasing.** The secant needs the *specific* PC's distance. If two
  comparisons collide on `pc % MAP_SIZE` the slope is a blend = garbage. **This
  makes Checkpoint 8.3 a hard prerequisite for B and C, not optional.**

---

## Scope — Ranked Applications

Each application is independent and separately benchmarkable. Implement in this
order; ship and measure each before the next.

### Application A — Proportional infant-state vote weight (cheapest, do first)
**Wire:** `src/feedback.rs` `CmpFeedback::is_interesting`.
Replace the fixed `INFANT_STATE_INITIAL_VOTES` with a weight that scales inversely
with the new minimum distance (closer to flip → more votes). The number is already
computed; only its magnitude is currently discarded.
**Risk:** Low. Same place CMP_MAP already lives. No new data capture.
**Constitution check:** opt-in via existing `cmp` feature flag; no new system.

### Application B — ABI argument input-to-state aiming (highest value)
**Wire:** `src/evm/mutator.rs` argument mutation path (`mutate_with_vm_slots`).
When a comparison is near-flip and its operand traces to a scalar calldata
argument, drive that argument toward the flipping value. This is Harvey-style
input prediction at the value level.
**Two routes, by comparison class (see Core Method):**
- *Arithmetic-threshold operand* (the common case) → **snapshot-secant**. Probe the
  argument, measure slope, extrapolate. **NOT blocked on 8.2** — no operand capture
  needed.
- *Magic-value / hash / opaque equality operand* → gradient is noise; needs operand
  capture. **This sub-case only is BLOCKED ON Checkpoint 8.2.**
**Hard prerequisite:** Checkpoint 8.3 (index aliasing) — the secant needs the
specific comparison PC's distance, not a blended one.
**Risk:** Medium. Touches the hot mutation path. Secant route adds 1 probe
execution per aimed arg (gated).

### Application C — Temporal warp amount via snapshot-secant (recommended first NEW wire)
**Wire:** temporal warp selection (Feature 005 `temporal_warps` / warp mutation).
Gate on `AccessPattern.timestamp` / `AccessPattern.number` (already tracked in
`src/evm/mutator.rs:60`) being set THIS execution. Then apply the **Core Method**
snapshot-secant to recover the warp delta:
- Bare timelock `timestamp >= unlock` → `df/dt = 1` → one probe confirms, warp =
  abs_diff.
- Accrual `(timestamp − lastUpdate) * rate >= threshold` → `df/dt = rate` →
  secant recovers it in ONE step (accrual is linear). Warp = abs_diff / slope.
- Saturated `min(elapsed, cap) * rate` past cap → slope ≈ 0 → self-diagnose, skip.
Do **not** use `abs_diff` directly as the warp amount — that is correct only for
the bare-timelock special case and wrong by a factor of `rate` for accrual (this
was the original naive framing; superseded by the Core Method).
**Hard prerequisite:** Checkpoint 8.3 (index aliasing); Checkpoint 8.5 reframed
(see below).
**Risk:** Low–Medium. Self-contained to the temporal domain. Highest payoff of the
new wires: this is what makes C work on the staking/accrual exploits that are the
entire point of temporal skimming, not just trivial timelocks.

### Application D — Ghost Identity / caller selection
**Wire:** `src/evm/mutator.rs` prank/caller selection (Feature 004 path, ~line 382).
If the near-flip comparison is CALLER-based (`msg.sender == X`), pick the
`TrustedCallerMetadata` / `WhaleAddressMetadata` entry that satisfies it instead of
uniform random. CALLER equality is a magic-value class comparison (address is
opaque, no smooth gradient) → the secant does NOT apply here.
**Depends on:** Checkpoint 8.2 operand capture (this is a genuine 8.2 case).
**Risk:** Medium.

### Application E — txn_value / liquidation_percent aiming
**Wire:** EVMInput env/value mutation.
Value-gated checks (`msg.value >= price`, `collateral < debt * ratio`) are
arithmetic-threshold → use **snapshot-secant** on txn_value/liquidation_percent.
**NOT blocked on 8.2** for these arithmetic gates. Today these fields mutate within
blind byte ranges.
**Hard prerequisite:** Checkpoint 8.3.
**Risk:** Medium.

### Application F — NestedAction (mid-flight injection) targeting
**Wire:** `src/evm/mutator.rs` NestedAction generation (~line 374-468).
Point the injected re-entrant/nested call at the function whose guard comparison
is nearest flip, instead of selecting from oracle-flagged or random ABI targets.
**Risk:** Medium.

### Application G — Campaign step / topology selection (deepest; Feature 007 join)
**Wire:** campaign planner step selection (Feature 003) + `src/evm/planner/`.
Join three maps: a near-flip comparison (`CMP_MAP`) that reads a storage slot
(`READ_MAP`) → prioritize adding the campaign step whose function **writes** that
slot (`WRITE_MAP`). This is "what state change would flip the check that is almost
flipping." This is the runtime likelihood half of Feature 008's prediction engine;
the Feature 007 conservation map is the prior.
**Depends on:** Feature 007 conservation map (prior) for full effect; can ship the
CMP×READ×WRITE join independently as a heuristic first.
**Risk:** High. Architectural — touches the planner.

### Application H — Engagement Seeder linkage priority
**Wire:** Feature 002 Engagement Seeder.
When choosing which step-output→step-input data-flow link to seed, prioritize the
link whose target operand feeds the near-flip comparison.
**Risk:** Medium.

---

## Investigation Checkpoints

**8.1 — Confirm the single-consumer finding holds at build time.**
Grep-verify that no other module reads `CMP_MAP` beyond `CmpFeedback`. The spec
asserts this from source read on 2026-06-28; confirm no drift before wiring.

**8.2 — Operand value capture question (RE-SCOPED — now blocks only the
magic-value class: Application D, and the magic-value sub-case of B).**
The Core Method (snapshot-secant) removes the 8.2 dependency for ALL
arithmetic-threshold comparisons — C, E, and the arithmetic sub-case of B no
longer need operand capture, because sensitivity is measured by probing rather
than read from a stored value. 8.2 remains only for magic-value / hash / opaque
equality checks (e.g. CALLER equality in D) where the gradient is meaningless.
For that remaining class determine:
(a) Can we capture the target operand value cheaply at host.rs:541-574 without
    measurable throughput loss on the 26k exec/sec path?
(b) Or is the JUMPI `br` snapshot at host.rs:481 already sufficient for the
    branch conditions that matter?
(c) What is the memory cost of a parallel `CMP_TARGET_MAP[MAP_SIZE]` of EVMU256?
Resolve before D and before the magic-value sub-case of B. Do NOT slow the hot path.

**8.3 — Index aliasing under `pc % MAP_SIZE` — RESOLVED (2026-06-28).**
Closed in code rather than by measuring collision rate. Added a parallel
`CMP_PC: [u64; MAP_SIZE]` ownership array in host.rs that records a
(contract, pc) fingerprint (`cmp_owner_fp`) for the site holding each slot's
current minimum, written at all four CMP_MAP write sites (3 comparison handlers +
JUMPI). The secant pins `(pin_idx, pin_pc)` and `cmp_read_at` returns `None` if
`CMP_PC[idx] != pin_pc` — i.e. a colliding comparison or a JUMPI write took the
slot. The episode then aborts instead of computing a blended slope. Cost: one
`u64` store inside the already-conditional min-update branch; negligible on the
hot loop. Residual: distinct (contract, pc) pairs whose fingerprints collide
(64-bit, vanishingly rare) would not be detected — acceptable.

**8.4 — Does proportional voting (A) destabilize the infant-state scheduler?**
Heavy votes on near-flip states could starve coverage-driven exploration.
Benchmark A in isolation: does it improve time-to-exploit or cause premature
convergence on a single near-flip check? Report PER-TARGET, not just aggregate —
an average improvement can hide per-target regressions.
STILL OPEN — empirical, requires benchmark run.

**8.6 — Probe throughput gate — RESOLVED (2026-06-28).**
The scale-broken `NEAR_FLIP` magnitude gate was removed (1M means "huge" in
seconds, "dust" in wei — unfixable as a single constant). Replaced with two
scale-free gates in all three secant functions: (1) start an episode only when
`CmpMetadata.cmp_interesting` (the last run set a new global cmp minimum — i.e.
there is genuine fresh near-flip progress to chase); (2) a `cooldown: u32` (=8)
on each secant state, set on every episode completion/abort, decremented while
Idle, blocking a new episode until elapsed. Together these bound probe overhead
to ≤3 executions per (cooldown + 3) mutate calls and tie probing to actual cmp
progress. Net throughput still needs a benchmark (success criterion 6), but the
unbounded-probing risk from removing NEAR_FLIP is closed.

**8.5 — Secant validity for temporal comparisons (Application C) — REFRAMED.**
The original concern ("is abs_diff already in warp units") is resolved by the Core
Method: it is NOT, except for bare timelocks, and the secant recovers the correct
units by measurement. The real checkpoints are now:
(a) **Integer-truncation probe sizing** — confirm the adaptive-δ bracketing
    reliably escapes the `slope=0` false-flat caused by integer math with small
    `rate`. Validate on an accrual exploit with a low per-second rate.
(b) **Linearity assumption** — confirm accrual targets are linear in time (one-step
    secant exact) and identify how many real temporal exploits are non-linear
    (need 2–3 iterations). Use the temporal exploits in the dataset.
(c) **Saturation self-diagnosis** — confirm `slope≈0` correctly identifies capped
    accrual and the wire skips rather than warping uselessly.
(d) **Direction sign** — confirm the LT/GT opcode correctly yields warp-forward vs
    the (rare) warp-backward intent.
Validate (a)–(d) on both a bare timelock and a staking/accrual exploit.

---

## Success Criteria

This feature is worth building if and only if:

1. Application A (proportional voting) shows measurable time-to-exploit improvement
   on the benchmark set without premature convergence (Checkpoint 8.4).
2. Application C (snapshot-secant warp) finds at least one **accrual-class**
   temporal exploit — not just a bare timelock — that the gradient-blind baseline
   misses or finds materially faster. The accrual case is the proof the secant
   earns its keep; a bare timelock would pass even with the naive abs_diff and
   does not validate the method.
3. The snapshot-secant adds ≤ one probe execution per aimed comparison and the
   adaptive-δ bracketing reliably escapes integer-truncation false-flats (8.5a).
4. The operand-capture question (8.2) is resolved with a decision recorded for the
   magic-value class only — "captured, cost X%" or "JUMPI snapshot sufficient" or
   "not worth it, D descoped." (Arithmetic class no longer depends on it.)
5. Application G's CMP×READ×WRITE join is demonstrated to rank a correct next
   campaign step on at least one multi-step exploit, validating the runtime-
   likelihood concept that Feature 007's prior will plug into.
6. No measurable regression in baseline exec/sec throughput from any shipped
   application (the gradient is already computed; consumption must stay cheap).

---

## Non-Goals

- Not replacing coverage-driven exploration. CMP_MAP aiming is additive bias, not
  a new search strategy. Coverage feedback remains primary.
- Not forking revm or changing the opcode instrumentation semantics. We consume
  the existing gradient; we do not change how comparisons are measured (except the
  additive operand-capture in 8.2 if approved).
- Not implementing the Feature 007 conservation map here. Application G consumes
  that prior when it exists; it ships independently as a heuristic until then.

---

## Relationship to Other Features / Research

- **Feature 007 (Call Sequence Topology)** — supplies the prior; Application G is
  the runtime-likelihood half that joins it. Posterior = prior (007) × likelihood
  (CMP_MAP). See `research/sequence-alignment-mutation-prediction.md` §6.
- **Feature 005 (Temporal Skimming)** — Application C feeds warp amounts into the
  `temporal_warps` machinery.
- **Feature 004 (Ghost Identities)** — Application D aims caller/identity selection.
- **Feature 003 (Campaign Orchestrator)** — Application G extends planner step
  selection.
- **Feature 002 (Engagement Seeder)** — Application H prioritizes linkage seeds.
- **Detection architecture** — `research/machine-primitive-truth.md` §4a: CMP_MAP
  is a Layer 1 coverage/guidance map. This feature keeps it Layer 1 (guidance) —
  it steers search, it does not become a bug detector.

---

## Handoff Notes for Execution Agent

- Read `research/machine-primitive-truth.md` §4a and §1-2 first for the layer model.
- Read `research/sequence-alignment-mutation-prediction.md` §6 for the prior×likelihood framing behind Application G.
- Start with Application A — it is the lowest-risk, lives where CMP_MAP already is,
  and validates the proportional-weight thesis before any mutator surgery.
- Do NOT begin Applications B/D/E until Checkpoint 8.2 is resolved and recorded.
- Application C is the recommended first *new* wire (clean mapping, self-contained).
- Preserve throughput. The gradient is free to read; keep consumption O(1) per decision.
- Everything opt-in behind feature flags. No parallel systems. Do not fork revm.
