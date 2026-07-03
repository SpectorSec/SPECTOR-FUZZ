# Feature 017 — Coupled Signal Buses (Dimension → Warp Lever)

**Status:** Specified
**Owner:** TBD
**Last updated:** 2026-07-03
**Held:** LOCAL (builds on 016 TaintDim engine; inherits the taint-stack no-push policy)

---

## Overview

SPECTOR-FUZZ computes rich per-value metadata — economic **dimension** (016), **provenance**
(013), and caller **identity** (004) — but three of these signals are computed and then *never
routed to the decision that would consume them*. This feature closes the highest-value routing
gap: the **dimension bus does not reach the warp lever**.

Concretely, the `TaintDim` engine tags timestamp-derived values `Timestamp` and publishes a
located dimension to the mutator's secant (`read_located_dim()` → `probe_delta`). But the **warp
lever** — the mechanism that advances blocks between a prime step and an exploit step to let
off-screen accrual happen — is engaged purely by the `--temporal-skimming` flag and structural
position (last step), with a **fixed** base warp of 10 blocks. The `Timestamp` dimension the
engine already discovered has zero influence on whether or how far to warp.

This surfaced during the outside-in "chalkboard" exercise (see `project_system_design_capstone`
in memory / `SYSTEM_DESIGN.dot`): an external abstraction repeatedly drew a `dimension → warp`
edge that the code does not have. The abstraction assumed the clean, fully-coupled design; the
as-built ships the decoupled version.

**Weapons this builds on** (`spector-weapons.md`): TaintDim dimension tagging (016), Temporal
Pre-condition Skimming warp lever (005), Ledger Secant LOCATE/AMPLIFY (015).
This is an **extension** wiring two existing weapons together, not a new primitive.

## Why This Matters

Compound exploits that manipulate **a price AND rely on time progression** are the miss:

1. **yDAI / ERC4626 reflexive accrual** — `pricePerShare` (Price dim) inflates *and* the exploit
   needs a block advance for `earn()`/interest to compound. The `.max()` merge publishes `Price`
   (rank 4 > `Timestamp` rank 1), so the Timestamp signal is dropped before the planner ever
   decides to warp; warp then fires only if `--temporal-skimming` was set by hand.
2. **Reward-accrual drains (e.g., Yearn-style / staking)** — value accrues per-block; the located
   lever is an `Accumulator`-dim slot, but the probe delta for `Accumulator` falls through to the
   coarse generic bucket (`_ => x1/64`), under-resolving the tiny per-step drift.
3. **Oracle-staleness + timelock combos** — a `Timestamp`-dim comparison gates the exploit, but
   the warp magnitude is a fixed 10 blocks regardless of the discovered time-sensitivity.

In each case the engine *found the right dimension* and then failed to act on it.

## Success Criteria

This feature is worth building if and only if:

1. A campaign whose located lever carries a `Timestamp` dimension engages the warp lever **even
   without** the explicit `--temporal-skimming` flag (dimension-driven, not flag-only).
2. A compound value carrying **both** `Price` and `Timestamp` provenance preserves the `Timestamp`
   signal through the merge (the scalar `.max()` collapse no longer silently drops it).
3. Zero behavioral change when the new coupling flag is off — existing runs reproduce byte-for-byte
   (Constitution rule 2).
4. Measurable: on a reward-accrual regression contract, dimension-driven warp finds the divergence
   in ≥1 fewer manual-tuning iteration than flag-only warp (benchmark documented at Complete).

## Out of Scope

- **Caller-identity → provenance coupling.** Graded during the exercise as *correct within the
  calldata-mutation threat model*: `CALLER`/`ORIGIN`/`CALLVALUE` are intentionally `clean!()`
  (`cmp_linearity.rs:745`) because a write governed by `msg.sender` identity is not a
  fuzzer-mutable calldata lever. Not a defect; deliberately excluded.
- **Full bitset re-representation of `TaintDim`.** A complete set-valued dimension is a larger
  refactor; this feature takes the *minimal* signal-preserving change (a Timestamp-present bit
  riding alongside the scalar), not a rewrite of the lattice. See Risks.
- **New oracle.** This wires existing detectors; it adds no detection surface.

## Investigation Checkpoints

### Checkpoint 17.1 — Dimension bus terminus  ✓ RESOLVED
**Files:** `src/evm/mutator.rs`, `src/evm/planner/campaign_planner.rs`
**Question:** Does the located dimension reach the warp decision anywhere?
**Evidence:** `located_dim` is consumed *only* at `mutator.rs:727` (`probe_delta` scaling). The
planner's warp push is `campaign_planner.rs:304` `if temporal_skimming { warps.push((exploit_idx,
10)) }` — gated on the flag alone, fixed magnitude 10, no dimension read. **Confirmed decoupled.**

### Checkpoint 17.2 — Scalar collapse drops Timestamp  ✓ RESOLVED
**Files:** `src/evm/middlewares/cmp_linearity.rs`, `src/evm/feedbacks.rs`
**Question:** When a value is both Price- and Timestamp-derived, what dimension publishes?
**Evidence:** `TaintDim` merges via `.max()` (most-specific-wins) with `Price(4) > Timestamp(1)`;
`publish_located_dim()` emits a single scalar. A Price+Time value publishes `Price`; Timestamp is
lost before the mutator or planner sees it. **Confirmed lossy for compounds.**

### Checkpoint 17.3 — Warp engagement + refinement points  ✓ RESOLVED
**Files:** `src/evm/planner/campaign_planner.rs`, `src/executor.rs`
**Question:** Where is the base warp set, and where is it refined? Where does a dimension gate attach?
**Evidence:** Base warp set at `campaign_planner.rs:310` (fixed 10, gated on `temporal_skimming`).
Refined at `executor.rs:207-260` (controlled-probe secant, `temporal_argmin`/`temporal_read`),
but **only if `warp_delta > 0`** (`executor.rs:213`). So the refinement is dead unless the planner
seeded a base. **Wiring point = the planner's base-warp gate** (open it to the Timestamp
dimension); refinement then follows for free.

### Checkpoint 17.4 — Accumulator probe granularity  ✓ RESOLVED
**Files:** `src/evm/mutator.rs`
**Question:** Does the probe delta honor the `Accumulator` dimension?
**Evidence:** `mutator.rs:727-731` handles `Price => /256`, `Balance => /16`, and **everything
else — including `Accumulator` and `Timestamp` — falls to `_ => /64`.** Accumulator is a first-class
lattice member (rank 3) but has no dedicated probe granularity. **Confirmed under-routed.**

## Risks

- **Merge representation.** Adding a Timestamp-present bit alongside the scalar `dim` touches the
  hottest path in the taint engine (`pushtb!` on every opcode). Must stay a single `u8`/bool field
  in `TB`, `.max()`-free, OR-merged, to avoid regressing throughput. A full bitset is explicitly
  deferred.
- **False warp engagement.** Dimension-driven warp could fire on incidental `Timestamp` taint
  (any `TIMESTAMP` opcode read). Mitigation: gate on the *located* lever's dimension (post-LOCATE,
  the arg the secant actually selected), not on mere presence of Timestamp taint anywhere.
- **Interaction with `--temporal-skimming`.** New coupling must be additive (`flag OR
  dimension`), never suppress the existing flag-driven path (rule 2).

## Open Questions

- Should dimension-driven warp reuse the fixed base=10, or scale the base by the discovered
  time-sensitivity? (Lean: keep base=10 for v1; let the executor secant refine — smaller change,
  refinement already exists.)
- Accumulator probe granularity: `/512` (finer than Price, per the exercise's proposal) or `/256`
  (parity with Price)? Needs one benchmark on a reward-accrual contract to decide. (Plan assumes
  `/256` as the conservative default, revisit at Complete.)
