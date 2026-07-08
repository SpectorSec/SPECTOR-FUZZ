# Feature 026 — Economic Energy → Scheduler

**Status:** Specified (not built)
**Owner:** TBD
**Last updated:** 2026-07-08
**Held:** LOCAL
**Origin:** the "scheduler side" of the V5 `dim_flow` proposal (SYSTEM_DESIGN.dot line 240) + the reflexive-loop-scheduler-gap (memory `reflexive-loop-scheduler-gap`). These are the **same species of edge** — "economic signal → scheduler energy" — and this feature unifies them into one `compute()` change.

## Overview
The scheduler scores a corpus testcase purely by coverage + topology shape. `CorpusPowerABITestcaseScore::compute` (scheduler.rs:393):

```rust
let mut power = uncov_branch as f64 * POWER_MULTIPLIER;   // coverage
// ... decaying topology gamma-ray boost (shape) ...
power *= effective_boost;
```

There is **no economic term.** Two proposed edges both want to add one:
1. **Promote → Scheduler** (value-forward, `reflexive-loop-scheduler-gap`): the reflexive lever closes through the *mutator* only; the scheduler never learns that a `PromotionCandidate` exists, so a promoted step is drilled only when the scheduler *coincidentally* serves a matching input — the "3× front-loaded search cost."
2. **`dim_flow` → Scheduler** (dot line 240): the flow-flags (`PRICE_MANIPULATION_FLOW`→high, `ACCUMULATOR_INFLATION_FLOW`→med) feed `located_dim→probe_delta` but **do not boost scheduler vote weight.**

Both say: *let an economic signal add power to the inputs that carry it,* mirroring the existing topology boost (including its decay so it never traps the search).

## Why This is one feature, in two phases
The two edges differ in **signal locality**, and that difference dictates the build order:

- **Promote → Scheduler is per-testcase-clean.** The `PromotionCandidate` is a `(contract, selector)` singleton in state; a testcase's own selector either matches it or not. `compute()` can read it directly and boost — mirror of the topology `hints.lookup(selector)` block. **This is Phase A: low-risk, self-contained.**
- **`dim_flow` → Scheduler is timing-fraught.** The flow-flags are `static mut` globals (`PROXY_TAINT_FLOW`, `PRICE_MANIPULATION_FLOW`, …) reflecting the *last execution*, not the testcase being scored. Reading them in `compute()` mis-attributes the dimension. So the dimension must first be **stamped onto the testcase** (a per-testcase dim tag, set when the testcase is created from an execution that raised the flag), then read in `compute()`. **This is Phase B: needs a per-testcase dim metadata field first.**

Phase A alone closes the reflexive gap and gives 025's setter-lever its budget. Phase B generalizes it to all dimension skews.

## Weapons this builds on (`spector-weapons.md`)
PowerABIScheduler / `CorpusPowerABITestcaseScore::compute` (the topology gamma-ray boost is the exact template, incl. `PowerABITestcaseMetadata.topology_hits` decay) · 015 PromotionCandidate (Phase A signal) · 016/017 flow-flags + TaintDim (Phase B signal) · 025 Parameter-Bound skew (the lever this energy funds).

## Why This Matters
025 (and every skew) is an **amplify** lever — it decides *what* magnitude to tune. But a lever only fires when the scheduler serves an input that reaches it. Without an economic term, the scheduler picks by coverage/shape and the levers starve — this is the measured "3× front-loaded cost." 026 is the **multiplier that lifts every skew at once** by routing mutation budget to the economically-live inputs. It is the convergence point all skews flow into (the reason the other skew types weren't each a standalone build).

## Success Criteria
### Phase A — Promote → Scheduler
1. `compute()` reads the current `PromotionCandidate`; a testcase whose selector (and contract) matches receives an **economic boost** to `power`, mirroring the topology boost.
2. The boost **decays** with scheduling hits (reuse the `0.95^hits` pattern / a sibling counter) so a promoted step gets early pressure without permanently trapping the search.
3. **Regression:** with no candidate set (`!cand.set`), power is **byte-identical** to today.

### Phase B — `dim_flow` → Scheduler
4. A per-testcase **dimension tag** is stamped when a testcase is created from an execution that raised a flow-flag (NOT read from the `static mut` global at score time).
5. `compute()` boosts by dimension: `PRICE_MANIPULATION`→high, `ACCUMULATOR`→med, else→neutral (dot line 241 weights).
6. **Regression:** untagged testcases (no dimension) score byte-identical to today.

## Out of Scope
- The amplify-side levers themselves (025 and the other skew variants) — 026 only allocates *energy*, it does not tune magnitudes.
- Changing `next()` (scheduler.rs:305) round-robin corpus walk — power is applied by the mutational stage via `compute()`; that is the only surface 026 touches.
- Non-linear secant, cross-contract provenance — unrelated skew-math features.

## Investigation Checkpoints
### 26.1 — compute() is the only power surface ✓ (traced)
`next()` is round-robin (`corpus().next(id)`, scheduler.rs:305); the power that governs mutation budget is `CorpusPowerABITestcaseScore::compute` (scheduler.rs:393). The economic term belongs there, after the topology block.

### 26.2 — PromotionCandidate readable in compute() ⧗ (confirm in plan)
`compute(state, entry, idx)` has `state.metadata_map()` (already used for `UncoveredBranchesMetadata`, `TopologyHints`) and `entry.input().get_data_abi().function`. **Q:** confirm `PromotionCandidate` is reachable via `state.metadata_map().get::<PromotionCandidate>()` here and the selector/contract compare is available (mirror the `hints.lookup(selector)` path).

### 26.3 — decay counter ⧗ (confirm in plan)
`PowerABITestcaseMetadata.topology_hits` drives the topology decay. **Q:** reuse it, or add a sibling `promote_hits` so the two boosts decay independently? (Recommend sibling — a topology-matched step and a promoted step are different pressures.)

### 26.4 — per-testcase dim tag (Phase B) ⧗ (design)
The flow-flags are `static mut` (per-exec). **Q:** where is a testcase minted from an execution (the feedback `is_interesting`/`append_metadata` path) so the raised flag can be copied onto a new `PowerABITestcaseMetadata.located_dim` field? This is the Phase B keystone; Phase A does not need it.

### 26.5 — interaction with 025 ✓ (design)
025 promotes a Permission-with-uint-arg step (sets the candidate + `campaign.promoted`); 026 Phase A boosts the scheduler energy for inputs hitting that same `(contract, selector)`. Together: the setter lever gets *both* the secant (025, what) and the budget (026, how much) — the two-move plan closing on the same candidate.

## Validation
Phase A: measure iterations-to-first-promoted-step-drill before/after — the "3× front-loaded cost" should compress (promoted step drilled sooner, not coincidentally). Phase B: on a price-manipulation target, PRICE-tagged inputs receive more budget → faster convergence to the price skew. Full lib suite green + no-signal path byte-identical at each phase.
