# Feature 034 — ControlFlow Promotion Producer

## Status
Ready to build. Last remaining producer gap identified in the system inventory
(`.speckit/research/system-inventory-alignment-matrix.md` §2, §7 open items). Mirrors the
031-C/033-A pattern already shipped for Ownership and Invariant — same shape, same review bar.

## The gap (code-verified)

`src/evm/oracles/reentrancy.rs` — `ReentrancyOracle::oracle()` reads
`ctx.post_state.reentrancy_metadata.found: Vec<(EVMAddress, EVMU256)>` (contract, storage slot
touched during the reentrant call), and for each entry only calls
`EVMBugResult::new(...).push_to_output()`. It never constructs a `PromotionCandidate`. This is the
identical "fires, logs, stops" shape that 033 closed for Invariant — `LeakClass::ControlFlow` is
defined in the taxonomy (`leak_class.rs:64`, maps to `OracleType::Reentrancy`) but has zero
producers in the promotion pipeline.

`mutator.rs:1265` already carries the comment `// ControlFlow: no producer yet (oracle-side gap).`
— this feature removes that gap.

## What "ControlFlow" optimizes

Per THESIS.md's objective table: `ControlFlow → maximize unsafe state reach / recursive depth`.
`reentrancy_metadata.found` is a `Vec<(EVMAddress, EVMU256)>` — one entry per distinct
(contract, slot) touched reentrantly in this execution. The count of that vec is a direct,
already-computed proxy for "how much reentrant state was reached" — more distinct reentrant
storage touches = deeper/broader reentrancy. This is the same design already used for Ownership
(`snapshot_delta.rs`: `best_inflow = relocations.len() as u128`) — no new instrumentation needed.

## Routing decision

ControlFlow joins the **structural_pin** (Prime slot) family, not the lever family — per 031's own
kind-production-audit note: *"ControlFlow → matches `Permission | Ownership` in the structural_pin
filter → Prime slot ✓ (or add `| ControlFlow` to the filter — same code path)."*

Rationale: a reentrancy finding identifies a *precondition* (this contract/function must be
re-entered to reach the state), not a magnitude to numerically tune. `secant_promotable` already
falls through to `_ => false` for any kind not explicitly listed (`mutator.rs:324-333`) — ControlFlow
should stay excluded from lever amplification, same as Ownership.

## What changes

### 1. `src/evm/oracles/reentrancy.rs` — emit `PromotionCandidate{kind: ControlFlow}`

After the existing `found.is_empty()` early-return (current oracle body), before/alongside the
`.map(...).collect_vec()` bug-report loop, add (mirroring `snapshot_delta.rs`'s pattern exactly —
read current `PromotionCandidates` or fall back to legacy singleton, then `.record()`):

```rust
use crate::evm::{leak_class::LeakClass, planner::{PromotionCandidate, PromotionCandidates, TaintProvenanceTag}};

// Feature 034: emit ControlFlow PromotionCandidate so the planner can lock the re-entered
// contract into the Prime slot. contract = first reentrant touch's address; selector = the
// current top-level input's selector (same pattern as snapshot_delta.rs/invariant.rs — the
// call that TRIGGERED the reentrant path, not a synthetic "reentered function" we don't have).
let first = &reetrancy_metadata.found[0];
let selector: [u8; 4] = ctx.input.data.as_ref().map(|d| d.function).unwrap_or_default();
let candidate = PromotionCandidate {
    contract: first.0,
    selector,
    best_inflow: reetrancy_metadata.found.len() as u128,
    kind: LeakClass::ControlFlow,
    taint_provenance: TaintProvenanceTag::default(),
    phase: None,
    set: true,
};
let mut candidates = ctx
    .fuzz_state
    .metadata_map()
    .get::<PromotionCandidates>()
    .cloned()
    .or_else(|| {
        ctx.fuzz_state
            .metadata_map()
            .get::<PromotionCandidate>()
            .map(PromotionCandidates::from_singleton)
    })
    .unwrap_or_default();
if candidates.record(candidate.clone()) {
    ctx.fuzz_state.metadata_map_mut().insert(candidates);
    ctx.fuzz_state.metadata_map_mut().insert(candidate);
}
```

Place this BEFORE the existing bug-report loop (matches `invariant.rs`'s ordering: promotion is
unconditional, independent of any future dedup on the report side — there is no dedup gate in
`reentrancy.rs` today, so this is a pure additive insert, same as `echidna.rs`/`state_comp.rs`).

### 2. `src/evm/mutator.rs:1274-1281` — extend `structural_pin` filter

```rust
let structural_pin = candidates
    .and_then(|candidates| {
        candidates.first_set(&[
            crate::evm::leak_class::LeakClass::Ownership,
            crate::evm::leak_class::LeakClass::Permission,
            crate::evm::leak_class::LeakClass::ControlFlow,   // ← NEW
        ])
    })
    .map(|c| (c.contract, c.selector));
```

Ordering choice: place `ControlFlow` **last** in the preference list. Rationale — Ownership
(authority relocation) and Permission (privileged reach) are both governance-adjacent structural
prerequisites already established as the top two; ControlFlow (a reentrancy precondition) is a
different kind of "setup" (a call-tree shape requirement, not an access requirement) and shouldn't
displace either when multiple structural candidates coexist (the `PromotionCandidates` per-kind
map means all three can be live simultaneously — this is just which ONE gets pinned into the
single Prime slot this campaign). Open to reordering if the team disagrees; the important part is
that it's `first_set`, not a silent drop.

Also update the stale comment at `mutator.rs:1265` (`// ControlFlow: no producer yet (oracle-side
gap).`) to reflect the new producer.

### 3. `mutator.rs` tests — mirror the existing pattern

Add `controlflow_binds_to_structural_pin` (or similar) alongside the existing
`promotion_candidates_*` tests in `campaign_planner.rs` and the `secant_promotable_*` test in
`mutator.rs`:
- `secant_promotable(LeakClass::ControlFlow, _)` must stay `false` (it already does via the
  catch-all — add an explicit assertion so a future refactor of the match arms can't silently flip
  it).
- A `PromotionCandidates` test: record `ControlFlow` alone → `first_set(&[Ownership, Permission,
  ControlFlow])` returns it. Record `Ownership` then `ControlFlow` → `first_set` still returns
  `Ownership` (preference order holds).

### 4. `leak_class.rs` — no change needed

`LeakClass::ControlFlow.oracles()` already returns `&[Reentrancy]` (`leak_class.rs:64`) and
`.middleware()` already returns `Some(MiddlewareType::Reentrancy)` (`leak_class.rs:79`) — the SSOT
side is already correct; only the promotion producer was missing.

## What stays byte-identical

- No reentrancy finding (`found.is_empty()`) → no candidate emitted → unchanged.
- Existing bug-report behavior (`EVMBugResult::push_to_output()` per finding) — unchanged, still
  fires for every entry regardless of promotion outcome.
- Targets with no ControlFlow candidate ever recorded → `structural_pin` filter behavior identical
  to today (falls through to Ownership/Permission exactly as before).
- All existing `plan_campaign_sampled`/`secant_promotable` call sites — unaffected; this only adds
  a new value to an existing enum match, no signature changes.

## Out of scope

- Reordering the `structural_pin` preference list beyond adding ControlFlow last (a product
  decision, flag if the team wants different precedence).
- A same-kind high-water definition beyond what `PromotionCandidates.record()` already provides
  (strictly-greater `best_inflow` — i.e., a later execution with MORE distinct reentrant touches
  than the incumbent replaces it; this is already generic in `record()`, no ControlFlow-specific
  code needed).
- Any change to `reentrancy.rs`'s bug-reporting/dedup behavior — this feature is additive only.
