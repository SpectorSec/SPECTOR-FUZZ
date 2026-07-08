# Plan — Feature 023 — Verdict Routing

**Status:** Draft (specify.md 4/5 resolved; Phase 0 gates coding)
**Last updated:** 2026-07-07
**Held:** LOCAL

## Architecture (the shape)
Mirror the reflexive lever for a second `kind`. The value path already is: `feedbacks` derives `(step_index, inflow)` from `CampaignInflowBoundaries` → writes a `PromotionCandidate{contract, selector, best_inflow, kind=Value}` (global high-water) → `mutator.rs:667` pins that step and **amplifies**. Feature 023 adds the structural twin:

```
post-hoc verdict ──kind?──┬─ Value      → (exists) high-water candidate → mutator AMPLIFIES the Lever step
                          └─ Structural → NEW structural candidate       → mutator LOCKS the Prime step
                                         (kind=Permission, phase-tagged)   (preserve, don't mutate away)
```
Both carry through the **mutator** (23.1: planner has no intake). Both are keyed by **phase** (23.4). The only new decision is reading `.kind` (23.2) and branching the mutator action (23.3).

## Phase 0 — GATE: structural step-attribution ✓ RESOLVED (2026-07-07)
The value path attributes to "largest ledger belly call." The structural analogue must attribute the FunctionAuth verdict to a **step**. `FunctionAuthData` records by **contract** (`value_moves`, `material_writes`), not step.
**Finding (executor.rs:276-285):** `CampaignInflowBoundaries.offsets` are stamped `inflow_offsets.push(erc20_transfers.len())` at each step boundary — i.e. **indexed by ERC20-transfer count.** They locate VALUE (transfer) frames ONLY; a structural signal has no transfer, so it **cannot** be attributed via these offsets. → **the value offsets are NOT reusable for structural attribution.**
**BUT:** the executor's step loop (executor.rs, the block that pushes per-step offsets) has the **step index in scope**. So the fix is small & local — **Phase 1a: publish the current step index during each step's execution** (host/state field), so the inline `FunctionAuthTracer` stamps `(step, contract)` when it records a material move. The executor already knows the step; it just doesn't expose it. Feasible, bounded, no new infra beyond a cursor.

## Phase 1 — KEYSTONE: phase-tag the verdict
### 1a (from Phase 0) — expose the current step index inline ✓ BUILT + TESTED (2026-07-07)
- `function_auth.rs`: `static mut CURRENT_CAMPAIGN_STEP` + `set_campaign_step()/current_campaign_step()` (codebase idiom, single-threaded exec).
- `executor.rs`: publishes it per-step in the campaign loop (`Some(i)`), before the last-step + probe execs (`Some(last_idx)`), and clears it (`None`, cfg=evm) on the non-campaign path.
- `FunctionAuthTracer` stamps `material_at_step: HashMap<EVMAddress, usize>` (`#[serde(default)]`; carrier is `#[serde(skip)]` so corpus-safe) at both material sites (SSTORE pre≠new, non-zero-value CALL), `or_insert` first-write-wins.
- Test `material_move_phase_tagged_by_step`: step 2 → stamped 2; no campaign → empty. Release compiles, 7/7 function_auth green.
### 1b — carry the phase on the structural candidate
- Add `phase: Option<usize>` to the structural candidate (candidate-only — keeps `BugMetadata` (`oracle.rs:157`) untouched, dodges the serialized-state question).
- **Valuable standalone:** every downstream (report, router, future archetype socket) needs this coordinate. Smallest real unit.

## Phase 2 — structural candidate producer ✓ BUILT + TESTED (2026-07-07)
- `PromotionCandidate` gained `phase: Option<usize>` (`#[serde(default)]`, corpus-safe). Value producer (feedbacks.rs:459) now stamps `phase: Some(idx)`.
- `function.rs` (o_func fire site, where `contract`+`selector`+phase are all in scope): emits `PromotionCandidate{contract, selector, best_inflow:0, kind=Permission, phase: material_at_step[contract], set:true}` via `metadata_map_mut().insert()` — **only if `!already_set`**, so value (direct loss) keeps precedence and the value high-water clobbers this best_inflow=0 incumbent → **value path byte-identical (SC #5)**.
- Full lib suite: 178 passed / 0 failed (incl. PromotionCandidate phase round-trip).

## Phase 3 — kind-aware mutator (subsumes 019-C)
### 3a — kind guard ✓ BUILT + TESTED (2026-07-07)
- `mutator.rs:672`: the reflexive lever now amplifies **`kind == Value` only**; a structural candidate returns false (not amplified). Value path byte-identical (all pre-023 candidates were `Value`); structural candidates are produced + carried in the corpus but not wrongly amplified. Full suite green.
### 3b — LOCK the Prime step ✗ RE-SCOPED (2026-07-07, verified against source — do NOT build as a mutator vec)
**Finding:** a `locked` vec on `CampaignSequence` would be WRITE-ONLY. `mutator.rs:987` re-plans the campaign **fresh every iteration** via `plan_campaign_sampled` (a-priori: cache + topology + flags). The steps are *regenerated*, not mutated-and-preserved — so there is nothing to "preserve across mutation," and the next fresh plan never reads a `locked` vec. `maybe_promote_lever` only works because it RE-DERIVES `promoted` each iteration by matching the persistent global candidate's `(contract, selector)` against the freshly-sampled steps — it relies on the planner *happening* to sample that call.
**So the real "arrive & hold the structural move" is a PLANNER-INTAKE change:** `plan_campaign_sampled` must consume the global structural `PromotionCandidate` and *seed/pin* its `(contract, selector)` step into the sampled campaign. That is exactly the **post-hoc→planner socket** 023 scoped OUT (Out of Scope: "wiring … INTO the planner"). It is the same door named in the capstone (`structural-forward: post-hoc → Planner`). Belongs in the planner-socket feature, not 023.
**Net for task #14 (019-C):** the "kind-aware mutator" half is DONE (3a: value amplifies, structural does not wrong-amplify). The "hold" half is not a mutator concern at all — it's the planner socket. Task #14 should be re-scoped or closed with 3a; the hold moves to the socket feature.
- Live validation of the hold waits on the socket.

### SOCKET BUILT (2026-07-08) — the `post-hoc → Planner` edge, cut
Built directly (bounded change, cache exposes `(addr, sel, abi)`): `plan_campaign_sampled` gained `structural_pin: Option<(EVMAddress, [u8;4])>`; new `build_structural_step` looks the pin up in `prime/exploit/reflexive_targets` and `build_abi_step`s it; the planner RE-SEEDS that step each plan (the "hold" via re-planning, mirroring how `promoted` re-derives), placed before the exploit (stays last for warp), skipped if already present, NOT in `promoted` (so 3a never amplifies it). `mutator.rs:987` reads the global `kind==Permission` candidate and passes it; value/None paths byte-identical. Test `structural_pin_seeds_step_into_plan` + full suite 179/0. **The structural verdict now flows END-TO-END: stamp phase (1a) → produce candidate (2) → kind-aware mutator (3a) → planner re-seeds the Prime (socket). A permission-leak exploit is now RELIABLY REACHED, not coincidentally sampled or report-only.**

## Test plan
- **Unit:** phase attribution returns the correct step for a 3-step campaign (borrow→prime→exploit) where step 1 records a structural move. Structural candidate carries the right phase+kind. Mutator locks vs amplifies per kind.
- **Regression (SC #5):** value-only run — candidate/mutator path byte-identical (diff the promoted-step selection + amplify delta vs pre-023).
- **Live (later):** a structural-bound target (staking-reward or yDAI `earn()` reflexive) — confirm the structural verdict pins a Prime step that survives mutation across iterations (the lock holds), vs today where it's report-only.

## Dependencies / co-edges (NOT in 023)
- **Archetype → planner** socket: full "place the verdict in the right archetype slot / choose the structural move" needs `archetype_catalog.json` loaded into the planner (integration-1 diagram, PROPOSED). 023's lock-Prime works without it (preserves the move that fired); the socket later lets the planner *choose* structural moves.
- **Divergence → oracle activation** (integration-2, PROPOSED): would pre-select the FunctionAuth MW on structural-class targets so the verdict fires more often. Orthogonal.

## Open sign-off items
1. Phase 0 result (attribution feasible via existing offsets? y/n).
2. Phase-1 home decision: `BugMetadata` field vs candidate-only (recommend candidate-only — dodges serialized `BugMetadata` change).
