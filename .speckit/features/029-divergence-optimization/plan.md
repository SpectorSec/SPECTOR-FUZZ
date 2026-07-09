# Feature 029 — Plan: System-Wide Integration (Benjamin Signal)

**Status:** Planned (Phase 2 of 029)
**Parent:** `specify.md` (beachhead built: publish_divergence, apply_divergence_secant, DivergenceFeedback, pin_gate)

## Origin
Benjamin's "Fuzzing Uniswap V4" talk (Recon 2026) revealed three system-wide gaps in how 029 integrates with the rest of SPECTOR. His core lesson: when signals get absorbed through indirection (coverage collapsed into `runActions`), fuzzer conjectures break. Our divergence signal was similarly absorbed — ephemeral thread-local, no persistence, no scheduler feedback. These three additions close those loops.

## Additions

### #1 — Persist divergence metadata through corpus serialization [BUILT]
**Status:** Built in beachhead (`feedback.rs:830-847`). `DivergenceSecantState` has `Serialize, Deserialize, impl_serdeany!`. No additional work needed.

When a corpus entry is serialized and reloaded, `pin_gate` carries over. Phase 3 starts immediately without re-exploring Phase 1. This is Benjamin's "shortcuts on" phase — the divergence-maximized path is the new starting point.

**Files:** `src/feedback.rs:830-847` ✓

### #2 — Close the `liquid → amplify` edge (compound sequence canary)
**Status:** To build
**Edge (diagram):** `liquid -> amplify [dashed red, PROPOSED: profit confirmed -> boost AMPLIFY confidence]`

**Problem:** The diagram shows that profit confirmation (liquidation) should boost AMPLIFY confidence, but no edge exists. Benjamin's talk proves this matters: when `runActions` absorbed all coverage, the fuzzer couldn't attribute success to the compound sequence (`addSwap + addSettle + addDonate`). Our analog: when an execution has BOTH divergence (Phase 1 success) AND profit (Phase 3 success), that compound sequence should be reinforced.

**Implementation:** In `TokenBalanceFeedback::record_aposteriori_candidate`, after `best_inflow_step` finds a material step, also check `read_divergence()`. If both inflow and divergence are non-zero, emit a `CompoundSequenceCanary` metadata. This metadata feeds into 026 energy boosts and provides a canary for coverage verification (Benjamin's "emit a log when donate + swap co-occur").

**Pattern:**
- Canary struct: `CompoundSequenceCanary { inflow: u128, divergence: u128 }` with `impl_serdeany!`
- Producer: `record_aposteriori_candidate` in `evm/feedbacks.rs`
- Consumer: 026 scheduler energy boost (future, same pattern as `PromotionCandidate`)
- Coverage: the canary's existence is itself a coverage event the fuzzer can target

**Safety:** Additive — a dead metadata write until something reads it. Zero regression.

### #3 — Planner socket for divergence-pinned sequences
**Status:** Deferred (requires campaign-based divergence, which is follow-on to beachhead)

**Problem:** The beachhead tunes `txn_value` — no campaign steps involved. Once `DivergenceFeedback` finds multi-step sequences (full 029 Phase 1), the divergence-peaked campaign should be pinned as a Prime step (024 socket) so the planner re-seeds it every iteration.

**Implementation:** Add `divergence_pin: Option<(EVMAddress, [u8; 4])>` to `plan_campaign_sampled`, mirroring `structural_pin`. Populated from a `DivergencePrimeCandidate` metadata set when `pin_gate` fires.

**Gate:** Only relevant when the divergence seq is campaign-based (not txn_value tuning). Do not build until `DivergenceFeedback` has discovered a multi-step divergence-maximizing campaign in practice.

## Build Order
1. ~~#1 (persistence)~~ ✓ built in beachhead
2. **#2 (canary) — this session**
3. #3 (planner socket) — deferred, re-evaluate after campaign-based divergence is live

## Success Criteria (Phase 2)
- ✓ #1: `DivergenceSecantState` survives corpus serialization (impl_serdeany!)
- [ ] #2: A compound canary is emitted when inflow + divergence co-occur in one execution
- [ ] #2: No regression when no divergence published (canary not emitted, behavior byte-identical)
- [ ] #3: (deferred) Planner re-seeds the divergence-peaked sequence as a Prime
