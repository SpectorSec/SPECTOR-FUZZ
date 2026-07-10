# Feature 037 — Wire DivergenceFeedback + Give CompoundSequenceCanary a Consumer

## Status
**BLOCKED — needs a design decision, not ready to implement as originally written.** The original
version of this spec proposed nesting `DivergenceFeedback` directly into `infant_feedback`
(mirroring how `CmpFeedback`/`TokenBalanceFeedback` are combined there today). That approach is
**incorrect** — verified by tracing the actual per-iteration call order in `fuzzer.rs`, not assumed.
See "Gap 1 — corrected" below before any implementation starts.

## Gap 0 — the ordering defect that blocks the naive fix (code-verified, found on review)

`fuzzer.rs::evaluate_input_events` calls, in this exact order, for every executed input:

1. `run_target()` (`fuzzer.rs:408`) — runs the campaign; `state.get_execution_result()` is
   populated synchronously here.
2. `self.infant_feedback.is_interesting(...)` (`fuzzer.rs:423-425`) — today: `CmpFeedback` OR
   `TokenBalanceFeedback` (`EagerOrFeedback`, `evm_fuzzer.rs:496`).
3. `self.objective.is_interesting(...)` (`fuzzer.rs:427-429`) — bound to `OracleFeedback`
   (`evm_fuzzer.rs:918-931`). `feedback.rs:219-220`'s own doc comment: *"Called after every
   execution. It executes the producers and then oracles."* **This is the only place any oracle,
   including `ERC4626Oracle`, actually runs — and therefore the only place `publish_divergence()`
   is called for the current execution.**
4. `self.infant_result_feedback.is_interesting(...)` (`fuzzer.rs:453-455`, `DataflowFeedback`) —
   only reached if step 2 already returned true; can only add extra votes to an infant state that
   was already added, never trigger adding one.
5. `self.feedback.is_interesting(...)` (`fuzzer.rs:469-471`) — `MaxMapFeedback` (coverage), the
   main-corpus decision.

**Step 2 runs before step 3.** `DivergenceFeedback` needs `read_divergence()`, which only step 3
(this iteration's oracle pass) can set. `DIVERGENCE_OBJECTIVE` (`feedbacks.rs:58`) is a thread-local
`Cell` that nothing resets between iterations — so if `DivergenceFeedback` ran at step 2, it would
read whatever the **previous** iteration's oracle pass published, not the current one. Silent
one-iteration lag, not a crash — the mechanism would vote the infant-state scheduler on the wrong
execution's signal indefinitely.

Confirmed this is NOT a problem for `CmpFeedback`/`TokenBalanceFeedback` (today's contents of
`infant_feedback`): `TokenBalanceFeedback::is_interesting` (`feedbacks.rs:689`) reads
`state.get_execution_result()` directly — populated at step 1, available well before step 2 needs
it. `DivergenceFeedback` is architecturally different: its signal is oracle-produced, not
execution-result-direct, and the existing combinator position assumes the latter.

**Moving it to `infant_result_feedback` (step 4, which DOES run after the oracle pass) doesn't fix
this either** — whether an infant state is added to the corpus at all is decided at `fuzzer.rs:446`
(`if is_infant_interesting && !reverted`), gated on step 2's verdict alone. Step 4 can only sponsor
extra votes for a state some other feedback already added; it can never be the trigger — but
`DivergenceFeedback`'s own doc comment (`feedbacks.rs:863-864`) says it needs to be exactly that
trigger (*"the state is marked interesting and the infant-state scheduler votes"*).

### The actual decision needed before implementing

Two real options, both with real cost — this needs product/architecture sign-off, not a unilateral
pick:

1. **Reorder the shared loop**: swap steps 2 and 3 (`objective` before `infant_feedback`) in
   `fuzzer.rs`. Blast radius: this is generic, shared machinery used by every fuzzing
   configuration — `CmpFeedback`/`TokenBalanceFeedback`'s current behavior would need re-verifying
   under the new order (they don't appear to depend on ordering per the direct-execution-result
   read above, but "appears not to" is not the same as a full re-audit of every consumer).
2. **Compute divergence eagerly, decoupled from the Oracle-trait pass**: give `ERC4626Oracle`'s
   price-comparison logic a path that runs directly off `state.get_execution_result()`/observers
   right after step 1, independent of the full `OracleFeedback` producer/oracle machinery — so
   `publish_divergence` fires before step 2 without reordering anything shared. Likely the smaller
   blast radius, but needs checking whether `ERC4626Oracle`'s price read genuinely only needs data
   already present in the execution result, or needs the oracle-context setup (`OracleCtx::new`,
   `campaign_intermediate_states`, `temporal_warps`) that step 3 currently provides.

**Do not proceed with either until one is chosen.** The rest of this spec (below) describes what
correct behavior looks like once the ordering is fixed — it does not by itself constitute a safe
implementation plan.

## Gap 1 — `DivergenceFeedback` is never instantiated (code-verified)

`DivergenceFeedback<SC>` (`feedbacks.rs:859-950`) is a complete `Feedback<EVMFuzzState>` impl — it
reads `read_divergence()`, checks `DivergenceSecantState.pin_gate`, and calls
`self.scheduler.vote(...)` on a new divergence ceiling. It is referenced **nowhere outside its own
definition** — confirmed by grep across the whole tree.

`evm_fuzzer.rs:472-497` builds the infant-scheduler feedback as:

```rust
let cmp_feedback = CmpFeedback::new(cmps, infant_scheduler.clone(), evm_executor_ref.clone());
let balance_feedback = TokenBalanceFeedback::new(attackers, infant_scheduler.clone(), ...);
let infant_feedback = libafl::feedbacks::EagerOrFeedback::new(cmp_feedback, balance_feedback);
```

Two slots, both filled. `DivergenceFeedback` has no path into this. Since `EagerOrFeedback::new`
itself produces a `Feedback` impl, it nests — this is the standard LibAFL pattern for combining
more than two feedbacks (already proven by `Sha3WrappedFeedback` wrapping the outer `feedback` at
`evm_fuzzer.rs:932-937`).

### Fix — INVALID AS WRITTEN, see Gap 0 above

The nesting below is mechanically correct (it does add `DivergenceFeedback` to the combinator) but
is not a correct fix — per Gap 0, this position in `infant_feedback` runs before the oracle pass
that would populate `read_divergence()` for the current execution. **Do not implement this without
first resolving Gap 0's ordering decision.** Kept here only to show the mechanical nesting shape,
which is still needed once the data-availability problem is fixed (whichever option is chosen —
reordering the loop or computing divergence eagerly, the endpoint still needs `DivergenceFeedback`
added to this combinator or its replacement):

```rust
let divergence_feedback = crate::evm::feedbacks::DivergenceFeedback::new(infant_scheduler.clone());
let infant_feedback = libafl::feedbacks::EagerOrFeedback::new(
    libafl::feedbacks::EagerOrFeedback::new(cmp_feedback, balance_feedback),
    divergence_feedback,
);
```

`DivergenceFeedback::new(scheduler: SC)` already takes exactly the same scheduler type
`cmp_feedback`/`balance_feedback` use (`infant_scheduler.clone()`) — no new type-parameter plumbing
needed, this is a one-line constructor add plus a re-nest of the existing combinator.

### What this closes

Per `feedbacks.rs:859-872`'s own doc comment, once wired: any execution where `read_divergence()`
returns a new ceiling (published today only by `erc4626.rs:154`) makes the infant state
"interesting" and votes it up in the infant-state scheduler — this is the mechanism that would let
the fuzzer discover **multi-step sequences** that maximize oracle-divergence magnitude (Phase 1
proper), rather than only tuning a single `txn_value` via `apply_divergence_secant` (which is all
that's live today). `029/plan.md:37,41` explicitly gates the NEXT phase of 029 (pinning a
divergence-discovered multi-step campaign as a Prime step) on `DivergenceFeedback` having found
something "in practice" — that can't happen while it's never instantiated.

### What stays byte-identical

- No divergence ever published (`read_divergence() == 0`, i.e. no ERC4626 vault in scope) →
  `DivergenceFeedback::is_interesting` returns `Ok(false)` immediately → inert, same as today.
- `DivergenceSecantState.pin_gate` set → `DivergenceFeedback` also goes silent (checked at
  `feedbacks.rs:928-932`) — the existing Phase 1→3 handoff is respected, this feature doesn't
  change that gate's semantics.
- `cmp_feedback`/`balance_feedback`'s own `is_interesting` results — unaffected; `EagerOrFeedback`
  is an OR, adding a third arm only adds MORE ways to become interesting, never fewer.

## Gap 2 — `CompoundSequenceCanary` has no consumer (code-verified)

`029/plan.md:24` states the design intent explicitly: *"This metadata feeds into 026 energy boosts
and provides a canary for coverage verification."* Grepped `CompoundSequenceCanary` across the
entire tree: it appears in exactly one place outside its own struct/impl —
`feedbacks.rs:538-549`, where `TokenBalanceFeedback::record_aposteriori_candidate` writes it when
both `inflow > 0` and `read_divergence() > 0` in the same execution. Nothing in `scheduler.rs`, or
anywhere else, ever reads it. The stated integration point does not exist in code.

### Fix — give it the same shape as `PromotionCandidate`'s existing scheduler hook

Mirror `scheduler.rs:520-558`'s `promote_boost` pattern (a small, decaying multiplier gated on
metadata presence) rather than inventing a new mechanism:

```rust
// Feature 037 — Compound sequence canary → scheduler energy (029/plan.md:24's stated,
// previously unimplemented integration point). A testcase whose execution produced BOTH
// attacker inflow AND oracle divergence in the same run is evidence of a compound
// liquid→amplify sequence (Benjamin's "donate + swap co-occur" pattern) — worth a modest,
// decaying boost distinct from the plain promote_boost (which only checks presence of
// ANY candidate, not this specific co-occurrence).
if let Some(canary) = state.metadata_map().get::<CompoundSequenceCanary>() {
    if canary.set {
        let hits = /* new decay counter, e.g. PowerABITestcaseMetadata.compound_hits */;
        power *= compound_boost(hits); // same shape as promote_boost/dim_boost: flat ceiling, 0.95^hits decay
    }
}
```

This needs a new `compound_hits: u32` field on `PowerABITestcaseMetadata` (mirroring
`topology_hits`/`promote_hits`/`dim_hits` already there) and a `compound_boost(hits) -> f64`
function identical in shape to `promote_boost`/`dim_boost` (pick a ceiling constant, e.g. 1.5x —
smaller than `promote_boost`'s 2.0x since this is a secondary telemetry signal, not the primary
promotion mechanism).

### Alternative if the team doesn't want a new scheduler hook right now

Correct `029/plan.md:24`'s claim instead — note that `CompoundSequenceCanary` is currently
telemetry-only (written, not consumed) and strike "feeds into 026 energy boosts" until it's
actually wired. This is the cheaper option but leaves the signal doing nothing. Flagging as a
genuine either/or, not defaulting to one — the scheduler-hook option is recommended since it's a
small, well-precedented addition (same shape as two boosts that already exist), but this is a
product call on whether 029's compound-sequence signal is worth spending schedule energy on yet.

## Tests to add

- A regression test confirming `DivergenceFeedback` is actually present in the constructed
  `infant_feedback` tuple type at compile time (type-level — if the nesting is removed, this
  should fail to compile) is hard to express directly; instead, add an integration-style test that
  constructs `DivergenceFeedback`, calls `is_interesting` with a nonzero `read_divergence()`, and
  asserts `scheduler.vote(...)` was invoked (may need a mock/spy scheduler — check what the
  existing `CmpFeedback`/`TokenBalanceFeedback` tests use for this, if any).
- If the `compound_boost` scheduler hook is built: `compound_boost_zero_hits_is_ceiling`,
  `compound_boost_decays`, mirroring the existing `promote_boost_decays_from_full_to_neutral` test
  exactly.

## Out of scope

- Building 029's next phase (pinning a `DivergenceFeedback`-discovered multi-step sequence as a
  Prime step, `029/plan.md:37-41`) — that is explicitly gated on THIS feature landing and
  `DivergenceFeedback` finding something in practice first. Don't build ahead of evidence.
- Tier-2 divergence publishing from Invariant/Echidna oracles (rewriting boolean invariants to
  return signed magnitude) — a separate, larger feature (029's own spec scope), not part of this
  wiring fix.
- Any change to `apply_divergence_secant` or `divergence_value` — both already correctly wired,
  untouched by this feature.
