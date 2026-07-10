# Feature 037 — Wire DivergenceFeedback + Give CompoundSequenceCanary a Consumer

## Status
Ready to build. Found during a system-inventory pass over Feature 029 (Divergence Optimization),
which was never checked against the 033/034/035 remediation work because it's a separate objective
channel. Both gaps are the same "component exists, never wired" pattern the rest of the audit
already tracks — this is that same audit extended to 029.

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

### Fix

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
