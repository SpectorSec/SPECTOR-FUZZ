# Feature 033 — Invariant Promotion Producer

## The architectural shift: terminal event → intermediate control signal

Most invariant fuzzers treat a violation as an endpoint:
```
Execute → Invariant fails → Report bug → Stop
```

Feature 033 changes the invariant into an intermediate control signal:
```
Execute → Invariant fails → PromotionCandidate(Invariant)
  → Planner → Lever selection → Secant amplification → Scheduler bias → Execute again
```

That is a fundamentally different architecture. The fuzzer doesn't just DETECT the violation —
it EXPLOITS the knowledge to go deeper.

Traditional invariant fuzzing asks: "Did something bad happen?"
SPECTOR-FUZZ asks: "Something bad happened. Now let's characterize the neighborhood around
that failure."

Characterization means:
- Can we make the violation worse?
- Can we make it happen faster?
- Can we reduce prerequisites?
- Can we increase economic impact?
- Can we reproduce it reliably?

That's how a human auditor behaves after discovery. They don't stop at "found a bug" —
they immediately explore the boundary conditions.

## Why invariant failure belongs in the Lever slot (the principle, not the implementation)

An invariant failure is evidence that the preceding execution step is highly informative.
Therefore:
```
Invariant Failure
      ↓
Identify the execution step that produced it
      ↓
Promote that step
      ↓
Optimize around it
```

The violating call belongs in the Lever position because it is the call whose parameter space
is worth exploring. Not because the routing code says so — because that is the step whose
variation changes the outcome.

## The optimization objective abstraction

`best_inflow` understates what the secant is optimizing. Each LeakClass defines a different
objective. The secant architecture is already general — it optimizes whatever the oracle
publishes as the signal. Making that explicit:

| Leak Class   | Optimization Objective                        |
|---|---|
| Value        | maximize extracted value (best_inflow)        |
| Permission   | maximize privilege escalation depth           |
| Ownership    | maximize unauthorized ownership transition    |
| Invariant    | maximize invariant violation distance         |
| ControlFlow  | maximize recursive depth / unsafe state reach |
| Message      | maximize attacker-controlled dispatch reach   |

The secant isn't "optimizing value." It's optimizing whatever objective the oracle defines.
That makes the architecture uniform across all six leak classes — not a special case for each.

For Invariant specifically: `best_inflow` should be replaced by a signed violation distance
(how far from the invariant boundary the execution landed). Larger distance = deeper violation
= stronger promotion candidate.

## The gap (code-verified in Feature 031 spec)

`echidna.rs`, `invariant.rs`, `state_comp.rs` — none emit PromotionCandidates. They fire,
log, and stop. `LeakClass::Invariant` is defined in the taxonomy (020) with oracle mappings
`[Invariant, StateComparison, Echidna]` but has zero producers in the promotion pipeline.

Feature 031's routing handles Invariant automatically via `value_lever_pin` (same Lever slot
as Value). The missing piece is the oracle-side emit.

## What the fix looks like

In `echidna.rs`, `invariant.rs`, `state_comp.rs` — on a material finding:
```rust
state.add_metadata(PromotionCandidate {
    contract,
    selector,          // the call that produced the violation
    best_inflow: violation_distance,  // signed distance from invariant boundary
    kind: LeakClass::Invariant,
    taint_provenance: ...,
    phase: Some(step_idx),
    set: true,
});
```

## The deeper contribution: generalizing the optimization framework

Feature 033 is not "adding invariant support." It is the second instance of a general pattern:

*Observations naturally become optimization objectives rather than terminal findings.*

Invariant is the second leak class in this pattern (Value is the first). Ownership, ControlFlow,
and eventually Message can all follow the same pattern. Each oracle that today produces a
pass/fail result becomes an oracle that produces a promotion candidate with a class-specific
optimization objective — and the secant optimizes it.

## 032 + 033 form a complete loop

```
Oracle
    │
    ▼
Promotion Candidate
    │
    ▼
Optimization Objective   ← Feature 033 (what to optimize)
    │
    ▼
Execution Intent         ← Feature 032 (what conditions to manipulate)
    │
    ▼
Primitive Selection
    │
    ▼
Campaign
```

033 answers: what should we optimize?
032 answers: what execution conditions should we manipulate while optimizing it?
Clean separation. Together they form the complete evidence→action loop.
