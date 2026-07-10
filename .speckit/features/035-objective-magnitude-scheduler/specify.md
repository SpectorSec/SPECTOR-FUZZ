# Feature 035 — Objective-Magnitude-Aware Scheduler Feedback

## Status
Ready to build, with one tunable-constants decision flagged below for sign-off before merge (not
a blocker to drafting the implementation — the shape is fixed, the numbers are adjustable).

## The gap (code-verified)

`scheduler.rs:520-558` (`Feature 026 Phase A`) boosts power for any corpus input matching a live
`PromotionCandidate`'s `(contract, selector)`, via `promote_boost(hits: u32) -> f64`
(`scheduler.rs:163-167`):

```rust
fn promote_boost(hits: u32) -> f64 {
    const PROMOTE_BOOST: f64 = 2.0;
    let decay = 0.95_f64.powi(hits as i32);
    1.0 + (PROMOTE_BOOST - 1.0) * decay
}
```

This is **presence-only**: a `Value` candidate with `best_inflow` = 1 wei gets the identical 2.0x
boost as one with `best_inflow` = 1000 ETH. Same for `Invariant` (`|violation_delta|`) and
`Ownership` (relocation count) — the magnitude each kind's producer already computes and stores in
`best_inflow` is read by `record()`'s high-water check but never influences scheduler energy. This
is the last item in the system inventory's "not yet built" list (§7: *"Objective-magnitude-aware
scheduler feedback... `promote_boost` is presence-only; no kind-aware magnitude scaling yet"*) and
was flagged as a known gap, not a bug, in THESIS.md's Ownership/Permission corrections.

## Why this matters

Two campaigns can both have a live Value candidate — one found a 0.001 ETH leak, another found a
1000 ETH leak. Both get scheduled with identical extra energy today. The whole point of `best_inflow`
being a high-water mark is that bigger is more informative; the scheduler should spend more search
budget on the target that's proven to matter more, not treat "any candidate" as equally worth
chasing.

## Proposed design

**Cross-kind magnitudes are not comparable in absolute terms** — Value's `best_inflow` is wei
(routinely 10^15-10^18+), Ownership's is a relocation count (single digits), ControlFlow's (034) is
a reentrant-touch count (single digits), Invariant's is a violation-distance in whatever units the
oracle's comparison uses. A shared *absolute* threshold would either never fire for structural
kinds or always saturate for Value. Use a **log-scaled, self-normalizing** multiplier instead —
it needs no per-kind calibration because `ln(1+x)` compresses any magnitude range the same way,
and a magnitude of 0 (today's Permission/ControlFlow presence-only candidates) always maps to no
extra boost, preserving current behavior exactly for those:

```rust
/// Feature 035 — magnitude-aware extra multiplier on top of the existing presence-based
/// `promote_boost`. Log-scaled so it needs no per-kind calibration: ln(1+x) compresses any
/// magnitude range (wei amounts, relocation counts, violation distances) onto the same curve.
/// magnitude=0 → 1.0 (no extra boost — byte-identical to pre-035 for presence-only candidates
/// like Permission's `best_inflow=0` and low-touch ControlFlow). Bounded above by
/// MAGNITUDE_BOOST_MAX so no single huge Value inflow can dominate the schedule indefinitely.
fn magnitude_boost(best_inflow: u128) -> f64 {
    const MAGNITUDE_BOOST_MAX: f64 = 1.5; // extra multiplier ceiling (on top of promote_boost's 2.0x)
    const MAGNITUDE_LOG_SCALE: f64 = 1e18; // ~1 ETH in wei — the point the curve approaches its cap
    if best_inflow == 0 {
        return 1.0;
    }
    let x = ((best_inflow as f64) + 1.0).ln();
    let scale = MAGNITUDE_LOG_SCALE.ln();
    let ratio = (x / scale).clamp(0.0, 1.0);
    1.0 + (MAGNITUDE_BOOST_MAX - 1.0) * ratio
}
```

Combine at the call site (`scheduler.rs:546-556`, inside `if matches_promoted`):

```rust
if matches_promoted {
    let hits = match entry.metadata::<PowerABITestcaseMetadata>() {
        Ok(meta) => meta.promote_hits,
        Err(_) => 0,
    };
    // Feature 035: scale the presence boost by the matched candidate's objective magnitude.
    let magnitude = candidate_magnitude; // best_inflow of whichever PromotionCandidates entry matched — see below
    power *= promote_boost(hits) * magnitude_boost(magnitude);
    ...
}
```

`magnitude_boost` is `>= 1.0` always, so `promote_boost(hits) * magnitude_boost(magnitude) >=
promote_boost(hits)` — this is a strict enhancement, never a regression relative to today's flat
boost, for every kind and every magnitude including 0.

### Threading the magnitude through

`scheduler.rs:530-545`'s `matches_promoted` is currently a `bool` (did ANY kind's candidate match
this input). To read magnitude-boost needs the matched candidate's `best_inflow`, not just whether
one matched — restructure to `Option<u128>` (the matched magnitude) rather than `bool`:

```rust
let matched_magnitude: Option<u128> = state
    .metadata_map()
    .get::<PromotionCandidates>()
    .and_then(|candidates| {
        candidates.by_kind.values().find(|cand| {
            cand.set && abi.function == cand.selector && input.get_contract() == cand.contract
        })
    })
    .map(|cand| cand.best_inflow)
    .or_else(|| {
        state.metadata_map().get::<PromotionCandidate>().and_then(|cand| {
            (cand.set && abi.function == cand.selector && input.get_contract() == cand.contract)
                .then_some(cand.best_inflow)
        })
    });
if let Some(magnitude) = matched_magnitude {
    let hits = ...;
    power *= promote_boost(hits) * magnitude_boost(magnitude);
    ...
}
```

## Tests to add

- `magnitude_boost_zero_is_neutral`: `magnitude_boost(0) == 1.0` exactly.
- `magnitude_boost_monotonic`: `magnitude_boost(a) <= magnitude_boost(b)` for `a < b`.
- `magnitude_boost_bounded`: `magnitude_boost(u128::MAX) <= 1.5 + epsilon` (never unbounded).
- `magnitude_boost_never_reduces_promote_boost`: for a range of `hits` and `magnitude` values,
  `promote_boost(hits) * magnitude_boost(magnitude) >= promote_boost(hits)`.
- A scheduler-level test (mirroring the existing `PowerABITestcaseMetadata` tests) confirming a
  higher-`best_inflow` candidate yields strictly more power than a lower one at the same `hits`.

## Open decision (flag before merge, don't block drafting on it)

`MAGNITUDE_BOOST_MAX = 1.5` and `MAGNITUDE_LOG_SCALE = 1e18` are placeholders reflecting "Value
inflow in the ETH range should approach the cap; structural counts in the single digits should get
a small but non-zero nudge." If the team wants a different ceiling (how much should magnitude ever
be allowed to outweigh the base presence signal) or a different reference scale, that's a tuning
call, not an architecture one — the `magnitude_boost` function shape (log-scaled, bounded, zero at
magnitude=0) is the part that should hold regardless of the constants chosen.

## Out of scope

- Per-kind separate scaling curves (e.g., a different `MAGNITUDE_LOG_SCALE` for Ownership's
  relocation counts vs. Value's wei amounts) — the log-scale design intentionally avoids needing
  this; revisit only if empirical tuning shows one kind's curve saturates too early/late relative
  to another.
- Changing `promote_boost`'s own hits-decay curve — untouched, this feature only adds a multiplier
  alongside it.
- Any change to how `PromotionCandidates.record()` computes or stores `best_inflow` — that's
  upstream and already correct (031-C/033-A, PR #1).
