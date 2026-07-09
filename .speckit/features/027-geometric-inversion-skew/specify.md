# Feature 027 — Geometric / Inversion Skew (log-space secant)

**Status:** BUILT (2026-07-09) — live real-pool validation pending
**Owner:** TBD
**Held:** LOCAL
**Origin:** the one confirmed *capability* gap in the skew program ([[skew-coverage-program]]): the secant is linear-only.

## Overview
The whole secant family assumes the comparison distance is **linear in the arg** — `secant_step` (mutator.rs) is `x* = x1 + d1·δ/(d1−d2)` and gives up (`None`) the moment `d1 ≤ d2`. But many DeFi levers move the distance **multiplicatively**: AMM reserves (spot price ∝ 1/x), Uniswap-V3 ticks (price = 1.0001^tick), and any power-law `d ∝ x^k`. On those the linear model mis-steps or stalls, and the gate was only ever punted to concolic.

027 adds `secant_step_geometric` — the same two-point secant in **log space**, where any power-law becomes affine:
```
L1 = ln x1 ; L2 = ln(x1+δ) ; L* = L1 − d1·(L2−L1)/(d2−d1) ; x* = exp(L*)
```
Log space is the single generalization that covers *both* cases the research doc named (1/x AND base^tick), since `log(x^k) = k·log(x)`. It also naturally handles **direction inversion**: when the distance GREW with x (`d2 > d1`, the case linear abandons), the log-space root lands at `x* < x1` — "the amount went the wrong way, invert it."

## Weapons this builds on
`secant_step` (linear distance-aiming, 008/009) · the secant driver `apply_value_secant` / warp+calldata secants (mutator.rs Probe2 arms) · 009 §5.3 `requeue_for_concolic` stall handler.

## Why This Matters
This is the "beats-havoc" capability: a coverage/havoc fuzzer cannot aim a multiplicative price lever at all, and even our linear secant abandoned it to slow concolic. 027 lets the deterministic secant solve inverted/power-law price surfaces directly — the AMM and V3 mispricing classes.

## Design (as built)
- `secant_step_geometric(x1, d1, d2, delta) -> Option<u128>`: f64 log-space intermediates (a NEXT-guess heuristic — the secant re-probes, so integer precision is unnecessary), clamped back to the u128 arg domain. `None` on degenerate probes (`x1==0`, `d1==d2`, `δ==0`, non-finite / out-of-domain result).
- Wired at BOTH `secant_step` call sites (mutator.rs ~500 value/txn_value, ~605 calldata-arg): `linear.or_else(|| secant_step_geometric(...))`.
- **No regression by construction:** the concolic safety-net requeue still fires on EVERY linear stall (over-requeue is safe; under-requeue is the regression the code warns against) — geometric only *adds* a guess on top, never starves concolic. When linear succeeds, behaviour is byte-identical.

## Success Criteria
1. `secant_step_geometric` recovers a meaningful step in the `d2 > d1` (distance-grew) case the linear secant abandons — and inverts direction (`x* < x1`). ✓ unit-tested.
2. Same direction as linear (step up) when distance shrinks with x. ✓
3. Degenerate probes → `None`. ✓
4. Concolic requeue behaviour unchanged (no lost gate). ✓ by construction.
5. Linear-success path byte-identical. ✓

## Out of Scope / Pending
- **Live real-pool validation** — a fork target with an inverted/V3-tick price lever, confirming the log-space guess converges where linear stalled. This is the honest open item (the math is unit-tested; correctness-vs-real-pool behaviour is not yet observed). See [[skew-coverage-program]].
- A dedicated V3 tick-domain model (exact 1.0001^tick inversion) — log-space is the general approximation; a tick-exact variant is a later refinement if validation shows it's needed.
- Proxy/Delegate skew (cross-contract provenance) — the remaining substantive skew build.
