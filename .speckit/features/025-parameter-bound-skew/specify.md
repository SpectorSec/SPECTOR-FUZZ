# Feature 025 — Parameter-Bound Skew (Admin Lever)

**Status:** Specified (not built)
**Owner:** TBD
**Last updated:** 2026-07-08
**Held:** LOCAL
**Origin:** skew-coverage frontier — the "amplify side" of the V5 `dim_flow` proposal (SYSTEM_DESIGN.dot). Resolves the capstone tension *"structural verdict has no magnitude to grow"* (memory `post-hoc-routing-capstone`) for the setter subclass.

## Overview
Today the reflexive lever amplifies **Value** candidates only. The kind-guard at `mutator.rs:677`:

```rust
if cand.kind != crate::evm::leak_class::LeakClass::Value {
    return false;   // structural (Permission) → not amplified
}
```

Feature 024 (the post-hoc→planner socket) already makes a **Permission** candidate *reach and hold* its function as a Prime step (`campaign_planner.rs` re-seeds it each plan). But some structural moves — `setFee`, `setRewardRate`, `updatePoolParams`, `setOracle` — **do** carry a magnitude: their **uint256 argument**. 024 reaches the setter; 025 **tunes its argument**.

The mechanism is the *existing* secant. 025 widens which candidate kind flows through the built promote → locate → amplify → `dim_flow→probe_delta` path (dot line 220, the bold CRITICAL edge) to include a **Permission candidate whose selector exposes a tunable uint arg**. No new math, no new objective — the ledger delta over the whole campaign is still the objective (per whole-campaign baseline delta, memory `phantom-eth-valuation`).

## Weapons this builds on (`spector-weapons.md`)
015 Promote→Locate→Amplify (LedgerSecant, `apply_ledger_secant`) · 016 TaintDim `located_dim → probe_delta` (the CRITICAL bold edge, already funds the step size) · 020 LeakClass SSOT (`kind == Permission`) · 023/024 verdict-routing + post-hoc→planner socket (produces the Permission candidate and re-seeds it as a Prime). The secant's own **LOCATE** phase (mutator.rs:821+) already auto-rotates args by measured sensitivity — it finds the right arg for free.

## Why This Matters
Governance / parameter-setting bugs (`setFee`, `setRewardRate`, `setThreshold`, `setOracle`) are one of the largest business-logic classes and are invisible to a value-only lever: the fuzzer can *reach* the setter (024) but never *skews its parameter to the value that breaks the invariant*. Skewing the fee/reward parameter to an extreme simulates the worst-case economic scenario — exactly what a confused-deputy or unauthenticated setter entry enables. This is the cheapest of the open skew levers (reuses the entire secant) and has crisp validation.

## Composition with 024 (why they don't collide)
024 socket seeds the setter as a **Prime BEFORE the exploit step** (`campaign_planner.rs:359`). 025 promotes that same step into the secant so its arg is tuned. The setter's profit is realized **downstream** (set fee now → skim later), so the objective must be the **whole-campaign** ledger delta — which the secant already measures and which the 024 ordering (Prime before Exploit) preserves. The two compose into: *reach & hold the setter (024) + tune its magnitude (025) + measure profit across the whole chain (existing objective).*

## Success Criteria
1. A **Permission** candidate whose target selector exposes ≥1 uint-typed arg is **promotable into the secant** (the `mutator.rs:677` guard is relaxed for this subclass only).
2. Candidates with **no tunable uint arg** (pure auth reach, e.g. a bare privileged toggle) still take the 024 Prime-lock path and are **NOT** promoted — no spurious amplification.
3. The secant tunes the setter arg via the **existing** LOCATE + `dim_flow→probe_delta` path; **no new secant math**.
4. Objective is the **whole-campaign** ledger delta; a delayed (downstream) profit from a setter skew is captured.
5. **Regression:** with no Permission-with-uint-arg candidate, the value/reflexive path AND the 024 socket path are **byte-identical**.

## Out of Scope
- **Geometric/Inversion skew** (1/x, V3 log-tick) — needs *non-linear* secant math; separate feature. 025 is linear-secant only.
- **Proxy/Delegate skew** — gated on cross-contract provenance (`mutator.rs:780` same-contract-only); separate feature.
- **Invariant-Δk skew** (addLiquidity/skim as lever) — a different candidate source; separate feature.
- The scheduler-energy edge (`dim_flow→scheduler`) — that is **Feature 026**, the "how much budget" half. 025 is the "what math" (amplify) half.
- Any change to oracle detection, taint, or the 024 socket's Prime-seed ordering.

## Investigation Checkpoints
### 25.1 — the kind guard is the single gate ✓ (traced)
`mutator.rs:677` returns false for any `kind != Value`. Relaxing it for `Permission + has-uint-arg` is the entry point. Confirm no other site filters kind before `apply_ledger_secant` runs.

### 25.2 — arg-type availability at promote time ⧗ (confirm in plan)
The candidate carries `(contract, selector)`; the campaign step carries `step.data: BoxedABI`. **Q:** is the arg type-list reachable at the promote site (mutator.rs:684-690) to test "has a uint256 arg"? The secant's `read_step_arg_u128` already assumes uint args by index — so the type info must be reachable; confirm the exact accessor (`step.data.b.get_bytes` / ABI arg descriptor) and that a setter with a single uint arg passes.

### 25.3 — LOCATE picks the setter arg ✓ (design)
The secant LOCATE phase (mutator.rs:821+) rotates args by measured `local_slope` sensitivity and keeps the most sensitive. A setter's magnitude arg will dominate sensitivity → selected automatically. No new arg-selection logic.

### 25.4 — double-promotion safety ⧗ (confirm in plan)
024 re-seeds the Permission step via the planner every iteration; 025 promotes the same step into `campaign.promoted` for the secant. **Q:** does `campaign.promoted` being set for a structural step interfere with the 024 planner re-seed (which keys on the global candidate, not `promoted`)? Expected: independent (planner reads the candidate; mutator reads `promoted`), but verify the re-seed still fires when `promoted` is non-empty.

### 25.5 — objective is whole-campaign ✓ (traced)
`apply_ledger_secant` reads the campaign ledger objective (whole-campaign baseline delta). A downstream-realized setter profit is already in-scope. No objective change.

## Validation
Crisp pass/fail: a synthetic (or fork) target with an unauthenticated/confused-deputy `setFee`-style setter whose extreme value enables a downstream skim. **Before 025:** setter reached (024) but arg untuned → no profit. **After 025:** secant drives the arg to the invariant-breaking value → whole-campaign ledger delta > 0. Full lib suite green + value/024 paths byte-identical.
