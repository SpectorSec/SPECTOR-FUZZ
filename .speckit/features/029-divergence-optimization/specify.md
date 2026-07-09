# Feature 029 — Divergence Optimization (Phase-1 "optimization mode")

**Status:** Specified (not built)
**Held:** LOCAL
**Origin:** the ① reconvene (liquid→amplify) sharpened by (a) DeepSeek's code-path trace and (b) Alex/Recon's "fuzzing liquidity" talk (optimization mode: maximize invariant-break magnitude, THEN extract). Triangulated: design (Claude) ∧ code-path (DeepSeek) ∧ practice (Alex).

## The problem, in one line
The secants optimize **CMP distance** (`apply_value_secant`, targets `cmp_argmin()`, bails on `d==0`, mutator.rs:516) and **profit** (`apply_ledger_secant`, targets `read_ledger_objective()` = `TokenBalanceFeedback` inflow, mutator.rs:814). **Neither optimizes oracle/invariant DIVERGENCE MAGNITUDE.** For a small-tolerance bug (Alex's 1-second truncation → 15 wei invariant break; Lido basis-point rounding) the extraction landscape is **flat**: profit = 0 (nothing extracted yet), CMP distance buried in noise. The $151M path does not exist in the extraction landscape until the divergence is maximized *first*.

## The 3-phase model (target signal per phase)
| Phase | Objective | Status |
|---|---|---|
| **1. Divergence Max** | `ORACLE_MAG` (invariant/oracle break magnitude) | **THIS FEATURE — missing** |
| 2. CMP Flip | `CMP_MAP` | built (`apply_value_secant`) |
| 3. Extraction | `best_inflow` / ledger | built (`TokenBalanceFeedback` + `apply_ledger_secant`) |

Phase 1 is the **enabling prerequisite**, not a parallel lane: it transforms flat terrain so Phases 2–3 become reachable.

## Verified anchors (traced 2026-07-09)
- **erc4626.rs:142–151** — reads `price_pre/price_post/shares_pre/shares_post`, collapses through boolean predicates (`share_price_drained`, `became_zero_share`), and **DISCARDS the delta**. The magnitude is one subtraction (`price_post − price_pre`) from values already in scope. This is the beachhead.
- **invariant.rs:103–144** — returns `Vec<u64>` bug indices; **no magnitude** (Echidna-style boolean). Tier-2 (needs magnitude-valued property, à la Alex's boolean→signed-int rewrite).
- **feedbacks.rs:50/59** — `LEDGER_OBJECTIVE` thread-local + `publish_ledger_objective()`: the exact precedent to mirror for a published magnitude channel.
- **mutator.rs:814** — `apply_ledger_secant` reads the published objective and peak-finds via `secant_step_signed`. The template to clone (NOT the CMP-based `apply_value_secant`).

## Enabling change — publish the discarded divergence
- `publish_divergence(EVMU256)` / `read_divergence()` global, mirroring `LEDGER_OBJECTIVE` (thread-local, same-thread publish/read within one iteration).
- **Per-oracle emission is tiered** (emission cost is oracle-specific):
  - **Tier 1 — beachhead: erc4626** publishes `price_post − price_pre` at the point it currently discards it (147). Small, in-scope.
  - Tier 1 — `snapshot_delta` (slot delta already in result — publishable) and `temporal_skim` (divergence>threshold — already computed).
  - **Tier 2 — generic Echidna-boolean invariants** (`sum == total`, Alex's exact case): the property must be *rewritten* to return a signed magnitude. Follow-on, not beachhead.

## Consumption — `apply_divergence_secant` (path b, guided/skew)
- Clone of `apply_ledger_secant`: target = `read_divergence()` instead of `read_ledger_objective()`; reuses `secant_step_signed` (peak-find) + `secant_step_geometric` (027) — the divergence landscape of truncation/rounding is **cliff-shaped** (floor discontinuities), which is exactly what the log-space secant was built for.
- **Rejected: path (c) `DivergenceFeedback` (scheduler vote).** A second feedback voting on `ORACLE_MAG` alongside `TokenBalanceFeedback`'s `best_inflow` vote makes the two gradients **compete in one scheduler → oscillation**. The mutator two-stage secant has only ONE voter (TokenBalance) → no oscillation. This is the (b) vs (c) skew-vs-havoc call, decided for (b) on the handoff argument below.

## THE HANDOFF (the sharpened part — resolves the oscillation gap)
A **one-bit objective-mode switch inside the mutator**, with the "lock the path" done by machinery already shipped this session:

1. **Feed:** during Phase 1 the divergence secant probes the setup input. Emit a `PromotionCandidate` for the setup step so **026-A promote→scheduler energy** retains it (else under-fed — the same reason 026-A exists). Profit is flat here → `TokenBalanceFeedback` is silent → nothing competes.
2. **Gate:** on divergence peak (`secant_step_signed` slope flattens / converges), **pin the setup step as a Prime** → **024 post-hoc→planner socket re-seeds it every plan** (the "hold") → flip the secant's read target `read_divergence()` → `read_ledger_objective()`.
3. **Extract:** Phase 3 (existing extraction secant + `TokenBalanceFeedback`) climbs profit on the locked prefix.

Sequential, single-voter, single switchable objective — no competing scheduler gradient. Composes 024 (pin/re-seed) + 026-A (retain energy) + 027 (cliff landscape) + the ledger-secant template. Feature 029's handoff is buildable *because* those exist.

## Success Criteria
1. `read_divergence()` returns a non-zero magnitude on the erc4626 beachhead where the oracle previously only emitted a boolean bug. ✓ unit-testable at the publish site.
2. `apply_divergence_secant` peak-finds `read_divergence()` (reuses signed + geometric secants); no CMP_MAP dependency.
3. On divergence peak, the setup step is pinned as a Prime and the objective flips to profit (one mode bit) — verified by state transition.
4. **No scheduler oscillation:** exactly one feedback votes at a time (divergence phase profit-silent; extraction phase divergence-locked).
5. **Regression:** with no divergence published (Generic/0), power and secant behaviour byte-identical to pre-029.
6. **End-to-end (validation):** on an ERC4626/rounding target, a divergence that produces no profit at flat params is maximized (Phase 1), pinned, and then extracted (Phase 3) — the path that was invisible pre-029.

## Out of Scope
- Tier-2 generic-invariant magnitude (magnitude-valued property rewrite) — follow-on once the beachhead proves the loop.
- The (c) `DivergenceFeedback` scheduler-vote path — rejected (oscillation).
- ② `arbitrary_call` MW and Proxy ⑤ — below 029 on the board.

## Open checkpoints (verify in plan)
- **29.1** exact mutator integration: is `apply_divergence_secant` a sibling driver in the same mutate pass as `apply_ledger_secant`, gated by the mode bit? Where does the mode bit live (a `DivergenceSecantState` metadata, mirroring `ValueSecantState`)?
- **29.2** the peak→pin trigger: reuse `maybe_pin_aposteriori_lever` with a new `LeakClass`/kind for the divergence setup, or a dedicated pin? Confirm the 024 socket re-seeds a divergence-kind pin.
- **29.3** does `TokenBalanceFeedback` need explicit suppression during Phase 1, or is "profit flat ⇒ silent" sufficient in practice? (Success criterion 4.)
- **29.4** erc4626 publish site: publish the raw `price_post − price_pre`, or a normalized/basis-point magnitude (Alex used bps for relative sizing)? Signed (insolvent vs underpaying direction).
