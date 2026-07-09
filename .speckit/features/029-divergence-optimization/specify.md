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

## Trigger — `OPTIMIZE_THRESHOLD` (when to enter Phase 1)
An oracle fire carries a magnitude (once emitted). At the feedback fire site (feedback.rs ~296, before bug registration):
- **magnitude ≥ `OPTIMIZE_THRESHOLD`** → the bug is already material; register directly (today's behaviour, byte-identical).
- **magnitude < `OPTIMIZE_THRESHOLD`** → a *small* divergence ("off-by-one, who cares") → **route into Phase 1** to find the compound ceiling before reporting. This is Alex's escalation criterion verbatim (small rounding → optimization mode → real severity). The threshold is what distinguishes "already a finding" from "escalate first."

## Consumption — TWO gradients, phase-gated (corrects the earlier "(b) only, reject (c)")
Phase 1 needs BOTH — they optimize different axes:
- **(b) `apply_divergence_secant` — MAGNITUDE (one arg).** Clone of `apply_ledger_secant`: target = `read_divergence()`; reuses `secant_step_signed` (peak) + `secant_step_geometric` (027 — truncation/rounding divergence is **cliff-shaped**, the log-space secant's terrain). Tunes the amount knob (deposit size / vote %) toward the divergence peak.
- **(c) `DivergenceFeedback<SC>` — SEQUENCE (multi-step).** Mirror of `TokenBalanceFeedback` keyed on `bug_idx` (`best_divergence: HashMap<bug_idx, EVMU256>`); climbs which *sequence* raises the break (deposit→wait→deploy→vote; ERC4626 deposit→donate). **The secant cannot discover a sequence — only a corpus/scheduler gradient can.** So (c) is not redundant with (b); it's the sequence half.
- **Why this does NOT oscillate (corrects my over-rejection):** `TokenBalanceFeedback` is *naturally silent during Phase 1* — divergence setup deposits/donates, so attacker `best_inflow` is flat or negative → it doesn't vote. `DivergenceFeedback` has the floor in Phase 1 without competition. An explicit lock is needed only at the Phase-1→3 boundary (below): once the setup is pinned, `DivergenceFeedback` stops voting and `TokenBalanceFeedback` takes over. Mutually exclusive by phase, not by removing (c).

## THE HANDOFF (the sharpened part — resolves the oscillation gap)
A **one-bit objective-mode switch inside the mutator**, with the "lock the path" done by machinery already shipped this session:

1. **Feed (Phase 1):** `DivergenceFeedback` (c) climbs the *sequence* gradient while `apply_divergence_secant` (b) tunes the *magnitude*. `TokenBalanceFeedback` is naturally silent (profit flat/negative during setup) → the divergence gradient owns the scheduler uncontested. Emit a `PromotionCandidate` for the setup step so **026-A promote→scheduler energy** also retains it.
2. **Gate (1→3 boundary):** on divergence peak (`secant_step_signed` slope flattens / `best_divergence` plateaus), **pin the setup step as a Prime** → **024 post-hoc→planner socket re-seeds it every plan** (the "hold") → **`DivergenceFeedback` stops voting** and the secant's read target flips `read_divergence()` → `read_ledger_objective()`. This lock is the ONE explicit anti-oscillation mechanism.
3. **Extract (Phase 3):** existing extraction secant + `TokenBalanceFeedback` climb profit on the locked prefix.

**One active voter per phase** (DivergenceFeedback in P1 / TokenBalance in P3), made mutually exclusive by the pin-lock — not by dropping (c). Composes 024 (pin/re-seed) + 026-A (retain energy) + 027 (cliff landscape) + the ledger-secant template. Feature 029's handoff is buildable *because* those exist.

## Success Criteria
1. `read_divergence()` returns a non-zero magnitude on the erc4626 beachhead where the oracle previously only emitted a boolean bug. ✓ unit-testable at the publish site.
2. `apply_divergence_secant` peak-finds `read_divergence()` (reuses signed + geometric secants); no CMP_MAP dependency.
3. On divergence peak, the setup step is pinned as a Prime and the objective flips to profit (one mode bit) — verified by state transition.
4. **No scheduler oscillation:** exactly one feedback votes at a time (divergence phase profit-silent; extraction phase divergence-locked).
5. **Regression:** with no divergence published (Generic/0), power and secant behaviour byte-identical to pre-029.
6. **End-to-end (validation):** on an ERC4626/rounding target, a divergence that produces no profit at flat params is maximized (Phase 1), pinned, and then extracted (Phase 3) — the path that was invisible pre-029.

## Out of Scope
- Tier-2 generic-invariant magnitude (magnitude-valued property rewrite) — follow-on once the beachhead proves the loop.
- ② `arbitrary_call` MW and Proxy ⑤ — below 029 on the board.

## Open checkpoints (verify in plan)
- **29.1** exact mutator integration: is `apply_divergence_secant` (b) a sibling driver in the same mutate pass as `apply_ledger_secant`, gated by the mode bit? Where does the mode bit live (a `DivergenceSecantState` metadata, mirroring `ValueSecantState`)?
- **29.2** the peak→pin trigger: reuse `maybe_pin_aposteriori_lever` with a new `LeakClass`/kind for the divergence setup, or a dedicated pin? Confirm the 024 socket re-seeds a divergence-kind pin.
- **29.3** the phase-lock: is "profit flat ⇒ `TokenBalanceFeedback` silent in P1" empirically sufficient, or does the pin also need to explicitly gate `DivergenceFeedback` off in P3? (The one place oscillation could still bite.)
- **29.4** erc4626 publish site: raw `price_post − price_pre` vs normalized/bps magnitude (Alex used bps for relative sizing); signed (insolvent vs underpaying direction).
- **29.5** `DivergenceFeedback` (c) chain order in `evm_fuzzer.rs` — before `TokenBalanceFeedback`; confirm the scheduler-vote pattern (`HasVote`) mirrors `TokenBalanceFeedback` cleanly for a `bug_idx`-keyed high-water.
- **29.6** `OPTIMIZE_THRESHOLD` value/units — per-oracle (bps) or absolute? And confirm the ≥threshold path is byte-identical to today's direct registration.
