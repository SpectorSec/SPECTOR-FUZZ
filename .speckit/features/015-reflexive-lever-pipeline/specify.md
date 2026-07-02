# Feature 015 — Reflexive Lever Pipeline (Promote → Locate → Amplify)

**Status:** Investigating — all checkpoints (15.1–15.7) RESOLVED with source evidence; awaiting sign-off to advance to plan.md
**Owner:** Skyler
**Last updated:** 2026-07-02

---

## Overview

SPECTOR-FUZZ cannot discover **reflexive-body** exploits — the class where the
manipulation is a *transition* (skew → read → unskew) interleaved into every cycle,
not a state that can be frozen into the fork. yDAI is the canonical case: the depth-1
ground truth (`calls.db`) is
`[deposit → earn → add_liquidity → withdrawAll → remove_liquidity_imbalance] ×5`, where
`add_liquidity` / `remove_liquidity_imbalance` skew the Curve StableSwap invariant, the
vault reads the skewed price, and the unwind pockets the difference.

Tracing the causal chain (recorded in `project_oracle_flow_model.md`) eliminated
vocabulary (earn() added), the prime-as-state model (corrected to reflexive), and capital
seed (bumped 1M→1B, no gradient). What remains needs **three cooperating pieces that today
are either missing or specified-but-never-wired**:

1. **Promote** — the manipulation lever (`add_liquidity`) only appears in the runtime
   belly (`get_next_call`, `mutator.rs:635`); it is never in the tunable campaign frame
   (planner emits only `Borrow→prime→exploit`: `campaign_planner.rs` 104/117-118/156-167).
   **No promotion mechanism exists** (verified: empty grep `promote|hoist|capture|belly|
   reflexive` in `planner/` + `mutator.rs`).
2. **Locate** — even with the lever in the frame, nothing identifies *which arg* is the
   value knob. The secant rotates over all args blindly (`mutator.rs:497`); there is no
   ledger-analog of `cmp_argmin`.
3. **Amplify** — nothing turns the knob toward the profit peak. Correction from
   investigation: **011 Part A is actually BUILT** — `TokenBalanceFeedback` carries
   `eth_gradient`, `best_eth_total`, `net_realized()`, and live engine valuation
   (`value_token_inflow_eth`) at `feedbacks.rs:198-416`. So the realized-ETH *objective
   already exists and is computed every execution*. What is missing is the *actor*: 011
   Part B (the amplifier that moves an amount) was **Specified but never built** (verified:
   empty grep `blood|amplif|ladder|scale_up`). 015 builds the actor and points it at the
   already-existing objective.

### Why this is ONE build, not a dependency on scattered specs

The initial framing scoped 015 narrowly ("promotion only; consume 011/013/014"). That is
wrong in practice: **011 Part A/B and the taint locator are scattered specs that were
never wired into the run loop.** A thin promotion layer resting on unbuilt amplifier +
in-progress taint depends on things that don't move — so it wouldn't move either. To move
the needle on yDAI, 015 must **own and ship the full pipeline end-to-end**. The scattered
specs are *realized* by 015; they inherit their working form from this build.

This does **not** create a parallel system (constitution rule 3). 011 Part B never
produced code; 015 *implements* the amplifier it described, as a LibAFL `Mutator`/stage.
013/014 taint, where it exists and is queryable, is *used* by the locator — not
re-implemented.

### Architecture — three parts, all owned here

```
Part 1: PROMOTE  (novel; the belly gap)
  one mechanism, two triggers:
    a-priori  = archetype match         → known reflexive classes (yDAI/Harvest Curve-skew)
    a-posteriori = ledger sensitivity   → novel reflexive levers (generalization)
  effect: hoist the belly lever into the campaign frame as a pinned, amount-anchored step
      │
      ▼
Part 2: LOCATE  (absorbs the "value-lever locator")
  attribution: which arg of the promoted step is the value knob
    primary  = 013/014 taint sink-attribution (reuse where built + queryable)
    fallback = ledger-sensitivity sweep (perturb each arg, keep max |dLedger/darg|)
      │
      ▼
Part 3: AMPLIFY  (absorbs 011 Part A + Part B; realizes them)
  magnitude: turn the located knob toward the interior profit peak
    objective = net-realized ETH ledger (011 Part A, wired into the tuner, not just ranking)
    tuner     = ledger-secant: reuse Idle→Probe1→Probe2 machine, but
                repointed from CMP_MAP → ledger; SIGNED i128; secant-on-derivative
                (interior peak, not a root) with cached slope (2 probes/step);
                trust-region clamp; pin the promoted frame across probes;
                NO concolic requeue (SMT chokes on Curve's Newton-iteration invariant)
```

**Correction that stays in force:** the locator generalizes *attribution*, not
*discovery*. Generalization to novel exploits comes from Part 1's a-posteriori trigger
(promote-on-ledger-response), not from the locator. Promotion is a single mechanism with
two triggers, not two features.

## Why This Matters

- **Yearn yDAI (2020, ~$11M / our 69× baseline family)** — reflexive Curve-skew read;
  undiscoverable today because the `add_liquidity` lever never enters the tunable frame.
- **Harvest Finance (2020, ~$34M)** — same shape (`add_liquidity` skews Curve virtual
  price, vault reads it, unwind pockets delta). One a-priori Curve-skew archetype covers
  both.
- **Novel reflexive AMM manipulations** — any protocol reading a pool-derived price
  mid-sequence. Part 1's a-posteriori trigger promotes the lever with no registered
  pattern — the generalization path.

## Success Criteria

Worth building if and only if:

1. **Promote:** a runtime belly call that moves the net-realized ledger is materialized as
   a pinned, amount-anchored step in the campaign frame — verifiable in the emitted
   structure (a promoted `add_liquidity` step appears in yDAI runs where the frame is
   2-step today).
2. **Two triggers:** promotion fires independently from (a) archetype match with no ledger
   signal, and (b) ledger response with no registered archetype.
3. **Locate:** the promoted step's value-knob arg is identified (taint or sensitivity
   sweep), and the amplifier tunes *that* arg — not a blind rotation.
4. **Amplify:** the ledger-secant moves the located amount toward a higher net-realized
   ETH, backing off on revert; realized-ETH ranking (011 Part A) selects survivors.
5. **Regression-safe:** flag off ⇒ campaign structure and results byte-equivalent to today
   (constitution rule 2).
6. **The prize:** on yDAI, the promoted+located+amplified frame yields a positive
   net-realized-ETH gradient where the 2-step frame yields none.

## Absorbs / Supersedes

| Prior spec | Fate under 015 |
|---|---|
| **011 Part A** (realized-ETH gradient) | Realized here as the amplifier's *objective* (wired into the tuner, not only ranking). 011 Part A marked superseded-by-015. |
| **011 Part B** (blood-in-water amplifier) | Realized here as Part 3 (ledger-secant). 011 Part B marked superseded-by-015. |
| **009** (concolic/secant dispatch) | Reused: the Idle→Probe1→Probe2 secant machine is repointed to the ledger. 009's concolic *requeue* is explicitly NOT inherited on this path. |
| **013/014** (taint models) | Reused where built + queryable, as Part 2's primary attribution source. Not re-implemented. |

## Out of Scope

- **Non-reflexive exploit classes** — the 2-step frame already serves them; the whole
  pipeline is bypassed when the flag is off (zero code path).
- **N-step generic planning** — explicitly NOT extending the planner to arbitrary depth
  (oracle-flow model: "DON'T extend planner to N-steps"). Promotion adds *one* identified
  lever step, bounded, not open-ended search.
- **A new taint engine** — Part 2 uses 013/014 or a coarse sensitivity fallback; it does
  not build taint infrastructure.

## Investigation Checkpoints

### Checkpoint 15.1 — The belly gap is real and singular  ✓ RESOLVED
**Files:** `src/evm/planner/campaign_planner.rs`, `src/evm/mutator.rs`
**Evidence:** Planner emits only `Borrow→prime→exploit` (104/117-118/156-167); belly is
runtime `get_next_call` (`mutator.rs:635`); secant bails without orchestrator, rotates
frame args only (469-472,497); no promotion exists (empty grep). **The lever is
unreachable by any tuner.**

### Checkpoint 15.2 — 011 A/B are unbuilt, so absorb (not depend)  ✓ RESOLVED
**Files:** `.speckit/features/011-impact-maximization/*`, `src/**`
**Evidence:** 011 Part B **Specified, not built** (empty grep `blood|amplif|ladder|
scale_up`); Part A is ranking-only. Neither is wired to move an amount. **015 builds them
as Part 3.**

### Checkpoint 15.3 — A campaign step can carry a promoted, pinned, amount-anchored lever  ✓ RESOLVED
**Files:** `src/evm/input.rs`, `src/evm/planner/campaign_planner.rs`
**Evidence:** Steps are **not a restricted enum** — `CampaignSequence.steps` is
`Vec<ConciseEVMInput>` (`input.rs:50-61`). A promoted lever is simply another
`ConciseEVMInput` inserted into the vec; the executor already iterates it. The `warps:
Vec<(usize,u64)>` field, added later with `#[serde(default)]` "for backward compatibility
with Features 001-004", is the **exact precedent** for tagging promoted steps: add a
`#[serde(default)] promoted: Vec<usize>` (step indices that are pinned/amount-anchored
levers) with zero impact on existing campaigns. `StepLinkage` (`input.rs:38-46`) already
routes an output to a later step's param — reusable to anchor the lever's amount. Insertion
slot: between `prime` and `exploit` in `plan_campaign_sampled` (push order
`campaign_planner.rs:158/164/167`). **No new enum, no parallel system.**

### Checkpoint 15.4 — A-priori trigger: registry exists to hang Curve-skew on  ✓ RESOLVED
**Files:** `src/evm/topology.rs`, `src/evm/presets/mod.rs`, `src/evm/planner/campaign_planner.rs`
**Evidence:** Two substrates, both feeding `pick_prime_and_exploit`:
(1) **Onchain** — `TopologyReport{families, ranked}` (`topology.rs:141`, `impl_serdeany`,
stored as metadata at `corpus_initializer.rs:649` "so campaign planners can" read it), with
an `ExploitClass` ranking consumed by the planner (`campaign_planner.rs:9,125,162`). Adding
a `ReflexiveSkew` `ExploitClass` + a scoring rule in `TopologyReport::analyze` is the
a-priori hint.
(2) **Offchain** — the preset `ExploitTemplate{exploit_name, function_sigs, calls}`
(`presets/mod.rs:39-42`) already carries selectors; `preset_selectors` flows into
`pick_prime_and_exploit` (`campaign_planner.rs:85-90`). Recognizing
`add_liquidity`/`remove_liquidity_imbalance` selectors in the preset is the offchain hint.
**A small `ExploitClass` extension, not a new registry.**

### Checkpoint 15.5 — Ledger attribution granularity  ✓ RESOLVED (with design constraint)
**Files:** `src/evm/feedbacks.rs`, `src/evm/onchain/flashloan.rs`
**Evidence:** The realized-ETH objective (`net_eth`) is computed **per whole execution**
(`feedbacks.rs:389`) from sequence-level `flashloan_data.owed/earned` + summed attacker
transfers. There is **no per-call attribution today**. BUT the underlying accumulators are
live per-call: `earned += value_transfer` fires on each CALL opcode in `on_step`
(`flashloan.rs:412`), `owed` on txn value (`analyze_call:354`). **Constraint discovered:**
only *native-ETH* (earned/owed) is cheap per-call; yDAI's profit is *token-denominated*
(USDC/DAI) and engine-valued only at execution end — so a per-call ETH-value hook would
require per-call engine valuation (too costly). **Resolution:** the a-posteriori trigger
keys on the cheap per-call signal available now — attacker `erc20_transfers` deltas (raw
units) attributed to the emitting `get_next_call` boundary — not net-ETH. Precise ETH
ranking stays at the per-execution feedback for survivor selection. This splits cleanly:
**Amplify needs only the per-execution objective (already exists); only the a-posteriori
Promote trigger needs the new per-call transfer-delta snapshot** (piggybacks the executor
loop, no revm fork — rule 4 satisfied).

### Checkpoint 15.6 — Locate: taint not available; sensitivity sweep is the path  ✓ RESOLVED
**Files:** `.speckit/features/013-*/specify.md`, `014-*/specify.md`, taint src
**Evidence:** Both 013 and 014 are **Status: Planning** (not built). Existing taint code
(`cmp_linearity.rs`, 009a) is a linear/non-linear *classifier*, not arg→sink attribution.
**Resolution:** 015 Part 2 cannot depend on taint sink-attribution; it ships the
**ledger-sensitivity sweep** (perturb each arg of the promoted step, keep max
|Δobjective/Δarg| using the per-execution objective from 15.5) as the working locator.
Taint remains a *future* precision upgrade when 013/014 land — not a dependency.

### Checkpoint 15.7 — Amplify: the secant machine repoints to the ledger cleanly  ✓ RESOLVED (with wiring note)
**Files:** `src/evm/mutator.rs`, `src/feedback.rs`
**Evidence:** The phase machine is `SecantPhase{Idle,Probe1,Probe2}` with
`ValueSecantState{phase,pin_idx,pin_pc,x1,d1,cooldown}` / `CalldataSecantState{…,cursor,…}`,
both `impl_serdeany!` (`feedback.rs:696-739`); `secant_step(x1,d1,d2,delta)` is a pure,
objective-agnostic u128 root-finder (`mutator.rs:208`). Repoint = a new **LedgerSecantState**
(same shape) + a **signed** `secant_step_signed(x1, g1:i128, g2:i128, delta)` targeting the
*derivative* root (interior peak) with a cached previous slope (2 probes/3 phases — no extra
phase). Each probe is already its own execution, so reading the **per-execution objective**
(15.5) at probe boundaries aligns exactly; the "reset pinned CMP idx + read CMP_MAP" step
swaps for "read the execution's objective". Pin = the promoted frame's stable step index
(15.3). **Wiring note for plan.md:** the mutator's secant currently reads a global (CMP_MAP)
that a middleware writes during execution; the ledger analog is to have `TokenBalanceFeedback`
(or a thin middleware) publish the per-execution objective into a global/metadata the
ledger-secant reads at probe boundaries — mirroring CMP_MAP exactly. Engine-valued gross is
NOT needed in the mutator hot path if the amplify objective is the raw attacker-inflow ceiling
(monotone proxy); net-ETH stays the survivor selector. Resolve which (raw-inflow vs published
net-ETH) is the amplify objective in plan.md.

## Risks

- **Pinning / slope noise:** promotion changes structure; the amplifier's probe pair must
  see a *pinned* promoted frame or the profit slope is drift. Part 1 and Part 3 must share
  the pin (coordinate with 008/009 secant pinning).
- **Over-promotion:** promoting on any twitch floods the frame and blows the search space
  on a 3.5GB box. Trigger must be thresholded; **one** promoted lever per frame.
- **Attribution staleness under rotation:** cached-slope amplifier goes stale if the active
  coordinate rotates (DeepSeek). Part 2 must *fix* the lever arg so Part 3 isn't chasing a
  moving coordinate.
- **Concolic mis-route:** a promoted-but-unflippable lever must not fall into 009's
  concolic requeue (SMT chokes on Curve's Newton invariant). The ledger path must not
  inherit that fallback.
- **Three-part surface:** building all three at once is more code than a single oracle.
  Mitigate by strict task ordering (Promote → Locate → Amplify), each independently
  testable, feature-flagged, with the 2-step regression as the floor.

## Open Questions

- A-priori trigger home: preset layer (offchain, user-declared) vs topology intelligence
  (auto-detected onchain)? 15.4 decides.
- Does yDAI need the lever to *repeat* (×5), or does a single promoted step with a tuned
  amount suffice while `get_next_call` supplies repetition? (Suspect single step suffices.)
- Does promotion slot before/after `pick_prime_and_exploit`, and can it reuse that
  function's value-flow ordering instead of a new selector heuristic?
