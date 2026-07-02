# Plan — Feature 015 — Reflexive Lever Pipeline (Promote → Locate → Amplify)

**Status:** APPROVED (Skyler, 2026-07-02) — proceeding to tasks.md
**Checkpoints resolved:** 15.1 ✓, 15.2 ✓, 15.3 ✓, 15.4 ✓, 15.5 ✓, 15.6 ✓, 15.7 ✓
**Last updated:** 2026-07-02

**Decisions locked (2026-07-02):**
- **CLI deps — Option A (auto-enable + warn):** `--reflexive-lever` auto-enables
  `campaign_orchestrator` + the realized-value objective; a loud warning if the user
  explicitly disables either while keeping the lever on. (Minimum friction; the lever is
  inert without them.)
- **Amplify objective — Option A (raw-inflow secant / net-ETH selector):** the secant
  climbs the cheap raw attacker-inflow ceiling in its probe loop (no engine call in the hot
  path); net-ETH valuation confirms the survivor at the finish line only. Same precision,
  fraction of the exec/sec cost.

---

## Architecture Decision

No new trait and no new Cargo feature. 015 is an **extension of three existing systems**,
gated by one runtime `Config` bool (`reflexive_lever`), mirroring how 011 Part A shipped as
the runtime bool `impact_eth_gradient` (`config.rs:69`, `evm_fuzzer.rs:426`):

- **Part 1 Promote** — extends the **campaign planner** (Feature 003). A promoted lever is
  an ordinary `ConciseEVMInput` inserted into `CampaignSequence.steps` between prime and
  exploit; a `#[serde(default)] promoted: Vec<usize>` field tags which step indices are
  levers (pinned, amount-anchored). Two triggers feed it:
  - **1a a-priori** — a new `ExploitClass::ReflexiveSkew` scored in `TopologyReport::analyze`
    (`topology.rs`) and recognized from preset selectors (`add_liquidity` /
    `remove_liquidity_imbalance`) in `pick_prime_and_exploit` (`campaign_planner.rs:198`).
  - **1b a-posteriori** — (Phase 2) promote a runtime belly call when the per-call attacker
    `erc20_transfer` delta signals it (needs the new per-call snapshot; see 15.5).
- **Part 2 Locate** — a **ledger-sensitivity sweep** in the mutator: perturb each arg of the
  promoted step, keep the arg with max |Δobjective/Δarg|. No taint dependency (013/014 both
  unbuilt — 15.6).
- **Part 3 Amplify** — a new **secant "Application"** reusing the `SecantPhase{Idle,Probe1,
  Probe2}` machine (`feedback.rs:696`), driven by the per-execution realized-value objective
  instead of CMP_MAP. Signed derivative-root secant for the interior profit peak.

## New Types

| Type | Purpose | impl_serdeany? |
|------|---------|---------------|
| `CampaignSequence.promoted: Vec<usize>` (field, not a type) | Step indices that are promoted, pinned, amount-anchored levers. `#[serde(default)]` — byte-compatible with existing campaigns (same idiom as `warps`). | n/a (host struct already serde) |
| `LedgerSecantState { phase: SecantPhase, pin_step: usize, arg_idx: usize, x1: u128, g1: i128, prev_slope: Option<i128>, cooldown: u32 }` | Per-corpus amplify state. `pin_step` pins the promoted frame step (not a CMP idx); `g1`/`prev_slope` are **signed** (profit derivative changes sign at the peak); `prev_slope` caches the previous slope so secant-on-derivative stays 2 probes / 3 phases. | **yes** (mirror `ValueSecantState`) |
| `ExploitClass::ReflexiveSkew` (enum variant) | A-priori archetype class for `TopologyReport.ranked`. | n/a (`TopologyReport` already `impl_serdeany`) |
| `fn secant_step_signed(x1: u128, g1: i128, g2: i128, delta: u128) -> Option<u128>` | Pure signed sibling of `secant_step` (`mutator.rs:208`) that root-finds the **derivative** (peak), not the raw distance. Unit-testable in isolation. | n/a (free fn) |
| `static LEDGER_OBJECTIVE` (global scalar, mirrors `CMP_MAP`) | The amplify secant reads the per-execution objective at probe boundaries the same way it reads `CMP_MAP` today; `TokenBalanceFeedback` publishes it. | n/a (global) |

## Registration

- **corpus_initializer.rs** — insert empty `LedgerSecantState` metadata at init (alongside
  the existing secant states); `TopologyReport::analyze` (already called at
  `corpus_initializer.rs:626`) gains the `ReflexiveSkew` scoring rule.
- **evm_fuzzer.rs** — at the `TokenBalanceFeedback::new` site (`:426`), when
  `config.reflexive_lever` is on, the feedback publishes its per-execution objective into
  `LEDGER_OBJECTIVE` after each execution (the write mirrors how the cmp middleware writes
  `CMP_MAP`). No new feedback registered — extends the existing one.
- **mutator.rs** — new `apply_ledger_secant` (gated `if config.reflexive_lever && campaign
  has a promoted step`), following the `apply_value_secant` idiom (`:367`); runs the Locate
  sweep once to fix `arg_idx`, then the signed secant. **Does NOT inherit the 009 concolic
  requeue** (`requeue_for_concolic`, `:228`) — a flat ledger slope means "not the lever,"
  not "hand to SMT" (Curve's Newton invariant chokes concolic — 15.7 risk).

## CLI

- **Flag:** `--reflexive-lever` (bool; Phase 2 adds `--reflexive-lever-adaptive` for the
  a-posteriori trigger if we want it separately gated).
- **Config field:** `reflexive_lever: bool` (add to `config.rs` near `impact_eth_gradient:69`
  and `campaign_orchestrator:106`).
- **Conflicts with:** none (checked `config.rs:62-113`; names `reflexive*` unused).
- **Dependency:** implies `campaign_orchestrator` (promotion has no meaning without the
  planner frame) and turns on the realized-value objective path (reuses `impact_eth_gradient`
  machinery). Plan: `--reflexive-lever` auto-enables both if unset, warns if explicitly off.

## Interaction with Existing Features

| Feature | Interaction |
|---------|------------|
| 001 Value Capture | Reuses `StepLinkage` (`input.rs:38`) to anchor the promoted lever's amount to a captured value if needed. No change to value_capture. |
| 002 Engagement Seeder | None. |
| 003 Campaign Orchestrator | **Extended** — promotion inserts one lever step into the planner frame; hard prerequisite. |
| 004 Ghost Identities | None. |
| 005 Temporal Skimming | Orthogonal; a promoted step could carry a `warps` entry but not required for yDAI. |
| 009 Concolic/Secant | **Reuses** the `SecantPhase` machine + `secant_step` pattern; **explicitly does not** inherit the concolic requeue on the ledger path. |
| 011 Impact Max | **Absorbs.** Part A objective (built, `feedbacks.rs:198-416`) becomes the amplify driver; Part B (unbuilt) is realized as Part 3. |
| 013/014 Taint | Not a dependency (both Planning). Future precision upgrade for Part 2. |

## Performance

- **When disabled (`reflexive_lever=false`):** zero code path — planner promotion branch
  skipped, `apply_ledger_secant` not called, `LEDGER_OBJECTIVE` never published. Campaign
  structure byte-identical to today (regression floor).
- **When enabled:** +1 promoted step per reflexive campaign; Locate sweep = one execution
  per arg of the promoted step (bounded, one-time per corpus entry, cached in `arg_idx`);
  Amplify = 2 probe executions per secant episode (unchanged from existing secant cost).
  Watch the 3.5GB ceiling — the sweep is the only new multi-exec cost; bound it to the
  promoted step's args only (not the whole frame).

## Test Plan

- **Unit test:**
  - `secant_step_signed` on a synthetic hump (g>0 then g<0) returns an x near the peak;
    flat/monotone returns `None`. (Pure, no EVM — mirrors the existing `secant_step` tests.)
  - `CampaignSequence` with `promoted` round-trips through serde and an old (no-`promoted`)
    JSON deserializes via `#[serde(default)]` (backward-compat proof).
- **Integration test:** yDAI preset (`ydai_only.json`, selectors incl. `add_liquidity`
  0x4515cef3 / `remove_liquidity_imbalance` 0x9fdaea0c) with `--reflexive-lever`:
  assert (a) the emitted campaign contains a promoted `add_liquidity` step between prime and
  exploit, and (b) the realized-value objective shows a positive gradient across amplify
  episodes where the 2-step frame shows none. (The SC-6 "prize" criterion.)
- **Regression test:** a non-reflexive target with the flag off — assert campaign structure
  and bug set byte-equivalent to the pre-015 binary (constitution rule 2).

## Build Staging (task ordering)

Phase 1 — **ships yDAI, zero new instrumentation** (all objective/accounting already exists):
  1. Promote 1a (archetype: `ExploitClass::ReflexiveSkew` + preset-selector recognition +
     `promoted` field + planner insertion).
  2. Locate (sensitivity sweep, fixes `arg_idx`).
  3. Amplify (`LedgerSecantState` + `secant_step_signed` + `LEDGER_OBJECTIVE` publish +
     `apply_ledger_secant`).

Phase 2 — **generalization to novelty** (adds the per-call snapshot from 15.5):
  4. Promote 1b (a-posteriori: per-call attacker `erc20_transfer` delta snapshot in the
     executor loop → promote the emitting belly call).

Each task is independently testable behind the runtime flag with the 2-step regression as
the floor.
