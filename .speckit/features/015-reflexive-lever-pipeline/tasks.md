# Tasks — Feature 015 — Reflexive Lever Pipeline (Promote → Locate → Amplify)

**Status:** In Progress — PHASE 1 CODE-COMPLETE (T1–T9 ✅) + PHASE 2/T10 CODE-COMPLETE (a-posteriori promote ✅), all unit tests green. Live yDAI-fork validation (9b/9c) + live novel-target discovery are the user's Lane-A steps.
**Last updated:** 2026-07-02
**Decisions locked:** CLI deps = auto-enable+warn (A); Amplify objective = raw-inflow secant / net-ETH selector (A).

### Progress log (2026-07-02)
- **T1 ✅** `CampaignSequence.promoted: Vec<usize>` (`#[serde(default)]`); mutator round-trip test extended, backward-compat asserted.
- **T2 ✅** `ExploitClass::ReflexiveSkew` + `analyze()` scoring (88 for AMM×{ERC4626|Lending|Staking}); no-op oracle-activation arm.
- **T3 ✅** A-priori Promote wired: `maybe_promote_lever` + lever inserted between prime & exploit, index recorded in `promoted`. **Wiring gap found & fixed:** the Curve selectors (`0x4515cef3`/`0x9fdaea0c`) are NOT in `PRIME_SELECTORS`, so keying on `prime_targets` could never fire. Added a dedicated `CampaignTargetCache.reflexive_targets` field (`#[serde(default)]`), scanned independently of the prime/exploit allowlists and read ONLY on the reflexive path → off-path behavior byte-identical.
- **T4 ✅** `Config.reflexive_lever` + `--reflexive-lever` CLI flag; auto-enables `campaign_orchestrator`+`impact_eth_gradient` (field-level OR at both onchain & offchain literals) with `warn!` blocks on both entry paths. Added `tracing::warn` import.
- **T9 (partial) ✅** `test_reflexive_lever_promoted_into_frame` + `test_reflexive_lever_inert_when_disabled` — both green; full planner module 9/9 green (no regressions).
- `cargo check --bin spectorfuzz` clean. Amplify machinery (T5–T8) not yet started.

### Progress log — AMPLIFY (2026-07-02)
- **T5 ✅** `LEDGER_OBJECTIVE` = thread-local `Cell<u128>` in feedbacks.rs + `publish/read_ledger_objective()`. `TokenBalanceFeedback` gained a `reflexive_lever` flag; publishes summed raw attacker inflow on EVERY execution (reverts/zero ⇒ 0) BEFORE early returns, gated on the flag (off-path never written). Added `evmu256_to_u128_sat_fb`. Constructor arity updated (evm_fuzzer.rs call site + the `eth_gradient_off_is_inert` test).
- **T6 ✅** `secant_step_signed(x1,g1,g2,delta)` in mutator.rs — interior-peak (derivative-root) finder; `None` on flat/monotone/trough. NOT cmp-gated (ledger secant is cmp-independent). 2 unit tests green.
- **T7 ✅** `LedgerSecantState` in feedback.rs (`impl_serdeany!`, auto-registered): phase, pin_step, n_args, locate_cursor, best_sens/best_arg, located, arg_idx, x1, o1, prev_x1, prev_slope, cooldown. NO corpus_initializer insert — siblings (Value/CalldataSecantState) are lazy `unwrap_or_default`; followed that pattern (deviation from tasks.md's "insert at init", which had no real precedent).
- **T8 ✅** `apply_ledger_secant` + `read/write_step_arg_u128` free fns (mutator.rs). Gate: `reflexive_lever` && campaign has a promoted step with tunable args. LOCATE = rotate cursor over the step's args, keep max |Δledger/Δarg| → cache arg_idx. AMPLIFY = Idle→Probe1→Probe2 reads LEDGER_OBJECTIVE at probe boundaries, computes local slope; `+→−` bracket ⇒ secant_step_signed peak, else trust-region march. NO requeue_for_concolic. Wired into mutate() at 40% prob, not cmp-gated, self-gating. Clone-per-iteration contract mirrors apply_value_secant (state in metadata; absolute arg writes on each clone).
- **T9 ✅** unit: `promoted` populated round-trip, `LedgerSecantState` round-trip, `secant_step_signed` peak/none, plus the promote-path tests. `cargo test --lib` = only 7 env failures (live-RPC endpoint tests + missing `/tmp/campaign_test/out` bytecode fixture) — all pre-existing & unrelated (they panic on network/missing-file before any 015 code). 9b/9c (live yDAI-fork gradient / regression byte-diff) need the fork run = user's Lane-A step.

**PHASE 1 CODE-COMPLETE.** Whole binary + all touched modules compile clean; new unit tests green. NEXT = Phase 2 / T10 (a-posteriori promote), or the user's live yDAI-fork validation.

Build order is the data dependency: Promote produces the tunable step → Locate names its
knob arg → Amplify turns it. Each task is independently testable behind `--reflexive-lever`;
the 2-step campaign (flag off) is the regression floor at every step.

---

## PHASE 1 — ships yDAI end-to-end, zero new instrumentation

## Task 1 — `promoted` field on CampaignSequence
**Files:** `src/evm/input.rs`
**What:** Add `#[serde(default)] pub promoted: Vec<usize>` to `CampaignSequence` (after
`warps`, `input.rs:60`). Step indices marked here are pinned, amount-anchored levers.
Follow the `warps` idiom exactly (doc comment noting backward compatibility).
**Done when:** Compiles; a serde round-trip test (Task 9a) shows an old campaign JSON with no
`promoted` key deserializes to an empty vec.
**Blocks:** Task 3, Task 8

---

## Task 2 — `ExploitClass::ReflexiveSkew` + topology scoring
**Files:** `src/evm/topology.rs`
**What:** Add a `ReflexiveSkew` variant to `ExploitClass`; in `TopologyReport::analyze`
(`topology.rs:~147-202`) score it when the family set / selectors show an AMM-skew shape
(pair present + a deposit/withdraw vault family). Emit it in the ranked list and the
`info!("Ranked attack surface")` print (`:213`).
**Done when:** Compiles; on the yDAI target the ranked surface log lists `ReflexiveSkew`.
**Blocks:** Task 3

---

## Task 3 — A-priori Promote: insert the lever step in the planner
**Files:** `src/evm/planner/campaign_planner.rs`
**What:** New `fn maybe_promote_lever(cache, topology_report, preset_selectors, rand) ->
Option<ConciseEVMInput>` that fires when (a) `ExploitClass::ReflexiveSkew` is top-ranked, or
(b) preset selectors contain `add_liquidity` (0x4515cef3) / `remove_liquidity_imbalance`
(0x9fdaea0c). It builds the lever step via `build_abi_step` (`:604`). In
`plan_campaign_sampled` (`:148`) insert it between the prime push (`:164`) and exploit push
(`:167`), and record its index in `CampaignSequence.promoted`. Gated on
`config.reflexive_lever` (thread the flag in, as `temporal_skimming` already is at `:150`).
**Done when:** With `--reflexive-lever` on the yDAI preset, the emitted campaign has a
promoted `add_liquidity` step between prime and exploit and its index in `promoted`; flag off
⇒ identical 2-step frame as today.
**Blocks:** Task 8

---

## Task 4 — CLI flag + auto-enable dependencies
**Files:** `src/evm/config.rs`, CLI arg parsing (`src/bin/*` / wherever `impact_eth_gradient`
is parsed), `src/fuzzers/evm_fuzzer.rs`
**What:** Add `pub reflexive_lever: bool` to `Config` (near `:69`). Add `--reflexive-lever`
CLI flag. On parse: if `reflexive_lever` and `!campaign_orchestrator` → set it + `warn!`; if
`reflexive_lever` and `!impact_eth_gradient` → set it + `warn!`; if the user explicitly
passed `--no-...` for either while `--reflexive-lever` is on → loud `warn!` (Decision A).
**Done when:** `--reflexive-lever` alone brings up a run with orchestrator + realized-value
objective active; log shows the auto-enable warnings.
**Blocks:** Task 5, Task 8

---

## Task 5 — Publish the raw-inflow objective global
**Files:** `src/evm/host.rs` (global, beside `CMP_MAP`), `src/evm/feedbacks.rs`
**What:** Add `static LEDGER_OBJECTIVE` (u128, unsafe-global mirror of `CMP_MAP`). In
`TokenBalanceFeedback::is_interesting` (`feedbacks.rs:308-316`, where `best_inflow`/raw
inflow is already summed cheaply — **no engine call**), when `config.reflexive_lever`,
publish the summed attacker raw inflow for this execution into `LEDGER_OBJECTIVE`. Net-ETH
path (`:389`) is unchanged and remains the survivor selector (Decision A).
**Done when:** Compiles; a smoke run prints the objective advancing across executions; when
flag off `LEDGER_OBJECTIVE` is never written.
**Blocks:** Task 8

---

## Task 6 — `secant_step_signed` (derivative-root secant) + unit test
**Files:** `src/evm/mutator.rs`
**What:** Add `fn secant_step_signed(x1: u128, g1: i128, g2: i128, delta: u128) ->
Option<u128>` next to `secant_step` (`:208`): root-find the **derivative** (interior peak),
returning `None` on flat/monotone (not the lever). Unit test: synthetic hump (g1>0, g2<0) →
x between the probes near the peak; monotone → `None`.
**Done when:** `cargo test secant_step_signed` passes.
**Blocks:** Task 8

---

## Task 7 — `LedgerSecantState` metadata + registration
**Files:** `src/feedback.rs`, `src/evm/corpus_initializer.rs`
**What:** Add `LedgerSecantState { phase: SecantPhase, pin_step: usize, arg_idx: usize,
x1: u128, g1: i128, prev_slope: Option<i128>, cooldown: u32 }` with `impl_serdeany!`
(mirror `ValueSecantState`, `feedback.rs:709-718`). Insert empty instance at init in
`corpus_initializer.rs` alongside existing secant-state metadata.
**Done when:** Compiles; metadata present on fresh corpus entries.
**Blocks:** Task 8

---

## Task 8 — Locate sweep + `apply_ledger_secant`
**Files:** `src/evm/mutator.rs`
**What:** New `apply_ledger_secant<I,S>` following the `apply_value_secant` idiom (`:367`),
gated `if config.reflexive_lever && campaign has a promoted step`:
  1. **Locate (once, cache in `arg_idx`):** sweep each arg of the promoted step, perturb,
     read `LEDGER_OBJECTIVE` delta, keep max |Δobj/Δarg|.
  2. **Amplify:** run the `Idle→Probe1→Probe2` machine on the promoted step's `arg_idx`,
     reading `LEDGER_OBJECTIVE` at probe boundaries, applying `secant_step_signed` with the
     cached `prev_slope`; trust-region clamp the step; pin the promoted frame across probes.
  **Do NOT** call `requeue_for_concolic` — a flat ledger slope means "not the lever," never
  "hand to SMT" (Curve Newton invariant chokes concolic).
**Done when:** On the yDAI preset with `--reflexive-lever`, the promoted step's amount moves
across amplify episodes and the objective climbs; flag off ⇒ method never entered.
**Blocks:** Task 9

---

## Task 9 — Tests: unit, integration, regression
**Files:** `src/evm/input.rs` (9a), `tests/` or feature `validate.sh` (9b/9c)
**What:**
  - **9a unit:** `CampaignSequence` serde round-trip incl. `promoted`; legacy JSON (no key)
    → empty vec.
  - **9b integration:** yDAI preset + `--reflexive-lever` → assert promoted `add_liquidity`
    step present between prime/exploit AND objective shows a positive gradient where the
    2-step frame shows none (SC-6 prize). Net-ETH selector confirms the survivor.
  - **9c regression:** non-reflexive target, flag off → campaign structure + bug set
    byte-equivalent to pre-015 binary (constitution rule 2).
**Done when:** 9a passes in `cargo test`; 9b shows the gradient; 9c shows no diff.
**Blocks:** none (Phase 1 complete)

---

## PHASE 2 — generalization to novelty (adds the only new instrumentation)

## Task 10 — A-posteriori Promote: per-call transfer-delta snapshot
**Files:** executor loop (campaign step execution), `src/evm/onchain/flashloan.rs`
**What:** Snapshot attacker `erc20_transfers` (raw units) at each `get_next_call` boundary;
when a runtime belly call produces a positive attacker-inflow delta above a threshold,
promote that call into `CampaignSequence.steps`/`promoted` for subsequent Locate+Amplify.
Threshold + one-lever-per-frame bound to protect the 3.5GB ceiling (Risk: over-promotion).
**Done when:** On a target with no registered archetype, a ledger-moving belly call is
promoted and then amplified; bounded to one lever/frame.
**Blocks:** none (generalization path; independently shippable after Phase 1)

### T10 — BUILD LOG (2026-07-02): CODE-COMPLETE, compiles clean, unit tests green.
Architecture pivot from the literal spec (documented deviation, cleaner + gate-respecting):
the atomic campaign's staged-state chaining accumulates ONE ordered `erc20_transfers` log
across all steps (vm.rs replaces evmstate from the input's staged state each `execute()`, and
the executor chains `new_state` forward). So per-step attribution needs no opcode-level
`get_next_call` hook and no `flashloan.rs` change — just the log offset at each step boundary.
- **`CampaignSequence.aposteriori: bool`** (`#[serde(default)]`, input.rs). Planner sets it in
  `plan_campaign_sampled` ONLY when `reflexive_lever && promoted.is_empty()` (reflexive path,
  no a-priori archetype). Off-path false ⇒ executor does one bool check, no work.
- **Executor (executor.rs)**: when `campaign.aposteriori`, push `erc20_transfers.len()` at each
  step boundary into new metadata `CampaignInflowBoundaries { offsets }` (len == steps+1). This
  is the ONLY new instrumentation.
- **feedbacks.rs**: `record_aposteriori_candidate` (gated on `reflexive_lever` + armed campaign)
  attributes per-step attacker inflow via the boundary slices and records the single largest
  mover (>`APOSTERIORI_MIN_INFLOW`=1e15, high-water) into `PromotionCandidate {contract,
  selector, best_inflow, set}`. Pure core extracted to free fn `best_inflow_step` (unit-tested).
- **mutator.rs**: `maybe_pin_aposteriori_lever` (before the AMPLIFY block) reads the candidate
  and pins the matching `(contract, selector)` campaign step into `promoted` — then the existing
  `apply_ledger_secant` (T8) Locates + Amplifies it, same mutate pass. One lever/frame.
- **Metadata** `CampaignInflowBoundaries` + `PromotionCandidate` in campaign_planner.rs
  (`impl_serdeany!`), re-exported from planner mod.
- **Tests:** feedbacks — attribution picks largest / rejects dust / skips borrow+selectorless /
  ignores non-attacker / rejects malformed offsets. planner — armed when no archetype /
  disarmed when a-priori fires / off when flag off. `cargo check --bin` clean.
- **Deviation from spec:** flashloan.rs untouched (no per-call hook needed — offsets suffice);
  "get_next_call boundary" realized as the campaign STEP boundary (the fuzzer plays the belly as
  chained single-call inputs; the atomic campaign is where they become an ordered log).
- **NOT proven:** live discovery on a novel target (needs the Lane-A fork run, like 9b/9c).
