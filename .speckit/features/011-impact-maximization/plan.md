# Feature 011 — Impact Maximization · Implementation Plan

**Status:** Tasked (Phase 1) — signed off Skyler 2026-06-29
**Owner:** Skyler
**Last updated:** 2026-06-29

> **Plan refinement (discovered during tasking):** `liquidate_via_engine` (vm.rs:552)
> returns `Option<()>` and leaves proceeds in `flashloan_data.earned` — it is not a pure
> valuation. Part A therefore uses an extracted helper
> `value_token_inflow_eth(caller, token, amount, state) -> Option<EVMU256>` (snapshot →
> liquidate → read earned delta → restore) shared with the loot oracle. See tasks.md T1.
**Spec:** [`specify.md`](./specify.md) — all blocking checkpoints resolved, signed off 2026-06-29.

> Scope decision carried from sign-off: **Part A core = realized-ETH gradient.** The
> %-of-TVL severity metric (Checkpoint 11.5) is deferred to a follow-on and is **not**
> built here. Part B (amplifier) ships behind its own flag.

---

## 1. Architecture decisions (resolving the spec's Open Questions)

| # | Open question | Decision | Rationale |
|---|---|---|---|
| OQ1 | Value every token inflow, or only the dominant one? | **Pre-filter then sum.** Only invoke the engine when the raw `best_inflow` ceiling for a token actually rises (the existing cheap check); when it does, ETH-value the changed token(s) and sum across all attacker-held tokens, caching a per-token ETH rate for the rest. | Keeps valuation off the hot path (spec Risk: valuation overhead); reuses the gradient's existing change-detection. |
| OQ2 | Geometric ladder vs. secant for the amount search? | **Phase 1 = fixed geometric ladder `{2×, 10×, 100×, U256::MAX}`.** Secant (Feature 008) is a **Phase 2** enhancement, noted not built. | Deterministic and unit-testable (Success Criterion 2 & 4); the ladder is the minimal thing that proves the mechanism before adaptive search. |
| OQ3 | Part B in `mutator.rs` or a dedicated Stage? | **Dedicated `ImpactAmplifierStage`**, mirroring `ConcolicStage` (concolic_stage.rs:29). | The "amplify → execute → keep-best → back-off" loop is a re-run loop, not a single mutation; a Stage isolates it and the `enabled` early-return gives constitution rule 1 (zero code path when off) for free. |
| OQ4 | One CLI flag or two? | **Two.** `--impact-eth-gradient` (Part A) and `--amplify` (Part B). `--amplify` **implies** Part A's valuation (the amplifier ranks variants by realized ETH, so it needs the engine valuation regardless of the gradient flag). | Part A is a low-risk default-candidate; Part B is aggressive. Separability lets us ship/measure A alone. |

---

## 2. Part A — Value-denominated extraction gradient

**Nature:** EXTENSION of `TokenBalanceFeedback` (`src/evm/feedbacks.rs:180`). No parallel system.

### 2.1 New field + constructor
- Add `eth_gradient: bool` and `evm_executor: Option<Rc<RefCell<EVMExecutor<...>>>>` to
  `TokenBalanceFeedback`. When `eth_gradient == false`, the executor ref is `None` and the
  struct behaves **byte-identically** to today (Success Criterion 3 / constitution rule 2).
- New constructor arg threaded at `evm_fuzzer.rs:384`:
  `TokenBalanceFeedback::new(attackers, infant_scheduler.clone(), config.impact_eth_gradient, eth_engine_ref)`
  where `eth_engine_ref = config.impact_eth_gradient.then(|| evm_executor_ref.clone())`.

### 2.2 `is_interesting` change (feedbacks.rs:233–289)
- Keep the existing raw-unit `inflow_by_token` accumulation untouched (it is the change
  pre-filter).
- **When `eth_gradient` is on AND a token's raw `best_inflow` ceiling rose:** value that
  inflow to ETH by calling the validated engine through the held executor ref —
  `self.evm_executor.as_ref().unwrap().deref().borrow_mut().<engine valuation>(token, amount, state-result)`,
  the same `liquidate_via_engine` / `resolveToEth` path the loot oracle uses
  (erc20.rs:231–258). Sum ETH across attacker-held tokens into `eth_inflow_total`.
- Track `best_eth_inflow: EVMU256` alongside `best_inflow`. The **vote weight** becomes a
  function of the ETH ceiling, not the token-unit ceiling — so an expensive blue-chip
  position out-votes a thin-liquidity mountain (Success Criterion 2).
- **Borrow safety (Checkpoint 11.2):** the only live borrow in this scope is
  `state.get_execution_result()` (borrows `state`); the engine `borrow_mut()` is on the
  executor `RefCell` — a different object. No conflict. Mirror `CmpFeedback` (feedbacks.rs:90,106).

### 2.3 Feedback→amplifier hand-off (writes `AmplifyHint`)
- When `eth_gradient` registers a **new ETH ceiling**, write/refresh an `AmplifyHint` into
  `state.metadata_map_mut()` (Part B reads it). See §4.

---

## 3. Part B — Blood-in-the-water amplifier (`ImpactAmplifierStage`)

**Nature:** NEW capability, implemented as a LibAFL `Stage` modeled on `ConcolicStage`.
New file `src/evm/impact_amplifier.rs` (or `src/evm/stages/impact_amplifier.rs`).

### 3.1 Struct + wiring (mirror concolic_stage.rs:29–58, evm_fuzzer.rs:338–373)
```text
pub struct ImpactAmplifierStage<OT> {
    pub enabled: bool,                              // config.amplify; early-return when false
    pub vm_executor: Rc<RefCell<EVMQueueExecutor>>, // same ref ConcolicStage holds
    pub max_runs_per_seed: usize,                   // bound (spec Risk: corpus thrash)
    pub phantom: PhantomData<OT>,
}
impl UsesState ... { type State = EVMFuzzState; }
impl Stage<EVMFuzzExecutor<OT>, EM, Z> for ImpactAmplifierStage<OT>  // fn perform(...)
```
- Constructed next to `concolic_stage` (~evm_fuzzer.rs:343) with `evm_executor_ref.clone()`.
- Added to the stage tuple at evm_fuzzer.rs:373:
  `tuple_list!(std_stage, concolic_stage, impact_amplifier_stage, coverage_obs_stage)`.

### 3.2 `perform` loop
1. `if !self.enabled { return Ok(()) }` — constitution rule 1.
2. Read `AmplifyHint` from `state.metadata_map()`; if absent, return (nothing profitable yet).
3. Load the profitable testcase by the hint's corpus idx (mirror concolic_stage.rs:104–111;
   skip borrow/step inputs via `get_data_abi().is_none()`).
4. For each `factor` in the ladder `{2, 10, 100, U256::MAX}`:
   - Clone the input; **amplify the amount operands** (§3.3).
   - Re-execute via `self.vm_executor.borrow_mut().execute(&variant, state)`.
   - ETH-value the result with the same engine path as Part A.
   - Keep the variant if realized ETH strictly exceeds the running best;
     **back off (discard) on revert / no-gain** — the loot path already snapshots & restores
     (erc20.rs:232,255), so a reverted re-run leaves prior best intact (Checkpoint 11.6).
5. If a better variant was found, hand it to the corpus via the `Evaluator` bound
   (`fuzzer.evaluate_input(...)`, as ConcolicStage adds solutions) so the amplified trace
   becomes a real seed / can drive the PoC.
6. Respect `max_runs_per_seed`; clear/age the `AmplifyHint` so one seed can't monopolize energy.

### 3.3 Amplifying the amount operands (Checkpoint 11.3)
Two operand sites, both already mutable in-tree:
- **`input.txn_value: Option<EVMU256>`** (input.rs) — native msg.value: `saturating_mul(factor)` or `U256::MAX`.
- **uint256 ABI args** — walk `input.data` (BoxedABI); select `A256` args where
  `inner_type == A256InnerType::Uint` (abi.rs:637,661); read `U256::try_from_be_slice(&data)`
  (abi.rs:728), scale (saturating), write back via `set_bytes` (abi.rs:714). This is the same
  path `BoxedABI::mutate_with_vm_slots` (abi.rs:394,414) uses — **extension, not a new system.**

---

## 4. Shared data structure — `AmplifyHint`

```text
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct AmplifyHint {
    pub corpus_idx: usize,           // the profitable testcase
    pub operand_offsets: Vec<usize>, // which A256 Uint args / txn_value to scale
    pub eth_ceiling: EVMU256,        // current best realized ETH (for keep-best compare)
}
impl_serdeany!(AmplifyHint);
```
- Registered like `ConcolicPrioritizationMetadata` (concolic_stage.rs:60–66) — via
  `impl_serdeany!`; if it ever stores a non-derivable type, register explicitly before fuzzing
  (the `CampaignIntermediateStatesEVM::register()` precedent, evm_fuzzer.rs:350).
- **Written by** Part A (§2.3) on a new ETH ceiling; **read by** Part B (§3.2). This mirrors
  the `TopologyHints` (mutator.rs:649) and Feature 008 secant metadata flow.

---

## 5. Config / CLI

`src/evm/config.rs` (Config struct) + the CLI layer:
- `pub impact_eth_gradient: bool` — flag `--impact-eth-gradient` (default **false**).
- `pub amplify: bool` — flag `--amplify` (default **false**); turning it on forces the
  valuation engine ref even if `--impact-eth-gradient` is off (the amplifier ranks by ETH).
- Both default-false ⇒ a run with neither flag is byte-equivalent to today (Success Criterion 3).

---

## 6. Phasing (maps to tasks.md, not yet written)

- **Phase 1 — Part A gradient:** field + constructor + `is_interesting` ETH valuation + flag.
  Independently shippable & measurable. *Gate:* Success Criteria 2 & 3.
- **Phase 2 — `AmplifyHint` + `ImpactAmplifierStage` (ladder):** the amplifier. *Gate:*
  Success Criteria 1 & 4 (measured ETH delta on Yearn, ON vs OFF).
- **Phase 3 (follow-on, may defer):** secant-adaptive amount search (Feature 008 reuse);
  %-of-TVL severity metric (Checkpoint 11.5).

---

## 7. Testing strategy (binds to Success Criteria)

| Criterion | Test |
|---|---|
| SC-2 (ranks ETH not units) | Unit test: two synthetic tokens — more units of a cheap token vs fewer units of an expensive one — assert the higher-ETH path gets the higher vote. Pure `feedbacks.rs` test, engine valuation stubbed/mocked. |
| SC-3 (zero path when off) | Regression: a known seed run with both flags off produces byte-equivalent corpus/oracle output vs pre-feature `main`. |
| SC-1 (amplifier increases loot) | **Lane A** on the Yearn fork: same seed + time budget, `--amplify` ON vs OFF; assert realized-ETH ceiling strictly greater (or already at the liquidity ceiling). *Deploy = Skyler's step.* |
| SC-4 (terminates, overflow-safe) | Unit test: ladder up to `U256::MAX` does not overflow `EVMU512` earned/owed; `max_runs_per_seed` bound holds; reverted variant leaves best unchanged. |

---

## 8. Risks & mitigations (from spec §Risks)

- **Corpus thrash** → `max_runs_per_seed`; fire only on a *new* ETH ceiling; age the hint.
- **Valuation overhead** → value only when raw inflow ceiling rose (OQ1 pre-filter); cache per-token rate.
- **`RefCell` double-borrow** → resolved (Checkpoint 11.2); state vs executor are distinct objects.
- **Interaction with this session's depth-cap / overflow fixes** → amplified amounts flow
  through the *same* execution path and are bounded by pool liquidity; the depth cap and
  EVMU512 headroom (Checkpoint 11.6) are respected, never bypassed.
- **Constitution rule 2** → both flags default false; `None` executor ref ⇒ original token-unit
  gradient is the untouched default path.

---

## 9. Files touched (summary)

| File | Change |
|---|---|
| `src/evm/feedbacks.rs` | Part A: field, constructor, `is_interesting` ETH valuation, `AmplifyHint` write |
| `src/evm/impact_amplifier.rs` *(new)* | Part B: `ImpactAmplifierStage` |
| `src/evm/abi.rs` | (read-only reuse of `A256` mutate path; helper to scale an `A256` if not already exposed) |
| `src/evm/mod.rs` | register new module |
| `src/fuzzers/evm_fuzzer.rs` | wire feedback args (:384), construct + add stage (:343, :373) |
| `src/evm/config.rs` + CLI | two flags |
| `AmplifyHint` (in feedbacks.rs or amplifier module) | shared metadata + `impl_serdeany!` |
| tests | SC-2, SC-3, SC-4 |
