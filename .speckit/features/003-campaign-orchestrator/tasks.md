# Task List — Campaign Orchestrator (Feature 003)

**Status:** Tasked  
**Owner:** TBD  
**Last updated:** 2026-06-26  

This document lists the sequential, atomic tasks required to implement the Campaign Orchestrator.

---

## Task Checklist

- [ ] **Task 1 — Define `CampaignSequence` and `StepLinkage` data structures**  
  *Description:* Add `CampaignSequence` (with `steps: Vec<ConciseEVMInput>` and `linkages: Vec<StepLinkage>`) and `StepLinkage` (with `from_step`, `from_output_word`, `to_step`, `to_param_index`) as serializable structs.  
  *Touches:* `src/evm/input.rs`  
  *Done when:* Project compiles and both structs derive `Serialize, Deserialize, Clone, Debug`.

- [ ] **Task 2 — Add `campaign` field to `EVMInput` and `ConciseEVMInput`**  
  *Description:* Add `pub campaign: Option<CampaignSequence>` to both `EVMInput` and `ConciseEVMInput`. Propagate through constructors (all `EVMInput` construction sites set it to `None`). Implement `to_inputs()` on `ConciseEVMInput` that expands a campaign into `Vec<(EVMInput, u32)>` with chained states.  
  *Touches:* `src/evm/input.rs`, `src/evm/middlewares/value_capture.rs`, `src/evm/middlewares/cheatcode/mod.rs`, `src/evm/middlewares/sha3_bypass.rs`, `src/evm/onchain/mod.rs`, `src/evm/onchain/flashloan.rs`, `src/evm/vm.rs`, `src/evm/corpus_initializer.rs`, `src/evm/mutator.rs`  
  *Done when:* All construction sites compile with the new field defaulting to `None`.

- [ ] **Task 3 — Add `--campaign-orchestrator` CLI flag**  
  *Description:* Add `campaign_orchestrator: bool` to `FuzzConfig`. Wire CLI argument `--campaign-orchestrator` in the argument parser.  
  *Touches:* `src/evm/config.rs`, `src/evm/mod.rs`  
  *Done when:* `cargo run -- --help` prints the new flag; flag is consumed into config.

- [ ] **Task 4 — Create `src/evm/planner/` module skeleton**  
  *Description:* Create `src/evm/planner/mod.rs` with module declarations. Export `CampaignSequence`, `StepLinkage`, `plan_campaign`, and `execute_campaign`.  
  *Touches:* `src/evm/planner/mod.rs` (New File)  
  *Done when:* `mod planner;` compiles in `src/evm/mod.rs`.

- [ ] **Task 5 — Implement `plan_campaign()` in `campaign_planner.rs`**  
  *Description:* Implement the deterministic state-machine planning algorithm:
  1. Scan ABI registry for target contracts (flashloan providers, vault/deposit selectors, exploit selectors).
  2. Build step sequence: Borrow(asset) → ABI(state_priming) → ABI(exploit).
  3. For each step's parameters: resolve from linkages first → observed_values → mutate_with_vm_slots fallback.
  4. Record StepLinkage entries for cross-step parameter routing.
  5. Return `None` if insufficient steps or unresolvable parameters.  
  *Touches:* `src/evm/planner/campaign_planner.rs` (New File)  
  *Done when:* `plan_campaign()` compiles and returns `Option<CampaignSequence>` given valid ABI registry input.

- [ ] **Task 6 — Implement `execute_campaign()` in `campaign_executor.rs`**  
  *Description:* Implement the sequential execution loop:
  1. Receive `CampaignSequence` and initial `EVMState`.
  2. For each step: convert `ConciseEVMInput` → `(EVMInput, u32)` with state chaining.
  3. Call `evaluate_input_events()` per step.
  4. On revert: mark campaign as failed, return early.
  5. On success: propagate result state to next step.  
  *Touches:* `src/evm/planner/campaign_executor.rs` (New File)  
  *Done when:* `execute_campaign()` compiles and executes a Borrow→ABI sequence with correct state propagation.

- [ ] **Task 7 — Hook campaign generation into the mutator**  
  *Description:* In `FuzzMutator::mutate()`, add campaign generation path (~10% probability when `campaign_orchestrator` is enabled and the state has usable ABI targets). Call `plan_campaign()` and attach result to `input.campaign`.  
  *Touches:* `src/evm/mutator.rs`  
  *Done when:* Mutator generates campaigns under the flag; existing single-step mutations unchanged when disabled.

- [ ] **Task 8 — Wire campaign execution into the fuzzer loop**  
  *Description:* In the evaluation path (likely `evm_fuzzer.rs` or `fuzzer.rs`), detect `input.campaign.is_some()`. If set, route to `execute_campaign()` instead of the single-step `execute()` dispatch. Maintain existing oracle/feedback evaluation on the final state.  
  *Touches:* `src/fuzzers/evm_fuzzer.rs` or `src/fuzzer.rs`  
  *Done when:* Campaigns execute atomically through the fuzzer loop; oracles fire on final state.

- [ ] **Task 9 — Write unit tests**  
  *Description:* Write 3 unit tests in `src/evm/planner/campaign_planner.rs`:
  1. **`test_sequence_serialization`**: Create `CampaignSequence`, round-trip through JSON, verify fields.
  2. **`test_plan_campaign_borrow_abi`**: Mock ABI registry, assert 2-step Borrow→ABI sequence produced.
  3. **`test_linkage_routing`**: After Borrow step, verify linkage routes token address to deposit param.  
  *Touches:* `src/evm/planner/campaign_planner.rs`  
  *Done when:* `cargo test` runs and passes all 3 planner unit tests.

- [ ] **Task 10 — Write integration and regression tests**  
  *Description:* 
  1. **Integration test**: Deploy mock flashloan + mock vault contracts. Run fuzzer with `--campaign-orchestrator`. Verify a Borrow→deposit campaign executes and the vault balance reflects the deposit.
  2. **Regression test**: Run B1 benchmark with and without the flag. Verify identical coverage when disabled.  
  *Touches:* `src/evm/planner/campaign_executor.rs` (integration test), fuzzer benchmark scripts  
  *Done when:* Integration test passes; regression test confirms zero behavior change with flag off.

---

## Task Dependency Graph

```
Task 1 (data structs) ──┐
                        ├──► Task 2 (campaign field on EVMInput) ──┐
Task 3 (CLI flag) ──────┘                                          │
                                                                    ├──► Task 4 (module skeleton)
                                                                    │
                                              Task 5 (planner) ────┤
                                              Task 6 (executor) ───┤
                                                                    │
                                              Task 7 (mutator hook)─┤
                                              Task 8 (fuzzer wire) ─┤
                                                                    │
                                              Task 9 (unit tests) ──┤
                                              Task 10 (integration) ┘
```

Tasks 1-3 are independent and can be done in parallel. Tasks 4-8 depend on 1-3. Tasks 9-10 depend on 5-8.

---

## Notes

- **Flag defaults to `false`** — all new code gated behind it. No silent behavior changes (Constitution Art 4).
- **No LibAFL trait modifications** — `CampaignSequence` uses existing `ConciseEVMInput` which already satisfies `Input`-adjacent serialization.
- **Minimizer is reused** — `EVMMinimizer` already handles multi-step traces. No changes needed.
- **No `execute()` internals modified** — campaign execution uses the same `evaluate_input_events` path as single steps, just looped.
