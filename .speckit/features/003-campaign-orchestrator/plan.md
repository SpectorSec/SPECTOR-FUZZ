# Implementation Plan — Campaign Orchestrator (Feature 003)

**Status:** Planned  
**Owner:** TBD  
**Last updated:** 2026-06-26  

---

## 1. Architectural Strategy

The Campaign Orchestrator does **not** create a new execution engine. It reuses the existing replay-loop pattern (`evm_fuzzer.rs:882-916`) to execute an atomic sequence of `EVMInput`s within a single fuzzer event, chaining state between steps.

### Key Insight from Checkpoints

The replay loop already does everything we need:
```rust
// evm_fuzzer.rs:849-861 — existing multi-step execution
let mut vm_state = initial_vm_state.clone();
for txn in testcase {
    let (inp, call_until) = txn.to_input(vm_state.clone());
    fuzzer.evaluate_input_events(state, &mut executor, &mut mgr, inp, false)?;
    vm_state = state.get_execution_result().new_state.clone();
}
```

The Campaign Planner's job is to **generate the `Vec<ConciseEVMInput>`** that feeds into this loop, with:
1. Correct step ordering (Borrow → ABI → ABI → ...)
2. Parameter values routed from previous step outputs via `observed_values`
3. Early abort on any step revert

---

## 2. Algorithm Design & Pseudocode

### A. CampaignSequence Structure

```rust
/// A planned multi-step campaign executed atomically.
pub struct CampaignSequence {
    /// Ordered list of campaign steps (ConciseEVMInput for serialization).
    pub steps: Vec<ConciseEVMInput>,
    /// Linkage table: maps (step_index, output_word_index) -> (step_index, param_index)
    /// so we can deterministically route outputs to inputs across steps.
    pub linkages: Vec<StepLinkage>,
}

/// A single linkage edge: output word M of step S feeds input param P of step T.
pub struct StepLinkage {
    pub from_step: usize,
    pub from_output_word: usize,
    pub to_step: usize,
    pub to_param_index: usize,
}
```

### B. Campaign Planning Algorithm

The planner is a deterministic state machine that builds a campaign step-by-step:

```
PLAN_CAMPAIGN(abi_registry, observed_values, state):
  1. TARGET SELECTION:
     Scan abi_registry for:
       - Flashloan providers (EVMInputTy::Borrow candidates)
       - Vault/deposit contracts (selectors: deposit, mint, stake)
       - Exploit targets (selectors: withdraw, redeem, liquidate, sync)
  
  2. STEP CONSTRUCTION:
     Initialize empty campaign = CampaignSequence { steps: [], linkages: [] }
     
     Step 0 — Asset Sourcing:
       Pick a flashloan provider or swap pool.
       Build a Borrow EVMInput targeting that token.
       Record expected output: tokens now in caller balance.
       campaign.steps.push(borrow_input);
     
     Step 1..N — State Priming + Exploit:
       For each planned action:
         a. SELECTOR MATCHING: Choose a function selector from the target contract's ABI.
         b. PARAMETER RESOLUTION: For each ABI parameter:
            - Check linkages: was a previous step's output of matching type produced?
              If yes, route it (record linkage entry).
            - Check observed_values: does the current state have a captured value
              matching the expected type?
            - Fallback: use mutate_with_vm_slots (existing Phase 2 linkage).
         c. BUILD ConciseEVMInput with resolved parameters.
         d. campaign.steps.push(step_input);
         e. Record expected output signatures for linkage in subsequent steps.
  
  3. VALIDATION:
     If any step's parameter cannot be resolved (no observed value, no linkage, no ABI match):
       → Discard campaign, return None.
     If campaign has fewer than 2 steps:
       → Discard campaign (pointless — a single step is not a campaign).

  4. RETURN campaign.
```

### C. Campaign Execution

The execution hook lives in the mutator:

```
MUTATE(input, state):
  // Existing mutation logic...
  
  // NEW: Campaign generation (~10% probability)
  if state.rand_mut().below(100) < CAMPAIGN_PROBABILITY && campaign_eligible(state):
    campaign = PLAN_CAMPAIGN(abi_registry, observed_values, state)
    if campaign is Some:
      input.campaign = Some(campaign)
      return Mutated
  
  // Fall through to existing single-step mutation
  ...
```

When `input.campaign` is `Some`, the execution path changes:

```
EVALUATE_INPUT_EVENTS(fuzzer, state, executor, mgr, input):
  if input.campaign is Some:
    let campaign = input.campaign.take();
    let mut vm_state = input.get_state().clone();
    
    for step_ci in campaign.steps:
      let (step_input, call_until) = step_ci.to_input(vm_state.clone());
      
      // Execute this step
      fuzzer.evaluate_input_events(state, executor, mgr, step_input, false)?;
      
      // Early abort on revert
      if state.get_execution_result().reverted:
        return;  // Campaign failed
      
      vm_state = state.get_execution_result().new_state.clone();
    
    // After all steps succeed, the state has the final result.
    // Existing oracle/feedback evaluation fires naturally.
  else:
    // Original single-step execution path
    ...
```

### D. Minimization

The existing `EVMMinimizer` in `src/evm/minimizer.rs:94-176` already handles multi-transaction traces. When a campaign fires an oracle, the `TxnTrace` will contain all steps. The minimizer's greedy skip-one algorithm will prune redundant steps automatically.

**No minimizer changes needed.**

---

## 3. Modified Existing Files

### A. `src/evm/input.rs`
- Add `CampaignSequence` struct definition (with `Serialize`, `Deserialize`).
- Add `campaign: Option<CampaignSequence>` field to `EVMInput`.
- Add `campaign: Option<CampaignSequence>` field to `ConciseEVMInput`.
- Implement `to_inputs()` on `ConciseEVMInput` (or a new helper) that produces `Vec<(EVMInput, u32)>` with proper state chaining.

### B. `src/evm/abi.rs`
- Add a new public function `plan_campaign(...)` implementing the deterministic planning algorithm.
- Add helper: `get_compatible_observed_values(param_type, observed_values) -> Vec<EVMU256>` that filters by ABI type.

### C. `src/evm/mutator.rs`
- Add campaign generation logic in the `FuzzMutator::mutate()` method (gated by ~10% probability, opt-in CLI flag).
- Call `plan_campaign()` when eligible, attach to `input.campaign`.

### D. `src/evm/config.rs`
- Add `campaign_orchestrator: bool` configuration field.
- Default: `false` (disabled by — per constitution Article 4).

### E. `src/evm/mod.rs`
- Wire CLI flag `--campaign-orchestrator`.

### F. `src/fuzzers/evm_fuzzer.rs`
- In `evaluate_input_events` (or a wrapper), detect `input.campaign` and execute the sequential multi-step flow.

### G. `src/state_input.rs` (if needed)
- Verify `StagedVMState` serialization handles campaign-aware states correctly.

### H. `.speckit/features/003-campaign-orchestrator/specify.md`
- Update if implementation deviates from spec (per constitution Article 7).

---

## 4. New Files Created

### A. `src/evm/planner/`
- `mod.rs` — module declaration, re-exports `CampaignSequence`, `StepLinkage`, `plan_campaign`.
- `campaign_planner.rs` — the deterministic planning algorithm, target/selector scanning, parameter resolution.
- `campaign_executor.rs` — the sequential execution wrapper that drives multiple `evaluate_input_events` calls.

### B. `src/evm/planner/campaign_planner.rs`
Contains:
- `pub struct CampaignSequence` with `steps: Vec<ConciseEVMInput>` and `linkages: Vec<StepLinkage>`.
- `pub fn plan_campaign(...) -> Option<CampaignSequence>` — the deterministic state machine.
- Target/selector scanning helpers.
- Parameter resolution with linkage table construction.

### C. `src/evm/planner/campaign_executor.rs`
Contains:
- `pub fn execute_campaign(...)` — iterates steps, chains state, aborts on revert.

---

## 5. CLI Flag Addition

```
--campaign-orchestrator    Enable Campaign Planner for multi-step exploit synthesis
                           (default: disabled, no behavior change when off)
```

Wired in `src/evm/mod.rs` following existing patterns (e.g., `--value-capture`).

---

## 6. Testing Plan

### A. Unit Tests (`src/evm/planner/campaign_planner.rs`)
1. **`test_campaign_sequence_serialization`**: Create a `CampaignSequence` with 3 steps, serialize to JSON, deserialize, verify `steps.len()` and `linkages` integrity.
2. **`test_plan_campaign_borrow_abi`**: Mock ABI registry with a flashloan provider and a deposit function. Call `plan_campaign()` and assert it produces a 2-step Borrow→ABI sequence.
3. **`test_plan_campaign_linkage_routing`**: After a Borrow step, verify that the returned token address is linked to the deposit step's address parameter.

### B. Integration Test
4. **`test_campaign_execution`**: Deploy a mock flashloan provider + mock vault on a local fork. Run a campaign `Borrow(token) → vault.deposit(token, amount)` and assert the state shows the deposited balance in the vault.

### C. Regression Test
5. **`test_disabled_flag_produces_identical_results`**: Run the B1 benchmark with and without `--campaign-orchestrator`. Verify identical coverage distribution when disabled.

---

## 7. Performance Analysis

- **When disabled**: Zero overhead. The `campaign` field on `EVMInput` is `None`, the planner code is never entered. Compile-time overhead is ~0.
- **When enabled**: Campaign generation runs in the mutator (~10% of mutations). The scan over `abi_registry` is bounded by the number of deployed contracts (typically <100). The sequential execution of N steps is O(N) calls to `evaluate_input_events`, each of which is already the unit of fuzzer work. A 3-step campaign is ~3x the work of a single step — acceptable because campaigns replace wasted single-step mutations.
- **Memory**: `CampaignSequence` with `Vec<ConciseEVMInput>` is serialized to/from the corpus. Each `ConciseEVMInput` is ~200-500 bytes. A 5-step campaign adds ~2.5KB per testcase — negligible.

---

## 8. Rollback Plan

If the changes cause compile errors or regressions:
1. Revert modified files:
   ```bash
   git checkout src/evm/input.rs src/evm/abi.rs src/evm/mutator.rs \
     src/evm/config.rs src/evm/mod.rs src/fuzzers/evm_fuzzer.rs
   ```
2. Remove new directory:
   ```bash
   rm -rf src/evm/planner/
   ```
3. Revert and remove `--campaign-orchestrator` CLI wiring.
