# Plan — Feature 022 — JIT Causal Taint & Secant Solver Refactor

**Status:** Built & Live-Verified
**Owner:** Antigravity & skyler
**Last updated:** 2026-07-06

---

## 1. Implementation Steps

### Step 1: Clean up the Hot Path in `Sha3WrappedFeedback::is_interesting`
**File:** `src/evm/feedbacks.rs`
* Remove the `CmpLinearityTaint` re-execution logic inside the `is_interesting` method of `Sha3WrappedFeedback`.
* Remove all static flag resets that ran during this step (since they will be moved to the JIT and append sites).

### Step 2: Implement JIT Causal Verification inside the Oracle Feedback Loop
**File:** `src/feedback.rs`
* Modify `OracleFeedback::is_interesting()` so that if an oracle flags a bug candidate (when `concolic_secant_dispatch` is enabled) and `injection_analysis_ran()` is false:
  * Downcast `self.executor` dynamically to `EVMQueueExecutor` via `as_any()`.
  * To bypass generic borrow-checker constraints on `state` and `input` (since they are mutably borrowed by `oracle_ctx` in the loop), safely project `oracle_ctx.input` and `oracle_ctx.fuzz_state` and cast them to `&EVMInput` and `&mut EVMFuzzState` using raw pointer casting (`as *const I as *const EVMInput` and `as *mut S as *mut EVMFuzzState`).
  * Instantiate a new `CmpLinearityTaint` middleware object.
  * Execute the `reexecute_with_middleware` pass.
  * Call `cmp_linearity::injection_chain_verdict()` to check the causal link.
  * Check `injection_exploit_path_detected()`. If false, bypass/continue to suppress the bug.


### Step 3: Implement JIT Causal Verification in Promotion Candidate Identification
**File:** `src/evm/feedbacks.rs`
* Modify `record_aposteriori_candidate()` so that if `best_inflow_step` identifies a promotion candidate and `injection_analysis_ran()` is false:
  * Downcast the `self.evm_executor` JIT.
  * Execute the `reexecute_with_middleware` pass.
  * Check `injection_causal_link_confirmed()` before completing the candidate promotion.

### Step 4: Execute Taint Analysis on Corpus Insertion (Cold Path)
**File:** `src/evm/feedbacks.rs`
* In `Sha3WrappedFeedback::append_metadata()`, if the testcase is not a step input, perform the `CmpLinearityTaint` re-execution pass.
* Extract the argument-to-storage provenance mapping (`host.arg_slot_provenance`) and add it to the testcase's metadata using:
  ```rust
  testcase.add_metadata(ArgStorageProvenance { per_slot: prov });
  ```

### Step 5: Update the Secant Mutator to Read Testcase Metadata
**File:** `src/evm/mutator.rs`
* Update the argument filters in `apply_calldata_secant()` and `apply_value_secant()` to retrieve `ArgStorageProvenance` directly from the metadata of the `testcase` currently being mutated instead of the global `state.metadata_map()`.
  ```rust
  let testcase = state.corpus().get(corpus_idx).unwrap().borrow();
  let prov_map = testcase.metadata_map().get::<crate::evm::feedbacks::ArgStorageProvenance>();
  ```

---

## 2. Test Plan

1. **Compilation**: Ensure the codebase compiles cleanly with both cargo release and cargo test.
2. **Unit Tests**: Add tests verifying that `ArgStorageProvenance` is correctly attached to testcases and retrieved by the mutator.
3. **Performance Audit**: Run a baseline campaign on a benchmark contract (e.g. `tests/bench/reentrancy_flash.sol`) and verify that execution speed exceeds 15,000 exec/sec (compared to the ~700 exec/sec baseline).
4. **Vulnerability Regression Check**: Run a mainnet/BSC fork exploit verification (like EGD-Finance or RES02) and verify that the fuzzer still correctly identifies the exploit and suppresses phantoms.
