# Feature 022 — JIT Causal Taint & Secant Solver Refactor

**Status:** Built & Live-Verified
**Owner:** Antigravity & skyler
**Last updated:** 2026-07-06

---

## 1. Overview and Problem Statement

SpectorFuzz implements two key optimization and validation frameworks:
1. **Feature 009 (Concolic/Secant Dispatch)**: Employs a numeric secant solver (`CmpLinearityTaint`) to determine the linearity of comparisons and scale input mutations.
2. **Feature 019 (Causal Identity)**: Filters out false-positive bug reports by ensuring that an oracle violation has a direct taint path back to the attacker's calldata (`INJECTION_CONFIRMED_EXPLOIT_PATH`).

### The Performance Bottleneck
Because the fuzzer's core evaluation loop uses the VM-agnostic `GenericVM` abstraction, it cannot natively invoke EVM-specific functions such as `reexecute_with_middleware()`. To work around this, the previous agent wired the `CmpLinearityTaint` re-execution pass inside `Sha3WrappedFeedback::is_interesting`.

Since `Sha3WrappedFeedback` wraps the fuzzer's coverage check, it is evaluated on **every single mutated input**. This introduces a mandatory double-execution tax on 100% of inputs, capping overall throughput at ~700 exec/sec.

### The Soundness Bug
The current wiring writes the extracted `ArgStorageProvenance` map into the global `state.metadata_map()`. Since the re-execution pass runs on every input, this global map is constantly overwritten by random, discarded mutations. When the mutator selects a parent testcase to mutate, it reads this corrupted global map instead of the specific provenance associated with that parent testcase.

---

## 2. Technical Solution: JIT & Per-Testcase Metadata

This feature refactors the execution model to move the taint analysis from the **always-on hot path** to the **Just-in-Time (JIT) cold path**.

### A. Dynamic Downcasting
`GenericVM` already implements the `as_any()` trait method. Inside generic feedbacks (like `OracleFeedback`), we can downcast `self.executor` dynamically at runtime:
```rust
let mut executor_borrow = self.executor.borrow_mut();
if let Some(evm_executor) = executor_borrow.as_any().downcast_mut::<EVMQueueExecutor>() {
    evm_executor.reexecute_with_middleware(input, state, lin);
}
```

### B. Just-In-Time (JIT) Bug Verification
We remove `CmpLinearityTaint` re-execution from the hot `is_interesting` path. Instead:
1. When an oracle detects a bug candidate in `feedback.rs`, we check if the causal taint analysis has run.
2. If it has not, we downcast the executor JIT, run the re-execution pass, and call `injection_chain_verdict()`.
3. If the path is verified as causally linked, the fuzzer registers the bug. Otherwise, the bug is discarded as a phantom.

### C. JIT Promotion Candidate Verification
In `feedbacks.rs::record_aposteriori_candidate()`, if `best_inflow_step` identifies a ledger-moving candidate but the analysis has not run, we trigger the re-execution JIT to verify the causal link before performing the promotion.

### D. Per-Testcase Metadata Isolation
* For corpus inputs, we move the `CmpLinearityTaint` re-execution to `Sha3WrappedFeedback::append_metadata()`, which executes *only* when a new testcase is actually saved to the corpus (cold path).
* The resulting `ArgStorageProvenance` is stored in the **Testcase's private metadata map** (`testcase.add_metadata`), rather than the global state.
* The mutator is updated to query the metadata of the selected parent testcase (`state.corpus().get(corpus_idx)...`), ensuring correct, uncorrupted mutation guidance.

---

## 3. Success Criteria

1. **Throughput Jump**: Average execution speed on standard mainnet/BSC fork targets increases from ~700 exec/sec to **15,000+ exec/sec** (pure EVM execution limits).
2. **Correct Provenance Attribution**: The mutator successfully retrieves the specific, correct `ArgStorageProvenance` of the base testcase currently selected for mutation.
3. **Exploit Path Integrity**: Zero change to the bug-detection fidelity. Real exploits are still verified with the `INJECTION_CONFIRMED` causal chain, and phantoms (like `burn(0)`) remain fully suppressed.
