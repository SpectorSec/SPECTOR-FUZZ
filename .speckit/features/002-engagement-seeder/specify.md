# Specification — Data-Flow Linkage Seeding (Feature 002)

## 1. Architectural Goals
DeFi exploits typically depend on matching outputs of one contract call to the inputs of another (e.g. matching a dynamic token balance or share output to a subsequent transfer or redeem input). 

Rather than relying on fuzzy pattern matching, we implement **Data-Flow Linkage Seeding**. This is a deterministic data-routing mechanism linking captured EVM return values directly to candidate mutation slots based on structural boundaries.
*   **Target:** Make the Mutator (`src/evm/mutator.rs`) query `observed_values` to dynamically seed candidate input parameters.
*   **Linkage Routing:** When mutating a transaction input parameter, the mutator draws from observed return values associated with the target contract, preserving exact value state transitions.
*   **Performance Integrity:** The lookup must be direct ($O(1)$ mapping or basic local filtering), ensuring no latency impact on the critical execution loop.

---

## 2. Technical Requirements

### A. Context Propagation
*   The `mutate_with_vm_slots` function must receive the active contract address and a reference to the `observed_values` database from the active fuzzer state.

### B. Linkage Priorities
1.  **Contract-Local Linkage:** Prioritize values previously returned by the target contract being called (keys matching `{active_contract}_*_return`).
2.  **State-Wide Linkage:** Fall back to observed return values from any other contract in the current execution state.
3.  **Standard Fallback:** Fall back to the fuzzer's default random mutations or constant pools if no observed values exist.
