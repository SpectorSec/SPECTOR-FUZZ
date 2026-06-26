# Implementation Plan — Data-Flow Linkage Seeding (Feature 002)

## 1. Architectural Strategy
We will link captured execution values, contract storage slots, and deployed address registries directly into the EVM ABI Mutator. When mutating `uint256` or `address` parameters, we resolve values using a strict hierarchy of support structures:

### A. Uint256 Parameter Mutation Hierarchy
1.  **Contract-Local Return Linkage:** Lookup observed return values under keys matching the active contract (`{active_contract}_*_return`).
2.  **State-Wide Return Linkage:** Fallback to observed return values from any contract in the state.
3.  **Storage Slot Hints:** Draw from the contract's actual storage slots (`vm_slots` populated by `sload` and `sstore` tracking).
4.  **Standard Fallback:** Default to standard LibAFL byte mutation (bit-flips, additions, subtractions).

### B. Address Parameter Mutation Hierarchy
1.  **Contract-Local Return Linkage:** Use observed address return values from the active contract.
2.  **State-Wide Return Linkage:** Use observed address return values from any contract.
3.  **Deployed Address Registry:** Draw from known deployed target contract addresses (`ABIAddressToInstanceMap`) or registered whale/caller addresses (`WhaleAddressMetadata`).
4.  **Standard Fallback:** Default to standard random address generation or the zero address.

---

## 2. Code Changes

### A. Update `mutate_with_vm_slots` Signature
Modify the signature in [src/evm/abi.rs](file:///workspace/_global/ityfuzz-src/src/evm/abi.rs) to:
```rust
    pub fn mutate_with_vm_slots<Loc, Addr, VS, S, CI>(
        &mut self,
        state: &mut S,
        vm_slots: Option<HashMap<EVMU256, EVMU256>>,
        active_contract: Option<EVMAddress>,
        observed_values: Option<&HashMap<String, Vec<EVMU256>>>,
    ) -> MutationResult
```
Propagate this update through recursive array/tuple mutator calls and top-level invocations in `input.rs` and `mutator.rs`.

### B. Implement Seeding Hierarchy in `abi.rs`
For `T256` (U256 and Address) parameters:
* Implement the priority lookup tree for return linkage, storage slots, and registered target address structures.
* Safely write chosen bytes directly to the mutated parameter's data buffer.
