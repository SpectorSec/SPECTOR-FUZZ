# Task List — Data-Flow Linkage Seeding

**Status:** In Progress  
**Owner:** TBD  
**Last updated:** 2026-06-25  

This document lists the sequential tasks required to implement the Data-Flow Linkage Seeding.

---

## Task Checklist

- [x] **Task 1 — Update `mutate_with_vm_slots` signature**  
  *Description:* Update signature of `mutate_with_vm_slots` in `abi.rs` to take `active_contract` and `observed_values`.  
  *Touches:* [src/evm/abi.rs](file:///workspace/_global/ityfuzz-src/src/evm/abi.rs)

- [x] **Task 2 — Update recursive calls in `abi.rs`**  
  *Description:* Propagate the new arguments to all nested `mutate_with_vm_slots` calls inside array and tuple mutation blocks.  
  *Touches:* [src/evm/abi.rs](file:///workspace/_global/ityfuzz-src/src/evm/abi.rs)

- [x] **Task 3 — Update call sites in `input.rs` and `mutator.rs`**  
  *Description:* Update top-level mutator invocation sites to extract the active contract and `observed_values` from input/state and pass them down.  
  *Touches:* [src/evm/input.rs](file:///workspace/_global/ityfuzz-src/src/evm/input.rs), [src/evm/mutator.rs](file:///workspace/_global/ityfuzz-src/src/evm/mutator.rs)

- [ ] **Task 4 — Implement linkage lookup and seeding**  
  *Description:* Implement lookup matching active contract address prefixes against keys in `observed_values` and falling back to state-wide keys.  
  *Touches:* [src/evm/abi.rs](file:///workspace/_global/ityfuzz-src/src/evm/abi.rs)

- [ ] **Task 5 — Write unit and integration tests**  
  *Description:* Write a test verifying that the mutator successfully extracts and uses observed values when mutating inputs.  
  *Touches:* [src/evm/middlewares/value_capture.rs](file:///workspace/_global/ityfuzz-src/src/evm/middlewares/value_capture.rs) or [src/evm/abi.rs](file:///workspace/_global/ityfuzz-src/src/evm/abi.rs)
