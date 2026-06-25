# Implementation Plan — Value Capture Middleware

**Status:** Planned  
**Owner:** TBD  
**Last updated:** 2026-06-25  

---

## 1. Algorithm Design & Pseudocode

The **Value Capture Middleware** records returned U256 values from contract calls.

### Middleware State
```rust
struct ValueCaptureMiddleware {
    // Keeps track of active nested calls: (target_address, selector)
    call_stack: Vec<(EVMAddress, [u8; 4])>,
}
```

### Call Entry Interception (`on_step`)
During `on_step`, when we encounter a call opcode (CALL, STATICCALL, DELEGATECALL, CALLCODE):
```
1. Get opcode at current pc.
2. If opcode in [0xf1, 0xf2, 0xf4, 0xfa]:
    a. Peek stack to retrieve target_address.
    b. Peek stack to retrieve arg_offset and arg_len.
    c. If arg_len >= 4:
        i. Read 4 bytes from interpreter memory at arg_offset.
        ii. Push (target_address, selector) to call_stack.
    d. Else:
        i. Push (target_address, [0u8; 4]) to call_stack (fallback/empty call).
```

### Call Return Interception (`on_return`)
When a sub-call completes, `on_return` fires:
```
1. Pop (target_address, selector) from call_stack.
2. If call_stack was empty, return.
3. If ret_bytes.len() >= 32:
    a. For each 32-byte chunk in ret_bytes:
        i. Convert chunk to EVMU256.
        ii. Format key as: "{target_address:?}_{selector_hex}_return".
        iii. Access host.evmstate.observed_values.
        iv. If value is not already present:
            - Push value to observed_values[key].
            - If observed_values[key].len() > 10:
                - Remove oldest element (keep last 10 unique values).
```

### Top-Level Call Interception (End of `execute_from_pc`)
At the very end of `execute_from_pc` in `vm.rs`:
```
1. Get selector (first 4 bytes) from input.to_bytes().
2. Get target_address from input.get_contract().
3. If result.output.len() >= 32:
    a. For each 32-byte chunk in result.output:
        i. Convert chunk to EVMU256.
        ii. Format key as: "{target_address:?}_{selector_hex}_return".
        iii. If value is not already present in result.new_state.observed_values[key]:
            - Push value to result.new_state.observed_values[key].
            - Cap history at 10 unique values.
```

---

## 2. Modified Existing Files

### A. `src/evm/vm.rs`
- Add `observed_values: HashMap<String, Vec<EVMU256>>` to `EVMState`.
- Update `execute_from_pc` to intercept the top-level return value and store it in `result.new_state.observed_values`.

### B. `src/evm/middlewares/middleware.rs`
- Add `ValueCapture` variant to `MiddlewareType` enum:
```rust
pub enum MiddlewareType {
    ...
    ValueCapture,
}
```

### C. `src/evm/config.rs`
- Add `value_capture: bool` configuration field.
- Bind CLI option `--value-capture` to the configuration.

### D. `src/fuzzers/evm_fuzzer.rs`
- Instantiate and register `ValueCaptureMiddleware` in `fuzz_host` if `config.value_capture` is enabled.

---

## 3. New Files Created

- `src/evm/middlewares/value_capture.rs` containing the `ValueCaptureMiddleware` struct and its implementation of `Middleware<SC>`.

---

## 4. LibAFL Trait Implementations

We implement the `Middleware<SC>` trait for `ValueCaptureMiddleware`. It does not require implementing custom LibAFL traits directly, but interacts with `EVMFuzzState` and `FuzzHost`.

---

## 5. Performance Analysis

- **Memory Overhead**: The `observed_values` map is capped to 10 unique values per selector. String keys are short. Memory footprint per state remains under ~1KB even for deep execution paths.
- **CPU Overhead**: Peeking the stack and reading memory in `on_step` is done only on CALL opcodes. This avoids checking every single instruction, maintaining high interpreter throughput.
- **Lock Contention**: The Value Chain Graph is completely thread-local and in-memory. No database locks are acquired.

---

## 6. Testing Plan

### A. Unit Tests
- Create unit tests in `src/evm/middlewares/value_capture.rs` testing the parsing of return data bytes into U256 values.
- Verify that the history limit (10 values) is strictly enforced and oldest unique values are correctly maintained.

### B. Integration Test
- Create a test Solidity contract `ValueCaptureTest.sol` with:
  - `function getDynamicValue() public returns (uint256)` returning a dynamic counter or pseudo-random hash.
  - A script to fuzz this contract offline with `--value-capture` enabled.
- Verify that the returned counter value is captured and stored in the `observed_values` map of the resulting states in the corpus.

### C. Regression Test
- Run the fuzzer on `ValueCaptureTest.sol` without the flag and verify that `observed_values` remains empty.
- Run the baseline B1 fuzzer test suite to confirm zero performance drop when disabled.

---

## 7. Rollback Plan

If the changes cause compile errors or regressions:
1. Revert changes to modified files using git:
   ```bash
   git checkout src/evm/vm.rs src/evm/middlewares/middleware.rs src/evm/config.rs src/fuzzers/evm_fuzzer.rs
   ```
2. Remove `src/evm/middlewares/value_capture.rs`.
