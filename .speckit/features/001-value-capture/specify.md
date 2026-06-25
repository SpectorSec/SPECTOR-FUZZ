# Feature 001 — Value Capture Middleware

**Status:** In Progress  
**Owner:** TBD  
**Last updated:** 2026-06-25  

---

## Overview

DeFi exploits typically depend on multi-transaction sequences where values returned by one contract call (e.g. flash loan amount, reserve level, dynamic share price, token indices, vault balances) are reused as inputs to subsequent calls. Without capturing these dynamically produced return values, the fuzzer struggles to generate valid multi-step exploit sequences.

This feature implements the **Value Capture Middleware** (Phase 1 of the SPECTOR-FUZZ cognitive architecture). It intercepts call returns, extracts returned 32-byte words (interpreted as EVM U256 values), and maps them in an in-memory `observed_values` registry within `EVMState`. These values form a thread-local "Value Chain Graph" that the mutator can later query to route return values to subsequent inputs, avoiding expensive disk I/O lock contention.

---

## Why This Matters

Traditional fuzzers randomly mutate inputs based on a static seed corpus or simple comparison constants. In complex DeFi protocols:
1. A user deposits funds, receiving a dynamically generated `liquidityPositionID` or `vaultShareAmount`.
2. To trigger a withdrawal or exploit a vulnerability, the subsequent transactions must target exactly those returned values.
3. If the returned values are not recorded and fed back into the mutator, the chance of hitting the exact 256-bit identifier is practically zero.

Implementing an in-memory, thread-local Value Capture middleware captures this feedback loop at maximum execution speed without hitting disk storage.

---

## Success Criteria

This feature is worth building if and only if:
1. Return values from both top-level execution calls and internal calls (e.g. STATICCALL, CALL) can be intercepted dynamically.
2. The active function signature (selector) for the intercepted return value can be accurately identified.
3. The captured return values can be associated directly with the corresponding execution state (`EVMState`) inside the infant state corpus without introducing memory leaks or excessive cloning overhead.
4. The fuzzer compile time and baseline fuzzing speed (~2M iterations in 30 mins) are not regressed when the middleware is disabled.

---

## Out of Scope

- A persistent database (RocksDB/Sled) for the Value Chain Graph. (This is strictly in-memory and ephemeral inside `EVMState` to avoid slowing down REVM).
- Injecting the captured values into the mutator. (Mutator integration belongs to a subsequent phase/feature).
- Complex heuristic parsing of nested ABI return structures. (We focus on raw 32-byte chunks/words, which cover addresses, slot keys, token balances, and IDs).

---

## Investigation Checkpoints

These must all be resolved before `plan.md` is written. Each checkpoint requires concrete evidence from the codebase.

### Checkpoint 1.1 — Trace Call Return Interception in Fuzzer
**Files:** `src/evm/host.rs`, `src/evm/middlewares/middleware.rs`  
**Question:** Where does the fuzzer execute calls, and how does it invoke the registered middlewares' `on_return` function? Does `on_return` get called for all sub-calls (internal CALL/STATICCALL/DELEGATECALL), or only for the top-level transaction execution?  
**Evidence required:** Paste the exact code blocks from `host.rs` showing the `on_return` invocation and trace where calls are executed.  
**Resolution:** [x] **Sub-calls are intercepted via `on_return` in `call_internal`; top-level transaction returns must be intercepted at the end of `execute_from_pc`.**
*Evidence:* In `src/evm/host.rs` line 1458, `on_return` is invoked on all active middlewares inside `call_internal`:
```rust
        unsafe {
            if self.middlewares_enabled {
                let mut middlewares = self.middlewares.read().unwrap().clone();
                for middleware in middlewares.iter_mut() {
                    middleware
                        .deref()
                        .borrow_mut()
                        .on_return(interp, self, state, &ret_buffer);
                }
            }
        }
```
`call_internal` executes nested/internal calls but not the top-level transaction call. For the top-level transaction call, we will manually invoke the middleware `on_return` callback at the end of `execute_from_pc` in `src/evm/vm.rs` using `result.output`.

### Checkpoint 1.2 — Retrieve Active Function Selector/Signature
**Files:** `src/evm/host.rs`, `src/evm/middlewares/`  
**Question:** How does the middleware determine which function returned the captured data? Is there an existing call stack or active function selector variable inside `FuzzHost` or `Interpreter`, or must we track the selectors ourselves?  
**Evidence required:** Code snippets or architectural analysis showing how call context (contract address, function selector) is tracked during execution and returns.  
**Resolution:** [x] **No built-in call stack exists. We track call context in `on_step` and pop in `on_return`. Top-level calls use `input.to_bytes()`.**
*Evidence:* By peeking at call opcodes in `on_step` (like `CallPrinter` does in `src/evm/middlewares/call_printer.rs` at line 185), we can retrieve `arg_offset` and `arg_len` from the stack, extract the 4-byte selector from `interp.memory`, and maintain our own internal call stack `Vec<(EVMAddress, [u8; 4])>`. On `on_return`, we pop from this stack to match the return value to the caller. Top-level calls are resolved directly using the `EVMInput`.

### Checkpoint 1.3 — Accessing and Extending `EVMState`
**Files:** `src/evm/vm.rs`, `src/evm/host.rs`  
**Question:** Where is the `EVMState` struct defined, and how do middlewares access it? Can we modify `EVMState` to include `observed_values`? How does `FuzzHost` map to the active `EVMState`?  
**Evidence required:** Paste the definition of `EVMState` and search for how it is accessed or updated inside middlewares (e.g. `Cheatcode` or `Sha3Bypass`).  
**Resolution:** [x] **`EVMState` is defined in `vm.rs` and accessed via `host.evmstate`. Modifications automatically propagate.**
*Evidence:* `EVMState` is defined in `src/evm/vm.rs` line 225. During execution, the active state is held in `FuzzHost::evmstate` (`src/evm/host.rs` line 179). Any updates to `host.evmstate` are cloned back into `result.new_state` inside `execute_from_pc` (line 675) when the execution ends, which is then added to the corpus. Thus, updating `host.evmstate.observed_values` directly updates the state saved in the corpus.

### Checkpoint 1.4 — Serialization and Performance impact on `EVMState`
**Files:** `src/evm/vm.rs`, `src/state.rs`  
**Question:** Does `EVMState` derive serialization traits? What will be the impact of adding `observed_values: HashMap<String, Vec<EVMU256>>` to `EVMState` on memory usage, serialization speed, and code compilation?  
**Evidence required:** Check how `EVMState` is serialized/deserialized in the codebase and identify any potential bottlenecks.  
**Resolution:** [x] **Uses derived serialization. Adding a capped `HashMap` preserves compilation and speed.**
*Evidence:* `EVMState` derives `Serialize` and `Deserialize` (line 224 in `vm.rs`). Adding `observed_values: HashMap<String, Vec<EVMU256>>` requires no custom serialization code. To guarantee that memory usage and cloning overhead remain completely negligible, we will cap the history size (e.g. keeping at most 10 unique values per selector).

---

## What We Know vs. What We're Assuming

| Claim | Status | Source |
|---|---|---|
| Fuzzing multi-step DeFi flows requires routing dynamically generated return values | **Known** | Protocol analysis and fuzzer theory |
| `on_return` middleware callback intercepts return data | **Known** | `middleware.rs` trait definition |
| FuzzHost has access to the current transaction/call execution context | **Known** | `host.rs` design |
| EVMState is stored inside the infant state corpus and can be modified | **Known** | `vm.rs` and `state.rs` implementation |

---

## Rough Design Hypothesis (do not implement until checkpoints clear)

We will implement `ValueCaptureMiddleware` as a new middleware struct. When `on_return` is invoked:
1. Extract the active call context (target address and function selector).
2. Read the return buffer `_ret`. If it contains data (specifically checking if size >= 32 bytes), parse it into U256 words.
3. Fetch the mutable reference to the current `EVMState` from `host.evmstate`.
4. Append the parsed U256 values to `observed_values` under a key corresponding to the selector (e.g. `"0x12345678_ret"` or similar) with a history limit of 10.
5. Expose this through a new CLI flag `--value-capture` which is disabled by default.

---

## Dependencies on Other Features

- This is Phase 1 and serves as the foundation for the mutator routing (Phase 4).
