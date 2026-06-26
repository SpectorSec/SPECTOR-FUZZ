# Specification — Campaign Orchestrator (Feature 003)

## 1. Architectural Goals
DeFi exploits rarely consist of a single standalone transaction. Instead, they are multi-transaction campaigns where state must be primed sequentially (e.g., flashloan asset -> deposit to vault -> artificially inflate vault share price -> redeem or liquidate). 

To synthesize these complex scenarios deterministically without relying on generic AI or unconstrained random walk, we introduce the **Campaign Orchestrator**. This component plans and executes multi-step transaction sequences by tracing data-flow linkages between contract interface boundaries.
*   **Target:** Introduce a deterministic `CampaignPlanner` integrated into the mutator/scheduler flow.
*   **Data-Driven Chaining:** Utilize the `observed_values` registry (capturing contract outputs) to link step inputs (e.g., step $N$ returns a contract address or token amount which is fed into step $N+1$).
*   **Deterministic State Transitions:** Build sequences sequentially based on matching parameter types (e.g., passing a token address returned by a swap into a lending pool deposit).

---

## 2. Technical Requirements

### A. Sequence Structure & Representation
*   Define a sequence structure (`CampaignSequence`) that represents a logical sequence of transaction inputs (`EVMInput`).
*   Allow the mutator to execute these sequences as a transaction block, ensuring that intermediate state alterations (such as temporary flashloan balances) persist across the sequence.

### B. Linkage-Based Planning
*   **Target Selection:** Scan the ABI registry for contracts matching entry points (flashloans, vaults, protocols).
*   **Chaining Rules:**
    1.  **Asset Sourcing (Step 1):** Identify flashloan providers or swap pools to acquire initial capital/assets.
    2.  **State Priming (Step 2):** Route the acquired assets or returned addresses into target protocols (e.g., deposit, mint, borrow).
    3.  **Exploit Execution (Step 3):** Trigger target function selectors (e.g., liquidate, withdraw, sync) using the linkable parameters.
*   Chaining must align strictly with ABI types (e.g., only feed address return values into address parameter slots).

### C. Validation & Revert Handling
*   If any transaction step in the planned campaign sequence reverts, the orchestrator should mark the sequence as invalid, halting execution early to preserve fuzzing performance ($O(1)$ early aborts).

---

## 3. Investigation Checkpoints (Resolved)

Before any `plan.md` is written, the following checkpoints must be resolved with concrete evidence from the codebase:

### Checkpoint A: Existing Multi-Transaction Infrastructure
*   **Question**: What mechanisms already exist for executing a sequence of operations within a single fuzzer iteration?
*   **Go/No-Go**: If `nested_actions` already supports full ABI-encoded multi-step sequences with intermediate state persistence, the Campaign Planner may reduce to a scheduling wrapper rather than a new execution engine.
*   **Resolution**: [x] **Four mechanisms exist but none provide full multi-transaction campaign support with intermediate `observed_values` routing across steps.**

    **Mechanism 1 — `nested_actions: Vec<NestedAction>` on `EVMInput`:**
    *   Location: `src/evm/input.rs:52-56` (struct def), `src/evm/input.rs:162` (field on EVMInput)
    *   Execution: `src/evm/vm.rs:745` — `self.host.nested_actions = input.get_nested_actions()`
    *   Each action is executed in `host.rs:1027-1052` — writes target address to slot 0, calldata length to slot 9999, calldata chunks to slots 10000+. The *contract bytecode* must explicitly read these slots.
    *   **Limitation**: These are NOT independent ABI calls. They are storage-slot-based IPC that requires the contract to opt-in. The mutator currently populates them for cheatcode pranking (`mutator.rs:341`), not for multi-step sequencing.

    **Mechanism 2 — `repeat: usize` field:**
    *   Location: `src/evm/input.rs:156`, `src/evm/vm.rs:662-670`
    *   Repeats the **same** calldata N times with a fresh interpreter (pc reset between, line 666).
    *   **Limitation**: Identical calldata each iteration. No parameter evolution between repeats. Cannot express Flashloan→Deposit→Exploit.

    **Mechanism 3 — `step` mode (control-leak continuations):**
    *   Location: `src/evm/vm.rs:793-836`
    *   When a contract leaks control (arbitrary call detected), `PostExecutionCtx` is saved into `EVMState.post_execution`. The next input with `step=true` resumes from this context (line 794: `let post_exec = vm_state.post_execution.pop().unwrap()`).
    *   Output is concatenated: `data = Bytes::from([vec![0; 4], res.output.to_vec()].concat())` (line 802).
    *   **Limitation**: Reactive — only triggered when the fuzzer detects a control leak. Cannot express proactive campaigns where no leak occurs.

    **Mechanism 4 — Infant corpus state chaining across fuzzer iterations:**
    *   Location: `src/fuzzers/evm_fuzzer.rs:845-861` (corpus loading), `src/evm/mutator.rs:239-242` (state selection)
    *   Each fuzzer iteration picks an infant state, executes one `EVMInput`, and stores result back. The next iteration can pick that result state.
    *   The `TxnTrace` in `StagedVMState` (via `full_trace` feature) records the chain of `ConciseEVMInput`s that built the state (`src/state_input.rs:26`).
    *   `get_call_seq()` in `src/evm/cov_stage.rs:63-98` and `src/evm/minimizer.rs:37-72` reconstructs the full multi-step `Vec<(EVMInput, u32)>` from the trace.
    *   **Limitation**: Cross-iteration state linkage relies on the scheduler picking the right parent state. There's no guarantee a planned sequence executes atomically. The oracle fires on the final state but the trace must be reconstructed backwards.

    **Conclusion for Go/No-Go**: A new `CampaignSequence` type is needed to represent an atomic multi-step plan executed within a single `evaluate_input_events` call. The existing mechanisms are building blocks but none alone enables "flashloan → A → B → C" with intermediate value routing.

### Checkpoint B: Return-Value-to-Input Routing Resolution
*   **Question**: How does `observed_values` keying map to downstream function parameter slots?
*   **Resolution**: [x] **Linkage is purely value-pool-based, not positional or semantic. Only `observed_values` entries matching the ABI type of the target parameter are eligible; within those, selection is random.**

    *   Location: `src/evm/abi.rs:416-510` (the Phase 2 implementation)
    *   For **address** parameters (line 418-472):
        ```
        1. 50% chance: scan observed_values for contract-local prefix match → collect ALL `EVMU256` values → convert to address → pick random
        2. fallback: scan ABIAddressToInstanceMap + WhaleAddressMetadata → pick random
        3. fallback: random address or zero address
        ```
    *   For **uint256** parameters (line 474-510):
        ```
        1. 50% chance: scan observed_values for contract-local prefix match → collect ALL `EVMU256` values → pick random
        2. fallback: byte_mutator with vm_slots
        ```
    *   Key format (from `value_capture.rs:101`): `"{target:?}_{selector_hex}_return"` — e.g. `"0x1234...abcd_b29e522c_return"`
    *   **No positional awareness**: If a function returns `(uint256, address)`, both values are stored separately under the same key. The mutator cannot know that the first returned word was a token ID and the second was an address. All values of matching type are pooled.
    *   **Implication for Campaign Planner**: The planner must track parameter positions explicitly. It cannot rely on the current pooled linkage for precise routing. A planned sequence should record "Step N output word at index M → Step N+1 input parameter at index P" as explicit metadata.

### Checkpoint C: Campaign Sequence Data Model
*   **Question**: What is the minimal data structure for a `CampaignSequence`?
*   **Resolution**: [x] **The minimal structure is `Vec<ConciseEVMInput>` with a wrapper type, because `EVMInput` is the existing `Input` trait implementor for LibAFL, and `ConciseEVMInput` is the serializable representation.**

    *   `EVMInput` is the LibAFL `Input` implementor. It carries heavy runtime state (`sstate: StagedVMState`, `access_pattern`, `swap_data`) that is `#[serde(skip_deserializing)]` to avoid serialization overhead (input.rs:127,130,143,159).
    *   `ConciseEVMInput` (input.rs:167-215) is the serialization-friendly representation. It is what gets written to disk for corpus/replay files.
    *   Corpus loading (`evm_fuzzer.rs:808-826`) already reads `ConciseEVMInput` from JSON, one per line, grouped into `Vec<ConciseEVMInput>` testcases.
    *   Replay execution (`evm_fuzzer.rs:882-916`) iterates the `Vec<ConciseEVMInput>`, converts each to `(EVMInput, u32)` via `to_input(vm_state)`, and chains states: `vm_state = state.get_execution_result().new_state.clone()` (line 911).
    *   **Key insight**: The replay loop already perfectly chains multi-step sequences. The fuzzer loop (line 862) does not — it calls `fuzz_loop` which processes one `EVMInput` per iteration.
    *   **Conclusion**: A `CampaignSequence` wrapper around `Vec<ConciseEVMInput>` with a `to_inputs(base_state)` method can reuse the existing `evaluate_input_events` or `execute` path. The wrapper should implement or wrap the LibAFL `Input` trait for corpus storage.

### Checkpoint D: Flashloan Priming as Campaign Step 0
*   **Question**: Can a campaign sequence start with a Borrow step, then continue with ABI steps in the same fuzzer iteration?
*   **Resolution**: [x] **Yes, but only if the campaign is executed as multiple sequential `evaluate_input_events` calls (like the replay loop), because `execute()` returns a new `EVMState` that must be fed into the next call.**

    *   Location: `src/evm/vm.rs:1052-1116` (the `execute()` dispatch)
    *   `EVMInputTy::Borrow` execution (lines 1062-1108):
        *   Clones the input's state: `self.host.evmstate = input.get_state().clone()` (line 1074-1077).
        *   Calls `token_ctx.buy(...)` which mutates `self.host.evmstate` (tokens go to caller balance).
        *   Returns `new_state: StagedVMState::new_with_state(self.host.evmstate.clone())` (line 1088-1093).
    *   `EVMInputTy::ABI` execution (line 1113): `self.execute_abi(input, state)` — clones state at line 744: `let mut vm_state = input.get_state().clone()`.
    *   **The Borrow path updates `self.host.evmstate` directly, buys tokens, and returns the new state.** If a campaign sequence processes Borrow first, then ABI, the ABI step must use the Borrow's output state as its input state.
    *   **This is exactly what the replay loop does** (evm_fuzzer.rs:852-859): calls `evaluate_input_events` for each step, captures `state.get_execution_result().new_state`, and passes it to the next `to_input(vm_state)`.
    *   **Conclusion**: Campaign execution must mirror the replay loop pattern — sequential `evaluate_input_events` calls per step, with state chaining. A new `CampaignSequence` type does not need to modify the `execute()` internals; it wraps the multi-step call chain.

### Checkpoint E: Minimization Semantics for Multi-Step Exploits
*   **Question**: Can the existing trace minimizer handle multi-input sequences?
*   **Resolution**: [x] **Yes. `EVMMinimizer` in `src/evm/minimizer.rs:94-176` already handles multi-transaction traces and uses greedy skip-one-at-a-time minimization.**

    *   Location: `src/evm/minimizer.rs:94-176`
    *   Algorithm (lines 121-170):
        1. Reconstruct the full `Vec<(EVMInput, u32)>` from the `TxnTrace` via `get_call_seq()` (line 118).
        2. For each index `try_skip` (0..txs.len()), execute all transactions except the skipped one, starting from `initial_state` (lines 125-157).
        3. If the oracle still fires (`objective.reproduces()`), remove that transaction permanently (line 160-165).
        4. Repeat until a full pass removes nothing (lines 123, 166).
    *   **State chaining** inside the minimizer: `current_state = state.get_execution_result().new_state.clone()` (line 152), exactly matching the replay loop pattern.
    *   **Revert handling**: If a pruned sequence causes a revert, the loop breaks early via `if reverted { break; }` (lines 154-156).
    *   **Conclusion**: The minimizer is already multi-step aware. A `CampaignSequence` can be minimized by converting to `Vec<(EVMInput, u32)>` and running the existing `EVMMinimizer::minimize()`. No new minimizer logic is needed.
