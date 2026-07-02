# Feature 014 — TAINT Model Oracles (Non-Injection Primitives)

**Status:** Planning
**Owner:** TBD
**Last updated:** 2026-06-30
**Depends on:** Feature 013 Phase 0 (taint engine bugs fixed)

---

## Why This Exists

Feature 013 covers the **CALL boundary** (7 models) and **persistent cross-execution taint** (2 models). That's 9 of the 14 TAINT 3 models.

These 5 cannot be detected at CALL boundaries or persistent storage alone. They need **opcode sequence analysis**, **return-value tracking**, and/or **balance state diff**. They are the TAINT models that survive as separate infrastructure even after 013 is built.

```
013 Phase 2 covers:  THEFT, GOVERNANCE, REENTRANCY, SAFE_ERC20,
                     BALANCE_DELTA, CALLGAP, ASYMMETRY
                     (all are "did attacker data reach a CALL param?")

013 Phase 3-4 covers: ACCOUNTING_DESYNC, LIQUIDATION_CASCADE
                     (all are "was this slot poisoned by a prior execution?")

014 covers:           ORACLE, FLASH_LOAN, ORACLE_STALE,
                     EMPTY_STATE, DoS
                     (all need "what happened BETWEEN and AFTER CALLs?")
```

### Oracle Reduction

SpecterFuzz today has **18 oracles** (15 flaggable + 3 auto-detected). After 013 + 014:

| Fate | Count | Oracles |
|---|---|---|
| **Dead code** (subsumed by taint) | **3** | arbitrary_call, function, approval |
| **Absorbed into middleware** (heuristic → inline) | **4** | reentrancy, pair, fee_on_transfer, freshness |
| **Survive unchanged** (correctly post-hoc or domain-specific) | **11** | erc20, erc4626, rebasing, typed_bug, echidna, invariant, selfdestruct, nft, crosschain, math_calculate, topology |
| **Total removed or absorbed** | **7 of 18 (~39%)** | — |

The heuristics layer shrinks by nearly 40%. The surviving 11 are either correctly post-hoc (balance diffs, invariants) or domain-specific (NFT, cross-chain, selfdestruct) — not reachability guesses that taint proves instead.

---

## Investigation Checkpoints

Every checkpoint below was resolved against the current source code at commit HEAD of `github.com/fuzzland/ityfuzz`. All are **CONFIRMED** — no unresolved research questions remain.

| # | Question | Source Evidence | Verdict |
|---|---|---|---|
| **014.CP.0** | Does `on_return` receive the return data Bytes? Can it distinguish CALL vs DELEGATECALL for return-value taint? | `middleware.rs:87-94`: `unsafe fn on_return(&mut self, _interp: &mut Interpreter, _host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState, _ret: &Bytes)` — has `_ret` for return data, `_interp` for opcode access. `cmp_linearity.rs:509-519` confirms current impl is just `self.pop_ctx()`. | **CONFIRMED** — extension point ready. |
| **014.CP.1** | Does existing code define oracle function selectors for return-value taint marking? | `freshness.rs:45-59`: `LATEST_ROUND_DATA_SEL`, `LATEST_ANSWER_SEL`, `GET_ROUND_DATA_SEL` constants and `pub fn is_oracle_interface(sel: &[u8; 4]) -> bool`. FreshnessOracle is instantiated in `evm_fuzzer.rs:568`. | **CONFIRMED** — oracle selectors already defined. Reuse in middleware. |
| **014.CP.2** | Do comparison opcode handlers (LT/GT/EQ) have access to both operands' taint bits? | `cmp_linearity.rs:340-355`: `0x10..=0x14 => { let a = pop!(); let b = pop!(); ... if a.t \|\| b.t { LIN_SAW_TAINTED_CMP = true; } }` — both operands' TB values on the shadow stack are observable. | **CONFIRMED** — comparison taint check pattern proven. |
| **014.CP.3** | Does a slot detection infrastructure exist for identifying totalSupply/balance slots at runtime? | `slot_detector.rs` — full module with `get_cached_balance_slot()`, `compute_mapping_storage_slot()`, known token slot overrides, whale addresses. Used by `seed_erc20_balances()` in `corpus_initializer.rs:134`. | **CONFIRMED** — slot_detector.rs available for 014 Phase 4 (empty state guard). |
| **014.CP.4** | Is there an existing FreshnessOracle that performs post-hoc staleness checks? | `freshness.rs:35-43`: FreshnessOracle with `max_staleness: u64`, oracle_contracts list, latestRoundData selector. Post-hoc: fires AFTER execution by re-calling the oracle. | **CONFIRMED** — post-hoc oracle exists; 014 Phase 3 (inline check) complements it. |
| **014.CP.5** | Does the REVERT opcode handler (0xfd/0xfe) track anything? Can pre-revert comparison state be recovered? | `cmp_linearity.rs:502`: `0xfd \| 0xfe \| 0xff => {}` — no-op. No pre-revert comparison saved. 014 Phase 5 (DoS detection) must add `LAST_CMP_A/B` tracking before `0x10..=0x14` and read it at REVERT. | **CONFIRMED** — REVERT is a blank slate; pre-revert tracking can be added. |
| **014.CP.6** | Is TIMESTAMP (0x42) tracked in the shadow stack? Can it be used as a staleness-check landmark? | `cmp_linearity.rs:409`: `0x42 \| 0x43 => pushtb!(TB { t: true, nl: false })` — TIMESTAMP and NUMBER are marked as taint sources. No staleness-specific tracking exists. | **CONFIRMED** — TIMESTAMP is in the opcode dispatch; staleness window tracking is new. |

### Gate Check: All 014 Investigation Checkpoints resolved with concrete source evidence. Proceeding to plan.md.

---

## Dependency Graph

```
Phase 0: Return-Value Taint Propagation
  │
  ├──► Phase 1: Oracle Detection
  │       │
  │       └──► Phase 2: Flash Loan Detection (oracle + borrow sequence)
  │
  ├──► Phase 3: Oracle Staleness Detection
  │
  ├──► Phase 4: Empty State Guard Detection
  │
  └──► Phase 5: DoS Detection
```

Phase 0 is the foundation for multiple downstream phases. Phases 1-5 are independent of each other.

---

## Phase 0 — Return-Value Taint Propagation

**Goal:** Mark taint on the RETURN path from CALLs, not just the CALL boundary. Extend the taint engine to track "this value came from an oracle" or "this value was produced by an external contract call."

### Problem

Current taint engine only propagates taint from **calldata** (input bytes). Values returned by CALLs are treated as clean — `clean!()` or `popn!()` discards any taint the child might have labeled.

For example: `latestRoundData()` returns `(roundId, answer, startedAt, updatedAt, answeredInRound)`. The `answer` value is pushed onto the parent's stack. The engine sees it as clean. But if the oracle is manipulated, this value is the attacker's lever.

### Mechanism

After `pop_ctx()` in `on_return`, mark the shadow stack positions corresponding to the return data:

```rust
fn on_return(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, ...) {
    // Existing: restore parent context
    self.pop_ctx(opcode);

    // NEW: propagate oracle taint from return data
    // The RETURNDATA contains the child's output. If the child was
    // a known oracle function, mark the return value as oracle-tainted.
    let ret_offset = saved_ret_offset;  // from the CALL's stack frame
    let ret_len = saved_ret_len;

    if is_known_oracle(callee_address, calldata_selector) {
        // Mark return data bytes as oracle-tainted
        for i in ret_offset..ret_offset + ret_len {
            self.mem[i] = true;  // oracle-tainted
        }
    }
}
```

### Oracle Detection at Init

Load known oracle selectors from init-time analysis:

```rust
// FuzzHost init:
oracle_selectors: HashMap<EVMAddress, Vec<[u8; 4]>> = detect_oracles(abimap);
// Known patterns:
// - Chainlink: latestRoundData (0xfeaf968c), latestAnswer (0x50d25bcd)
// - Uniswap V2: getReserves (0x0902f1ac)
// - Uniswap V3: slot0 (0x3850c7bd)
// - TWAP: observe (0x883bdbfd)
// - Custom: getPrice, getRate, getAssetPrice, peek, getTwap
```

### What It Unlocks

Without Phase 0, the engine never sees that a comparison value came from an oracle. With Phase 0, every subsequent phase can check: "is this comparison's operand oracle-tainted?"

### Files:
- `src/evm/middlewares/cmp_linearity.rs` — extend `on_return` with return-value taint
- `src/evm/host.rs` — add `oracle_selectors` to FuzzHost

---

## Phase 1 — Oracle Detection

**Goal:** Detect when oracle return values are compared and the comparison gates a value-moving CALL.

### The Pattern

```
CALL latestRoundData() → returns answer
  ↓
stack ← answer (oracle-tainted by Phase 0)
  ↓
LT/GT/EQ(price_ceiling, answer) → gate check
  ↓
JUMPI(revert_path) → if answer passes check, continue
  ↓
CALL borrow(amount = f(answer)) ← value movement gated by oracle
```

### Detection

In `on_step` at comparison opcodes (0x10-0x14):

```rust
0x10..=0x14 => {
    let a = pop!();
    let b = pop!();
    let oracle_involved = (a.t && was_oracle_source(a)) || (b.t && was_oracle_source(b));

    if oracle_involved {
        // Record: "an oracle value was compared at this PC"
        ORACLE_CMP_PCS.insert((address, pc));
    }

    if oracle_involved && comparison_result_was_pass {
        // The oracle value passed the gate check AND
        // a subsequent CALL moves value based on oracle data
        ORACLE_GATED_TRANSFER_DETECTED = true;
    }
}
```

Then at the next CALL boundary, check if the CALL target or amount is derived from an oracle-compared value. If yes, it's an **oracle-gated drain**.

### Relationship to 013

013's THEFT model catches "calldata controlled `from` param." Oracle catches "oracle value controlled `amount` param." Both are provenance, different source:

```
013: input bytes → CALL to address (attacker-controlled target)
014: oracle return → comparison → borrow amount (price-manipulated value)
```

### Files:
- `src/evm/middlewares/injection_detect.rs` — add oracle-return checks to comparison handler
- OR new middleware `oracle_tracker.rs`

---

## Phase 2 — Flash Loan Detection

**Goal:** Detect the oracle-manipulation-with-flash-loan pattern: borrow capital → manipulate oracle price → exploit gated function → repay loan.

### The Pattern

```
CALL flashloan(amount)   ← borrow large capital (FLASH_LOAN model)
  ↓
CALL latestRoundData()   ← read oracle (ORACLE model)
  ↓
swap()                    ← manipulate TWAP/oracle feed
  ↓
CALL latestRoundData()   ← read manipulated oracle
  ↓
comparison: oracle_now > oracle_before
  ↓
CALL borrow(amount = f(spread)) ← exploit the manipulated price
  ↓
CALL repay(flashloan)    ← repay the flash loan
```

### Detection

Sequence of CALLs within the same execution:

```rust
// Track oracle reads and borrow/mint CALLs in sequence
let oracle_reads: Vec<(EVMAddress, [u8; 4], EVMU256)>;
   // (address, selector, return_value)
let value_movements: Vec<(EVMAddress, [u8; 4], EVMU256)>;
   // (sink_address, selector, amount)

// After execution, check:
if oracle_reads.len() >= 2
   && value_movements.len() >= 1
   && time_between(oracle_reads) > 0  // oracle was read at two different times
   && value_delta(oracle_reads[0], oracle_reads[1]) > threshold
   && amount(value_movements[0]) > epsilon
{
    // FLASH_LOAN_MANIPULATION: oracle was read twice with different values,
    // and a borrow/mint occurred between/between the reads
}
```

### Relationship to Phase 1

Phase 1 detects a single oracle-gated comparison. Phase 2 detects the multi-CALL sequence: oracle read → price change → second oracle read → exploit. Phase 1 is "your comparison depends on an oracle." Phase 2 is "your oracle changed between reads and a value moved."

### Files:
- `src/evm/middlewares/flashloan_oracle.rs` — new middleware tracking oracle read sequences

---

## Phase 3 — Oracle Staleness Detection

**Goal:** Detect when an oracle's `updatedAt` field is not checked against current `block.timestamp`, meaning stale data can be used.

### The Pattern

```solidity
(uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) =
    priceFeed.latestRoundData();

// Missing: require(updatedAt >= block.timestamp - FRESHNESS_PERIOD, "stale");
_oracleBasedAction(answer);  // uses possibly stale answer
```

### Detection

At CALL to `latestRoundData` (0xfeaf968c), the return data contains `updatedAt` at a known offset. After the CALL returns, track the return data bytes:

1. Read `updatedAt` from the CALL's return data (RETURNDATA)
2. Within the next ~50 opcodes, check if `TIMESTAMP` (0x42) is pushed onto the stack
3. Check if a comparison (`LT`/`GT`/`EQ`) uses `updatedAt` and `TIMESTAMP` as operands
4. If the comparison is absent → **stale oracle check missing**

```rust
fn on_step(...) {
    match opcode {
        0xf1 if is_latestRoundData(interp.callee(), interp.calldata()) => {
            ORACLE_READ_PC = Some(interp.bytecode.pc());
        }
        0x42 => {  // TIMESTAMP
            if ORACLE_READ_PC.is_some() && recent_pc(interp.bytecode.pc(), ORACLE_READ_PC, 50) {
                TIMESTAMP_AFTER_ORACLE = true;
            }
        }
        0x10..=0x14 if TIMESTAMP_AFTER_ORACLE && UPDATED_AT_ON_STACK => {
            STALE_CHECK_OBSERVED = true;
        }
    }
}

fn on_return(...) {
    if STALE_CHECK_OBSERVED {
        // PASS — timestamp was compared against updatedAt
    } else if ORACLE_READ_PC.is_some() && execution_did_not_revert {
        // FAIL — oracle was read but no staleness check in next 50 opcodes
        STALE_ORACLE_DETECTED = true;
    }
}
```

### Relationship to existing Freshness oracle

The existing `freshness.rs` oracle is post-hoc: it checks `block.timestamp - last_update > threshold` after execution. Phase 3 checks it inline: "was there a timestamp comparison within 50 opcodes of the oracle read?" The inline check has lower FP — it catches the absence of the check itself, not a computed staleness threshold.

Winner: run both. Inline for mechanism, post-hoc for outcome.

### Files:
- `src/evm/middlewares/oracle_staleness.rs` — new middleware tracking TIMESTAMP vs updatedAt

---

## Phase 4 — Empty State Guard Detection

**Goal:** Detect when `mint`/`deposit` functions do not check `totalSupply` before transferring value, enabling the first-deposit inflation attack (ERC-4626).

### The Pattern

```solidity
function deposit(uint256 assets, address receiver) returns (uint256 shares) {
    // Missing:
    // require(totalSupply() > 0, "first deposit must provide minimum");
    // or:
    // if (totalSupply() == 0) shares = assets - MIN_SHARES;

    _mint(receiver, shares = convertToShares(assets));
    _transferFrom(msg.sender, address(this), assets);  // value moves before totalSupply guard
}
```

### Detection

At CALL to `deposit` (0x47e7ef24) / `mint` (0x94bf804d) / `withdraw` (0x69328dec) / `redeem` (0xba087652):

1. Within the first ~30 opcodes of the called function, check for SLOAD of `totalSupply` slot
2. Track the opcode sequence: is SLOAD followed by comparison → JUMPI (revert on zero)?
3. If the function reaches `CALL transferFrom`/`MSTORE(transfer_event)` without executing a totalSupply guard → **empty state guard missing**

```rust
fn on_step(...) {
    match opcode {
        0xf1 if is_deposit_mint_redeem(interp.calldata()) => {
            TOTAL_SUPPLY_CHECKED = false;
            MONITOR_SLOAD = true;
        }
        0x54 if MONITOR_SLOAD && is_totalSupply_slot(interp.stack.peek(0)) => {
            TOTAL_SUPPLY_SLOAD_SEEN = true;
        }
        0x10..=0x14 if TOTAL_SUPPLY_SLOAD_SEEN && !TOTAL_SUPPLY_JUMPI_SEEN => {
            // Comparison of totalSupply against something
        }
        0x57 if TOTAL_SUPPLY_SLOAD_SEEN && !TOTAL_SUPPLY_JUMPI_SEEN => {
            // JUMPI — likely the `require(totalSupply > 0)` guard
            TOTAL_SUPPLY_JUMPI_SEEN = true;
        }
        0xf1 if is_transfer(interp.calldata()) && MONITOR_SLOAD && !TOTAL_SUPPLY_JUMPI_SEEN => {
            // Value moved without totalSupply guard
            EMPTY_STATE_GUARD_MISSING = true;
        }
    }
}
```

### Slot Detection

The `totalSupply` slot for ERC-4626 / ERC-20 is typically slot 0, but may be different for proxies or non-standard layouts. Use the existing `slot_detector.rs` infrastructure or heuristic: the first SLOAD within a deposit function that returns a value used in a subsequent comparison.

### Files:
- `src/evm/middlewares/empty_state_guard.rs` — new middleware

---

## Phase 5 — DoS Detection

**Goal:** Detect when a function reverts conditionally based on a tainted storage value, enabling a state-dependent denial of service.

### The Pattern

```solidity
function redeem(uint256 shares) external {
    require(totalAssets() > minAssets, "below minimum");
    // If `minAssets` was set by an attacker (tainted storage), this always reverts.
    // Legitimate users cannot withdraw.
}
```

### Detection

At REVERT (0xfd) or REVERT with reason:

1. Read the last comparison opcode before REVERT (saved from opcode trace)
2. Check if either operand was loaded from storage (SLOAD at the same PC or nearby PC)
3. Check the storage key: was it written by this execution? (intra-execution) Or by a prior execution? (cross-execution, needs Phase 3/4 of 013)
4. If the comparison also uses tainted calldata → **attacker-controlled revert condition**

```rust
fn on_step(...) {
    match opcode {
        0x10..=0x14 => {
            // Save last comparison operands
            LAST_CMP_A = interp.stack.peek(1);
            LAST_CMP_B = interp.stack.peek(0);
            LAST_CMP_PC = interp.bytecode.pc();
        }
        0xfd | 0xfe => {  // REVERT / INVALID
            if let Some(pc) = LAST_CMP_PC {
                let revert_storage_slot = storage_slot_of_operand(LAST_CMP_A, LAST_CMP_B);
                if let Some(slot) = revert_storage_slot {
                    let tainted = host.tainted_storage.get(&(address, slot));
                    if tainted {
                        // REVERT was gated by a storage value that was
                        // written by attacker-controlled data
                        DOS_VIA_STATE_DEPENDENT_REVERT = true;
                    }
                }
            }
        }
    }
}
```

### State-Dependent vs. Standard Revert

- Standard revert: requires that fails regardless of state (e.g., input validation)
- State-dependent revert: the condition reads from storage that has changed since deployment
- Taint-dependent revert: the storage value was WRITTEN by attacker-controlled data

The taint engine catches only the last category. A state-dependent revert without taint is an invariant check, not an exploit.

### Files:
- `src/evm/middlewares/dos_detector.rs` — new middleware

---

## Summary: What Each Phase Needs

| Phase | Needs from 013 | Needs from other Phase | New infrastructure |
|---|---|---|---|
| 0: Return-value taint | Phase 0 (DELEGATECALL fix) | None | Oracle address detection, shadow stack marking on_return |
| 1: Oracle detection | Phase 0 | Phase 0 | Comparison-opcode oracle check |
| 2: Flash loan | Phase 0 | Phase 1 | Multi-CALL sequence tracking |
| 3: Oracle staleness | Phase 0 | None | Opcode window tracking (50 ops after CALL) |
| 4: Empty state guard | Phase 0 | None | Opcode sequence analysis within called function |
| 5: DoS | Phase 3 (persistent taint) | None | Pre-revert opcode trace + storage key check |

Phases 0-1 are the core infrastructure. Phases 2-5 are independent detectors that plug into the taint engine's existing opcode dispatch.

## Total New Middleware

| Phase | Middleware | Lines (est.) | New static flags |
|---|---|---|---|
| 0 | Extends `cmp_linearity.rs` on_return | +20 | — |
| 1 | `oracle_tracker.rs` | ~150 | `ORACLE_GATED_TRANSFER` |
| 2 | `flashloan_oracle.rs` | ~100 | `FLASH_LOAN_MANIPULATION` |
| 3 | `oracle_staleness.rs` | ~120 | `STALE_ORACLE` |
| 4 | `empty_state_guard.rs` | ~80 | `EMPTY_STATE_GUARD_MISSING` |
| 5 | `dos_detector.rs` | ~100 | `DOS_VIA_STATE_DEPENDENT_REVERT` |

~570 lines total for the 5 TAINT models that 013 cannot cover.
