# Tasks — Feature 014 — TAINT Model Oracles (Non-Injection Primitives)

**Status:** DRAFT — awaiting approval
**Last updated:** 2026-07-02
**Depends on:** Feature 013 Phase 0 (DELEGATECALL bugs fixed) — prerequisite for correct oracle return-value taint through proxy calls.

Build order: Phase 0 (return-value taint) is the foundation for Phase 1-3. Phases 4-5 are independent. Each task is independently testable behind its CLI flag; the pre-014 binary (flag off) is the regression floor at every step.

---

## PHASE 1 — core infrastructure (return-value taint + oracle detection)

## Task 1 — Return-value taint marking (Phase 0)
**Files:** `src/evm/middlewares/cmp_linearity.rs:509-519`, `src/evm/host.rs`
**What:**

**host.rs:** Add `oracle_selectors` field to FuzzHost:
```rust
pub oracle_selectors: HashMap<EVMAddress, Vec<[u8; 4]>>,
```

**corpus_initializer.rs:** At init, scan ABIMap for known oracle selectors (`FreshnessOracle::is_oracle_interface()`) and populate `host.oracle_selectors`.

**cmp_linearity.rs:** Extend `on_return` to mark oracle return data as tainted in memory:
```rust
unsafe fn on_return(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState, ret: &Bytes) {
    if host.call_depth > MAX_CALL_DEPTH { return; }
    self.pop_ctx();

    if host.call_depth > 0 && ret.len() >= 4 {
        let callee = interp.input.target_address;
        if ret.len() >= 4 {
            if let Some(selectors) = host.oracle_selectors.get(&callee) {
                let selector = &interp.input.input[..4];
                if selectors.contains(selector) {
                    let end = ret.len().min(MEMORY_LIMIT_BYTES);
                    ensure!(self.mem, end);
                    self.mem[..end].fill(true);
                }
            }
        }
    }
}
```

Also add `oracle_source: bool` field to `TB` struct (in addition to `t` and `nl`). Set when return-value taint is marked. Reset to false on MLOAD/SLOAD (conservative — oracle taint is an address-domain marker, not value).

**Config flag:** `--return-value-taint` → `config.return_value_taint: bool`.

**Done when:** Unit: CALL to mock oracle → return data bytes tainted in shadow memory. Non-oracle CALL → clean.
**Blocks:** Task 2, Task 3, Task 4

---

## Task 2 — Oracle detection middleware (Phase 1)
**Files:** `src/evm/middlewares/oracle_tracker.rs` (new)
**What:** New middleware detecting oracle-gated value movement. At comparison opcodes (0x10-0x14), checks if either operand carries oracle return taint (TB.oracle_source flag from Phase 0).

```rust
unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, state: &mut EVMFuzzState) {
    let opcode = interp.bytecode.opcode();
    match opcode {
        0x10..=0x14 => {
            // Read shadow stack operands via cmp_linearity's static TB access
            // (or reimplement a minimal shadow read)
            let a_oracle = self.last_taint_a; // simplified
            let b_oracle = self.last_taint_b;
            if a_oracle || b_oracle {
                ORACLE_CMP_SEEN = true;
                // Track: did a following CALL move value based on oracle data?
            }
        }
        0xf1 | 0xf2 | 0xf4 | 0xfa if ORACLE_CMP_SEEN => {
            // Check if this CALL moves value to a sink
            if is_financial_sink(interp.input.target_address, &host.hash_to_address) {
                ORACLE_GATED_TRANSFER_DETECTED = true;
            }
        }
        _ => {}
    }
}
```

**Static flag:**
```rust
pub static mut ORACLE_GATED_TRANSFER_DETECTED: bool = false;
```

**Registration:** Register in `evm_fuzzer.rs` when `config.oracle_detection`.

**Config flag:** `--oracle-detection` → `config.oracle_detection: bool`. Depends on `return_value_taint` (auto-enable + warn).

**Done when:** Integration: oracle-gated comparison followed by value-moving CALL → flag fires. Non-oracle gate → no FP.
**Blocks:** Task 4

---

## PHASE 2 — independent detectors

## Task 3 — Oracle staleness middleware (Phase 3)
**Files:** `src/evm/middlewares/oracle_staleness.rs` (new)
**What:** New middleware detecting missing `updatedAt` staleness checks after `latestRoundData()`. Tracks a state machine in on_step:

1. `ORACLE_READ_PC` set when `latestRoundData` CALL seen
2. Within next 50 PCs: TIMESTAMP (0x42) pushed → `TIMESTAMP_AFTER_ORACLE`
3. Comparison (0x10-0x14) with updatedAt + TIMESTAMP → `STALE_CHECK_OBSERVED`
4. Post-execution: oracle read but no check → `STALE_ORACLE_DETECTED`

```rust
const STALE_WINDOW: usize = 50;

pub static mut STALE_ORACLE_DETECTED: bool = false;

unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, state: &mut EVMFuzzState) {
    let pc = interp.bytecode.pc();
    match interp.bytecode.opcode() {
        0xf1 if is_latestRoundData_call(&interp.input) => {
            self.oracle_read_pc = Some(pc);
            self.stale_check_observed = false;
        }
        0x42 if self.oracle_read_pc.is_some() && pc <= self.oracle_read_pc.unwrap() + STALE_WINDOW => {
            self.timestamp_after_oracle = true;
        }
        0x10..=0x14 if self.timestamp_after_oracle => {
            // Check if operands include updatedAt (from return data) and TIMESTAMP
            self.stale_check_observed = true;
        }
        _ => {}
    }
}

unsafe fn on_return(&mut self, _interp: &mut Interpreter, _host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState, _ret: &Bytes) {
    if self.oracle_read_pc.is_some() && !self.stale_check_observed {
        STALE_ORACLE_DETECTED = true;
    }
    // Reset per-execution state
    self.oracle_read_pc = None;
    self.timestamp_after_oracle = false;
    self.stale_check_observed = false;
}
```

Reuses `FreshnessOracle::is_oracle_interface()` for detecting oracle calls.

**Config flag:** `--oracle-staleness` → `config.oracle_staleness: bool`.

**Done when:** Unit: latestRoundData without TIMESTAMP comparison → `STALE_ORACLE_DETECTED` fires. With proper check → no flag.
**Blocks:** None

---

## Task 4 — Empty state guard middleware (Phase 4)
**Files:** `src/evm/middlewares/empty_state_guard.rs` (new)
**What:** New middleware detecting missing totalSupply guard in deposit/mint functions (ERC-4626 first-deposit inflation).

At CALL to deposit(0x47e7ef24)/mint(0x94bf804d)/withdraw(0x69328dec)/redeem(0xba087652):
- Track SLOADs within the first ~30 opcodes
- Identify totalSupply slot (slot 0 for standard ERC-20, or via `slot_detector.rs`)
- Check for JUMPI after comparison against zero
- If value-moving CALL (transferFrom/transfer) occurs before JUMPI → guard missing

```rust
pub static mut EMPTY_STATE_GUARD_MISSING: bool = false;

// State machine:
// IDLE → DEPOSIT_ENTERED (on deposit selector) → MONITOR_SLOAD
// → TOTAL_SUPPLY_SLOAD (on SLOAD to slot 0 + matching selector range)
// → TOTAL_SUPPLY_CHECKED (on JUMPI after comparison)
// → VALUE_MOVED (on transferFrom/transfer CALL)
// If VALUE_MOVED fires in DEPOSIT_ENTERED state without TOTAL_SUPPLY_CHECKED → MISSING
```

**Config flag:** `--empty-state-guard` → `config.empty_state_guard: bool`.

**Done when:** Unit: deposit without guard → `EMPTY_STATE_GUARD_MISSING`. Deposit with `require(totalSupply > 0)` → no flag.
**Blocks:** None

---

## Task 5 — Flash loan oracle detection middleware (Phase 2)
**Files:** `src/evm/middlewares/flashloan_oracle.rs` (new)
**What:** New middleware detecting multi-CALL oracle manipulation sequences.

Track across the execution:
```rust
struct OracleRead {
    call_index: usize,
    address: EVMAddress,
    selector: [u8; 4],
    return_value: EVMU256,
}
struct ValueMovement {
    call_index: usize,
    sink_address: EVMAddress,
    amount: EVMU256,
}
```

Accumulate `oracle_reads` and `value_movements` during execution. Post-execution (on_return), check:
- ≥2 oracle reads at different call indices
- Value movement between the two reads
- Value delta above threshold (price changed between reads)
- Repayment pattern (borrow → manipulate → exploit → repay)

```rust
pub static mut FLASH_LOAN_MANIPULATION: bool = false;

unsafe fn on_return(&mut self, _interp: &mut Interpreter, _host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState, _ret: &Bytes) {
    if self.oracle_reads.len() >= 2
        && self.value_movements.len() >= 1
        && self.oracle_reads.last().unwrap().call_index > self.oracle_reads[0].call_index
        && self.has_value_delta()
        && self.has_borrow_before_first_read()
    {
        FLASH_LOAN_MANIPULATION = true;
    }
}
```

**Config flag:** `--flashloan-detection` → `config.flashloan_detection: bool`. Depends on `return_value_taint` + `oracle_detection`.

**Done when:** Integration: AAVE flash loan attack → `FLASH_LOAN_MANIPULATION` fires. Non-flashloan sequence → no FP.
**Blocks:** None

---

## Task 6 — DoS detection middleware (Phase 5)
**Files:** `src/evm/middlewares/dos_detector.rs` (new)
**What:** New middleware detecting state-dependent reverts controlled by tainted storage.

**Prerequisite:** 013 Phase 3 (persistent taint on `host.tainted_storage`).

Track last comparison operands:
```rust
struct LastCmp {
    pc: usize,
    left: EVMU256,
    right: EVMU256,
    left_from_storage: bool,
    right_from_storage: bool,
    storage_key: Option<EVMU256>,
}
```

At REVERT (0xfd):
```rust
0xfd | 0xfe => {
    if let Some(cmp) = self.last_cmp.take() {
        if let Some(key) = cmp.storage_key {
            let address = interp.input.target_address;
            if host.tainted_storage.get(&(address, key)).copied().unwrap_or(false) {
                DOS_VIA_STATE_DEPENDENT_REVERT = true;
            }
        }
    }
}
```

**Config flag:** `--dos-detection` → `config.dos_detection: bool`. Depends on `injection_persist` (013 Phase 3).

**Done when:** Integration: state-dependent revert controlled by tainted storage → flag fires. Standard revert → no FP.
**Blocks:** None

---

## Task 7 — Tests: unit, integration, regression
**Files:** `tests/` or `src/evm/middlewares/*_test.rs` (inline tests per middleware)
**What:**

- **7a unit:** Phase 0 — oracle return-value taint marking via on_return.
- **7b unit:** Phase 1 — oracle_gated_transfer detection on synthetic sequence.
- **7c unit:** Phase 3 — staleness window tracking; TIMESTAMP within 50 PCs vs outside.
- **7d unit:** Phase 4 — deposit guard detection; with and without totalSupply check.
- **7e integration:** AAVE flash loan fork — Phase 2 detects borrow→manipulate→repay.
- **7f integration:** Chainlink oracle fork — Phase 3 detects stale read; Phase 1 detects oracle-gated transfer.
- **7g regression:** All `--*-detection` flags off → bug set byte-equivalent to pre-014 binary.

**Done when:** All tests pass. Regression shows no diff.
**Blocks:** None
