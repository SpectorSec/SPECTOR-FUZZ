# Plan — Feature 014 — TAINT Model Oracles (Non-Injection Primitives)

**Status:** DRAFT
**Checkpoints resolved:** 014.CP.0 ✓, 014.CP.1 ✓, 014.CP.2 ✓, 014.CP.3 ✓, 014.CP.4 ✓, 014.CP.5 ✓, 014.CP.6 ✓
**Last updated:** 2026-07-02
**Depends on:** Feature 013 Phase 0 (DELEGATECALL bugs fixed)

**Decisions locked:**
- **Phase 0 (return-value taint) extends cmp_linearity.rs on_return** — no new middleware for the taint marking itself. The return data and callee identity are available in `on_return`'s existing `(_interp, _host, _ret)` signature.
- **Phase 1-5 are separate middlewares** — each is a self-contained opcode-sequence detector. They read the shadow stack state left by cmp_linearity but do NOT modify it. Registered in `evm_fuzzer.rs` when their config flags are enabled.
- **Oracle selectors reuse FreshnessOracle constants** — `LATEST_ROUND_DATA_SEL`, `LATEST_ANSWER_SEL`, `GET_ROUND_DATA_SEL` already defined in `freshness.rs:45-53`. Phase 0 loads them into `FuzzHost.oracle_selectors` at init.
- **No Z3 dependency** — all phases are inline opcode-sequence analysis. Concolic dispatch (009) is separate.
- **39% oracle reduction is contingent on 013 + 014 both shipping** — 3 subsumed (injection detection), 4 absorbed (opcode middleware), 11 survive. 015 contributes nothing to this count.

---

## Architecture Decision

No new Cargo feature, no new trait. Phase 0 extends `CmpLinearityTaint::on_return`. Phases 1-5 are new middlewares that read the shadow stack and static flags set by cmp_linearity.

### Phase 0 — Return-Value Taint (cmp_linearity.rs on_return)

**Mechanism:** In `on_return` (`cmp_linearity.rs:509-519`), after `self.pop_ctx()`, check if the returning CALL was to a known oracle function. If yes, mark the return data bytes in `self.mem` as tainted.

```rust
unsafe fn on_return(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState, ret: &Bytes) {
    if host.call_depth > MAX_CALL_DEPTH { return; }
    self.pop_ctx();

    // Phase 0: oracle return-value taint
    if host.call_depth > 0 && !ret.is_empty() {
        let callee = interp.input.target_address;
        let selector = &interp.input.input[..4];
        if host.oracle_selectors.get(&callee).map_or(false, |sels| sels.contains(selector)) {
            // Mark return data as tainted in memory
            // The shadow stack's RETURN ops will read from mem taint
            let ret_offset = 0;  // actual offset tracked from the CALL site
            let ret_len = ret.len().min(MEMORY_LIMIT_BYTES);
            if let Some(end) = safe_mem_end(ret_offset, ret_len) {
                ensure!(self.mem, end);
                self.mem[ret_offset..ret_offset + ret_len].fill(true);
            }
        }
    }
}
```

**Oracle address detection at init:** Populate `FuzzHost.oracle_selectors` during corpus initialization by scanning ABIMap for known oracle selectors (`is_oracle_interface()` from `freshness.rs:55`).

**New FuzzHost field:**
```rust
pub oracle_selectors: HashMap<EVMAddress, Vec<[u8; 4]>>,
```

Gated on `config.return_value_taint`.

### Phase 1 — Oracle Detection (oracle_tracker.rs)

New middleware that runs during `on_step`, reading the shadow stack state at comparison opcodes. Checks if either operand carries taint from an oracle return value.

**Mechanism:** At comparison opcodes (0x10-0x14), inspect both operands' TB values. If one is oracle-tainted AND the comparison gates a subsequent value-moving CALL, set `ORACLE_GATED_TRANSFER`.

```rust
0x10..=0x14 => {
    let a = pop!();
    let b = pop!();
    let oracle_involved = (a.t && was_from_oracle_return(a)) || (b.t && was_from_oracle_return(b));
    // was_from_oracle_return: TB carries a new flag `oracle_source: bool`
    // set by Phase 0's return-value marking
    
    if oracle_involved && comparison_passed {
        subsequent_call_hook_to_check.value_movement = true;
        ORACLE_GATED_TRANSFER_DETECTED = true;
    }
}
```

Requires extending TB with `oracle_source: bool` field (in addition to `t` and `nl`). This is the only change to `cmp_linearity.rs`'s core types.

Gated on `config.oracle_detection`.

### Phase 2 — Flash Loan Detection (flashloan_oracle.rs)

New middleware tracking multi-CALL sequences within a single execution. Detects: oracle read → price change → second oracle read → value movement → repayment.

**Mechanism:** Track `oracle_reads: Vec<(CALL_index, return_value)>` and `value_movements: Vec<(CALL_index, amount)>` across the execution. After execution, check:
- ≥2 oracle reads at different CALL indices
- Value delta above threshold
- Borrow/mint between the two reads
- Repayment after the value movement

Uses 013 Phase 2's sink address detection for identifying financial contracts.

Gated on `config.flashloan_detection`.

### Phase 3 — Oracle Staleness Detection (oracle_staleness.rs)

New middleware checking whether a `latestRoundData()` call is followed within ~50 opcodes by a `TIMESTAMP` comparison against `updatedAt`.

**Mechanism:** Track state machine: `ORACLE_READ_PC` set at latestRoundData CALL → `TIMESTAMP_AFTER_ORACLE` set if TIMESTAMP (0x42) pushed within 50 PCs → `STALE_CHECK_OBSERVED` set if comparison uses both. Post-execution: if oracle was read but no staleness check observed → `STALE_ORACLE_DETECTED`.

Reuses `FreshnessOracle::is_oracle_interface()` for identifying oracle calls. Complements the existing post-hoc FreshnessOracle with inline detection.

Gated on `config.oracle_staleness`.

### Phase 4 — Empty State Guard Detection (empty_state_guard.rs)

New middleware checking whether deposit/mint functions check `totalSupply > 0` before transferring value (ERC-4626 first-deposit inflation attack).

**Mechanism:** At CALL to deposit/mint/redeem functions, monitor the first ~30 opcodes:
1. SLOAD of totalSupply slot (use `slot_detector.rs` or heuristic: first SLOAD in function)
2. Comparison of totalSupply against 0
3. JUMPI on zero → guard present
4. If CALL transferFrom/transfer occurs without JUMPI → `EMPTY_STATE_GUARD_MISSING`

Gated on `config.empty_state_guard`.

### Phase 5 — DoS Detection (dos_detector.rs)

New middleware checking whether a REVERT is gated by a storage value written by attacker-controlled data.

**Mechanism:** Track last comparison operands before REVERT. At REVERT (0xfd):
1. Read the last comparison opcode's operands
2. Check if either operand came from SLOAD
3. Check the storage key against `host.tainted_storage` (from 013 Phase 3)
4. If tainted → `DOS_VIA_STATE_DEPENDENT_REVERT`

Requires 013 Phase 3 (persistent taint) as prerequisite.

Gated on `config.dos_detection`.

---

## New Types

| Type | Location | Purpose |
|------|----------|---------|
| `TB.oracle_source: bool` | `cmp_linearity.rs` | Phase 0: marks taint that originated from oracle return |
| `FuzzHost.oracle_selectors` | `host.rs` field | Phase 0: map of known oracle contracts → their selectors |
| `ORACLE_GATED_TRANSFER` | `oracle_tracker.rs` static | Phase 1: oracle-gated value movement flag |
| `FLASH_LOAN_MANIPULATION` | `flashloan_oracle.rs` static | Phase 2: multi-CALL oracle manipulation flag |
| `STALE_ORACLE` | `oracle_staleness.rs` static | Phase 3: missing staleness check flag |
| `EMPTY_STATE_GUARD_MISSING` | `empty_state_guard.rs` static | Phase 4: first-deposit guard missing flag |
| `DOS_VIA_STATE_DEPENDENT_REVERT` | `dos_detector.rs` static | Phase 5: tainted-storage DoS flag |

---

## Registration

- **cmp_linearity.rs** — Phase 0: extend `on_return` with oracle return-value marking. Add `oracle_source` field to TB.
- **host.rs** — Phase 0: add `oracle_selectors` field.
- **corpus_initializer.rs** — Phase 0: populate `oracle_selectors` from ABIMap at init.
- **New middlewares:** `oracle_tracker.rs`, `flashloan_oracle.rs`, `oracle_staleness.rs`, `empty_state_guard.rs`, `dos_detector.rs` — registered in `evm_fuzzer.rs` when their config flags are enabled.
- **config.rs** — new fields: `return_value_taint`, `oracle_detection`, `flashloan_detection`, `oracle_staleness`, `empty_state_guard`, `dos_detection`.

---

## CLI

- **Flags:** `--return-value-taint`, `--oracle-detection`, `--flashloan-detection`, `--oracle-staleness`, `--empty-state-guard`, `--dos-detection`.
- **Config fields:** One boolean per phase in `config.rs`.
- **Dependencies:** Phase 1 depends on Phase 0. Phase 2 depends on Phase 0+1. Phase 3 depends on Phase 0. Phase 5 depends on 013 Phase 3. Phase 4 is independent.

---

## Interaction with Existing Features

| Feature | Interaction |
|---------|------------|
| 013 Taint | **Prerequisite** (Phase 0 bugfix). Phase 5 reads `host.tainted_storage`. |
| 009 Concolic | None — all phases are inline opcode analysis, no Z3. |
| FreshnessOracle | **Absorbed into Phase 3** — post-hoc stale check (FreshnessOracle) becomes redundant when inline check (Phase 3) ships. Phase 3 reuses its selector constants. |

---

## Performance

- **When disabled:** zero code path — all phase flags checked before entering new code. Middlewares not registered.
- **When enabled (Phase 0):** +1 HashMap lookup per CALL return. Negligible.
- **When enabled (Phase 1):** +few TB checks per comparison opcode. Existing shadow stack ops dominate.
- **When enabled (Phase 3):** PC window tracking (~50 opcode window). Constant overhead per oracle CALL.
- **Memory:** `oracle_selectors` map sized by the ABI surface. ~1KB for typical fork.

---

## Test Plan

- **Phase 0:** Unit: CALL to mock Chainlink oracle → return data bytes marked tainted in shadow memory. Not marked for non-oracle CALLs.
- **Phase 1:** Unit: oracle-gated comparison → `ORACLE_GATED_TRANSFER` fires. Non-oracle comparison → no FP.
- **Phase 2:** Integration: aave flash loan attack → `FLASH_LOAN_MANIPULATION` detects the multi-CALL sequence.
- **Phase 3:** Unit: latestRoundData without timestamp check → `STALE_ORACLE` fires. With check → no flag.
- **Phase 4:** Unit: deposit without totalSupply check → `EMPTY_STATE_GUARD_MISSING`. With check → no flag.
- **Phase 5:** Integration: state-dependent revert triggered by tainted storage → `DOS` fires.
- **Regression:** All oracles disabled → bug set identical to pre-014 binary.

---

## Build Staging (task ordering)

**Phase 1 (core infrastructure):**
1. Phase 0: Return-value taint on on_return + oracle_selectors + TB.oracle_source field.
2. Phase 1: Oracle detection middleware (opcode-sequence checks at comparison sites).

**Phase 2 (independent detectors):**
3. Phase 3: Oracle staleness (opcode window tracking).
4. Phase 4: Empty state guard (opcode sequence within called function).
5. Phase 2: Flash loan (multi-CALL sequence tracking).

**Phase 3 (dependent on 013 Phase 3):**
6. Phase 5: DoS detection (pre-revert comparison + tainted storage check).
