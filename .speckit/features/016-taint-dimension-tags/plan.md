# Plan — Feature 016 — Taint Dimension Tags

**Status:** DRAFT
**Depends on:** 013 (host.tainted_storage), 014 (oracle return marking), 015 (LedgerSecantState)
**Last updated:** 2026-07-02
**Checkpoints pending:** 016.CP.0-6

---

## Architecture Decision

No new Cargo feature. Phase 0 upgrades existing types in `cmp_linearity.rs`. Phases 1-3 extend existing middlewares and the mutator.

### Decision 1: Memory representation

`Vec<bool>` → `Vec<TaintDim>` with `#[repr(u8)]`. Zero size overhead. No change to grow/resize logic.

### Decision 2: Dim combination in linear ops

Most-specific wins: `Price > Accumulator > Balance > Timestamp > Generic`. If one operand has a higher-priority dim, the result inherits it. This over-approximates (safe for mutation bias).

### Decision 3: Oracle return mapping

Phase 1 modifies `cmp_linearity.rs` `on_return`. For each oracle selector known in `host.oracle_selectors`, the return data is tagged per offset, not uniformly. Phase 0's current code marks all return bytes as `true` — this becomes marking specific word offsets with `Price` or `Timestamp`.

### Decision 4: Flow type → scheduler wiring

Phase 2 sets `DIMENSION_FLOW: TaintDim` as a thread-local. Phase 3 reads it in `mutator.rs` `mutate()` for bias and in `LedgerSecantState` for probe delta. The `current_typed_bug` entries carry descriptive strings for the oracle system.

---

## New Types

| Type | Location | Size | Purpose |
|------|----------|------|---------|
| `TaintDim` (enum) | `cmp_linearity.rs` | 1 byte | Tags the economic dimension of a tainted value |
| `TB.dim: TaintDim` | `cmp_linearity.rs` | +1 byte | Per-stack-slot dimension tag |
| `Ctx.mem: Vec<TaintDim>` | `cmp_linearity.rs` | same as before | Memory shadow with dim tags |
| `Ctx.storage: HashMap<EVMU256, TaintDim>` | `cmp_linearity.rs` | +1 byte per entry | Storage shadow with dim tags |
| `Ctx.input_data: Vec<TaintDim>` | `cmp_linearity.rs` | same as before | Calldata shadow with dim tags |
| `TaintProvenance.dim: TaintDim` | `host.rs` | +1 byte | Persistent dim for value-confirmed provenance |
| `LedgerSecantState.located_dim: TaintDim` | `feedback.rs` | +1 byte | Dimension of the secant's located lever |

## Modified Files

| File | Phase | Change |
|------|-------|--------|
| `cmp_linearity.rs` | 0 | TB, mem, storage, input_data → TaintDim. Propagation rules. |
| `cmp_linearity.rs` | 1 | on_return tags oracle return data per offset. |
| `cmp_linearity.rs` | 2 | on_step detects flow types from dim + call patterns. |
| `host.rs` | 0 | TaintProvenance.dim field. |
| `host.rs` | 0 | oracle_selectors: add offset→dim mapping (or just use simple Price-for-all; offset tagging is Phase 1) |
| `oracle_tracker.rs` | 2 | Was opcode-proximity. Now uses TB.dim for precise detection. |
| `feedbacks.rs` | 3 | DIMENSION_FLOW static flag. |
| `feedback.rs` | 3 | LedgerSecantState.located_dim field. |
| `mutator.rs` | 3 | apply_ledger_secant reads located_dim for probe delta. mutate() biases on DIMENSION_FLOW. |

## New Static Flags

| Flag | Location | Set by | Read by |
|------|----------|--------|---------|
| `DIMENSION_FLOW: TaintDim` | `feedbacks.rs` | Phase 2 flow type detectors | Phase 3 mutator |
| `PROXY_TAINT_FLOW: bool` | `cmp_linearity.rs` | Phase 2 on DELEGATECALL boundary | `current_typed_bug` |
| `PRICE_MANIPULATION_FLOW: bool` | `oracle_tracker.rs` | Phase 2 on Price-cmp→value-move | `current_typed_bug` |
| `ACCUMULATOR_INFLATION_FLOW: bool` | `cmp_linearity.rs` | Phase 2 on repeated Price-dim SLOAD | `current_typed_bug` |

## Performance

- **When disabled (all flags off):** No change — dim tags are set but never read by the mutator. Runtime cost = +1 byte copy per TB push/pop (existing cache line).
- **Phase 0 enabled:** +1 byte per memory/storage/stack element. ~5% memory increase in the shadow stack (TB grows from 2 bytes to 3).
- **Phase 3 enabled:** +1 switch-on-dim per `apply_ledger_secant` invocation (once per ~10 executions). Negligible.

## CLI

No new CLI flags. Dimension tagging is always-on (the cost is a single byte per TB). The Phase 3 flow-type wiring is gated by `--oracle-detection`, `--dos-detection`, etc. from 014.

## Build Staging

### Phase 0 — Core dimension tag upgrade (3 tasks)
1. Define `TaintDim` enum. Add `dim: TaintDim` to TB. Upgrade `mem`, `storage`, `input_data`. Update propagation rules.
2. Upgrade `TaintProvenance`. Add `dim` field. Update SLOAD/SSTORE.
3. Test: all existing taint ops preserve behavior with dim defaulting to `Generic`.

### Phase 1 — Oracle return dimension tagging (1 task)
4. Extend `on_return` to tag oracle return data per word offset with Price/Timestamp.

### Phase 2 — Flow type detection (2 tasks)
5. Add DELEGATECALL proxy bridge detection (when dim != Generic crosses proxy boundary).
6. Add Price-dim comparison → gated CALL detection (upgrade oracle_tracker from proximity to dim-precise).
7. Add accumulator inflation detection (repeated Price-dim SLOAD to same slot across executions).

### Phase 3 — Scheduler + mutator wiring (2 tasks)
8. Add `DIMENSION_FLOW` static flag. Wire into mutator `mutate()` for bias.
9. Add `LedgerSecantState.located_dim`. Wire into `apply_ledger_secant` for probe delta.

## Test Plan

- **Regression:** All Phase 0-3 changes must pass existing test suite (126 non-network tests).
- **Phase 0 unit:** Each opcode's dim propagation tested in isolation.
- **Phase 1 unit:** Oracle return marked with correct dim per offset.
- **Phase 2 integration:** Three-flow-type detection against synthetic contracts.
- **Phase 3 integration:** Secant chooses µ-steps for Price dim vs %-steps for Balance dim.
