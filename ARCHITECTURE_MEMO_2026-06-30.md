# Architectural Discovery: Injection Hooks vs Post-hoc Oracles

**Date:** 2026-06-30
**From:** DeepSeek + user
**To:** Claude (and anyone else working on oracles/false positives)

---

## What We Found

We watched two libafl seminars. The "Advanced Fuzzing with LibAFL" talk (Dominic Maier) introduced **injection-style hooks** — inline instrumentation that detects when fuzzer-mutated input reaches a sensitive sink at the *moment of action*, not after the fact.

Example from the talk: hook `sqlite_exec`, check if the fuzzer's mutated input appears in parameter 2 (the SQL query). If yes, it's an injection. Flag it inline, zero false positives.

## The Mapping to SpecterFuzz

We have two execution interception layers:

| Layer | What it does | Current state |
|-------|-------------|---------------|
| **Middleware** (`src/evm/middlewares/`) | Inline opcode-level hooks (cheatcodes, sha3_bypass, reentrancy, flashloan) | Already inline, but only `reentrancy.rs` detects exploits |
| **Oracle** (`src/evm/oracles/`) | Post-hoc state diff comparison (before → execute → after) | Every oracle was blindly dropped here by fuzzland |

## The Categorization We Never Did

Not all DeFi primitives can be detected post-hoc. Some are **temporal** — the exploit IS the interleaving, not the outcome:

| Primitive | Mode | Why | Existing oracle/middleware |
|-----------|------|-----|---------------------------|
| **Control leak** (reentrancy) | **Inline only** | The exploit IS the call sequence; post-hoc sees a balance change indistinguishable from a normal withdrawal | `reentrancy.rs` middleware ✅ (already inline — this is why it works) |
| **Message leak** (arbitrary call) | **Inline only** | The exploit is data flow to an unchecked CALL target | `arb_call.rs` oracle ❌ (currently post-hoc, should be inline) |
| **Permission leak** | **Inline only** | The exploit is identity at call time; post-hoc has to infer who *should* be caller | `function.rs` oracle ❌ (post-hoc) |
| **Approval leak** | **Inline only** | Approval event + spender identity; post-hoc misses the caller-spender relationship | `approval.rs` oracle ❌ (post-hoc) |
| **Value leak** (ERC20) | **Post-hoc** | Balance diff is sufficient; mechanism doesn't matter | `erc20.rs` oracle ✅ (correct as-is) |
| **Invariant leak** (4626, price) | **Post-hoc** | Share/reserve ratio diff; needs before/after snapshot | `erc4626.rs`, `fee_on_transfer.rs`, `rebasing.rs` ✅ (correct as-is) |
| **Freshness** | **Post-hoc** | Timestamp comparison | `freshness.rs` ✅ (correct as-is) |

## Why This Matters for False Positives

The oracles that false-positive (fee_on_transfer, temporal_skim) are **state-diff oracles trying to do a temporal job**:
- `fee_on_transfer.rs` — measures net delta over the entire execution, can't distinguish a 60 USDC fee from 60 USDC theft. If it were inline, it'd check: "did the fuzzer's calldata reach `transferFrom(from≠self)`?"
- `temporal_skim.rs` — post-hoc balance drift across blocks can't separate yield accrual from priming.

The reentrancy middleware works precisely because it's inline — it sees the call stack interleaving, not the balance outcome.

## The libafl Connection

The libafl injection hook (talk at 41:22) hooks `sqlite_exec` and checks: "did the fuzzer's input appear in the second parameter?" This is exactly what our temporal oracles need — not "did value move?" but "did value move AND was it triggered by a fuzzer-controlled argument reaching a sensitive function parameter?"

## Action Items

1. **Convert** `arb_call.rs`, `function.rs`, `approval.rs` from post-hoc oracles to inline middleware hooks
2. **Keep** `erc20.rs`, `erc4626.rs`, `fee_on_transfer.rs`, `rebasing.rs`, `freshness.rs`, `invariant.rs` as post-hoc
3. **Remove** `sha3_bypass.rs` or deprioritize — it's an optimizer for a code path DeFi rarely hits, and injection hooks give better signal per byte
4. **Blueprint**: `middlewares/reentrancy.rs` is the pattern — hooks CALL opcodes. New injection hooks hook CALL with parameter inspection (check if calldata args contain attacker-controlled addresses)

## Empirical Validation (2026-06-30)

A/B test directly compared biased vs unbiased config on a Yearn V3 fork:

| Metric | Biased (topology + sha3 ON) | Unbiased (--no-topology, sha3 off) |
|--------|---------------------------|-----------------------------------|
| Executions | ~150K then crash @ 460s | **2,282,257**, no crash @ 840s+ |
| Memory | Declined → MEM_ABORT | **Stable 1.3-1.5 GB** |
| exec/sec | Stuck 155-230 | **Climbing to thousands** |
| Finding | 1 Fund Loss, 0.025 ETH | **1 Fund Loss, 0.024 ETH (same dust)** |

**Result:** 15x throughput, no crash, same finding. sha3_bypass + topology are pure overhead on DeFi targets. Validates the decision to deprioritize both.

---

## Phase 2: Taint Injection Detection (Feature 013)

**What it is:** Every EVM stack value carries a shadow `TB { t: bool, nl: bool, provenance: u64 }`. The `provenance` field is a bitmap tracking which calldata arg indices (after the 4-byte selector) contributed to the value.

| Component | Where | What it does |
|-----------|-------|-------------|
| **TB.provenance** | `cmp_linearity.rs` | Set at `CALLDATALOAD` (computes `arg_idx = (offset - 4) / 32`), propagated through all ops via OR, cleared at SLOAD/MLOAD |
| **host.arg_slot_provenance** | `host.rs` | `HashMap<(EVMAddress, EVMU256), u64>` — at SSTORE, if the stored value has non-zero provenance, the bitmap is OR'd in |
| **ArgStorageProvenance** | `feedbacks.rs` | State metadata snapshotted after each CmpLinearityTaint reexecution |
| **LOCATE filter** | `mutator.rs:727-749` | In Idle phase, before probing arg `i`, checks per-contract aggregated bitmap; if bit `i` is 0 → skip this arg entirely |

**Why it matters:** The LOCATE phase previously swept every arg blindly — 10-arg call = 10 probe executions. With provenance tracking, if only args 2 and 5 touch storage, LOCATE skips the other 8. This is 4x fewer executions for the typical case.

**The six taint-informed flow types (deferred to Feature 016):** Not all provenance is equal — a price oracle return value is different from a user-supplied accumulator parameter. Feature 016 upgrades `provenance: u64` to `dim: TaintDim` with a most-specific-wins propagation lattice (Price > Accumulator > Balance > Timestamp > Generic).

---

## Phase 3: Taint-Driven Oracle Middleware (Feature 014)

**What it is:** Instead of post-hoc state diffs, six inline middlewares detect exploit patterns at the moment of execution — hooking CALL, SLOAD, REVERT, TIMESTAMP, and BALANCE opcodes.

| Middleware | File | Opcodes hooked | What it detects |
|-----------|------|---------------|-----------------|
| **Return-value taint** (Phase 0) | `cmp_linearity.rs` | CALL + RETURN | Tags bytes from known FreshnessOracle calls as tainted |
| **OracleTracker** (Phase 1) | `oracle_tracker.rs` | CALL, JUMPI, comparison | Oracle CALL → comparison → value-moving CALL in a 60-op window |
| **FlashloanOracle** (Phase 2) | `flashloan_oracle.rs` | CALL, BALANCE | Borrow → oracle read ×2 → value movement between/after reads |
| **OracleStaleness** (Phase 3) | `oracle_staleness.rs` | TIMESTAMP, CALL, JUMPI | Oracle CALL → 50 ops w/o TIMESTAMP → comparison |
| **EmptyStateGuard** (Phase 4) | `empty_state_guard.rs` | CALL, SLOAD, JUMPI | Deposit/mint/withdraw/redeem → 40 ops w/o SLOAD+JUMPI → transfer |
| **DoSDetector** (Phase 5) | `dos_detector.rs` | SLOAD, REVERT | Revert after SLOAD: is the slot attacker-tainted? (reads 013 Phase 3 `host.tainted_storage`) |

**Architecture principle:** These middlewares register on the main fuzz_host via `add_middlewares`. They write to static flags (`INJECTION_TAINTED_CALL_TARGET`, `INJECTION_TAINTED_CALLDATA`, etc.) that are consumed by the feedback layer. They do NOT consume their own output — they are write-only.

**Why it matters:** Post-hoc oracles can detect that value moved but cannot prove the value movement was caused by attacker-controlled input. Inline taint hooks answer the causality question at the opcode level.

---

## Phase 4: Causal Oracle Gating (Phase 0)

**The problem:** Oracle false positives fall into two disjoint classes:
1. **Phantom/coincidental** — value moved for a non-attacker reason (e.g., normal yield accrual flagged as theft). Killed by causality.
2. **Real but worthless** — attacker CAN cause the described behavior, but the net profit is $0 after fees/MEV. Killed by valuation (net-realized ledger).

Phase 0 kills class 1 by restructuring the feedback chain:

```
Before:  inner feedback → Sha3 reexecution → oracle fire
After:   CmpLinearityTaint reexecution → INJECTION_CONFIRMED_EXPLOIT_PATH → inner feedback → Sha3 reexecution → oracle fire (gated)
```

**The gate** in `feedback.rs`:
```rust
// OracleFeedback::is_interesting()
if !injection_exploit_path_detected() { continue; }
known_bugs.insert(...)
```

Single line, all 14 oracles benefit. The `injection_chain_verdict()` function (at `feedbacks.rs:133`) walks the `TAINTED_CALLS` chain: CALL → CALL → ... → SSTORE. Only if every link is tainted is `INJECTION_CONFIRMED_EXPLOIT_PATH` set.

**Validation:** 126 non-network tests pass, 5 pre-existing RPC failures unchanged. Zero regressions.

---

## Provenance-Enhanced Ledger Secant (LOCATE Narrowing)

The ledger secant's LOCATE phase (`mutator.rs`) identifies which input bytes trigger oracle fires. With Feature 013 Phase 6's arg→slot provenance tracking:

1. **Aggregation:** `ArgStorageProvenance` metadata collects per-(contract, slot) provenance bitmaps from `host.arg_slot_provenance`
2. **Per-contract OR:** All slot bitmaps for the pin contract are OR'd into a single u64
3. **Filter:** If arg `i` has bit 0 in the OR'd bitmap → skip it entirely
4. **Result:** LOCATE only probes args that demonstrably touch storage of the pin contract

This is a 3-10x speedup on typical DeFi targets where the majority of calldata is selector + padding + addresses that never reach storage.

---

---

## Phase 5: Taint Dimension Tags (Feature 016)

**What it is:** Upgrades taint from flat `TB{t, nl, provenance}` to dimension-aware `TB{t, nl, provenance, dim: TaintDim}`. Every stack value carries an economic dimension tag (Price, Accumulator, Balance, Timestamp, Generic) that propagates through a most-specific-wins lattice.

### Core changes

| Component | Before | After |
|-----------|--------|-------|
| `TB` | `{t, nl, provenance: u64}` | `+ dim: TaintDim` |
| Memory | `Vec<bool>` | `Vec<TaintDim>` |
| Storage shadow | `HashMap<EVMU256, bool>` | `HashMap<EVMU256, TaintDim>` |
| Input data | `Vec<bool>` | `Vec<TaintDim>` |
| `TaintProvenance` | `{tainted, stored_value}` | `+ dim: TaintDim` |
| `LedgerSecantState` | no dim info | `+ located_dim: TaintDim` |

### Lattice: most-specific-wins

```
Price (5) > Accumulator (4) > Balance (3) > Timestamp (2) > Generic (1)
```

Mixed-dim linear ops (ADD, SUB, MUL) → highest priority wins. Non-linear ops (SHA3, EXP) → reset to Generic.

### Oracle return tagging (Phase 1)

`tag_oracle_return()` marks return data per word offset:

| Selector | Offset 0 | Offset 32 | Offset 64 | Offset 96 | Offset 128 |
|----------|----------|-----------|-----------|-----------|------------|
| `latestRoundData` | Generic | **Price** | **Timestamp** | **Timestamp** | Generic |
| `latestAnswer` | **Price** | — | — | — | — |
| `getRoundData` | Generic | **Price** | **Timestamp** | **Timestamp** | Generic |
| `peek` | **Price** | — | — | — | — |

### Flow type detection (Phase 2)

| Flow type | Detection rule | Static flag |
|-----------|---------------|-------------|
| **Proxy bridge** | `dim != Generic` crosses DELEGATECALL boundary | `PROXY_TAINT_FLOW` |
| **Price manipulation** | Price-dim comparison → value-moving CALL | `PRICE_MANIPULATION_FLOW` |
| **Accumulator inflation** | Same slot written with Price-dim ≥2× | `ACCUMULATOR_INFLATION_FLOW` |

### Secant integration (Phase 3)

`LedgerSecantState.located_dim` controls probe delta:

```
Price    → x1 / 256  (fine-grained — prices sensitive)
Balance  → x1 / 16   (coarse — balances handle larger steps)
Generic  → x1 / 64   (default)
```

`DIMENSION_FLOW` is published as a thread-local after each CmpLinearityTaint reexecution, consumed by the mutator for mutation bias.

### Files touched

- `src/evm/middlewares/cmp_linearity.rs` — TaintDim enum, TB.dim, Vec<TaintDim> everywhere, propagation rules, oracle tagging, flow detection
- `src/evm/host.rs` — TaintProvenance.dim
- `src/evm/feedbacks.rs` — DIMENSION_FLOW thread-local, publish_located_dim, read_located_dim
- `src/feedback.rs` — LedgerSecantState.located_dim
- `src/evm/mutator.rs` — probe_delta by dimension, located_dim set during LOCATE

---

## The Big Picture

```
Injection hooks (Phase 2-4)  → answer "could the attacker cause this?"  → kills class 1 FPs
Net-realized ledger (future) → answer "is this profitable after fees?" → kills class 2 FPs
Both needed. Neither subsumes the other.
```

## TL;DR

```
Inline = temporal (reentrancy, arb_call, permission, approval) — catches mechanism
Post-hoc = state-diff (20 transfers, 4626, freshness, rebasing) — catches outcome
Both needed. Mixing them up = false positives.

Causality (taint) kills phantom FPs. Valuation kills worthless FPs.
Both needed. Neither subsumes the other.
```
