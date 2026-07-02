# Specify — Feature 016 — Taint Dimension Tags

**Status:** DRAFT
**Depends on:** 013 (persistent taint), 014 (oracle return marking), 015 (ledger secant pipeline)
**Build staging:** 4 phases
**Investigation checkpoints:** 016.CP.0–6

---

## Problem

The taint engine (013+014) tracks **whether** a value is tainted (`TB.t: bool`) but not **what kind** of taint. This creates a blind spot at every feedback boundary:

```
TB.t = true  →  mutator: "something is tainted, but is it a price, balance, or timestamp?"
             →  secant:  "I can't choose a step size — prices need µ-steps, balances need %-steps"
             →  scheduler: "I can't tell if this path manipulates prices or just passes data"
```

The three flow types identified in the architecture (proxy bridge, price/oracle link, accumulator inflation) all collapse to the same `true` at the feedback boundary. The system has no way to:

1. Prioritize price-manipulation paths over balance-read paths during mutation
2. Choose dimension-appropriate step sizes in the secant solver (015)
3. Distinguish the three flow types for campaign planning and scheduler bias

---

## Solution

Upgrade taint from `{t: bool, nl: bool}` to `{t: bool, nl: bool, dim: TaintDim}` where `TaintDim` is a 1-byte enum tagging the **economic dimension** of the tainted value.

### Propagation Rules

| Op category | Dim propagation |
|-------------|-----------------|
| Linear (ADD, SUB, MUL, etc.) | OR of all input dims; if mixed, most-specific wins |
| Non-linear (SHA3, EXP, etc.) | Reset to `Generic` |
| MLOAD | Dim read from memory vector |
| SLOAD | Dim read from storage (upgraded `TaintProvenance`) |
| CALL return data (marked by 014 Phase 0) | Tagged per selector (Price / Timestamp / Generic) |
| DELEGATECALL | Dim preserved (proxy bridge detection) |
| PUSH (constant) | `Generic` (no taint, dim irrelevant) |

### Memory Upgrade

`mem: Vec<bool>` → `Vec<TaintDim>`. No size increase — both fit in 1 byte per element with `#[repr(u8)]`.

### Storage Upgrade

`TaintProvenance { tainted, stored_value }` → `TaintProvenance { tainted, stored_value, dim }`. The `dim` field tracks what kind of taint was last written to the slot. Propagated through SLOAD → `TB.dim`.

### Oracle Return Tagging

`latestRoundData()` return layout (32-byte words):
- word[0] (roundId): `Generic`
- word[1] (answer): `Price`  
- word[2] (startedAt): `Timestamp`
- word[3] (updatedAt): `Timestamp`
- word[4] (answeredInRound): `Generic`

`latestAnswer()` return:
- word[0]: `Price`

### Flow Type Detection

| Flow type | Detection rule | Signal |
|-----------|---------------|--------|
| Proxy bridge | `TB.dim == Price\|Balance` AND value crosses DELEGATECALL boundary | `PROXY_TAINT_FLOW` |
| Price/oracle link | `TB.dim == Price` AND comparison gates value-moving CALL | `PRICE_MANIPULATION_FLOW` |
| Accumulator inflation | Same storage slot written ≥2× with `Price`-tagged taint across executions | `ACCUMULATOR_INFLATION_FLOW` |

### Secant Solver Integration (015)

The `LedgerSecantState.locate_cursor` sweep currently probes every arg blindly. With dim tags:

- `dim == Price`: probe delta = `x1 / 256` (fine-grained — prices are sensitive)
- `dim == Balance`: probe delta = `x1 / 16` (coarse — balances handle larger steps)
- `dim == Generic`: probe delta = `x1 / 64` (default)
- After locate, record `located_dim: TaintDim` so the mutator knows which economic dimension it found

---

## Investigation Checkpoints

### 016.CP.0 — Can `Vec<bool>` be upgraded to `Vec<TaintDim>` without breaking existing ops?

Look at `cmp_linearity.rs`:
- `self.mem` grows via `ensure!` macro and `resize()` — both accept any `Copy` type
- `self.storage` grows via `HashMap::insert` — bool → enum is a type change only
- `self.input_data` tracked calldata taint — bool → enum
- Indexing: `self.mem[..end] = vec![true; end]` needs `vec![TaintDim::Generic; end]` — must audit all fill/assignment sites

Verdict: Upgrade is safe. No existing code reads the numeric value of `bool`. All consumers use `.t` for boolean checks.

### 016.CP.1 — How should linear ops combine mixed dimensions?

If `ADD(a=Price, b=Balance)` → what dim does the result carry?

Options:
- A (most-specific wins): `Price > Accumulator > Balance > Timestamp > Generic`. Result = most-specific.
- B (set to Generic): Any mixed-dim op → Generic. Conservative but loses info.
- C (bitwise OR): If multiple dims present, Generic. Only single-dim ops preserve dim.

Recommendation: **Option A** — most-specific wins. Prices are the most impactful dimension, so if either operand is Price, the result is Price. This is an over-approximation (may mark some non-price values as Price) but safe for mutation bias (over-bias, never under-bias).

### 016.CP.2 — What oracle selectors map to Price vs Timestamp vs Generic?

Sources:
- `freshness.rs` defines `LATEST_ROUND_DATA_SEL`, `LATEST_ANSWER_SEL`, `GET_ROUND_DATA_SEL`
- Chainlink interface: `latestRoundData()` returns 5 words; `latestAnswer()` returns 1 word; `getRoundData(uint80)` returns 5 words
- Uniswap V3 TWAP: `observe()` returns tick accumulators → Price (or Generic)
- MakerDAO spotter: `peek()` returns (price, bool) → Price

Mapping:
| Selector | Dim per return offset |
|----------|----------------------|
| `latestRoundData` | off 0: Generic, 32: Price, 64: Timestamp, 96: Timestamp, 128: Generic |
| `latestAnswer` | off 0: Price (entire 32 bytes) |
| `getRoundData` | Same layout as `latestRoundData` |
| `observe` | off 0: Generic (tick accumulator — needs geometric mean → Price via mutator) |
| `peek` | off 0: Price |

### 016.CP.3 — How does the secant solver (015) consume dimension info?

Current `LedgerSecantState`:
```rust
pub arg_idx: usize,   // the chosen knob arg
pub x1: u128,         // amplify base point
pub prev_slope: Option<i128>,
```

With dim tags, add:
```rust
pub located_dim: TaintDim,  // dimension of the located lever
```

The `Locate` phase, after finding the arg with max |Δobj/Δarg|, records `located_dim` from `TB.dim` at the locate probe. The `Amplify` phase reads `located_dim` to choose probe delta:
```rust
let probe_delta = match located_dim {
    TaintDim::Price => x1 / 256,
    TaintDim::Balance => x1 / 16,
    TaintDim::Timestamp => x1 / 64,
    _ => x1 / 64,
};
```

### 016.CP.4 — How does the mutator bias on dimension-tagged variables?

Current mutator selects which arg to mutate randomly (or via secant). With dim tags:

- If `INJECTION_CONFIRMED_EXPLOIT_PATH && flow_type == PriceManipulation` → bias mutation energy toward Price-dim args in the exploit path
- If `PROXY_TAINT_FLOW` detected → bump the proxy args' mutation probability by 2×
- If `ACCUMULATOR_INFLATION_FLOW` detected → increase the accumulator step variable's mutation range

Implementation: New static flags in `cmp_linearity.rs` or per-middleware, read in `mutator.rs` `mutate()` dispatch.

### 016.CP.5 — Do the three flow types need separate static flags or a unified signal?

Options:
- A (separate): `PROXY_TAINT_FLOW: bool`, `PRICE_MANIPULATION_FLOW: bool`, `ACCUMULATOR_INFLATION_FLOW: bool` — explicit per-type signals
- B (unified): Single `DIMENSION_FLOW: TaintDim` with the active flow type — simpler but loses proxy-vs-price distinction
- C (hybrid): `DIMENSION_FLOW: TaintDim` for the scheduler + `current_typed_bug` entries for oracle consumption

Recommendation: **Option C**. The scheduler needs only the dimension to bias mutation energy. The oracle system (`TypedBugOracle`) needs descriptive strings. Feed both.

### 016.CP.6 — Can dimension tags be backfilled through existing persistent taint?

`host.tainted_storage` currently stores `TaintProvenance { tainted: bool, stored_value: EVMU256 }`. If we add `dim: TaintDim`, existing slots with no dim info get `dim: Generic`. On the next SLOAD, the dim is populated from the storage provenance. This is a soft migration — no re-encoding needed for existing `tainted_storage` entries.

---

## Build Staging

- **Phase 0 (core):** Upgrade TB, memory, storage, input_data to `TaintDim`. Propagate dim through all ops. Refactor all `Vec<bool>` → `Vec<TaintDim>` sites.
- **Phase 1 (oracle tagging):** Mark oracle return data with Price/Timestamp per selector + offset in `on_return`.
- **Phase 2 (flow type detection):** Detect the three flow types using dim tags. New static flags.
- **Phase 3 (scheduler + mutator wiring):** Read dim tags in `mutator.rs` for bias. Feed `located_dim` to `LedgerSecantState`. Wire flow type flags into campaign planning.

---

## Test Plan

- **Phase 0 unit:** ADD(Price, Generic) → Price. ADD(Price, Balance) → Price (most-specific wins). MLOAD from Price-tainted memory → Price. SLOAD from Generic storage → Generic.
- **Phase 1 unit:** `latestRoundData` return → bytes 0-31: Price, bytes 64-95: Timestamp. `latestAnswer` return → all Price.
- **Phase 2 integration:** Three-transaction sequence: add_liquidity → oracle read → withdraw → `PRICE_MANIPULATION_FLOW` fires.
- **Phase 3 integration:** Secant solver chooses fine-grained δ for Price-dim lever vs coarse δ for Balance-dim lever.
- **Regression:** All dimensions off → pre-016 binary behavior.
