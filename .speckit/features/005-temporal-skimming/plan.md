# Implementation Plan — Temporal Pre-condition Skimming (Multi-Block State Priming)

**Status:** Planned  
**Owner:** TBD  
**Last updated:** 2026-06-27  

---

## 1. Approach Decision: In-Campaign Warp Step (Option B)

Following the spec's own suggestion (specify.md:101), v1 uses the **simpler model**: a `Warp(u64)` step inside the existing campaign sequence, rather than persisting state across separate LibAFL corpus rounds.

**Why Option B over Option A:**
- Reuses existing campaign infrastructure (no LibAFL corpus/scheduler changes)
- State flows naturally through the campaign loop (already clones `StagedVMState` between steps)
- No cross-round state serialization needed — avoids 500KB-5MB per snapshot overhead
- Block context modification between steps is straightforward (`host.env.block` mutation)
- Still satisfies all success criteria: block boundary exists between prime and exploit

**Trade-off accepted:** Steps remain within one fuzzer round (one corpus entry). True cross-round persistence (Option A) can be layered on later if needed.

---

## 2. Algorithm Design

### 2.1 — Warp Step in Campaign Sequence

Add a new step type `CampaignStepType::Warp(u64)` that, when encountered in the campaign loop, advances the block context without executing a transaction.

**Current campaign loop** (`executor.rs:156-191`):
```
for step in steps[0..n-1]:
    input = build_input(step, current_state)
    result = vm.execute(input)
    current_state = result.new_state

last_step = steps[n-1]
input = build_input(last_step, current_state)
result = vm.execute(input)
```

**Extended loop**:
```
for step in steps:
    match step.type:
        Transaction(ci) =>
            input = build_input(ci, current_state)
            result = vm.execute(input)
            current_state = result.new_state
        Warp(delta) =>
            advance host.env.block.number += delta
            advance host.env.block.timestamp += delta * 12
            current_state.trace.record_warp(delta)
            # Capture pre-warp snapshot for oracle comparison
            record_temporal_snapshot(current_state)
```

### 2.2 — New Types

```rust
// src/evm/planner/mod.rs or input.rs

pub enum CampaignStepType {
    Transaction(ConciseEVMInput),
    Warp(u64),  // number of blocks to advance
}
```

### 2.3 — Temporal Snapshot Metadata

A new metadata type stored in `fuzz_state.metadata_map()` that captures pre-prime token balances for cross-round divergence detection:

```rust
// src/evm/oracles/mod.rs

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TemporalBalanceSnapshot {
    /// (token, account) -> balance before warp
    pub balances: HashMap<(EVMAddress, EVMAddress), EVMU256>,
    /// Block number at time of snapshot
    pub snapshot_block: EVMU256,
}

impl_serdeany!(TemporalBalanceSnapshot);
```

### 2.4 — TemporalSkimOracle

A new oracle that:
1. **In `transition()`:** Before a warp step, snapshot token balances of all known tokens into `TemporalBalanceSnapshot` metadata
2. **In `oracle()`:** After a warp step, re-query the same balances and flag unexpected deltas (balance changes that occurred "off-screen" during the block advancement)

### 2.5 — Campaign Planner Integration

Extend `plan_campaign()` to optionally synthesize `Warp` steps:
- After a "prime" step (deposit, stake, donate), insert `Warp(N)` before the exploit step
- Use topology hints: if the exploit class is `TimelockBypass` or `RebaseDesync`, add a warp of 1-100 blocks
- CLI flag `--temporal-skimming` enables this synthesis

---

## 3. Modified Existing Files

### A. `src/evm/input.rs`
- Add `CampaignStepType` enum
- Modify `CampaignSequence.steps` from `Vec<ConciseEVMInput>` to `Vec<CampaignStepType>`
- (Or keep `Vec<ConciseEVMInput>` and add a separate `warps: Vec<(usize, u64)>` mapping — simpler, backward-compatible)

### B. `src/evm/planner/campaign_executor.rs` (or `src/executor.rs`)
- Modify the campaign step loop to handle `Warp` steps
- On warp: call `host.warp()` / `host.roll()` to advance block context
- Record temporal snapshots before warp

### C. `src/evm/oracles/mod.rs`
- Add `TemporalBalanceSnapshot` metadata type
- Add `TemporalSkimOracle` module declaration

### D. `src/evm/oracles/temporal_skim.rs` (new file)
- `TemporalSkimOracle` implementation
- `transition()`: query token balances, store snapshot
- `oracle()`: re-query, compare, flag divergence

### E. `src/evm/planner/mod.rs` (plan_campaign)
- Optionally insert `Warp` steps after prime steps when `--temporal-skimming` is enabled
- Use topology + exploit class to determine warp delta

### F. `src/evm/config.rs`
- Add `pub temporal_skimming: bool` to config

### G. `src/evm/mod.rs`
- Add `--temporal-skimming` CLI flag
- Wire to config and planner

### H. `src/fuzzers/evm_fuzzer.rs`
- Register `TemporalSkimOracle` in oracle pipeline if flag enabled
- Pass flag to planner

---

## 4. Block Advancement Implementation

**Key finding from Checkpoint 5.3:** `host.env.block` is overwritten from `input.env` at `vm.rs:598` at the start of every execution. Cheatcode mutations are not persisted.

**Solution for in-campaign warp:** Before executing the next campaign step, directly modify `host.env.block`:

```rust
// Inside the campaign loop, when encountering a Warp(delta) step:
let host = &mut *executor.borrow_mut();
let block = &mut host.env.block;
block.number += EVMU256::from(delta);
block.timestamp += EVMU256::from(delta * 12); // ~12 sec per block
```

This works because the campaign loop in `executor.rs` has access to `self.vm` (the executor), and can modify `host.env.block` between `vm.execute()` calls.

The subsequent step's `input.env` will be **overridden** by this modified `host.env` — so we must ensure the step input's env is updated from the host before execution. Alternatively, we can have the warp step explicitly set `input.env.block = host.env.block`.

---

## 5. Testing Plan

### Unit Tests
1. **CampaignStepType serialization** — Warp(delta) round-trips through serde
2. **Warp advances block context** — Mock campaign with Transaction → Warp(100) → Transaction; verify block.number increases by 100 between steps
3. **TemporalBalanceSnapshot serde** — Round-trip through serde_json
4. **TemporalSkimOracle snapshot** — Mock state; verify snapshot captures correct balances
5. **TemporalSkimOracle divergence detection** — Feed pre/post states with known delta; verify oracle flags it

### Integration Test
Use `GhostRouterMock` (from Feature 004) or a new `TemporalSkimMock` contract:
1. Prime step: `deposit()` to inflate share price
2. Warp(1000) — advance blocks
3. Exploit step: `withdraw()` with stale share price
4. Assert divergence is detected

### Regression Test
- Run existing B1 benchmark with flag disabled → same results as baseline
- Run with flag enabled → no crash, no false positive explosion

---

## 6. Performance Impact

- **Memory:** `TemporalBalanceSnapshot` stores N token-account pairs. Expected < 100 entries. Negligible.
- **CPU:** Snapshot queries cost static calls proportional to tokens × accounts. < 1ms per warp step.
- **Block advancement:** Pure arithmetic on host.env.block fields. Negligible.

---

## 7. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Warp step breaks state continuity (host.env diverges from input.env) | Force host.env back into input.env before next transaction step |
| False positives from non-exploit state changes during warp | TemporalSkimOracle requires min profit threshold (same as ERC20Oracle: `earned > owed + 0.01 ETH`) |
| Campaign planner doesn't know when to insert warps | Start with manual annotation (CLI flag + topology hints); automate in later iteration |
| Warp in the middle of a campaign breaks the trace | Record warp as a trace event; trace consumers skip warp entries |

---

## 8. Implementation Order

1. Add `CampaignStepType` enum and `warps` field to `CampaignSequence`
2. Modify campaign executor loop to handle warp steps (advance block context)
3. Add `TemporalBalanceSnapshot` metadata type
4. Create `TemporalSkimOracle` (snapshot + divergence detection)
5. Register oracle in `evm_fuzzer.rs`
6. Add `--temporal-skimming` CLI flag + config
7. Extend campaign planner to synthesize warp steps
8. Write unit tests
9. Write integration test
10. Update documentation
