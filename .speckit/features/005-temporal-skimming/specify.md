# Feature 005 — Temporal Pre-condition Skimming (Multi-Block State Priming)

**Status:** Investigating  
**Owner:** TBD  
**Last updated:** 2026-06-26  

---

## Overview

Some DeFi exploits cannot be executed in a single transaction. The attacker must perform a **state-priming operation** (deposit collateral, manipulate an oracle price, accrue rewards, unlock a timelock) in one transaction or block, then execute the **exploit** in a subsequent transaction after the protocol's internal accounting has diverged from reality across a block boundary.

Currently, SPECTOR-FUZZ's campaign system (`plan_campaign` → `execute_campaign`) chains all steps atomically within one execution event — same block, same transaction, same EVM state. This is correct for flash-loan-based exploits but fundamentally cannot reach exploits that require state to evolve across rounds.

Temporal Pre-condition Skimming extends the fuzzer to **persist state across separate execution rounds**, enabling multi-block exploit discovery.

---

## Why This Matters

From the DeFi incident database, multi-block priming patterns appear in several categories:

- **Lending protocol rebalancing:** Tx 1 deposits collateral with a manipulated oracle price → liquidation threshold incorrectly calculated → Tx 2 liquidates more than entitled
- **Vault share inflation:** Tx 1 makes a small donation to inflate shares → Tx 2 exploits the inflated share price for profit
- **Timelock bypass:** Tx 1 schedules a privileged action → Tx 2 executes it before the timelock expiry check properly validates (race condition)
- **Reward accumulation:** Tx 1 stakes tokens → rewards accrue over blocks → Tx 2 claims rewards based on stale state
- **Rebasing token desync:** Tx 1 triggers a rebase → internal accounting diverges from actual balances → Tx 2 exploits the divergence

The critical distinction: **block boundary** must exist between prime and exploit for the desync to occur. Single-transaction campaigns cannot reproduce this.

---

## Success Criteria

This feature is worth building if and only if:

1. The fuzzer can "checkpoint" state after an execution round and "restore" it in a later round without interfering with normal corpus evolution
2. A multi-round campaign can be defined where Round N primes state, the fuzzer advances blocks (warp), and Round N+1 executes the exploit against the evolved state
3. An oracle model exists that can detect state divergence across rounds — e.g., "balance after Round N+1 differs from expected based on Round N's state"
4. The feature produces at least one validated exploit from the incident database that the single-transaction campaign system cannot reach

---

## Out of Scope

- True concurrency or mempool simulation (ordering multiple transactions within a block). We focus on sequential rounds with block boundaries between them
- Replaying historical mainnet states — the fork already provides the initial state
- State cloning across parallel fuzzer instances — we stay within a single LibAFL process

---

## Investigation Checkpoints

### Checkpoint 5.1 — Campaign Step Execution Model
**Files:** `src/evm/planner/campaign_executor.rs`, `src/evm/vm.rs`, `src/evm/input.rs`  
**Question:** How does `execute_campaign` currently chain steps? What state carries forward between steps? Does the campaign execute entirely within one call to `vm.execute()`, or can steps be split across separate fuzzer rounds?  
**Evidence required:** The `execute_campaign` implementation, the `CampaignStep` and `ConciseEVMInput` schemas, and how `new_state` flows between steps.

### Checkpoint 5.2 — State Serialization and Metadata Persistence
**Files:** `src/evm/types.rs`, `src/state_input.rs`, `src/evm/corpus_initializer.rs`  
**Question:** What does it take to persist an `EVMStagedVMState` across fuzzer rounds? Is the state serializable (Serde)? Is there existing infrastructure for storing state in corpus metadata?  
**Evidence required:** The `StagedVMState` definition, its Serde derives, and existing examples of `SerdeAny` metadata that persist across rounds (like `CampaignIntermediateStates` at `types.rs:73`).

### Checkpoint 5.3 — Block Advancement Between Rounds
**Files:** `src/evm/host.rs`, `src/evm/middlewares/cheatcode/mod.rs`  
**Question:** Can the fuzzer advance `block.number`, `block.timestamp`, or other block context between execution rounds? Is there an existing `vm.warp()` cheatcode implementation? Does it update the host's `env` block context?  
**Evidence required:** The `vm.warp()` implementation path, how `Env.block` is modified, and whether this can be triggered between campaign steps (not during execution).

### Checkpoint 5.4 — Oracle Model for Cross-Round State Divergence
**Files:** `src/evm/oracles/` (all)  
**Question:** The existing oracles (ERC20Oracle, FunctionOracle, CrossChainOracle, etc.) all operate on **post-state of a single transaction**. What would a cross-round oracle look like? Possibilities:
- **Balance delta oracle:** Compare token balances at end of Round N vs. start of Round N+1, flag unexpected changes
- **Invariant oracle:** Run invariant checks before and after the block boundary
- **Stale state oracle:** Detect when Round N+1's execution reads state that Round N modified (stale slot detection)

**Evidence required:** Survey all existing oracles. Which ones could be adapted to compare state snapshots rather than post-state only?

### Checkpoint 5.5 — Real Incident Validation
**File:** `/workspace/_global/DeFi-Security-Incident/vulns/`  
**Question:** Pick 3 incidents that clearly require a block boundary. For each:
1. What state is primed in Tx 1?
2. What block condition triggers the desync?
3. How many blocks must elapse between Tx 1 and Tx 2?
4. Could the atomic campaign system reproduce this? (Likely no — the desync requires the block boundary.)

---

## Risks

- **Performance collapse:** If every fuzzer round saves and restores full EVM state, throughput could drop dramatically. Must use incremental state diff, not full clone
- **Corpus explosion:** Multi-round campaigns multiply the state space. Without careful pruning, the corpus could grow unbounded
- **False positives:** A state difference between rounds is not necessarily an exploit — need a clear "profitable" threshold (same as `earned > owed + 0.01 ETH` in ERC20Oracle)
- **LibAFL model mismatch:** LibAFL's corpus model is designed around independent test cases, not chained sequences across rounds. May need to extend the scheduler or corpus traits

---

## Open Questions

- Can the existing `CampaignIntermediateStates` metadata (already stored in state at `executor.rs:174`) serve as the checkpoint mechanism, or does it need a different structure?
- For block advancement: does the fuzzer control `block.number` per-round via the config, or do we need to call `vm.warp()` explicitly? What happens to transactions that expect a specific block number?
- Is there a simpler model: instead of persisting state, could we define the multi-round campaign as a single input with an explicit "warp" step? E.g., `Step A → block.advance(N) → Step B` where the warp is a no-op EVM step?
