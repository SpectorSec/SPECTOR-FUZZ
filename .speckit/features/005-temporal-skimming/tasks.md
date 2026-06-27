# Task Breakdown — Temporal Pre-condition Skimming

**Status:** Tasked  
**Owner:** TBD  
**Last updated:** 2026-06-27  

---

## Tasks (in order, must complete sequentially)

### Task 1 — Add CampaignStepType and Warp Support to CampaignSequence

**Files:** `src/evm/input.rs`, `src/evm/planner/mod.rs`

- [ ] Add `CampaignStepType` enum:
  ```rust
  #[derive(Clone, Debug, Serialize, Deserialize)]
  pub enum CampaignStepType {
      Transaction(ConciseEVMInput),
      Warp(u64),
  }
  ```
- [ ] Modify `CampaignSequence` to hold `Vec<CampaignStepType>` (or add `warps: BTreeMap<usize, u64>` for backward compat)
- [ ] Update `plan_campaign()` to output `Vec<CampaignStepType>` instead of `Vec<ConciseEVMInput>`
- [ ] Update `ConciseEVMInput` campaign field type if needed
- [ ] **Verify:** `cargo check --features evm` compiles

### Task 2 — Modify Campaign Executor Loop for Warp Steps

**Files:** `src/executor.rs`, `src/evm/vm.rs`

- [ ] In `run_target()` campaign loop, match on `CampaignStepType`:
  - `Transaction(ci)` → existing logic (build input, execute, advance state)
  - `Warp(delta)` → advance `host.env.block.number += delta`, `host.env.block.timestamp += delta * 12`
- [ ] After warp, clone `host.env` into the current state's env so next step uses advanced block context
- [ ] Record warp in trace (optional, for debugging)
- [ ] **Verify:** Unit test — campaign with `Transaction → Warp(100) → Transaction`; assert block.number differs by 100 between steps

### Task 3 — Add TemporalBalanceSnapshot Metadata

**File:** `src/evm/oracles/mod.rs`

- [ ] Add `TemporalBalanceSnapshot` struct:
  ```rust
  #[derive(Clone, Debug, Default, Serialize, Deserialize)]
  pub struct TemporalBalanceSnapshot {
      pub balances: HashMap<(EVMAddress, EVMAddress), EVMU256>,
      pub snapshot_block: EVMU256,
  }
  impl_serdeany!(TemporalBalanceSnapshot);
  ```
- [ ] Export in module
- [ ] **Verify:** `cargo check` compiles

### Task 4 — Create TemporalSkimOracle

**New file:** `src/evm/oracles/temporal_skim.rs`

- [ ] Implement `Oracle` trait for `TemporalSkimOracle`
- [ ] **`transition()`:** Before a warp is about to execute:
  - Scan known tokens (from `ERC20Oracle` data or ABI map)
  - For each token, query `balanceOf(protocol_address)` via `ctx.call_pre_batch()`
  - Store result in `TemporalBalanceSnapshot` metadata
- [ ] **`oracle()`:** After a warp + exploit step:
  - Load `TemporalBalanceSnapshot` from metadata
  - Re-query same balances via `ctx.call_post_batch()`
  - Compute delta = post - snapshot
  - If `abs(delta) > threshold` (e.g., 0.01 ETH), flag as temporal divergence
- [ ] Add module declaration to `oracles/mod.rs`
- [ ] **Verify:** Unit test — mock pre/post with known balance delta; assert oracle fires

### Task 5 — Register TemporalSkimOracle in Fuzzer Pipeline

**File:** `src/fuzzers/evm_fuzzer.rs`

- [ ] Import `TemporalSkimOracle`
- [ ] If `config.temporal_skimming`, push `TemporalSkimOracle` into oracle list
- [ ] Pass `address_to_name` map if needed
- [ ] **Verify:** Fuzzer runs with flag enabled, oracle fires on temporal divergence

### Task 6 — CLI Flag and Config

**Files:** `src/evm/config.rs`, `src/evm/mod.rs`

- [ ] Add `pub temporal_skimming: bool` to EVM config struct
- [ ] Add `#[arg(long, default_value = "false")]` flag `--temporal-skimming` to `EvmArgs`
- [ ] Wire flag from args → config → evm_fuzzer
- [ ] Gate planner warp synthesis behind flag
- [ ] **Verify:** Run with and without flag; behavior differs

### Task 7 — Extend Campaign Planner for Warp Synthesis

**File:** `src/evm/planner/mod.rs` (plan_campaign)

- [ ] After the prime step(s), if `config.temporal_skimming`:
  - Check topology exploit class
  - If class is `TimelockBypass` → insert `Warp(1)` (single block)
  - If class is `RebaseDesync` → insert `Warp(100)` (multiple blocks)
  - Default: `Warp(10)` after any privileged prime step
- [ ] Ensure warp is inserted between prime and exploit steps, not after the last step
- [ ] **Verify:** Unit test — plan_campaign returns steps including Warp when flag is on

### Task 8 — Unit Tests

- [ ] **Test:** CampaignStepType serde round-trip (Warp(100) survives JSON)
- [ ] **Test:** Warp advances block context in executor loop
- [ ] **Test:** TemporalBalanceSnapshot serde round-trip
- [ ] **Test:** TemporalSkimOracle stores and retrieves snapshot
- [ ] **Test:** TemporalSkimOracle detects balance divergence
- [ ] **Test:** planner inserts warp for TimelockBypass topology
- [ ] **Verify:** All tests pass under `cargo test --features evm`

### Task 9 — Integration Test with TemporalSkimMock

**New file:** `tests/bench/TemporalSkimMock.sol`

- [ ] Create Solidity contract:
  ```solidity
  contract TemporalSkimMock {
      uint256 public rewardRate = 1 ether;
      mapping(address => uint256) public deposits;
      uint256 public lastUpdate;
      
      function deposit() external { deposits[msg.sender] += 1 ether; lastUpdate = block.number; }
      function claim() external returns (uint256) {
          uint256 elapsed = block.number - lastUpdate;
          uint256 reward = deposits[msg.sender] * rewardRate * elapsed / 1e18;
          deposits[msg.sender] = 0;
          return reward;
      }
  }
  ```
- [ ] Compile, generate .abi + .bin
- [ ] Write integration test script (Python or shell):
  - Run fuzzer with `--temporal-skimming` → should detect reward divergence
  - Run without flag → should NOT detect it
- [ ] **Verify:** Integration test passes

### Task 10 — Final Review and Documentation

- [ ] Update flag help strings
- [ ] Add module docstring to `TemporalSkimOracle`
- [ ] Add `TemporalBalanceSnapshot` docstring
- [ ] Update README features section
- [ ] Add temporal-skimming to feature table
- [ ] **Verify:** `cargo check` + `cargo test` all green
