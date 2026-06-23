use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};

use bytes::Bytes;
use revm_interpreter::bytecode::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::FRESHNESS_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

/// Detects stale oracle data consumed without a freshness check (Ghost #3).
///
/// Monitors contracts that expose `latestRoundData()` (Chainlink AggregatorV3
/// interface, selector 0xfeaf968c). After each execution it calls the function
/// and checks three conditions:
///
///   1. `updatedAt == 0`     → oracle was never updated
///   2. `answer <= 0`        → oracle returned an invalid price
///   3. `block.timestamp - updatedAt > MAX_STALENESS` → data is stale
///
/// All three fire only when the execution SUCCEEDED (no revert) — if the
/// consuming protocol reverted it already caught the staleness itself.
///
/// Auto-activated when `latestRoundData` selector is found in any ABI.
/// Corpus seeds warp `block.timestamp` past the heartbeat boundary so the
/// fuzzer naturally explores the stale-read path.
pub struct FreshnessOracle {
    /// Contracts that expose latestRoundData() — oracle mocks or Chainlink forks.
    oracle_contracts: Vec<EVMAddress>,
    pub address_to_name: HashMap<EVMAddress, String>,
    /// latestRoundData() calldata — just the selector, no args.
    calldata: Bytes,
    /// Staleness threshold in seconds. Default: 3600 (Chainlink 1h heartbeat).
    max_staleness: u64,
}

/// latestRoundData() = 0xfeaf968c
pub const LATEST_ROUND_DATA_SEL: [u8; 4] = [0xfe, 0xaf, 0x96, 0x8c];

/// latestAnswer() = 0x50d25bcd  (older Chainlink interface)
pub const LATEST_ANSWER_SEL: [u8; 4] = [0x50, 0xd2, 0x5b, 0xcd];

/// getRoundData(uint80) = 0x9a6fc8f5
pub const GET_ROUND_DATA_SEL: [u8; 4] = [0x9a, 0x6f, 0xc8, 0xf5];

/// Returns true if the selector matches any Chainlink oracle interface.
pub fn is_oracle_interface(sel: &[u8; 4]) -> bool {
    sel == &LATEST_ROUND_DATA_SEL
        || sel == &LATEST_ANSWER_SEL
        || sel == &GET_ROUND_DATA_SEL
}

impl FreshnessOracle {
    pub fn new(
        oracle_contracts: Vec<EVMAddress>,
        address_to_name: HashMap<EVMAddress, String>,
        max_staleness_secs: u64,
    ) -> Self {
        Self {
            oracle_contracts,
            address_to_name,
            calldata: Bytes::from(LATEST_ROUND_DATA_SEL.to_vec()),
            max_staleness: max_staleness_secs,
        }
    }

    /// Parse the `latestRoundData` return tuple:
    /// (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    /// Each slot is 32 bytes. Returns (answer, updatedAt) or None if too short.
    fn parse_round_data(data: &[u8]) -> Option<(EVMU256, EVMU256)> {
        if data.len() < 128 {
            return None;
        }
        // slot 1 (offset 32): answer (int256 — treat as U256 for sign check)
        let answer = EVMU256::try_from_be_slice(&data[32..64]).unwrap_or(EVMU256::ZERO);
        // slot 3 (offset 96): updatedAt (uint256)
        let updated_at = EVMU256::try_from_be_slice(&data[96..128]).unwrap_or(EVMU256::ZERO);
        Some((answer, updated_at))
    }
}

impl
    Oracle<
        EVMState,
        EVMAddress,
        Bytecode,
        Bytes,
        EVMAddress,
        EVMU256,
        Vec<u8>,
        EVMInput,
        EVMFuzzState,
        ConciseEVMInput,
        EVMQueueExecutor,
    > for FreshnessOracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(
        &self,
        ctx: &mut OracleCtx<
            EVMState,
            EVMAddress,
            Bytecode,
            Bytes,
            EVMAddress,
            EVMU256,
            Vec<u8>,
            EVMInput,
            EVMFuzzState,
            ConciseEVMInput,
            EVMQueueExecutor,
        >,
        _stage: u64,
    ) -> Vec<u64> {
        if self.oracle_contracts.is_empty() {
            return vec![];
        }

        // Only flag when the consuming protocol didn't revert — a revert means
        // it caught the staleness itself.
        let reverted = ctx.fuzz_state.get_execution_result().reverted;
        if reverted {
            return vec![];
        }

        // Current block timestamp from the execution environment.
        let block_ts: EVMU256 = ctx.input.env.block.timestamp;

        // Query latestRoundData() post-execution on each oracle contract.
        let queries: Vec<(EVMAddress, Bytes)> = self
            .oracle_contracts
            .iter()
            .map(|addr| (*addr, self.calldata.clone()))
            .collect();

        let post_results = ctx.call_post_batch(&queries);

        // Re-borrow result after mutable call_post_batch is done.
        let result = ctx.fuzz_state.get_execution_result();

        let mut res = vec![];
        for (i, oracle_addr) in self.oracle_contracts.iter().enumerate() {
            let data = post_results[i].clone();

            let (answer, updated_at) = match Self::parse_round_data(&data) {
                Some(v) => v,
                None => continue,
            };

            let oracle_name = self
                .address_to_name
                .get(oracle_addr)
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            let mut hasher = DefaultHasher::new();
            oracle_addr.hash(&mut hasher);

            // Condition 1: oracle never updated
            if updated_at == EVMU256::ZERO {
                let bug_idx = (hasher.finish() << 8) + FRESHNESS_BUG_IDX;
                EVMBugResult::new(
                    "Stale Oracle — Never Updated".to_string(),
                    bug_idx,
                    format!(
                        "Oracle {} updatedAt == 0: data was never set. \
                         Consuming protocol accepted it without reverting.",
                        oracle_name,
                    ),
                    ConciseEVMInput::from_input(ctx.input, result),
                    None,
                    Some(oracle_name.to_string()),
                )
                .push_to_output();
                res.push(bug_idx);
                continue;
            }

            // Condition 2: invalid (non-positive) answer
            // int256 is stored as U256; negative values have the high bit set.
            // We detect: answer == 0 OR answer's high bit set (negative int256).
            let answer_is_invalid = answer == EVMU256::ZERO || answer.bit(255);
            if answer_is_invalid {
                let bug_idx = (hasher.finish() << 8) + FRESHNESS_BUG_IDX + 1;
                EVMBugResult::new(
                    "Invalid Oracle Answer".to_string(),
                    bug_idx,
                    format!(
                        "Oracle {} returned answer <= 0 ({}) without the consumer reverting. \
                         Protocol accepted an invalid price.",
                        oracle_name, answer,
                    ),
                    ConciseEVMInput::from_input(ctx.input, result),
                    None,
                    Some(oracle_name.to_string()),
                )
                .push_to_output();
                res.push(bug_idx);
            }

            // Condition 3: stale data
            if block_ts > updated_at {
                let age = block_ts - updated_at;
                let max = EVMU256::from(self.max_staleness);
                if age > max {
                    let bug_idx = (hasher.finish() << 8) + FRESHNESS_BUG_IDX + 2;
                    EVMBugResult::new(
                        "Stale Oracle Price".to_string(),
                        bug_idx,
                        format!(
                            "Oracle {} price is {} seconds stale (max: {}). \
                             Consuming protocol accepted stale data without reverting \
                             (missing updatedAt freshness check).",
                            oracle_name, age, self.max_staleness,
                        ),
                        ConciseEVMInput::from_input(ctx.input, result),
                        None,
                        Some(oracle_name.to_string()),
                    )
                    .push_to_output();
                    res.push(bug_idx);
                }
            }
        }
        res
    }
}
