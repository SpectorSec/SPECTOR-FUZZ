use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::hash::{Hash, Hasher};

use bytes::Bytes;
use revm_interpreter::bytecode::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::FEE_ON_TRANSFER_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

/// Detects fee-on-transfer tokens: an account's real balance change is less
/// than the NET amount its Transfer events say it should have received.
///
/// Measured net-to-net (mirrors `rebasing.rs`): for each (token, account) we sum
/// ALL inflow events minus ALL outflow events into `expected`, and compare against
/// the actual whole-execution balance delta. The previous version compared a SINGLE
/// transfer's value against the whole-execution delta — which false-positived on any
/// trace where the recipient also moved the token elsewhere (it invented a phantom
/// "fee" out of an unrelated outflow; e.g. a 15,562 USDC transfer + a 60 USDC outflow
/// looked like a 60 USDC "fee" on fee-less USDC). See `fee_shortfall`.
pub struct FeeOnTransferOracle {
    pub address_to_name: HashMap<EVMAddress, String>,
    /// balanceOf(address) selector
    balance_of_sel: Vec<u8>,
}

impl FeeOnTransferOracle {
    pub fn new(address_to_name: HashMap<EVMAddress, String>) -> Self {
        Self {
            address_to_name,
            balance_of_sel: hex::decode("70a08231").unwrap(),
        }
    }

    fn balance_calldata(&self, addr: &EVMAddress) -> Bytes {
        let mut data = self.balance_of_sel.clone();
        data.extend_from_slice(&[0u8; 12]); // left-pad address to 32 bytes
        data.extend_from_slice(addr.as_slice());
        Bytes::from(data)
    }
}

/// Decide whether a recipient's balance shortfall is a real transfer fee.
///
/// `expected` = net inflow from Transfer events (sum of inflows − outflows for that
/// account); `actual` = the real balance delta. A fee-on-transfer token delivers
/// strictly less than the net inflow. Returns `Some(fee)` only when the shortfall
/// exceeds a rounding tolerance of 1 basis point (0.01%) of `expected` — integer
/// division dust is not a fee, and real FoT tokens charge whole percents.
fn fee_shortfall(expected: EVMU256, actual: EVMU256) -> Option<EVMU256> {
    if expected == EVMU256::ZERO || actual >= expected {
        return None;
    }
    let fee = expected - actual;
    // fee < expected / 10000  →  below 1bp  →  rounding noise, not a fee.
    if fee.saturating_mul(EVMU256::from(10000u64)) < expected {
        return None;
    }
    Some(fee)
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
    > for FeeOnTransferOracle
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
        let transfers = ctx.post_state.erc20_transfers.clone();
        if transfers.is_empty() {
            return vec![];
        }

        // Net flow per (token, account) from ALL Transfer events: how much the
        // account SHOULD have gained if the token moves exact values. Comparing one
        // transfer against the whole-execution balance delta (old logic) invented a
        // phantom fee whenever the recipient also sent the token elsewhere — net-to-net
        // (like rebasing.rs) is the correct measurement.
        let mut inflow:  HashMap<(EVMAddress, EVMAddress), EVMU256> = HashMap::new();
        let mut outflow: HashMap<(EVMAddress, EVMAddress), EVMU256> = HashMap::new();
        let mut recipients: Vec<(EVMAddress, EVMAddress)> = Vec::new();
        let mut seen = HashSet::new();
        for (token, from, to, value) in &transfers {
            *inflow.entry((*token, *to)).or_insert(EVMU256::ZERO) += *value;
            *outflow.entry((*token, *from)).or_insert(EVMU256::ZERO) += *value;
            if seen.insert((*token, *to)) {
                recipients.push((*token, *to));
            }
        }

        // One balanceOf query per net recipient, before and after the whole execution.
        let queries: Vec<(EVMAddress, Bytes)> = recipients
            .iter()
            .map(|(token, to)| (*token, self.balance_calldata(to)))
            .collect();

        let pre_balances  = ctx.call_pre_batch(&queries);
        let post_balances = ctx.call_post_batch(&queries);

        let mut res = vec![];
        for (i, (token, to)) in recipients.iter().enumerate() {
            // A failed/empty balanceOf static call (token code not loaded, or the call
            // reverted — common under a runaway call tree / resource pressure) returns
            // empty bytes, which parse as 0 and manufacture a phantom "fee=full amount"
            // (actual=0). Unmeasurable is NOT a zero balance — skip this recipient.
            if pre_balances[i].is_empty() || post_balances[i].is_empty() {
                continue;
            }
            let pre  = EVMU256::try_from_be_slice(pre_balances[i].as_slice()).unwrap_or(EVMU256::ZERO);
            let post = EVMU256::try_from_be_slice(post_balances[i].as_slice()).unwrap_or(EVMU256::ZERO);

            let in_v  = inflow.get(&(*token, *to)).copied().unwrap_or(EVMU256::ZERO);
            let out_v = outflow.get(&(*token, *to)).copied().unwrap_or(EVMU256::ZERO);
            let expected = in_v.saturating_sub(out_v); // net the account should have gained
            let actual   = post.saturating_sub(pre);   // net it actually gained

            let Some(fee) = fee_shortfall(expected, actual) else {
                continue;
            };

            let mut hasher = DefaultHasher::new();
            token.hash(&mut hasher);
            to.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + FEE_ON_TRANSFER_BUG_IDX;

            let token_name = self
                .address_to_name
                .get(token)
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            EVMBugResult::new(
                "Fee-on-Transfer".to_string(),
                bug_idx,
                format!(
                    "Token {} to {:?}: net expected={} actual={} (fee={})",
                    token_name, to, expected, actual, fee,
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                None,
                Some(token_name.to_string()),
            )
            .push_to_output();
            res.push(bug_idx);
        }
        res
    }
}

#[cfg(test)]
mod fee_on_transfer_tests {
    use super::*;

    /// The exact false positive from the Yearn fork: a recipient received 15,562
    /// USDC and sent 60 elsewhere. Net expected (15,502) == actual (15,502) → no fee.
    /// The OLD logic compared the single 15,562 transfer against the 15,502 delta and
    /// screamed "fee = 60" on fee-less USDC. Net-to-net makes it vanish.
    #[test]
    fn usdc_multi_transfer_is_not_a_fee() {
        let expected = EVMU256::from(15_502_267_944u64); // 15,562 in − 60 out
        let actual   = EVMU256::from(15_502_267_944u64);
        assert_eq!(fee_shortfall(expected, actual), None);
    }

    /// A real fee-on-transfer token: received 900 of an expected 1000 → 100 fee (10%).
    #[test]
    fn real_fee_is_flagged() {
        let fee = fee_shortfall(EVMU256::from(1000u64), EVMU256::from(900u64));
        assert_eq!(fee, Some(EVMU256::from(100u64)));
    }

    /// Integer-division dust (1 wei short of 1e18) is below the 1bp tolerance → not a fee.
    #[test]
    fn rounding_dust_is_not_a_fee() {
        let expected = EVMU256::from(1_000_000_000_000_000_000u64);
        let actual   = expected - EVMU256::from(1u64);
        assert_eq!(fee_shortfall(expected, actual), None);
    }

    /// Pure net receiver with full delivery → no fee; zero expected → no fee.
    #[test]
    fn full_delivery_and_zero_expected() {
        assert_eq!(fee_shortfall(EVMU256::from(1000u64), EVMU256::from(1000u64)), None);
        assert_eq!(fee_shortfall(EVMU256::ZERO, EVMU256::ZERO), None);
    }
}
