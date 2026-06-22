use std::collections::{hash_map::DefaultHasher, HashMap};
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

/// Detects fee-on-transfer tokens: ERC-20 Transfer events where the amount
/// received at `to` (post - pre balance) is less than the event's `value`.
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

        // Build pre/post balance queries: (token, balanceOf(to))
        let queries: Vec<(EVMAddress, Bytes)> = transfers
            .iter()
            .map(|(token, _from, to, _value)| (*token, self.balance_calldata(to)))
            .collect();

        let pre_balances  = ctx.call_pre_batch(&queries);
        let post_balances = ctx.call_post_batch(&queries);

        let mut res = vec![];
        for (i, (token, _from, to, claimed_value)) in transfers.iter().enumerate() {
            let pre  = EVMU256::try_from_be_slice(pre_balances[i].as_slice()).unwrap_or(EVMU256::ZERO);
            let post = EVMU256::try_from_be_slice(post_balances[i].as_slice()).unwrap_or(EVMU256::ZERO);

            // Only flag if balance actually increased (not a self-transfer or burn)
            if post <= pre {
                continue;
            }
            let actual = post - pre;
            if actual >= *claimed_value {
                continue;
            }

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
                    "Token {} transfer to {:?}: claimed={} actual={} (fee={})",
                    token_name,
                    to,
                    claimed_value,
                    actual,
                    claimed_value - actual,
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
