use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::hash::{Hash, Hasher};

use bytes::Bytes;
use revm_interpreter::bytecode::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::REBASING_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

/// Detects rebasing-token accounting mismatches.
///
/// A rebasing token (AMPL, stETH) can change `balanceOf(addr)` without emitting
/// a Transfer event.  Protocols that account for balance changes only by watching
/// Transfer events will have stale, exploitable accounting.
///
/// Detection logic per (token, protocol_address) pair:
///   net_transfer_flow = Σ inbound_value − Σ outbound_value  (from Transfer events)
///   balance_delta     = post_balance − pre_balance
///   mismatch          = balance_delta ≠ net_transfer_flow (and neither is zero)
///
/// A mismatch means the token's balance changed in a way that Transfer events
/// don't explain — classic rebasing behaviour.
pub struct RebasingOracle {
    /// Protocol-deployed addresses to monitor.  We query their balanceOf for each
    /// token seen in Transfer events.
    pub known_contracts: HashSet<EVMAddress>,
    pub address_to_name: HashMap<EVMAddress, String>,
    balance_of_sel: Vec<u8>,
}

impl RebasingOracle {
    pub fn new(known_contracts: HashSet<EVMAddress>, address_to_name: HashMap<EVMAddress, String>) -> Self {
        Self {
            known_contracts,
            address_to_name,
            balance_of_sel: hex::decode("70a08231").unwrap(),
        }
    }

    fn balance_calldata(&self, addr: &EVMAddress) -> Bytes {
        let mut data = self.balance_of_sel.clone();
        data.extend_from_slice(&[0u8; 12]);
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
    > for RebasingOracle
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

        // Collect unique (token, protocol_addr) pairs worth checking.
        // We only care about protocol contracts — attacker addresses are expected
        // to receive arbitrary amounts.
        let mut pairs: Vec<(EVMAddress, EVMAddress)> = Vec::new();
        let mut seen = HashSet::new();
        for (token, from, to, _) in &transfers {
            for addr in [from, to] {
                if self.known_contracts.contains(addr) {
                    let key = (*token, *addr);
                    if seen.insert(key) {
                        pairs.push(key);
                    }
                }
            }
        }
        if pairs.is_empty() {
            return vec![];
        }

        // Query pre and post balances for each pair.
        let queries: Vec<(EVMAddress, Bytes)> = pairs
            .iter()
            .map(|(token, addr)| (*token, self.balance_calldata(addr)))
            .collect();

        let pre_results  = ctx.call_pre_batch(&queries);
        let post_results = ctx.call_post_batch(&queries);

        // Compute net Transfer flow for each (token, addr) pair from events.
        let mut net_flow: HashMap<(EVMAddress, EVMAddress), i128> = HashMap::new();
        for (token, from, to, value) in &transfers {
            let v = (*value).min(EVMU256::from(i128::MAX)).as_limbs()[0] as i128;
            if self.known_contracts.contains(from) {
                *net_flow.entry((*token, *from)).or_default() -= v;
            }
            if self.known_contracts.contains(to) {
                *net_flow.entry((*token, *to)).or_default() += v;
            }
        }

        let mut res = vec![];
        for (i, (token, addr)) in pairs.iter().enumerate() {
            let pre  = EVMU256::try_from_be_slice(pre_results[i].as_slice()).unwrap_or(EVMU256::ZERO);
            let post = EVMU256::try_from_be_slice(post_results[i].as_slice()).unwrap_or(EVMU256::ZERO);

            // Skip pairs where the balance didn't change at all.
            if pre == post {
                continue;
            }

            let balance_delta: i128 = if post >= pre {
                (post - pre).min(EVMU256::from(i128::MAX)).as_limbs()[0] as i128
            } else {
                -((pre - post).min(EVMU256::from(i128::MAX)).as_limbs()[0] as i128)
            };

            let flow = *net_flow.get(&(*token, *addr)).unwrap_or(&0i128);

            if balance_delta == flow {
                continue;
            }

            // The balance changed by a different amount than Transfer events
            // account for — rebasing token behaviour.
            let mut hasher = DefaultHasher::new();
            token.hash(&mut hasher);
            addr.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + REBASING_BUG_IDX;

            let contract_name = self
                .address_to_name
                .get(addr)
                .map(|s| s.as_str())
                .unwrap_or("unknown");
            let token_name = self
                .address_to_name
                .get(token)
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            EVMBugResult::new(
                "Rebasing Token Mismatch".to_string(),
                bug_idx,
                format!(
                    "{} balance in {} changed by {} but Transfer events account for only {} \
                     — rebasing token may corrupt accounting",
                    token_name, contract_name, balance_delta, flow,
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                None,
                Some(contract_name.to_string()),
            )
            .push_to_output();
            res.push(bug_idx);
        }
        res
    }
}
