use std::collections::{HashMap, HashSet};

use bytes::Bytes;
use libafl::prelude::HasMetadata;
use revm_interpreter::bytecode::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::{TemporalBalanceSnapshot, TEMPORAL_SKIM_BUG_IDX},
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::{HasCaller, HasExecutionResult},
};

fn snapshot_key(token: &EVMAddress, account: &EVMAddress) -> String {
    format!("0x{:?}_0x{:?}", token, account)
}

/// A post-warp balance gain is a *skim* (unearned, time-extracted value) only if:
///   - the account is attacker-controlled (`is_attacker`) — we don't care that a
///     protocol or third party accrued yield, only what the attacker extracted; and
///   - the account never paid anything in (`!made_outflow`) — a legitimate yield
///     earner deposits first (shows up as a sender), so a pure receiver that gained
///     value purely from a time-warp got it for free; and
///   - the gain clears the dust threshold.
/// This is what separates a real skim from normal yield accrual, which the old
/// "flag any balance increase" logic conflated.
fn is_skim(is_attacker: bool, made_outflow: bool, delta: EVMU256, min_delta: EVMU256) -> bool {
    is_attacker && !made_outflow && delta >= min_delta
}

pub struct TemporalSkimOracle {
    pub address_to_name: HashMap<EVMAddress, String>,
    balance_of_sel: Vec<u8>,
}

impl TemporalSkimOracle {
    pub fn new(address_to_name: HashMap<EVMAddress, String>) -> Self {
        Self {
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

    /// Collect all unique (token, account) pairs from ERC20 transfers in a state.
    fn collect_transfer_accounts(&self, state: &EVMState) -> Vec<(EVMAddress, EVMAddress)> {
        let mut pairs = Vec::new();
        for (token, from, to, _value) in &state.erc20_transfers {
            pairs.push((*token, *from));
            pairs.push((*token, *to));
        }
        pairs.sort();
        pairs.dedup();
        pairs
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
    > for TemporalSkimOracle
{
    fn transition(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        if ctx.fuzz_state.has_metadata::<TemporalBalanceSnapshot>() {
            return 0;
        }
        let pairs = self.collect_transfer_accounts(ctx.pre_state);
        if pairs.is_empty() {
            return 0;
        }
        let queries: Vec<(EVMAddress, Bytes)> = pairs
            .iter()
            .map(|(token, account)| (*token, self.balance_calldata(account)))
            .collect();
        let pre_balances = ctx.call_pre_batch(&queries);

        let mut balances = HashMap::new();
        for (i, (token, account)) in pairs.iter().enumerate() {
            let bal = EVMU256::try_from_be_slice(pre_balances[i].as_slice()).unwrap_or(EVMU256::ZERO);
            balances.insert(snapshot_key(token, account), bal);
        }

        ctx.fuzz_state.metadata_map_mut().insert(TemporalBalanceSnapshot {
            balances,
            pairs: pairs.clone(),
            snapshot_block: EVMU256::ZERO,
        });
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
        let snapshot = match ctx.fuzz_state.metadata_map().get::<TemporalBalanceSnapshot>() {
            Some(s) => s.clone(),
            None => return vec![],
        };
        ctx.fuzz_state.metadata_map_mut().remove::<TemporalBalanceSnapshot>();

        if snapshot.balances.is_empty() {
            return vec![];
        }

        // Accounts that sent ANY token this execution = they paid something in, so a
        // balance gain is plausibly earned yield, not a free skim. (Built from post
        // transfers' `from` field.)
        let senders: HashSet<EVMAddress> = ctx
            .post_state
            .erc20_transfers
            .iter()
            .map(|(_token, from, _to, _value)| *from)
            .collect();

        let min_delta = EVMU256::from(1000000000000000u64); // 0.001 token dust floor

        let pairs = &snapshot.pairs;
        let queries: Vec<(EVMAddress, Bytes)> = pairs
            .iter()
            .map(|(token, account)| (*token, self.balance_calldata(account)))
            .collect();
        let post_balances = ctx.call_post_batch(&queries);

        let mut res = vec![];
        for (i, (token, account)) in pairs.iter().enumerate() {
            let pre = snapshot.balances.get(&snapshot_key(token, account)).copied().unwrap_or(EVMU256::ZERO);
            let post = EVMU256::try_from_be_slice(post_balances[i].as_slice()).unwrap_or(EVMU256::ZERO);
            if post <= pre {
                continue;
            }
            let delta = post - pre;

            // Scope to a real skim: attacker-controlled account, no outflow, over dust.
            // Without this it flagged every yield-bearing position as "theft".
            let is_attacker = ctx.fuzz_state.has_caller(account);
            let made_outflow = senders.contains(account);
            if !is_skim(is_attacker, made_outflow, delta, min_delta) {
                continue;
            }

            let token_name = self.address_to_name.get(token).cloned().unwrap_or_else(|| format!("{:?}", token));
            let account_name = self.address_to_name.get(account).cloned().unwrap_or_else(|| format!("{:?}", account));

            EVMBugResult::new(
                "Temporal Skim".to_string(),
                TEMPORAL_SKIM_BUG_IDX,
                format!(
                    "Temporal balance divergence: {} balance of {} increased by {} during campaign (pre: {}, post: {})",
                    account_name, token_name, delta, pre, post,
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                None,
                Some(token_name),
            )
            .push_to_output();
            res.push(TEMPORAL_SKIM_BUG_IDX);
        }
        res
    }
}

#[cfg(test)]
mod temporal_skim_tests {
    use super::*;

    fn big() -> EVMU256 { EVMU256::from(1000000000000000u64) } // dust floor

    #[test]
    fn attacker_free_gain_is_a_skim() {
        // attacker, no outflow, over threshold → skim.
        assert!(is_skim(true, false, big(), big()));
    }

    #[test]
    fn earned_yield_is_not_a_skim() {
        // attacker that PAID IN (made an outflow) → plausibly earned yield, not flagged.
        assert!(!is_skim(true, true, big() * EVMU256::from(100u64), big()));
    }

    #[test]
    fn non_attacker_gain_is_ignored() {
        // a protocol/third party accruing yield is not the attacker's exploit.
        assert!(!is_skim(false, false, big() * EVMU256::from(100u64), big()));
    }

    #[test]
    fn dust_gain_is_ignored() {
        assert!(!is_skim(true, false, big() - EVMU256::from(1u64), big()));
    }
}
