use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::hash::{Hash, Hasher};

use bytes::Bytes;
use revm_interpreter::bytecode::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::APPROVAL_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::{HasCaller, HasExecutionResult},
};

/// Detects unexpected ERC-20 approvals: a protocol contract (owner) approving
/// an attacker-controlled address (spender). Catches permit() bypasses,
/// reentrancy-based approval escalation, and missing access-control on approve().
pub struct SuspiciousApprovalOracle {
    /// Known protocol-deployed contract addresses.
    pub known_contracts: HashSet<EVMAddress>,
    pub address_to_name: HashMap<EVMAddress, String>,
}

impl SuspiciousApprovalOracle {
    pub fn new(
        known_contracts: HashSet<EVMAddress>,
        address_to_name: HashMap<EVMAddress, String>,
    ) -> Self {
        Self { known_contracts, address_to_name }
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
    > for SuspiciousApprovalOracle
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
        let approvals = &ctx.post_state.erc20_approvals;
        if approvals.is_empty() {
            return vec![];
        }

        let attackers: HashSet<EVMAddress> = ctx.fuzz_state.callers_pool.iter().cloned().collect();

        let mut res = vec![];
        for (token, owner, spender, value) in approvals {
            // Flag: protocol contract approved attacker as spender
            if !self.known_contracts.contains(owner) {
                continue;
            }
            if !attackers.contains(spender) {
                continue;
            }

            let mut hasher = DefaultHasher::new();
            token.hash(&mut hasher);
            owner.hash(&mut hasher);
            spender.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + APPROVAL_BUG_IDX;

            let owner_name = self
                .address_to_name
                .get(owner)
                .map(|s| s.as_str())
                .unwrap_or("unknown");
            let token_name = self
                .address_to_name
                .get(token)
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            EVMBugResult::new(
                "Suspicious Approval".to_string(),
                bug_idx,
                format!(
                    "Protocol contract {} approved attacker {:?} for {} tokens of {}",
                    owner_name, spender, value, token_name,
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                None,
                Some(owner_name.to_string()),
            )
            .push_to_output();
            res.push(bug_idx);
        }
        res
    }
}
