use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::hash::{Hash, Hasher};

use bytes::Bytes;
use revm_interpreter::bytecode::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::NFT_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::{HasCaller, HasExecutionResult},
};

/// Detects ERC-721 ownership theft: a tokenId transferred from a non-attacker
/// address to an attacker-controlled address (fuzzer callers pool).
pub struct NFTOwnershipOracle {
    pub address_to_name: HashMap<EVMAddress, String>,
}

impl NFTOwnershipOracle {
    pub fn new(address_to_name: HashMap<EVMAddress, String>) -> Self {
        Self { address_to_name }
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
    > for NFTOwnershipOracle
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
        let transfers = &ctx.post_state.nft_transfers;
        if transfers.is_empty() {
            return vec![];
        }

        // Build attacker set from fuzzer callers pool at check time
        let attackers: HashSet<EVMAddress> = ctx.fuzz_state.callers_pool.iter().cloned().collect();

        let mut res = vec![];
        for (token_contract, from, to, token_id) in transfers {
            // Only flag if recipient is an attacker address and sender is not
            if !attackers.contains(to) {
                continue;
            }
            if attackers.contains(from) {
                continue;
            }

            let mut hasher = DefaultHasher::new();
            token_contract.hash(&mut hasher);
            token_id.hash(&mut hasher);
            to.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + NFT_BUG_IDX;

            let contract_name = self
                .address_to_name
                .get(token_contract)
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            EVMBugResult::new(
                "NFT Ownership Leak".to_string(),
                bug_idx,
                format!(
                    "ERC-721 tokenId {} transferred from {:?} to attacker {:?} in contract {}",
                    token_id, from, to, contract_name,
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
