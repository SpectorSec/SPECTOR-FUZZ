use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};

use bytes::Bytes;
use revm_interpreter::bytecode::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::ERC4626_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

/// Detects ERC-4626 share-price manipulation.
///
/// The share price is `convertToAssets(1e18)`. It should never decrease
/// between transactions — a decrease means either:
///   - A donation attack (attacker donated underlying to inflate then deflate)
///   - An accounting bug (totalAssets diverged from expected)
///   - A share-price inflation attack (classic Cream/Hundred pattern)
///
/// Auto-activated by the corpus initializer when `convertToAssets` (0x07a2d13a)
/// is found in the ABI — no user configuration needed.
pub struct ERC4626Oracle {
    /// ERC-4626 vault addresses to monitor → last known share price.
    pub vaults: HashMap<EVMAddress, EVMU256>,
    pub address_to_name: HashMap<EVMAddress, String>,
    convert_to_assets_calldata: Bytes,
}

impl ERC4626Oracle {
    /// `vaults` = list of contract addresses confirmed to be ERC-4626 vaults.
    pub fn new(vaults: Vec<EVMAddress>, address_to_name: HashMap<EVMAddress, String>) -> Self {
        // convertToAssets(1e18) — query one share's worth
        let mut calldata = vec![0x07u8, 0xa2, 0xd1, 0x3a];
        // 1e18 = 0xde0b6b3a7640000 left-padded to 32 bytes
        calldata.extend_from_slice(&[0u8; 24]);
        calldata.extend_from_slice(&[0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]);

        Self {
            vaults: vaults.into_iter().map(|a| (a, EVMU256::ZERO)).collect(),
            address_to_name,
            convert_to_assets_calldata: Bytes::from(calldata),
        }
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
    > for ERC4626Oracle
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
        if self.vaults.is_empty() {
            return vec![];
        }

        // Query convertToAssets(1e18) in pre and post state for each vault.
        let queries: Vec<(EVMAddress, Bytes)> = self
            .vaults
            .keys()
            .map(|addr| (*addr, self.convert_to_assets_calldata.clone()))
            .collect();

        let pre_results  = ctx.call_pre_batch(&queries);
        let post_results = ctx.call_post_batch(&queries);

        let mut res = vec![];
        for (i, (vault, _)) in self.vaults.iter().enumerate() {
            let pre  = EVMU256::try_from_be_slice(pre_results[i].as_slice()).unwrap_or(EVMU256::ZERO);
            let post = EVMU256::try_from_be_slice(post_results[i].as_slice()).unwrap_or(EVMU256::ZERO);

            // Share price of zero means the vault reverted or isn't initialized — skip.
            if pre == EVMU256::ZERO || post == EVMU256::ZERO {
                continue;
            }

            // Flag if share price DECREASED — unexpected in a healthy vault.
            if post >= pre {
                continue;
            }

            let mut hasher = DefaultHasher::new();
            vault.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + ERC4626_BUG_IDX;

            let name = self
                .address_to_name
                .get(vault)
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            EVMBugResult::new(
                "ERC-4626 Share Price Manipulation".to_string(),
                bug_idx,
                format!(
                    "Vault {} share price decreased: {} → {} \
                     (possible donation/inflation attack)",
                    name, pre, post,
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                None,
                Some(name.to_string()),
            )
            .push_to_output();
            res.push(bug_idx);
        }
        res
    }
}
