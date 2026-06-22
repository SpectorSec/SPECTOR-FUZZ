use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::hash::{Hash, Hasher};

use bytes::Bytes;
use revm_interpreter::bytecode::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::CROSSCHAIN_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

/// lzReceive(uint16,bytes,uint64,bytes) = 0x001d3567
const LZ_RECEIVE_SEL: [u8; 4] = [0x00, 0x1d, 0x35, 0x67];
/// ccipReceive((bytes32,uint64,bytes,bytes,(address,uint256)[])) = 0x85572ffb
const CCIP_RECEIVE_SEL: [u8; 4] = [0x85, 0x57, 0x2f, 0xfb];
/// xReceive(bytes32,uint256,address,bytes32,string,bytes) = 0x2901504d  (Connext)
const X_RECEIVE_SEL: [u8; 4] = [0x29, 0x01, 0x50, 0x4d];

fn is_crosschain_receiver(data: &[u8]) -> bool {
    data.len() >= 4
        && (data[..4] == LZ_RECEIVE_SEL || data[..4] == CCIP_RECEIVE_SEL || data[..4] == X_RECEIVE_SEL)
}

fn selector_name(data: &[u8]) -> &'static str {
    if data[..4] == LZ_RECEIVE_SEL {
        "lzReceive"
    } else if data[..4] == CCIP_RECEIVE_SEL {
        "ccipReceive"
    } else {
        "xReceive"
    }
}

/// Detects when a cross-chain message receiver accepts a call from an untrusted
/// address.
///
/// LayerZero, CCIP, and Connext receivers should only accept calls from their
/// canonical bridge endpoint. If they execute successfully when called by any
/// arbitrary address, an attacker can forge (srcChainId, srcSender, payload)
/// and exploit the target.
pub struct CrossChainOracle {
    /// Addresses of legitimate bridge endpoint contracts (e.g. the LayerZero
    /// Endpoint, CCIP Router). Any address NOT in this set that successfully
    /// calls a receiver is flagged.
    pub trusted_bridges: HashSet<EVMAddress>,
    pub address_to_name: HashMap<EVMAddress, String>,
}

impl CrossChainOracle {
    pub fn new(trusted_bridges: HashSet<EVMAddress>, address_to_name: HashMap<EVMAddress, String>) -> Self {
        Self { trusted_bridges, address_to_name }
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
    > for CrossChainOracle
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
        use crate::input::VMInputT;
        let calldata = ctx.input.get_direct_data();
        if !is_crosschain_receiver(&calldata) {
            return vec![];
        }

        // Only flag when the call succeeds (non-reverted)
        let exec_result = ctx.fuzz_state.get_execution_result();
        if exec_result.reverted {
            return vec![];
        }

        let caller = ctx.input.get_caller();
        if self.trusted_bridges.contains(&caller) {
            return vec![];
        }

        let contract = ctx.input.get_contract();
        let fn_name = selector_name(&calldata);

        let mut hasher = DefaultHasher::new();
        contract.hash(&mut hasher);
        caller.hash(&mut hasher);
        calldata[..4].hash(&mut hasher);
        let bug_idx = (hasher.finish() << 8) + CROSSCHAIN_BUG_IDX;

        let contract_name = self
            .address_to_name
            .get(&contract)
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        EVMBugResult::new(
            "CrossChain Access Control".to_string(),
            bug_idx,
            format!(
                "{}() on {} accepted call from untrusted address {:?} — \
                 srcChainId/srcSender can be forged",
                fn_name, contract_name, caller,
            ),
            ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            None,
            Some(contract_name.to_string()),
        )
        .push_to_output();

        vec![bug_idx]
    }
}
