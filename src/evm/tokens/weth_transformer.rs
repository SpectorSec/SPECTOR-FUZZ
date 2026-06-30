use std::fmt::Debug;

use alloy_primitives::hex;
use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::{
    interpreter::{ExtBytecode, InputsImpl, SharedMemory},
    interpreter_types::ReturnData as ReturnDataTr,
    CallInput, Interpreter,
};
use revm_primitives::{hardfork::SpecId, Bytes as PrimBytes};
use serde::{de::DeserializeOwned, Serialize};

use super::{uniswap::CODE_REGISTRY, PairContext};
use crate::{
    evm::{
        types::{EVMAddress, EVMFuzzState, EVMU256, EVMU512},
        vm::{EVMExecutor, MEM_LIMIT},
    },
    generic_vm::vm_state::VMStateT,
    get_code_tokens,
    input::ConciseSerde,
    is_call_success,
    scale,
};

#[derive(Clone, Debug, Default)]
pub struct WethContext {
    pub weth_address: EVMAddress,
}

pub fn withdraw_bytes(amount: EVMU256) -> Bytes {
    let mut ret = Vec::new();
    ret.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]); // transfer to a dead address
    ret.extend_from_slice(&[0x00; 30]); // 0x000...dead
    ret.extend_from_slice(&[0xde, 0xad]);
    ret.extend_from_slice(&amount.to_be_bytes::<32>()); // amount
    Bytes::from(ret)
}

impl PairContext for WethContext {
    fn transform<VS, CI, SC>(
        &self,
        src: &EVMAddress,
        next: &EVMAddress,
        amount: EVMU256,
        state: &mut EVMFuzzState,
        vm: &mut EVMExecutor<VS, CI, SC>,
        reverse: bool,
    ) -> Option<(EVMAddress, EVMU256)>
    where
        VS: VMStateT + Default + 'static,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        if reverse {
            // println!("bought {:?} weth", amount);
            // buy
            vm.host.evmstate.flashloan_data.owed += EVMU512::from(amount) * scale!();
            vm.host
                .evmstate
                .flashloan_data
                .oracle_recheck_balance
                .insert(self.weth_address);
        } else {
            // println!("sold {:?} weth", amount);
            // sell
            vm.host.evmstate.flashloan_data.earned += EVMU512::from(amount) * scale!();
            vm.host
                .evmstate
                .flashloan_data
                .oracle_recheck_balance
                .insert(self.weth_address);
        }

        // todo: fix real balance
        vm.host.evmstate.balance.insert(self.weth_address, EVMU256::MAX);

        let addr = self.weth_address;
        let code = get_code_tokens!(addr, vm, state);
        let calldata = if reverse { Bytes::from(vec![]) } else { withdraw_bytes(amount) };
        let caller = if reverse { *next } else { *src };
        let call_value = if reverse { amount } else { EVMU256::ZERO };
        let interp_input = InputsImpl {
            target_address: addr,
            bytecode_address: Some(addr),
            caller_address: caller,
            input: CallInput::Bytes(PrimBytes::copy_from_slice(calldata.as_ref())),
            call_value,
        };
        let mut interp = Interpreter::new(
            SharedMemory::new_with_memory_limit(MEM_LIMIT),
            ExtBytecode::new((*code).clone()),
            interp_input,
            false,
            SpecId::PRAGUE,
            1e10 as u64,
        );
        let ir = vm.host.run_inspect(&mut interp, state);
        if !is_call_success!(ir) {
            // A WETH wrap/unwrap can legitimately revert during fuzzing (e.g. an
            // absurd amount exceeding balance). The transform simply doesn't apply —
            // return None and let the caller fall back, rather than crashing the whole
            // fuzzer with a panic. (Was a leftover debug panic in front of this return.)
            tracing::debug!(
                "[weth] transform call reverted: {:?} => {:?} {:?} ({:?})",
                caller,
                addr,
                hex::encode(calldata.as_ref()),
                ir
            );
            return None;
        }

        Some((*next, amount))
    }

    fn name(&self) -> String {
        "weth".to_string()
    }
}
