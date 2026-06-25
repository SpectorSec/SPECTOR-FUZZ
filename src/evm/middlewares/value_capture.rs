use std::any::Any;
use std::clone::Clone;
use std::collections::HashMap;
use std::fmt::Debug;
use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::{
    interpreter_types::{InputsTr, Jumps},
    CallInput, Interpreter,
};
use serde::{Deserialize, Serialize};

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    types::{as_u64, convert_u256_to_h160, EVMAddress, EVMFuzzState, EVMU256},
    vm::is_reverted_or_control_leak,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValueCaptureMiddleware {
    // Local stack to track nested calls: (target_address, selector)
    pub call_stack: Vec<(EVMAddress, [u8; 4])>,
}

impl ValueCaptureMiddleware {
    pub fn new() -> Self {
        Self {
            call_stack: Vec::new(),
        }
    }
}

impl<SC> Middleware<SC> for ValueCaptureMiddleware
where
    SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
{
    unsafe fn on_step(
        &mut self,
        interp: &mut Interpreter,
        _host: &mut FuzzHost<SC>,
        _state: &mut EVMFuzzState,
    ) {
        let opcode = interp.bytecode.opcode();
        // Check for CALL, CALLCODE, DELEGATECALL, STATICCALL opcodes
        if matches!(opcode, 0xf1 | 0xf2 | 0xf4 | 0xfa) {
            let stack_len = interp.stack.len();
            let (target_address_u256, arg_offset_u256, arg_len_u256) = match opcode {
                0xf1 | 0xf2 => {
                    // CALL, CALLCODE stack: [gas, addr, value, args_offset, args_len, ret_offset, ret_len]
                    if stack_len >= 5 {
                        (
                            interp.stack.peek(1).unwrap(),
                            interp.stack.peek(3).unwrap(),
                            interp.stack.peek(4).unwrap(),
                        )
                    } else {
                        return;
                    }
                }
                0xf4 | 0xfa => {
                    // DELEGATECALL, STATICCALL stack: [gas, addr, args_offset, args_len, ret_offset, ret_len]
                    if stack_len >= 4 {
                        (
                            interp.stack.peek(1).unwrap(),
                            interp.stack.peek(2).unwrap(),
                            interp.stack.peek(3).unwrap(),
                        )
                    } else {
                        return;
                    }
                }
                _ => return,
            };

            let target = convert_u256_to_h160(target_address_u256);
            let arg_offset = as_u64(arg_offset_u256) as usize;
            let arg_len = as_u64(arg_len_u256) as usize;

            let mut selector = [0u8; 4];
            if arg_len >= 4 {
                if interp.memory.len() >= arg_offset + 4 {
                    selector.copy_from_slice(&interp.memory.slice_len(arg_offset, 4));
                } else if interp.memory.len() > arg_offset {
                    let avail = interp.memory.len() - arg_offset;
                    selector[..avail].copy_from_slice(&interp.memory.slice_len(arg_offset, avail));
                }
            }
            self.call_stack.push((target, selector));
        }
    }

    unsafe fn on_return(
        &mut self,
        _interp: &mut Interpreter,
        host: &mut FuzzHost<SC>,
        _state: &mut EVMFuzzState,
        ret: &Bytes,
    ) {
        if let Some((target, selector)) = self.call_stack.pop() {
            let call_success = host.last_call_result
                .map(|r| !is_reverted_or_control_leak(&r))
                .unwrap_or(true);
            if call_success && ret.len() >= 32 {
                let key = format!("{:?}_{}_return", target, hex::encode(selector));
                let mut values_to_add = Vec::new();
                for chunk in ret.chunks_exact(32) {
                    let val = EVMU256::from_be_bytes::<32>(chunk.try_into().unwrap());
                    values_to_add.push(val);
                }

                if !values_to_add.is_empty() {
                    let observed = &mut host.evmstate.observed_values;
                    let list = observed.entry(key).or_default();
                    for val in values_to_add {
                        if !list.contains(&val) {
                            list.push(val);
                        }
                    }
                    if list.len() > 10 {
                        let drain_idx = list.len() - 10;
                        list.drain(0..drain_idx);
                    }
                }
            }
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::ValueCapture
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::vm::EVMState;
    use libafl::schedulers::QueueScheduler;

    #[test]
    fn test_value_capture_history_capping() {
        let mut middleware = ValueCaptureMiddleware::new();
        let target = EVMAddress::repeat_byte(0x12);
        let selector = [0xaa, 0xbb, 0xcc, 0xdd];
        
        // Push target and selector to simulate step entry
        middleware.call_stack.push((target, selector));

        // Create a FuzzHost with dummy QueueScheduler
        let scheduler = QueueScheduler::new();
        let mut host = FuzzHost::new(scheduler, "work_dir".to_string());
        host.evmstate = EVMState::new();

        // Construct 12 unique U256 values inside ret bytes (12 * 32 = 384 bytes)
        let mut ret_data = Vec::new();
        for i in 1..=12 {
            let val = EVMU256::from(i);
            ret_data.extend_from_slice(&val.to_be_bytes::<32>());
        }
        let ret_bytes = Bytes::from(ret_data);

        // Construct valid dummy interpreter and state
        let dummy_address = EVMAddress::repeat_byte(0x12);
        let dummy_bytecode = revm_interpreter::bytecode::Bytecode::new_raw(revm_primitives::Bytes(bytes::Bytes::new()));
        let interp_input = revm_interpreter::interpreter::InputsImpl {
            target_address: dummy_address,
            bytecode_address: Some(dummy_address),
            caller_address: dummy_address,
            input: revm_interpreter::CallInput::Bytes(revm_primitives::Bytes::new()),
            call_value: EVMU256::ZERO,
        };
        let mut dummy_interp = Interpreter::new(
            revm_interpreter::interpreter::SharedMemory::new(),
            revm_interpreter::interpreter::ExtBytecode::new(dummy_bytecode),
            interp_input,
            false,
            revm_primitives::hardfork::SpecId::PRAGUE,
            10000000000,
        );
        let mut dummy_state = EVMFuzzState::default();

        unsafe {
            middleware.on_return(&mut dummy_interp, &mut host, &mut dummy_state, &ret_bytes);
        }

        // Verify key
        let key = format!("{:?}_{}_return", target, hex::encode(selector));
        let list = host.evmstate.observed_values.get(&key).expect("observed values list should exist");

        // Should be capped at 10
        assert_eq!(list.len(), 10);
        // The first 2 elements (1 and 2) should be drained, leaving 3 through 12
        assert_eq!(list[0], EVMU256::from(3));
        assert_eq!(list[9], EVMU256::from(12));
    }

    #[test]
    fn test_value_capture_integration() {
        use std::{cell::RefCell, collections::HashMap, path::Path, rc::Rc};
        use libafl::prelude::StdScheduler;
        use revm_interpreter::bytecode::Bytecode;
        use crate::evm::{
            host::FuzzHost,
            input::{ConciseEVMInput, EVMInput, EVMInputTy},
            mutator::AccessPattern,
            types::{generate_random_address, EVMFuzzState, EVMU256},
            vm::{EVMExecutor, EVMState},
        };
        use crate::generic_vm::vm_executor::GenericVM;
        use crate::state_input::StagedVMState;
        use crate::state::FuzzState;

        // 1. With Value Capture Enabled
        {
            let mut state: EVMFuzzState = FuzzState::new(0);
            let path = Path::new("work_dir");
            if !path.exists() {
                std::fs::create_dir(path).unwrap();
            }

            let mut host = FuzzHost::new(StdScheduler::new(), "work_dir".to_string());
            host.evmstate = EVMState::new();
            
            // Add value capture middleware
            let value_capture_mw = Rc::new(RefCell::new(ValueCaptureMiddleware::new()));
            host.add_middlewares(value_capture_mw);

            let mut evm_executor: EVMExecutor<EVMState, ConciseEVMInput, StdScheduler<EVMFuzzState>> = EVMExecutor::new(
                host,
                generate_random_address(&mut state),
            );

            // Mock bytecode of ValueCaptureMock compiled with solc
            let mock_bytecode = hex::decode("6080604052348015600e575f80fd5b506101b18061001c5f395ff3fe608060405234801561000f575f80fd5b5060043610610029575f3560e01c8063b29e522c1461002d575b5f80fd5b610047600480360381019061004291906100ba565b61005e565b6040516100559291906100f4565b60405180910390f35b5f8060648361006d9190610148565b60c88461007a9190610148565b91509150915091565b5f80fd5b5f819050919050565b61009981610087565b81146100a3575f80fd5b50565b5f813590506100b481610090565b92915050565b5f602082840312156100cf576100ce610083565b5b5f6100dc848285016100a6565b91505092915050565b6100ee81610087565b82525050565b5f6040820190506101075f8301856100e5565b61011460208301846100e5565b9392505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f61015282610087565b915061015d83610087565b92508282019050808211156101755761017461011b565b5b9291505056fea2646970667358221220c6f4b72bf77af4e26ee6f4cca8ed0051e7ab649120af9e524768a089b3c9cfc464736f6c634300081a0033").unwrap();

            let deployment_loc = evm_executor
                .deploy(
                    Bytecode::new_raw(revm_primitives::Bytes::from(mock_bytecode)),
                    None,
                    generate_random_address(&mut state),
                    &mut FuzzState::new(0),
                )
                .unwrap();

            // Function selector: getValues(uint256) -> b29e522c
            let function_hash = hex::decode("b29e522c").unwrap();

            // Invoke getValues(5) -> should return 5+100 = 105 and 5+200 = 205
            let input = EVMInput {
                caller: generate_random_address(&mut state),
                contract: deployment_loc,
                data: None,
                sstate: StagedVMState::new_uninitialized(),
                sstate_idx: 0,
                txn_value: Some(EVMU256::ZERO),
                step: false,
                env: Default::default(),
                access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                liquidation_percent: 0,
                direct_data: Bytes::from(
                    [
                        function_hash.clone(),
                        hex::decode("0000000000000000000000000000000000000000000000000000000000000005").unwrap(),
                    ]
                    .concat(),
                ),
                input_type: EVMInputTy::ABI,
                randomness: vec![],
                repeat: 1,
                swap_data: HashMap::new(),
                nested_actions: Vec::new(),
            };

            let execution_result = evm_executor.execute(&input, &mut state);
            assert!(!execution_result.reverted);

            // Verify observed_values has captured [105, 205] under the key:
            // "deployment_loc_b29e522c_return"
            let key = format!("{:?}_b29e522c_return", deployment_loc);
            let observed = &execution_result.new_state.state.observed_values;
            let list = observed.get(&key).expect("observed values should be captured");
            assert_eq!(list.len(), 2);
            assert_eq!(list[0], EVMU256::from(105));
            assert_eq!(list[1], EVMU256::from(205));
        }

        // 2. With Value Capture Disabled (standard baseline execution)
        {
            let mut state: EVMFuzzState = FuzzState::new(0);
            let path = Path::new("work_dir");
            if !path.exists() {
                std::fs::create_dir(path).unwrap();
            }

            let mut host = FuzzHost::new(StdScheduler::new(), "work_dir".to_string());
            host.evmstate = EVMState::new();
            // Do NOT add ValueCaptureMiddleware

            let mut evm_executor: EVMExecutor<EVMState, ConciseEVMInput, StdScheduler<EVMFuzzState>> = EVMExecutor::new(
                host,
                generate_random_address(&mut state),
            );

            let mock_bytecode = hex::decode("6080604052348015600e575f80fd5b506101b18061001c5f395ff3fe608060405234801561000f575f80fd5b5060043610610029575f3560e01c8063b29e522c1461002d575b5f80fd5b610047600480360381019061004291906100ba565b61005e565b6040516100559291906100f4565b60405180910390f35b5f8060648361006d9190610148565b60c88461007a9190610148565b91509150915091565b5f80fd5b5f819050919050565b61009981610087565b81146100a3575f80fd5b50565b5f813590506100b481610090565b92915050565b5f602082840312156100cf576100ce610083565b5b5f6100dc848285016100a6565b91505092915050565b6100ee81610087565b82525050565b5f6040820190506101075f8301856100e5565b61011460208301846100e5565b9392505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f61015282610087565b915061015d83610087565b92508282019050808211156101755761017461011b565b5b9291505056fea2646970667358221220c6f4b72bf77af4e26ee6f4cca8ed0051e7ab649120af9e524768a089b3c9cfc464736f6c634300081a0033").unwrap();

            let deployment_loc = evm_executor
                .deploy(
                    Bytecode::new_raw(revm_primitives::Bytes::from(mock_bytecode)),
                    None,
                    generate_random_address(&mut state),
                    &mut FuzzState::new(0),
                )
                .unwrap();

            let function_hash = hex::decode("b29e522c").unwrap();

            let input = EVMInput {
                caller: generate_random_address(&mut state),
                contract: deployment_loc,
                data: None,
                sstate: StagedVMState::new_uninitialized(),
                sstate_idx: 0,
                txn_value: Some(EVMU256::ZERO),
                step: false,
                env: Default::default(),
                access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                liquidation_percent: 0,
                direct_data: Bytes::from(
                    [
                        function_hash.clone(),
                        hex::decode("0000000000000000000000000000000000000000000000000000000000000005").unwrap(),
                    ]
                    .concat(),
                ),
                input_type: EVMInputTy::ABI,
                randomness: vec![],
                repeat: 1,
                swap_data: HashMap::new(),
                nested_actions: Vec::new(),
            };

            let execution_result = evm_executor.execute(&input, &mut state);
            assert!(!execution_result.reverted);

            // Verify observed_values is empty/does not contain captured values
            let observed = &execution_result.new_state.state.observed_values;
            assert!(observed.is_empty());
        }
    }
}

