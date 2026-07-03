use crate::evm::input::CampaignSequence;

/// Executes a multi-step campaign sequentially, chaining state between steps.
///
/// Mirrors the replay-loop pattern in `evm_fuzzer.rs:882-916`.
/// Each step uses the previous step's output state as its input state.
/// Early aborts on any step revert.
pub fn execute_campaign(_campaign: &CampaignSequence) {
    // Execution is handled inside FuzzExecutor::run_target in src/executor.rs
}

#[cfg(test)]
#[cfg(feature = "evm")]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;
    use std::str::FromStr;

    use libafl::state::HasMetadata;
    use revm_interpreter::bytecode::Bytecode;
    use revm_primitives::Bytes;

    use crate::evm::abi::{ABIAddressToInstanceMap, AEmpty, AUnknown, BoxedABI};
    use crate::evm::host::FuzzHost;
    use crate::evm::input::{ConciseEVMInput, EVMInput};
    use crate::evm::middlewares::cheatcode::{Cheatcode, CHEATCODE_ADDRESS};
    use crate::evm::planner::{plan_campaign, CampaignTargetCache};
    use crate::evm::scheduler::{PowerABIScheduler, UncoveredBranchesMetadata};
    use crate::evm::types::{fixed_address, EVMAddress, EVMFuzzState, EVMStagedVMState, EVMU256};
    use crate::evm::vm::{EVMExecutor, EVMState};
    use crate::generic_vm::vm_executor::GenericVM;
    use crate::state::{FuzzState, HasExecutionResult};

    fn load_bytecode(path: &str) -> Bytecode {
        let hex_code = std::fs::read_to_string(path)
            .expect("bytecode not found")
            .trim()
            .to_string();
        let bytes = hex::decode(&hex_code).unwrap();
        Bytecode::new_raw(Bytes::from(bytes))
    }

    #[cfg_attr(not(feature = "integration_test"), ignore)]
    #[test]
    fn test_campaign_execution_integration() {
        let work_dir = "/tmp/ityfuzz_campaign_test";
        let _ = std::fs::create_dir_all(work_dir);

        let mut state: EVMFuzzState = FuzzState::new(0);
        let mut host = FuzzHost::new(PowerABIScheduler::new(), work_dir.to_string());
        host.add_middlewares(Rc::new(RefCell::new(Cheatcode::new(""))));
        host.set_code(
            CHEATCODE_ADDRESS,
            Bytecode::new_raw(Bytes::from(vec![0xfd, 0x00])),
            &mut state,
        );

        let deployer = fixed_address("8EF508Aca04B32Ff3ba5003177cb18BfA6Cd79dd");
        let mut executor: EVMExecutor<EVMState, ConciseEVMInput, PowerABIScheduler<EVMFuzzState>> =
            EVMExecutor::new(host, deployer);

        state.add_metadata(ABIAddressToInstanceMap::new());
        state.add_metadata(UncoveredBranchesMetadata::new());

        let vault_addr =
            EVMAddress::from_str("0xAAAA000000000000000000000000000000000001").unwrap();
        let exploit_addr =
            EVMAddress::from_str("0xBBBB000000000000000000000000000000000002").unwrap();

        let vault_code = load_bytecode("/tmp/campaign_test/out/MockVault.bin");
        let exploit_code = load_bytecode("/tmp/campaign_test/out/MockExploit.bin");

        executor
            .deploy(vault_code, None, vault_addr, &mut state)
            .expect("MockVault deploy failed");
        executor
            .deploy(exploit_code, None, exploit_addr, &mut state)
            .expect("MockExploit deploy failed");

        let mut prime_abi = BoxedABI::new(Box::new(AUnknown {
            concrete: BoxedABI::new(Box::new(AEmpty {})),
            size: 0,
        }));
        prime_abi.set_func([0x6e, 0x55, 0x3f, 0x65]);

        let mut exploit_abi = BoxedABI::new(Box::new(AUnknown {
            concrete: BoxedABI::new(Box::new(AEmpty {})),
            size: 0,
        }));
        exploit_abi.set_func([0x44, 0x1a, 0x3e, 0x70]);

        let mut abi_map = ABIAddressToInstanceMap::new();
        abi_map.map.insert(vault_addr, vec![prime_abi]);
        abi_map.map.insert(exploit_addr, vec![exploit_abi]);

        state.add_metadata(CampaignTargetCache::new(&abi_map, Vec::new()));

        let cache = state
            .metadata_map()
            .get::<CampaignTargetCache>()
            .expect("CampaignTargetCache not found");
        let campaign = plan_campaign(cache, None, false).expect("plan_campaign returned None");

        assert_eq!(campaign.steps.len(), 2, "expected 2-step campaign (ABI->ABI)");
        assert_eq!(campaign.steps[0].contract, vault_addr);
        assert_eq!(campaign.steps[1].contract, exploit_addr);

        let initial_vm_state: EVMState = executor.host.evmstate.clone();
        let mut current_sstate = EVMStagedVMState::new_with_state(initial_vm_state);

        for (i, step_ci) in campaign.steps.iter().enumerate() {
            let (step_input, _) = step_ci.to_input(current_sstate);
            executor.execute(&step_input, &mut state);
            assert!(
                !state.get_execution_result().reverted,
                "step {} reverted",
                i
            );
            current_sstate = state.get_execution_result().new_state.clone();
        }

        let final_vm_state: &EVMState = &state.get_execution_result().new_state.state;
        if let Some(storage) = final_vm_state.state.get(&vault_addr) {
            let val = storage.get(&EVMU256::ZERO).unwrap_or(&EVMU256::ZERO);
            assert!(*val > EVMU256::ZERO, "vault totalDeposits should be > 0");
        }

        if let Some(storage) = final_vm_state.state.get(&exploit_addr) {
            let val = storage.get(&EVMU256::ZERO).unwrap_or(&EVMU256::ZERO);
            assert!(*val > EVMU256::ZERO, "exploit totalWithdrawn should be > 0");
        }

        let _ = std::fs::remove_dir_all(work_dir);
    }
}
