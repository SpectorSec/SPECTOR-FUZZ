use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    str::FromStr,
};

use bytes::Bytes;
use itertools::Itertools;
use libafl::state::HasMetadata;
use revm_interpreter::bytecode::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        leak_class::LeakClass,
        middlewares::cheatcode::CHEATCODE_ADDRESS,
        oracle::EVMBugResult,
        oracles::INVARIANT_BUG_IDX,
        planner::{PromotionCandidate, TaintProvenanceTag},
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{BugMetadata, Oracle, OracleCtx},
    oracle_should_skip,
    state::HasExecutionResult,
};

pub struct InvariantOracle {
    pub batch_call_txs: Vec<(EVMAddress, EVMAddress, Bytes)>,
    pub names: HashMap<Vec<u8>, (String, u64)>,
    pub failed_slot: EVMU256,
}

impl InvariantOracle {
    pub fn new(invariant_funcs: Vec<(EVMAddress, Vec<u8>)>, names: HashMap<Vec<u8>, String>) -> Self {
        Self {
            batch_call_txs: invariant_funcs
                .iter()
                .map(|(address, invariant_func)| {
                    let invariant_tx = Bytes::from(invariant_func.clone());
                    (
                        EVMAddress::from_str("0x0000000000000000000000000000000000007777").unwrap(),
                        *address,
                        invariant_tx,
                    )
                })
                .collect_vec(),
            names: names
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        (v.clone(), {
                            let mut hasher = DefaultHasher::new();
                            k.hash(&mut hasher);
                            hasher.finish()
                        }),
                    )
                })
                .collect::<HashMap<_, _>>(),
            failed_slot: EVMU256::from_str_radix(
                "6661696c65640000000000000000000000000000000000000000000000000000",
                16,
            )
            .unwrap(),
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
    > for InvariantOracle
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
        let mut res = vec![];
        for (nth, tx) in self.batch_call_txs.iter().enumerate() {
            let bug_idx = (nth << 8) as u64 + INVARIANT_BUG_IDX;
            let (call_res, new_state) = ctx.call_post_batch_dyn(&[tx.clone()]);
            let (msg, succ) = &call_res[0];
            let violated = *succ && {
                // assertTrue in Foundry writes to slot
                // 0x6661696c65640000000000000000000000000000000000000000000000000000
                // if the invariant is violated in cheatcode contract.
                new_state
                    .get(&CHEATCODE_ADDRESS)
                    .map(|data| {
                        data.get(&self.failed_slot)
                            .map(|v| v == &EVMU256::from(1))
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
            };
            if !violated {
                continue;
            }

            // Items 3+4 (audit remediation): emit Invariant PromotionCandidate so the
            // planner can lock the violating call into the campaign. Unconditional —
            // runs even when oracle_should_skip would suppress the duplicate report,
            // so the optimization objective keeps refining every execution (same model
            // as Value's feedbacks.rs ledger path). Value takes precedence over structural.
            let already_set = ctx
                .fuzz_state
                .metadata_map()
                .get::<PromotionCandidate>()
                .map(|c| c.set)
                .unwrap_or(false);
            if !already_set {
                let selector: [u8; 4] = ctx
                    .input
                    .data
                    .as_ref()
                    .map(|d| d.function)
                    .unwrap_or_default();
                ctx.fuzz_state.metadata_map_mut().insert(PromotionCandidate {
                    contract: ctx.input.contract,
                    selector,
                    best_inflow: 0,
                    kind: LeakClass::Invariant,
                    taint_provenance: TaintProvenanceTag::default(),
                    phase: None,
                    set: true,
                });
            }

            let (name, _) = self.names.get(&tx.2.to_vec()).unwrap();
            // Dedup gate applies only to the human-facing report, not to the promotion above.
            if !oracle_should_skip!(ctx, bug_idx) {
                EVMBugResult::new(
                    "Invariant".to_string(),
                    bug_idx,
                    format!(
                        "Invariant {:?} violated, {:?}",
                        name,
                        String::from_utf8(msg.iter().filter(|&c| *c > 0).cloned().collect::<Vec<u8>>())
                    ),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                    None,
                    Some(name.clone()),
                )
                .push_to_output();
            }
            res.push(bug_idx);
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, path::Path, rc::Rc, str::FromStr};

    use bytes::Bytes;
    use libafl::prelude::StdScheduler;
    use revm_interpreter::{bytecode::Bytecode, InstructionResult};

    use crate::{
        evm::{
            host::FuzzHost,
            middlewares::cheatcode::{Cheatcode, CHEATCODE_ADDRESS},
            types::{EVMAddress, generate_random_address, EVMFuzzState, EVMU256},
            vm::{EVMExecutor, EVMState},
        },
        generic_vm::vm_executor::GenericVM,
        logger,
        state::FuzzState,
    };

    fn load_bytecode(path: &str) -> Bytecode {
        let hex_code = std::fs::read_to_string(path).expect("bytecode not found").trim().to_string();
        let bytes = hex::decode(&hex_code).unwrap();
        Bytecode::new_raw(revm_primitives::Bytes::from(bytes))
    }

    #[test]
    fn test_invariant_violation_detected() {
        logger::init_test();

        let counter_addr = EVMAddress::from_str("0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEF1234").unwrap();
        let counter_code = load_bytecode("tests/presets/invariant/Counter.bytecode");

        let path = Path::new("work_dir");
        if !path.exists() {
            std::fs::create_dir(path).unwrap();
        }
        let mut deploy_state: EVMFuzzState = FuzzState::new(0);

        let mut fuzz_host = FuzzHost::new(StdScheduler::new(), "work_dir".to_string());
        fuzz_host.add_middlewares(Rc::new(RefCell::new(Cheatcode::new(""))));
        fuzz_host.set_code(
            CHEATCODE_ADDRESS,
            Bytecode::new_raw(revm_primitives::Bytes::from(vec![0xfd, 0x00])),
            &mut deploy_state,
        );

        let mut evm_executor: EVMExecutor<EVMState, crate::evm::input::ConciseEVMInput, StdScheduler<EVMFuzzState>> =
            EVMExecutor::new(fuzz_host, generate_random_address(&mut deploy_state));
        evm_executor.deploy(counter_code, None, counter_addr, &mut deploy_state).unwrap();

        let caller = generate_random_address(&mut deploy_state);

        // Invariant holds before drain(): invariant_value_positive() should return OK
        let mut vm_state: EVMState = evm_executor.host.evmstate.clone();
        let (_, before) = evm_executor.fast_call_(
            counter_addr,
            Bytes::from(hex::decode("fd6fdaab").unwrap()), // invariant_value_positive()
            &mut vm_state,
            &mut deploy_state,
            EVMU256::ZERO,
            caller,
        );
        assert!(before.is_ok(), "invariant should hold initially, got {before:?}");

        // Call drain() to zero out value
        let mut vm_state2: EVMState = evm_executor.host.evmstate.clone();
        let (_, drain_res) = evm_executor.fast_call_(
            counter_addr,
            Bytes::from(hex::decode("9890220b").unwrap()), // drain()
            &mut vm_state2,
            &mut deploy_state,
            EVMU256::ZERO,
            caller,
        );
        assert!(drain_res.is_ok(), "drain() should succeed");

        // Invariant violated: invariant_value_positive() should revert
        let (_, after) = evm_executor.fast_call_(
            counter_addr,
            Bytes::from(hex::decode("fd6fdaab").unwrap()), // invariant_value_positive()
            &mut vm_state2,
            &mut deploy_state,
            EVMU256::ZERO,
            caller,
        );
        assert_eq!(after, InstructionResult::Revert, "invariant_value_positive() must revert after drain()");
    }
}
