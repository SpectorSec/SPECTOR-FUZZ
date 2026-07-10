use std::str::FromStr;

use bytes::Bytes;
use libafl::prelude::HasMetadata;
use revm_interpreter::bytecode::Bytecode;

use crate::{
    evm::{
        host::STATE_CHANGE,
        input::{ConciseEVMInput, EVMInput},
        leak_class::LeakClass,
        oracle::EVMBugResult,
        oracles::STATE_COMP_BUG_IDX,
        planner::{PromotionCandidate, TaintProvenanceTag},
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::vm_state::VMStateT,
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

pub enum StateCompMatching {
    Exact,
    DesiredContain,
    StateContain,
}

impl FromStr for StateCompMatching {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Exact" => Ok(StateCompMatching::Exact),
            "DesiredContain" => Ok(StateCompMatching::DesiredContain),
            "StateContain" => Ok(StateCompMatching::StateContain),
            _ => Err(()),
        }
    }
}

pub struct StateCompOracle {
    pub desired_state: EVMState,
    pub matching_style: StateCompMatching,
}

impl StateCompOracle {
    pub fn new(desired_state: EVMState, matching_style: String) -> Self {
        Self {
            desired_state,
            matching_style: StateCompMatching::from_str(matching_style.as_str())
                .expect("invalid state comp matching style"),
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
    > for StateCompOracle
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
        let comp = |state1: &EVMState, state2: &EVMState| -> bool {
            match self.matching_style {
                StateCompMatching::Exact => state1.eq(state2),
                StateCompMatching::DesiredContain => state1.is_subset_of(state2),
                StateCompMatching::StateContain => state2.is_subset_of(state1),
            }
        };

        unsafe {
            if STATE_CHANGE && comp(&ctx.post_state, &self.desired_state) {
                // Items 3+4 (audit remediation): emit Invariant PromotionCandidate so the
                // planner locks the violating call into the campaign. Value takes precedence.
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
                EVMBugResult::new_simple(
                    "state_comp".to_string(),
                    STATE_COMP_BUG_IDX,
                    "Found equivalent state".to_string(),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                )
                .push_to_output();
                vec![STATE_COMP_BUG_IDX]
            } else {
                vec![]
            }
        }
    }
}
