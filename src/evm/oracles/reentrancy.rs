use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
};

use bytes::Bytes;
use itertools::Itertools;
use libafl::prelude::HasMetadata;
use revm_interpreter::bytecode::Bytecode;

use super::{OracleTargetMetadata, REENTRANCY_BUG_IDX};
use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        leak_class::LeakClass,
        oracle::EVMBugResult,
        planner::{PromotionCandidate, PromotionCandidates, TaintProvenanceTag},
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    generic_vm::vm_state::VMStateT,
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

pub struct ReentrancyOracle {
    pub address_to_name: HashMap<EVMAddress, String>,
}

impl ReentrancyOracle {
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
    > for ReentrancyOracle
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
        let reetrancy_metadata = &ctx.post_state
            .as_any()
            .downcast_ref::<EVMState>()
            .unwrap()
            .reentrancy_metadata;
        if reetrancy_metadata.found.is_empty() {
            return vec![];
        }
        // Push flagged addresses into OracleTargetMetadata for mutator feedback
        if ctx.fuzz_state.metadata_map().get::<OracleTargetMetadata>().is_none() {
            ctx.fuzz_state.metadata_map_mut().insert(OracleTargetMetadata::default());
        }
        let meta = ctx.fuzz_state.metadata_map_mut().get_mut::<OracleTargetMetadata>().unwrap();
        for (addr, _slot) in &reetrancy_metadata.found {
            let key = addr.0 .0;
            let entry = meta.targets.entry(key).or_insert_with(|| ("Reentrancy".to_string(), REENTRANCY_BUG_IDX, 0));
            entry.2 += 1;
        }

        // Feature 034: emit ControlFlow PromotionCandidate so the planner can lock the
        // re-entered contract into the Prime slot. best_inflow = distinct reentrant
        // storage touches (more touches = broader/deeper reentrancy = higher objective).
        // Mirrors snapshot_delta.rs's Ownership pattern exactly.
        let first_contract = reetrancy_metadata.found.iter().next().map(|(addr, _)| *addr).unwrap_or_default();
        let selector: [u8; 4] = ctx.input.data.as_ref().map(|d| d.function).unwrap_or_default();
        let candidate = PromotionCandidate {
            contract: first_contract,
            selector,
            best_inflow: reetrancy_metadata.found.len() as u128,
            kind: LeakClass::ControlFlow,
            taint_provenance: TaintProvenanceTag::default(),
            phase: None,
            set: true,
        };
        let mut candidates = ctx
            .fuzz_state
            .metadata_map()
            .get::<PromotionCandidates>()
            .cloned()
            .or_else(|| {
                ctx.fuzz_state
                    .metadata_map()
                    .get::<PromotionCandidate>()
                    .map(PromotionCandidates::from_singleton)
            })
            .unwrap_or_default();
        if candidates.record(candidate.clone()) {
            ctx.fuzz_state.metadata_map_mut().insert(candidates);
            ctx.fuzz_state.metadata_map_mut().insert(candidate);
        }

        reetrancy_metadata
            .found
            .iter()
            .map(|(addr, slot)| {
                let mut hasher = DefaultHasher::new();
                addr.hash(&mut hasher);
                let real_bug_idx = (hasher.finish() << 8) + REENTRANCY_BUG_IDX;

                let name = self.address_to_name.get(addr).unwrap_or(&format!("{:?}", addr)).clone();
                EVMBugResult::new(
                    "Reentrancy".to_string(),
                    real_bug_idx,
                    format!("Reentrancy on {:?} at slot {:?}", name, slot),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                    None,
                    Some(name.clone()),
                )
                .push_to_output();
                real_bug_idx
            })
            .collect_vec()
    }
}
