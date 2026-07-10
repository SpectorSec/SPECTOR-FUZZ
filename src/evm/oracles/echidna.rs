use std::collections::HashMap;

use bytes::Bytes;
use itertools::Itertools;
use libafl::prelude::HasMetadata;
use revm_interpreter::bytecode::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        leak_class::LeakClass,
        oracle::EVMBugResult,
        oracles::ECHIDNA_BUG_IDX,
        planner::{PromotionCandidate, PromotionCandidates, TaintProvenanceTag},
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

pub struct EchidnaOracle {
    pub batch_call_txs: Vec<(EVMAddress, Bytes)>,
    pub names: HashMap<Vec<u8>, String>,
}

impl EchidnaOracle {
    pub fn new(echidna_funcs: Vec<(EVMAddress, Vec<u8>)>, names: HashMap<Vec<u8>, String>) -> Self {
        Self {
            batch_call_txs: echidna_funcs
                .iter()
                .map(|(address, echidna_func)| {
                    let echidna_txn = Bytes::from(echidna_func.clone());
                    (*address, echidna_txn)
                })
                .collect_vec(),
            names,
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
    > for EchidnaOracle
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
        let results: Vec<bool> = ctx
            .call_post_batch(&self.batch_call_txs)
            .iter()
            .map(|out| out.iter().map(|x| *x == 0).all(|x| x))
            .collect();

        // Items 3+4 (audit remediation): emit Invariant PromotionCandidate on first
        // violation so the planner locks the violating call into the campaign.
        // No dedup gate here — echidna.rs re-evaluates every execution, so the
        // high-water check is the dedup.
        let any_violated = results.iter().any(|&v| v);
        if any_violated {
            let selector: [u8; 4] = ctx.input.data.as_ref().map(|d| d.function).unwrap_or_default();
            let candidate = PromotionCandidate {
                contract: ctx.input.contract,
                selector,
                best_inflow: 0,
                kind: LeakClass::Invariant,
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
        }

        results
            .into_iter()
            .enumerate()
            .map(|(idx, violated)| {
                if violated {
                    let name = self.names.get(&self.batch_call_txs[idx].1.to_vec()).unwrap();
                    let bug_idx = (idx << 8) as u64 + ECHIDNA_BUG_IDX;
                    EVMBugResult::new(
                        "Echidna".to_string(),
                        bug_idx,
                        format!("Invariant {:?} violated", name),
                        ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                        None,
                        Some(name.clone()),
                    )
                    .push_to_output();
                    bug_idx
                } else {
                    0
                }
            })
            .filter(|x| *x != 0)
            .collect_vec()
    }
}
