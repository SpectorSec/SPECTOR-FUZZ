//! Feature 020-B — SnapshotDelta oracle: the detection home for
//! `LeakClass::Ownership`.
//!
//! Ownership (primitive 06) is authority *relocation*, distinct from Permission
//! (primitive 04, the *act* of an unauthorized call). Its verdict is a boundary
//! comparison — did an authority-bearing storage slot change across this tx —
//! so by the Information Availability Law it needs NO per-opcode witness and is
//! a post-hoc oracle, not an inline middleware (`LeakClass::Ownership.
//! middleware() == None`).
//!
//! Watch set (v1, bounded): the universal EIP-1967 proxy slots (implementation
//! / admin / beacon), plus any per-contract authority slots explicitly
//! registered via `watch_slot` (topology intelligence / owner()-backing slots
//! feed this later). Fire condition: a watched slot's value differs pre-tx vs
//! post-tx. A no-op re-write of the same value (pre == post) does NOT fire —
//! this mirrors the 019 materiality principle: an authority write that
//! relocates nothing is not a leak.

use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    hash::{Hash, Hasher},
};

use bytes::Bytes;
use itertools::Itertools;
use libafl::prelude::HasMetadata;
use revm_interpreter::bytecode::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        leak_class::LeakClass,
        oracle::EVMBugResult,
        oracles::OWNERSHIP_BUG_IDX,
        planner::{PromotionCandidate, PromotionCandidates, TaintProvenanceTag},
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

/// A watched authority slot whose value moved across the tx.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relocation {
    pub contract: EVMAddress,
    pub slot: EVMU256,
    pub pre: EVMU256,
    pub post: EVMU256,
}

/// Post-hoc governance-state objective gate. Watches authority-bearing storage
/// slots and emits an objective when one is relocated (value change) across a
/// non-reverting execution.
pub struct SnapshotDeltaOracle {
    /// Contracts under test (for naming + scoping — universal slots are only
    /// checked on these, so a proxy write inside an unrelated dependency
    /// doesn't spuriously fire).
    pub address_to_name: HashMap<EVMAddress, String>,
    /// The universal EIP-1967 proxy slots, checked on every monitored contract.
    universal_slots: Vec<EVMU256>,
    /// Extra per-contract authority slots (owner()/admin() backing slots,
    /// topology-discovered).
    extra_slots: HashMap<EVMAddress, HashSet<EVMU256>>,
}

impl SnapshotDeltaOracle {
    pub fn new(address_to_name: HashMap<EVMAddress, String>) -> Self {
        // EIP-1967: keccak256("eip1967.proxy.{implementation,admin,beacon}") - 1.
        let hex = |s: &str| EVMU256::from_str_radix(s, 16).expect("valid EIP-1967 slot literal");
        let universal_slots = vec![
            hex("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"), // implementation
            hex("b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"), // admin
            hex("a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"), // beacon
        ];
        Self {
            address_to_name,
            universal_slots,
            extra_slots: HashMap::new(),
        }
    }

    /// Register an additional authority-bearing slot for a contract (e.g. an
    /// `owner()`-backing slot discovered by the topology pass). Idempotent.
    #[allow(dead_code)]
    pub fn watch_slot(&mut self, contract: EVMAddress, slot: EVMU256) {
        self.extra_slots.entry(contract).or_default().insert(slot);
    }

    /// Read a slot from an `EVMState` storage overlay, treating an absent slot
    /// as zero. Absent = "not written in this state" — comparing pre vs
    /// post overlays isolates exactly this-tx writes.
    fn slot_value(
        state_map: &HashMap<EVMAddress, HashMap<EVMU256, EVMU256>>,
        contract: &EVMAddress,
        slot: &EVMU256,
    ) -> EVMU256 {
        state_map
            .get(contract)
            .and_then(|slots| slots.get(slot))
            .copied()
            .unwrap_or(EVMU256::ZERO)
    }

    /// PURE detection core (unit-tested without an executor): diff every
    /// watched slot of every monitored contract between the pre-tx and
    /// post-tx overlays; report those that moved.
    pub fn detect_relocations(&self, pre: &EVMState, post: &EVMState) -> Vec<Relocation> {
        let mut out = Vec::new();
        for contract in self.address_to_name.keys() {
            let watched = self
                .universal_slots
                .iter()
                .copied()
                .chain(self.extra_slots.get(contract).into_iter().flatten().copied());
            // Dedup in case an extra slot coincides with a universal one.
            for slot in watched.unique() {
                let pre_v = Self::slot_value(&pre.state, contract, &slot);
                let post_v = Self::slot_value(&post.state, contract, &slot);
                if pre_v != post_v {
                    out.push(Relocation {
                        contract: *contract,
                        slot,
                        pre: pre_v,
                        post: post_v,
                    });
                }
            }
        }
        out
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
    > for SnapshotDeltaOracle
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
        // A revert leaves state untouched — no relocation. (Belt-and-suspenders:
        // detect_relocations would already report nothing, since a reverted tx
        // contributes no storage overlay delta.)
        if ctx.fuzz_state.get_execution_result().reverted {
            return vec![];
        }

        let relocations = self.detect_relocations(ctx.pre_state, &ctx.post_state);
        if relocations.is_empty() {
            return vec![];
        }

        // Items 3+4 (audit remediation): emit Ownership PromotionCandidate so the
        // planner can lock the violating call into the Prime slot
        // (structural_pin). Store it in the Ownership slot rather than racing
        // Permission/Invariant/Value for one singleton.
        let first = &relocations[0];
        let selector: [u8; 4] = ctx.input.data.as_ref().map(|d| d.function).unwrap_or_default();
        let candidate = PromotionCandidate {
            contract: first.contract,
            selector,
            best_inflow: relocations.len() as u128,
            kind: LeakClass::Ownership,
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

        relocations
            .iter()
            .map(|r| {
                let mut hasher = DefaultHasher::new();
                r.contract.hash(&mut hasher);
                r.slot.hash(&mut hasher);
                let bug_idx = (hasher.finish() << 8) + OWNERSHIP_BUG_IDX;

                let name = self
                    .address_to_name
                    .get(&r.contract)
                    .cloned()
                    .unwrap_or_else(|| format!("{:?}", r.contract));

                EVMBugResult::new(
                    "Ownership/Authority Relocation".to_string(),
                    bug_idx,
                    format!(
                        "{} authority slot {:#x} relocated {:#x} -> {:#x} in a single tx \
                         (ownership leak)",
                        name, r.slot, r.pre, r.post,
                    ),
                    ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                    None,
                    Some(name.clone()),
                )
                .push_to_output();
                bug_idx
            })
            .collect_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> EVMAddress {
        EVMAddress::repeat_byte(b)
    }

    const IMPL_SLOT: &str = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

    fn state_with(contract: EVMAddress, slot: EVMU256, value: EVMU256) -> EVMState {
        let mut s = EVMState::default();
        s.state.entry(contract).or_default().insert(slot, value);
        s
    }

    #[test]
    fn upgrade_slot_change_fires() {
        // EIP-1967 implementation slot moves 0 -> 0xBEEF: a relocation.
        let c = addr(0x11);
        let mut names = HashMap::new();
        names.insert(c, "Proxy".to_string());
        let oracle = SnapshotDeltaOracle::new(names);

        let slot = EVMU256::from_str_radix(IMPL_SLOT, 16).unwrap();
        let pre = EVMState::default();
        let post = state_with(c, slot, EVMU256::from(0xBEEFu64));

        let hits = oracle.detect_relocations(&pre, &post);
        assert_eq!(hits.len(), 1, "impl-slot change must relocate");
        assert_eq!(hits[0].contract, c);
        assert_eq!(hits[0].slot, slot);
    }

    #[test]
    fn owner_noop_no_fire() {
        // Re-writing the SAME value into a watched slot is not a relocation (pre ==
        // post).
        let c = addr(0x22);
        let mut names = HashMap::new();
        names.insert(c, "Vault".to_string());
        let mut oracle = SnapshotDeltaOracle::new(names);
        let owner_slot = EVMU256::from(7u64);
        oracle.watch_slot(c, owner_slot);

        let val = EVMU256::from(0xAAAAu64);
        let pre = state_with(c, owner_slot, val);
        let post = state_with(c, owner_slot, val);

        assert!(
            oracle.detect_relocations(&pre, &post).is_empty(),
            "a no-op re-write of the same authority value is not a leak"
        );
    }

    #[test]
    fn extra_owner_slot_change_fires() {
        // An explicitly-watched owner slot (topology-discovered) moving fires.
        let c = addr(0x33);
        let mut names = HashMap::new();
        names.insert(c, "Governed".to_string());
        let mut oracle = SnapshotDeltaOracle::new(names);
        let owner_slot = EVMU256::from(3u64);
        oracle.watch_slot(c, owner_slot);

        let pre = state_with(c, owner_slot, EVMU256::from(1u64));
        let post = state_with(c, owner_slot, EVMU256::from(2u64));

        let hits = oracle.detect_relocations(&pre, &post);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].pre, EVMU256::from(1u64));
        assert_eq!(hits[0].post, EVMU256::from(2u64));
    }

    #[test]
    fn unwatched_slot_change_does_not_fire() {
        // A change to a non-authority slot (not universal, not registered) is ignored.
        let c = addr(0x44);
        let mut names = HashMap::new();
        names.insert(c, "Token".to_string());
        let oracle = SnapshotDeltaOracle::new(names);

        let random_slot = EVMU256::from(42u64);
        let pre = state_with(c, random_slot, EVMU256::from(100u64));
        let post = state_with(c, random_slot, EVMU256::from(999u64));

        assert!(
            oracle.detect_relocations(&pre, &post).is_empty(),
            "non-authority slots are out of the watch set"
        );
    }

    #[test]
    fn change_on_unmonitored_contract_ignored() {
        // Universal slots are only checked on contracts we're monitoring; a proxy write
        // inside an unrelated dependency does not fire.
        let monitored = addr(0x55);
        let stranger = addr(0x66);
        let mut names = HashMap::new();
        names.insert(monitored, "Mine".to_string());
        let oracle = SnapshotDeltaOracle::new(names);

        let slot = EVMU256::from_str_radix(IMPL_SLOT, 16).unwrap();
        let pre = EVMState::default();
        let post = state_with(stranger, slot, EVMU256::from(0xBEEFu64));

        assert!(
            oracle.detect_relocations(&pre, &post).is_empty(),
            "relocation on an unmonitored contract is out of scope"
        );
    }
}
