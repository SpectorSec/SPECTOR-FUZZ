use std::fmt::Debug;

use libafl::{
    inputs::Input,
    mutators::MutationResult,
    prelude::{HasMaxSize, HasRand, Mutator, State},
    schedulers::Scheduler,
    state::HasMetadata,
    Error,
};
use alloy_sol_types::SolCall;
use foundry_cheatcodes::Vm;
use libafl_bolts::{prelude::Rand, Named};
use revm_interpreter::{interpreter_types::Jumps, Interpreter};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::onchain::flashloan::CAN_LIQUIDATE;
/// Mutator for EVM inputs
use crate::evm::input::{EVMInputT, NestedAction};
use crate::evm::oracles::{OracleTargetMetadata, TrustedCallerMetadata, WhaleAddressMetadata};
use crate::evm::planner::{plan_campaign, CampaignTargetCache};
use crate::evm::topology::{TopologyHints, TopologyReport};
use crate::{
    evm::{
        abi::{ABIAddressToInstanceMap, BoxedABI},
        input::EVMInputTy::Borrow,
        middlewares::cheatcode::CHEATCODE_ADDRESS,
        types::{convert_u256_to_h160, EVMAddress, EVMU256},
        vm::{Constraint, EVMState, EVMStateT},
    },
    generic_vm::vm_state::VMStateT,
    input::{ConciseSerde, VMInputT},
    r#const::{
        ABI_MUTATE_CHOICE,
        CAMPAIGN_CHOICE,
        EXPLOIT_PRESET_CHOICE,
        HAVOC_CHOICE,
        HAVOC_MAX_ITERS,
        LIQUIDATE_CHOICE,
        LIQ_PERCENT,
        LIQ_PERCENT_CHOICE,
        MUTATE_CALLER_CHOICE,
        MUTATION_RETRIES,
        MUTATOR_SAMPLE_MAX,
        RANDOMNESS_CHOICE,
        RANDOMNESS_CHOICE_2,
        TURN_TO_STEP_CHOICE,
    },
    state::{HasCaller, HasItyState, HasPresets, InfantStateState},
};

/// [`AccessPattern`] records the access pattern of the input during execution.
/// This helps to determine what is needed to be fuzzed. For instance, we don't
/// need to mutate caller if the execution never uses it.
///
/// Each mutant should report to its parent's access pattern
/// if a new corpus item is added, it should inherit the access pattern of its
/// source
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AccessPattern {
    pub caller: bool,             // or origin
    pub balance: Vec<EVMAddress>, // balance queried for accounts
    pub call_value: bool,
    pub gas_price: bool,
    pub number: bool,
    pub coinbase: bool,
    pub timestamp: bool,
    pub prevrandao: bool,
    pub gas_limit: bool,
    pub chain_id: bool,
    pub basefee: bool,
}

impl AccessPattern {
    /// Create a new access pattern with all fields set to false
    pub fn new() -> Self {
        Self {
            balance: vec![],
            caller: false,
            call_value: false,
            gas_price: false,
            number: false,
            coinbase: false,
            timestamp: false,
            prevrandao: false,
            gas_limit: false,
            chain_id: false,
            basefee: false,
        }
    }

    /// Record access pattern of current opcode executed by the interpreter
    pub fn decode_instruction(&mut self, interp: &Interpreter) {
        match interp.bytecode.opcode() {
            0x31 => self.balance.push(convert_u256_to_h160(interp.stack.peek(0).unwrap())),
            0x33 => self.caller = true,
            0x3a => self.gas_price = true,
            0x43 => self.number = true,
            0x41 => self.coinbase = true,
            0x42 => self.timestamp = true,
            0x44 => self.prevrandao = true,
            0x45 => self.gas_limit = true,
            0x46 => self.chain_id = true,
            0x48 => self.basefee = true,
            0x34 => self.call_value = true,
            _ => {}
        }
    }
}

/// [`FuzzMutator`] is a mutator that mutates the input based on the ABI and
/// access pattern
pub struct FuzzMutator<VS, Loc, Addr, SC, CI>
where
    VS: Default + VMStateT,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Scheduler for selecting the next VM state to use if we decide to mutate
    /// the VM state of the input
    pub infant_scheduler: SC,
    /// Enable campaign orchestrator mode (atomic multi-step exploit sequences).
    pub campaign_orchestrator: bool,
    /// Enable Ghost Identities (identity spoofing for privileged functions).
    pub ghost_identities: bool,
    pub phantom: std::marker::PhantomData<(VS, Loc, Addr, CI)>,
}

impl<VS, Loc, Addr, SC, CI> FuzzMutator<VS, Loc, Addr, SC, CI>
where
    VS: Default + VMStateT,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Create a new [`FuzzMutator`] with the given scheduler
    pub fn new(infant_scheduler: SC, campaign_orchestrator: bool, ghost_identities: bool) -> Self {
        Self {
            infant_scheduler,
            campaign_orchestrator,
            ghost_identities,
            phantom: Default::default(),
        }
    }

    fn ensures_constraint<I, S>(input: &mut I, state: &mut S, new_vm_state: &VS, constraints: Vec<Constraint>) -> bool
    where
        I: VMInputT<VS, Loc, Addr, CI> + Input + EVMInputT,
        S: State + HasRand + HasMaxSize + HasItyState<Loc, Addr, VS, CI> + HasCaller<Addr> + HasMetadata,
    {
        // precheck
        for constraint in &constraints {
            match constraint {
                Constraint::MustStepNow => {
                    if input.get_input_type() == Borrow {
                        return false;
                    }
                }
                Constraint::Contract(_) => {
                    if input.get_input_type() == Borrow {
                        return false;
                    }
                }
                _ => {}
            }
        }

        for constraint in constraints {
            match constraint {
                Constraint::Caller(caller) => {
                    input.set_caller_evm(caller);
                }
                Constraint::Value(value) => {
                    input.set_txn_value(value);
                }
                Constraint::Contract(target) => {
                    let rand_int = state.rand_mut().next();
                    let always_none = state.rand_mut().below(MUTATOR_SAMPLE_MAX);
                    let abis = state
                        .metadata_map()
                        .get::<ABIAddressToInstanceMap>()
                        .expect("ABIAddressToInstanceMap not found");
                    let abi = match abis.map.get(&target) {
                        Some(abi) => {
                            if !abi.is_empty() {
                                match always_none {
                                    0..=ABI_MUTATE_CHOICE => {
                                        // we return a random abi
                                        Some((*abi)[rand_int as usize % abi.len()].clone())
                                    }
                                    _ => None,
                                }
                            } else {
                                None
                            }
                        }
                        None => None,
                    };
                    input.set_contract_and_abi(target, abi);
                }
                Constraint::NoLiquidation => {
                    input.set_liquidation_percent(0);
                }
                Constraint::MustStepNow => {
                    input.set_step(true);
                    // todo(@shou): move args into
                    // debug!("vm state: {:?}", input.get_state());
                    input.set_as_post_exec(new_vm_state.get_post_execution_needed_len());
                    input.mutate(state);
                }
            }
        }
        true
    }
}

impl<VS, Loc, Addr, SC, CI> Named for FuzzMutator<VS, Loc, Addr, SC, CI>
where
    VS: Default + VMStateT,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>>,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    fn name(&self) -> &str {
        "FuzzMutator"
    }
}

impl<VS, Loc, Addr, I, S, SC, CI> Mutator<I, S> for FuzzMutator<VS, Loc, Addr, SC, CI>
where
    I: VMInputT<VS, Loc, Addr, CI> + Input + EVMInputT,
    S: State + HasRand + HasMaxSize + HasItyState<Loc, Addr, VS, CI> + HasCaller<Addr> + HasCaller<EVMAddress> + HasMetadata + HasPresets,
    SC: Scheduler<State = InfantStateState<Loc, Addr, VS, CI>>,
    VS: Default + VMStateT + EVMStateT,
    Addr: PartialEq + Debug + Serialize + DeserializeOwned + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Mutate the input
    #[allow(unused_assignments)]
    fn mutate(&mut self, state: &mut S, input: &mut I, _stage_idx: i32) -> Result<MutationResult, Error> {
        // if the VM state of the input is not initialized, swap it with a state
        // initialized
        if !input.get_staged_state().initialized {
            let concrete = state.get_infant_state(&mut self.infant_scheduler).unwrap();
            input.set_staged_state(concrete.1, concrete.0);
        }

        // use exploit template
        if state.has_preset() && state.rand_mut().below(MUTATOR_SAMPLE_MAX) < EXPLOIT_PRESET_CHOICE {
            // if flashloan_v2, we don't mutate if it's a borrow
            if input.get_input_type() != Borrow {
                match state.get_next_call() {
                    Some((addr, abi)) => {
                        input.set_contract_and_abi(addr, Some(abi));
                        input.mutate(state);
                        return Ok(MutationResult::Mutated);
                    }
                    None => {
                        // debug!("cannot find next call");
                    }
                }
            }
        }
        // Campaign generation: probability scaled by topology confidence when orchestrator is enabled
        if self.campaign_orchestrator {
            let campaign_threshold = if let Some(hints) = state.metadata_map().get::<TopologyHints>() {
                let max_conf = hints.sets.iter().map(|s| s.confidence).max().unwrap_or(0) as f64;
                // Scale: 10% base * (1 + confidence/100), e.g., 95% conf -> ~19.5%
                ((CAMPAIGN_CHOICE as f64) * (1.0 + max_conf / 100.0)).min(MUTATOR_SAMPLE_MAX as f64) as u64
            } else {
                CAMPAIGN_CHOICE
            };
            if state.rand_mut().below(MUTATOR_SAMPLE_MAX) < campaign_threshold {
                if let Some(cache) = state.metadata_map().get::<CampaignTargetCache>() {
                    let topology_report = state.metadata_map().get::<TopologyReport>();
                    if let Some(campaign) = plan_campaign(cache, topology_report) {
                        *input.get_campaign_mut() = Some(campaign);
                        return Ok(MutationResult::Mutated);
                    }
                }
            }
        }

        // determine whether we should conduct havoc
        // (a sequence of mutations in batch vs single mutation)
        // let mut amount_of_args = input.get_data_abi().map(|abi|
        // abi.b.get_size()).unwrap_or(0) / 32 + 1; if amount_of_args > 6 {
        //     amount_of_args = 6;
        // }
        let should_havoc = state.rand_mut().below(MUTATOR_SAMPLE_MAX) < HAVOC_CHOICE;

        // determine how many times we should mutate the input
        let havoc_times = if should_havoc {
            state.rand_mut().below(HAVOC_MAX_ITERS) + 1 // (amount_of_args *
                                                        // HAVOC_MAX_ITERS) as
                                                        // u64;
        } else {
            1
        };

        let mut mutated = false;

        {
            if !input.is_step() && state.rand_mut().below(MUTATOR_SAMPLE_MAX) < MUTATE_CALLER_CHOICE {
                let old_idx = input.get_state_idx();
                let (idx, new_state) = state.get_infant_state(&mut self.infant_scheduler).unwrap();
                if idx != old_idx {
                    if !state.has_caller(&input.get_caller()) {
                        input.set_caller(state.get_rand_caller());
                    }

                    if Self::ensures_constraint(input, state, &new_state.state, new_state.state.get_constraints()) {
                        mutated = true;
                        input.set_staged_state(new_state, idx);
                    }
                }
            }

            // Mutate nested actions (with 15% probability)
            if state.rand_mut().below(100) < 15 {
                // Check oracle-flagged targets first (80% bias)
                let oracle_targets = state.metadata_map()
                    .get::<OracleTargetMetadata>()
                    .map(|m| m.targets.keys().cloned().collect::<Vec<[u8; 20]>>())
                    .unwrap_or_default();

                let use_oracle_target = !oracle_targets.is_empty() && state.rand_mut().below(100) < 80;

                if use_oracle_target {
                    eprintln!("[FeedbackLoop] using {} oracle-flagged targets for NestedAction", oracle_targets.len());
                }

                let keys: Option<Vec<EVMAddress>> = if use_oracle_target {
                    Some(oracle_targets.into_iter().map(EVMAddress::from).collect())
                } else {
                    let abis = state.metadata_map().get::<ABIAddressToInstanceMap>();
                    abis.map(|m| m.map.keys().cloned().collect::<Vec<EVMAddress>>())
                };

                if let Some(keys) = keys {
                    if !keys.is_empty() {
                        let target_idx = state.rand_mut().below(keys.len() as u64) as usize;
                        let target_addr = keys[target_idx];

                        let abi_len = {
                            let abis = state.metadata_map().get::<ABIAddressToInstanceMap>();
                            abis.and_then(|m| m.map.get(&target_addr).map(|v| v.len())).unwrap_or(0)
                        };

                        if abi_len > 0 {
                            let abi_idx = state.rand_mut().below(abi_len as u64) as usize;
                            let chosen_abi = {
                                let abis = state.metadata_map().get::<ABIAddressToInstanceMap>().unwrap();
                                abis.map.get(&target_addr).unwrap()[abi_idx].clone()
                            };

                            let selector = chosen_abi.function;
                            let mut abi = chosen_abi;
                            abi.mutate_with_vm_slots(
                                state,
                                None,
                                Some(target_addr),
                                Some(&input.get_state().as_any().downcast_ref::<EVMState>().unwrap().observed_values),
                            );
                            let calldata = abi.get_bytes();
                            let actions = input.get_nested_actions_mut();
                            actions.clear();

                            // Optionally inject a prank action (30% of nested action gens)
                            // 50% single-call prank, 50% startPrank+stopPrank pair
                            {
                                // First, check if we have trusted callers for this (target, selector) pair
                                // from TrustedCallerMetadata (Ghost Identities feature)
                                let trusted_addr = if self.ghost_identities {
                                    let key = format!("0x{:?}_0x{:?}", target_addr, selector);
                                    let trusted_set = state.metadata_map()
                                        .get::<TrustedCallerMetadata>()
                                        .and_then(|m| m.trusted_callers.get(&key).cloned());
                                    if let Some(set) = trusted_set {
                                        if !set.is_empty() {
                                            let addrs: Vec<EVMAddress> = set.into_iter().collect();
                                            let idx = state.rand_mut().below(addrs.len() as u64) as usize;
                                            Some(addrs[idx])
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };

                                let prank_addr = trusted_addr.or_else(|| {
                                    // Fallback to WhaleAddressMetadata
                                    let whale_set = state.metadata_map()
                                        .get::<WhaleAddressMetadata>()
                                        .map(|w| w.addresses.clone());
                                    if let Some(set) = whale_set {
                                        if !set.is_empty() {
                                            let addrs: Vec<EVMAddress> = set.into_iter().collect();
                                            let idx = state.rand_mut().below(addrs.len() as u64) as usize;
                                            Some(addrs[idx])
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                });

                                if let Some(prank_addr) = prank_addr {
                                    if state.rand_mut().below(100) < 30 {
                                        if state.rand_mut().below(100) < 50 {
                                            // 50%: single-call vm.prank(addr)
                                            let prank_call = Vm::prank_0Call { msgSender: prank_addr };
                                            let prank_calldata = prank_call.abi_encode();
                                            actions.push(NestedAction {
                                                target: CHEATCODE_ADDRESS.into(),
                                                calldata: bytes::Bytes::from(prank_calldata),
                                                value: EVMU256::ZERO,
                                            });
                                            actions.push(NestedAction {
                                                target: target_addr,
                                                calldata: bytes::Bytes::from(calldata.clone()),
                                                value: EVMU256::ZERO,
                                            });
                                        } else {
                                            // 50%: vm.startPrank(addr) + target + vm.stopPrank()
                                            let start_call = Vm::startPrank_0Call { msgSender: prank_addr };
                                            let start_calldata = start_call.abi_encode();
                                            actions.push(NestedAction {
                                                target: CHEATCODE_ADDRESS.into(),
                                                calldata: bytes::Bytes::from(start_calldata),
                                                value: EVMU256::ZERO,
                                            });
                                            actions.push(NestedAction {
                                                target: target_addr,
                                                calldata: bytes::Bytes::from(calldata.clone()),
                                                value: EVMU256::ZERO,
                                            });
                                            let stop_call = Vm::stopPrankCall {};
                                            let stop_calldata = stop_call.abi_encode();
                                            actions.push(NestedAction {
                                                target: CHEATCODE_ADDRESS.into(),
                                                calldata: bytes::Bytes::from(stop_calldata),
                                                value: EVMU256::ZERO,
                                            });
                                        }
                                    }
                                }
                            }

                            if actions.is_empty() {
                                actions.push(NestedAction {
                                    target: target_addr,
                                    calldata: bytes::Bytes::from(calldata),
                                    value: EVMU256::ZERO,
                                });
                            }
                            mutated = true;
                        }
                    }
                }
            }

            // Re-sample function selector with 10% probability
            // Prevents getting stuck on a single function (e.g. deposit())
            // Biases toward oracle-flagged targets (same 80% pattern as NestedAction)
            if state.rand_mut().below(100) < 10 {
                let abi_map = state.metadata_map().get::<ABIAddressToInstanceMap>().cloned();
                let oracle_targets: Vec<EVMAddress> = state.metadata_map()
                    .get::<OracleTargetMetadata>()
                    .map(|m| m.targets.keys().cloned().map(EVMAddress::from).collect())
                    .unwrap_or_default();

                let use_oracle_bias = !oracle_targets.is_empty() && state.rand_mut().below(100) < 80;

                if let Some(abi_map) = abi_map {
                    let mut candidates: Vec<(EVMAddress, BoxedABI)> = Vec::new();
                    for (addr, abis) in &abi_map.map {
                        if use_oracle_bias && !oracle_targets.contains(addr) {
                            continue;
                        }
                        for abi in abis {
                            candidates.push((*addr, abi.clone()));
                        }
                    }

                    if !candidates.is_empty() {
                        let idx = state.rand_mut().below(candidates.len() as u64) as usize;
                        let (contract, chosen) = candidates.swap_remove(idx);
                        input.set_contract_and_abi(contract, Some(chosen));
                        mutated = true;
                    }
                }
            }

            if input.get_staged_state().state.has_post_execution() &&
                !input.is_step() &&
                state.rand_mut().below(MUTATOR_SAMPLE_MAX) < TURN_TO_STEP_CHOICE
            {
                macro_rules! turn_to_step {
                    () => {
                        input.set_step(true);
                        // todo(@shou): move args into
                        input.set_as_post_exec(input.get_state().get_post_execution_needed_len());
                        for _ in 0..havoc_times - 1 {
                            input.mutate(state);
                        }
                        mutated = true;
                    };
                }
                if input.get_input_type() != Borrow {
                    turn_to_step!();
                }

                return Ok(MutationResult::Mutated);
            }
        }

        // mutate the input once
        let mut mutator = || -> MutationResult {
            // if the input is a step input (resume execution from a control leak)
            // we should not mutate the VM state, but only mutate the bytes
            if input.is_step() {
                let res = match state.rand_mut().below(MUTATOR_SAMPLE_MAX) {
                    0..=LIQUIDATE_CHOICE => {
                        // only when there are more than one liquidation path, we attempt to liquidate
                        if unsafe { CAN_LIQUIDATE } {
                            let prev_percent = input.get_liquidation_percent();
                            input.set_liquidation_percent(if state.rand_mut().below(MUTATOR_SAMPLE_MAX) <
                                LIQ_PERCENT_CHOICE
                            {
                                LIQ_PERCENT
                            } else {
                                0
                            } as u8);
                            if prev_percent != input.get_liquidation_percent() {
                                MutationResult::Mutated
                            } else {
                                MutationResult::Skipped
                            }
                        } else {
                            MutationResult::Skipped
                        }
                    }
                    _ => input.mutate(state),
                };
                input.set_txn_value(EVMU256::ZERO);
                return res;
            }

            // if the input is to borrow token, we should mutate the randomness
            // (use to select the paths to buy token), VM state, and bytes
            if input.get_input_type() == Borrow {
                let rand_u8 = state.rand_mut().below(256) as u8;
                return match state.rand_mut().below(MUTATOR_SAMPLE_MAX) {
                    0..=RANDOMNESS_CHOICE => {
                        // mutate the randomness
                        input.set_randomness(vec![rand_u8; 1]);
                        MutationResult::Mutated
                    }
                    // mutate the bytes
                    _ => input.mutate(state),
                };
            }

            // mutate the bytes or VM state or liquidation percent (percentage of token to
            // liquidate) by default
            match state.rand_mut().below(MUTATOR_SAMPLE_MAX) {
                0..=LIQUIDATE_CHOICE => {
                    let prev_percent = input.get_liquidation_percent();
                    input.set_liquidation_percent(if state.rand_mut().below(MUTATOR_SAMPLE_MAX) < LIQ_PERCENT_CHOICE {
                        LIQ_PERCENT
                    } else {
                        0
                    } as u8);
                    if prev_percent != input.get_liquidation_percent() {
                        MutationResult::Mutated
                    } else {
                        MutationResult::Skipped
                    }
                }
                LIQUIDATE_CHOICE..=RANDOMNESS_CHOICE_2 => {
                    let rand_u8 = state.rand_mut().below(256) as u8;
                    input.set_randomness(vec![rand_u8; 1]);
                    MutationResult::Mutated
                }
                _ => input.mutate(state),
            }
        };

        let mut res = if mutated {
            MutationResult::Mutated
        } else {
            MutationResult::Skipped
        };
        let mut tries = 0;

        // try to mutate the input for [`havoc_times`] times with MUTATION_RETRIES
        // retries if the input is not mutated
        while res != MutationResult::Mutated && tries < MUTATION_RETRIES {
            for i in 0..havoc_times {
                if mutator() == MutationResult::Mutated {
                    res = MutationResult::Mutated;
                }
            }
            tries += 1;
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use alloy_sol_types::{SolCall, SolInterface};
    use bytes::Bytes;
    use foundry_cheatcodes::Vm::{self, VmCalls};
    use libafl::state::HasMetadata;
    use serde_json;
    use crate::evm::abi::{AEmpty, A256, A256InnerType, ABIAddressToInstanceMap};
    use crate::evm::input::{EVMInput, EVMInputT, EVMInputTy};
    use crate::evm::middlewares::cheatcode::CHEATCODE_ADDRESS;
    use crate::evm::oracles::{OracleTargetMetadata, WhaleAddressMetadata, TrustedCallerMetadata};
    use crate::evm::types::{EVMAddress, EVMFuzzState, EVMStagedVMState, EVMU256};
    use crate::evm::mutator::BoxedABI;

    #[test]
    fn test_oracle_target_metadata_push_and_read() {
        let mut state = EVMFuzzState::new(0);

        assert!(state.metadata_map().get::<OracleTargetMetadata>().is_none());

        if state.metadata_map().get::<OracleTargetMetadata>().is_none() {
            state.metadata_map_mut().insert(OracleTargetMetadata::default());
        }
        let meta = state.metadata_map_mut().get_mut::<OracleTargetMetadata>().unwrap();
        let addr = [0x01u8; 20];
        meta.targets.entry(addr).or_insert_with(|| ("ArbitraryCall".to_string(), 8, 1));
        meta.targets.get_mut(&addr).unwrap().2 += 1;

        assert_eq!(meta.targets.get(&addr).unwrap().2, 2);
        assert_eq!(meta.targets.len(), 1);
        assert_eq!(meta.targets.get(&addr).unwrap().0, "ArbitraryCall");
        assert_eq!(meta.targets.get(&addr).unwrap().1, 8);
    }

    #[test]
    fn test_set_contract_and_abi_switches_selector() {
        let contract = EVMAddress::default();
        let mut input = EVMInput {
            caller: EVMAddress::default(),
            contract,
            data: None,
            sstate: EVMStagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(EVMU256::ZERO),
            step: false,
            env: Default::default(),
            access_pattern: std::rc::Rc::new(std::cell::RefCell::new(Default::default())),
            liquidation_percent: 0,
            direct_data: Bytes::new(),
            input_type: EVMInputTy::ABI,
            randomness: vec![],
            repeat: 1,
            swap_data: HashMap::new(),
            nested_actions: Vec::new(),
            campaign: None,
        };

        let selectors: [[u8; 4]; 3] = [
            [0x0f, 0xe1, 0xf4, 0xf7],
            [0x2e, 0x1a, 0x7d, 0x4d],
            [0x61, 0x4e, 0xd3, 0xe0],
        ];

        let abis: Vec<BoxedABI> = vec![
            BoxedABI { b: Box::new(AEmpty {}), function: selectors[0] },
            BoxedABI { b: Box::new(A256 { data: vec![0; 32], is_address: false, dont_mutate: false, inner_type: A256InnerType::Uint }), function: selectors[1] },
            BoxedABI { b: Box::new(AEmpty {}), function: selectors[2] },
        ];

        input.set_contract_and_abi(contract, Some(abis[0].clone()));
        assert_eq!(input.data.as_ref().unwrap().function, selectors[0]);

        input.set_contract_and_abi(contract, Some(abis[1].clone()));
        assert_eq!(input.data.as_ref().unwrap().function, selectors[1]);

        input.set_contract_and_abi(contract, Some(abis[2].clone()));
        assert_eq!(input.data.as_ref().unwrap().function, selectors[2]);

        input.set_contract_and_abi(contract, Some(abis[0].clone()));
        assert_eq!(input.data.as_ref().unwrap().function, selectors[0]);
    }

    #[test]
    fn test_abi_address_to_instance_map_routing() {
        let contract_a = EVMAddress::default();
        let contract_b = {
            let mut bytes = [0u8; 20];
            bytes[19] = 1;
            EVMAddress::from(bytes)
        };

        let deposit_sel = [0x0f, 0xe1, 0xf4, 0xf7];
        let withdraw_sel = [0x2e, 0x1a, 0x7d, 0x4d];

        let mut abi_map = ABIAddressToInstanceMap::new();
        abi_map.add(contract_a, BoxedABI { b: Box::new(AEmpty {}), function: deposit_sel });
        abi_map.add(contract_a, BoxedABI { b: Box::new(A256 { data: vec![0; 32], is_address: false, dont_mutate: false, inner_type: A256InnerType::Uint }), function: withdraw_sel });
        abi_map.add(contract_b, BoxedABI { b: Box::new(AEmpty {}), function: deposit_sel });

        assert_eq!(abi_map.map.get(&contract_a).unwrap().len(), 2);
        assert_eq!(abi_map.map.get(&contract_b).unwrap().len(), 1);
        assert_eq!(abi_map.map.get(&contract_a).unwrap()[0].function, deposit_sel);
        assert_eq!(abi_map.map.get(&contract_a).unwrap()[1].function, withdraw_sel);
    }

    #[test]
    fn test_prank_action_abi_encoding() {
        let whale = EVMAddress::from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);

        // Encode vm.prank(whale)
        let prank_call = Vm::prank_0Call { msgSender: whale };
        let encoded = prank_call.abi_encode();

        // Should be 36 bytes: 4-byte selector + 32-byte padded address
        assert_eq!(encoded.len(), 36, "prank(address) abi_encode should be 36 bytes");

        // Decode back and verify it's a prank_0 call
        let decoded = VmCalls::abi_decode(&encoded).expect("abi_decode should succeed");
        match decoded {
            VmCalls::prank_0(args) => {
                assert_eq!(args.msgSender, whale, "Decoded prank address should match");
            }
            other => panic!("Expected prank_0, got {:?}", other),
        }

        // Verify the NestedAction targets CHEATCODE_ADDRESS
        use crate::evm::input::NestedAction;
        let action = NestedAction {
            target: CHEATCODE_ADDRESS.into(),
            calldata: bytes::Bytes::from(encoded),
            value: EVMU256::ZERO,
        };
        assert_eq!(action.target.as_slice(), crate::evm::middlewares::cheatcode::CHEATCODE_ADDRESS.as_slice());
    }

    #[test]
    fn test_whale_address_metadata_seeding() {
        let mut state = EVMFuzzState::new(0);
        use std::collections::HashSet;

        // Simulate what corpus_initializer does: insert WhaleAddressMetadata
        let mut addresses = HashSet::new();
        addresses.insert(EVMAddress::from([0xde, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]));
        addresses.insert(EVMAddress::from([0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]));
        state.metadata_map_mut().insert(WhaleAddressMetadata { addresses });

        // Verify metadata is populated
        let meta = state.metadata_map().get::<WhaleAddressMetadata>()
            .expect("WhaleAddressMetadata should exist after insert");
        assert_eq!(meta.addresses.len(), 2, "Should have 2 whale addresses");

        // Verify it can be cloned (needed by mutator to avoid borrow issues)
        let cloned = meta.clone();
        assert_eq!(cloned.addresses.len(), 2);
    }

    #[test]
    fn test_start_stop_prank_action_abi_encoding() {
        let whale = EVMAddress::from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);

        // 1. Encode vm.startPrank(whale)
        let start_call = Vm::startPrank_0Call { msgSender: whale };
        let start_encoded = start_call.abi_encode();
        assert_eq!(start_encoded.len(), 36);

        let decoded_start = VmCalls::abi_decode(&start_encoded).expect("startPrank decode should succeed");
        match decoded_start {
            VmCalls::startPrank_0(args) => {
                assert_eq!(args.msgSender, whale);
            }
            other => panic!("Expected startPrank_0, got {:?}", other),
        }

        // 2. Encode vm.stopPrank()
        let stop_call = Vm::stopPrankCall {};
        let stop_encoded = stop_call.abi_encode();
        assert_eq!(stop_encoded.len(), 4, "stopPrank has no arguments, should be 4-byte selector");

        let decoded_stop = VmCalls::abi_decode(&stop_encoded).expect("stopPrank decode should succeed");
        match decoded_stop {
            VmCalls::stopPrank(_) => {}
            other => panic!("Expected stopPrank, got {:?}", other),
        }
    }

    #[test]
    fn test_trusted_caller_metadata_serde_roundtrip() {
        use std::collections::HashSet;

        let addr_a = EVMAddress::from([0x11; 20]);
        let addr_b = EVMAddress::from([0x22; 20]);
        let contract = EVMAddress::from([0xaa; 20]);
        let selector: [u8; 4] = [0x2e, 0x1a, 0x7d, 0x4d];
        let key = format!("0x{:?}_0x{:?}", contract, selector);

        let mut meta = TrustedCallerMetadata::default();
        let mut callers = HashSet::new();
        callers.insert(addr_a);
        callers.insert(addr_b);
        meta.trusted_callers.insert(key.clone(), callers);

        // Serialize + deserialize via serde_json
        let encoded = serde_json::to_string(&meta).expect("serialize should succeed");
        let decoded: TrustedCallerMetadata = serde_json::from_str(&encoded).expect("deserialize should succeed");

        let entry = decoded.trusted_callers.get(&key).expect("key should exist after round-trip");
        assert_eq!(entry.len(), 2, "should have 2 trusted callers");
        assert!(entry.contains(&addr_a));
        assert!(entry.contains(&addr_b));
        assert!(entry.contains(&addr_a)); // verify idempotent
    }

    #[test]
    fn test_trusted_caller_metadata_in_state() {
        use std::collections::HashSet;

        let mut state = EVMFuzzState::new(0);
        let contract = EVMAddress::from([0xbb; 20]);
        let selector: [u8; 4] = [0x0f, 0xe1, 0xf4, 0xf7];
        let trusted = EVMAddress::from([0x33; 20]);
        let key = format!("0x{:?}_0x{:?}", contract, selector);

        let mut callers = HashSet::new();
        callers.insert(trusted);
        let meta = TrustedCallerMetadata { trusted_callers: HashMap::from([(key.clone(), callers)]) };
        state.metadata_map_mut().insert(meta);

        let stored = state.metadata_map().get::<TrustedCallerMetadata>()
            .expect("TrustedCallerMetadata should exist");
        let entry = stored.trusted_callers.get(&key).expect("key should exist");
        assert!(entry.contains(&trusted));
        assert_eq!(entry.len(), 1);
    }

    #[test]
    fn test_trusted_caller_metadata_fallback_to_whale() {
        use std::collections::HashSet;

        let mut state = EVMFuzzState::new(0);

        let mut whale_addrs = HashSet::new();
        let whale = EVMAddress::from([0xde, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        whale_addrs.insert(whale);
        state.metadata_map_mut().insert(WhaleAddressMetadata { addresses: whale_addrs });

        assert!(state.metadata_map().get::<TrustedCallerMetadata>().is_none(),
            "TrustedCallerMetadata should not exist when not inserted");

        let whales = state.metadata_map().get::<WhaleAddressMetadata>().expect("WhaleAddressMetadata should exist");
        assert_eq!(whales.addresses.len(), 1);
        assert!(whales.addresses.contains(&whale));
    }

    #[test]
    fn test_trusted_caller_metadata_empty_is_default() {
        let meta = TrustedCallerMetadata::default();
        assert!(meta.trusted_callers.is_empty(), "default TrustedCallerMetadata should have empty map");

        let mut state = EVMFuzzState::new(0);
        state.metadata_map_mut().insert(TrustedCallerMetadata::default());

        let stored = state.metadata_map().get::<TrustedCallerMetadata>()
            .expect("TrustedCallerMetadata should exist after insert");
        assert!(stored.trusted_callers.is_empty(), "stored metadata should have empty trusted_callers map");
    }

    #[test]
    fn test_trusted_caller_metadata_key_format() {
        let contract = EVMAddress::from([0xcc; 20]);
        let selector: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
        let key = format!("0x{:?}_0x{:?}", contract, selector);

        // Verify the key starts with "0x" and contains both hex representations
        assert!(key.starts_with("0x"), "key should start with 0x");
        assert!(key.contains("_0x"), "key should contain _0x separator");
        assert!(key.len() > 20, "key should be a non-trivial string");
    }
}
