/// Wrapper of smart contract VM, which implements LibAFL [`Executor`]
use std::cell::RefCell;
use std::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
    ops::Deref,
    rc::Rc,
};

use libafl::{
    executors::{Executor, ExitKind},
    inputs::Input,
    prelude::{HasCorpus, HasMetadata, HasObservers, ObserversTuple, UsesInput, UsesObservers},
    state::{State, UsesState},
    Error,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    input::{ConciseSerde, VMInputT},
    state::HasExecutionResult,
    state_input::StagedVMState,
    evm::types::CampaignIntermediateStates,
    evm::oracles::CampaignWarpStates,
};

#[cfg(feature = "evm")]
use crate::evm::input::EVMInput;
#[cfg(feature = "evm")]
use crate::evm::types::EVMU256;

/// Feature 041 (EO-04): write a captured EVMU256 return value into a specific ABI
/// argument slot of an EVMInput's calldata.  Mirrors the `write_step_arg_u128`
/// pattern in mutator.rs — modifies the ABI's inner bytes directly via
/// `get_bytes_vec` / `set_bytes` so the change is visible through `to_bytes()`,
/// which is what `execute_abi` actually reads.  Writing to `set_direct_data` is a
/// no-op when `to_bytes()` is non-empty, which is the case for any input that has
/// an `ABI` data field (the normal path).
#[cfg(feature = "evm")]
fn apply_linkage_arg(input: &mut EVMInput, param_index: usize, value: EVMU256) {
    let Some(abi) = &mut input.data else { return };
    let mut args = abi.get_bytes_vec();
    let offset = param_index * 32;
    if offset + 32 > args.len() {
        return;
    }
    let bytes = value.to_be_bytes::<32>();
    args[offset..offset + 32].copy_from_slice(&bytes);
    let full = [Vec::from(abi.function), args].concat();
    abi.set_bytes(full);
}

/// Wrapper of smart contract VM, which implements LibAFL [`Executor`]
/// TODO: in the future, we may need to add handlers?
/// handle timeout/crash of executing contract
#[allow(clippy::type_complexity)]
pub struct FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    S: UsesInput<Input = I>,
    OT: ObserversTuple<S>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// The VM executor
    pub vm: Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S, CI>>>,
    /// Observers (e.g., coverage)
    observers: OT,
    phantom: PhantomData<(I, S, Addr, Out)>,
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI> UsesState
    for FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    S: State + UsesInput<Input = I>,
    OT: ObserversTuple<S>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    type State = S;
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI> UsesObservers
    for FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    S: State + UsesInput<Input = I>,
    OT: ObserversTuple<S>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    type Observers = OT;
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI> Debug
    for FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    S: State + UsesInput<Input = I>,
    OT: ObserversTuple<S> + Debug,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuzzExecutor")
            // .field("evm_executor", &self.evm_executor)
            .field("observers", &self.observers)
            .finish()
    }
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
    FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    S: UsesInput<Input = I>,
    OT: ObserversTuple<S>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Create a new [`FuzzExecutor`]
    #[allow(clippy::type_complexity)]
    pub fn new(
        vm_executor: Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S, CI>>>,
        observers: OT,
    ) -> Self {
        Self {
            vm: vm_executor,
            observers,
            phantom: PhantomData,
        }
    }
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, EM, Z, CI> Executor<EM, Z>
    for FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
where
    I: VMInputT<VS, Loc, Addr, CI> + Input + 'static,
    OT: ObserversTuple<S>,
    S: State + HasExecutionResult<Loc, Addr, VS, Out, CI> + HasCorpus + HasMetadata + UsesInput<Input = I> + 'static,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default + Into<Vec<u8>> + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    /// Run the VM to execute the input
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        // Feature 038 (EO-01): clear any campaign-scoped metadata left over from a prior
        // execution BEFORE either path runs. The campaign path rewrites them with fresh
        // data; the non-campaign path (and mid-campaign reverts via the early-return below)
        // must leave them absent so OracleFeedback's OracleCtx never attributes this
        // execution to a stale prior campaign frame. Use the concrete EVM type aliases
        // (which are 'static) rather than the generic parameters (which are not).
        #[cfg(feature = "evm")]
        {
            use crate::evm::types::CampaignIntermediateStatesEVM;
            state.metadata_map_mut().remove::<CampaignIntermediateStatesEVM>();
            state.metadata_map_mut().remove::<CampaignWarpStates>();
            state.metadata_map_mut().remove::<crate::evm::planner::CampaignInflowBoundaries>();
        }

        // Campaign mode: execute multi-step atomic sequence.
        // SAFETY: I = EVMInput, and types match, in the EVM monomorphization (cfg evm).
        #[cfg(feature = "evm")]
        if let Some(evm_input) = input.as_any().downcast_ref::<EVMInput>() {
            use crate::evm::types::{CampaignIntermediateStates, EVMStagedVMState};
            if let Some(campaign) = &evm_input.campaign {
                if !campaign.steps.is_empty() {
                    let steps = campaign.steps.clone();
                    let mut current_state: EVMStagedVMState = evm_input.sstate.clone();
                    let mut intermediate_states: Vec<EVMStagedVMState> = Vec::new();

                    // Feature 015 Phase 2 (a-posteriori Promote): record the offset into the
                    // campaign's ordered `erc20_transfers` log at each step boundary, so the
                    // feedback can attribute an attacker-inflow delta to the belly call that
                    // produced it. `offsets[i]` = log length BEFORE step `i`; a trailing entry
                    // (after the last step) closes the final slice. Only armed when the planner
                    // set `aposteriori` (reflexive path, no a-priori archetype) ⇒ off-path this
                    // is one `bool` check and no allocation.
                    let aposteriori = campaign.aposteriori;
                    let mut inflow_offsets: Vec<usize> = Vec::new();
                    if aposteriori {
                        inflow_offsets.push(current_state.state.erc20_transfers.len());
                    }

                    for (i, step_ci) in steps.iter().enumerate().take(steps.len() - 1) {
                        // Feature 023 Phase 1a: publish the executing step so the inline
                        // FunctionAuthTracer can attribute a structural move to its step.
                        crate::evm::middlewares::function_auth::set_campaign_step(Some(i));
                        let (mut step_input, _) = step_ci.to_input(current_state.clone());
                        // Feature 041 (EO-04): apply any output→input linkages targeting
                        // this step using observed_values captured by value_capture.rs in
                        // prior steps. Iterates zero times when linkages is empty (common
                        // case) so this is byte-identical for all current campaigns.
                        for linkage in campaign.linkages.iter().filter(|l| l.to_step == i) {
                            if linkage.from_step >= i {
                                continue; // malformed: source must precede target
                            }
                            if let Some(vals) = current_state.state.observed_values.get(&linkage.from_registry_key) {
                                if let Some(captured) = vals.last() {
                                    apply_linkage_arg(&mut step_input, linkage.to_param_index, *captured);
                                }
                            }
                        }
                        // Apply warp delta before execute, so vm.rs:598 picks up the warped env
                        if let Some(delta) = campaign.warps.iter().find(|(idx, _)| *idx == i).map(|(_, d)| d) {
                            step_input.env.block.number += EVMU256::from(*delta);
                            step_input.env.block.timestamp += EVMU256::from(*delta * 12);
                        }
                        let step_ref: &I = unsafe { &*(&step_input as *const EVMInput as *const I) };
                        let res = self.vm.deref().borrow_mut().execute(step_ref, state);
                        state.set_execution_result(res);
                        // Feature 039 (EO-02): check revert BEFORE pushing — a reverted step
                        // produced no valid post-state, so it should not be recorded.
                        if state.get_execution_result().reverted {
                            return Ok(ExitKind::Ok);
                        }
                        current_state = unsafe {
                            let generic_ref: &StagedVMState<Loc, Addr, VS, CI> = &state.get_execution_result().new_state;
                            let concrete_ref: &EVMStagedVMState = &*(generic_ref as *const StagedVMState<Loc, Addr, VS, CI> as *const EVMStagedVMState);
                            concrete_ref.clone()
                        };
                        // Feature 039 (EO-02): push the POST-step state (after reassignment
                        // above), not the pre-step state. Consumers reading
                        // intermediate_states[i] now get "state after step i completed."
                        intermediate_states.push(current_state.clone());
                        if aposteriori {
                            inflow_offsets.push(current_state.state.erc20_transfers.len());
                        }
                    }

                    let last_idx = steps.len() - 1;
                    // Feature 023 Phase 1a: last step is the current phase for the exploit-step
                    // execute below (and the controlled-probe re-execs, which run the last step).
                    crate::evm::middlewares::function_auth::set_campaign_step(Some(last_idx));
                    // Warp delta for the exploit step (the planner's base; the secant
                    // refines it below via controlled probes).
                    let mut warp_delta: u64 = campaign
                        .warps
                        .iter()
                        .find(|(idx, _)| *idx == last_idx)
                        .map(|(_, d)| *d)
                        .unwrap_or(0);

                    // ── Controlled-probe warp refinement (Application C) ──
                    // Re-execute the exploit step at two controlled warps from the
                    // SAME prefix state, so only the warp varies → a clean slope with
                    // no cross-iteration noise. Compute the warp that flips the
                    // time-gated threshold and use it for the real execution below.
                    //
                    // Feature 040 (EO-03): probes are safe because vm.rs:1463 reloads
                    // evmstate from the input's embedded staged state at the top of every
                    // execute() call — probe writes cannot persist into the real step.
                    // divergence/timestamp thread-locals are written only in the
                    // post-run_target feedback pass (OracleFeedback::is_interesting),
                    // which is structurally unreachable from inside run_target.
                    // If a new middleware introduces execution-scoped global state that
                    // isn't part of EVMState and isn't reset by temporal_reset_all(),
                    // it must be explicitly reset here or added to the middleware audit
                    // table in .speckit/research/execution-ordering-audit-2026-07-10.md.
                    #[cfg(feature = "cmp")]
                    if warp_delta > 0 {
                        use crate::evm::host::{temporal_argmin, temporal_read, temporal_reset_all};
                        const DELTA: u64 = 100;
                        const MAX_WARP: u64 = 1_000_000;
                        let base = warp_delta;

                        // Probe 1 at `base`.
                        unsafe { temporal_reset_all() };
                        {
                            let (mut p, _) = steps.last().unwrap().to_input(current_state.clone());
                            p.env.block.number += EVMU256::from(base);
                            p.env.block.timestamp += EVMU256::from(base * 12);
                            let pr: &I = unsafe { &*(&p as *const EVMInput as *const I) };
                            let _ = self.vm.deref().borrow_mut().execute(pr, state);
                        }
                        if let Some((pin, fp, d1, _bn1)) = unsafe { temporal_argmin() } {
                            // Probe 2 at `base + DELTA` (fresh measurement).
                            unsafe { temporal_reset_all() };
                            {
                                let (mut p, _) = steps.last().unwrap().to_input(current_state.clone());
                                p.env.block.number += EVMU256::from(base + DELTA);
                                p.env.block.timestamp += EVMU256::from((base + DELTA) * 12);
                                let pr: &I = unsafe { &*(&p as *const EVMInput as *const I) };
                                let _ = self.vm.deref().borrow_mut().execute(pr, state);
                            }
                            if let Some((d2, _bn2)) = unsafe { temporal_read(pin, fp) } {
                                // gap shrinks as warp grows: rate = (d1-d2)/DELTA;
                                // warp* = base + d1/rate = base + d1*DELTA/(d1-d2).
                                if d1 > d2 {
                                    let dd = d1 - d2;
                                    let step = d1.saturating_mul(DELTA as u128).saturating_div(dd);
                                    warp_delta = (base as u128)
                                        .saturating_add(step)
                                        .min(MAX_WARP as u128)
                                        as u64;
                                    tracing::debug!(
                                        "[secant-exec] controlled probe: base={} d1={} d2={} -> warp*={}",
                                        base, d1, d2, warp_delta
                                    );
                                }
                                // d1<=d2 → flat (time not the lever) → keep base.
                            }
                        }
                    }

                    let (mut last_input, _) = steps.last().unwrap().to_input(current_state.clone());
                    // Feature 041 (EO-04): apply linkages targeting the exploit step using
                    // observed_values accumulated through the prefix steps. to_input above
                    // clones current_state so it's still accessible here.
                    for linkage in campaign.linkages.iter().filter(|l| l.to_step == last_idx) {
                        if linkage.from_step >= last_idx {
                            continue;
                        }
                        if let Some(vals) = current_state.state.observed_values.get(&linkage.from_registry_key) {
                            if let Some(captured) = vals.last() {
                                apply_linkage_arg(&mut last_input, linkage.to_param_index, *captured);
                            }
                        }
                    }
                    if warp_delta > 0 {
                        last_input.env.block.number += EVMU256::from(warp_delta);
                        last_input.env.block.timestamp += EVMU256::from(warp_delta * 12);
                    }
                    let last_ref: &I = unsafe { &*(&last_input as *const EVMInput as *const I) };
                    let res = self.vm.deref().borrow_mut().execute(last_ref, state);
                    state.set_execution_result(res);
                    // Store intermediate states and warps in state metadata for oracle access
                    state.add_metadata(CampaignIntermediateStates {
                        states: intermediate_states,
                    });
                    state.add_metadata(CampaignWarpStates {
                        warps: campaign.warps.clone(),
                    });
                    // Feature 015 Phase 2: close the final slice and publish the boundaries so
                    // the feedback can attribute per-step attacker inflow. `offsets.len()` ends
                    // up `steps.len() + 1`.
                    if aposteriori {
                        let final_len = unsafe {
                            let generic_ref: &StagedVMState<Loc, Addr, VS, CI> = &state.get_execution_result().new_state;
                            let concrete_ref: &EVMStagedVMState = &*(generic_ref as *const StagedVMState<Loc, Addr, VS, CI> as *const EVMStagedVMState);
                            concrete_ref.state.erc20_transfers.len()
                        };
                        inflow_offsets.push(final_len);
                        state.add_metadata(crate::evm::planner::CampaignInflowBoundaries {
                            offsets: inflow_offsets,
                        });
                    }
                    return Ok(ExitKind::Ok);
                }
            }
        }

        // Feature 023 Phase 1a: single input (not a campaign step) → no phase to attribute.
        #[cfg(feature = "evm")]
        crate::evm::middlewares::function_auth::set_campaign_step(None);
        let res = self.vm.deref().borrow_mut().execute(input, state);
        // the execution result is added to the fuzzer state
        // later the feedback/objective can run oracle on this result
        state.set_execution_result(res);
        Ok(ExitKind::Ok)
    }
}

#[cfg(test)]
#[cfg(feature = "evm")]
mod execution_ordering_tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use libafl::executors::Executor;
    use libafl::prelude::{HasMetadata, StdScheduler};
    use libafl::state::UsesState;
    use libafl_bolts::tuples::tuple_list;
    use bytes::Bytes as StdBytes;
    use revm_interpreter::bytecode::Bytecode;
    use revm_primitives::Bytes as RevmBytes;

    use super::FuzzExecutor;
    use crate::evm::abi::{AEmpty, A256, A256InnerType, BoxedABI};
    use crate::evm::host::FuzzHost;
    use crate::evm::input::{CampaignSequence, ConciseEVMInput, EVMInput, EVMInputTy, StepLinkage};
    use crate::evm::middlewares::value_capture::ValueCaptureMiddleware;
    use crate::evm::oracles::CampaignWarpStates;
    use crate::evm::types::{
        CampaignIntermediateStatesEVM, EVMAddress, EVMFuzzState, EVMStagedVMState, EVMU256,
    };
    use crate::evm::vm::{EVMExecutor, EVMState};
    use crate::generic_vm::vm_executor::GenericVM;
    use crate::state::{FuzzState, HasExecutionResult};
    use crate::state_input::StagedVMState;

    struct StubFuzzer;
    impl UsesState for StubFuzzer {
        type State = EVMFuzzState;
    }

    fn addr(b: u8) -> EVMAddress {
        EVMAddress::from([b; 20])
    }

    /// Register serdeany types that don't use impl_serdeany! — required before the
    /// first `state.add_metadata(...)` call for these types in non-autoreg builds.
    fn register_metadata_types() {
        #[cfg(any(not(feature = "serdeany_autoreg"), miri))]
        unsafe {
            crate::evm::types::CampaignIntermediateStatesEVM::register();
        }
    }

    // GenericVM's `By` parameter is bytes::Bytes, not revm_primitives::Bytes.
    type DynVM = dyn GenericVM<
        EVMState,
        Bytecode,
        StdBytes,
        EVMAddress,
        EVMAddress,
        EVMU256,
        Vec<u8>,
        EVMInput,
        EVMFuzzState,
        ConciseEVMInput,
    >;

    fn make_fuzz_executor(
        host: FuzzHost<StdScheduler<EVMFuzzState>>,
    ) -> FuzzExecutor<
        EVMState,
        EVMAddress,
        Bytecode,
        StdBytes,
        EVMAddress,
        EVMU256,
        Vec<u8>,
        EVMInput,
        EVMFuzzState,
        (),
        ConciseEVMInput,
    > {
        let evm_exec: EVMExecutor<EVMState, ConciseEVMInput, StdScheduler<EVMFuzzState>> =
            EVMExecutor::new(host, addr(0xfe));
        let vm_rc: Rc<RefCell<DynVM>> = Rc::new(RefCell::new(evm_exec));
        FuzzExecutor::new(vm_rc, tuple_list!())
    }

    fn make_fuzz_executor_with_value_capture(
        host: FuzzHost<StdScheduler<EVMFuzzState>>,
    ) -> FuzzExecutor<
        EVMState,
        EVMAddress,
        Bytecode,
        StdBytes,
        EVMAddress,
        EVMU256,
        Vec<u8>,
        EVMInput,
        EVMFuzzState,
        (),
        ConciseEVMInput,
    > {
        let mut evm_exec: EVMExecutor<EVMState, ConciseEVMInput, StdScheduler<EVMFuzzState>> =
            EVMExecutor::new(host, addr(0xfe));
        evm_exec
            .host
            .add_middlewares(Rc::new(RefCell::new(ValueCaptureMiddleware::new())));
        let vm_rc: Rc<RefCell<DynVM>> = Rc::new(RefCell::new(evm_exec));
        FuzzExecutor::new(vm_rc, tuple_list!())
    }

    fn aempty_abi(selector: [u8; 4]) -> BoxedABI {
        let mut abi = BoxedABI::new(Box::new(AEmpty {}));
        abi.set_func(selector);
        abi
    }

    fn a256_abi(selector: [u8; 4]) -> BoxedABI {
        let mut abi = BoxedABI::new(Box::new(A256 {
            data: vec![0u8; 32],
            is_address: false,
            dont_mutate: false,
            inner_type: A256InnerType::Uint,
        }));
        abi.set_func(selector);
        abi
    }

    fn step(contract: EVMAddress, selector: [u8; 4], abi: BoxedABI) -> ConciseEVMInput {
        ConciseEVMInput {
            contract,
            caller: addr(0x02),
            input_type: EVMInputTy::ABI,
            data: Some(abi),
            repeat: 1,
            ..Default::default()
        }
    }

    fn campaign_input(
        steps: Vec<ConciseEVMInput>,
        linkages: Vec<StepLinkage>,
        initial: EVMStagedVMState,
    ) -> EVMInput {
        let ci = ConciseEVMInput {
            campaign: Some(CampaignSequence {
                steps,
                linkages,
                warps: vec![],
                promoted: vec![],
                aposteriori: false,
            }),
            repeat: 1,
            ..Default::default()
        };
        ci.to_input(initial).0
    }

    /// EO-01 (Feature 038): run_target must clear stale campaign metadata at the
    /// top of every invocation — including non-campaign inputs.
    #[cfg_attr(not(feature = "integration_test"), ignore)]
    #[test]
    fn eo01_run_target_clears_campaign_metadata_on_non_campaign_input() {
        register_metadata_types();
        let work_dir = "/tmp/ityfuzz_eo01_test";
        let _ = std::fs::create_dir_all(work_dir);
        let mut state: EVMFuzzState = FuzzState::new(0);

        let host = FuzzHost::new(StdScheduler::new(), work_dir.to_string());
        let mut fuzz_executor = make_fuzz_executor(host);

        // Pre-populate stale metadata from a previous campaign frame.
        state.add_metadata(CampaignIntermediateStatesEVM { states: vec![] });
        state.add_metadata(CampaignWarpStates { warps: vec![] });
        assert!(state.metadata_map().get::<CampaignIntermediateStatesEVM>().is_some());
        assert!(state.metadata_map().get::<CampaignWarpStates>().is_some());

        // Non-campaign input targeting an address with no code — reverts but that
        // is irrelevant; what matters is the metadata cleared at the top.
        let ci = ConciseEVMInput {
            contract: addr(0x99),
            caller: addr(0x02),
            input_type: EVMInputTy::ABI,
            repeat: 1,
            ..Default::default()
        };
        let (top_input, _) = ci.to_input(StagedVMState::new_uninitialized());

        let mut z = StubFuzzer;
        let mut em = StubFuzzer;
        fuzz_executor
            .run_target(&mut z, &mut state, &mut em, &top_input)
            .unwrap();

        assert!(
            state.metadata_map().get::<CampaignIntermediateStatesEVM>().is_none(),
            "EO-01: CampaignIntermediateStatesEVM must be absent after non-campaign run_target"
        );
        assert!(
            state.metadata_map().get::<CampaignWarpStates>().is_none(),
            "EO-01: CampaignWarpStates must be absent after non-campaign run_target"
        );

        let _ = std::fs::remove_dir_all(work_dir);
    }

    /// EO-02 (Feature 039): intermediate_states[i] must reflect the POST-step state
    /// (storage written by step i), not the pre-step state.  Also covers the revert
    /// sub-case: if a prefix step reverts, run_target returns early and leaves
    /// CampaignIntermediateStatesEVM absent (the EO-01 clear happened, the EO-02
    /// write never happened).
    ///
    /// Increment contract (runtime bytecode):
    ///   storage[0] += 1; MSTORE(0, storage[0]); RETURN(0, 32)
    ///   60 00 54 60 01 01 80 60 00 55 60 00 52 60 20 60 00 f3
    #[cfg_attr(not(feature = "integration_test"), ignore)]
    #[test]
    fn eo02_intermediate_states_are_post_step_and_cleared_on_revert() {
        register_metadata_types();
        let work_dir = "/tmp/ityfuzz_eo02_test";
        let _ = std::fs::create_dir_all(work_dir);
        let mut state: EVMFuzzState = FuzzState::new(0);

        let addr_inc = addr(0x01);
        let sel_inc = [0x11u8, 0x22, 0x33, 0x44];
        let increment_bytes =
            hex::decode("6000546001018060005560005260206000f3").unwrap();

        let mut host = FuzzHost::new(StdScheduler::new(), work_dir.to_string());
        host.set_code(
            addr_inc,
            Bytecode::new_raw(RevmBytes::from(increment_bytes)),
            &mut state,
        );

        let initial_vm = host.evmstate.clone();
        let initial_sstate = EVMStagedVMState::new_with_state(initial_vm);

        let mut fuzz_executor = make_fuzz_executor(host);

        // 3-step campaign: each step increments storage[0] by 1.
        // After prefix step 0 → storage[0] = 1; after prefix step 1 → storage[0] = 2.
        let steps = vec![
            step(addr_inc, sel_inc, aempty_abi(sel_inc)),
            step(addr_inc, sel_inc, aempty_abi(sel_inc)),
            step(addr_inc, sel_inc, aempty_abi(sel_inc)),
        ];
        let top_input = campaign_input(steps, vec![], initial_sstate);

        let mut z = StubFuzzer;
        let mut em = StubFuzzer;
        fuzz_executor
            .run_target(&mut z, &mut state, &mut em, &top_input)
            .unwrap();

        let meta = state
            .metadata_map()
            .get::<CampaignIntermediateStatesEVM>()
            .expect("EO-02: CampaignIntermediateStatesEVM must be present after successful campaign");

        // Two prefix steps → two entries (the exploit step is not recorded).
        assert_eq!(
            meta.states.len(),
            2,
            "EO-02: expected 2 intermediate states for a 3-step campaign"
        );

        // intermediate_states[0] must reflect POST-step-0 storage (counter = 1).
        let s0 = meta.states[0].state.state.get(&addr_inc).unwrap();
        assert_eq!(
            s0.get(&EVMU256::ZERO).copied().unwrap_or(EVMU256::ZERO),
            EVMU256::from(1u64),
            "EO-02: intermediate_states[0] must be the post-step-0 state (counter=1)"
        );

        // intermediate_states[1] must reflect POST-step-1 storage (counter = 2).
        let s1 = meta.states[1].state.state.get(&addr_inc).unwrap();
        assert_eq!(
            s1.get(&EVMU256::ZERO).copied().unwrap_or(EVMU256::ZERO),
            EVMU256::from(2u64),
            "EO-02: intermediate_states[1] must be the post-step-1 state (counter=2)"
        );

        // ── Revert sub-case ──────────────────────────────────────────────────
        // A prefix step that reverts (INVALID = 0xfe) causes early return from
        // run_target before state.add_metadata is called.  The EO-01 clear at the
        // top means CampaignIntermediateStatesEVM is absent afterward.
        let mut state2: EVMFuzzState = FuzzState::new(0);
        state2.add_metadata(CampaignIntermediateStatesEVM { states: vec![] });

        let addr_rev = addr(0x02);
        let sel_rev = [0xAAu8, 0xBB, 0xCC, 0xDD];
        let revert_bytes = hex::decode("fe").unwrap(); // INVALID always reverts

        let work_dir2 = "/tmp/ityfuzz_eo02b_test";
        let _ = std::fs::create_dir_all(work_dir2);
        let mut host2 = FuzzHost::new(StdScheduler::new(), work_dir2.to_string());
        host2.set_code(
            addr_rev,
            Bytecode::new_raw(RevmBytes::from(revert_bytes)),
            &mut state2,
        );
        let initial_sstate2 =
            EVMStagedVMState::new_with_state(host2.evmstate.clone());
        let mut fuzz_executor2 = make_fuzz_executor(host2);

        let steps2 = vec![
            step(addr_rev, sel_rev, aempty_abi(sel_rev)), // reverts immediately
            step(addr_rev, sel_rev, aempty_abi(sel_rev)),
            step(addr_rev, sel_rev, aempty_abi(sel_rev)),
        ];
        let top_input2 = campaign_input(steps2, vec![], initial_sstate2);

        let mut z2 = StubFuzzer;
        let mut em2 = StubFuzzer;
        fuzz_executor2
            .run_target(&mut z2, &mut state2, &mut em2, &top_input2)
            .unwrap();

        assert!(
            state2
                .metadata_map()
                .get::<CampaignIntermediateStatesEVM>()
                .is_none(),
            "EO-02 revert: CampaignIntermediateStatesEVM must be absent when a prefix step reverts"
        );

        let _ = std::fs::remove_dir_all(work_dir);
        let _ = std::fs::remove_dir_all(work_dir2);
    }

    /// EO-04 (Feature 041): apply_linkage_arg must route a return value captured by
    /// ValueCaptureMiddleware from step 0 into step 1's calldata argument slot.
    ///
    /// Contract A — return-slot0 (addr 0x01):
    ///   SLOAD(0) → MSTORE(0, val) → RETURN(0, 32)
    ///   Storage[0] is pre-seeded with NONCE = 42.
    ///   Bytecode: 60 00 54 60 00 52 60 20 60 00 f3
    ///
    /// Contract B — check-nonce (addr 0x02):
    ///   if CALLDATALOAD(4) == SLOAD(0) { STOP } else { REVERT }
    ///   Storage[0] is pre-seeded with NONCE = 42.
    ///   Bytecode: 60 04 35 60 00 54 14 60 0F 57 60 00 60 00 FD 5B 00
    #[cfg_attr(not(feature = "integration_test"), ignore)]
    #[test]
    fn eo04_step_linkage_routes_captured_return_to_next_step_argument() {
        register_metadata_types();
        const NONCE: u64 = 42;

        let addr_a = addr(0x01); // return-slot0 contract
        let addr_b = addr(0x02); // check-nonce contract
        let sel_a = [0xAAu8, 0xBB, 0xCC, 0xDD];
        let sel_b = [0x11u8, 0x22, 0x33, 0x44];

        // return-slot0: PUSH1 0 / SLOAD / PUSH1 0 / MSTORE / PUSH1 32 / PUSH1 0 / RETURN
        let return_slot0_bytes = hex::decode("60005460005260206000f3").unwrap();
        // check-nonce: PUSH1 4 / CALLDATALOAD / PUSH1 0 / SLOAD / EQ / PUSH1 15 / JUMPI
        //              / PUSH1 0 / PUSH1 0 / REVERT / JUMPDEST / STOP
        let check_nonce_bytes = hex::decode("60043560005414600f5760006000fd5b00").unwrap();

        let work_dir = "/tmp/ityfuzz_eo04_test";
        let _ = std::fs::create_dir_all(work_dir);
        let mut state: EVMFuzzState = FuzzState::new(0);

        let mut host = FuzzHost::new(StdScheduler::new(), work_dir.to_string());
        host.set_code(
            addr_a,
            Bytecode::new_raw(RevmBytes::from(return_slot0_bytes.clone())),
            &mut state,
        );
        host.set_code(
            addr_b,
            Bytecode::new_raw(RevmBytes::from(check_nonce_bytes.clone())),
            &mut state,
        );

        // Pre-seed storage[0] with NONCE at BOTH contracts so they agree.
        let mut initial_vm = host.evmstate.clone();
        initial_vm
            .state
            .entry(addr_a)
            .or_default()
            .insert(EVMU256::ZERO, EVMU256::from(NONCE));
        initial_vm
            .state
            .entry(addr_b)
            .or_default()
            .insert(EVMU256::ZERO, EVMU256::from(NONCE));
        let initial_sstate = EVMStagedVMState::new_with_state(initial_vm);

        // Step 0 calls addr_a (no args needed — the contract ignores calldata).
        // Step 1 calls addr_b with a uint256 argument slot that must receive NONCE.
        let steps = vec![
            step(addr_a, sel_a, aempty_abi(sel_a)),
            step(addr_b, sel_b, a256_abi(sel_b)), // arg slot 0 starts as zeros
        ];

        let registry_key = format!("{:?}_{}_return", addr_a, hex::encode(sel_a));
        let linkage = StepLinkage {
            from_step: 0,
            from_registry_key: registry_key,
            to_step: 1,
            to_param_index: 0,
        };

        // ── WITH linkage ──────────────────────────────────────────────────────
        let mut host_with = FuzzHost::new(StdScheduler::new(), work_dir.to_string());
        host_with.set_code(
            addr_a,
            Bytecode::new_raw(RevmBytes::from(return_slot0_bytes.clone())),
            &mut state,
        );
        host_with.set_code(
            addr_b,
            Bytecode::new_raw(RevmBytes::from(check_nonce_bytes.clone())),
            &mut state,
        );
        let mut fuzz_executor_with =
            make_fuzz_executor_with_value_capture(host_with);

        let top_with = campaign_input(steps.clone(), vec![linkage], initial_sstate.clone());
        let mut z = StubFuzzer;
        let mut em = StubFuzzer;
        fuzz_executor_with
            .run_target(&mut z, &mut state, &mut em, &top_with)
            .unwrap();

        // The exploit step (check-nonce) must NOT have reverted when linkage routed
        // the captured NONCE into its calldata.
        let result_with = state.get_execution_result();
        assert!(
            !result_with.reverted,
            "EO-04 WITH linkage: exploit step must succeed when nonce is routed"
        );

        // ── WITHOUT linkage ───────────────────────────────────────────────────
        let mut host_without = FuzzHost::new(StdScheduler::new(), work_dir.to_string());
        host_without.set_code(
            addr_a,
            Bytecode::new_raw(RevmBytes::from(return_slot0_bytes)),
            &mut state,
        );
        host_without.set_code(
            addr_b,
            Bytecode::new_raw(RevmBytes::from(check_nonce_bytes)),
            &mut state,
        );
        let mut fuzz_executor_without =
            make_fuzz_executor_with_value_capture(host_without);

        let top_without = campaign_input(steps, vec![], initial_sstate); // no linkages
        let mut z2 = StubFuzzer;
        let mut em2 = StubFuzzer;
        fuzz_executor_without
            .run_target(&mut z2, &mut state, &mut em2, &top_without)
            .unwrap();

        // Without linkage the nonce slot stays zero → mismatch → REVERT.
        let result_without = state.get_execution_result();
        assert!(
            result_without.reverted,
            "EO-04 WITHOUT linkage: exploit step must revert when nonce slot is zero"
        );

        let _ = std::fs::remove_dir_all(work_dir);
    }
}

// implement HasObservers trait for ItyFuzzer
impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI> HasObservers
    for FuzzExecutor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, OT, CI>
where
    I: VMInputT<VS, Loc, Addr, CI>,
    S: State + UsesInput<Input = I>,
    OT: ObserversTuple<S>,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    /// Get the observers
    fn observers(&self) -> &OT {
        &self.observers
    }

    /// Get the observers (mutable)
    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}
