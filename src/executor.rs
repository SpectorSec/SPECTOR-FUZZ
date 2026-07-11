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
/// argument slot of an EVMInput's calldata.  Mirrors the `write_calldata_arg_u128`
/// pattern in mutator.rs but writes the full 32-byte word (EVMU256) instead of the
/// lower 16 bytes, since `observed_values` stores full EVMU256 return values.
///
/// Offset layout: selector (4 bytes) + arg_index * 32 bytes.  If the calldata is
/// shorter than required the write is silently skipped (safe no-op, same guard as
/// the mutator pattern).
#[cfg(feature = "evm")]
fn apply_linkage_arg(input: &mut EVMInput, param_index: usize, value: EVMU256) {
    use bytes::Bytes;
    use crate::evm::input::EVMInputT;
    let mut data = input.to_bytes();
    let offset = 4 + param_index * 32;
    if offset + 32 > data.len() {
        return;
    }
    let bytes = value.to_be_bytes::<32>();
    data[offset..offset + 32].copy_from_slice(&bytes);
    input.set_direct_data(Bytes::from(data));
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
