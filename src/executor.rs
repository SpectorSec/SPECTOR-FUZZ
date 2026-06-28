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

                    for (i, step_ci) in steps.iter().enumerate().take(steps.len() - 1) {
                        let (mut step_input, _) = step_ci.to_input(current_state.clone());
                        // Apply warp delta before execute, so vm.rs:598 picks up the warped env
                        if let Some(delta) = campaign.warps.iter().find(|(idx, _)| *idx == i).map(|(_, d)| d) {
                            step_input.env.block.number += EVMU256::from(*delta);
                            step_input.env.block.timestamp += EVMU256::from(*delta * 12);
                        }
                        let step_ref: &I = unsafe { &*(&step_input as *const EVMInput as *const I) };
                        let res = self.vm.deref().borrow_mut().execute(step_ref, state);
                        state.set_execution_result(res);
                        // Capture intermediate state for oracle consumption
                        intermediate_states.push(current_state);
                        if state.get_execution_result().reverted {
                            return Ok(ExitKind::Ok);
                        }
                        current_state = unsafe {
                            let generic_ref: &StagedVMState<Loc, Addr, VS, CI> = &state.get_execution_result().new_state;
                            let concrete_ref: &EVMStagedVMState = &*(generic_ref as *const StagedVMState<Loc, Addr, VS, CI> as *const EVMStagedVMState);
                            concrete_ref.clone()
                        };
                    }

                    let last_idx = steps.len() - 1;
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

                    let (mut last_input, _) = steps.last().unwrap().to_input(current_state);
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
                    return Ok(ExitKind::Ok);
                }
            }
        }

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
