use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt::{Debug, Formatter},
    ops::Deref,
    rc::Rc,
};

use libafl::{
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    observers::ObserversTuple,
    prelude::Testcase,
    schedulers::Scheduler,
    Error,
};
use libafl_bolts::Named;

use super::{input::EVMInput, types::EVMFuzzState};
use crate::{
    evm::{input::ConciseEVMInput, middlewares::sha3_bypass::Sha3TaintAnalysis, vm::EVMExecutor},
    generic_vm::vm_state::VMStateT,
    input::VMInputT,
    r#const::INFANT_STATE_INITIAL_VOTES,
    scheduler::HasVote,
    state::{HasExecutionResult, HasInfantStateState, InfantStateState},
    evm::{types::EVMAddress, vm::EVMState},
};

use revm_primitives::ruint::Uint;
type EVMU256 = Uint<256, 4>;

/// A wrapper around a feedback that also performs sha3 taint analysis
/// when the feedback is interesting.
#[allow(clippy::type_complexity)]
pub struct Sha3WrappedFeedback<VS, F, SC>
where
    VS: VMStateT,
    F: Feedback<EVMFuzzState>,
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    pub inner_feedback: Box<F>,
    pub sha3_taints: Rc<RefCell<Sha3TaintAnalysis>>,
    pub evm_executor: Rc<RefCell<EVMExecutor<VS, ConciseEVMInput, SC>>>,
    pub enabled: bool,
}

impl<VS, F, SC> Feedback<EVMFuzzState> for Sha3WrappedFeedback<VS, F, SC>
where
    VS: VMStateT + 'static,
    F: Feedback<EVMFuzzState>,
    SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
{
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut EVMFuzzState,
        manager: &mut EM,
        input: &EVMInput,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = EVMFuzzState>,
        OT: ObserversTuple<EVMFuzzState>,
    {
        // checks if the inner feedback is interesting
        if self.enabled {
            match self
                .inner_feedback
                .is_interesting(state, manager, input, observers, exit_kind)
            {
                Ok(true) => {
                    if !input.is_step() {
                        // reexecute with sha3 taint analysis
                        // Use full_reset (not cleanup) so ctxs / prev_opcode /
                        // prev_dirty_len from the previous re-execution don't
                        // leak into this one. Plain cleanup() only resets
                        // dirty_memory/storage/stack — the call/return ctx
                        // stack and prev-opcode telemetry both need to be
                        // reset too or the assertion trips at pc=0 of the
                        // first opcode in the new execution.
                        self.sha3_taints.deref().borrow_mut().full_reset();

                        (self.evm_executor.deref().borrow_mut()).reexecute_with_middleware(
                            input,
                            state,
                            self.sha3_taints.clone(),
                        );
                    }
                    Ok(true)
                }
                Ok(false) => Ok(false),
                Err(e) => Err(e),
            }
        } else {
            self.inner_feedback
                .is_interesting(state, manager, input, observers, exit_kind)
        }
    }

    #[inline]
    #[allow(unused_variables)]
    fn append_metadata<OT>(
        &mut self,
        state: &mut EVMFuzzState,
        observers: &OT,
        testcase: &mut Testcase<EVMInput>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<EVMFuzzState>,
    {
        self.inner_feedback.as_mut().append_metadata(state, observers, testcase)
    }
}

impl<VS, F, SC> Sha3WrappedFeedback<VS, F, SC>
where
    VS: VMStateT,
    F: Feedback<EVMFuzzState>,
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    #[allow(clippy::type_complexity)]
    pub(crate) fn new(
        inner_feedback: F,
        sha3_taints: Rc<RefCell<Sha3TaintAnalysis>>,
        evm_executor: Rc<RefCell<EVMExecutor<VS, ConciseEVMInput, SC>>>,
        enabled: bool,
    ) -> Self {
        Self {
            inner_feedback: Box::new(inner_feedback),
            sha3_taints,
            evm_executor,
            enabled,
        }
    }
}

impl<VS, F, SC> Named for Sha3WrappedFeedback<VS, F, SC>
where
    VS: VMStateT,
    F: Feedback<EVMFuzzState>,
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    fn name(&self) -> &str {
        todo!()
    }
}

impl<VS, F, SC> Debug for Sha3WrappedFeedback<VS, F, SC>
where
    VS: VMStateT,
    F: Feedback<EVMFuzzState>,
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    fn fmt(&self, _f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        todo!()
    }
}

/// TokenBalanceFeedback — the fund-loss gradient signal.
///
/// Tracks the maximum ERC-20 value extracted to any attacker address in a
/// single execution, per token. When a new maximum is reached the state is
/// marked interesting and the infant-state scheduler votes heavily for that VM
/// snapshot, causing the fuzzer to keep climbing until extraction plateaus.
///
/// This is NOT a bug detector — that's OracleFeedback. This is the gravity
/// that pulls every oracle waypoint (reentrancy, invariant, approval) toward
/// maximum fund extraction. The fuzzer stops when best_inflow stops growing.
/// That ceiling is the bounty number.
pub struct TokenBalanceFeedback<SC> {
    /// Attacker-controlled addresses whose inflows we track.
    attackers: HashSet<EVMAddress>,
    /// Per-token maximum total attacker inflow seen in a single execution.
    /// Monotonically increasing — a new max means a new interesting state.
    best_inflow: HashMap<EVMAddress, EVMU256>,
    scheduler: SC,
}

impl<SC> TokenBalanceFeedback<SC> {
    pub fn new(attackers: HashSet<EVMAddress>, scheduler: SC) -> Self {
        Self {
            attackers,
            best_inflow: HashMap::new(),
            scheduler,
        }
    }
}

impl<SC> Debug for TokenBalanceFeedback<SC> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenBalanceFeedback")
            .field("tokens_tracked", &self.best_inflow.len())
            .finish()
    }
}

impl<SC> Named for TokenBalanceFeedback<SC> {
    fn name(&self) -> &str {
        "TokenBalanceFeedback"
    }
}

impl<SC> Feedback<EVMFuzzState> for TokenBalanceFeedback<SC>
where
    SC: Scheduler<State = InfantStateState<EVMAddress, EVMAddress, EVMState, ConciseEVMInput>>
        + HasVote<InfantStateState<EVMAddress, EVMAddress, EVMState, ConciseEVMInput>>,
{
    fn init_state(&mut self, _state: &mut EVMFuzzState) -> Result<(), Error> {
        Ok(())
    }

    fn is_interesting<EMI, OT>(
        &mut self,
        state: &mut EVMFuzzState,
        _manager: &mut EMI,
        input: &EVMInput,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EMI: EventFirer<State = EVMFuzzState>,
        OT: ObserversTuple<EVMFuzzState>,
    {
        let result = state.get_execution_result();
        if result.reverted {
            return Ok(false);
        }

        let transfers = result.new_state.state.erc20_transfers.clone();
        if transfers.is_empty() {
            return Ok(false);
        }

        // Sum total inflow to attacker addresses per token in this execution.
        let mut inflow_by_token: HashMap<EVMAddress, EVMU256> = HashMap::new();
        for (token, _from, to, value) in &transfers {
            if self.attackers.contains(to) && *value > EVMU256::ZERO {
                *inflow_by_token.entry(*token).or_insert(EVMU256::ZERO) += *value;
            }
        }

        if inflow_by_token.is_empty() {
            return Ok(false);
        }

        // Check if any token hit a new extraction ceiling.
        let mut new_ceiling = false;
        for (token, inflow) in &inflow_by_token {
            let best = self.best_inflow.entry(*token).or_insert(EVMU256::ZERO);
            if inflow > best {
                *best = *inflow;
                new_ceiling = true;
            }
        }

        if new_ceiling {
            // Vote aggressively for this VM snapshot so the fuzzer prioritizes
            // exploring further from this state. 5x base votes — profitable
            // states deserve far more attention than coverage-only states.
            self.scheduler.vote(
                state.get_infant_state_state(),
                input.get_state_idx(),
                INFANT_STATE_INITIAL_VOTES * 5,
            );
        }

        Ok(new_ceiling)
    }
}
