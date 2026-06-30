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
    evm::{types::{EVMAddress, EVMQueueExecutor, EVMU512}, vm::EVMState},
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
                    // Feature 009a: clear last input's linearity verdict so the
                    // concolic-dispatch triage never reads a stale value (step
                    // inputs get no reexecution → must default to "keep concolic").
                    #[cfg(feature = "concolic_secant_dispatch")]
                    crate::evm::middlewares::cmp_linearity::lin_reset_verdict();
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

                        // Feature 009a: classify this input's tainted comparisons
                        // (linear vs non-linear) for the concolic-dispatch triage.
                        // Only when concolic is enabled (it manages concolic budget) —
                        // verdict lands in cmp_linearity globals, read in
                        // ConcolicFeedbackWrapper::append_metadata.
                        #[cfg(feature = "concolic_secant_dispatch")]
                        if crate::evm::middlewares::cmp_linearity::lin_concolic_enabled() {
                            let lin = std::rc::Rc::new(std::cell::RefCell::new(
                                crate::evm::middlewares::cmp_linearity::CmpLinearityTaint::new(),
                            ));
                            (self.evm_executor.deref().borrow_mut())
                                .reexecute_with_middleware(input, state, lin);
                        }
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
    /// Feature 011 (Part A): when true, interestingness is gated on a new
    /// *realized-ETH* ceiling rather than the raw token-unit ceiling. When false
    /// the executor ref is `None` and this struct behaves exactly as before.
    eth_gradient: bool,
    /// Liquidation engine, used only when `eth_gradient` is on, to value token
    /// inflows in ETH via `EVMExecutor::value_token_inflow_eth`. Concrete
    /// `EVMQueueExecutor` (same ref the executor/concolic stage hold) so no extra
    /// generic param is threaded through the feedback tuple.
    evm_executor: Option<Rc<RefCell<EVMQueueExecutor>>>,
    /// Feature 011 (Part A): best realized-ETH total (raw `earned`-delta scale)
    /// seen across executions. A new max is the ETH-denominated interesting event.
    best_eth_total: EVMU512,
}

impl<SC> TokenBalanceFeedback<SC> {
    pub fn new(
        attackers: HashSet<EVMAddress>,
        scheduler: SC,
        eth_gradient: bool,
        evm_executor: Option<Rc<RefCell<EVMQueueExecutor>>>,
    ) -> Self {
        Self {
            attackers,
            best_inflow: HashMap::new(),
            scheduler,
            eth_gradient,
            evm_executor,
            best_eth_total: EVMU512::ZERO,
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

        // --- Original token-unit gradient (default, unchanged when flag off) ---
        if !self.eth_gradient {
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
            return Ok(new_ceiling);
        }

        // --- Feature 011 (Part A): realized-ETH gradient ---
        // Pre-filter: a token's raw inflow ceiling rising is a necessary condition
        // for more realized ETH, so only pay for engine valuation when it does.
        // (`best_inflow` was already updated above.)
        if !new_ceiling {
            return Ok(false);
        }
        let Some(executor) = self.evm_executor.clone() else {
            // Flag on but no engine ref wired: degrade to raw behavior rather than
            // silently dropping the signal.
            self.scheduler.vote(
                state.get_infant_state_state(),
                input.get_state_idx(),
                INFANT_STATE_INITIAL_VOTES * 5,
            );
            return Ok(true);
        };

        // Per-(attacker, token) inflows — the engine liquidates `amount` of `token`
        // transferred FROM the holder, so we must keep the holder, not collapse it.
        let mut inflow_pairs: HashMap<(EVMAddress, EVMAddress), EVMU256> = HashMap::new();
        for (token, _from, to, value) in &transfers {
            if self.attackers.contains(to) && *value > EVMU256::ZERO {
                *inflow_pairs.entry((*to, *token)).or_insert(EVMU256::ZERO) += *value;
            }
        }

        // Value each inflow against THIS execution's outcome, then restore the shared
        // executor exactly as found — valuation must be side-effect free
        // (`value_token_inflow_eth` snapshots/restores internally per call; we also
        // restore the post-state we install here).
        let post_state = state.get_execution_result().new_state.state.clone();
        let mut eth_total = EVMU512::ZERO;
        {
            let mut exec = executor.deref().borrow_mut();
            let original = exec.host.evmstate.clone();
            exec.host.evmstate = post_state;
            for ((attacker, token), amount) in &inflow_pairs {
                if let Some(delta) = exec.value_token_inflow_eth(*attacker, *token, *amount, state) {
                    eth_total = eth_total.saturating_add(delta);
                }
            }
            exec.host.evmstate = original;
        }

        // Interesting iff a new realized-ETH ceiling. This is what makes the gradient
        // value-aware: a small pile of an expensive token now out-ranks a large pile
        // of a thin-liquidity token (SC-2).
        if eth_total > self.best_eth_total {
            self.best_eth_total = eth_total;
            self.scheduler.vote(
                state.get_infant_state_state(),
                input.get_state_idx(),
                INFANT_STATE_INITIAL_VOTES * 5,
            );
            return Ok(true);
        }
        Ok(false)
    }
}
