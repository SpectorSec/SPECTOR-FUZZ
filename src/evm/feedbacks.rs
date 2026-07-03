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
use libafl_bolts::{impl_serdeany, Named};
use libafl::state::HasMetadata;
use serde::{Deserialize, Serialize};

use super::{input::EVMInput, types::EVMFuzzState};
use crate::{
    evm::{input::{ConciseEVMInput, EVMInputTy}, middlewares::sha3_bypass::Sha3TaintAnalysis, vm::EVMExecutor},
    evm::planner::{CampaignInflowBoundaries, PromotionCandidate},
    generic_vm::vm_state::VMStateT,
    input::VMInputT,
    r#const::INFANT_STATE_INITIAL_VOTES,
    scheduler::HasVote,
    state::{HasExecutionResult, HasInfantStateState, InfantStateState},
    evm::{types::{EVMAddress, EVMQueueExecutor, EVMU512}, vm::EVMState},
};

use revm_primitives::ruint::Uint;
type EVMU256 = Uint<256, 4>;

use std::cell::Cell;

use super::middlewares::cmp_linearity::TaintDim;

thread_local! {
    /// Feature 015 — the AMPLIFY objective (Decision A: raw attacker inflow drives the
    /// ledger-secant hot path; net-realized ETH stays the survivor selector at `:394`).
    /// `TokenBalanceFeedback` publishes the summed raw attacker inflow here every
    /// execution WHEN `reflexive_lever` is on; the mutator's `apply_ledger_secant` reads
    /// it at probe boundaries. Thread-local so each per-core fuzzing loop has its own
    /// objective (publish + read happen on the same thread within one iteration) — no
    /// lock, no `unsafe`. Stays `0` when the feature is off (never written).
    static LEDGER_OBJECTIVE: Cell<u128> = const { Cell::new(0) };
    /// Feature 016 Phase 3 — last detected dimension flow type from the taint
    /// analysis reexecution. Set after CmpLinearityTaint runs, read by the mutator's
    /// `apply_ledger_secant` to bias probe delta and mutation energy.
    static DIMENSION_FLOW: Cell<TaintDim> = const { Cell::new(TaintDim::Generic) };
}

/// Publish this execution's raw-inflow objective (Feature 015). Only called when
/// `reflexive_lever` is on, so off-path this global is never touched.
pub fn publish_ledger_objective(value: u128) {
    LEDGER_OBJECTIVE.with(|c| c.set(value));
}

/// Read the last published raw-inflow objective (Feature 015). `0` before any publish.
pub fn read_ledger_objective() -> u128 {
    LEDGER_OBJECTIVE.with(|c| c.get())
}

/// Feature 016 Phase 3 — publish the detected dimension flow type from the taint
/// analysis reexecution. Called from `Sha3WrappedFeedback::is_interesting()` after
/// CmpLinearityTaint runs.
pub fn publish_located_dim(dim: TaintDim) {
    DIMENSION_FLOW.with(|c| c.set(dim));
}

/// Read the last published dimension flow type. `Generic` before any publish.
pub fn read_located_dim() -> TaintDim {
    DIMENSION_FLOW.with(|c| c.get())
}

/// Feature 013 Phase 6 — arg-to-storage provenance for ledger secant LOCATE.
/// Maps (contract, slot) → u64 bitmap of calldata arg indices that contributed
/// to the SSTORE. Populated from `FuzzHost.arg_slot_provenance` after each
/// CmpLinearityTaint reexecution. Read by `apply_ledger_secant` to skip
/// sweeping args that never touch any storage slot for the pin contract.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ArgStorageProvenance {
    pub per_slot: HashMap<(EVMAddress, EVMU256), u64>,
}
impl_serdeany!(ArgStorageProvenance);

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
            // Phase 0: run injection taint analysis BEFORE oracles fire so
            // INJECTION_CONFIRMED_EXPLOIT_PATH is live when they evaluate.
            #[cfg(feature = "concolic_secant_dispatch")]
            if !input.is_step() {
                // Reset per-execution static flags for all 013/014 features.
                crate::evm::middlewares::cmp_linearity::injection_reset_static();
                crate::evm::middlewares::oracle_tracker::OracleTracker::reset_static();
                crate::evm::middlewares::oracle_staleness::OracleStaleness::reset_static();
                crate::evm::middlewares::empty_state_guard::EmptyStateGuard::reset_static();
                crate::evm::middlewares::flashloan_oracle::FlashloanOracle::reset_static();
                crate::evm::middlewares::dos_detector::DoSDetector::reset_static();

                let lin = std::rc::Rc::new(std::cell::RefCell::new(
                    crate::evm::middlewares::cmp_linearity::CmpLinearityTaint::new(),
                ));
                (self.evm_executor.deref().borrow_mut())
                    .reexecute_with_middleware(input, state, lin);
                // Feature 013 Phase 2+5: four-link chain verdict.
                crate::evm::middlewares::cmp_linearity::injection_chain_verdict();
                unsafe {
                    crate::evm::middlewares::cmp_linearity::INJECTION_ANALYSIS_RAN = true;
                }
                // Feature 016 Phase 3: publish the detected dimension flow type.
                {
                    use crate::evm::middlewares::cmp_linearity::{
                        PRICE_MANIPULATION_FLOW, PROXY_TAINT_FLOW, ACCUMULATOR_INFLATION_FLOW,
                        TIMESTAMP_TAINT_WRITTEN, TIMESTAMP_DIM_LOCATED,
                    };
                    let dim = if unsafe { PRICE_MANIPULATION_FLOW } {
                        TaintDim::Price
                    } else if unsafe { ACCUMULATOR_INFLATION_FLOW } {
                        TaintDim::Accumulator
                    } else if unsafe { PROXY_TAINT_FLOW } {
                        TaintDim::Generic  // proxy tag — not a dimension itself
                    } else {
                        TaintDim::Generic
                    };
                    publish_located_dim(dim);
                    // Feature 017 Wire B: publish Timestamp-dim-located alongside located_dim.
                    // True when any SSTORE wrote a value with ts_seen=true during reexecution.
                    unsafe {
                        TIMESTAMP_DIM_LOCATED = TIMESTAMP_TAINT_WRITTEN;
                    }
                }
                // Feature 013 Phase 6: snapshot arg-slot provenance for the
                // ledger secant LOCATE phase (reads it during mutation).
                let prov = self.evm_executor.deref().borrow().host.arg_slot_provenance.clone();
                if !prov.is_empty() {
                    state.add_metadata(ArgStorageProvenance { per_slot: prov });
                }
            }

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

                        // Feature 009a + 013: CmpLinearityTaint reexecution already
                        // completed above (before inner feedback), populating both the
                        // linearity verdict and injection chain. No second reexecution.
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
    /// Feature 015: when true, publish this execution's summed raw attacker inflow to
    /// `LEDGER_OBJECTIVE` so the ledger-secant can amplify the promoted lever. Purely
    /// additive — the survivor selection (net-ETH ceiling) is unchanged.
    reflexive_lever: bool,
}

impl<SC> TokenBalanceFeedback<SC> {
    pub fn new(
        attackers: HashSet<EVMAddress>,
        scheduler: SC,
        eth_gradient: bool,
        evm_executor: Option<Rc<RefCell<EVMQueueExecutor>>>,
        reflexive_lever: bool,
    ) -> Self {
        Self {
            attackers,
            best_inflow: HashMap::new(),
            scheduler,
            eth_gradient,
            evm_executor,
            best_eth_total: EVMU512::ZERO,
            reflexive_lever,
        }
    }

    /// Feature 015 Phase 2 (a-posteriori Promote): attribute per-step attacker inflow across
    /// an armed campaign and record the single largest ledger-moving belly call as a
    /// `PromotionCandidate`. The atomic campaign accumulates one ordered `erc20_transfers` log;
    /// the executor stamped step-boundary offsets (`CampaignInflowBoundaries`) so step `i`'s
    /// transfers are the slice `[offsets[i]..offsets[i+1]]`. We keep only the highest-inflow
    /// step above `APOSTERIORI_MIN_INFLOW` (one lever/frame — bounds over-promotion against the
    /// 3.5GB ceiling), and only replace the incumbent on a strictly larger delta (high-water).
    /// The mutator later pins the matching step into `promoted` for Locate+Amplify.
    ///
    /// Entirely gated: fires only when `reflexive_lever` is on and the campaign was armed
    /// (`aposteriori && promoted.is_empty()`), so off-path it is a couple of cheap checks.
    fn record_aposteriori_candidate(&self, state: &mut EVMFuzzState, input: &EVMInput) {
        let Some(campaign) = &input.campaign else { return };
        if !campaign.aposteriori || !campaign.promoted.is_empty() {
            return;
        }

        // Snapshot transfers + revert flag, then drop the execution-result borrow so the
        // metadata write below can take &mut state.
        let (transfers, reverted) = {
            let result = state.get_execution_result();
            (
                result.new_state.state.erc20_transfers.clone(),
                result.reverted,
            )
        };
        if reverted {
            return;
        }

        // Boundary offsets recorded by the campaign executor (one per step + a trailing close).
        let offsets = match state.metadata_map().get::<CampaignInflowBoundaries>() {
            Some(b) if b.offsets.len() == campaign.steps.len() + 1 => b.offsets.clone(),
            _ => return,
        };

        // Attribute per-step attacker inflow; keep the single largest mover above the floor.
        let Some((idx, inflow)) = best_inflow_step(
            &campaign.steps,
            &transfers,
            &offsets,
            &self.attackers,
            APOSTERIORI_MIN_INFLOW,
        ) else {
            return;
        };
        let step = &campaign.steps[idx];
        let selector = step.data.as_ref().map(|d| d.function).unwrap_or_default();
        let contract = step.contract;

        // High-water: only a strictly larger delta unseats the incumbent candidate.
        let incumbent = state
            .metadata_map()
            .get::<PromotionCandidate>()
            .filter(|c| c.set)
            .map(|c| c.best_inflow)
            .unwrap_or(0);
        if inflow > incumbent {
            tracing::info!(
                "[aposteriori-tel] promotion candidate: step={} contract={:?} selector=0x{} inflow={}",
                idx, contract, hex::encode(selector), inflow
            );
            state.add_metadata(PromotionCandidate {
                contract,
                selector,
                best_inflow: inflow,
                set: true,
            });
        }
    }
}

/// Feature 015 Phase 2 — dust floor for a-posteriori promotion: an attributed per-step
/// attacker inflow must clear this to be a candidate (rejects rounding/refund noise). 1e15 raw
/// units ≈ 0.001 of an 18-decimal token; below-decimal tokens (e.g. 6-dec USDC) clear it at
/// ~1e9 human units, which is well past dust. A live-tuning parameter, deliberately generous.
const APOSTERIORI_MIN_INFLOW: u128 = 1_000_000_000_000_000;

/// Feature 015 Phase 2 — pure per-step attacker-inflow attribution. Given the campaign's
/// ordered `erc20_transfers` log, the executor's boundary `offsets` (`len == steps.len()+1`,
/// so step `i`'s transfers are `[offsets[i]..offsets[i+1]]`), the attacker set and a dust
/// floor, return the `(step_index, inflow)` of the SINGLE largest ledger-moving belly call, or
/// `None`. Borrow and selector-less steps are skipped (nothing to pin/tune). Extracted from
/// `record_aposteriori_candidate` so the attribution is unit-testable without a live fork.
fn best_inflow_step(
    steps: &[ConciseEVMInput],
    transfers: &[(EVMAddress, EVMAddress, EVMAddress, EVMU256)],
    offsets: &[usize],
    attackers: &HashSet<EVMAddress>,
    min_inflow: u128,
) -> Option<(usize, u128)> {
    if offsets.len() != steps.len() + 1 {
        return None;
    }
    let mut best: Option<(usize, u128)> = None;
    for (i, step) in steps.iter().enumerate() {
        if step.input_type == EVMInputTy::Borrow || step.data.is_none() {
            continue;
        }
        let (lo, hi) = (offsets[i], offsets[i + 1]);
        if hi <= lo || hi > transfers.len() {
            continue;
        }
        let mut sum = EVMU256::ZERO;
        for (_token, _from, to, value) in &transfers[lo..hi] {
            if attackers.contains(to) && *value > EVMU256::ZERO {
                sum = sum.saturating_add(*value);
            }
        }
        let inflow = evmu256_to_u128_sat_fb(sum);
        if inflow >= min_inflow && best.map_or(true, |(_, b)| inflow > b) {
            best = Some((i, inflow));
        }
    }
    best
}

/// Feature 011 (Part A) test seam: sum the realized-ETH value of a set of
/// per-(attacker, token) inflows, valuing each via the injected `value_one`.
///
/// In production `value_one` calls the liquidation engine
/// (`EVMExecutor::value_token_inflow_eth`); in tests it is a fake rate table, so the
/// value-inversion decision (expensive-small pile out-ranks cheap-large pile) is
/// unit-testable without a live engine or an `EVMFuzzState`. Inflows the valuator
/// cannot price (`None`) are skipped.
/// Feature 015 — saturating EVMU256 → u128 (the ledger objective is u128, matching the
/// secant's arg-amount domain). Values above 2^128 clamp to `u128::MAX`.
fn evmu256_to_u128_sat_fb(v: EVMU256) -> u128 {
    let limbs = v.as_limbs(); // [u64; 4], little-endian
    if limbs[2] != 0 || limbs[3] != 0 {
        u128::MAX
    } else {
        ((limbs[1] as u128) << 64) | (limbs[0] as u128)
    }
}

fn aggregate_eth_inflow(
    inflow_pairs: &HashMap<(EVMAddress, EVMAddress), EVMU256>,
    mut value_one: impl FnMut(EVMAddress, EVMAddress, EVMU256) -> Option<EVMU512>,
) -> EVMU512 {
    let mut total = EVMU512::ZERO;
    for ((attacker, token), amount) in inflow_pairs {
        if let Some(delta) = value_one(*attacker, *token, *amount) {
            total = total.saturating_add(delta);
        }
    }
    total
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

        // Feature 015: publish the raw-inflow AMPLIFY objective on EVERY execution
        // (reverts / zero-inflow ⇒ 0) BEFORE any early return, so the ledger-secant reads
        // a wrong lever amount as a drop rather than a stale value. One cheap scan,
        // engine-free, only when the flag is on ⇒ off-path this global is never written.
        if self.reflexive_lever {
            let obj: u128 = if result.reverted {
                0
            } else {
                let mut sum = EVMU256::ZERO;
                for (_token, _from, to, value) in &result.new_state.state.erc20_transfers {
                    if self.attackers.contains(to) && *value > EVMU256::ZERO {
                        sum = sum.saturating_add(*value);
                    }
                }
                evmu256_to_u128_sat_fb(sum)
            };
            publish_ledger_objective(obj);
        }

        // Feature 015 Phase 2 (a-posteriori Promote): discover the ledger-moving belly call
        // and record it as a promotion candidate. Self-gates on an armed campaign, so this is
        // inert unless `--reflexive-lever` is on AND the planner found no a-priori archetype.
        if self.reflexive_lever {
            self.record_aposteriori_candidate(state, input);
        }

        // Re-borrow the execution result after the (possibly &mut) candidate write above.
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
        // restore the post-state we install here). The aggregation itself lives in the
        // pure `aggregate_eth_inflow` seam so the value-inversion logic is unit-testable
        // without a live engine (the closure is the injection point).
        let post_state = state.get_execution_result().new_state.state.clone();
        // Cost/credit already accrued this execution (same scale!() units the engine
        // credits, so directly comparable to the gross inflow value below):
        //   owed   = ETH the attacker spent/borrowed (msg.value, flashloan principal)
        //   earned = native ETH already returned to the attacker
        let owed = post_state.flashloan_data.owed;
        let prior_earned = post_state.flashloan_data.earned;

        let gross_eth = {
            let mut exec = executor.deref().borrow_mut();
            let original = exec.host.evmstate.clone();
            exec.host.evmstate = post_state;
            let total = aggregate_eth_inflow(&inflow_pairs, |attacker, token, amount| {
                exec.value_token_inflow_eth(attacker, token, amount, state)
            });
            exec.host.evmstate = original;
            total
        };

        // NET realized value, not gross. Ranking by gross inflow chases flashloan-funded
        // swaps (e.g. borrow 4722 ETH → buy USDC) that look enormous but net ~0 after
        // the spend — observed live on the Yearn fork. Subtracting `owed` makes the
        // gradient climb actual profit: the mirage collapses to 0, a real drain stands.
        let net_eth = net_realized(gross_eth, prior_earned, owed);

        // Interesting iff a new realized-NET-ETH ceiling. This is what makes the gradient
        // value-aware: a small pile of an expensive token out-ranks a large pile of a
        // thin-liquidity token (SC-2), and a big-but-unprofitable swap out-ranks nothing.
        if net_eth > self.best_eth_total {
            self.best_eth_total = net_eth;
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

/// Feature 011 (Part A) — net realized value of an execution, in `scale!()` units.
///
/// `gross` = ETH value of attacker token inflows (liquidated via the engine),
/// `earned` = native ETH already returned to the attacker, `owed` = ETH the attacker
/// spent/borrowed. Net = (gross + earned) − owed, saturating at 0: a position that
/// cost more than it returned is not profit and must not advance the gradient.
/// Pure and unit-tested so the gross-vs-net decision is pinned independent of the engine.
fn net_realized(gross: EVMU512, earned: EVMU512, owed: EVMU512) -> EVMU512 {
    gross.saturating_add(earned).saturating_sub(owed)
}

#[cfg(test)]
mod impact_011_tests {
    use super::*;

    fn addr(b: u8) -> EVMAddress {
        EVMAddress::from([b; 20])
    }

    /// T6 / SC-3 (unit proxy): with the flag off the feedback is constructed inert —
    /// no engine ref is held, so `is_interesting` takes the original early-return path
    /// and the new code is unreachable. (Full byte-for-byte e2e regression is the
    /// Lane-A run, T8.)
    #[test]
    fn eth_gradient_off_is_inert() {
        let fb = TokenBalanceFeedback::<()>::new(HashSet::new(), (), false, None, false);
        assert!(!fb.eth_gradient, "flag must default off");
        assert!(fb.evm_executor.is_none(), "no engine ref when flag off");
        assert_eq!(fb.best_eth_total, EVMU512::ZERO);
    }

    /// T7 / SC-2: the gradient must rank by realized ETH, not raw token units. A large
    /// pile of a cheap token has more *units* but a small pile of an expensive token has
    /// more *ETH* — the ETH valuation must invert the raw-unit ranking.
    #[test]
    fn eth_value_beats_token_units() {
        let attacker = addr(1);
        let cheap = addr(0xC); // 1 wei/unit
        let expensive = addr(0xE); // 1_000_000 wei/unit

        let cheap_large: HashMap<(EVMAddress, EVMAddress), EVMU256> =
            [((attacker, cheap), EVMU256::from(1_000_000u64))].into_iter().collect();
        let expensive_small: HashMap<(EVMAddress, EVMAddress), EVMU256> =
            [((attacker, expensive), EVMU256::from(10u64))].into_iter().collect();

        // Fake valuator: ETH = rate(token) * amount. No engine, no EVMFuzzState.
        let mut value_one = |_a: EVMAddress, token: EVMAddress, amount: EVMU256| -> Option<EVMU512> {
            let amt = amount.to::<u64>() as u128;
            let rate: u128 = if token == cheap {
                1
            } else if token == expensive {
                1_000_000
            } else {
                0
            };
            Some(EVMU512::from(rate * amt))
        };

        let eth_cheap = aggregate_eth_inflow(&cheap_large, &mut value_one);
        let eth_expensive = aggregate_eth_inflow(&expensive_small, &mut value_one);

        // Raw token units would rank the cheap pile higher...
        assert!(
            EVMU256::from(1_000_000u64) > EVMU256::from(10u64),
            "cheap pile has more raw units"
        );
        // ...but realized ETH inverts it — which is the whole point of the feature.
        assert!(
            eth_expensive > eth_cheap,
            "expensive-small pile ({eth_expensive}) must out-rank cheap-large pile ({eth_cheap}) in ETH"
        );
    }

    /// Inflows the valuator cannot price are skipped, not counted as zero-blocking.
    #[test]
    fn unpriceable_inflows_are_skipped() {
        let pairs: HashMap<(EVMAddress, EVMAddress), EVMU256> =
            [((addr(1), addr(2)), EVMU256::from(5u64))].into_iter().collect();
        let total = aggregate_eth_inflow(&pairs, |_, _, _| None);
        assert_eq!(total, EVMU512::ZERO);
    }

    /// The gross-inflow mirage: a flashloan-funded swap acquires a huge gross inflow
    /// but spends just as much (owed). Net must collapse to 0 so it does NOT advance
    /// the gradient — this is the live Yearn finding (4722 ETH swap, ~0 net) encoded.
    #[test]
    fn gross_mirage_nets_zero() {
        let huge = EVMU512::from(4_722_000_000_000_000_000_000u128); // ~4722 ETH gross
        let owed = EVMU512::from(4_722_000_000_000_000_000_000u128); // spent the same
        assert_eq!(net_realized(huge, EVMU512::ZERO, owed), EVMU512::ZERO);

        // A position that cost MORE than it returned is a loss → saturates to 0, never negative.
        let loss = net_realized(EVMU512::from(100u64), EVMU512::ZERO, EVMU512::from(150u64));
        assert_eq!(loss, EVMU512::ZERO);
    }

    /// A real drain (little spent, much extracted) yields positive net and out-ranks
    /// the mirage — the gradient now climbs profit, not gross.
    #[test]
    fn real_profit_beats_mirage() {
        let real = net_realized(EVMU512::from(6u64), EVMU512::ZERO, EVMU512::from(1u64)); // drain
        let mirage = net_realized(
            EVMU512::from(4_722_000u64),
            EVMU512::ZERO,
            EVMU512::from(4_722_000u64),
        ); // big swap, ~0 net
        assert!(real > mirage, "real profit ({real}) must out-rank gross mirage ({mirage})");
        assert_eq!(mirage, EVMU512::ZERO);
    }

    // ── Feature 015 Phase 2 (T10) — a-posteriori per-step inflow attribution ──

    use crate::evm::abi::{AEmpty, BoxedABI};
    use crate::evm::input::{ConciseEVMInput, EVMInputTy};

    /// A campaign step: `Borrow` (no data) or an `ABI` call carrying an (empty) BoxedABI so
    /// `data.is_some()`. `best_inflow_step` only checks presence, not the selector bytes.
    fn step(borrow: bool, with_data: bool) -> ConciseEVMInput {
        ConciseEVMInput {
            input_type: if borrow { EVMInputTy::Borrow } else { EVMInputTy::ABI },
            data: if with_data { Some(BoxedABI::new(Box::new(AEmpty {}))) } else { None },
            ..Default::default()
        }
    }

    /// One erc20 transfer tuple `(token, from, to, value)`.
    fn xfer(to: EVMAddress, v: u128) -> (EVMAddress, EVMAddress, EVMAddress, EVMU256) {
        (addr(0xAA), addr(0xBB), to, EVMU256::from(v))
    }

    const E18: u128 = 1_000_000_000_000_000_000;

    /// The single largest ledger-moving belly call is attributed to its step. Steps:
    /// 0=borrow (skipped), 1=big inflow, 2=small inflow. Boundaries carve the ordered log.
    #[test]
    fn aposteriori_attributes_largest_step() {
        let attacker = addr(1);
        let attackers: HashSet<EVMAddress> = [attacker].into_iter().collect();
        let steps = [step(true, false), step(false, true), step(false, true)];
        // step1 = transfers[0..2] (8e18), step2 = transfers[2..3] (1e18); borrow slice empty.
        let transfers = vec![
            xfer(attacker, 5 * E18),
            xfer(attacker, 3 * E18),
            xfer(attacker, 1 * E18),
        ];
        let offsets = vec![0usize, 0, 2, 3]; // len == steps+1
        let got = best_inflow_step(&steps, &transfers, &offsets, &attackers, APOSTERIORI_MIN_INFLOW);
        assert_eq!(got, Some((1, 8 * E18)), "step 1 is the biggest ledger mover");
    }

    /// Dust below the floor produces no candidate (rejects rounding/refund noise).
    #[test]
    fn aposteriori_rejects_below_threshold() {
        let attacker = addr(1);
        let attackers: HashSet<EVMAddress> = [attacker].into_iter().collect();
        let steps = [step(false, true), step(false, true)];
        let transfers = vec![xfer(attacker, 1_000u128), xfer(attacker, 2_000u128)];
        let offsets = vec![0usize, 1, 2];
        let got = best_inflow_step(&steps, &transfers, &offsets, &attackers, APOSTERIORI_MIN_INFLOW);
        assert_eq!(got, None, "sub-floor dust must not become a candidate");
    }

    /// Borrow steps and selector-less steps are skipped even with huge inflow in their slice
    /// (a flashloan credit is not the lever). Only the real ABI call is attributed.
    #[test]
    fn aposteriori_skips_borrow_and_selectorless() {
        let attacker = addr(1);
        let attackers: HashSet<EVMAddress> = [attacker].into_iter().collect();
        // 0=borrow (huge), 1=selector-less (huge), 2=real ABI (moderate).
        let steps = [step(true, false), step(false, false), step(false, true)];
        let transfers = vec![
            xfer(attacker, 100 * E18), // borrow slice
            xfer(attacker, 50 * E18),  // selector-less slice
            xfer(attacker, 2 * E18),   // real ABI slice
        ];
        let offsets = vec![0usize, 1, 2, 3];
        let got = best_inflow_step(&steps, &transfers, &offsets, &attackers, APOSTERIORI_MIN_INFLOW);
        assert_eq!(got, Some((2, 2 * E18)), "only the tunable ABI step is a candidate");
    }

    /// Inflow to a non-attacker address is not the adversary's ledger → no candidate.
    #[test]
    fn aposteriori_ignores_non_attacker_inflow() {
        let attackers: HashSet<EVMAddress> = [addr(1)].into_iter().collect();
        let steps = [step(false, true)];
        let transfers = vec![xfer(addr(9), 100 * E18)]; // to a stranger, not the attacker
        let offsets = vec![0usize, 1];
        let got = best_inflow_step(&steps, &transfers, &offsets, &attackers, APOSTERIORI_MIN_INFLOW);
        assert_eq!(got, None, "non-attacker inflow is not promotable");
    }

    /// Malformed boundaries (`offsets.len() != steps.len()+1`) are rejected defensively.
    #[test]
    fn aposteriori_rejects_malformed_offsets() {
        let attackers: HashSet<EVMAddress> = [addr(1)].into_iter().collect();
        let steps = [step(false, true), step(false, true)];
        let transfers = vec![xfer(addr(1), 100 * E18)];
        let bad = vec![0usize, 1]; // len 2, needs 3
        assert_eq!(best_inflow_step(&steps, &transfers, &bad, &attackers, 0), None);
    }
}
