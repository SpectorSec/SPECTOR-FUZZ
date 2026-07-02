use std::fmt::Debug;

use bytes::Bytes;
use libafl::{
    inputs::Input,
    mutators::MutationResult,
    prelude::{HasMaxSize, HasRand, Mutator, State},
    schedulers::Scheduler,
    state::{HasCorpus, HasMetadata},
    Error,
};
use alloy_sol_types::SolCall;
use foundry_cheatcodes::Vm;
use libafl_bolts::{prelude::{Rand, StdRand}, Named};
use revm_interpreter::{interpreter_types::Jumps, Interpreter};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::onchain::flashloan::CAN_LIQUIDATE;
/// Mutator for EVM inputs
use crate::evm::input::{CampaignSequence, EVMInputT, NestedAction};
use crate::evm::oracles::{TrustedCallerMetadata, WhaleAddressMetadata};
use crate::evm::planner::{plan_campaign_sampled, CampaignTargetCache};
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
    /// Calldata argument indices (0-based, arg = offset / 32) that were loaded
    /// via CALLDATALOAD during execution. Used for Application B secant.
    pub calldata_args: Vec<usize>,
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
            calldata_args: vec![],
        }
    }

    /// Record access pattern of current opcode executed by the interpreter
    pub fn decode_instruction(&mut self, interp: &Interpreter) {
        match interp.bytecode.opcode() {
            0x31 => self.balance.push(convert_u256_to_h160(interp.stack.peek(0).unwrap())),
            0x33 => self.caller = true,
            0x3a => self.gas_price = true,
            0x35 => {
                // CALLDATALOAD: load 32 bytes from calldata at offset (top of stack)
                // Track which calldata argument index was accessed: arg = offset / 32
                if let Ok(offset) = interp.stack.peek(0) {
                    let offset_u64 = crate::evm::types::as_u64(offset);
                    if offset_u64 % 32 == 0 {
                        let arg_idx = (offset_u64 / 32) as usize;
                        if !self.calldata_args.contains(&arg_idx) {
                            self.calldata_args.push(arg_idx);
                        }
                    }
                }
            }
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

// ── Snapshot-secant CMP_MAP helpers (Applications B/C/E) ────────────────────
//
// CMP_MAP is a global, never-reset, monotonically-decreasing min-map. A
// derivative needs two INDEPENDENT same-PC measurements, so the secant pins one
// index and resets it to MAX before each measuring execution. All distance math
// is u128 (not as_u64) to preserve wei-scale accrual/value distances.

/// Saturating EVMU256 → u128. `as_u64` (types.rs) takes only limb 0 and would
/// truncate wei-scale distances — exactly the accrual case Application C targets.
#[cfg(feature = "cmp")]
fn evmu256_to_u128_sat(d: EVMU256) -> u128 {
    let l = d.as_limbs(); // little-endian [u64; 4]
    if l[2] != 0 || l[3] != 0 {
        u128::MAX
    } else {
        (l[0] as u128) | ((l[1] as u128) << 64)
    }
}

/// Argmin over CMP_MAP at full 256-bit width. Returns
/// (pinned_index, owner_fingerprint, distance). The owner fingerprint pins the
/// specific comparison so later reads can detect slot aliasing (Checkpoint 8.3).
/// # Safety: reads the global CMP_MAP / CMP_PC statics.
#[cfg(feature = "cmp")]
unsafe fn cmp_argmin() -> Option<(usize, u64, u128)> {
    let mut best: Option<(usize, EVMU256)> = None;
    for (i, &d) in crate::evm::host::CMP_MAP.iter().enumerate() {
        if d > EVMU256::ZERO && d < EVMU256::MAX && best.map_or(true, |(_, bd)| d < bd) {
            best = Some((i, d));
        }
    }
    best.map(|(i, d)| (i, crate::evm::host::CMP_PC[i], evmu256_to_u128_sat(d)))
}

// Time-gated (warp) secant targeting now lives in the campaign executor via
// controlled probes; it reads the temporal maps through `host::temporal_*`. The
// former mutator-side copies (cmp_argmin_temporal / cmp_t_read_at / cmp_t_reset_at)
// were removed as redundant.

/// Read the distance at a pinned index, validating that the slot still belongs
/// to the pinned comparison (`expect_fp`). `None` if the slot was untouched
/// (MAX) this run OR a colliding comparison/JUMPI has taken it — in which case
/// the secant aborts rather than computing a blended slope.
/// # Safety: reads the global CMP_MAP / CMP_PC statics.
#[cfg(feature = "cmp")]
unsafe fn cmp_read_at(idx: usize, expect_fp: u64) -> Option<u128> {
    if crate::evm::host::CMP_PC[idx] != expect_fp {
        return None; // aliasing/clobber detected — do not blend two comparisons
    }
    let d = crate::evm::host::CMP_MAP[idx];
    if d >= EVMU256::MAX {
        None
    } else {
        Some(evmu256_to_u128_sat(d))
    }
}

/// Reset a pinned index (distance → MAX, owner → none) so the next execution
/// measures it fresh. This is what makes the two probes independent
/// per-execution measurements.
/// # Safety: writes the global CMP_MAP / CMP_PC statics.
#[cfg(feature = "cmp")]
unsafe fn cmp_reset_at(idx: usize) {
    crate::evm::host::CMP_MAP[idx] = EVMU256::MAX;
    crate::evm::host::CMP_PC[idx] = 0;
}

/// Pure secant computation shared by all three aiming applications (the heart of
/// the method, extracted so it is unit-testable in isolation).
///
/// Given input value `x1` at measurement 1, distance `d1` measured at `x1` and
/// `d2` measured at `x1 + delta`, returns the input value estimated to flip the
/// comparison:  `x* = x1 + d1·delta / (d1 − d2)`.
/// Returns `None` when the gradient is flat (`d1 <= d2`) — the input is not the
/// lever for this comparison (saturated accrual, time-independent check, or an
/// aliasing abort that surfaced as no distance change). All math is u128 so
/// wei-scale accrual/value distances are preserved (u64 / `as_u64` would
/// truncate exactly the case these applications exist for).
#[cfg(feature = "cmp")]
fn secant_step(x1: u128, d1: u128, d2: u128, delta: u128) -> Option<u128> {
    let dd = d1.saturating_sub(d2);
    if dd == 0 {
        return None;
    }
    let step = d1.saturating_mul(delta).saturating_div(dd);
    Some(x1.saturating_add(step))
}

/// Feature 015 — secant on the ledger's DERIVATIVE (finds an interior profit peak).
///
/// The value/calldata secants ([`secant_step`]) drive one monotone comparison distance
/// to zero. A reflexive-skew lever is different: pushing the amount too far *reverses*
/// the profit (over-skew pays more slippage than it steals), so the objective is a hump
/// and the target is its MAXIMUM — where the derivative crosses zero from `+` to `−`.
///
/// `g1`, `g2` are two signed slope samples of the objective, measured at `x1` and
/// `x1 + delta`. When they bracket a downward zero-crossing (`g1 > 0 > g2`) the peak lies
/// between the probes; linear-interpolate the derivative's root:
///   `x* = x1 + g1·delta / (g1 − g2)`.
/// Returns `None` on flat (`g1 == g2`), monotone (both slopes same sign — the peak, if
/// any, is outside this bracket), or a trough (`g1 < 0 < g2`, a minimum — never the
/// lever's profit peak). All value math is unsigned wei-scale (u128) to match the
/// arg-amount domain; only the slopes are signed.
fn secant_step_signed(x1: u128, g1: i128, g2: i128, delta: u128) -> Option<u128> {
    // Interior maximum only: derivative must fall through zero (`+` → `−`).
    if !(g1 > 0 && g2 < 0) {
        return None;
    }
    // g1 > 0 > g2 ⇒ (g1 − g2) > 0 and fits (our slopes are far from i128 extremes).
    let denom = g1.saturating_sub(g2) as u128;
    if denom == 0 {
        return None;
    }
    let step = (g1 as u128).saturating_mul(delta) / denom;
    Some(x1.saturating_add(step))
}

/// Feature 009 §5.3 stall→requeue fallback.
///
/// When the secant definitively gives up on a comparison (flat gradient,
/// `secant_step == None`), hand the CURRENT corpus input back to the concolic
/// queue. Without this, a gate that the dispatch triage routed AWAY from concolic
/// (classified linear) but the secant can't flip would be a LOST branch. Pushing
/// it onto `ConcolicPrioritizationMetadata.interesting_idx` guarantees concolic
/// still gets it → the linear/non-linear mis-route can never cost a branch.
///
/// Over-requeue is safe (concolic just runs on a few inputs the secant might have
/// solved later); under-requeue is not (regression). So this errs toward safety.
#[cfg(all(feature = "cmp", feature = "concolic_secant_dispatch"))]
fn requeue_for_concolic<S>(state: &mut S)
where
    S: HasCorpus + HasMetadata,
{
    use libafl::corpus::Corpus;
    if let Some(cur) = *state.corpus().current() {
        if let Some(meta) = state
            .metadata_map_mut()
            .get_mut::<crate::evm::concolic::concolic_stage::ConcolicPrioritizationMetadata>()
        {
            let idx: usize = usize::from(cur);
            if !meta.interesting_idx.contains(&idx) {
                meta.interesting_idx.push(idx);
                crate::evm::middlewares::cmp_linearity::lin_bump_requeued();
            }
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
    /// Enable Temporal Pre-condition Skimming (multi-block state priming).
    pub temporal_skimming: bool,
    /// Feature 015: enable reflexive-lever promotion (hoist the skew lever into the
    /// campaign frame so the ledger-secant can amount-tune it).
    pub reflexive_lever: bool,
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
    pub fn new(infant_scheduler: SC, campaign_orchestrator: bool, ghost_identities: bool, temporal_skimming: bool, reflexive_lever: bool) -> Self {
        Self {
            infant_scheduler,
            campaign_orchestrator,
            ghost_identities,
            temporal_skimming,
            reflexive_lever,
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


    /// Snapshot-secant for txn_value / msg.value (Application E).
    ///
    /// Same iteration-based secant as the warp variant, but probes the
    /// transaction value dimension instead.  Gate (a): only when CMP_MAP
    /// shows a near-flip.  Gate (b): only when call_value was accessed.
    #[cfg(feature = "cmp")]
    fn apply_value_secant<I, S>(&self, input: &mut I, state: &mut S) -> bool
    where
        I: VMInputT<VS, Loc, Addr, CI> + EVMInputT,
        S: HasMetadata + HasCorpus,
    {
        // Gate (b): only probe when call_value was actually accessed this run.
        let ap = input.get_access_pattern().borrow().clone();
        if !ap.call_value {
            return false;
        }

        let cmp_interesting = state
            .metadata_map()
            .get::<crate::feedback::CmpMetadata>()
            .map(|m| m.cmp_interesting)
            .unwrap_or(false);

        let mut secant = state
            .metadata_map()
            .get::<crate::feedback::ValueSecantState>()
            .cloned()
            .unwrap_or_default();

        const PROBE_DELTA: u128 = 1_000_000_000_000_000; // 0.001 ETH in wei
        const COOLDOWN: u32 = 8;

        let read_value = |input: &I| -> u128 {
            input.get_txn_value().map(evmu256_to_u128_sat).unwrap_or(0)
        };

        match secant.phase {
            crate::feedback::SecantPhase::Idle => {
                if secant.cooldown > 0 {
                    secant.cooldown -= 1;
                    state.metadata_map_mut().insert(secant);
                    return false;
                }
                if !cmp_interesting {
                    return false;
                }
                let Some((pin_idx, pin_pc, d)) = (unsafe { cmp_argmin() }) else { return false };
                if d == 0 {
                    return false;
                }
                let x1 = read_value(input);
                secant.pin_idx = pin_idx;
                secant.pin_pc = pin_pc;
                secant.x1 = x1;
                secant.phase = crate::feedback::SecantPhase::Probe1;
                unsafe { cmp_reset_at(pin_idx) };
                input.set_txn_value(EVMU256::from(x1));
                state.metadata_map_mut().insert(secant);
                true
            }
            crate::feedback::SecantPhase::Probe1 => {
                let Some(d1) = (unsafe { cmp_read_at(secant.pin_idx, secant.pin_pc) }) else {
                    secant.phase = crate::feedback::SecantPhase::Idle;
                    secant.cooldown = COOLDOWN;
                    state.metadata_map_mut().insert(secant);
                    return false;
                };
                secant.d1 = d1;
                let x2 = secant.x1.saturating_add(PROBE_DELTA);
                secant.phase = crate::feedback::SecantPhase::Probe2;
                unsafe { cmp_reset_at(secant.pin_idx) };
                input.set_txn_value(EVMU256::from(x2));
                state.metadata_map_mut().insert(secant);
                true
            }
            crate::feedback::SecantPhase::Probe2 => {
                let d2 = unsafe { cmp_read_at(secant.pin_idx, secant.pin_pc) }.unwrap_or(secant.d1);
                secant.phase = crate::feedback::SecantPhase::Idle;
                secant.cooldown = COOLDOWN;
                match secant_step(secant.x1, secant.d1, d2, PROBE_DELTA) {
                    None => {
                        // 009 §5.3: secant can't flip this gate — hand back to concolic.
                        #[cfg(feature = "concolic_secant_dispatch")]
                        requeue_for_concolic(state);
                        state.metadata_map_mut().insert(secant);
                        false
                    }
                    Some(correct) => {
                        input.set_txn_value(EVMU256::from(correct));
                        state.metadata_map_mut().insert(secant);
                        true
                    }
                }
            }
        }
    }

    /// Snapshot-secant for calldata arguments (Application B — arithmetic-threshold route).
    ///
    /// Probes every calldata argument accessed this execution.  Flat-gradient
    /// detection (slope ≈ 0) self-diagnoses non-lever arguments, so no explicit
    /// operand-to-argument mapping is required.
    #[cfg(feature = "cmp")]
    fn apply_calldata_secant<I, S>(&self, input: &mut I, state: &mut S) -> bool
    where
        I: VMInputT<VS, Loc, Addr, CI> + EVMInputT,
        S: HasMetadata + HasCorpus,
    {
        if !self.campaign_orchestrator {
            // Only run in campaign mode where ABI is known and we can mutate args
            return false;
        }

        let ap = input.get_access_pattern().borrow().clone();
        if ap.calldata_args.is_empty() {
            return false;
        }

        let cmp_interesting = state
            .metadata_map()
            .get::<crate::feedback::CmpMetadata>()
            .map(|m| m.cmp_interesting)
            .unwrap_or(false);

        let mut secant = state
            .metadata_map()
            .get::<crate::feedback::CalldataSecantState>()
            .cloned()
            .unwrap_or_default();

        const PROBE_DELTA: u128 = 100; // small delta for integer arguments
        const COOLDOWN: u32 = 8;

        // Probe exactly ONE argument per episode so the distance change is
        // attributable to that argument. `cursor` rotates across accessed args.
        let args = &ap.calldata_args;
        let arg_idx = args[secant.cursor % args.len()];

        match secant.phase {
            crate::feedback::SecantPhase::Idle => {
                if secant.cooldown > 0 {
                    secant.cooldown -= 1;
                    state.metadata_map_mut().insert(secant);
                    return false;
                }
                if !cmp_interesting {
                    return false;
                }
                let Some((pin_idx, pin_pc, d)) = (unsafe { cmp_argmin() }) else { return false };
                if d == 0 {
                    return false;
                }
                let x1 = self.read_calldata_arg_u128(input, arg_idx);
                secant.pin_idx = pin_idx;
                secant.pin_pc = pin_pc;
                secant.arg_idx = arg_idx;
                secant.x1 = x1;
                secant.phase = crate::feedback::SecantPhase::Probe1;
                unsafe { cmp_reset_at(pin_idx) };
                self.write_calldata_arg_u128(input, arg_idx, x1);
                state.metadata_map_mut().insert(secant);
                true
            }
            crate::feedback::SecantPhase::Probe1 => {
                let Some(d1) = (unsafe { cmp_read_at(secant.pin_idx, secant.pin_pc) }) else {
                    secant.phase = crate::feedback::SecantPhase::Idle;
                    secant.cooldown = COOLDOWN;
                    secant.cursor = secant.cursor.wrapping_add(1);
                    state.metadata_map_mut().insert(secant);
                    return false;
                };
                secant.d1 = d1;
                let x2 = secant.x1.saturating_add(PROBE_DELTA);
                secant.phase = crate::feedback::SecantPhase::Probe2;
                unsafe { cmp_reset_at(secant.pin_idx) };
                self.write_calldata_arg_u128(input, secant.arg_idx, x2);
                state.metadata_map_mut().insert(secant);
                true
            }
            crate::feedback::SecantPhase::Probe2 => {
                let d2 = unsafe { cmp_read_at(secant.pin_idx, secant.pin_pc) }.unwrap_or(secant.d1);
                secant.phase = crate::feedback::SecantPhase::Idle;
                secant.cooldown = COOLDOWN;
                secant.cursor = secant.cursor.wrapping_add(1); // rotate to next arg
                match secant_step(secant.x1, secant.d1, d2, PROBE_DELTA) {
                    None => {
                        // This argument is not the lever for the pinned comparison.
                        // 009 §5.3 (conservative): requeue for concolic. Over-requeue
                        // here (another arg may be the lever) is safe — never a
                        // regression; full-rotation gating is a future refinement.
                        #[cfg(feature = "concolic_secant_dispatch")]
                        requeue_for_concolic(state);
                        state.metadata_map_mut().insert(secant);
                        false
                    }
                    Some(correct) => {
                        self.write_calldata_arg_u128(input, secant.arg_idx, correct);
                        state.metadata_map_mut().insert(secant);
                        true
                    }
                }
            }
        }
    }

    /// Read a 32-byte calldata argument as u128 (lower 16 bytes)
    fn read_calldata_arg_u128<I>(&self, input: &I, arg_idx: usize) -> u128
    where
        I: VMInputT<VS, Loc, Addr, CI> + EVMInputT,
    {
        let data = input.to_bytes();
        let offset = 4 + arg_idx * 32; // skip selector
        if offset + 32 > data.len() {
            return 0;
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&data[offset + 16..offset + 32]); // lower 16 bytes
        u128::from_be_bytes(bytes)
    }

    /// Write a u64 to a 32-byte calldata argument slot
    fn write_calldata_arg_u128<I>(&self, input: &mut I, arg_idx: usize, value: u128)
    where
        I: VMInputT<VS, Loc, Addr, CI> + EVMInputT,
    {
        let mut data = input.to_bytes();
        let offset = 4 + arg_idx * 32;
        if offset + 32 > data.len() {
            return;
        }
        // Write to lower 16 bytes of the 32-byte word (EVM is big-endian)
        let bytes = value.to_be_bytes();
        data[offset + 16..offset + 32].copy_from_slice(&bytes);
        input.set_direct_data(Bytes::from(data));
    }

    /// Feature 015 — LOCATE + AMPLIFY on a promoted reflexive-skew lever.
    ///
    /// Unlike the value/calldata secants this reads the POST-execution realized-inflow
    /// ledger (`LEDGER_OBJECTIVE`, published by `TokenBalanceFeedback`) rather than the
    /// in-execution `CMP_MAP`, and it tunes an argument of a CAMPAIGN STEP (the promoted
    /// lever) rather than the top-level input. The whole campaign runs atomically in one
    /// `run_target`, so writing the lever's arg on this clone and reading the ledger next
    /// call closes the tune→execute→measure loop — the same clone-per-iteration contract
    /// the value-secant relies on (state lives in `metadata_map`, not on the input).
    ///
    /// LOCATE: rotate over the lever's args, probe each, keep the arg with the strongest
    /// |Δledger/Δarg| — that's the amount knob. AMPLIFY: gradient-ascend the knob toward
    /// the profit peak; when two consecutive local slopes bracket a `+→−` crossing, snap
    /// to the interpolated peak via `secant_step_signed`. NO concolic requeue: a flat
    /// ledger slope means "not the lever," never "hand to SMT."
    fn apply_ledger_secant<I, S>(&self, input: &mut I, state: &mut S) -> bool
    where
        I: VMInputT<VS, Loc, Addr, CI> + EVMInputT,
        S: HasMetadata + HasCorpus,
    {
        if !self.reflexive_lever {
            return false;
        }

        // Gate: the input must carry a campaign whose first promoted step has tunable args.
        let (pin_step, n_args) = {
            let Some(campaign) = input.get_campaign() else { return false };
            let Some(&pin) = campaign.promoted.first() else { return false };
            let Some(step) = campaign.steps.get(pin) else { return false };
            let n = step.data.as_ref().map(|a| a.get_bytes_vec().len() / 32).unwrap_or(0);
            (pin, n)
        };
        if n_args == 0 {
            return false; // no addressable arg words (e.g. an empty-ABI fixture) — nothing to tune.
        }

        // Scale-adaptive probe/march, floored so a planner default of 0 can still grow.
        const BASE: u128 = 1_000_000_000_000_000_000; // 1 token @ 18 decimals
        const MAX_ARG: u128 = 1_000_000_000 * BASE; // trust-region ceiling (1e9 tokens)
        const COOLDOWN: u32 = 8;

        let obj = crate::evm::feedbacks::read_ledger_objective();

        let mut s = state
            .metadata_map()
            .get::<crate::feedback::LedgerSecantState>()
            .cloned()
            .unwrap_or_default();
        // Re-plan drift: if the pinned frame changed under us, restart bookkeeping.
        if s.pin_step != pin_step || s.n_args != n_args {
            s = crate::feedback::LedgerSecantState { pin_step, n_args, ..Default::default() };
        }

        let arg = if s.located { s.arg_idx } else { s.locate_cursor % n_args };
        let probe_delta = (s.x1 / 16).max(BASE / 1000);

        match s.phase {
            crate::feedback::SecantPhase::Idle => {
                if s.cooldown > 0 {
                    s.cooldown -= 1;
                    state.metadata_map_mut().insert(s);
                    return false;
                }
                // Baseline x1 = the step's current arg value; pin it for this episode.
                let x1 = read_step_arg_u128(input.get_campaign(), pin_step, arg);
                s.x1 = x1;
                write_step_arg_u128(input.get_campaign_mut(), pin_step, arg, x1);
                s.phase = crate::feedback::SecantPhase::Probe1;
                state.metadata_map_mut().insert(s);
                true
            }
            crate::feedback::SecantPhase::Probe1 => {
                // `obj` is the ledger from the x1 execution → O1.
                s.o1 = obj;
                let x2 = s.x1.saturating_add(probe_delta).min(MAX_ARG);
                write_step_arg_u128(input.get_campaign_mut(), pin_step, arg, x2);
                s.phase = crate::feedback::SecantPhase::Probe2;
                state.metadata_map_mut().insert(s);
                true
            }
            crate::feedback::SecantPhase::Probe2 => {
                // `obj` is the ledger from the x1+δ execution → O2. Local slope over δ.
                let o2 = obj;
                let local_slope: i128 = (o2 as i128).saturating_sub(s.o1 as i128);
                s.phase = crate::feedback::SecantPhase::Idle;
                s.cooldown = COOLDOWN;

                if !s.located {
                    // LOCATE: record this arg's sensitivity, rotate to the next.
                    let sens = local_slope.unsigned_abs();
                    if sens > s.best_sens {
                        s.best_sens = sens;
                        s.best_arg = arg;
                    }
                    s.locate_cursor += 1;
                    if s.locate_cursor >= n_args {
                        if s.best_sens > 0 {
                            s.arg_idx = s.best_arg;
                            s.located = true;
                            s.prev_slope = None; // begin amplify fresh
                        } else {
                            // No arg moved the ledger this rotation → not the lever here.
                            s.locate_cursor = 0;
                        }
                    }
                    // Restore the baseline so the throwaway execution is neutral.
                    write_step_arg_u128(input.get_campaign_mut(), pin_step, arg, s.x1);
                    state.metadata_map_mut().insert(s);
                    return false;
                }

                // AMPLIFY: interpolate the peak on a `+→−` bracket, else march the knob.
                let next_x = match s.prev_slope {
                    Some(g_prev) if g_prev > 0 && local_slope < 0 && s.x1 > s.prev_x1 => {
                        secant_step_signed(s.prev_x1, g_prev, local_slope, s.x1 - s.prev_x1)
                            .unwrap_or(s.x1)
                    }
                    _ => {
                        // Multiplicative-ish trust-region march, floored for x1 == 0.
                        let march = (s.x1 / 2).max(BASE);
                        if local_slope > 0 {
                            s.x1.saturating_add(march)
                        } else if local_slope < 0 {
                            s.x1.saturating_sub(march)
                        } else {
                            s.x1 // flat: hold
                        }
                    }
                }
                .min(MAX_ARG);

                s.prev_x1 = s.x1;
                s.prev_slope = Some(local_slope);
                write_step_arg_u128(input.get_campaign_mut(), pin_step, arg, next_x);
                state.metadata_map_mut().insert(s);
                true
            }
        }
    }
}

/// Feature 015 — read a promoted campaign step's arg word as u128 (lower 16 bytes).
/// `0` when the step/arg is absent (empty ABI, out-of-range index).
fn read_step_arg_u128(campaign: &Option<CampaignSequence>, pin_step: usize, arg_idx: usize) -> u128 {
    let Some(c) = campaign else { return 0 };
    let Some(step) = c.steps.get(pin_step) else { return 0 };
    let Some(abi) = &step.data else { return 0 };
    let args = abi.get_bytes_vec();
    let off = arg_idx * 32;
    if off + 32 > args.len() {
        return 0;
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(&args[off + 16..off + 32]);
    u128::from_be_bytes(b)
}

/// Feature 015 — write a u128 into a promoted campaign step's arg word (lower 16 bytes,
/// big-endian) and re-encode the step's calldata. No-op when the step/arg is absent.
fn write_step_arg_u128(campaign: &mut Option<CampaignSequence>, pin_step: usize, arg_idx: usize, value: u128) {
    let Some(c) = campaign else { return };
    let Some(step) = c.steps.get_mut(pin_step) else { return };
    let Some(abi) = &mut step.data else { return };
    let mut args = abi.get_bytes_vec();
    let off = arg_idx * 32;
    if off + 32 > args.len() {
        return;
    }
    args[off + 16..off + 32].copy_from_slice(&value.to_be_bytes());
    // `set_bytes` strips the leading 4-byte selector; prepend it back.
    let full = [Vec::from(abi.function), args].concat();
    abi.set_bytes(full);
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
    S: State + HasRand + HasMaxSize + HasItyState<Loc, Addr, VS, CI> + HasCaller<Addr> + HasCaller<EVMAddress> + HasMetadata + HasPresets + HasCorpus,
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
                        // Telemetry: which call from the preset sequence the fuzzer serves,
                        // and where. Over a run this shows whether the exploit SHAPE engages
                        // (selectors called in the seeded order) — the controlled-experiment
                        // measurement of intelligence/data-flow alignment.
                        tracing::info!("[preset-tel] served selector=0x{} target={:?}", hex::encode(abi.function), addr);
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
                // Scale: base * (1 + (confidence/100) * bias). bias (--topology-bias) dials
                // the steer from floodlight (1.0) to nudge (0.3 default) to off (0.0).
                ((CAMPAIGN_CHOICE as f64) * (1.0 + (max_conf / 100.0) * hints.bias)).min(MUTATOR_SAMPLE_MAX as f64) as u64
            } else {
                CAMPAIGN_CHOICE
            };
            if state.rand_mut().below(MUTATOR_SAMPLE_MAX) < campaign_threshold {
                // Seed a local RNG from the fuzzer RNG so the planner can SAMPLE the
                // candidate pool (get_next_call-style) instead of first()/first().
                // Taken before the immutable metadata borrow below to avoid a
                // simultaneous &mut state / &state conflict.
                let mut plan_rand = StdRand::with_seed(state.rand_mut().next());
                if let Some(cache) = state.metadata_map().get::<CampaignTargetCache>() {
                    let topology_report = state.metadata_map().get::<TopologyReport>();
                    // No per-selector value anchor: the planner samples structure and the
                    // net-realized ledger (objective layer) selects economic survivors.
                    // The removed anchor read observed_values (ABI-return words), which
                    // misread approve's bool `true` as profit and skewed chains toward
                    // approve→approve. Economic truth now lives solely at the ledger.
                    if let Some(campaign) = plan_campaign_sampled(cache, topology_report, self.temporal_skimming, self.reflexive_lever, &mut plan_rand) {
                        // Telemetry: the multi-step CHAIN the fuzzer assembled — does it
                        // sequence the exploit selectors (add_liquidity -> remove_imbalance ->
                        // deposit/withdraw) into a real sentence, or just isolated words? This
                        // is the "builds the exploit vs speaks the vocabulary" measurement.
                        let chain: Vec<String> = campaign
                            .steps
                            .iter()
                            .map(|s| match s.input_type {
                                crate::evm::input::EVMInputTy::Borrow => "borrow".to_string(),
                                _ => match &s.data {
                                    Some(d) => format!("0x{}", hex::encode(d.function)),
                                    None => "?".to_string(),
                                },
                            })
                            .collect();
                        tracing::info!("[chain-tel] campaign: {}", chain.join(" -> "));
                        // Warp refinement is done by the campaign EXECUTOR via
                        // controlled probes (src/executor.rs) — clean, deterministic.
                        // The planner's base warp flows through unchanged here.
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

        // Application E: CMP_MAP-guided txn_value secant
        #[cfg(feature = "cmp")]
        if state.rand_mut().below(100) < 30 {
            let ap = input.get_access_pattern().borrow().clone();
            if ap.call_value {
                if self.apply_value_secant(input, state) {
                    mutated = true;
                }
            }
        }

        // Application B: CMP_MAP-guided calldata argument secant
        #[cfg(feature = "cmp")]
        if state.rand_mut().below(100) < 20 {
            if self.apply_calldata_secant(input, state) {
                mutated = true;
            }
        }

        // Feature 015: ledger-guided AMPLIFY of a promoted reflexive-skew lever. Not
        // cmp-gated (its signal is the post-execution ledger, not CMP_MAP); self-gates on
        // `reflexive_lever` + presence of a promoted step, so it is inert off-path.
        if self.reflexive_lever && state.rand_mut().below(100) < 40 {
            if self.apply_ledger_secant(input, state) {
                mutated = true;
            }
        }

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
                // Aim the re-entry by VALUE FLOW + CONTEXT (feedback), not oracle-flag
                // (forcing). The nested action is a re-entry/callback payload; we point it at:
                //   (1) contracts the LIVE target revealed value from (value-capture — where
                //       the money is actually moving), and
                //   (2) the contract we're currently interacting with (the natural reentrancy
                //       re-entry — you re-enter what you're calling),
                // falling back to the full contract set. This informs the aim from what the
                // program shows, instead of forcing it toward oracle-flagged addresses (which
                // include false positives). Oracle findings no longer steer the mutator here.
                let all_contracts: Vec<EVMAddress> = state
                    .metadata_map()
                    .get::<ABIAddressToInstanceMap>()
                    .map(|m| m.map.keys().cloned().collect())
                    .unwrap_or_default();

                let mut informed: Vec<EVMAddress> = Vec::new();
                // (1) value-flow: known contracts that produced observed return values.
                //     Match by the value_capture key prefix ("{addr:?}_...") — format-agnostic.
                if let Some(evm) = input.get_state().as_any().downcast_ref::<EVMState>() {
                    for addr in &all_contracts {
                        let prefix = format!("{:?}", addr);
                        if evm.observed_values.keys().any(|k| k.starts_with(&prefix)) {
                            informed.push(*addr);
                        }
                    }
                }
                // (Context — the contract being called — is already captured here: you call
                // it, it returns a value, so it lands in observed_values and thus in `informed`.
                // That's the natural reentrancy re-entry, arrived at via value flow.)

                let keys: Option<Vec<EVMAddress>> = if !informed.is_empty() {
                    Some(informed)
                } else if !all_contracts.is_empty() {
                    Some(all_contracts)
                } else {
                    None
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
            // Prevents getting stuck on a single function (e.g. deposit()).
            // Prefers contracts where value flows (value-capture feedback), not oracle-flagged
            // targets — informs the re-sample from the program, doesn't force it from our prior.
            if state.rand_mut().below(100) < 10 {
                let abi_map = state.metadata_map().get::<ABIAddressToInstanceMap>().cloned();

                if let Some(abi_map) = abi_map {
                    // Contracts the LIVE target revealed value from (value-capture). When any
                    // exist, prefer them; otherwise consider all. No oracle-flag forcing.
                    let value_flow: std::collections::HashSet<EVMAddress> = input
                        .get_state()
                        .as_any()
                        .downcast_ref::<EVMState>()
                        .map(|s| {
                            abi_map
                                .map
                                .keys()
                                .filter(|addr| {
                                    let prefix = format!("{:?}", addr);
                                    s.observed_values.keys().any(|k| k.starts_with(&prefix))
                                })
                                .cloned()
                                .collect()
                        })
                        .unwrap_or_default();

                    let mut candidates: Vec<(EVMAddress, BoxedABI)> = Vec::new();
                    for (addr, abis) in &abi_map.map {
                        if !value_flow.is_empty() && !value_flow.contains(addr) {
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

    // Serializes tests that mutate the global CMP_MAP/CMP_PC statics so they don't
    // race each other under parallel execution (cargo's default). Poison-tolerant.
    #[cfg(feature = "cmp")]
    static CMP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    #[test]
    fn test_temporal_balance_snapshot_serde_roundtrip() {
        use crate::evm::oracles::TemporalBalanceSnapshot;

        let token = EVMAddress::from([0xaa; 20]);
        let account = EVMAddress::from([0xbb; 20]);
        let key = format!("0x{:?}_0x{:?}", token, account);
        let mut balances = HashMap::new();
        balances.insert(key.clone(), EVMU256::from(1000u64));

        let snapshot = TemporalBalanceSnapshot {
            balances,
            pairs: vec![(token, account)],
            snapshot_block: EVMU256::from(42u64),
        };

        let encoded = serde_json::to_string(&snapshot).expect("serialize should succeed");
        let decoded: TemporalBalanceSnapshot = serde_json::from_str(&encoded).expect("deserialize should succeed");

        assert_eq!(decoded.balances.len(), 1);
        assert_eq!(decoded.balances[&key], EVMU256::from(1000u64));
        assert_eq!(decoded.pairs.len(), 1);
        assert_eq!(decoded.pairs[0], (token, account));
        assert_eq!(decoded.snapshot_block, EVMU256::from(42u64));
    }

    #[test]
    fn test_temporal_balance_snapshot_in_state() {
        use crate::evm::oracles::TemporalBalanceSnapshot;

        let mut state = EVMFuzzState::new(0);
        let token = EVMAddress::from([0xcc; 20]);
        let account = EVMAddress::from([0xdd; 20]);
        let key = format!("0x{:?}_0x{:?}", token, account);
        let mut balances = HashMap::new();
        balances.insert(key.clone(), EVMU256::from(500u64));

        state.metadata_map_mut().insert(TemporalBalanceSnapshot {
            balances,
            pairs: vec![(token, account)],
            snapshot_block: EVMU256::from(100u64),
        });

        let stored = state.metadata_map().get::<TemporalBalanceSnapshot>()
            .expect("TemporalBalanceSnapshot should exist");
        assert_eq!(stored.balances.len(), 1);
        assert_eq!(stored.balances[&key], EVMU256::from(500u64));
        assert_eq!(stored.pairs.len(), 1);
        assert_eq!(stored.snapshot_block, EVMU256::from(100u64));

        // Verify we can remove it (as the oracle does after consuming)
        state.metadata_map_mut().remove::<TemporalBalanceSnapshot>();
        assert!(state.metadata_map().get::<TemporalBalanceSnapshot>().is_none());
    }

    #[test]
    fn test_campaign_sequence_warps_default_empty() {
        let campaign = crate::evm::input::CampaignSequence {
            steps: Vec::new(),
            linkages: Vec::new(),
            warps: Vec::new(),
            promoted: Vec::new(),
        };
        assert!(campaign.warps.is_empty());
        assert!(campaign.promoted.is_empty());
        // Verify backward compatibility: default when deserialized from old format
        let json = r#"{"steps":[],"linkages":[]}"#;
        let decoded: crate::evm::input::CampaignSequence = serde_json::from_str(json).expect("should deserialize without warps field");
        assert!(decoded.warps.is_empty(), "warps should default to empty for backward compat");
        // Feature 015: pre-015 JSON (no `promoted` key) must default to empty.
        assert!(decoded.promoted.is_empty(), "promoted should default to empty for backward compat");
    }

    #[test]
    fn test_campaign_sequence_promoted_roundtrip() {
        // A populated `promoted` vec must survive a serde round-trip intact.
        let campaign = crate::evm::input::CampaignSequence {
            steps: Vec::new(),
            linkages: Vec::new(),
            warps: vec![(2, 10)],
            promoted: vec![1, 3],
        };
        let encoded = serde_json::to_string(&campaign).expect("serialize");
        let decoded: crate::evm::input::CampaignSequence =
            serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded.promoted, vec![1, 3], "promoted indices round-trip");
        assert_eq!(decoded.warps, vec![(2, 10)]);
    }

    #[test]
    fn test_ledger_secant_state_roundtrip() {
        use crate::feedback::{LedgerSecantState, SecantPhase};
        let s = LedgerSecantState {
            phase: SecantPhase::Probe2,
            pin_step: 2,
            n_args: 4,
            locate_cursor: 3,
            best_sens: 12345,
            best_arg: 1,
            located: true,
            arg_idx: 1,
            x1: 1_000_000_000_000_000_000,
            o1: 42,
            prev_x1: 500_000_000_000_000_000,
            prev_slope: Some(-77),
            cooldown: 8,
        };
        let encoded = serde_json::to_string(&s).expect("serialize");
        let d: LedgerSecantState = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(d.phase, SecantPhase::Probe2);
        assert_eq!(d.pin_step, 2);
        assert_eq!(d.n_args, 4);
        assert_eq!(d.arg_idx, 1);
        assert!(d.located);
        assert_eq!(d.x1, 1_000_000_000_000_000_000);
        assert_eq!(d.prev_slope, Some(-77));
        assert_eq!(d.cooldown, 8);
        // Default is a clean Idle/unlocated state.
        let def = LedgerSecantState::default();
        assert_eq!(def.phase, SecantPhase::Idle);
        assert!(!def.located);
        assert_eq!(def.prev_slope, None);
    }

    // ── Tier 1: snapshot-secant unit fixtures (Feature 008) ─────────────────
    // These validate the method's LOGIC deterministically, no fuzzer run needed.

    #[cfg(feature = "cmp")]
    #[test]
    fn test_secant_step_linear_accrual_exact() {
        // Linear accrual: distance(t) = threshold − rate·(t − t0).
        // rate=2, t0=0, threshold=1000 → true flip at t = 1000/2 = 500.
        // x1=10 → f=20 → d1=980 ; x2=110 → f=220 → d2=780 ; δ=100.
        assert_eq!(
            super::secant_step(10, 980, 780, 100),
            Some(500),
            "linear accrual must be exact in one secant step"
        );
    }

    #[test]
    fn test_secant_step_signed_finds_interior_peak() {
        // Symmetric hump: derivative +200 at x1=10, −200 at x1+δ=110.
        // Peak is exactly midway: x* = 10 + 200·100/(200−(−200)) = 10 + 50 = 60.
        assert_eq!(
            super::secant_step_signed(10, 200, -200, 100),
            Some(60),
            "bracketed +/− slopes must interpolate the derivative's root (the peak)"
        );
        // Asymmetric hump: slope still steep (+300) at x1, mildly negative (−100) at x1+δ
        // ⇒ peak sits closer to the RIGHT probe. x* = 10 + 300·100/400 = 85.
        assert_eq!(super::secant_step_signed(10, 300, -100, 100), Some(85));
    }

    #[test]
    fn test_secant_step_signed_none_when_not_a_peak() {
        // Monotone increasing (peak beyond the bracket) → None (step further, don't solve).
        assert_eq!(super::secant_step_signed(10, 200, 100, 100), None);
        // Monotone decreasing (past the peak / wrong side) → None.
        assert_eq!(super::secant_step_signed(10, -100, -200, 100), None);
        // Trough (derivative −→+, a MINIMUM) → None; never the profit peak.
        assert_eq!(super::secant_step_signed(10, -200, 200, 100), None);
        // Flat → None.
        assert_eq!(super::secant_step_signed(10, 0, 0, 100), None);
    }

    #[cfg(feature = "cmp")]
    #[test]
    fn test_secant_step_flat_gradient_aborts() {
        // d1 == d2 → input did not move the comparison → not the lever.
        assert_eq!(super::secant_step(10, 1000, 1000, 100), None);
        // d2 > d1 (distance grew) → saturating dd == 0 → also abort.
        assert_eq!(super::secant_step(10, 900, 1000, 100), None);
    }

    #[cfg(feature = "cmp")]
    #[test]
    fn test_secant_step_wei_scale_no_truncation() {
        // rate=1e18, threshold=1e24, t0=0 → true flip at 1e6.
        // This case overflows u64; as_u64 truncation would corrupt it.
        let e18: u128 = 1_000_000_000_000_000_000;
        let threshold: u128 = 1_000_000 * e18; // 1e24
        let d1 = threshold - 10 * e18; // x1=10  → f=1e19
        let d2 = threshold - 110 * e18; // x2=110 → f=1.1e20
        assert_eq!(
            super::secant_step(10, d1, d2, 100),
            Some(1_000_000),
            "wei-scale distances must not truncate"
        );
    }

    #[cfg(feature = "cmp")]
    #[test]
    fn test_evmu256_to_u128_sat() {
        let v = EVMU256::from(1u128 << 100);
        assert_eq!(super::evmu256_to_u128_sat(v), 1u128 << 100, "100-bit value preserved");
        let two_128 = EVMU256::from(u128::MAX) + EVMU256::from(1u64); // 2^128
        assert_eq!(super::evmu256_to_u128_sat(two_128), u128::MAX, "overflow saturates");
    }

    #[cfg(feature = "cmp")]
    #[test]
    fn test_cmp_ownership_validation_and_reset() {
        let _g = CMP_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let idx = 1000usize; // unique index, within MAP_SIZE (4096)
        unsafe {
            crate::evm::host::CMP_MAP[idx] = EVMU256::from(777u64);
            crate::evm::host::CMP_PC[idx] = 0xABCD;
            // Correct owner → reads the distance.
            assert_eq!(super::cmp_read_at(idx, 0xABCD), Some(777));
            // Wrong owner (aliasing / clobber) → None: never blends two comparisons.
            assert_eq!(super::cmp_read_at(idx, 0x1234), None);
            // Reset clears both arrays → subsequent read is None.
            super::cmp_reset_at(idx);
            assert_eq!(crate::evm::host::CMP_MAP[idx], EVMU256::MAX);
            assert_eq!(crate::evm::host::CMP_PC[idx], 0);
            assert_eq!(super::cmp_read_at(idx, 0xABCD), None);
        }
    }

    #[cfg(feature = "cmp")]
    #[test]
    fn test_cmp_owner_fp_nonzero_and_pc_sensitive() {
        let a = EVMAddress::default();
        let fp1 = crate::evm::host::cmp_owner_fp(a, 100);
        let fp2 = crate::evm::host::cmp_owner_fp(a, 101);
        assert_ne!(fp1, 0, "fingerprint must never be the 0 sentinel");
        assert_ne!(fp1, fp2, "distinct PCs must produce distinct fingerprints");
    }

}
