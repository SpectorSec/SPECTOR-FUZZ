use std::{collections::HashMap, fmt::Debug, marker::PhantomData};

/// Corpus schedulers for ItyFuzz
/// Used to determine which input / VMState to fuzz next
use libafl::corpus::Corpus;
use libafl::{
    corpus::Testcase,
    prelude::{CorpusId, HasMetadata, HasTestcase, UsesInput},
    schedulers::{RemovableScheduler, Scheduler},
    state::{HasCorpus, State, UsesState},
    Error,
};
use libafl_bolts::impl_serdeany;
use revm_primitives::HashSet;
use serde::{Deserialize, Serialize};

use super::{
    host::{BRANCH_STATUS, BRANCH_STATUS_IDX},
    feedbacks::CompoundSequenceCanary,
    planner::{PromotionCandidate, PromotionCandidates},
    topology::TopologyHints,
    types::EVMAddress,
};
use crate::{
    evm::{
        abi::FUNCTION_SIG,
        blaz::builder::{ArtifactInfoMetadata, BuildJobResult},
        corpus_initializer::EVMInitializationArtifacts,
        input::EVMInput,
        middlewares::cmp_linearity::TaintDim,
    },
    input::VMInputT,
    power_sched::{PowerMutationalStageWithId, TestcaseScoreWithId},
    r#const::{MAX_POWER, MIN_POWER, POWER_MULTIPLIER},
};

/// The status of the branch, whether it is covered on true, false or both
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum BranchCoveredStatus {
    /// The branch is covered on true
    True,
    /// The branch is covered on false
    False,
    /// The branch is covered on both true and false
    Both,
}

impl BranchCoveredStatus {
    fn merge(&self, branch_status: bool) -> (Self, bool) {
        match self {
            Self::Both => (Self::Both, false),
            Self::True => {
                if branch_status {
                    (Self::True, false)
                } else {
                    (Self::Both, true)
                }
            }
            Self::False => {
                if branch_status {
                    (Self::Both, true)
                } else {
                    (Self::False, false)
                }
            }
        }
    }

    fn from(branch_status: bool) -> Self {
        if branch_status {
            Self::True
        } else {
            Self::False
        }
    }
}

/// The Metadata for uncovered branches
#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct UncoveredBranchesMetadata {
    branch_to_testcases: HashMap<(EVMAddress, usize), HashSet<CorpusId>>,
    testcase_to_uncovered_branches: HashMap<CorpusId, usize>,
    branch_status: HashMap<(EVMAddress, usize), BranchCoveredStatus>,
}

impl Default for UncoveredBranchesMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl UncoveredBranchesMetadata {
    /// Create new [`struct@UncoveredBranchesMetadata`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            branch_to_testcases: HashMap::new(),
            testcase_to_uncovered_branches: HashMap::new(),
            branch_status: HashMap::new(),
        }
    }
}

impl_serdeany!(UncoveredBranchesMetadata);

/// The Metadata for each testcase used in ABI power schedules.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct PowerABITestcaseMetadata {
    /// Number of lines in source code, initialized in on_add
    lines: usize,
    /// How many times this testcase has received a topology boost.
    /// Used to decay the boost: effective_boost = base * 0.95^topology_hits.
    /// Prevents the fuzzer from getting trapped in a local optimum on
    /// topology-predicted paths that don't actually yield oracle fires.
    pub topology_hits: u32,
    /// Feature 026 Phase A — how many times this testcase received the
    /// Promote→Scheduler economic boost. Sibling of `topology_hits` so the two
    /// pressures decay independently (a topology-shaped step and a promoted
    /// lever are different signals). `#[serde(default)]` = corpus
    /// back-compat.
    #[serde(default)]
    pub promote_hits: u32,
    /// Feature 026 Phase B — the economic dimension this testcase's execution
    /// exhibited, snapshotted from the (per-execution) flow-flags at mint
    /// time (on_add). Enables the `dim_flow→scheduler` energy steer without
    /// reading `static mut` flags at score time.
    #[serde(default)]
    pub located_dim: TaintDim,
    /// Feature 026 Phase B — decay counter for the dimension boost (sibling of
    /// the other two).
    #[serde(default)]
    pub dim_hits: u32,
    /// Feature 037 — testcase-local snapshot that this execution produced both
    /// attacker inflow and oracle divergence. Scheduler scoring must read this
    /// stamped value, not the global current-execution canary.
    #[serde(default)]
    pub compound_sequence: bool,
    /// Feature 037 — decay counter for the compound-sequence boost.
    #[serde(default)]
    pub compound_hits: u32,
    /// INV-016 — testcase-local timestamp located warp scheduling flag.
    #[serde(default)]
    pub timestamp_located: bool,
}

impl PowerABITestcaseMetadata {
    /// Create new [`struct@SchedulerTestcaseMetadata`]
    #[must_use]
    pub fn new(lines: usize) -> Self {
        Self {
            lines,
            topology_hits: 0,
            promote_hits: 0,
            located_dim: TaintDim::Generic,
            dim_hits: 0,
            compound_sequence: false,
            compound_hits: 0,
            timestamp_located: false,
        }
    }
}

/// Feature 026 Phase A — the Promote→Scheduler energy multiplier at a given
/// decay tick. Pure, unit-testable (cf. the 025 `secant_promotable` precedent).
/// `PROMOTE_BOOST` is the full early boost applied to an input exercising the
/// promoted (contract, selector); it decays exponentially with each hit (mirror
/// of the topology gamma-ray boost) so a promoted lever gets front-loaded
/// pressure without permanently trapping the search:   hits=0 → 2.0x   ·
/// hits→∞ → 1.0x (neutral).
fn promote_boost(hits: u32) -> f64 {
    const PROMOTE_BOOST: f64 = 2.0;
    let decay = 0.95_f64.powi(hits as i32);
    1.0 + (PROMOTE_BOOST - 1.0) * decay
}

/// Feature 037 — modest, decaying scheduler boost for testcases whose own
/// execution produced the compound sequence canary (inflow + divergence).
fn compound_boost(hits: u32) -> f64 {
    const COMPOUND_BOOST: f64 = 1.5;
    let decay = 0.95_f64.powi(hits as i32);
    1.0 + (COMPOUND_BOOST - 1.0) * decay
}

/// Feature 035 — magnitude-aware extra multiplier on top of the presence-based
/// `promote_boost`. Log-scaled so it needs no per-kind calibration: ln(1+x) compresses
/// any magnitude range (wei amounts, relocation counts, violation distances) onto the
/// same curve. magnitude=0 → 1.0 exactly (byte-identical to pre-035 for presence-only
/// candidates like Permission's best_inflow=0). Bounded above by MAGNITUDE_BOOST_MAX so
/// no single large Value inflow can permanently dominate the schedule.
fn magnitude_boost(best_inflow: u128) -> f64 {
    const MAGNITUDE_BOOST_MAX: f64 = 1.5;
    const MAGNITUDE_LOG_SCALE: f64 = 1e18; // ~1 ETH in wei — curve approaches cap here
    if best_inflow == 0 {
        return 1.0;
    }
    let x = (best_inflow as f64 + 1.0).ln();
    let scale = MAGNITUDE_LOG_SCALE.ln();
    let ratio = (x / scale).clamp(0.0, 1.0);
    1.0 + (MAGNITUDE_BOOST_MAX - 1.0) * ratio
}

/// Feature 026 Phase B — classify the just-executed input's economic dimension
/// from the (per-execution) flow-flags, called at testcase-mint time (on_add).
/// Most-specific wins: PRICE > ACCUMULATOR > Generic. The flags are `static
/// mut` set during execution and not yet cleared at on_add (no intervening
/// execution), so this is a best-effort per-testcase snapshot. Fail-safe:
/// Generic ⇒ no boost ⇒ byte-identical to pre-026-B.
fn classify_flow_dim() -> TaintDim {
    use crate::evm::middlewares::cmp_linearity::{ACCUMULATOR_INFLATION_FLOW, PRICE_MANIPULATION_FLOW};
    unsafe {
        if PRICE_MANIPULATION_FLOW {
            TaintDim::Price
        } else if ACCUMULATOR_INFLATION_FLOW {
            TaintDim::Accumulator
        } else {
            TaintDim::Generic
        }
    }
}

/// Feature 026 Phase B — the `dim_flow→scheduler` energy multiplier:
/// PRICE→high, ACCUMULATOR→med, everything else neutral (dot line 241 weights).
/// Decays `0.95^hits` like the promote/topology boosts (sibling `dim_hits`) so
/// an economic dimension gets front-loaded budget without trapping.
/// Floors at 1.0 (never penalises). Pure, unit-testable.
fn dim_boost(dim: TaintDim, hits: u32) -> f64 {
    let base = match dim {
        TaintDim::Price => 1.75,
        TaintDim::Accumulator => 1.4,
        // Generic / Timestamp / Balance carry no scheduler dim-steer (Timestamp is a PRIME-phase
        // warp lever, not a mutation-energy dimension; Balance is coarse and already coverage-led).
        _ => return 1.0,
    };
    let decay = 0.95_f64.powi(hits as i32);
    1.0 + (base - 1.0) * decay
}

impl_serdeany!(PowerABITestcaseMetadata);

#[derive(Debug, Clone)]
pub struct PowerABIScheduler<S> {
    phantom: PhantomData<S>,
}

impl<S> Default for PowerABIScheduler<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> PowerABIScheduler<S> {
    pub fn new() -> Self {
        Self { phantom: PhantomData }
    }

    fn add_abi_metadata(&mut self, testcase: &mut Testcase<EVMInput>, artifact: &BuildJobResult) -> Result<(), Error> {
        let input = testcase.input().clone().unwrap();
        let tc_func = match input.get_data_abi() {
            Some(abi) => abi.function,
            None => {
                testcase.add_metadata(PowerABITestcaseMetadata::new(1));
                return Ok(()); // Some EVMInput don't have abi, like borrow
            }
        };
        let tc_func_name = unsafe {
            FUNCTION_SIG.get(&tc_func).unwrap_or_else(|| {
                panic!(
                    "function signature {} @ {:?} not found in FUNCTION_SIG",
                    hex::encode(tc_func),
                    input.get_contract()
                )
            })
        };
        let tc_func_slug = {
            let amount_args = tc_func_name.matches(',').count() + {
                if tc_func_name.contains("()") {
                    0
                } else {
                    1
                }
            };
            let name = tc_func_name.split('(').next().unwrap();
            format!("{}:{}", name, amount_args)
        };
        for (_filename, ast) in artifact.asts.iter() {
            let contracts = ast["contracts"].as_array().unwrap();
            for contract in contracts {
                let funcs = contract["functions"].as_array().unwrap();
                for func in funcs {
                    let func_slug = {
                        let arg_len = func["args"].as_array().unwrap().len();
                        let name = func["name"].as_str().unwrap();
                        format!("{}:{}", name, arg_len)
                    };

                    if tc_func_slug == func_slug {
                        let func_source = func["source"].as_str().unwrap();
                        let num_lines = func_source.matches('\n').count() + 1;
                        if num_lines <= 1 {
                            break; // not true function implementation, break to
                                   // find in next contract
                        }
                        testcase.add_metadata(PowerABITestcaseMetadata::new(num_lines));
                        return Ok(());
                    }
                }
            }
        }
        // NOTE: testcase function is [0,0,0,0] !fallback!
        testcase.add_metadata(PowerABITestcaseMetadata::new(1));
        Ok(())
    }
}

impl<S> UsesState for PowerABIScheduler<S>
where
    S: State + UsesInput,
{
    type State = S;
}

impl<S> Scheduler for PowerABIScheduler<S>
where
    S: State + HasCorpus<Input = EVMInput> + HasTestcase + HasMetadata,
{
    fn on_add(&mut self, state: &mut Self::State, idx: CorpusId) -> Result<(), Error> {
        // Feature 026 Phase B — snapshot the economic dimension NOW: the flow-flags
        // reflect the just-executed interesting input and no execution
        // intervenes before on_add.
        let flow_dim = classify_flow_dim();
        // Feature 037 — snapshot compound-sequence telemetry NOW. This converts
        // current-execution metadata into testcase-local metadata before later
        // scheduler scoring, preventing cross-iteration canary bleed.
        let compound_sequence = state
            .metadata_map()
            .get::<CompoundSequenceCanary>()
            .map(|canary| canary.set)
            .unwrap_or(false);
        // INV-016 — snapshot timestamp located taint flag NOW before it is cleared.
        let timestamp_located = unsafe { crate::evm::middlewares::cmp_linearity::TIMESTAMP_TAINT_WRITTEN };
        // adding power scheduling information based on code size
        {
            let mut testcase = state.testcase_mut(idx).unwrap();
            let input = testcase.input().clone().unwrap();
            {
                let current_idx = *state.corpus().current();
                testcase.set_parent_id_optional(current_idx);
            }
            let meta = state.metadata_map().get::<ArtifactInfoMetadata>().unwrap();
            let artifact = match meta.get(&input.contract) {
                Some(artifact) => artifact,
                None => {
                    let mut m = PowerABITestcaseMetadata::new(1);
                    m.located_dim = flow_dim;
                    m.compound_sequence = compound_sequence;
                    m.timestamp_located = timestamp_located;
                    testcase.add_metadata(m);
                    return Ok(());
                } // some contracts are not in ArtifactInfo, like borrow
            };
            if !input.is_step() {
                self.add_abi_metadata(&mut testcase, artifact)?;
                if let Ok(m) = testcase.metadata_mut::<PowerABITestcaseMetadata>() {
                    m.located_dim = flow_dim;
                    m.compound_sequence = compound_sequence;
                    m.timestamp_located = timestamp_located;
                }
            }
        }

        // adding power scheduling information based on branch covered
        {
            let meta: &mut UncoveredBranchesMetadata =
                state.metadata_map_mut().get_mut::<UncoveredBranchesMetadata>().unwrap();
            let mut uncovered_counters = 0;

            let mut fullfilled = HashSet::new();

            for it in unsafe { BRANCH_STATUS.iter().take(BRANCH_STATUS_IDX) } {
                let (addr, pc, br) = it.unwrap();
                if fullfilled.contains(&(addr, pc)) {
                    continue;
                }

                match meta.branch_status.get_mut(&(addr, pc)) {
                    Some(v) => {
                        let (new_v, is_updated) = v.merge(br);

                        // remove all testcases that already cover this branch
                        if is_updated {
                            assert_eq!(new_v, BranchCoveredStatus::Both);
                            meta.branch_to_testcases
                                .get(&(addr, pc))
                                .expect("branch_to_testcases should contain this branch")
                                .iter()
                                .for_each(|tc_id| {
                                    if *tc_id == idx {
                                        return;
                                    }
                                    meta.testcase_to_uncovered_branches
                                        .entry(*tc_id)
                                        .and_modify(|e| *e -= 1)
                                        .or_insert(0);
                                });
                            meta.branch_to_testcases.remove(&(addr, pc));
                        } else {
                            // not fully covered, so add this testcase to the branch
                            meta.branch_to_testcases.entry((addr, pc)).or_default().insert(idx);
                            uncovered_counters += 1;
                        }

                        *v = new_v;
                    }
                    None => {
                        // not covered before, so no testcases cover this branch
                        meta.branch_status.insert((addr, pc), BranchCoveredStatus::from(br));

                        // not fully covered, so add this testcase to the branch
                        meta.branch_to_testcases.entry((addr, pc)).or_default().insert(idx);

                        uncovered_counters += 1;
                    }
                }

                fullfilled.insert((addr, pc));
            }

            // finally add the testcase to the uncovered_branches
            meta.testcase_to_uncovered_branches.insert(idx, uncovered_counters);
        }

        Ok(())
    }

    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, Error> {
        if state.corpus().count() == 0 {
            Err(Error::empty("No entries in corpus".to_owned()))
        } else {
            let id = state
                .corpus()
                .current()
                .map(|id| state.corpus().next(id))
                .flatten()
                .unwrap_or_else(|| state.corpus().first().unwrap());
            self.set_current_scheduled(state, Some(id))?;
            Ok(id)
        }
    }
}

impl<S> RemovableScheduler for PowerABIScheduler<S>
where
    S: State + HasCorpus<Input = EVMInput> + HasTestcase + HasMetadata,
{
    fn on_remove(
        &mut self,
        _state: &mut Self::State,
        _idx: CorpusId,
        _testcase: &Option<Testcase<<Self::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn on_replace(
        &mut self,
        _state: &mut Self::State,
        _idx: CorpusId,
        _prev: &Testcase<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

pub trait ABIScheduler: Scheduler
where
    Self::State: HasCorpus,
{
    // on_add but with artifacts passed when state has no ArtifactInfoMetadata
    fn on_add_artifacts(
        &mut self,
        state: &mut Self::State,
        idx: CorpusId,
        artifacts: &EVMInitializationArtifacts,
    ) -> Result<(), Error>;
}

impl<S> ABIScheduler for PowerABIScheduler<S>
where
    S: State + HasCorpus<Input = EVMInput> + HasTestcase + HasMetadata,
{
    fn on_add_artifacts(
        &mut self,
        state: &mut S,
        idx: CorpusId,
        artifacts: &EVMInitializationArtifacts,
    ) -> Result<(), Error> {
        let mut testcase = state.testcase_mut(idx).unwrap();
        testcase.set_parent_id_optional(None);
        let input = testcase.input().clone().unwrap();
        let artifact = match artifacts.build_artifacts.get(&input.contract) {
            Some(artifact) => artifact,
            None => {
                testcase.add_metadata(PowerABITestcaseMetadata::new(1));
                return Ok(());
            } // build_artifacts may not contain contracts whose source code is not available
        };
        self.add_abi_metadata(&mut testcase, artifact)?;
        Ok(())
    }
}

/// The power assigned to each corpus entry
/// This result is used for power scheduling
#[derive(Debug, Clone)]
pub struct CorpusPowerABITestcaseScore<S> {
    phantom: PhantomData<S>,
}

impl<S> TestcaseScoreWithId<S> for CorpusPowerABITestcaseScore<S>
where
    S: HasCorpus<Input = EVMInput> + HasMetadata,
{
    fn compute(state: &S, entry: &mut Testcase<S::Input>, idx: CorpusId) -> Result<f64, Error> {
        let uncov_branch = {
            let meta = state.metadata_map().get::<UncoveredBranchesMetadata>().unwrap();
            meta.testcase_to_uncovered_branches.get(&idx).unwrap_or(&0).to_owned() + 1
        };

        let mut power = uncov_branch as f64 * POWER_MULTIPLIER;

        // Topology gamma ray: boost power for sequences that match the predicted
        // exploit shape. The boost decays exponentially with each scheduling hit
        // so the fuzzer concentrates pressure on topology-predicted paths early
        // but returns to full exploration as those paths fail to yield new branches.
        //
        // Formula: effective_boost = 1.0 + (base_boost - 1.0) * 0.95^hits
        //   hits=0  → full boost    (e.g. 1.95x at 95% confidence)
        //   hits=14 → ~50% of boost (1.475x)
        //   hits=45 → ~10% of boost (effectively neutral)
        //
        // v1: counter ticks on scheduling (compute call). v2 should tick only
        // on trace observation — when the ghost actually sees the selector fire.
        if let Some(hints) = state.metadata_map().get::<TopologyHints>() {
            if let Some(input) = entry.input() {
                if let Some(abi) = input.get_data_abi() {
                    let selector = abi.function;
                    if let Some(confidence) = hints.lookup(&selector) {
                        let hits = match entry.metadata::<PowerABITestcaseMetadata>() {
                            Ok(meta) => meta.topology_hits,
                            Err(_) => 0,
                        };
                        // --topology-bias scales the confidence steer (floodlight→nudge→off).
                        let base_boost = 1.0 + (confidence as f64 / 100.0) * hints.bias;
                        let decay = 0.95_f64.powi(hits as i32);
                        let effective_boost = 1.0 + (base_boost - 1.0) * decay;
                        power *= effective_boost;

                        // increment hit counter for decay
                        if let Ok(meta) = entry.metadata_mut::<PowerABITestcaseMetadata>() {
                            meta.topology_hits = meta.topology_hits.saturating_add(1);
                        }
                    }
                }
            }
        }

        // Feature 026 Phase A — Promote → Scheduler energy. The reflexive (015) and
        // parameter-bound (025) levers promote a (contract, selector) via
        // PromotionCandidate, but the scheduler never learned of it: a promoted
        // step was drilled only when this scorer happened to serve a matching
        // input — the measured "3x front-loaded cost". Here we boost power for
        // inputs that exercise the promoted (contract, selector), with the same
        // exponential decay as the topology boost (a sibling promote_hits counter) so
        // a promoted lever gets early pressure without permanently trapping the search.
        // With no candidate set (!cand.set), this is inert → power byte-identical to
        // pre-026.
        if let Some(input) = entry.input() {
            if let Some(abi) = input.get_data_abi() {
                // Feature 035: return the matched candidate's best_inflow so magnitude_boost
                // can scale the promote_boost multiplicatively. Option::None = no match →
                // inert, byte-identical to pre-035.
                let matched_magnitude: Option<u128> = state
                    .metadata_map()
                    .get::<PromotionCandidates>()
                    .and_then(|candidates| {
                        candidates.by_kind.values().find(|cand| {
                            cand.set && abi.function == cand.selector && input.get_contract() == cand.contract
                        })
                    })
                    .map(|cand| cand.best_inflow)
                    .or_else(|| {
                        state.metadata_map().get::<PromotionCandidate>().and_then(|cand| {
                            (cand.set && abi.function == cand.selector && input.get_contract() == cand.contract)
                                .then_some(cand.best_inflow)
                        })
                    });
                if let Some(magnitude) = matched_magnitude {
                    let hits = match entry.metadata::<PowerABITestcaseMetadata>() {
                        Ok(meta) => meta.promote_hits,
                        Err(_) => 0,
                    };
                    power *= promote_boost(hits) * magnitude_boost(magnitude);

                    if let Ok(meta) = entry.metadata_mut::<PowerABITestcaseMetadata>() {
                        meta.promote_hits = meta.promote_hits.saturating_add(1);
                    }
                }
            }
        }

        // Feature 037 — compound sequence canary → scheduler energy. This reads
        // testcase-local metadata stamped in on_add, not the global current-execution
        // canary, so one compound execution cannot boost unrelated later testcases.
        let (compound_sequence, compound_hits) = match entry.metadata::<PowerABITestcaseMetadata>() {
            Ok(meta) => (meta.compound_sequence, meta.compound_hits),
            Err(_) => (false, 0),
        };
        if compound_sequence {
            power *= compound_boost(compound_hits);
            if let Ok(meta) = entry.metadata_mut::<PowerABITestcaseMetadata>() {
                meta.compound_hits = meta.compound_hits.saturating_add(1);
            }
        }

        // Feature 026 Phase B — dim_flow → scheduler energy. Boost inputs whose
        // execution exhibited a high-value economic dimension
        // (PRICE_MANIP→high, ACCUM→med), read from the per-testcase
        // `located_dim` stamped at mint (not the static-mut flags, which reflect the
        // wrong execution at score time). Decays like the others. Generic ⇒ inert ⇒
        // byte-identical.
        let (dim, dim_hits) = match entry.metadata::<PowerABITestcaseMetadata>() {
            Ok(meta) => (meta.located_dim, meta.dim_hits),
            Err(_) => (TaintDim::Generic, 0),
        };
        let boost = dim_boost(dim, dim_hits);
        if boost > 1.0 {
            power *= boost;
            if let Ok(meta) = entry.metadata_mut::<PowerABITestcaseMetadata>() {
                meta.dim_hits = meta.dim_hits.saturating_add(1);
            }
        }

        if power >= MAX_POWER {
            power = MAX_POWER;
        }
        if power <= MIN_POWER {
            power = MIN_POWER;
        }

        Ok(power)
    }
}

/// The standard powerscheduling stage
pub type PowerABIMutationalStage<E, EM, I, M, Z> =
    PowerMutationalStageWithId<E, CorpusPowerABITestcaseScore<<E as UsesState>::State>, EM, I, M, Z>;

#[cfg(test)]
mod tests {
    use super::{compound_boost, dim_boost, magnitude_boost, promote_boost, TaintDim};

    #[test]
    fn dim_boost_tiers_and_decay() {
        // PRICE > ACCUMULATOR > neutral at hits=0.
        assert!(dim_boost(TaintDim::Price, 0) > dim_boost(TaintDim::Accumulator, 0));
        assert!((dim_boost(TaintDim::Price, 0) - 1.75).abs() < 1e-9);
        assert!((dim_boost(TaintDim::Accumulator, 0) - 1.4).abs() < 1e-9);
        // Non-steered dimensions are exactly neutral (byte-identical path).
        assert_eq!(dim_boost(TaintDim::Generic, 0), 1.0);
        assert_eq!(dim_boost(TaintDim::Timestamp, 0), 1.0);
        assert_eq!(dim_boost(TaintDim::Balance, 0), 1.0);
        // Decays toward — but never below — neutral.
        assert!(dim_boost(TaintDim::Price, 10) < dim_boost(TaintDim::Price, 0));
        assert!(dim_boost(TaintDim::Price, 100) > 1.0);
        assert!(dim_boost(TaintDim::Price, 100) < 1.01);
    }

    #[test]
    fn compound_boost_decays_from_full_to_neutral() {
        assert!((compound_boost(0) - 1.5).abs() < 1e-9, "full boost at hits=0");
        assert!(compound_boost(1) < compound_boost(0));
        assert!(compound_boost(10) < compound_boost(1));
        assert!(compound_boost(100) > 1.0, "still above neutral at moderate hits");
        assert!(compound_boost(100) < 1.01, "approaching neutral");
        assert!(compound_boost(100_000) >= 1.0, "never below neutral");
    }

    #[test]
    fn promote_boost_decays_from_full_to_neutral() {
        // hits=0 → full 2.0x early pressure.
        assert!((promote_boost(0) - 2.0).abs() < 1e-9, "full boost at hits=0");
        // strictly decreasing as the lever is repeatedly scheduled.
        assert!(promote_boost(1) < promote_boost(0));
        assert!(promote_boost(10) < promote_boost(1));
        // approaches — but never drops below — neutral (1.0): a promoted lever loses
        // its front-loaded advantage but is never penalised.
        assert!(promote_boost(100) > 1.0, "still above neutral at moderate hits");
        assert!(promote_boost(100) < 1.01, "approaching neutral");
        assert!(promote_boost(100_000) >= 1.0, "never below neutral — 1.0 is the floor");
    }

    // Feature 035 tests

    #[test]
    fn magnitude_boost_zero_is_neutral() {
        // Permission/ControlFlow emit best_inflow=0 (presence-only) → must be byte-identical to
        // pre-035 (no extra multiplier).
        assert_eq!(magnitude_boost(0), 1.0);
    }

    #[test]
    fn magnitude_boost_monotonic() {
        // Larger magnitudes must yield at least as much boost — secant can only improve best_inflow.
        assert!(magnitude_boost(1) >= magnitude_boost(0));
        assert!(magnitude_boost(1_000) >= magnitude_boost(1));
        assert!(magnitude_boost(1_000_000_000_000_000_000) >= magnitude_boost(1_000));
    }

    #[test]
    fn magnitude_boost_bounded() {
        // Never exceeds MAGNITUDE_BOOST_MAX (1.5) regardless of how large best_inflow gets.
        assert!(magnitude_boost(u128::MAX) <= 1.5 + 1e-9);
        assert!(magnitude_boost(u128::MAX) >= 1.0);
    }

    #[test]
    fn magnitude_boost_never_reduces_promote_boost() {
        // Combined multiplier promote_boost(hits) * magnitude_boost(magnitude) must always
        // be >= promote_boost(hits) alone (magnitude_boost is always >= 1.0).
        for hits in [0u32, 1, 10, 100] {
            for magnitude in [0u128, 1, 1_000, 1_000_000_000_000_000_000, u128::MAX] {
                let combined = promote_boost(hits) * magnitude_boost(magnitude);
                assert!(
                    combined >= promote_boost(hits) - 1e-9,
                    "hits={hits} magnitude={magnitude}: combined={combined} < promote_boost={}",
                    promote_boost(hits)
                );
            }
        }
    }
}
