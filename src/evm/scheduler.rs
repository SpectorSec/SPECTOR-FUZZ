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
    topology::TopologyHints,
    types::EVMAddress,
};
use crate::{
    evm::{
        abi::FUNCTION_SIG,
        blaz::builder::{ArtifactInfoMetadata, BuildJobResult},
        corpus_initializer::EVMInitializationArtifacts,
        input::EVMInput,
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
}

impl PowerABITestcaseMetadata {
    /// Create new [`struct@SchedulerTestcaseMetadata`]
    #[must_use]
    pub fn new(lines: usize) -> Self {
        Self { lines, topology_hits: 0 }
    }
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
                    testcase.add_metadata(PowerABITestcaseMetadata::new(1));
                    return Ok(());
                } // some contracts are not in ArtifactInfo, like borrow
            };
            if !input.is_step() {
                self.add_abi_metadata(&mut testcase, artifact)?;
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
