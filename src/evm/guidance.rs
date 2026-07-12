// =============================================================================
// spectrefuzz.guidance — Rust structs matching 09_export_guidance.py JSON schema
// =============================================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use libafl_bolts::impl_serdeany;

// ── Top Level ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guidance {
    pub version: u64,
    pub generated_at: f64,
    pub meta: Meta,
    pub functions: HashMap<String, FunctionEntry>,
    pub scheduler: SchedulerIndex,
    pub mutator: MutatorIndex,
    pub oracle: OracleIndex,
    pub contracts: Vec<ContractEntry>,

    /// Precomputed from sv_flows: contract_address → {slot_name → influence_weight}
    /// Weight = number of sv_flows edges this slot mediates.
    /// Used by UCB scheduler to prioritize high-leverage cold slots.
    #[serde(default)]
    pub slot_influence_weights: HashMap<String, HashMap<String, f64>>,

    #[serde(default)]
    pub storage_layout: HashMap<String, HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub num_functions: usize,
    pub num_params: usize,
    pub num_kill_chains: usize,
    pub num_invariants: usize,
    pub num_contracts: usize,
}

// ── Functions ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionEntry {
    pub contract: String,
    #[serde(default)]
    pub selector: Option<String>,
    pub visibility: String,
    pub is_entry: bool,
    pub is_invariant: bool,
    pub is_payable: bool,

    #[serde(default)]
    pub params: Vec<ParamGuidance>,

    #[serde(default)]
    pub guards: Vec<String>,

    pub access_control: AccessControl,
    pub state: StateAccess,
    pub kill_chains: KillChainSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamGuidance {
    pub index: usize,
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: String,

    #[serde(default)]
    pub reaches_sink: Vec<SinkReach>,

    #[serde(default)]
    pub influences_state: Vec<StateInfluence>,

    #[serde(default)]
    pub flows_to_callee: Vec<CalleeFlow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkReach {
    pub sink: String,
    pub arg: i64,
    pub depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateInfluence {
    #[serde(rename = "var")]
    pub state_var: String,
    #[serde(default)]
    pub enables_sinks: Vec<SinkRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkRef {
    pub sink: String,
    pub depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalleeFlow {
    pub callee: String,
    pub arg: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControl {
    pub has_modifiers: bool,
    #[serde(default)]
    pub modifiers: Vec<String>,
    pub needs_precondition: Option<bool>,
    pub precondition_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateAccess {
    #[serde(default)]
    pub reads: Vec<String>,
    #[serde(default)]
    pub writes: Vec<String>,
    #[serde(default)]
    pub global_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainSummary {
    pub sink_count: usize,
    #[serde(default)]
    pub sinks: Vec<String>,
    pub min_depth: usize,
    #[serde(default)]
    pub chains: Vec<KillChainEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainEntry {
    pub sink: String,
    #[serde(default)]
    pub pivot: String,
    pub depth: usize,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub sv_path: String,
    #[serde(default)]
    pub guards: String,
}

// ── Scheduler ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerIndex {
    /// after["borrow"] → ["withdraw", "repay", "claimRewards"]
    pub after: HashMap<String, Vec<String>>,

    /// All public/external non-view functions
    pub entry_points: Vec<String>,
}

impl SchedulerIndex {
    pub fn next_candidates(&self, fn_name: &str) -> &[String] {
        self.after.get(fn_name).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

// ── Mutator ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutatorIndex {
    pub high_value_params: Vec<HighValueParam>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighValueParam {
    pub function: String,
    pub param_index: usize,
    pub param_name: String,
    pub reaches_sink: bool,
    pub influences_state: bool,
}

impl MutatorIndex {
    pub fn for_function(&self, fn_name: &str) -> Vec<&HighValueParam> {
        self.high_value_params
            .iter()
            .filter(|p| p.function == fn_name)
            .collect()
    }
}

// ── Oracle ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleIndex {
    pub invariants: Vec<InvariantDef>,
    pub num_invariants: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantDef {
    pub contract: String,
    pub name: String,
    #[serde(default)]
    pub selector: Option<String>,
    #[serde(default)]
    pub returns: String,
}

// ── Contracts ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractEntry {
    pub id: String,
    pub name: String,
    pub address: String,
    pub is_library: Option<bool>,
    pub is_interface: Option<bool>,
    pub is_proxy: Option<bool>,
    #[serde(default)]
    pub protocol: Option<String>,
}

// ── Runtime: Slot Novelty (UCB scheduler state) ────────────────────────────
// Updated during fuzzing, not from JSON.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotNoveltyMap {
    /// (contract_address, slot_index) → total write count
    pub write_counts: HashMap<(String, u64), usize>,

    /// (contract_address, slot_index) → precomputed weight
    pub influence_weights: HashMap<String, HashMap<u64, f64>>,

    pub total_sequences: usize,
}

impl SlotNoveltyMap {
    /// Novelty score for a set of (contract, slot_index) writes.
    /// Higher = more novel (cold slots with high influence weight).
    pub fn novelty_score(&self, modified_slots: &[(String, u64)]) -> f64 {
        let mut score = 0.0;
        for (contract, slot) in modified_slots {
            let contract_lower = contract.to_lowercase();
            let count = self.write_counts.get(&(contract_lower.clone(), *slot)).unwrap_or(&0);
            let freq_term = 1.0 / (1.0 + (*count as f64)).ln_1p();
            let infl = self
                .influence_weights
                .get(&contract_lower)
                .and_then(|m| m.get(slot))
                .copied()
                .unwrap_or(1.0);
            score += freq_term * infl;
        }
        score
    }

    pub fn record_write(&mut self, slots: &[(String, u64)]) {
        for (contract, slot) in slots {
            let contract_lower = contract.to_lowercase();
            let entry = self.write_counts.entry((contract_lower, *slot)).or_insert(0);
            *entry += 1;
        }
        self.total_sequences += 1;
    }

    /// Decay: multiply all counts by factor (e.g. 0.5) so old slots cool.
    pub fn decay(&mut self, factor: f64) {
        for count in self.write_counts.values_mut() {
            *count = (*count as f64 * factor) as usize;
        }
    }
}

/// Semantic footprint of a sequence — used for corpus dedup.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct SemanticFootprint {
    /// Sorted, deduped (contract, slot_index) pairs this sequence wrote.
    pub slot_touches: Vec<(String, u64)>,
}

impl SemanticFootprint {
    pub fn new(mut slots: Vec<(String, u64)>) -> Self {
        slots.sort();
        slots.dedup();
        Self {
            slot_touches: slots,
        }
    }
}

// ── Loader ─────────────────────────────────────────────────────────────────

impl Guidance {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }
}

// ── LibAFL Metadata wrapper ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuidanceMetadata {
    pub guidance: Guidance,
    pub slot_novelty: SlotNoveltyMap,
    pub unique_footprints: HashMap<SemanticFootprint, f64>,
}

impl GuidanceMetadata {
    pub fn new(guidance: Guidance) -> Self {
        let mut resolved_weights: HashMap<String, HashMap<u64, f64>> = HashMap::new();

        // 1. Build a lookup for contract name -> address
        let mut name_to_addr = HashMap::new();
        for c in &guidance.contracts {
            name_to_addr.insert(c.name.clone(), c.address.to_lowercase());
        }

        // 2. Resolve slot influence weights to (contract_address, slot_index)
        for (contract_name, slots) in &guidance.storage_layout {
            if let Some(addr) = name_to_addr.get(contract_name) {
                let mut slot_map = HashMap::new();
                for (slot_str, fq_var_name) in slots {
                    if let Ok(slot_idx) = slot_str.parse::<u64>() {
                        // Look up fq_var_name weight in slot_influence_weights under "contracts" or "lib"
                        let mut weight = 1.0; // default baseline weight if not found
                        if let Some(cat_weights) = guidance.slot_influence_weights.get("contracts") {
                            if let Some(w) = cat_weights.get(fq_var_name) {
                                weight = *w;
                            }
                        }
                        if let Some(cat_weights) = guidance.slot_influence_weights.get("lib") {
                            if let Some(w) = cat_weights.get(fq_var_name) {
                                weight = *w;
                            }
                        }
                        slot_map.insert(slot_idx, weight);
                    }
                }
                if !slot_map.is_empty() {
                    resolved_weights.insert(addr.clone(), slot_map);
                }
            }
        }

        Self {
            guidance,
            slot_novelty: SlotNoveltyMap {
                write_counts: HashMap::new(),
                influence_weights: resolved_weights,
                total_sequences: 0,
            },
            unique_footprints: HashMap::new(),
        }
    }
}

impl_serdeany!(GuidanceMetadata);
