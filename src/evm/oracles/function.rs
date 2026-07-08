use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::hash::{Hash, Hasher};

use libafl::prelude::HasMetadata;
use bytes::Bytes;
use revm_interpreter::bytecode::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        leak_class::LeakClass,
        oracles::{FUNCTION_BUG_IDX, TrustedCallerMetadata},
        planner::{PromotionCandidate, TaintProvenanceTag},
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    input::VMInputT,
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

/// Detects unauthorized access to privileged functions.
///
/// For each (contract, selector) rule, records which callers are allowed.
/// If an execution calls that function with a disallowed caller and does NOT
/// revert, it's a permission leak — primitive 4 of the Six Primitives.
///
/// Auto-populated by the corpus initializer by scanning ABI function names
/// for privileged keywords (withdraw, mint, pause, setOwner, etc.).
/// Can also be populated from explicit CLI rules for custom harnesses.
pub struct FunctionOracle {
    /// (contract, selector) → set of allowed caller addresses.
    /// Empty allowed set means ALL callers are blocked except deployer.
    rules: HashMap<(EVMAddress, [u8; 4]), HashSet<EVMAddress>>,
    /// Human-readable function name for each (contract, selector) pair.
    names: HashMap<(EVMAddress, [u8; 4]), String>,
    pub address_to_name: HashMap<EVMAddress, String>,
    /// Feature 019 Phase A — when true, apply the materiality gate: an unauthorized
    /// privileged call is a leak only if the privileged contract had a material sink
    /// this tx (`FunctionAuthTracer` evidence). Off = pre-019 behavior, byte-identical.
    causal_identity: bool,
}

impl FunctionOracle {
    pub fn new(address_to_name: HashMap<EVMAddress, String>) -> Self {
        Self {
            rules: HashMap::new(),
            names: HashMap::new(),
            address_to_name,
            causal_identity: false,
        }
    }

    /// Enable the Feature 019 materiality gate (driven by `--causal-identity`).
    pub fn set_causal_identity(&mut self, enabled: bool) {
        self.causal_identity = enabled;
    }

    /// Register a privileged function. Only `allowed_callers` may call it
    /// without reverting; all others fire the oracle.
    pub fn add_rule(
        &mut self,
        contract: EVMAddress,
        selector: [u8; 4],
        fn_name: String,
        allowed_callers: HashSet<EVMAddress>,
    ) {
        self.rules.insert((contract, selector), allowed_callers);
        self.names.insert((contract, selector), fn_name);
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Lowercase function name substrings that indicate a privileged operation.
/// Matched against the ABI `function_name` field during corpus initialization.
pub const PRIVILEGED_KEYWORDS: &[&str] = &[
    "withdraw",
    "drain",
    "mint",
    "burn",
    "pause",
    "unpause",
    "setowner",
    "transferownership",
    "renounceownership",
    "upgrade",
    "initialize",
    "setrole",
    "grantrole",
    "revokerole",
    "emergencywithdraw",
    "rescue",
    "sweep",
];

/// Returns true if `fn_name` contains any privileged keyword (case-insensitive).
pub fn is_privileged_fn(fn_name: &str) -> bool {
    let lower = fn_name.to_lowercase();
    PRIVILEGED_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

impl
    Oracle<
        EVMState,
        EVMAddress,
        Bytecode,
        Bytes,
        EVMAddress,
        EVMU256,
        Vec<u8>,
        EVMInput,
        EVMFuzzState,
        ConciseEVMInput,
        EVMQueueExecutor,
    > for FunctionOracle
{
    fn transition(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        // Populate TrustedCallerMetadata for Ghost Identities
        // When a privileged function call succeeds, record the caller as trusted for that (contract, selector)
        if !self.rules.is_empty() {
            let result = ctx.fuzz_state.get_execution_result();
            if !result.reverted {
                let caller = ctx.input.get_caller();
                let contract = ctx.input.get_contract();
                let data = ctx.input.get_direct_data();
                if data.len() >= 4 {
                    let selector: [u8; 4] = data[..4].try_into().unwrap();
                    let key = (contract, selector);
                    // Only populate if this is a known privileged function
                    if self.rules.contains_key(&key) {
                        if !ctx.fuzz_state.has_metadata::<TrustedCallerMetadata>() {
                            ctx.fuzz_state.metadata_map_mut().insert(TrustedCallerMetadata::default());
                        }
                        let meta = ctx.fuzz_state.metadata_map_mut()
                            .get_mut::<TrustedCallerMetadata>()
                            .unwrap();
                        let dynamic_key = format!("0x{:?}_0x{:?}", contract, selector);
                        meta.trusted_callers.entry(dynamic_key).or_default().insert(caller);
                    }
                }
            }
        }
        0
    }

    fn oracle(
        &self,
        ctx: &mut OracleCtx<
            EVMState,
            EVMAddress,
            Bytecode,
            Bytes,
            EVMAddress,
            EVMU256,
            Vec<u8>,
            EVMInput,
            EVMFuzzState,
            ConciseEVMInput,
            EVMQueueExecutor,
        >,
        _stage: u64,
    ) -> Vec<u64> {
        if self.rules.is_empty() {
            return vec![];
        }

        let result = ctx.fuzz_state.get_execution_result();
        // Only flag successful calls — a revert is the access control working.
        if result.reverted {
            return vec![];
        }

        let caller   = ctx.input.get_caller();
        let contract = ctx.input.get_contract();
        let data     = ctx.input.get_direct_data();

        if data.len() < 4 {
            return vec![];
        }
        let selector: [u8; 4] = data[..4].try_into().unwrap();

        let key = (contract, selector);
        // Check static rules first (from corpus init)
        let allowed_static = match self.rules.get(&key) {
            Some(a) => a,
            None => return vec![],
        };

        // Also check dynamic TrustedCallerMetadata (Ghost Identities)
        let dynamic_key = format!("0x{:?}_0x{:?}", contract, selector);
        let allowed_dynamic = ctx.fuzz_state.metadata_map()
            .get::<TrustedCallerMetadata>()
            .and_then(|m| m.trusted_callers.get(&dynamic_key));

        // If caller is in either allowed set, no violation
        if allowed_static.contains(&caller) || allowed_dynamic.map(|set| set.contains(&caller)).unwrap_or(false) {
            return vec![];
        }

        // Feature 019 Phase A — materiality gate. An unauthorized privileged call that
        // changed nothing material (e.g. `DAI.burn(0x0, 0)`) is a no-op, not a permission
        // leak. Require the privileged contract to have had a material sink this tx —
        // an SSTORE with pre≠post, or a value-CALL — as recorded by FunctionAuthTracer.
        // Fail-CLOSED: absent materiality → not a leak. Gated on --causal-identity so
        // that with the flag off the oracle is byte-identical to pre-019 (the middleware
        // is not registered, so the metadata would be empty and unconditionally suppress).
        if self.causal_identity && !ctx.post_state.permission_leak_metadata.contract_material(&contract) {
            return vec![];
        }

        let fn_name = self.names.get(&key).map(|s| s.as_str()).unwrap_or("unknown");
        let contract_name = self
            .address_to_name
            .get(&contract)
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        caller.hash(&mut hasher);
        let bug_idx = (hasher.finish() << 8) + FUNCTION_BUG_IDX;

        EVMBugResult::new(
            "Unauthorized Function Access".to_string(),
            bug_idx,
            format!(
                "{}.{}() reached by unauthorized caller {:?} without reverting \
                 (permission leak)",
                contract_name, fn_name, caller,
            ),
            ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            None,
            Some(contract_name.to_string()),
        )
        .push_to_output();

        // Feature 023 Phase 2 — structural (Permission-kind) promotion candidate. Routes this
        // permission-leak verdict into the Borrow→Prime→Lever→Exploit chain: the kind-aware
        // mutator LOCKS this Prime step rather than amplifying it (structural has no magnitude →
        // best_inflow=0). Phase-tagged from FunctionAuthTracer's per-step attribution. Only fill
        // the slot if a candidate hasn't already claimed it — value (direct loss) takes precedence,
        // and the value a-posteriori producer high-water-clobbers this best_inflow=0 incumbent, so
        // a value run never loses its candidate to a structural fire (value path byte-identical).
        let already_set = ctx
            .fuzz_state
            .metadata_map()
            .get::<PromotionCandidate>()
            .map(|c| c.set)
            .unwrap_or(false);
        if !already_set {
            let phase = ctx
                .post_state
                .permission_leak_metadata
                .material_at_step
                .get(&contract)
                .copied();
            ctx.fuzz_state.metadata_map_mut().insert(PromotionCandidate {
                contract,
                selector,
                best_inflow: 0,
                kind: LeakClass::Permission,
                taint_provenance: TaintProvenanceTag::default(),
                phase,
                set: true,
            });
        }

        vec![bug_idx]
    }
}
