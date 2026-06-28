use std::collections::{HashMap, HashSet};

use libafl_bolts::impl_serdeany;
use serde::{Deserialize, Serialize};

use crate::evm::abi::{ABIAddressToInstanceMap, BoxedABI};
use crate::evm::input::{CampaignSequence, ConciseEVMInput, EVMInputTy};
use crate::evm::topology::{ExploitClass, TopologyReport};
use crate::evm::types::{EVMAddress, EVMU256};

/// Vault/prime selectors: functions that accept assets and change protocol state.
const PRIME_SELECTORS: &[[u8; 4]] = &[
    [0x47, 0xe7, 0xef, 0x34], // receiveWithPermit
    [0x6e, 0x55, 0x3f, 0x65], // deposit(uint256)
    [0xaa, 0x45, 0xde, 0x31], // mint
    [0x36, 0x63, 0x09, 0xb5], // stake
    [0xa3, 0x14, 0x6b, 0xd2], // addLiquidity
    [0x02, 0x2c, 0x0d, 0x9f], // deposit
];

/// Exploit trigger selectors: functions that extract value or manipulate state.
const EXPLOIT_SELECTORS: &[[u8; 4]] = &[
    [0x44, 0x1a, 0x3e, 0x70], // withdraw(uint256)
    [0xdb, 0x00, 0x6b, 0x75], // redeem
    [0x4e, 0x71, 0xd9, 0x2d], // sync
    [0xa9, 0x05, 0x9c, 0xbb], // liquidate(address,uint256,address)
    [0x4e, 0x84, 0x73, 0xcb], // skim
    [0x85, 0x38, 0x28, 0xb6], // donate
];

/// Function-NAME substrings that indicate a trigger/exploit function. TESTING
/// ONLY — gated behind `campaign_generic_fallback`, off by default. Name matching
/// is NOT machine truth: substrings also hit getters (`claimable`, `withdrawable`)
/// and miss attacker-renamed functions. Production stays on exact-selector truth.
#[cfg(feature = "campaign_generic_fallback")]
const EXPLOIT_NAME_PATTERNS: &[&str] = &[
    "withdraw", "redeem", "claim", "harvest", "exit", "unstake", "unlock",
    "collect", "skim", "sync", "liquidate", "drain", "payout", "sweep",
    "borrow", "cashout", "release", "settle",
];

/// Lowercased function name (portion before `(`) from the global signature
/// registry, if known. Returns `None` when signatures were not registered.
#[cfg(feature = "campaign_generic_fallback")]
fn fn_name_lc(abi: &BoxedABI) -> Option<String> {
    abi.get_func_signature()
        .map(|sig| sig.split('(').next().unwrap_or("").to_ascii_lowercase())
}

/// Pre-filtered campaign target cache, initialized once during corpus setup.
/// Replaces the O(N) ABI registry scan with an O(1) read-only lookup.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CampaignTargetCache {
    pub prime_targets: Vec<(EVMAddress, [u8; 4], BoxedABI)>,
    pub exploit_targets: Vec<(EVMAddress, [u8; 4], BoxedABI)>,
    pub borrowable_tokens: Vec<EVMAddress>,
    /// Fallback campaign targets: contracts the selector allowlist didn't match
    /// but that look campaignable (>= 2 functions incl. a trigger-named one).
    /// Each entry is (address, prime_fn_abi, exploit_fn_abi) — the exploit is the
    /// trigger-named function (pinned so the executor probe calls it), the prime is
    /// a different (benign) function. Forms a same-contract prime->exploit chain.
    pub generic_targets: Vec<(EVMAddress, Option<BoxedABI>, Option<BoxedABI>)>,
}

impl_serdeany!(CampaignTargetCache);

impl CampaignTargetCache {
    /// Build the cache from the ABI registry by scanning for known selector patterns.
    pub fn new(abi_map: &ABIAddressToInstanceMap, borrowable_tokens: Vec<EVMAddress>) -> Self {
        Self {
            prime_targets: find_targets_by_selector(abi_map, PRIME_SELECTORS),
            exploit_targets: find_targets_by_selector(abi_map, EXPLOIT_SELECTORS),
            borrowable_tokens,
            generic_targets: find_generic_targets(abi_map),
        }
    }

    /// Returns true if this cache has enough targets to form at least a 2-step campaign.
    pub fn is_viable(&self) -> bool {
        (!self.prime_targets.is_empty() && !self.exploit_targets.is_empty())
            || !self.generic_targets.is_empty()
    }
}

/// Deterministic state machine that builds a multi-step campaign sequence.
///
/// Uses the pre-filtered `CampaignTargetCache` for O(1) target selection.
/// When `topology_report` is provided, exploit classes ranked by the topology
/// engine are used to prioritize targets (e.g., preferring same-contract
/// prime/exploit pairs for vault-like vulnerability patterns).
///
/// Builds one of:
///   - Borrow → ABI(prime) → ABI(exploit)  (when borrowable tokens available)
///   - ABI(prime) → ABI(exploit)            (no borrow step, still useful for state chaining)
///
/// # Returns
/// `Some(CampaignSequence)` if a viable 2+ step chain was constructed,
/// `None` if insufficient targets were found.
pub fn plan_campaign(
    cache: &CampaignTargetCache,
    topology_report: Option<&TopologyReport>,
    temporal_skimming: bool,
) -> Option<CampaignSequence> {
    let mut steps: Vec<ConciseEVMInput> = Vec::new();

    // Step 0 (optional): Borrow step — acquire capital via flashloan
    if let Some(token_addr) = cache.borrowable_tokens.first() {
        steps.push(build_borrow_step(*token_addr));
    }

    // Populate prime + exploit steps (with concrete function ABIs), respecting hints
    let (prime_step, exploit_step) = pick_prime_and_exploit(cache, topology_report);
    if let Some((addr, abi)) = prime_step {
        steps.push(build_abi_step(addr, abi));
    }
    if let Some((addr, abi)) = exploit_step {
        steps.push(build_abi_step(addr, abi));
    }

    // Minimum viable campaign: at least 2 steps
    if steps.len() < 2 {
        return None;
    }

    // Temporal Pre-condition Skimming: Insert a warp (block advance) between
    // the prime step (state priming) and the exploit step. The warp simulates
    // block progression during which state divergence (interest accrual, reward
    // accumulation, oracle price changes) can occur off-screen.
    let mut warps: Vec<(usize, u64)> = Vec::new();
    if temporal_skimming {
        // The exploit step is always the last step. Insert warp before it.
        // Index is steps.len() - 1 (0-indexed).
        let exploit_idx = steps.len() - 1;
        // Default warp: 10 blocks (~2 minutes). Sufficient to trigger most
        // reward-accrual and timelock-based divergence patterns.
        warps.push((exploit_idx, 10));
    }

    Some(CampaignSequence { steps, linkages: Vec::new(), warps })
}

/// Pick prime and exploit target addresses, using topology intelligence
/// to prefer same-contract pairs when the top-ranked exploit class
/// suggests a single-contract vulnerability (ERC-4626 vaults, staking
/// pools, etc.).
type PickedStep = Option<(EVMAddress, Option<BoxedABI>)>;

fn pick_prime_and_exploit<'a>(
    cache: &'a CampaignTargetCache,
    topology_report: Option<&TopologyReport>,
) -> (PickedStep, PickedStep) {
    let prefer_same_contract = topology_report
        .and_then(|r| r.ranked.first())
        .map(|(cls, _)| {
            matches!(
                cls,
                ExploitClass::PriceGatedVault
                    | ExploitClass::FlashDepositDrain
                    | ExploitClass::RewardAccumulator
            )
        })
        .unwrap_or(false);

    if prefer_same_contract {
        // Prefer an address in both lists, pinning each side's concrete function.
        for (addr, _, p_abi) in &cache.prime_targets {
            if let Some((_, _, e_abi)) = cache.exploit_targets.iter().find(|(a, _, _)| a == addr) {
                return (
                    Some((*addr, Some(p_abi.clone()))),
                    Some((*addr, Some(e_abi.clone()))),
                );
            }
        }
    }

    // Default: first from each selector-matched list, carrying the concrete ABI.
    let prime = cache.prime_targets.first().map(|(a, _, abi)| (*a, Some(abi.clone())));
    let exploit = cache.exploit_targets.first().map(|(a, _, abi)| (*a, Some(abi.clone())));
    if prime.is_some() && exploit.is_some() {
        return (prime, exploit);
    }

    // Fallback: name-heuristic single-contract target. Pin the trigger function as
    // the exploit step (so the executor probe calls it, not the fallback) and a
    // different function as the benign prime step.
    if let Some((addr, prime_abi, exploit_abi)) = cache.generic_targets.first() {
        return (
            Some((*addr, prime_abi.clone())),
            Some((*addr, exploit_abi.clone())),
        );
    }

    (prime, exploit)
}

/// Find all contracts whose ABI list includes any of the given selectors.
fn find_targets_by_selector(
    abi_map: &ABIAddressToInstanceMap,
    selectors: &[[u8; 4]],
) -> Vec<(EVMAddress, [u8; 4], BoxedABI)> {
    let mut results = Vec::new();
    for (addr, abis) in &abi_map.map {
        for abi in abis {
            if abi.function == [0u8; 4] {
                continue;
            }
            if selectors.contains(&abi.function) {
                results.push((*addr, abi.function, abi.clone()));
            }
        }
    }
    results
}

/// TESTING-ONLY name-heuristic fallback (gated behind `campaign_generic_fallback`,
/// off by default). When the feature is disabled this returns empty, so the
/// `generic_targets` field, `is_viable`, and the `pick_prime_and_exploit` fallback
/// all become no-ops and production stays exact-selector (machine-truth) only.
///
/// When enabled: a contract with >= 2 functions AND >= 1 trigger-NAMED function is
/// treated as campaignable. Recognizes simple/novel staking/vault/timelock fixtures
/// the selector allowlist doesn't cover. NOT for production — see the const above.
#[cfg(not(feature = "campaign_generic_fallback"))]
fn find_generic_targets(
    _abi_map: &ABIAddressToInstanceMap,
) -> Vec<(EVMAddress, Option<BoxedABI>, Option<BoxedABI>)> {
    Vec::new()
}

#[cfg(feature = "campaign_generic_fallback")]
fn find_generic_targets(
    abi_map: &ABIAddressToInstanceMap,
) -> Vec<(EVMAddress, Option<BoxedABI>, Option<BoxedABI>)> {
    let mut out = Vec::new();
    for (addr, abis) in &abi_map.map {
        let fns: Vec<&BoxedABI> = abis.iter().filter(|a| a.function != [0u8; 4]).collect();
        if fns.len() < 2 {
            continue;
        }
        // Exploit = first trigger-named function (pinned so the probe calls it).
        let exploit = fns.iter().find(|a| {
            fn_name_lc(a)
                .map(|n| EXPLOIT_NAME_PATTERNS.iter().any(|p| n.contains(p)))
                .unwrap_or(false)
        });
        let Some(exploit) = exploit else { continue };
        let exploit_sel = exploit.function;
        // Prime = first function that is NOT the exploit (benign setup step).
        let prime = fns.iter().find(|a| a.function != exploit_sel);
        out.push((
            *addr,
            prime.map(|a| (*a).clone()),
            Some((*exploit).clone()),
        ));
    }
    out
}

/// Build a Borrow step that acquires tokens via flashloan.
fn build_borrow_step(token: EVMAddress) -> ConciseEVMInput {
    ConciseEVMInput {
        input_type: EVMInputTy::Borrow,
        caller: EVMAddress::default(),
        contract: token,
        data: None,
        txn_value: Some(EVMU256::from(1_000_000_000_000_000_000u64)), // 1 ETH worth
        step: false,
        env: Default::default(),
        liquidation_percent: 0,
        randomness: vec![],
        repeat: 1,
        layer: 0,
        call_leak: u32::MAX,
        return_data: None,
        swap_data: HashMap::new(),
        nested_actions: Vec::new(),
        campaign: None,
    }
}

/// Build an ABI step for a target contract.
/// Parameters are resolved by the mutator's existing `mutate_with_vm_slots` path.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::abi::{ABIAddressToInstanceMap, BoxedABI, AEmpty, AUnknown};
    use crate::evm::input::EVMInputTy;
    use std::collections::HashMap;

    // Serializes tests that call `set_func_with_signature`, which writes the global
    // `static mut FUNCTION_SIG` HashMap — concurrent writes are a data race (UB).
    #[cfg(feature = "campaign_generic_fallback")]
    static FUNCTION_SIG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn make_abi(selector: [u8; 4]) -> BoxedABI {
        let mut abi = BoxedABI::new(Box::new(AUnknown {
            concrete: BoxedABI::new(Box::new(AEmpty {})),
            size: 0,
        }));
        abi.set_func(selector);
        abi
    }

    #[test]
    fn test_cache_empty_returns_none() {
        let abi_map = ABIAddressToInstanceMap { map: HashMap::new() };
        let cache = CampaignTargetCache::new(&abi_map, Vec::new());
        assert!(!cache.is_viable());
        assert!(plan_campaign(&cache, None, false).is_none());
    }

    #[test]
    fn test_cache_prime_only_not_viable() {
        let mut map = HashMap::new();
        let addr = EVMAddress::default();
        map.insert(addr, vec![make_abi(PRIME_SELECTORS[0])]);
        let abi_map = ABIAddressToInstanceMap { map };
        let cache = CampaignTargetCache::new(&abi_map, Vec::new());
        assert!(!cache.is_viable());
        assert!(plan_campaign(&cache, None, false).is_none());
    }

    /// Simple/novel fixture (selectors NOT in the allowlist) is recognized via the
    /// name-based generic fallback: a contract with >=2 functions incl. a
    /// trigger-named one (`claimJackpot`) forms a same-contract 2-step campaign.
    #[cfg(feature = "campaign_generic_fallback")]
    #[test]
    fn test_generic_target_recognized_by_name() {
        let _g = FUNCTION_SIG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let addr = EVMAddress::repeat_byte(0x11);
        let claim_sel = [0x11u8, 0x11, 0x11, 0x11];
        let dep_sel = [0x22u8, 0x22, 0x22, 0x22];
        let mut claim = make_abi(claim_sel);
        claim.set_func_with_signature(claim_sel, "claimJackpot", "()");
        let mut dep = make_abi(dep_sel);
        dep.set_func_with_signature(dep_sel, "deposit", "(uint256)");

        let mut map = HashMap::new();
        map.insert(addr, vec![claim, dep]);
        let abi_map = ABIAddressToInstanceMap { map };
        let cache = CampaignTargetCache::new(&abi_map, Vec::new());

        assert!(cache.prime_targets.is_empty(), "these selectors aren't in the allowlist");
        assert!(cache.exploit_targets.is_empty());
        assert!(
            cache.generic_targets.iter().any(|(a, _, _)| *a == addr),
            "recognized via name fallback"
        );
        // The exploit step is pinned to the trigger function (claimJackpot).
        let (_, _, exploit_abi) = cache
            .generic_targets
            .iter()
            .find(|(a, _, _)| *a == addr)
            .unwrap();
        assert_eq!(
            exploit_abi.as_ref().map(|a| a.function),
            Some(claim_sel),
            "exploit step pinned to the trigger function's selector"
        );
        assert!(cache.is_viable());

        let campaign =
            plan_campaign(&cache, None, true).expect("generic fallback must yield a campaign");
        assert_eq!(campaign.steps.len(), 2, "single-contract prime->exploit 2-step chain");
        assert_eq!(campaign.warps.len(), 1, "temporal warp inserted before exploit step");
    }

    /// A contract with a trigger name but only ONE function is not campaignable.
    #[cfg(feature = "campaign_generic_fallback")]
    #[test]
    fn test_generic_single_function_not_viable() {
        let _g = FUNCTION_SIG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let addr = EVMAddress::repeat_byte(0x33);
        let sel = [0x33u8, 0x33, 0x33, 0x33];
        let mut claim = make_abi(sel);
        claim.set_func_with_signature(sel, "claim", "()");
        let mut map = HashMap::new();
        map.insert(addr, vec![claim]);
        let abi_map = ABIAddressToInstanceMap { map };
        let cache = CampaignTargetCache::new(&abi_map, Vec::new());
        assert!(cache.generic_targets.is_empty(), "needs >= 2 functions");
    }

    #[test]
    fn test_plan_campaign_prime_and_exploit() {
        let mut map = HashMap::new();
        let prime_addr = EVMAddress::from([0x01; 20]);
        let exploit_addr = EVMAddress::from([0x02; 20]);
        map.insert(prime_addr, vec![make_abi(PRIME_SELECTORS[0])]);
        map.insert(exploit_addr, vec![make_abi(EXPLOIT_SELECTORS[0])]);
        let abi_map = ABIAddressToInstanceMap { map };
        let cache = CampaignTargetCache::new(&abi_map, Vec::new());
        assert!(cache.is_viable());
        let campaign = plan_campaign(&cache, None, false).expect("should produce campaign");
        assert_eq!(campaign.steps.len(), 2);
        assert_eq!(campaign.steps[0].input_type, EVMInputTy::ABI);
        assert_eq!(campaign.steps[0].contract, prime_addr);
        assert_eq!(campaign.steps[1].input_type, EVMInputTy::ABI);
        assert_eq!(campaign.steps[1].contract, exploit_addr);
    }

    #[test]
    fn test_plan_campaign_with_borrow() {
        let mut map = HashMap::new();
        let token = EVMAddress::from([0x03; 20]);
        let prime_addr = EVMAddress::from([0x01; 20]);
        let exploit_addr = EVMAddress::from([0x02; 20]);
        map.insert(prime_addr, vec![make_abi(PRIME_SELECTORS[0])]);
        map.insert(exploit_addr, vec![make_abi(EXPLOIT_SELECTORS[0])]);
        let abi_map = ABIAddressToInstanceMap { map };
        let cache = CampaignTargetCache::new(&abi_map, vec![token]);
        assert!(cache.is_viable());
        let campaign = plan_campaign(&cache, None, false).expect("should produce campaign");
        assert_eq!(campaign.steps.len(), 3);
        assert_eq!(campaign.steps[0].input_type, EVMInputTy::Borrow);
        assert_eq!(campaign.steps[0].contract, token);
        assert_eq!(campaign.steps[1].input_type, EVMInputTy::ABI);
        assert_eq!(campaign.steps[2].input_type, EVMInputTy::ABI);
    }

    #[test]
    fn test_plan_campaign_same_contract_with_topology() {
        use crate::evm::topology::{ExploitClass, ProtocolFamily, TopologyReport};
        let mut map = HashMap::new();
        let vault_addr = EVMAddress::from([0x10; 20]);
        // Same contract has both prime (deposit) and exploit (redeem) selectors
        map.insert(vault_addr, vec![
            make_abi(PRIME_SELECTORS[0]),
            make_abi(EXPLOIT_SELECTORS[1]), // redeem
        ]);
        let abi_map = ABIAddressToInstanceMap { map };
        let cache = CampaignTargetCache::new(&abi_map, Vec::new());
        assert!(cache.is_viable());

        // Build a topology report that ranks PriceGatedVault (same-contract class) highest
        let mut families = HashSet::new();
        families.insert(ProtocolFamily::ERC4626);
        families.insert(ProtocolFamily::Chainlink);
        let report = TopologyReport::analyze(families);
        // Same address has both prime+exploit selectors → should pair on same contract
        let campaign = plan_campaign(&cache, Some(&report), false).expect("should produce campaign");
        assert_eq!(campaign.steps.len(), 2);
        assert_eq!(campaign.steps[0].contract, campaign.steps[1].contract,
            "topology with same-contract class should pick same address");
    }

    #[test]
    fn test_planner_adds_warp_when_temporal_skimming_enabled() {
        let mut map = HashMap::new();
        let prime_addr = EVMAddress::from([0x01; 20]);
        let exploit_addr = EVMAddress::from([0x02; 20]);
        map.insert(prime_addr, vec![make_abi(PRIME_SELECTORS[0])]);
        map.insert(exploit_addr, vec![make_abi(EXPLOIT_SELECTORS[0])]);
        let abi_map = ABIAddressToInstanceMap { map };
        let cache = CampaignTargetCache::new(&abi_map, Vec::new());

        // temporal_skimming = true → should insert warp before exploit step
        let campaign = plan_campaign(&cache, None, true).expect("should produce campaign");
        assert_eq!(campaign.steps.len(), 2);
        assert_eq!(campaign.warps.len(), 1, "should have 1 warp entry");
        assert_eq!(campaign.warps[0].0, 1, "warp should be before exploit step (index 1)");
        assert_eq!(campaign.warps[0].1, 10, "warp should default to 10 blocks");
    }

    #[test]
    fn test_planner_no_warp_when_temporal_skimming_disabled() {
        let mut map = HashMap::new();
        let prime_addr = EVMAddress::from([0x01; 20]);
        let exploit_addr = EVMAddress::from([0x02; 20]);
        map.insert(prime_addr, vec![make_abi(PRIME_SELECTORS[0])]);
        map.insert(exploit_addr, vec![make_abi(EXPLOIT_SELECTORS[0])]);
        let abi_map = ABIAddressToInstanceMap { map };
        let cache = CampaignTargetCache::new(&abi_map, Vec::new());

        // temporal_skimming = false → no warps (backward compatible)
        let campaign = plan_campaign(&cache, None, false).expect("should produce campaign");
        assert!(campaign.warps.is_empty(), "no warps when temporal_skimming is disabled");
    }
}

fn build_abi_step(target: EVMAddress, abi: Option<BoxedABI>) -> ConciseEVMInput {
    // Pin the concrete function (`abi`) so the step calls it directly — required for
    // the executor's controlled warp probe to exercise the time-gated function
    // instead of hitting the fallback with empty calldata. Args are still mutated
    // via the `mutate_with_vm_slots` path. `None` falls back to the contract.
    ConciseEVMInput {
        input_type: EVMInputTy::ABI,
        caller: EVMAddress::default(),
        contract: target,
        data: abi,
        txn_value: None,
        step: false,
        env: Default::default(),
        liquidation_percent: 0,
        randomness: vec![],
        repeat: 1,
        layer: 0,
        call_leak: u32::MAX,
        return_data: None,
        swap_data: HashMap::new(),
        nested_actions: Vec::new(),
        campaign: None,
    }
}
