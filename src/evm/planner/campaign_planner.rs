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

/// Pre-filtered campaign target cache, initialized once during corpus setup.
/// Replaces the O(N) ABI registry scan with an O(1) read-only lookup.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CampaignTargetCache {
    pub prime_targets: Vec<(EVMAddress, [u8; 4], BoxedABI)>,
    pub exploit_targets: Vec<(EVMAddress, [u8; 4], BoxedABI)>,
    pub borrowable_tokens: Vec<EVMAddress>,
}

impl_serdeany!(CampaignTargetCache);

impl CampaignTargetCache {
    /// Build the cache from the ABI registry by scanning for known selector patterns.
    pub fn new(abi_map: &ABIAddressToInstanceMap, borrowable_tokens: Vec<EVMAddress>) -> Self {
        Self {
            prime_targets: find_targets_by_selector(abi_map, PRIME_SELECTORS),
            exploit_targets: find_targets_by_selector(abi_map, EXPLOIT_SELECTORS),
            borrowable_tokens,
        }
    }

    /// Returns true if this cache has enough targets to form at least a 2-step campaign.
    pub fn is_viable(&self) -> bool {
        !self.prime_targets.is_empty() && !self.exploit_targets.is_empty()
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
) -> Option<CampaignSequence> {
    let mut steps: Vec<ConciseEVMInput> = Vec::new();

    // Step 0 (optional): Borrow step — acquire capital via flashloan
    if let Some(token_addr) = cache.borrowable_tokens.first() {
        steps.push(build_borrow_step(*token_addr));
    }

    // Populate prime + exploit steps, respecting topology hints
    let (prime_step, exploit_step) = pick_prime_and_exploit(cache, topology_report);
    if let Some(addr) = prime_step {
        steps.push(build_abi_step(addr));
    }
    if let Some(addr) = exploit_step {
        steps.push(build_abi_step(addr));
    }

    // Minimum viable campaign: at least 2 steps
    if steps.len() < 2 {
        return None;
    }

    Some(CampaignSequence { steps, linkages: Vec::new() })
}

/// Pick prime and exploit target addresses, using topology intelligence
/// to prefer same-contract pairs when the top-ranked exploit class
/// suggests a single-contract vulnerability (ERC-4626 vaults, staking
/// pools, etc.).
fn pick_prime_and_exploit<'a>(
    cache: &'a CampaignTargetCache,
    topology_report: Option<&TopologyReport>,
) -> (Option<EVMAddress>, Option<EVMAddress>) {
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
        // Try to find an address that appears in both prime and exploit lists
        let exploit_addrs: HashSet<EVMAddress> = cache
            .exploit_targets
            .iter()
            .map(|(a, _, _)| *a)
            .collect();
        for (addr, _, _) in &cache.prime_targets {
            if exploit_addrs.contains(addr) {
                return (Some(*addr), Some(*addr));
            }
        }
    }

    // Default: pick first from each list
    (
        cache.prime_targets.first().map(|(a, _, _)| *a),
        cache.exploit_targets.first().map(|(a, _, _)| *a),
    )
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
        assert!(plan_campaign(&cache, None).is_none());
    }

    #[test]
    fn test_cache_prime_only_not_viable() {
        let mut map = HashMap::new();
        let addr = EVMAddress::default();
        map.insert(addr, vec![make_abi(PRIME_SELECTORS[0])]);
        let abi_map = ABIAddressToInstanceMap { map };
        let cache = CampaignTargetCache::new(&abi_map, Vec::new());
        assert!(!cache.is_viable());
        assert!(plan_campaign(&cache, None).is_none());
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
        let campaign = plan_campaign(&cache, None).expect("should produce campaign");
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
        let campaign = plan_campaign(&cache, None).expect("should produce campaign");
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
        let campaign = plan_campaign(&cache, Some(&report)).expect("should produce campaign");
        assert_eq!(campaign.steps.len(), 2);
        assert_eq!(campaign.steps[0].contract, campaign.steps[1].contract,
            "topology with same-contract class should pick same address");
    }
}

fn build_abi_step(target: EVMAddress) -> ConciseEVMInput {
    // Construct a minimal ABI step. Parameter resolution happens during mutation
    // via the existing `mutate_with_vm_slots` path.
    ConciseEVMInput {
        input_type: EVMInputTy::ABI,
        caller: EVMAddress::default(),
        contract: target,
        data: None,
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
