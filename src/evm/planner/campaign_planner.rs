use std::collections::HashMap;

use libafl_bolts::impl_serdeany;
use serde::{Deserialize, Serialize};

use crate::evm::abi::{ABIAddressToInstanceMap, BoxedABI};
use crate::evm::input::{CampaignSequence, ConciseEVMInput, EVMInputTy};
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
) -> Option<CampaignSequence> {
    let mut steps: Vec<ConciseEVMInput> = Vec::new();

    // Step 0 (optional): Borrow step — acquire capital via flashloan
    if let Some(token_addr) = cache.borrowable_tokens.first() {
        steps.push(build_borrow_step(*token_addr));
    }

    // Step N: Prime state (deposit/mint/stake into target protocol)
    let has_prime = cache.prime_targets.first().map(|(addr, _, _)| *addr);
    if let Some(prime_addr) = has_prime {
        steps.push(build_abi_step(prime_addr));

        // Step N+1: Trigger exploit (withdraw/redeem/liquidate from target)
        if let Some((exploit_addr, _, _)) = cache.exploit_targets.first() {
            steps.push(build_abi_step(*exploit_addr));
        }
    }

    // Minimum viable campaign: at least 2 steps
    if steps.len() < 2 {
        return None;
    }

    Some(CampaignSequence { steps, linkages: Vec::new() })
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
        assert!(plan_campaign(&cache).is_none());
    }

    #[test]
    fn test_cache_prime_only_not_viable() {
        let mut map = HashMap::new();
        let addr = EVMAddress::default();
        map.insert(addr, vec![make_abi(PRIME_SELECTORS[0])]);
        let abi_map = ABIAddressToInstanceMap { map };
        let cache = CampaignTargetCache::new(&abi_map, Vec::new());
        assert!(!cache.is_viable());
        assert!(plan_campaign(&cache).is_none());
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
        let campaign = plan_campaign(&cache).expect("should produce campaign");
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
        let campaign = plan_campaign(&cache).expect("should produce campaign");
        assert_eq!(campaign.steps.len(), 3);
        assert_eq!(campaign.steps[0].input_type, EVMInputTy::Borrow);
        assert_eq!(campaign.steps[0].contract, token);
        assert_eq!(campaign.steps[1].input_type, EVMInputTy::ABI);
        assert_eq!(campaign.steps[2].input_type, EVMInputTy::ABI);
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
