use std::collections::HashMap;

use libafl_bolts::impl_serdeany;
use libafl_bolts::rands::{Rand, StdRand};
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
    /// Feature 015: contracts exposing a reflexive-skew liquidity primitive
    /// (`add_liquidity` / `remove_liquidity_imbalance`). Scanned independently of the
    /// prime/exploit allowlists so promotion can fire without polluting normal discovery;
    /// consulted ONLY on the `--reflexive-lever` path, so when the feature is off this
    /// field is computed once but never read — off-path behavior is byte-identical.
    #[serde(default)]
    pub reflexive_targets: Vec<(EVMAddress, [u8; 4], BoxedABI)>,
}

impl_serdeany!(CampaignTargetCache);

/// Feature 015 Phase 2 — per-step boundary offsets into the campaign's ordered
/// `erc20_transfers` log, written by the campaign executor when `CampaignSequence.aposteriori`
/// is set. `offsets[i]` is the length of the transfer log BEFORE step `i` executed, with a
/// trailing entry for the total after the last step — so step `i`'s transfers are the slice
/// `erc20_transfers[offsets[i]..offsets[i+1]]`. This is the ONLY new instrumentation the
/// a-posteriori path needs: the atomic campaign's staged-state chaining already accumulates
/// the transfer log in order across steps, so recording the offsets suffices to attribute an
/// attacker-inflow delta to the belly call that produced it. `offsets.len() == steps.len()+1`.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct CampaignInflowBoundaries {
    pub offsets: Vec<usize>,
}

impl_serdeany!(CampaignInflowBoundaries);

/// Feature 015 Phase 2 — the ledger-moving belly call discovered a-posteriori. The feedback
/// attributes per-step attacker inflow via `CampaignInflowBoundaries`, and records the single
/// highest-inflow step here (one lever/frame — protects the 3.5GB ceiling against
/// over-promotion). The mutator reads this and pins the matching campaign step into
/// `CampaignSequence.promoted` so Locate+Amplify (the ledger-secant) tunes it. Keyed by
/// `(contract, selector)` so the pin re-fires whenever that call recurs in a freshly sampled
/// campaign, despite clone-per-iteration corpus semantics. `best_inflow` is a high-water mark:
/// only a strictly larger delta replaces the incumbent candidate.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PromotionCandidate {
    pub contract: EVMAddress,
    pub selector: [u8; 4],
    pub best_inflow: u128,
    pub set: bool,
}

impl_serdeany!(PromotionCandidate);

impl CampaignTargetCache {
    /// Build the cache from the ABI registry by scanning for known selector patterns.
    /// Delegates with no preset selectors → hardcoded PRIME/EXPLOIT fallback.
    pub fn new(abi_map: &ABIAddressToInstanceMap, borrowable_tokens: Vec<EVMAddress>) -> Self {
        Self::new_with_preset(abi_map, borrowable_tokens, &[])
    }

    /// Candidate-based target discovery. When `preset_selectors` is non-empty (a preset
    /// matched the target), the prime/exploit chain candidates are drawn from the matched
    /// EXPLOIT'S OWN vocabulary — so the campaign chains what THIS exploit actually uses,
    /// adapting to the target instead of hunting a hardcoded function menu the exploit's
    /// selectors may fall entirely outside of. Empty → falls back to the hardcoded
    /// PRIME/EXPLOIT_SELECTORS. This removes the hidden candidate-bias at discovery: the
    /// same "candidates, not a fixed prior" principle the preset system already uses.
    pub fn new_with_preset(
        abi_map: &ABIAddressToInstanceMap,
        borrowable_tokens: Vec<EVMAddress>,
        preset_selectors: &[[u8; 4]],
    ) -> Self {
        let (prime_sels, exploit_sels): (&[[u8; 4]], &[[u8; 4]]) = if !preset_selectors.is_empty() {
            // Every matched-exploit selector is a candidate for both ends of the chain;
            // pick_prime_and_exploit (value-flow-aware) then orders them.
            (preset_selectors, preset_selectors)
        } else {
            (PRIME_SELECTORS, EXPLOIT_SELECTORS)
        };
        Self {
            prime_targets: find_targets_by_selector(abi_map, prime_sels),
            exploit_targets: find_targets_by_selector(abi_map, exploit_sels),
            borrowable_tokens,
            generic_targets: find_generic_targets(abi_map),
            // Feature 015: independent scan for the two reflexive-skew liquidity
            // primitives, regardless of what the prime/exploit allowlists matched.
            reflexive_targets: find_targets_by_selector(
                abi_map,
                &[SEL_ADD_LIQUIDITY, SEL_REMOVE_LIQUIDITY_IMBALANCE],
            ),
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
    // Deterministic entry (tests / no live fuzzer RNG): seed a fixed local RNG.
    // With single-candidate pools the sampled draw resolves to the sole element,
    // so structure is stable; production goes through the value-flow entry below
    // with the live `state.rand_mut()`.
    let mut rand = StdRand::with_seed(0xC0FFEE);
    // Deterministic/test entry keeps reflexive promotion OFF; the live fuzzer path
    // (mutator) passes `self.reflexive_lever`.
    plan_campaign_sampled(cache, topology_report, temporal_skimming, false, &mut rand)
}

/// Feature 015 selectors of reflexive-skew liquidity primitives.
/// `add_liquidity(uint256[N],uint256)` = 0x4515cef3 (Curve StableSwap 3-pool form);
/// `remove_liquidity_imbalance(uint256[N],uint256)` = 0x9fdaea0c.
const SEL_ADD_LIQUIDITY: [u8; 4] = [0x45, 0x15, 0xce, 0xf3];
const SEL_REMOVE_LIQUIDITY_IMBALANCE: [u8; 4] = [0x9f, 0xda, 0xea, 0x0c];

/// Feature 015 — a-priori Promote. If the harvested vocabulary (target cache) contains a
/// reflexive-skew liquidity primitive, return a pinned lever step for it. `add_liquidity`
/// is the primary skew lever (it moves the pool balance the vault reads); we fall back to
/// `remove_liquidity_imbalance`. Keyed on selector presence so it fires on both the preset
/// path (selectors seeded into the cache) and the onchain path (harvested ABIs).
fn maybe_promote_lever(cache: &CampaignTargetCache) -> Option<ConciseEVMInput> {
    for want in [SEL_ADD_LIQUIDITY, SEL_REMOVE_LIQUIDITY_IMBALANCE] {
        if let Some((addr, _sel, abi)) = cache.reflexive_targets.iter().find(|(_, sel, _)| *sel == want) {
            return Some(build_abi_step(*addr, Some(abi.clone())));
        }
    }
    None
}

/// Structural-sampling campaign planner. The planner's ONLY job is to propose an
/// atomic frame (borrow → sampled prime → sampled exploit) by drawing uniformly from
/// the harvested contract vocabulary, `get_next_call`-style. It deliberately does NOT
/// consult any per-selector "value-flow" signal: the authoritative economic feedback
/// is the primitive net-realized ledger (`flashloan_data.earned/owed`,
/// `net_realized()` in feedbacks.rs) that already gates the objective/fitness layer.
/// The planner PROPOSES structure; the machine-primitive ledger DISPOSES — monotonic
/// filtering keeps only sampled sequences that yield genuine token/ETH inflows. A
/// prior version anchored the prime on `observed_values` (a syntactic ABI-return
/// pool), which read `approve`'s `bool true` as profit and collapsed chains toward
/// `approve → approve`. That proxy is removed; the ledger is the single source of
/// economic truth.
pub fn plan_campaign_sampled<R: Rand>(
    cache: &CampaignTargetCache,
    topology_report: Option<&TopologyReport>,
    temporal_skimming: bool,
    reflexive_lever: bool,
    rand: &mut R,
) -> Option<CampaignSequence> {
    let mut steps: Vec<ConciseEVMInput> = Vec::new();
    // Feature 015: indices of promoted reflexive-skew lever steps.
    let mut promoted: Vec<usize> = Vec::new();

    // Step 0 (optional): Borrow step — acquire capital via flashloan
    if let Some(token_addr) = cache.borrowable_tokens.first() {
        steps.push(build_borrow_step(*token_addr));
    }

    // Populate prime + exploit steps (with concrete function ABIs), respecting hints
    let (prime_step, exploit_step) = pick_prime_and_exploit(cache, topology_report, rand);
    if let Some((addr, abi)) = prime_step {
        steps.push(build_abi_step(addr, abi));
    }
    // Feature 015 — a-priori Promote: hoist the reflexive-skew liquidity lever
    // (`add_liquidity`/`remove_liquidity_imbalance`) into the frame BETWEEN prime and
    // exploit, so the ledger-secant can pin and amount-tune it. Without this the lever
    // only ever appears in the runtime belly (`get_next_call`) where no tuner can reach
    // it. Trigger keys on selector presence in the harvested vocabulary (works for both
    // preset and onchain paths); the `ReflexiveSkew` topology class only prioritizes.
    if reflexive_lever {
        if let Some(lever) = maybe_promote_lever(cache) {
            promoted.push(steps.len());
            steps.push(lever);
        }
    }
    // Feature 015 Phase 2 (a-posteriori Promote): on the reflexive path, if NO a-priori
    // lever matched (the target exposes no registered reflexive primitive), arm the
    // executor to record per-step attacker-inflow boundaries so the feedback can discover
    // the ledger-moving belly call at runtime. One lever/frame: only arm when `promoted`
    // is still empty. Off the reflexive path this stays `false` ⇒ no executor overhead.
    let aposteriori = reflexive_lever && promoted.is_empty();
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

    Some(CampaignSequence { steps, linkages: Vec::new(), warps, promoted, aposteriori })
}

/// Pick prime and exploit target addresses, using topology intelligence
/// to prefer same-contract pairs when the top-ranked exploit class
/// suggests a single-contract vulnerability (ERC-4626 vaults, staking
/// pools, etc.).
type PickedStep = Option<(EVMAddress, Option<BoxedABI>)>;

fn pick_prime_and_exploit<R: Rand>(
    cache: &CampaignTargetCache,
    topology_report: Option<&TopologyReport>,
    rand: &mut R,
) -> (PickedStep, PickedStep) {
    // No per-selector "value-flow" anchor: economic truth is the net-realized ledger
    // at the objective layer (see plan_campaign_sampled docs). The planner only
    // samples structure; topology INFORMS a same-contract preference, nothing FORCES
    // an aim.
    let prefer_same_contract = topology_report
        .and_then(|r| r.ranked.first())
        .map(|(cls, _)| {
            matches!(
                cls,
                ExploitClass::PriceGatedVault
                    | ExploitClass::FlashDepositDrain
                    | ExploitClass::RewardAccumulator
                    | ExploitClass::ReflexiveSkew
            )
        })
        .unwrap_or(false);

    if prefer_same_contract {
        // Sample among same-contract prime/exploit pairs (not the first pair), each
        // side's concrete function pinned. Topology INFORMS the preference (same
        // contract); the draw within that preference stays a coverage-style sample.
        let pairs: Vec<(usize, usize)> = cache
            .prime_targets
            .iter()
            .enumerate()
            .filter_map(|(pi, (addr, p_sel, _))| {
                // Same-contract exploit candidates, EXCLUDING the prime's own selector.
                // A step calling the same function twice on the same contract is a
                // degenerate chain, not a prime→exploit — and it's exactly how a
                // single-vocabulary contract (e.g. 3Crv, whose only matched selector is
                // approve) forces X→X. Excluding p_sel drops such a prime out of the
                // same-contract pairing entirely (falls through to the default sampler).
                let exps: Vec<usize> = cache
                    .exploit_targets
                    .iter()
                    .enumerate()
                    .filter(|(_, (a, sel, _))| a == addr && sel != p_sel)
                    .map(|(i, _)| i)
                    .collect();
                sample_idx(exps.len(), rand).map(|k| (pi, exps[k]))
            })
            .collect();
        if let Some((pi, ei)) = sample_idx(pairs.len(), rand).map(|k| pairs[k]) {
            let (p_addr, _, p_abi) = &cache.prime_targets[pi];
            let (_, _, e_abi) = &cache.exploit_targets[ei];
            return (
                Some((*p_addr, Some(p_abi.clone()))),
                Some((*p_addr, Some(e_abi.clone()))),
            );
        }
    }

    // Default: SELECTOR-LEVEL sample from each candidate pool, exactly like the
    // original fuzzland's get_next_call (draw from `interesting_signatures`, a SET of
    // selectors, then resolve to a contract). Sampling raw `(contract, selector)`
    // entries would weight a selector by how many contracts expose it, so a ubiquitous
    // ERC-20 method (approve, on every token) drowns out the exploit-specific words —
    // the [pool-tel]-confirmed approve=3/7 skew. Two-stage sampling (uniform over
    // distinct selectors, then a contract carrying it) restores one-word-one-vote
    // while keeping contract diversity. Coverage-guided steps sequence the survivors.
    let prime = sample_by_selector(&cache.prime_targets, rand).map(|(a, _, abi)| (*a, Some(abi.clone())));
    let exploit = sample_by_selector(&cache.exploit_targets, rand).map(|(a, _, abi)| (*a, Some(abi.clone())));
    if prime.is_some() && exploit.is_some() {
        return (prime, exploit);
    }

    // Fallback: name-heuristic single-contract target (sampled). Pin the trigger
    // function as the exploit step (so the executor probe calls it, not the
    // fallback) and a different function as the benign prime step.
    if let Some(gi) = sample_idx(cache.generic_targets.len(), rand) {
        let (addr, prime_abi, exploit_abi) = &cache.generic_targets[gi];
        return (
            Some((*addr, prime_abi.clone())),
            Some((*addr, exploit_abi.clone())),
        );
    }

    (prime, exploit)
}

/// Selector-level uniform sample: draw a distinct selector (vocabulary word) uniformly
/// from `targets`, then a contract carrying it. Mirrors fuzzland's `get_next_call`
/// (draw from the selector SET `interesting_signatures`, then resolve a contract),
/// so a selector present on many contracts is one word with one vote — not weighted by
/// contract-multiplicity. `None` when empty.
fn sample_by_selector<'a, R: Rand>(
    targets: &'a [(EVMAddress, [u8; 4], BoxedABI)],
    rand: &mut R,
) -> Option<&'a (EVMAddress, [u8; 4], BoxedABI)> {
    // Distinct selectors, insertion-order-stable (determinism under a fixed seed).
    let mut selectors: Vec<[u8; 4]> = Vec::new();
    for (_, sel, _) in targets {
        if !selectors.contains(sel) {
            selectors.push(*sel);
        }
    }
    let sel = *selectors.get(sample_idx(selectors.len(), rand)?)?;
    // Contracts carrying the chosen selector; pick one uniformly (keeps diversity).
    let carriers: Vec<usize> = targets
        .iter()
        .enumerate()
        .filter(|(_, (_, s, _))| *s == sel)
        .map(|(i, _)| i)
        .collect();
    Some(&targets[carriers[sample_idx(carriers.len(), rand)?]])
}

/// Uniform random index into a slice of `len` elements (get_next_call-style draw).
/// `None` when empty. The one primitive behind the campaign's candidate sampling.
fn sample_idx<R: Rand>(len: usize, rand: &mut R) -> Option<usize> {
    if len == 0 {
        None
    } else {
        Some(rand.below(len as u64) as usize)
    }
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
    use std::collections::{HashMap, HashSet};

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

    /// Feature 015 — the cheapest proof the Promote path works end-to-end: a yDAI-like
    /// fixture (prime + exploit + a Curve pool exposing `add_liquidity`) must, with
    /// `reflexive_lever=true`, hoist the lever into the frame and record its index in
    /// `promoted`, and the promoted step must carry the `add_liquidity` selector.
    #[test]
    fn test_reflexive_lever_promoted_into_frame() {
        let mut map = HashMap::new();
        let prime_addr = EVMAddress::from([0x01; 20]);
        let exploit_addr = EVMAddress::from([0x02; 20]);
        let pool_addr = EVMAddress::from([0x0c; 20]); // Curve pool (the skew lever host)
        map.insert(prime_addr, vec![make_abi(PRIME_SELECTORS[0])]);
        map.insert(exploit_addr, vec![make_abi(EXPLOIT_SELECTORS[0])]);
        map.insert(pool_addr, vec![make_abi(SEL_ADD_LIQUIDITY)]);
        let abi_map = ABIAddressToInstanceMap { map };
        let cache = CampaignTargetCache::new(&abi_map, Vec::new());

        // The independent scan finds the lever even though it's not in PRIME_SELECTORS.
        assert!(
            cache.reflexive_targets.iter().any(|(a, s, _)| *a == pool_addr && *s == SEL_ADD_LIQUIDITY),
            "reflexive scan must discover the Curve pool's add_liquidity"
        );

        let mut rand = StdRand::with_seed(0xC0FFEE);
        let campaign = plan_campaign_sampled(&cache, None, false, true, &mut rand)
            .expect("viable prime+exploit → campaign");
        assert_eq!(campaign.promoted.len(), 1, "exactly one lever promoted");
        let lever_idx = campaign.promoted[0];
        let lever_sel = campaign.steps[lever_idx]
            .data
            .as_ref()
            .expect("promoted lever has a pinned ABI")
            .function;
        assert_eq!(lever_sel, SEL_ADD_LIQUIDITY, "promoted step is the add_liquidity lever");
        // The lever sits between prime and exploit (never last — the exploit reads after it).
        assert!(lever_idx < campaign.steps.len() - 1, "lever precedes the exploit step");
    }

    /// Off-path proof: with `reflexive_lever=false` the same fixture yields NO promotion,
    /// so the feature is genuinely inert when disabled (constitution: zero code path off).
    #[test]
    fn test_reflexive_lever_inert_when_disabled() {
        let mut map = HashMap::new();
        map.insert(EVMAddress::from([0x01; 20]), vec![make_abi(PRIME_SELECTORS[0])]);
        map.insert(EVMAddress::from([0x02; 20]), vec![make_abi(EXPLOIT_SELECTORS[0])]);
        map.insert(EVMAddress::from([0x0c; 20]), vec![make_abi(SEL_ADD_LIQUIDITY)]);
        let abi_map = ABIAddressToInstanceMap { map };
        let cache = CampaignTargetCache::new(&abi_map, Vec::new());

        let mut rand = StdRand::with_seed(0xC0FFEE);
        let campaign = plan_campaign_sampled(&cache, None, false, false, &mut rand)
            .expect("viable prime+exploit → campaign");
        assert!(campaign.promoted.is_empty(), "no promotion when reflexive_lever is off");
        assert_eq!(campaign.steps.len(), 2, "plain prime→exploit frame, lever untouched");
    }

    // ── Feature 015 Phase 2 (T10) — a-posteriori arming ──

    /// On a target with NO registered reflexive archetype (no `add_liquidity`/imbalance in the
    /// vocabulary), the reflexive path arms the executor's per-step inflow snapshot instead of
    /// promoting a-priori: `aposteriori == true`, `promoted` empty. This is the generalization
    /// trigger — "no archetype fired, so go discover the lever at runtime".
    #[test]
    fn test_aposteriori_armed_when_no_archetype() {
        let mut map = HashMap::new();
        // Prime + exploit only — deliberately NO Curve pool / reflexive selector present.
        map.insert(EVMAddress::from([0x01; 20]), vec![make_abi(PRIME_SELECTORS[0])]);
        map.insert(EVMAddress::from([0x02; 20]), vec![make_abi(EXPLOIT_SELECTORS[0])]);
        let abi_map = ABIAddressToInstanceMap { map };
        let cache = CampaignTargetCache::new(&abi_map, Vec::new());
        assert!(cache.reflexive_targets.is_empty(), "fixture has no reflexive archetype");

        let mut rand = StdRand::with_seed(0xC0FFEE);
        let campaign = plan_campaign_sampled(&cache, None, false, true, &mut rand)
            .expect("viable prime+exploit → campaign");
        assert!(campaign.promoted.is_empty(), "no a-priori lever to promote");
        assert!(campaign.aposteriori, "reflexive path with no archetype must arm a-posteriori");
    }

    /// When an a-priori archetype DOES fire, a-posteriori stays disarmed (the lever is already
    /// in the frame; one lever/frame). `promoted` populated ⇒ `aposteriori == false`.
    #[test]
    fn test_aposteriori_disarmed_when_apriori_fires() {
        let mut map = HashMap::new();
        map.insert(EVMAddress::from([0x01; 20]), vec![make_abi(PRIME_SELECTORS[0])]);
        map.insert(EVMAddress::from([0x02; 20]), vec![make_abi(EXPLOIT_SELECTORS[0])]);
        map.insert(EVMAddress::from([0x0c; 20]), vec![make_abi(SEL_ADD_LIQUIDITY)]);
        let abi_map = ABIAddressToInstanceMap { map };
        let cache = CampaignTargetCache::new(&abi_map, Vec::new());

        let mut rand = StdRand::with_seed(0xC0FFEE);
        let campaign = plan_campaign_sampled(&cache, None, false, true, &mut rand)
            .expect("viable prime+exploit → campaign");
        assert_eq!(campaign.promoted.len(), 1, "a-priori lever promoted");
        assert!(!campaign.aposteriori, "a-priori match ⇒ a-posteriori disarmed");
    }

    /// Off the reflexive path, a-posteriori is never armed (zero executor overhead).
    #[test]
    fn test_aposteriori_off_when_flag_off() {
        let mut map = HashMap::new();
        map.insert(EVMAddress::from([0x01; 20]), vec![make_abi(PRIME_SELECTORS[0])]);
        map.insert(EVMAddress::from([0x02; 20]), vec![make_abi(EXPLOIT_SELECTORS[0])]);
        let abi_map = ABIAddressToInstanceMap { map };
        let cache = CampaignTargetCache::new(&abi_map, Vec::new());

        let mut rand = StdRand::with_seed(0xC0FFEE);
        let campaign = plan_campaign_sampled(&cache, None, false, false, &mut rand)
            .expect("viable prime+exploit → campaign");
        assert!(!campaign.aposteriori, "flag off ⇒ never armed");
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
