/// Topology Intelligence — protocol family co-occurrence → ranked exploit class.
///
/// Every DeFi protocol exposes its shape through its ABI selector set.
/// When two protocol families appear in the same target set, the intersection
/// is almost always where the vulnerability lives. This module maps that
/// co-occurrence to a ranked list of exploit classes and the oracles that
/// detect them — before the fuzzer sends a single transaction.
use std::collections::{HashMap, HashSet};

use libafl_bolts::impl_serdeany;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::evm::{
    contract_utils::{ABIConfig, ContractLoader},
    oracles::function::is_privileged_fn,
    types::EVMAddress,
};

/// Protocol family inferred from ABI selector fingerprinting.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolFamily {
    ERC20,
    ERC721,
    ERC1155,
    ERC4626,
    Chainlink,
    UniswapV2,
    UniswapV3,
    Lending,
    FlashLoan,
    Governance,
    Staking,
    EIP712,
    Privileged,
    Callback,
    Rebasing,
}

impl ProtocolFamily {
    pub fn name(&self) -> &'static str {
        match self {
            ProtocolFamily::ERC20 => "ERC-20",
            ProtocolFamily::ERC721 => "ERC-721",
            ProtocolFamily::ERC1155 => "ERC-1155",
            ProtocolFamily::ERC4626 => "ERC-4626 vault",
            ProtocolFamily::Chainlink => "Chainlink oracle",
            ProtocolFamily::UniswapV2 => "Uniswap V2 AMM",
            ProtocolFamily::UniswapV3 => "Uniswap V3 AMM",
            ProtocolFamily::Lending => "lending protocol",
            ProtocolFamily::FlashLoan => "flash loan",
            ProtocolFamily::Governance => "governance",
            ProtocolFamily::Staking => "staking/rewards",
            ProtocolFamily::EIP712 => "EIP-712 permit",
            ProtocolFamily::Privileged => "privileged functions",
            ProtocolFamily::Callback => "callback receiver",
            ProtocolFamily::Rebasing => "rebasing token",
        }
    }
}

/// Exploit class derived from protocol family co-occurrence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExploitClass {
    /// ERC-4626 + Chainlink: price-gated vault — share price manipulation via stale oracle.
    /// Euler, Midas, EUL pattern.
    PriceGatedVault,
    /// ERC-4626 + FlashLoan: flash deposit/withdraw drain.
    /// Donate-inflate-redeem pattern.
    FlashDepositDrain,
    /// Lending + FlashLoan: leveraged undercollateralized borrow.
    /// CREAM, Euler v1 pattern.
    FlashBorrowLeverage,
    /// Governance + ERC-20: flash-loan governance attack.
    /// Beanstalk ($182M) pattern.
    FlashGovernance,
    /// AMM + Chainlink: spot price distortion fed to on-chain oracle.
    /// Mango Markets, TWAP gaming pattern.
    OraclePriceManip,
    /// ERC-721 + Callback: reentrancy via safeTransferFrom hook.
    /// NFT marketplace patterns.
    NFTReentrancy,
    /// Staking + Vault/Lending: reward accumulator miscalculation.
    /// Reserve/rewards desync, share inflation sub-class.
    RewardAccumulator,
    /// EIP-712: signature replay or missing domain separator.
    SignatureReplay,
    /// Privileged functions: unauthorized access / permission escalation.
    PermissionEscalation,
    /// Callback + ERC-20: arbitrary call with attacker-controlled target drains tokens.
    ArbitraryCallDrain,
    /// AMM alone: K-invariant bypass, slippage manipulation.
    AMMInvariant,
    /// Rebasing + ERC-20: fee-on-transfer / rebase accounting error.
    DeflationaryToken,
    /// Callback alone: unprotected flash callback allows state manipulation.
    UnprotectedCallback,
    /// Feature 015 — AMM + Vault/Staking: REFLEXIVE skew. A liquidity primitive
    /// (`add_liquidity`/`remove_liquidity_imbalance`) skews a pool invariant, a vault
    /// reads the skewed virtual price mid-sequence, and the unwind pockets the delta.
    /// Yearn yDAI ($11M), Harvest ($34M) pattern. The manipulation is a TRANSITION, so
    /// the lever must be promoted into the tunable frame (see Feature 015).
    ReflexiveSkew,
}

impl ExploitClass {
    pub fn name(&self) -> &'static str {
        match self {
            ExploitClass::PriceGatedVault => "price-gated vault (share price manip)",
            ExploitClass::FlashDepositDrain => "flash deposit/withdraw drain",
            ExploitClass::FlashBorrowLeverage => "flash-loan leveraged borrow drain",
            ExploitClass::FlashGovernance => "flash-loan governance takeover",
            ExploitClass::OraclePriceManip => "spot price / TWAP oracle manipulation",
            ExploitClass::NFTReentrancy => "NFT safeTransfer reentrancy",
            ExploitClass::RewardAccumulator => "reward accumulator / share inflation",
            ExploitClass::SignatureReplay => "signature replay / missing domain sep",
            ExploitClass::PermissionEscalation => "unauthorized privileged function call",
            ExploitClass::ArbitraryCallDrain => "arbitrary call drain",
            ExploitClass::AMMInvariant => "AMM K-invariant / slippage bypass",
            ExploitClass::DeflationaryToken => "fee-on-transfer / rebase accounting error",
            ExploitClass::UnprotectedCallback => "unprotected flash/swap callback",
            ExploitClass::ReflexiveSkew => "reflexive AMM skew (pool price read mid-sequence)",
        }
    }

    /// Primitive category (maps to the six DeFi data-flow primitives).
    pub fn primitive(&self) -> &'static str {
        match self {
            ExploitClass::PriceGatedVault => "invariant leak",
            ExploitClass::FlashDepositDrain => "value leak",
            ExploitClass::FlashBorrowLeverage => "value leak",
            ExploitClass::FlashGovernance => "permission leak",
            ExploitClass::OraclePriceManip => "invariant leak",
            ExploitClass::NFTReentrancy => "control leak",
            ExploitClass::RewardAccumulator => "invariant leak",
            ExploitClass::SignatureReplay => "permission leak",
            ExploitClass::PermissionEscalation => "permission leak",
            ExploitClass::ArbitraryCallDrain => "message leak",
            ExploitClass::AMMInvariant => "invariant leak",
            ExploitClass::DeflationaryToken => "value leak",
            ExploitClass::UnprotectedCallback => "control leak",
            // Reflexive skew leaks the pool INVARIANT (virtual price) into a vault read.
            ExploitClass::ReflexiveSkew => "invariant leak",
        }
    }
}

/// Result of topology analysis across all target contracts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyReport {
    pub families: HashSet<ProtocolFamily>,
    /// (exploit class, confidence 0-100), sorted descending by confidence.
    pub ranked: Vec<(ExploitClass, u8)>,
}

impl TopologyReport {
    /// Analyze a set of protocol families detected across all target contracts
    /// and return a ranked list of exploit classes.
    pub fn analyze(families: HashSet<ProtocolFamily>) -> Self {
        let mut scores: Vec<(ExploitClass, u8)> = Vec::new();

        let has = |f: &ProtocolFamily| families.contains(f);
        let has_amm = has(&ProtocolFamily::UniswapV2) || has(&ProtocolFamily::UniswapV3);

        // Two-family co-occurrences — highest confidence signals
        if has(&ProtocolFamily::ERC4626) && has(&ProtocolFamily::Chainlink) {
            scores.push((ExploitClass::PriceGatedVault, 95));
        }
        if has(&ProtocolFamily::ERC4626) && has(&ProtocolFamily::FlashLoan) {
            scores.push((ExploitClass::FlashDepositDrain, 90));
        }
        if has(&ProtocolFamily::Lending) && has(&ProtocolFamily::FlashLoan) {
            scores.push((ExploitClass::FlashBorrowLeverage, 90));
        }
        if has(&ProtocolFamily::Governance) && has(&ProtocolFamily::ERC20) {
            scores.push((ExploitClass::FlashGovernance, 85));
        }
        if has_amm && has(&ProtocolFamily::Chainlink) {
            scores.push((ExploitClass::OraclePriceManip, 85));
        }
        if has(&ProtocolFamily::ERC721) && has(&ProtocolFamily::Callback) {
            scores.push((ExploitClass::NFTReentrancy, 80));
        }
        if has(&ProtocolFamily::Staking)
            && (has(&ProtocolFamily::ERC4626) || has(&ProtocolFamily::Lending))
        {
            scores.push((ExploitClass::RewardAccumulator, 80));
        }
        if has(&ProtocolFamily::Callback) && has(&ProtocolFamily::ERC20) {
            scores.push((ExploitClass::ArbitraryCallDrain, 78));
        }
        // Feature 015 — reflexive skew: a manipulable pricing surface co-occurring with a
        // layer that reads that surface mid-sequence. Two shapes, both confirmed by corpus
        // mining (.speckit/research/reflexive-lever-corpus-mining.md — 57 cross-step incidents):
        //   (a) AMM/liquidity pool + vault/staking/lending that reads the pool price. The
        //       canonical Curve-vault yDAI shape.
        //   (b) lending-fork + flash loan with NO external AMM — the lending market IS the
        //       skewable surface (mint/redeem/borrow warps cToken `exchangeRate`, consumed by
        //       a later borrow). This is the mined MAJORITY (lending-dominated, ~40+ of 57),
        //       so we fire ReflexiveSkew here too, just under FlashBorrowLeverage (90) so the
        //       leverage class still leads while reflexive promotion is armed.
        // Ranked above the bare AMMInvariant single-family signal (65) so reflexive targets
        // prefer the promoted-lever plan. Concrete promotion still keys on selector presence
        // in the target cache (see campaign_planner) — this score drives prioritization only.
        if has_amm
            && (has(&ProtocolFamily::ERC4626)
                || has(&ProtocolFamily::Lending)
                || has(&ProtocolFamily::Staking))
        {
            scores.push((ExploitClass::ReflexiveSkew, 88));
        } else if has(&ProtocolFamily::Lending) && has(&ProtocolFamily::FlashLoan) {
            scores.push((ExploitClass::ReflexiveSkew, 82));
        }
        if has(&ProtocolFamily::Rebasing) && has(&ProtocolFamily::ERC20) {
            scores.push((ExploitClass::DeflationaryToken, 78));
        }

        // Single-family signals — lower confidence but always worth checking
        if has(&ProtocolFamily::Privileged) {
            scores.push((ExploitClass::PermissionEscalation, 85));
        }
        if has(&ProtocolFamily::EIP712) {
            scores.push((ExploitClass::SignatureReplay, 70));
        }
        if has_amm {
            scores.push((ExploitClass::AMMInvariant, 65));
        }
        if has(&ProtocolFamily::Callback) && !has(&ProtocolFamily::ERC20) {
            scores.push((ExploitClass::UnprotectedCallback, 72));
        }

        scores.sort_by(|a, b| b.1.cmp(&a.1));
        TopologyReport { families, ranked: scores }
    }

    /// Print topology report to tracing log.
    pub fn log(&self) {
        if self.ranked.is_empty() {
            return;
        }
        let family_names: Vec<&str> = self.families.iter().map(|f| f.name()).collect();
        info!("=== TOPOLOGY INTELLIGENCE ===");
        info!("  Families: {}", family_names.join(", "));
        info!("  Ranked attack surface:");
        for (class, confidence) in &self.ranked {
            info!("    [{:3}%] {} ({})", confidence, class.name(), class.primitive());
        }
        info!("=============================");
    }

    pub fn is_empty(&self) -> bool {
        self.ranked.is_empty()
    }
}

/// Classify a single ABI entry into a `ProtocolFamily`.
///
/// Name-first: function names are the canonical identifier for protocol
/// families. Selectors are deterministic for standard interfaces so the
/// two approaches agree — but name matching works for custom implementations
/// that don't use a standard function signature verbatim.
///
/// Delegates to existing detection functions where they already exist
/// (`is_oracle_interface`, `is_privileged_fn`) so classification logic
/// stays in one place.
fn extract_inherited_contracts(ast: &serde_json::Value) -> Vec<String> {
    let mut inherited = vec![];
    fn walk(value: &serde_json::Value, inherited: &mut Vec<String>) {
        if let Some(obj) = value.as_object() {
            if let Some(node_type) = obj.get("nodeType").and_then(|t| t.as_str()) {
                if node_type == "ContractDefinition" {
                    if let Some(base_contracts) = obj.get("baseContracts").and_then(|b| b.as_array()) {
                        for base in base_contracts {
                            if let Some(base_name) = base.get("baseName") {
                                if let Some(name) = base_name.get("name").and_then(|n| n.as_str()) {
                                    inherited.push(name.to_string());
                                }
                            }
                        }
                    }
                }
            }
            for (_, val) in obj {
                walk(val, inherited);
            }
        } else if let Some(arr) = value.as_array() {
            for val in arr {
                walk(val, inherited);
            }
        }
    }
    walk(ast, &mut inherited);
    inherited
}

pub fn classify_selector(
    selector: &[u8; 4],
    fn_name: &str,
    asts: Option<&Vec<(String, serde_json::Value)>>,
) -> Option<ProtocolFamily> {
    // Chainlink: existing detection function owns these selectors
    if crate::evm::oracles::freshness::is_oracle_interface(selector) {
        return Some(ProtocolFamily::Chainlink);
    }

    let n = fn_name.to_lowercase();

    // AST-based dynamic semantic verification (Primary)
    if let Some(ast_list) = asts {
        let mut inherits_erc4626 = false;
        let mut inherits_ctoken = false;

        for (_, ast) in ast_list {
            let parents = extract_inherited_contracts(ast);
            for parent in parents {
                let p = parent.to_lowercase();
                if p.contains("erc4626") {
                    inherits_erc4626 = true;
                }
                if p.contains("ctoken") || p.contains("cerc20") {
                    inherits_ctoken = true;
                }
            }
        }

        if inherits_erc4626 && matches!(n.as_str(), "deposit" | "mint" | "withdraw" | "redeem" | "asset") {
            return Some(ProtocolFamily::ERC4626);
        }

        if inherits_ctoken && matches!(n.as_str(), "mint" | "borrow" | "redeem" | "redeemunderlying") {
            return Some(ProtocolFamily::Lending);
        }
    }

    // Heuristics fallback (Secondary / Onchain Fork Environment)
    // ERC-4626 vault — names unique enough to not require sig disambiguation
    if matches!(
        n.as_str(),
        "convertoassets" | "converttoshares" | "totalassets" | "asset"
            | "previewdeposit" | "previewmint" | "previewwithdraw" | "previewredeem"
            | "maxdeposit" | "maxmint" | "maxwithdraw" | "maxredeem" | "redeem"
    ) {
        return Some(ProtocolFamily::ERC4626);
    }
    // deposit: ERC-4626 sig has 2 params (uint256,address); staking has 1 (uint256)
    if n == "deposit" && fn_name.contains("address") {
        return Some(ProtocolFamily::ERC4626);
    }

    // ERC-721
    if matches!(n.as_str(), "ownerof" | "tokenuri" | "getapproved") {
        return Some(ProtocolFamily::ERC721);
    }

    // ERC-1155
    if matches!(n.as_str(), "safebatchtransferfrom" | "balanceofbatch") {
        return Some(ProtocolFamily::ERC1155);
    }

    // ERC-20 (transfer/approve/balanceOf appear in many standards; ERC-20 is
    // the base case — more specific standards are caught above first)
    if matches!(n.as_str(), "transfer" | "transferfrom" | "approve" | "allowance" | "totalsupply" | "balanceof") {
        return Some(ProtocolFamily::ERC20);
    }

    // Uniswap V2 AMM
    if matches!(n.as_str(), "getreserves" | "token0" | "token1" | "swap" | "addliquidity" | "removeliquidity") {
        return Some(ProtocolFamily::UniswapV2);
    }

    // Uniswap V3 AMM — function names are distinctive enough
    if matches!(n.as_str(), "exactinputsingle" | "exactinput" | "exactoutputsingle" | "exactoutput" | "slot0") {
        return Some(ProtocolFamily::UniswapV3);
    }

    // Lending
    if matches!(n.as_str(), "borrow" | "repay" | "liquidate" | "liquidationcall") {
        return Some(ProtocolFamily::Lending);
    }

    // Flash loan entry points + callbacks
    if matches!(n.as_str(), "flashloan" | "executeoperation" | "uniswapv2call" | "pancakecall") {
        return Some(ProtocolFamily::FlashLoan);
    }

    // Callback receivers (execution windows mid-protocol-state)
    if matches!(n.as_str(), "onerc721received" | "onerc1155received" | "onerc1155batchreceived" | "tokensreceived") {
        return Some(ProtocolFamily::Callback);
    }

    // Governance
    if matches!(n.as_str(), "propose" | "castvote" | "queue") {
        return Some(ProtocolFamily::Governance);
    }

    // Staking / rewards
    if matches!(n.as_str(), "stake" | "unstake" | "getreward" | "notifyrewardamount" | "earned") {
        return Some(ProtocolFamily::Staking);
    }

    // EIP-712
    if n == "domain_separator" || n == "domainseparator" {
        return Some(ProtocolFamily::EIP712);
    }

    // Rebasing
    if matches!(n.as_str(), "rebase" | "sync") {
        return Some(ProtocolFamily::Rebasing);
    }

    // Privileged: existing detection function owns this classification
    if is_privileged_fn(fn_name) {
        return Some(ProtocolFamily::Privileged);
    }

    None
}

impl ExploitClass {
    /// Protocol families whose detected selectors should be prioritized
    /// for this exploit class. The scheduler collects the actual selectors
    /// the ABI loader classified into these families and boosts corpus entries
    /// that call them — no hardcoded bytes needed.
    pub fn target_families(&self) -> &'static [ProtocolFamily] {
        match self {
            ExploitClass::PriceGatedVault =>
                &[ProtocolFamily::ERC4626, ProtocolFamily::Chainlink, ProtocolFamily::FlashLoan],
            ExploitClass::FlashDepositDrain =>
                &[ProtocolFamily::ERC4626, ProtocolFamily::FlashLoan, ProtocolFamily::Callback],
            ExploitClass::FlashBorrowLeverage =>
                &[ProtocolFamily::Lending, ProtocolFamily::FlashLoan, ProtocolFamily::Callback],
            ExploitClass::FlashGovernance =>
                &[ProtocolFamily::Governance, ProtocolFamily::FlashLoan, ProtocolFamily::ERC20],
            ExploitClass::OraclePriceManip =>
                &[ProtocolFamily::UniswapV2, ProtocolFamily::UniswapV3, ProtocolFamily::Chainlink],
            ExploitClass::NFTReentrancy =>
                &[ProtocolFamily::ERC721, ProtocolFamily::Callback],
            ExploitClass::RewardAccumulator =>
                &[ProtocolFamily::Staking, ProtocolFamily::ERC4626, ProtocolFamily::Lending],
            ExploitClass::SignatureReplay =>
                &[ProtocolFamily::EIP712, ProtocolFamily::ERC20],
            ExploitClass::PermissionEscalation =>
                &[ProtocolFamily::Privileged, ProtocolFamily::ERC20],
            ExploitClass::ArbitraryCallDrain =>
                &[ProtocolFamily::Callback, ProtocolFamily::FlashLoan, ProtocolFamily::ERC20],
            ExploitClass::AMMInvariant =>
                &[ProtocolFamily::UniswapV2, ProtocolFamily::UniswapV3, ProtocolFamily::Rebasing],
            ExploitClass::DeflationaryToken =>
                &[ProtocolFamily::Rebasing, ProtocolFamily::ERC20],
            ExploitClass::UnprotectedCallback =>
                &[ProtocolFamily::Callback, ProtocolFamily::FlashLoan],
            ExploitClass::ReflexiveSkew =>
                &[ProtocolFamily::UniswapV2, ProtocolFamily::UniswapV3, ProtocolFamily::ERC4626],
        }
    }
}

/// Serializable topology hints stored as state metadata.
/// Produced from `TopologyReport` and consumed by `CorpusPowerABITestcaseScore`
/// to boost mutation energy toward topology-predicted exploit sequences.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)]
pub struct TopologyHints {
    /// Hint sets sorted descending by confidence.
    /// Each entry: (flat selector list, confidence 0-100).
    /// Flat because `[u8; 4]` doesn't impl Serialize cleanly as nested vec.
    pub sets: Vec<HintSet>,
    /// Mutator-bias strength in [0.0, 1.0] (from `--topology-bias`). Scales how much
    /// topology confidence steers the mutator: `multiplier = 1 + (conf/100) * bias`.
    /// 1.0 = full floodlight (legacy), 0.3 = nudge (default), 0.0 = topology stays on
    /// for intelligence + oracle gap-filling but the mutator runs unbiased.
    #[serde(default)]
    pub bias: f64,
    /// §7d content re-point / §7e #2 fix — per-CONTRACT family attribution, keeping the address
    /// key that the flat `sets`/`family_selectors` discard. Lets the planner pick the RIGHT
    /// capital-source contract for the Borrow slot instead of a blind first-token. Additive:
    /// existing flat consumers (mutator bias, scheduler boost) are untouched.
    #[serde(default)]
    pub contract_families: HashMap<EVMAddress, Vec<ProtocolFamily>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HintSet {
    pub confidence: u8,
    /// 4-byte selectors that should appear together in exploit sequences.
    /// Stored as Vec<[u8; 4]> — each inner array is one selector.
    pub selectors: Vec<[u8; 4]>,
}

impl_serdeany!(TopologyHints);

impl_serdeany!(TopologyReport);

impl TopologyHints {
    /// Build hint sets from the topology report using selectors the ABI loader
    /// actually found — no hardcoded bytes. Each exploit class declares which
    /// protocol families matter; we collect the real selectors that were
    /// classified into those families during corpus initialization.
    pub fn from_report_and_abi(
        report: &TopologyReport,
        address_to_abi: &HashMap<EVMAddress, Vec<ABIConfig>>,
        bias: f64,
        artifacts: &ContractLoader,
    ) -> Self {
        // Build family → selectors from already-loaded ABIs using the same
        // classify_selector logic that produced the topology report.
        let mut family_selectors: HashMap<ProtocolFamily, Vec<[u8; 4]>> = HashMap::new();
        // §7d/§7e #2: keep the per-CONTRACT attribution the flat map discards (address key).
        let mut contract_families: HashMap<EVMAddress, Vec<ProtocolFamily>> = HashMap::new();
        for (addr, abis) in address_to_abi {
            let asts = artifacts.contracts.iter()
                .find(|c| c.deployed_address == *addr)
                .and_then(|c| c.build_artifact.as_ref())
                .map(|a| &a.asts);
            for abi in abis {
                if let Some(family) = classify_selector(&abi.function, &abi.function_name, asts) {
                    family_selectors
                        .entry(family.clone())
                        .or_default()
                        .push(abi.function);
                    let cf = contract_families.entry(*addr).or_default();
                    if !cf.contains(&family) {
                        cf.push(family);
                    }
                }
            }
        }

        let sets = report
            .ranked
            .iter()
            .filter(|(_, confidence)| *confidence >= 70)
            .filter_map(|(class, confidence)| {
                let selectors: Vec<[u8; 4]> = class
                    .target_families()
                    .iter()
                    .flat_map(|f| family_selectors.get(f).cloned().unwrap_or_default())
                    .collect();
                if selectors.is_empty() {
                    None // no point boosting if the target has none of these selectors
                } else {
                    Some(HintSet { confidence: *confidence, selectors })
                }
            })
            .collect();

        TopologyHints { sets, bias, contract_families }
    }

    /// Returns the highest confidence hint set that contains `selector`,
    /// or `None` if no hint set matches.
    pub fn lookup(&self, selector: &[u8; 4]) -> Option<u8> {
        self.sets
            .iter()
            .find(|h| h.selectors.contains(selector))
            .map(|h| h.confidence)
    }
}

// ── Anti-topology ─────────────────────────────────────────────────────────────
//
// Anti-topology is the inverse of co-occurrence: it looks for ABSENT safety
// mechanisms that should be present given what IS there.  These checks run
// before the fuzzer sends a single transaction and output static pre-flight
// findings purely from the ABI selector set.
//
// Each rule asks: "given family X is present, is safety mechanism Y missing?"
// Missing safety mechanisms are often bugs in themselves — not just surfaces.

/// A static pre-flight finding produced before fuzzing begins.
#[derive(Debug, Clone)]
pub struct AntiTopologyFinding {
    /// Short machine-readable rule identifier.
    pub rule: &'static str,
    /// Human-readable description of the missing safety mechanism.
    pub detail: String,
    /// Confidence 0-100. Rules based on hard selector absence score higher
    /// than rules based on name heuristics.
    pub confidence: u8,
}

/// Run all anti-topology rules against the detected families and full ABI map.
/// Returns findings sorted descending by confidence.
/// Call this after `TopologyReport::analyze()` — it needs the same family set
/// plus the full `address_to_abi` map for param-signature inspection.
pub fn check_anti_topology(
    families: &HashSet<ProtocolFamily>,
    address_to_abi: &HashMap<EVMAddress, Vec<ABIConfig>>,
) -> Vec<AntiTopologyFinding> {
    let mut findings: Vec<AntiTopologyFinding> = Vec::new();

    let has = |f: &ProtocolFamily| families.contains(f);
    let has_amm = has(&ProtocolFamily::UniswapV2) || has(&ProtocolFamily::UniswapV3);

    // Flat sets for quick lookup
    let all_selectors: HashSet<[u8; 4]> = address_to_abi
        .values()
        .flat_map(|abis| abis.iter().map(|a| a.function))
        .collect();

    let all_abis: Vec<&ABIConfig> = address_to_abi
        .values()
        .flat_map(|abis| abis.iter())
        .collect();

    let has_sel = |s: [u8; 4]| all_selectors.contains(&s);

    let has_fn_keyword = |kw: &str| {
        all_abis.iter().any(|a| a.function_name.to_lowercase().contains(kw))
    };

    // ── Rule 1: Governance without timelock ───────────────────────────────────
    // propose()/execute() present but no queue() or delay() selector and no
    // function name containing "timelock" or "queue".
    // Beanstalk lost $182M to this exact configuration.
    if has(&ProtocolFamily::Governance) {
        let has_timelock = has_sel([0x56, 0x78, 0x13, 0x88]) // queue(uint256)
            || has_sel([0x6a, 0x42, 0xb8, 0xf8])             // delay()
            || has_sel([0xc0, 0x1a, 0x8c, 0x84])             // cancel(uint256)
            || has_fn_keyword("timelock")
            || has_fn_keyword("queue");

        if !has_timelock {
            findings.push(AntiTopologyFinding {
                rule: "governance-no-timelock",
                detail: "propose()/execute() present with no timelock delay — flash governance \
                         attack surface (flash borrow → vote → execute in one tx)"
                    .into(),
                confidence: 90,
            });
        }
    }

    // ── Rule 2: AMM + Chainlink without TWAP buffering ────────────────────────
    // Using a Chainlink oracle alongside an AMM without a TWAP window means
    // a single swap can skew the price the oracle reports — Mango Markets pattern.
    if has_amm && has(&ProtocolFamily::Chainlink) {
        let has_twap = has_fn_keyword("twap")
            || has_fn_keyword("period")
            || has_fn_keyword("average")
            || has_fn_keyword("window");

        if !has_twap {
            findings.push(AntiTopologyFinding {
                rule: "spot-price-no-twap",
                detail: "Chainlink oracle + AMM swap with no TWAP window — single swap can \
                         manipulate the price fed to the oracle"
                    .into(),
                confidence: 85,
            });
        }
    }

    // ── Rule 3: ERC-4626 vault without slippage protection ───────────────────
    // Standard-compliant vaults add minShares/minAssets/deadline params to
    // deposit/withdraw/redeem.  Absent these, a flash-donate inflates the
    // share price and the user receives fewer shares than expected — vault
    // inflation attack.
    if has(&ProtocolFamily::ERC4626) {
        let vault_entry_abis: Vec<&&ABIConfig> = all_abis
            .iter()
            .filter(|a| {
                matches!(
                    a.function,
                    [0x6e, 0x55, 0x3f, 0x65]   // deposit
                    | [0xb4, 0x60, 0xaf, 0x94]  // withdraw
                    | [0xba, 0x08, 0x76, 0x52]  // redeem
                )
            })
            .collect();

        if !vault_entry_abis.is_empty() {
            let has_slippage = vault_entry_abis.iter().any(|a| {
                let sig = a.abi.to_lowercase();
                sig.contains("min") || sig.contains("deadline") || sig.contains("max")
            });

            if !has_slippage {
                findings.push(AntiTopologyFinding {
                    rule: "vault-no-slippage",
                    detail: "ERC-4626 deposit/withdraw/redeem has no minShares/minAssets/deadline \
                             parameter — vault inflation attack surface"
                        .into(),
                    confidence: 82,
                });
            }
        }
    }

    // ── Rule 4: Flash loan callback without initiator validation ─────────────
    // executeOperation() that doesn't carry an `initiator` address parameter
    // cannot verify the flash loan was requested by this contract — the callback
    // can be invoked by anyone with an arbitrary payload.
    if has(&ProtocolFamily::FlashLoan) {
        let exec_op_abis: Vec<&&ABIConfig> = all_abis
            .iter()
            .filter(|a| a.function == [0x92, 0x0f, 0x5c, 0x84])
            .collect();

        for abi in &exec_op_abis {
            if !abi.abi.contains("initiator") && !abi.abi.contains("sender") {
                findings.push(AntiTopologyFinding {
                    rule: "flash-callback-no-initiator",
                    detail: format!(
                        "executeOperation() ABI `{}` has no initiator/sender param — \
                         caller validation may be absent, callback callable by anyone",
                        abi.abi
                    ),
                    confidence: 72,
                });
                break;
            }
        }
    }

    // ── Rule 5: ERC-20 transfer without fee accounting ────────────────────────
    // Protocol uses ERC-20 transfer/transferFrom but has no fee-on-transfer
    // awareness (no pre/post balance check pattern detectable from names).
    // Fee-on-transfer tokens cause accounting errors when the received amount
    // is less than the transfer amount.
    if has(&ProtocolFamily::ERC20) && !has(&ProtocolFamily::Rebasing) {
        let has_balance_check = has_fn_keyword("before")
            || has_fn_keyword("after")
            || has_fn_keyword("received")
            || has_fn_keyword("balance_before");

        // only flag if there's also a vault or lending protocol — those are the
        // contexts where fee-on-transfer accounting errors cause real fund loss
        let has_value_protocol =
            has(&ProtocolFamily::ERC4626) || has(&ProtocolFamily::Lending) || has(&ProtocolFamily::Staking);

        if !has_balance_check && has_value_protocol {
            findings.push(AntiTopologyFinding {
                rule: "no-fee-on-transfer-guard",
                detail: "ERC-20 + vault/lending/staking with no pre/post balance check pattern — \
                         fee-on-transfer tokens cause accounting desync"
                    .into(),
                confidence: 68,
            });
        }
    }

    // ── Rule 6: Privileged functions without any delay mechanism ─────────────
    // Admin functions callable immediately with no timelock, no multisig
    // pattern, and no role-based delay — single key compromise drains protocol.
    if has(&ProtocolFamily::Privileged) {
        let has_delay = has_sel([0x6a, 0x42, 0xb8, 0xf8]) // delay()
            || has_fn_keyword("timelock")
            || has_fn_keyword("multisig")
            || has_fn_keyword("gnosis")
            || has_fn_keyword("delay")
            || has_fn_keyword("schedule");

        if !has_delay {
            findings.push(AntiTopologyFinding {
                rule: "privileged-no-delay",
                detail: "privileged admin functions callable immediately — no timelock, \
                         multisig, or delay mechanism detected"
                    .into(),
                confidence: 75,
            });
        }
    }

    findings.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    findings
}

/// Log anti-topology findings at WARN level with a clear pre-flight prefix.
pub fn log_anti_topology(findings: &[AntiTopologyFinding]) {
    if findings.is_empty() {
        return;
    }
    warn!("=== ANTI-TOPOLOGY PRE-FLIGHT ===");
    for f in findings {
        warn!("  [{:3}%] [{}] {}", f.confidence, f.rule, f.detail);
    }
    warn!("================================");
}

#[cfg(test)]
mod reflexive_topology_tests {
    use super::*;

    fn analyze(fs: &[ProtocolFamily]) -> Vec<(ExploitClass, u8)> {
        TopologyReport::analyze(fs.iter().cloned().collect()).ranked
    }

    /// Corpus-mined shape (b): a lending fork + flash loan with NO external AMM must still
    /// rank ReflexiveSkew (the lending market is the skewable surface), just under
    /// FlashBorrowLeverage. This is the generalization beyond the Curve-vault shape.
    #[test]
    fn lending_plus_flashloan_ranks_reflexive_skew() {
        let ranked = analyze(&[ProtocolFamily::Lending, ProtocolFamily::FlashLoan]);
        let reflex = ranked.iter().find(|(c, _)| *c == ExploitClass::ReflexiveSkew);
        assert!(reflex.is_some(), "lending+flashloan must surface ReflexiveSkew");
        assert_eq!(reflex.unwrap().1, 82, "lending-fork reflexive score");
        // FlashBorrowLeverage (90) still leads it.
        let lev = ranked.iter().find(|(c, _)| *c == ExploitClass::FlashBorrowLeverage);
        assert!(lev.unwrap().1 > reflex.unwrap().1, "leverage class outranks reflexive");
    }

    /// The AMM-based shape (a) still fires at 88 and does not double-count with (b):
    /// exactly one ReflexiveSkew entry even when lending+flashloan+amm all co-occur.
    #[test]
    fn amm_shape_fires_once_no_double_count() {
        let ranked = analyze(&[
            ProtocolFamily::UniswapV2,
            ProtocolFamily::Lending,
            ProtocolFamily::FlashLoan,
        ]);
        let reflex: Vec<_> = ranked
            .iter()
            .filter(|(c, _)| *c == ExploitClass::ReflexiveSkew)
            .collect();
        assert_eq!(reflex.len(), 1, "exactly one ReflexiveSkew entry (else-if guards dup)");
        assert_eq!(reflex[0].1, 88, "AMM shape takes precedence at 88");
    }

    /// Negative: bare lending with no flash loan and no AMM must NOT invent a reflexive signal.
    #[test]
    fn bare_lending_no_reflexive() {
        let ranked = analyze(&[ProtocolFamily::Lending]);
        assert!(
            !ranked.iter().any(|(c, _)| *c == ExploitClass::ReflexiveSkew),
            "lending alone is not reflexive"
        );
    }

    #[test]
    fn test_classify_selector_with_ast_inheritance() {
        let selector = [0x00, 0x00, 0x00, 0x00];
        
        assert_eq!(classify_selector(&selector, "mint", None), Some(ProtocolFamily::Privileged));

        let ast_json = serde_json::json!({
            "nodeType": "ContractDefinition",
            "name": "MyVault",
            "baseContracts": [
                {
                    "baseName": {
                        "name": "ERC4626"
                    }
                }
            ]
        });
        let asts = vec![("MyVault.sol".to_string(), ast_json)];
        assert_eq!(
            classify_selector(&selector, "mint", Some(&asts)),
            Some(ProtocolFamily::ERC4626)
        );

        let ast_json_lending = serde_json::json!({
            "nodeType": "ContractDefinition",
            "name": "cToken",
            "baseContracts": [
                {
                    "baseName": {
                        "name": "CErc20"
                    }
                }
            ]
        });
        let asts_lending = vec![("cToken.sol".to_string(), ast_json_lending)];
        assert_eq!(
            classify_selector(&selector, "mint", Some(&asts_lending)),
            Some(ProtocolFamily::Lending)
        );
    }
}
