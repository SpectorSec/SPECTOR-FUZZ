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
    contract_utils::ABIConfig,
    oracles::function::is_privileged_fn,
    types::EVMAddress,
};

/// Protocol family inferred from ABI selector fingerprinting.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
        }
    }
}

/// Result of topology analysis across all target contracts.
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

/// Classify a single ABI selector + function name into a `ProtocolFamily`.
/// Returns `None` if the selector doesn't match any known family.
pub fn classify_selector(selector: &[u8; 4], fn_name: &str) -> Option<ProtocolFamily> {
    match selector {
        // ERC-20
        [0xa9, 0x05, 0x9c, 0xbb] // transfer(address,uint256)
        | [0x23, 0xb8, 0x72, 0xdd] // transferFrom(address,address,uint256)
        | [0x09, 0x5e, 0xa7, 0xb3] // approve(address,uint256)
        | [0x70, 0xa0, 0x82, 0x31] // balanceOf(address)
        | [0x18, 0x16, 0x0d, 0xdd] // totalSupply()
        => Some(ProtocolFamily::ERC20),

        // ERC-721
        [0x42, 0x84, 0x2e, 0x0e] // safeTransferFrom(address,address,uint256)
        | [0xb8, 0x8d, 0x4f, 0xde] // safeTransferFrom(address,address,uint256,bytes)
        | [0x63, 0x52, 0x21, 0x1e] // ownerOf(uint256)
        | [0x6f, 0x4f, 0x28, 0x78] // isApprovedForAll
        => Some(ProtocolFamily::ERC721),

        // ERC-1155
        [0xf2, 0x42, 0x43, 0x2a] // safeTransferFrom(address,address,uint256,uint256,bytes)
        | [0x2e, 0xb2, 0xc2, 0xd6] // safeBatchTransferFrom
        | [0x00, 0xfd, 0xd5, 0x8e] // balanceOf(address,uint256)
        => Some(ProtocolFamily::ERC1155),

        // ERC-4626 vault
        [0x07, 0xa2, 0xd1, 0x3a] // convertToAssets(uint256)
        | [0xef, 0x8b, 0x30, 0xf7] // convertToShares(uint256)
        | [0x6e, 0x55, 0x3f, 0x65] // deposit(uint256,address)
        | [0xb4, 0x60, 0xaf, 0x94] // withdraw(uint256,address,address)
        | [0xba, 0x08, 0x76, 0x52] // redeem(uint256,address,address)
        | [0x94, 0xbf, 0x80, 0x4d] // previewDeposit
        | [0x0a, 0x28, 0xa4, 0x77] // previewWithdraw
        | [0x4c, 0xde, 0xf3, 0x26] // previewRedeem
        => Some(ProtocolFamily::ERC4626),

        // Chainlink oracle interface
        [0xfe, 0xaf, 0x96, 0x8c] // latestRoundData()
        | [0x50, 0xd2, 0x5b, 0xcd] // latestAnswer()
        | [0x9a, 0x6f, 0xc8, 0xf5] // getRoundData(uint80)
        | [0xb5, 0xab, 0x58, 0xdc] // latestRound()
        => Some(ProtocolFamily::Chainlink),

        // Uniswap V2 AMM
        [0x09, 0x02, 0xf1, 0xac] // getReserves()
        | [0x02, 0x2c, 0x0d, 0x9f] // swap(uint256,uint256,address,bytes)
        | [0xe8, 0xe3, 0x37, 0x00] // addLiquidity
        | [0xba, 0xa2, 0xab, 0xde] // removeLiquidity
        | [0x7f, 0xf3, 0x6a, 0xb5] // swapExactETHForTokens
        => Some(ProtocolFamily::UniswapV2),

        // Uniswap V3 AMM
        [0x41, 0x28, 0x48, 0x01] // exactInputSingle
        | [0xb8, 0x58, 0x18, 0x3f] // exactInput
        | [0xdb, 0x3e, 0x21, 0x98] // exactOutputSingle
        | [0x09, 0x49, 0x7b, 0xf3] // slot0()
        => Some(ProtocolFamily::UniswapV3),

        // Lending protocol
        [0xc5, 0xeb, 0xea, 0xec] // borrow(uint256)
        | [0x0e, 0x75, 0x27, 0x02] // repay(uint256)
        | [0xf5, 0x14, 0x1a, 0x51] // liquidationCall / liquidate
        | [0x69, 0x32, 0x8d, 0xec] // deposit (Aave v2)
        | [0x8e, 0x19, 0x99, 0xd9] // withdraw (Aave v2)
        => Some(ProtocolFamily::Lending),

        // Flash loan entry points
        [0xab, 0x9c, 0x4b, 0x5d] // flashLoan(address,address,uint256,bytes) Aave v2
        | [0x5c, 0xfe, 0x9d, 0xe1] // flashLoan(address[],uint256[],uint256[],bytes) Balancer
        | [0x92, 0x0f, 0x5c, 0x84] // executeOperation (Aave callback)
        | [0x23, 0xe3, 0x0c, 0x8b] // uniswapV2Call
        | [0xfa, 0x46, 0x18, 0x43] // pancakeCall
        => Some(ProtocolFamily::FlashLoan),

        // Callback receivers — execution windows mid-protocol-state
        [0x15, 0x0b, 0x7a, 0x02] // onERC721Received
        | [0xf2, 0x3a, 0x6e, 0x61] // onERC1155Received
        | [0xbc, 0x19, 0x7c, 0x81] // onERC1155BatchReceived
        | [0x0e, 0x83, 0x13, 0x52] // tokensReceived (ERC-777)
        => Some(ProtocolFamily::Callback),

        // Governance
        [0xda, 0x35, 0xc6, 0x64] // propose(...)
        | [0x56, 0x78, 0x13, 0x88] // queue(uint256)
        | [0xfe, 0x0d, 0x94, 0xc1] // execute(uint256)
        | [0xc2, 0x6a, 0x23, 0x7d] // castVote(uint256,uint8)
        => Some(ProtocolFamily::Governance),

        // Staking / rewards
        [0xa6, 0x94, 0xfc, 0x3a] // stake(uint256)
        | [0x2e, 0x1a, 0x7d, 0x4d] // withdraw(uint256) — also used in staking
        | [0x3d, 0x18, 0xb9, 0x12] // getReward()
        | [0x3c, 0x6b, 0x16, 0xab] // notifyRewardAmount(uint256)
        => Some(ProtocolFamily::Staking),

        // EIP-712 domain separator
        [0x36, 0x44, 0xe5, 0x15] // DOMAIN_SEPARATOR()
        => Some(ProtocolFamily::EIP712),

        // Rebasing / sync
        [0x1c, 0x40, 0xe7, 0xab] // rebase(uint256,uint256)
        | [0xff, 0xf6, 0xca, 0xe9] // sync()
        => Some(ProtocolFamily::Rebasing),

        _ => {
            if is_privileged_fn(fn_name) {
                Some(ProtocolFamily::Privileged)
            } else {
                None
            }
        }
    }
}

impl ExploitClass {
    /// Selectors that should appear in mutation sequences for this exploit class.
    /// Used by the topology-weighted scheduler to concentrate fuzzing energy.
    pub fn target_selectors(&self) -> &'static [[u8; 4]] {
        match self {
            // vault + oracle interleave — deposit/redeem must cross latestRoundData boundary
            ExploitClass::PriceGatedVault => &[
                [0x6e, 0x55, 0x3f, 0x65], // deposit
                [0xb4, 0x60, 0xaf, 0x94], // withdraw
                [0xba, 0x08, 0x76, 0x52], // redeem
                [0xfe, 0xaf, 0x96, 0x8c], // latestRoundData
                [0x07, 0xa2, 0xd1, 0x3a], // convertToAssets
            ],
            // flash → deposit → redeem sequence
            ExploitClass::FlashDepositDrain => &[
                [0xab, 0x9c, 0x4b, 0x5d], // flashLoan (Aave)
                [0x6e, 0x55, 0x3f, 0x65], // deposit
                [0xba, 0x08, 0x76, 0x52], // redeem
                [0x92, 0x0f, 0x5c, 0x84], // executeOperation
            ],
            // flash → borrow → drain sequence
            ExploitClass::FlashBorrowLeverage => &[
                [0xab, 0x9c, 0x4b, 0x5d], // flashLoan
                [0xc5, 0xeb, 0xea, 0xec], // borrow
                [0x92, 0x0f, 0x5c, 0x84], // executeOperation
                [0x0e, 0x75, 0x27, 0x02], // repay
            ],
            // propose → warp → vote → execute sequence
            ExploitClass::FlashGovernance => &[
                [0xda, 0x35, 0xc6, 0x64], // propose
                [0xfe, 0x0d, 0x94, 0xc1], // execute
                [0xc2, 0x6a, 0x23, 0x7d], // castVote
                [0xa9, 0x05, 0x9c, 0xbb], // transfer (governance token flash)
            ],
            // swap skews reserves → oracle reads distorted price
            ExploitClass::OraclePriceManip => &[
                [0x02, 0x2c, 0x0d, 0x9f], // swap (UniV2)
                [0xfe, 0xaf, 0x96, 0x8c], // latestRoundData
                [0x09, 0x02, 0xf1, 0xac], // getReserves
                [0x41, 0x28, 0x48, 0x01], // exactInputSingle (UniV3)
            ],
            // safeTransferFrom triggers onERC721Received callback
            ExploitClass::NFTReentrancy => &[
                [0x42, 0x84, 0x2e, 0x0e], // safeTransferFrom(addr,addr,uint256)
                [0xb8, 0x8d, 0x4f, 0xde], // safeTransferFrom(addr,addr,uint256,bytes)
                [0x15, 0x0b, 0x7a, 0x02], // onERC721Received
            ],
            // stake → notify → getReward — reward math boundary
            ExploitClass::RewardAccumulator => &[
                [0xa6, 0x94, 0xfc, 0x3a], // stake
                [0x3d, 0x18, 0xb9, 0x12], // getReward
                [0x3c, 0x6b, 0x16, 0xab], // notifyRewardAmount
                [0x2e, 0x1a, 0x7d, 0x4d], // withdraw (staking)
            ],
            // permit with boundary v values + transferFrom
            ExploitClass::SignatureReplay => &[
                [0xd5, 0x05, 0xac, 0xcf], // permit
                [0x36, 0x44, 0xe5, 0x15], // DOMAIN_SEPARATOR
                [0x23, 0xb8, 0x72, 0xdd], // transferFrom
            ],
            // privileged fn called from attacker context
            ExploitClass::PermissionEscalation => &[
                // selectors vary per contract — handled by FunctionOracle at runtime
                // bias toward transfer/mint as the economic outcome
                [0xa9, 0x05, 0x9c, 0xbb], // transfer
                [0x40, 0xc1, 0x0f, 0x19], // mint
            ],
            // callback with attacker-controlled call target
            ExploitClass::ArbitraryCallDrain => &[
                [0x92, 0x0f, 0x5c, 0x84], // executeOperation
                [0x23, 0xe3, 0x0c, 0x8b], // uniswapV2Call
                [0xa9, 0x05, 0x9c, 0xbb], // transfer
            ],
            // swap → sync — K-invariant pressure
            ExploitClass::AMMInvariant => &[
                [0x02, 0x2c, 0x0d, 0x9f], // swap
                [0x09, 0x02, 0xf1, 0xac], // getReserves
                [0xff, 0xf6, 0xca, 0xe9], // sync
            ],
            // transfer into protocol that doesn't account for fee deduction
            ExploitClass::DeflationaryToken => &[
                [0xa9, 0x05, 0x9c, 0xbb], // transfer
                [0xff, 0xf6, 0xca, 0xe9], // sync
                [0x1c, 0x40, 0xe7, 0xab], // rebase
            ],
            // unvalidated callback entry point
            ExploitClass::UnprotectedCallback => &[
                [0x92, 0x0f, 0x5c, 0x84], // executeOperation
                [0x15, 0x0b, 0x7a, 0x02], // onERC721Received
                [0xf2, 0x3a, 0x6e, 0x61], // onERC1155Received
                [0x0e, 0x83, 0x13, 0x52], // tokensReceived (ERC-777)
            ],
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HintSet {
    pub confidence: u8,
    /// 4-byte selectors that should appear together in exploit sequences.
    /// Stored as Vec<[u8; 4]> — each inner array is one selector.
    pub selectors: Vec<[u8; 4]>,
}

impl_serdeany!(TopologyHints);

impl TopologyHints {
    pub fn from_report(report: &TopologyReport) -> Self {
        let sets = report
            .ranked
            .iter()
            .filter(|(_, confidence)| *confidence >= 70)
            .map(|(class, confidence)| HintSet {
                confidence: *confidence,
                selectors: class.target_selectors().to_vec(),
            })
            .collect();
        TopologyHints { sets }
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
