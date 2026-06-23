/// Topology Intelligence — protocol family co-occurrence → ranked exploit class.
///
/// Every DeFi protocol exposes its shape through its ABI selector set.
/// When two protocol families appear in the same target set, the intersection
/// is almost always where the vulnerability lives. This module maps that
/// co-occurrence to a ranked list of exploit classes and the oracles that
/// detect them — before the fuzzer sends a single transaction.
use std::collections::HashSet;

use libafl_bolts::impl_serdeany;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::evm::oracles::function::is_privileged_fn;

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
