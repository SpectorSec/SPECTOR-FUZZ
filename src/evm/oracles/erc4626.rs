use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};

use bytes::Bytes;
use revm_interpreter::bytecode::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::ERC4626_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

/// Detects ERC-4626 share-price manipulation, in BOTH directions:
///
///   - DRAIN — `convertToAssets(1e18)` (share price) *decreases* by more than a
///     rounding tolerance: value left the vault disproportionately.
///   - INFLATION — `convertToShares(1e18)` (shares a depositor would mint) goes from
///     >0 to *zero*: the classic Cream/Hundred donation/inflation attack, where the
///     attacker inflates the price so a victim's deposit rounds to zero shares.
///     The decrease-only check used to MISS this entirely (inflation moves the price
///     UP, hitting the `post >= pre` skip), so the documented attack went undetected.
///
/// Both are measured pre→post of this execution, so we only flag a transition this
/// execution *caused*, not a pre-existing vault state.
///
/// Auto-activated by the corpus initializer when `convertToAssets` (0x07a2d13a)
/// is found in the ABI — no user configuration needed.
pub struct ERC4626Oracle {
    /// ERC-4626 vault addresses to monitor → last known share price.
    pub vaults: HashMap<EVMAddress, EVMU256>,
    pub address_to_name: HashMap<EVMAddress, String>,
    convert_to_assets_calldata: Bytes,
    convert_to_shares_calldata: Bytes,
}

/// `convertToAssets(1e18)` decreased by more than a 1bp rounding tolerance → drain.
/// A 1-wei dip is integer-division dust, not a manipulation.
fn share_price_drained(pre: EVMU256, post: EVMU256) -> bool {
    if pre == EVMU256::ZERO || post == EVMU256::ZERO || post >= pre {
        return false;
    }
    let drop = pre - post;
    drop.saturating_mul(EVMU256::from(10000u64)) >= pre // >= 1bp
}

/// A probe deposit that used to mint shares now mints ZERO — the victim outcome of
/// an inflation attack. Only fires on a pre>0 → post==0 transition this execution
/// caused (a vault already inflated before the tx is not flagged here).
fn became_zero_share(pre_shares: EVMU256, post_shares: EVMU256) -> bool {
    pre_shares > EVMU256::ZERO && post_shares == EVMU256::ZERO
}

impl ERC4626Oracle {
    /// `vaults` = list of contract addresses confirmed to be ERC-4626 vaults.
    pub fn new(vaults: Vec<EVMAddress>, address_to_name: HashMap<EVMAddress, String>) -> Self {
        // 1e18 = 0x0de0b6b3a7640000, left-padded to 32 bytes.
        let arg_1e18 = |selector: [u8; 4]| -> Bytes {
            let mut cd = selector.to_vec();
            cd.extend_from_slice(&[0u8; 24]);
            cd.extend_from_slice(&[0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]);
            Bytes::from(cd)
        };

        Self {
            vaults: vaults.into_iter().map(|a| (a, EVMU256::ZERO)).collect(),
            address_to_name,
            convert_to_assets_calldata: arg_1e18([0x07, 0xa2, 0xd1, 0x3a]), // convertToAssets(1e18)
            convert_to_shares_calldata: arg_1e18([0xc6, 0xe6, 0xf5, 0x92]), // convertToShares(1e18)
        }
    }
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
    > for ERC4626Oracle
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
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
        if self.vaults.is_empty() {
            return vec![];
        }

        // Two probes per vault: convertToAssets(1e18) (share price, for drain) and
        // convertToShares(1e18) (shares a depositor mints, for inflation). Index 2i / 2i+1.
        let mut queries: Vec<(EVMAddress, Bytes)> = Vec::with_capacity(self.vaults.len() * 2);
        for addr in self.vaults.keys() {
            queries.push((*addr, self.convert_to_assets_calldata.clone()));
            queries.push((*addr, self.convert_to_shares_calldata.clone()));
        }

        let pre_results  = ctx.call_pre_batch(&queries);
        let post_results = ctx.call_post_batch(&queries);

        let read = |v: &[Vec<u8>], idx: usize| EVMU256::try_from_be_slice(v[idx].as_slice()).unwrap_or(EVMU256::ZERO);

        let mut res = vec![];
        for (i, (vault, _)) in self.vaults.iter().enumerate() {
            // A failed/empty convertTo* static call parses as 0; pairing a real pre with
            // a failed (→0) post would manufacture a phantom drain or zero-share
            // "inflation". Unmeasurable ≠ 0 — skip the vault if any of its 4 reads failed.
            if pre_results[2 * i].is_empty() || post_results[2 * i].is_empty()
                || pre_results[2 * i + 1].is_empty() || post_results[2 * i + 1].is_empty()
            {
                continue;
            }
            let price_pre   = read(&pre_results,  2 * i);
            let price_post  = read(&post_results, 2 * i);
            let shares_pre  = read(&pre_results,  2 * i + 1);
            let shares_post = read(&post_results, 2 * i + 1);

            // Feature 029 — publish divergence magnitude for the optimizer.
            // Both drain (price drop) and inflation (share drop) are meaningful deltas.
            // Published BEFORE the boolean gate so small deviations (Alex's 1-second
            // truncation) still feed the optimizer even when the predicate doesn't fire.
            let drain_mag = if price_pre > price_post { price_pre - price_post } else { EVMU256::ZERO };
            let inflate_mag = if shares_pre > shares_post { shares_pre - shares_post } else { EVMU256::ZERO };
            let mag = drain_mag.max(inflate_mag);
            crate::evm::feedbacks::publish_divergence(crate::evm::feedbacks::evmu256_to_u128_sat_fb(mag));

            let drained   = share_price_drained(price_pre, price_post);
            let inflated  = became_zero_share(shares_pre, shares_post);
            if !drained && !inflated {
                // Even when no oracle fires, the divergence was published above for the optimizer.
                continue;
            }

            let mut hasher = DefaultHasher::new();
            vault.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + ERC4626_BUG_IDX;

            let name = self
                .address_to_name
                .get(vault)
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            let detail = if inflated {
                format!(
                    "Vault {} INFLATED: a 1e18-asset deposit minted {} shares before, 0 after \
                     (donation/inflation attack — victim deposits round to zero shares)",
                    name, shares_pre,
                )
            } else {
                format!(
                    "Vault {} share price DRAINED: {} → {} (>1bp drop)",
                    name, price_pre, price_post,
                )
            };

            EVMBugResult::new(
                "ERC-4626 Share Price Manipulation".to_string(),
                bug_idx,
                detail,
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                None,
                Some(name.to_string()),
            )
            .push_to_output();
            res.push(bug_idx);
        }
        res
    }
}

#[cfg(test)]
mod erc4626_tests {
    use super::*;

    #[test]
    fn drain_needs_to_exceed_rounding() {
        let p = EVMU256::from(1_000_000_000_000_000_000u64);
        // 1-wei dip: below 1bp → not a drain.
        assert!(!share_price_drained(p, p - EVMU256::from(1u64)));
        // 1% drop → drain.
        assert!(share_price_drained(p, p - p / EVMU256::from(100u64)));
        // increase or zero → never a drain (that's the inflation path).
        assert!(!share_price_drained(p, p + EVMU256::from(1u64)));
        assert!(!share_price_drained(EVMU256::ZERO, p));
    }

    #[test]
    fn inflation_is_the_zero_share_transition() {
        // used to mint shares, now mints zero → inflation attack.
        assert!(became_zero_share(EVMU256::from(500u64), EVMU256::ZERO));
        // already zero before the tx → pre-existing state, not flagged here.
        assert!(!became_zero_share(EVMU256::ZERO, EVMU256::ZERO));
        // still mints shares → fine.
        assert!(!became_zero_share(EVMU256::from(500u64), EVMU256::from(490u64)));
    }
}
