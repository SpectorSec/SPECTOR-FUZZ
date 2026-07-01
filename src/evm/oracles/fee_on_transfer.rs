use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::hash::{Hash, Hasher};

use bytes::Bytes;
use revm_interpreter::bytecode::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        oracle::EVMBugResult,
        oracles::FEE_ON_TRANSFER_BUG_IDX,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256},
        vm::EVMState,
    },
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
};

/// Detects fee-on-transfer tokens: for a SINGLE `transfer`/`transferFrom` CALL, the
/// recipient's real balance increased by less than the amount claimed in the calldata.
///
/// The measurement is performed inline by `FeeOnTransferDetector` (a middleware), which
/// brackets each transfer's call frame — snapshotting the recipient's balance slot at
/// the CALL opcode and re-reading it at the matching return — and records
/// `(token, recipient, claimed, actual)` into `EVMState::fee_observations`. This oracle
/// only judges that evidence via `fee_shortfall`.
///
/// The previous implementations diffed balances over the WHOLE transaction (first a
/// single transfer vs whole-tx delta, then net-inflow vs whole-tx delta). Both could not
/// distinguish a transit/pass-through recipient (received then forwarded in a *later*
/// call, netting ~0) from a 100%-fee token, and manufactured phantom fees on fee-less
/// tokens like USDC (e.g. the 15,562 USDC Yearn-fork false positive). A per-frame
/// measurement is structurally immune to that: forwarding is a separate call.
pub struct FeeOnTransferOracle {
    pub address_to_name: HashMap<EVMAddress, String>,
}

impl FeeOnTransferOracle {
    pub fn new(address_to_name: HashMap<EVMAddress, String>) -> Self {
        Self { address_to_name }
    }
}

/// Decide whether a single transfer's balance shortfall is a real transfer fee.
///
/// `expected` = the amount claimed in the transfer's calldata; `actual` = the recipient's
/// real per-frame balance delta. A fee-on-transfer token delivers strictly less than the
/// claimed amount. Returns `Some(fee)` only when the shortfall exceeds a rounding
/// tolerance of 1 basis point (0.01%) of `expected` — integer division dust is not a fee,
/// and real FoT tokens charge whole percents.
fn fee_shortfall(expected: EVMU256, actual: EVMU256) -> Option<EVMU256> {
    if expected == EVMU256::ZERO || actual >= expected {
        return None;
    }
    // Zero-delta guard: even with per-frame inline measurement, a transfer whose
    // recipient netted ZERO within the call frame is not a credible fee victim — the
    // common cause is a self-transfer (from == to, balance unchanged) or a recipient
    // that received and re-sent inside the same frame. The only thing this rejects is
    // the pathological 100%-fee honeypot (effectively nonexistent), so require actual > 0.
    if actual == EVMU256::ZERO {
        return None;
    }
    let fee = expected - actual;
    // fee < expected / 10000  →  below 1bp  →  rounding noise, not a fee.
    if fee.saturating_mul(EVMU256::from(10000u64)) < expected {
        return None;
    }
    Some(fee)
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
    > for FeeOnTransferOracle
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
        // Inline per-transfer evidence recorded by FeeOnTransferDetector:
        // (token, recipient, claimed, actual). Each tuple is one bracketed transfer
        // call frame, so claimed-vs-actual is an apples-to-apples per-transfer fee.
        let observations = ctx.post_state.fee_observations.clone();
        if observations.is_empty() {
            return vec![];
        }

        let mut res = vec![];
        let mut reported = HashSet::new();
        for (token, to, claimed, actual) in &observations {
            let Some(fee) = fee_shortfall(*claimed, *actual) else {
                continue;
            };

            // One report per (token, recipient) — a fee token charges on every transfer,
            // so dedup to avoid flooding the corpus with the same finding.
            if !reported.insert((*token, *to)) {
                continue;
            }

            let mut hasher = DefaultHasher::new();
            token.hash(&mut hasher);
            to.hash(&mut hasher);
            let bug_idx = (hasher.finish() << 8) + FEE_ON_TRANSFER_BUG_IDX;

            let token_name = self
                .address_to_name
                .get(token)
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            EVMBugResult::new(
                "Fee-on-Transfer".to_string(),
                bug_idx,
                format!(
                    "Token {} to {:?}: claimed={} actual={} (fee={})",
                    token_name, to, claimed, actual, fee,
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
                None,
                Some(token_name.to_string()),
            )
            .push_to_output();
            res.push(bug_idx);
        }
        res
    }
}

#[cfg(test)]
mod fee_on_transfer_tests {
    use super::*;

    /// The exact false positive from the Yearn fork: a recipient received 15,562
    /// USDC and sent 60 elsewhere. Net expected (15,502) == actual (15,502) → no fee.
    /// The OLD logic compared the single 15,562 transfer against the 15,502 delta and
    /// screamed "fee = 60" on fee-less USDC. Net-to-net makes it vanish.
    #[test]
    fn usdc_multi_transfer_is_not_a_fee() {
        let expected = EVMU256::from(15_502_267_944u64); // 15,562 in − 60 out
        let actual   = EVMU256::from(15_502_267_944u64);
        assert_eq!(fee_shortfall(expected, actual), None);
    }

    /// A real fee-on-transfer token: received 900 of an expected 1000 → 100 fee (10%).
    #[test]
    fn real_fee_is_flagged() {
        let fee = fee_shortfall(EVMU256::from(1000u64), EVMU256::from(900u64));
        assert_eq!(fee, Some(EVMU256::from(100u64)));
    }

    /// Integer-division dust (1 wei short of 1e18) is below the 1bp tolerance → not a fee.
    #[test]
    fn rounding_dust_is_not_a_fee() {
        let expected = EVMU256::from(1_000_000_000_000_000_000u64);
        let actual   = expected - EVMU256::from(1u64);
        assert_eq!(fee_shortfall(expected, actual), None);
    }

    /// Transit/pass-through: recipient received tokens (expected>0) but netted ZERO
    /// balance change (forwarded them) → NOT a fee victim. This is the 92% phantom
    /// pattern observed on the Yearn fork (actual=0 with absurd "fees").
    #[test]
    fn transit_passthrough_is_not_a_fee() {
        assert_eq!(fee_shortfall(EVMU256::from(31065089360u64), EVMU256::ZERO), None);
        assert_eq!(fee_shortfall(EVMU256::from(5_132_510_927_991_555_994_808u128), EVMU256::ZERO), None);
    }

    /// Pure net receiver with full delivery → no fee; zero expected → no fee.
    #[test]
    fn full_delivery_and_zero_expected() {
        assert_eq!(fee_shortfall(EVMU256::from(1000u64), EVMU256::from(1000u64)), None);
        assert_eq!(fee_shortfall(EVMU256::ZERO, EVMU256::ZERO), None);
    }
}
