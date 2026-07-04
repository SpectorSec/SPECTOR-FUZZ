use std::collections::{HashMap, HashSet};

use libafl_bolts::impl_serdeany;
use serde::{Deserialize, Serialize};

use super::types::{EVMAddress, EVMU256, EVMU512};

/// Stores addresses flagged by oracles so the mutator can bias NestedAction
/// target selection toward addresses that triggered oracle detections.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OracleTargetMetadata {
    /// Map from flagged address to (reason, bug_idx, hit_count)
    pub targets: HashMap<[u8; 20], (String, u64, u64)>,
}

impl_serdeany!(OracleTargetMetadata);

/// Stores known whale/admin addresses that the mutator can use for
/// vm.prank / vm.startPrank injection inside nested actions.
/// Populated from WHALES constants, known deployers, and protocol admins
/// discovered during execution.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WhaleAddressMetadata {
    /// Set of addresses available for prank impersonation
    pub addresses: HashSet<EVMAddress>,
}

impl_serdeany!(WhaleAddressMetadata);

/// Stores protocol contract addresses that are authorized callers of
/// privileged functions. Used by the mutator to inject vm.prank(trusted_address)
/// when targeting privileged selectors (e.g., onlyRouter, onlyVault guards).
/// Key: "0xAddress_0xSelector" -> Set of addresses that successfully
/// called the privileged function without reverting.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrustedCallerMetadata {
    /// Key formatted as "0xAddress_0xSelector" for Serde compatibility
    pub trusted_callers: HashMap<String, HashSet<EVMAddress>>,
}

impl_serdeany!(TrustedCallerMetadata);

/// Stores a snapshot of token balances taken before a temporal warp (block
/// advancement). Used by TemporalSkimOracle to detect cross-round state
/// divergence — balance changes that occurred "off-screen" during the block
/// advancement between campaign steps.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TemporalBalanceSnapshot {
    /// Map from "0xToken_0xAccount" string key to balance at snapshot time.
    /// Uses string keys for Serde JSON compatibility (same pattern as
    /// TrustedCallerMetadata). The keys are formatted by snapshot_key() in
    /// temporal_skim.rs. Parsed back via pairs field for querying.
    pub balances: HashMap<String, EVMU256>,
    /// Parallel ordered list of (token, account) pairs matching the balance
    /// map keys, preserved for deterministic query reconstruction.
    pub pairs: Vec<(EVMAddress, EVMAddress)>,
    /// Block number at which the snapshot was taken.
    pub snapshot_block: EVMU256,
}

impl_serdeany!(TemporalBalanceSnapshot);

/// Stores the temporal warp operations (block advances) from a campaign execution.
/// Allows oracles to access the exact warps that occurred during execution.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CampaignWarpStates {
    pub warps: Vec<(usize, u64)>,
}

impl_serdeany!(CampaignWarpStates);

pub mod temporal_skim;

pub mod approval;
pub mod arb_call;
pub mod crosschain;
pub mod erc4626;
pub mod freshness;
pub mod rebasing;
pub mod arb_transfer;
pub mod echidna;
pub mod erc20;
pub mod fee_on_transfer;
pub mod function;
pub mod invariant;
pub mod nft;
pub mod reentrancy;
pub mod selfdestruct;
pub mod snapshot_delta;
pub mod state_comp;
pub mod typed_bug;
pub mod v2_pair;

pub static ERC20_BUG_IDX: u64 = 0;
pub static FUNCTION_BUG_IDX: u64 = 1;
pub static V2_PAIR_BUG_IDX: u64 = 2;
pub static ARB_TRANSFER_BUG_IDX: u64 = 3;
pub static TYPED_BUG_BUG_IDX: u64 = 4;
pub static SELFDESTRUCT_BUG_IDX: u64 = 5;
pub static ECHIDNA_BUG_IDX: u64 = 6;
pub static STATE_COMP_BUG_IDX: u64 = 7;
pub static ARB_CALL_BUG_IDX: u64 = 8;
pub static REENTRANCY_BUG_IDX: u64 = 9;
pub static INVARIANT_BUG_IDX: u64 = 10;
pub static INTEGER_OVERFLOW_BUG_IDX: u64 = 11;
pub static NFT_BUG_IDX: u64 = 12;
pub static FEE_ON_TRANSFER_BUG_IDX: u64 = 13;
pub static APPROVAL_BUG_IDX: u64 = 14;
pub static CROSSCHAIN_BUG_IDX: u64 = 15;
pub static REBASING_BUG_IDX: u64 = 16;
pub static ERC4626_BUG_IDX: u64 = 17;
pub static FRESHNESS_BUG_IDX: u64 = 18;
pub static TEMPORAL_SKIM_BUG_IDX: u64 = 19;
/// Feature 020-B — Ownership/Authority Relocation (SnapshotDelta oracle). Distinct idx from
/// FUNCTION_BUG_IDX so an `upgradeTo` by a non-admin can legitimately surface both a permission
/// leak (the call) and an ownership leak (the authority move).
pub static OWNERSHIP_BUG_IDX: u64 = 20;

/// Divide a U512 by another U512 and return a string with the decimal point at
/// the correct position For example, 1000 / 3 = 333.333, then a = 1000e6, b =
/// 3, fp = 6
pub fn u512_div_float(a: EVMU512, b: EVMU512, fp: usize) -> String {
    let mut res = format!("{}", a / b);
    if res.len() <= fp {
        res.insert_str(0, &"0".repeat(fp - res.len() + 1));
    }
    res.insert(res.len() - fp, '.');
    res
}

#[macro_export]
macro_rules! oracle_should_skip {
    ($ctx: expr, $key: expr) => {{
        let mut res = false;
        if let Some(meta) = $ctx.fuzz_state.metadata_map().get::<BugMetadata>() {
            res = meta.known_bugs.contains(&$key);
        }
        res
    }};
}
