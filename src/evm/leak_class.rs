//! Feature 020 — Leak Taxonomy Unification.
//!
//! `LeakClass` is the SINGLE SOURCE OF TRUTH for the leak-primitive taxonomy. It binds the
//! conceptual primitive to its detection oracle(s) (`OracleType`), its optional inline middleware
//! (`MiddlewareType`), and one canonical config string. The compiler is the validator: every impl
//! is an exhaustive `match`, so a new `OracleType`/`MiddlewareType` that a primitive should cover,
//! but doesn't, surfaces as a build error instead of silent drift.
//!
//! Phasing (see `.speckit/features/020-leak-taxonomy-unification/`):
//!   020-A — this enum + the reason-aware `PromotionCandidate.kind` field (byte-identical).
//!   020-B — `OracleType::Ownership` + the `SnapshotDelta` oracle (gives Ownership a real home).
//!   020-C — `OracleType::from_strs` routes `-d <class>` selection through `oracles()`/`as_str()`
//!           (this makes the SSOT drive detection); `mutator.rs` kind-aware amplification is
//!           deferred to 019-C (needs a `Permission` producer — no dead branch until then).
//!
//! `ALL`/`oracles()`/`as_str()` are consumed by `-d` routing; `from_str()` (legacy-alias parse)
//! and `middleware()` (attach law) are not yet wired, hence their `#[allow(dead_code)]`.
//!
//! **Out-of-band oracles (§5.4):** `FreshnessOracle` and `TemporalSkimOracle` are Value-primitive
//! detectors but have no `OracleType` variant — they auto-activate via ABI fingerprint
//! (`evm_fuzzer.rs`) and are NOT controllable by `-d`. They are intentionally omitted from
//! `oracles()` to avoid implying `-d value_leak` selects them; their activation is independent.

use serde::{Deserialize, Serialize};

use super::middlewares::middleware::MiddlewareType;
use super::OracleType;

/// The six leak primitives. This enum is the taxonomy root; the three concrete surfaces
/// (detection oracle, inline middleware, config string) all derive from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LeakClass {
    /// 01 — attacker steers control flow into a state a single top-level call can't reach.
    /// Built instance: re-entrant interleaving.
    ControlFlow,
    /// 02 — value/accounting skew: balances move without reconciling (fee-on-transfer, rebase,
    /// ERC20 transfer asymmetry).
    Value,
    /// 03 — attacker authors the message/target the contract dispatches to (arbitrary external
    /// call). Inline middleware is Phase-B (cross-contract provenance), so `None` today.
    Message,
    /// 04 — privileged function reached by an unauthorized caller with a MATERIAL effect.
    /// This is Feature 019 Phase A (the materiality gate).
    Permission,
    /// 05 — a declared/inferred invariant breaks. Post-hoc; needs no during-exec witness.
    Invariant,
    /// 06 — ownership/authority is relocated or destroyed. Distinct from Permission (the *act* of
    /// calling): this is a governance-state delta. Detection home = `SnapshotDelta` oracle (020-B).
    Ownership,
}

impl LeakClass {
    /// All six primitives, for iteration. Consumed by `OracleType::from_strs` (`-d` routing).
    pub const ALL: [LeakClass; 6] = [
        LeakClass::ControlFlow,
        LeakClass::Value,
        LeakClass::Message,
        LeakClass::Permission,
        LeakClass::Invariant,
        LeakClass::Ownership,
    ];

    /// Detection oracle(s) for this primitive. Returns a slice, not a single value, because a
    /// primitive legitimately spans several oracles (Value, Invariant). `Ownership` maps to the
    /// `SnapshotDelta` oracle (`OracleType::Ownership`), added in 020-B. Consumed by `-d` routing.
    pub fn oracles(&self) -> &'static [OracleType] {
        use OracleType::*;
        match self {
            LeakClass::ControlFlow => &[Reentrancy],
            // §1 audit: Pair (k-constant imbalance drain) + MathCalculate (arbitrary ERC20
            // transfer to attacker) are both direct-value-extraction detectors.
            LeakClass::Value => &[FeeOnTransfer, ERC20, Rebasing, ERC4626, Pair, MathCalculate],
            // §1 audit: CrossChain detects attacker calling bridge receive functions
            // (lzReceive/ccipReceive/xReceive) without authorization — message origin forgery.
            LeakClass::Message => &[ArbitraryCall, CrossChain],
            // §1 audit: Approval detects protocol contracts granting attacker ERC20 allowance —
            // an unauthorized privilege grant (distinct from the attacker calling a privileged
            // function directly, which is Function oracle territory, but same Permission class).
            LeakClass::Permission => &[Function, Approval],
            // §1 audit: TypedBug fires on user-defined typed invariant assertions (same
            // semantic class as Echidna/Invariant/StateComparison — declared invariant broken).
            LeakClass::Invariant => &[Invariant, StateComparison, Echidna, TypedBug],
            // §1 audit: SelfDestruct = ultimate authority destruction (already aliased to
            // Ownership in from_str; binds detection to the correct class here).
            // 020-B SnapshotDelta + NFTOwnershipOracle (028-orphan bind) + SelfdestructOracle.
            LeakClass::Ownership => &[Ownership, NFT, SelfDestruct],
        }
    }

    /// The inline middleware for this primitive, IFF its verdict needs during-execution state
    /// (Information Availability Law). `None` = pure post-hoc oracle; returning a struct here would
    /// be dead code — which is exactly the anti-pattern this method encodes against.
    #[allow(dead_code)]
    pub fn middleware(&self) -> Option<MiddlewareType> {
        match self {
            LeakClass::ControlFlow => Some(MiddlewareType::Reentrancy),
            LeakClass::Value => Some(MiddlewareType::FeeOnTransferDetector),
            LeakClass::Permission => Some(MiddlewareType::FunctionAuth),
            LeakClass::Message => None, // Phase B → Some(MiddlewareType::ArbitraryCall) (oracle-rooted, not `MessageLeak`)
            LeakClass::Invariant => None,
            LeakClass::Ownership => None,
        }
    }

    /// The ONE canonical config string — used by `-d <class>` selection and JSON template tags.
    pub fn as_str(&self) -> &'static str {
        match self {
            LeakClass::ControlFlow => "control_flow_leak",
            LeakClass::Value => "value_leak",
            LeakClass::Message => "message_leak",
            LeakClass::Permission => "permission_leak",
            LeakClass::Invariant => "invariant_leak",
            LeakClass::Ownership => "ownership_leak",
        }
    }

    /// Parse a canonical class string, or a legacy per-oracle alias (back-compat with existing
    /// `-d function`/`-d reentrancy` invocations). Returns `None` for an unknown string.
    #[allow(dead_code)]
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "control_flow_leak" | "reentrancy" => LeakClass::ControlFlow,
            "value_leak" | "fee_on_transfer" => LeakClass::Value,
            "message_leak" | "arbitrary_call" => LeakClass::Message,
            "permission_leak" | "function" => LeakClass::Permission,
            "invariant_leak" | "invariant" => LeakClass::Invariant,
            "ownership_leak" | "selfdestruct" => LeakClass::Ownership,
            _ => return None,
        })
    }
}

/// Preserves today's semantics: every existing a-posteriori promotion is value-inflow driven, so an
/// untagged/legacy `PromotionCandidate` (e.g. deserialized from a pre-020 corpus) reads back as
/// `Value`. This default is load-bearing for corpus back-compat (Constitution rule 2).
impl Default for LeakClass {
    fn default() -> Self {
        LeakClass::Value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_value_for_backcompat() {
        // Legacy promotions carried no class; they were value-inflow. Default must read as Value
        // or serialized corpora regress.
        assert_eq!(LeakClass::default(), LeakClass::Value);
    }

    #[test]
    fn built_primitives_map_to_oracles() {
        // Every primitive now resolves to a non-empty oracle set — Ownership gained its
        // SnapshotDelta home in 020-B.
        for lc in LeakClass::ALL {
            assert!(!lc.oracles().is_empty(), "{lc:?} should map to >=1 oracle");
        }
    }

    #[test]
    fn ownership_binds_to_snapshot_delta_oracle() {
        // 020-B: Ownership's detection home is the SnapshotDelta oracle (OracleType::Ownership);
        // the NFTOwnershipOracle joined it (028-orphan bind); SelfDestructOracle bound §1 audit
        // (contract destruction = ultimate authority change; already aliased in from_str).
        // Per the Information Availability Law it stays post-hoc (no inline middleware).
        assert_eq!(
            LeakClass::Ownership.oracles(),
            &[OracleType::Ownership, OracleType::NFT, OracleType::SelfDestruct]
        );
        assert!(LeakClass::Ownership.middleware().is_none());
    }

    #[test]
    fn value_binds_erc4626_orphan() {
        // ERC4626Oracle (share-price manipulation) is a Value-leak detector — bound into the SSOT
        // (was an orphan: oracle fired via bug_idx / topology auto-activation but unclaimed).
        assert!(LeakClass::Value.oracles().contains(&OracleType::ERC4626));
    }

    #[test]
    fn middleware_law_holds() {
        // Inline middleware exists exactly for the primitives whose verdict needs during-exec state.
        assert!(LeakClass::ControlFlow.middleware().is_some());
        assert!(LeakClass::Value.middleware().is_some());
        assert!(LeakClass::Permission.middleware().is_some());
        // Post-hoc (or not-yet-built) primitives must NOT claim a middleware.
        assert!(LeakClass::Message.middleware().is_none());
        assert!(LeakClass::Invariant.middleware().is_none());
        assert!(LeakClass::Ownership.middleware().is_none());
    }

    #[test]
    fn as_str_from_str_roundtrip() {
        for lc in LeakClass::ALL {
            assert_eq!(LeakClass::from_str(lc.as_str()), Some(lc), "roundtrip {lc:?}");
        }
    }

    #[test]
    fn legacy_oracle_aliases_resolve() {
        // Existing `-d <oracle>` strings keep working through the class layer.
        assert_eq!(LeakClass::from_str("function"), Some(LeakClass::Permission));
        assert_eq!(LeakClass::from_str("reentrancy"), Some(LeakClass::ControlFlow));
        assert_eq!(LeakClass::from_str("fee_on_transfer"), Some(LeakClass::Value));
        assert_eq!(LeakClass::from_str("nope"), None);
    }

    #[test]
    fn permission_binds_to_the_019_middleware() {
        // The 019 Phase A gate is the Permission primitive's inline hook — the coupling 020 formalizes.
        assert_eq!(
            LeakClass::Permission.middleware(),
            Some(MiddlewareType::FunctionAuth)
        );
    }
}
