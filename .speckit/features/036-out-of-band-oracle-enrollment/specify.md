# Feature 036 — Out-of-Band Oracle Taxonomy Enrollment

## Status
Lowest priority of the three remaining gaps. Not a regression, not blocking anything — pure
taxonomy completeness. Build after 034/035 if there's still appetite for audit closeout work.

## The gap (code-verified)

`freshness.rs` (`FreshnessOracle`, stale-price/Ghost-#3 detector) and `temporal_skim.rs`
(`TemporalSkimOracle`, time-extracted-value/skim detector) have **no `OracleType` variant** at all
— confirmed by grep across `src/evm/mod.rs`'s `OracleType` enum (18 variants, neither name appears).
They activate purely from `evm_fuzzer.rs`: `FreshnessOracle` auto-activates from ABI fingerprint
(`latestRoundData` selector present, `evm_fuzzer.rs:622-628`); `TemporalSkimOracle` activates on the
`--temporal-skimming` flag (`evm_fuzzer.rs:592-597`). Neither is reachable through `-d`, and neither
has a `LeakClass` mapping — `leak_class.rs`'s module doc (added in `c542a38`) documents this as
known and intentional, but the taxonomy itself still doesn't know these detectors exist.

Both are clearly **Value**-class by their own doc comments: `TemporalSkimOracle`'s `is_skim` doc
explicitly says *"unearned, time-extracted value"*; `FreshnessOracle` detects stale price data
consumed without a check — a precondition for mispriced-value extraction (Ghost #3). Same semantic
family as the already-bound `ERC4626` (share-price manipulation) and `Pair`/`MathCalculate`
(direct extraction, `c542a38`).

## Precedent: ERC4626 already solved half of this exact problem

`ERC4626Oracle` has the identical activation shape (ABI-fingerprint auto-detect, independent of
`-d`) and was already given a full `OracleType`/`LeakClass` binding despite that — see `3b95709`'s
fix for `-d all` and the existing `LeakClass::Value.oracles()` entry. The resolved precedent: an
oracle can be **enumerated** in the taxonomy for discoverability/reporting even when its
**activation** is independently gated. `-d` not controlling activation is a documented, accepted
property (see `ERC4626Oracle`, `evm_fuzzer.rs:600-609`) — it does not disqualify an oracle from
having a canonical `OracleType`/`LeakClass` identity.

## What changes

### 1. `src/evm/mod.rs` — add two `OracleType` variants

```rust
pub(crate) enum OracleType {
    ...
    ERC4626,
    Freshness,      // ← NEW
    TemporalSkim,   // ← NEW
}
```

Add `as_str()`/`from_str()` arms (`"freshness"`, `"temporal_skim"`), following the exact pattern of
every other variant. Add both to the `"all"` literal list in `from_strs` (mirrors the `3b95709`
ERC4626 fix — `-d all` should enumerate every registered detector, activation mechanism aside).
Do **not** add either to `"high_confidence"` unless the team wants that (these are heuristic/
precondition detectors, not high-confidence bug oracles — matches how `MathCalculate`/`Pair` etc.
were left out of `high_confidence` in `c542a38`).

### 2. `src/evm/leak_class.rs` — bind both to `LeakClass::Value`

```rust
LeakClass::Value => &[FeeOnTransfer, ERC20, Rebasing, ERC4626, Pair, MathCalculate, Freshness, TemporalSkim],
```

Update the module doc's "Out-of-band oracles (§5.4)" note (added in `c542a38`) to reflect that
they now HAVE an `OracleType`/`LeakClass` identity — the "out-of-band" property that remains is
narrower: *activation* is still independent of `-d`, not that they're untracked by the taxonomy.

### 3. `evm_fuzzer.rs` — no change to activation logic

Explicitly NOT changing how `FreshnessOracle`/`TemporalSkimOracle` get instantiated
(`evm_fuzzer.rs:592-628`) — this feature is enumeration/taxonomy only, matching the ERC4626
precedent where `-d` still doesn't gate the actual `oracles.push(...)` call. If the team later
wants `-d` to actually control these (e.g., `-d value_leak` implying "and disable freshness
checking too"), that's a separate, larger behavioral change — out of scope here.

### 4. Tests

- `oracle_type_from_strs_all_includes_freshness_and_temporal_skim` (mirrors the `3b95709` ERC4626
  test at `mod.rs:~1325`).
- `LeakClass::Value.oracles()` test update (mirrors `value_binds_erc4626_orphan` in
  `leak_class.rs`) — assert `Freshness` and `TemporalSkim` are both present.
- Golden regression: `-d all` byte-identical oracle SET aside from the two additions (no existing
  `-d <name>` invocation should change meaning — this is purely additive, same guarantee every
  prior taxonomy change in this series held).

## What stays byte-identical

- `FreshnessOracle`/`TemporalSkimOracle` activation conditions — completely unchanged.
- Every existing `-d <name>` invocation — unaffected (additive enum variants + additive `all`
  entries only).
- No `PromotionCandidate` producer is added for either — this feature is taxonomy-only. If the team
  wants Value-class promotion for stale-price/skim findings too, that's a natural follow-on
  (same shape as 034 for ControlFlow) but is explicitly NOT bundled here to keep this change small
  and low-risk.

## Out of scope

- Adding `PromotionCandidate` emission to either oracle (separate, optional future feature).
- Making `-d` actually gate these oracles' activation (a real behavioral change, not requested by
  the audit — the audit's finding was "taxonomy doesn't know they exist," not "activation should be
  flag-controlled").
- Any change to `--temporal-skimming`'s existing semantics.
