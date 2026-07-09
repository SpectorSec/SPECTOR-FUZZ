# Feature 031 — Kind-Aware Campaign Routing

## Problem (code-verified)

`plan_campaign_sampled` is kind-blind. It receives `PromotionCandidate` indirectly through two
narrow channels:

- `kind == Permission` → `structural_pin: Option<(EVMAddress, [u8;4])>` (mutator.rs:1182) → planner
  injects it as a structural step via `build_structural_step` (campaign_planner.rs:374). **Working.**
- `kind == Value` → `structural_pin = None` (comment at mutator.rs:1177: "handled by reflexive
  lever") → planner falls back to `maybe_promote_lever`, which iterates `REFLEXIVE_LEVER_SELECTORS`
  (14 hardcoded selectors, campaign_planner.rs:270). **Gap: if the dynamically discovered selector
  is NOT in that list, it is never injected into the campaign sequence.**
- `kind == Ownership` → falls through the `kind == Permission` filter entirely (mutator.rs:1182).
  Ownership candidate is written to `PROMOTION_CANDIDATE` but never read by the planner. **Gap.**
- `kind == Message` → not in scope (019-B, cross-contract provenance gated).

The consequence: the "information has a measurable lifetime" chain breaks at the planner for
Value and Ownership kinds. A runtime discovery (e.g., `harvest()` on a vault is a value leak)
changes mutator behavior (secant_promotable gates, 025) but does NOT pin that selector into
future campaign sequences. The planner cannot exploit what the runtime found.

## Root cause (one line)

`PromotionCandidate.kind` is written by every oracle path but read only by the mutator. The
campaign planner reads the selector but not the kind → cannot route Value vs Permission vs
Ownership to the correct BPLE slot.

## BPLE slot assignment (the routing rule)

| kind       | BPLE slot  | Planner action                              | Rationale                                       |
|------------|------------|---------------------------------------------|-------------------------------------------------|
| Value      | **Lever**  | inject between Prime and Exploit, mark `promoted` | candidate is the magnitude-tunable warper      |
| Permission | **Prime**  | inject as structural step (existing 024)    | candidate gates access; must precede the Lever  |
| Ownership  | **Prime**  | same as Permission                          | ownership controls who can act; setup step      |
| Message    | —          | deferred (019-B)                            | cross-contract provenance not yet consumable    |

## What changes

### 1. `src/evm/mutator.rs` — split the candidate read into two paths

Current (lines 1179-1183):
```rust
let structural_pin = state
    .metadata_map()
    .get::<PromotionCandidate>()
    .filter(|c| c.set && c.kind == LeakClass::Permission)
    .map(|c| (c.contract, c.selector));
```

New — two reads from the same metadata slot:
```rust
// Permission + Ownership → Prime slot (structural_pin, existing 024 path)
let structural_pin = state
    .metadata_map()
    .get::<PromotionCandidate>()
    .filter(|c| {
        c.set
            && matches!(c.kind, LeakClass::Permission | LeakClass::Ownership)
    })
    .map(|c| (c.contract, c.selector));

// Value → Lever slot (new dynamic lever pin)
let value_lever_pin = state
    .metadata_map()
    .get::<PromotionCandidate>()
    .filter(|c| c.set && c.kind == LeakClass::Value)
    .map(|c| (c.contract, c.selector));
```

Pass `value_lever_pin` as a new arg to `plan_campaign_sampled` (after `structural_pin`, before
`borrow_authority`).

### 2. `src/evm/planner/campaign_planner.rs` — add `value_lever_pin` parameter

Signature change:
```rust
pub fn plan_campaign_sampled<R: Rand>(
    cache: &CampaignTargetCache,
    topology_report: Option<&TopologyReport>,
    temporal_skimming: bool,
    effective_reflexive: bool,
    dimension_warp: bool,
    structural_pin: Option<(EVMAddress, [u8; 4])>,
    value_lever_pin: Option<(EVMAddress, [u8; 4])>,   // ← NEW
    borrow_authority: Option<EVMAddress>,
    divergence_value: Option<u128>,
    rand: &mut R,
) -> Option<CampaignSequence>
```

Replace the existing `maybe_promote_lever` block (lines 350-355) with two separate blocks:

```rust
// Feature 031 — dynamic Value lever (UNCONDITIONAL — not gated on effective_reflexive).
// The PromotionCandidate is runtime ground truth: the oracle found exactly which selector
// is the lever on THIS target. That knowledge should inject regardless of which a-priori
// flags were passed. effective_reflexive was designed for the static list (known patterns);
// runtime discovery is different — it requires no prior knowledge.
//
// Lever type coverage: this single path handles ALL Value-kind lever variants —
// reflexive-price (Curve), donation/sync, ERC4626 share-price, any novel protocol.
// The static list below handles ONLY reflexive-price for cold-start; everything else
// depends entirely on this dynamic path.
let dynamic_fired = if let Some((vc, vsel)) = value_lever_pin {
    if let Some(lever) = build_structural_step(cache, vc, vsel) {
        promoted.push(steps.len());
        steps.push(lever);
        true
    } else {
        false
    }
} else {
    false
};

// Cold-start fallback: static reflexive-price list (Curve/Compound/Aave only).
// Fires ONLY when: (a) no runtime candidate yet, AND (b) --reflexive-lever passed.
// Purpose: give known Curve-family targets a head start before runtime discovery
// produces a candidate. Returns None for novel protocols → runs flat until dynamic
// path fills in (same behaviour as today, but now it WILL fill in).
// NOT a general lever mechanism — it is a bootstrap for one pattern family.
if !dynamic_fired && effective_reflexive {
    if let Some(lever) = maybe_promote_lever(cache) {
        promoted.push(steps.len());
        steps.push(lever);
    }
}

### 3. All `plan_campaign_sampled` call sites — add `None` for `value_lever_pin`

- `plan_campaign` (line 218): `None`
- All test calls (lines 855, 890, 928, 951, 964, 989, 1012, 1030, 1046): `None`
- The live mutator call (line 1216): pass the new `value_lever_pin` local

### 4. Update `structural_pin_seeds_step_into_plan` test (line 906)

The test sets `structural_pin` for a Permission candidate. No change needed to the test body,
but the call site needs the new `None` for `value_lever_pin`.

Add a new test: `value_lever_pin_seeds_lever_step` — mirrors the structural_pin test but
passes `value_lever_pin` with a selector that IS in the cache (use the same mock ABI setup
as the structural test), asserts that:
1. The pinned selector appears in steps
2. Its index is in `campaign.promoted`
3. It appears BEFORE the exploit step (the Lever slot)

## What stays byte-identical

- No promotion candidate set → `value_lever_pin = None` → `dynamic_fired = false` → cold-start
  fallback runs `maybe_promote_lever` as before → byte-identical for all targets with no candidate
- `kind == Permission` path → `structural_pin` set as today, `value_lever_pin = None` → unchanged
- Known Curve target with `add_liquidity`, no candidate yet → dynamic path skips (None) →
  fallback fires `maybe_promote_lever` → same lever injected as before
- Known Curve target WITH a runtime candidate → dynamic path fires on candidate → more accurate
  (the specific contract+selector the oracle actually found, not a list guess)
- All existing tests pass `None` for `value_lever_pin` → byte-identical

## What this closes

The full audit chain for the Value path:

```
Runtime execution
  → ERC4626 oracle fires, publishes PromotionCandidate(kind=Value, contract=A, selector=harvest)
  → PROMOTION_CANDIDATE global set
  → mutator reads: value_lever_pin = Some((A, harvest))             ← now exists
  → plan_campaign_sampled injects harvest() between Prime + Exploit  ← now exists
  → promoted = [lever_idx]
  → secant tunes args on step lever_idx                              ← was already working
  → scheduler boosts inputs containing this step (026-A/B)          ← was already working
  → future executions spend more effort on A::harvest()             ← now complete
```

The Permission/Ownership expansion closes the same chain for structural candidates: Ownership
was silently dropped before. Now both structural kinds pin the Prime slot.

## Lever type taxonomy (what the Lever slot actually covers)

`--reflexive-lever` is a misnomer inherited from Feature 015 (first lever type discovered was
Curve-style reflexive price skew). The Lever slot in BPLE is general — it holds any call whose
write is consumed by a value-gating read later in the sequence. Types:

| Lever type | Example selectors | Coverage after 031 |
|---|---|---|
| Reflexive-price | `add_liquidity`, `remove_liquidity_imbalance` | Static list (cold-start) + dynamic |
| Donation/sync | `donate()`, `sync()`, `skim()` | Dynamic only (not in static list) |
| ERC4626 share-price | `deposit()` when used as price lever | Dynamic only |
| Rate/fee setter | `setFee()`, `setInterestRate()` | Permission path → Prime slot (correct — it's a prerequisite) |
| Novel protocol | anything runtime discovers | Dynamic only |
| Temporal | block advance | Separate warp mechanism (`temporal_skimming`), not selector-based |
| Proxy selector | delegate target swap | Proxy layer ⑤ — discrete mutation, out of scope here |

The static list (`REFLEXIVE_LEVER_SELECTORS`) is NOT a general lever system. It is a bootstrap
for one pattern family. After 031, the dynamic path is the general system.

## Kind production audit — why only 3 of 6 are in scope

All 6 LeakClass variants exist but only 3 currently produce PromotionCandidates:

| Kind | Producer | Where | In scope for 031? |
|---|---|---|---|
| Value | feedbacks.rs:477 (ledger-driven) | belly-call inflow detection | YES |
| Permission | function.rs:261 (FunctionAuth oracle) | 019-A materiality gate | YES |
| Ownership | snapshot_delta.rs (SnapshotDelta oracle) | 020-B governance delta | YES |
| ControlFlow | **NONE** | reentrancy.rs fires + logs, never promotes | NO — producer gap |
| Invariant | **NONE** | invariant.rs / state_comp.rs fire + log, never promote | NO — producer gap |
| Message | **NONE** (019-B not built) | ArbitraryCall oracle, cross-contract provenance gated | NO — deferred |

Adding planner routing for ControlFlow and Invariant in 031 would be dead code — no
PromotionCandidate with those kinds is ever set, so the routing branches never execute.

The producer gaps (ControlFlow + Invariant) are a separate feature:
- `reentrancy.rs` on_oracle_result → emit `PromotionCandidate { kind: ControlFlow, contract, selector }`
  where (contract, selector) = the re-entered function (the Prime the planner should pin)
- `invariant.rs` / `state_comp.rs` → emit `PromotionCandidate { kind: Invariant, contract, selector }`
  where (contract, selector) = the call that broke the property (the Lever the planner should pin)

Once those producers exist, the planner routing in 031 handles them automatically:
- ControlFlow → matches `Permission | Ownership` in the structural_pin filter → Prime slot ✓
  (or add `| ControlFlow` to the filter — same code path)
- Invariant → matches `Value` in the value_lever_pin filter → Lever slot ✓
  (Invariant-break is a magnitude-tunable lever, same BPLE position as Value)

## Out of scope

- `kind == Message` (019-B, needs cross-contract provenance — deferred)
- Ordering between structural_pin and value_lever_pin when BOTH are set (not currently possible
  since a candidate is a singleton; if that changes, structural goes to Prime and value goes to
  Lever by construction — no conflict)
- Changing `maybe_promote_lever` internals or `REFLEXIVE_LEVER_SELECTORS`
