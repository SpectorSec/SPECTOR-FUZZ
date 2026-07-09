# Feature 028 — Cross-Contract Provenance Consumption (Proxy track, layer ③)

**Status:** BUILT (2026-07-09)
**Held:** LOCAL
**Origin:** the Proxy/Delegate dependency analysis (V5 SYSTEM_DESIGN.dot review, [[skew-coverage-program]]). Cross-contract provenance is a 5-layer stack; this is layer ③.

## The 5-layer decomposition (from the dot review)
| Layer | Capability | Status |
|---|---|---|
| ① | Taint crosses CALL/DELEGATECALL boundary | ✅ 017 Phase 2 (cmp_linearity.rs:351–534) |
| ② | Per-contract provenance STORAGE | ✅ `ArgStorageProvenance.per_slot: (EVMAddress,EVMU256)→u64` (feedbacks.rs:87) |
| **③** | **Cross-contract provenance CONSUMPTION** | **THIS FEATURE** |
| ④ | Caller-identity as taint source (confused-deputy) | ❌ DEFERRED — threat-model decision (calldata-only kept 2026-07-09) |
| ⑤ | Discrete selector/target Proxy LEVER | ❌ NOT built — new mutation mode, secant N/A |

## Overview
The taint bits and the per-slot storage map already span contract boundaries (①②). The only same-contract restriction was in the **consumer**: the LOCATE "skip storage-inert args" check filtered `per_slot` to `*addr == step.contract` (was mutator.rs:780), so an arg whose only storage effect lands in a **callee / proxy target** was wrongly skipped — dropping exactly the cross-contract lever.

028 replaces that filter with `arg_reaches_storage(per_slot, arg)`: OR the arg's provenance across **every** contract's slots. An arg is skipped only if it reaches NO storage anywhere in the call tree.

## Why this is correct AND safe
- **Correct:** provenance is per-arg-index (`1 << arg_idx`); if arg X flowed into any storage slot (own contract or a delegatecall'd/called contract), X is a genuine storage lever regardless of which contract holds the slot.
- **Safe (over-inclusion):** the check only gates whether LOCATE *probes* an arg. Not-skipping wastes at most one probe, which LOCATE's sensitivity rotation self-corrects. Over-*exclusion* (the old filter) silently lost levers — that's the regression class the code elsewhere warns against ("under-requeue is not safe").

## As built
- `arg_reaches_storage(per_slot, arg) -> bool` (pure, unit-tested): OR across all slots; `arg < 64` guard for the u64 provenance width (also fixes a latent shift-overflow the inline lacked).
- LOCATE skip site: `Some(meta) => !arg_reaches_storage(&meta.per_slot, arg)`. Dropped the now-unused `step`/`pin` bindings (kept a promoted-exists guard).

## Success Criteria
1. An arg whose provenance bit appears only in a DIFFERENT contract's slot counts as storage-reaching. ✓ unit-tested (`arg_reaches_storage_is_cross_contract`).
2. An arg with no provenance anywhere is still skippable. ✓
3. Own-contract case unchanged. ✓
4. `arg >= 64` → false, no shift overflow. ✓
5. Full suite green (no regression to same-contract LOCATE). ✓

## Out of Scope
- ④ caller-identity taint (threat-model gated; calldata-only retained) and ⑤ the discrete proxy-selector lever — the actual Proxy skew mutation. 028 makes cross-contract provenance *consumable*; it does not add the proxy lever.
- Live fork validation that a real confused-deputy / proxy case is now located (the open item across the skew program).
