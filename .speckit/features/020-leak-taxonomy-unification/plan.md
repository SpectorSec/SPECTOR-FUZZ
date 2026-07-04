# Plan — Feature 020 — Leak Taxonomy Unification (LeakClass SSOT)

**Status:** 020-A BUILT + PUSHED (commit 03805a4). 020-B BUILT (SnapshotDelta oracle, unit-green). 020-C pending (needs 019-C producer).
**Checkpoints resolved:** 20.1 ✓, 20.2 ✓, 20.3 ✓, 20.4 ✓ (SnapshotDelta decision), 20.5 ✓
**Last updated:** 2026-07-04
**Held:** LOCAL

### Build log
- **020-A** (commit 03805a4, pushed): `LeakClass` SSOT enum + `PromotionCandidate.kind` (serde-default Value). 6 unit tests + full lib regression green. Accessors carry `#[allow(dead_code)]` (selection routing is 020-C).
- **020-B** (built, this session): `src/evm/oracles/snapshot_delta.rs` (`SnapshotDeltaOracle`, pure `detect_relocations` core + 5 unit tests); `OWNERSHIP_BUG_IDX = 20`; `OracleType::Ownership` (+ `as_str`/`from_str`/`from_strs` "all", NOT high_confidence); `Config.ownership_oracle` wired at both mod.rs construction sites; registered in `evm_fuzzer.rs` under `-d ownership_leak`/`-d ownership`/`-d all`; `LeakClass::Ownership.oracles() -> &[OracleType::Ownership]`. Watch set v1 = EIP-1967 impl/admin/beacon slots + `watch_slot`-registered owner slots; fires on pre≠post relocation (no-op re-write suppressed). 6+7 unit tests green.

---

## Architecture Decision

One enum, `LeakClass`, becomes the master delegator. The two concrete registries (`OracleType`,
`MiddlewareType`) and the promotion struct (`PromotionCandidate`) are *bound to it*, not replaced.
The compiler is the validator: exhaustive `match` in each `LeakClass` impl means an unaccounted
`OracleType`/`MiddlewareType` variant is a build error, not silent drift. No `revm` fork, no parallel
selection system (Constitution rules 3–4), no `--mw-*` flag namespace (rejected — split-brain).

```
                       ┌──────────────────────────────┐
   -d <class|oracle> ─►│          LeakClass           │  (SSOT — src/evm/leak_class.rs)
   JSON preset tag  ─► │  .oracles()   -> &[OracleType]│──► oracle registry (unchanged)
                       │  .middleware()-> Option<MwT>  │──► inline attach (unchanged)
                       │  .as_str()    -> &str         │──► one canonical config string
                       └───────────────┬──────────────┘
                                       │ kind
                                       ▼
                     PromotionCandidate { …, kind: LeakClass }
                                       │
                                       ▼
                     mutator.rs branch on kind:
                        Value      → LedgerSecant (numeric)     [existing]
                        Permission → admin call-tree permute    [020-C, needs 019-C]
                        Ownership  → (promotion N/A v1; objective-only)
```

### Phasing (partitioned by producer readiness)

- **020-A — Enum + binding + `kind` field (byte-identical refactor).** Introduce `LeakClass`; route
  `-d`/registration through it; add `PromotionCandidate.kind` defaulting to `Value`. No behavior
  change. Lands independently.
- **020-B — SnapshotDelta oracle + Ownership home.** New `oracles/snapshot_delta.rs`, new
  `OracleType::Ownership`, `LeakClass::Ownership.oracles() -> &[Ownership]`. Additive detection
  surface behind `-d ownership_leak` / `-d all`.
- **020-C — kind-aware amplification.** `mutator.rs` branches on `cand.kind`. Requires a `Permission`
  producer — lands with or after **019-C** (the found→PromotionCandidate wire that sets
  `kind = Permission`).

## New Types

| Type / field | Purpose | Location |
|--------------|---------|----------|
| `enum LeakClass { ControlFlow, Value, Message, Permission, Invariant, Ownership }` | the 6 primitives, SSOT | new `src/evm/leak_class.rs` |
| `LeakClass::oracles() -> &'static [OracleType]` | primitive → detection oracle(s); slice (Value/Invariant/Ownership span several) | same |
| `LeakClass::middleware() -> Option<MiddlewareType>` | inline hook iff Information Availability Law requires; `None` = post-hoc | same |
| `LeakClass::as_str()/from_str()` | one canonical config string + back-compat oracle aliases | same |
| `LeakClass::ALL: [LeakClass; 6]` | iteration | same |
| `impl Default for LeakClass` → `Value` | back-compat for untagged promotions | same |
| `PromotionCandidate.kind: LeakClass` | reason-aware promotion | `planner/campaign_planner.rs:99` |
| `OracleType::Ownership` | new detection variant | `mod.rs:525` (+ `as_str`/`from_strs`) |
| `SnapshotDeltaOracle` | post-hoc governance-state objective gate | new `oracles/snapshot_delta.rs` |

### The canonical binding (v1, against real variants)

```rust
match self {
  ControlFlow => oracles &[Reentrancy],                         mw Some(Reentrancy),
  Value       => oracles &[FeeOnTransfer, ERC20, Rebasing],     mw Some(FeeOnTransferDetector),
  Message     => oracles &[ArbitraryCall],                      mw None,   // Phase B → MessageLeak
  Permission  => oracles &[Function],                           mw Some(PermissionLeak),
  Invariant   => oracles &[Invariant, StateComparison, Echidna],mw None,
  Ownership   => oracles &[Ownership],                          mw None,   // SnapshotDelta (020-B)
}
```

## SnapshotDelta Oracle (Ownership home)

A post-hoc objective gate — **not** a middleware (its verdict is a boundary comparison, needs no
per-opcode witness; Information Availability Law → `.middleware() == None`).

- **Watch set (v1, bounded):** slots the corpus/topology scan flags as authority-bearing — EIP-1967
  implementation/admin slots, `owner()`/`admin()`-backing slots, targets of known governance
  selectors (`transferOwnership`, `renounceOwnership`, `upgradeTo(address)`,
  `changeAdmin(address)`). Reuse the existing topology intelligence pass (same source that populates
  the privileged-selector set 019 reads).
- **Fire condition:** snapshot the watch set pre-tx (from `initial_vm_state` / prior `new_state`) and
  post-tx (`get_execution_result().new_state`); emit an objective when any watched slot value changes
  (v1: any change; see Open Question on attacker-favorability refinement).
- **Bug type:** new typed bug "Ownership/Authority Relocation" (distinct bug-idx from o_func's
  "Unauthorized Function Access", so an `upgradeTo` by a non-admin can legitimately surface both).

## The kind-aware Mutator Branch (020-C)

`mutator.rs:666-752` currently reads `PromotionCandidate` and pins `(contract, selector)` into
`campaign.promoted` for the LedgerSecant. 020-C reads `cand.kind` and dispatches:

- `Value` → unchanged: pin + numeric LedgerSecant (015 machinery).
- `Permission` → pin the privileged step but **skip the numeric secant** (a permission belly has no
  numeric offset to bisect); instead amplify by permuting the administrative call sequence around the
  pinned step (reorder/duplicate the privileged call vs. its guards). Producer = 019-C.
- `Ownership` → no promotion in v1 (objective-only signal); the `kind` is carried for reporting.
- `Invariant`/`Message`/`ControlFlow` → default pin, existing behavior, until dedicated strategies
  are specced.

## Registration

- **`leak_class.rs`** — the enum + impls; unit-tested in isolation.
- **`mod.rs`** — `-d` parse: try `LeakClass::from_str` first (expands to `.oracles()`), fall through
  to the existing `OracleType::from_strs` for bare oracle names; `OracleType::Ownership` added to the
  enum + `as_str` + `from_strs`.
- **`evm_fuzzer.rs`** — oracle registration and inline-middleware attach read `LeakClass` (drive the
  set from `.oracles()`/`.middleware()`), so the taxonomy is the single gate. SnapshotDelta oracle
  registered when `Ownership` is selected.
- **`planner/campaign_planner.rs`** — `PromotionCandidate` gains `kind`; `impl Default` = `Value`.
- **`feedbacks.rs`** — a-posteriori construction (`:395`) sets `kind: LeakClass::Value` (its inflow
  semantics); 019-C, when it lands, constructs with `kind: LeakClass::Permission`.
- **`mutator.rs`** — consumer branch (020-C).

## CLI

- **No new flags for selection.** `-d <class>` gains the class strings (`permission_leak`,
  `value_leak`, `ownership_leak`, …) as canonical, keeping `-d function`/`-d reentrancy`/`-d all` as
  back-compat aliases. Inline behavior stays on the existing capability flags (`--causal-identity`
  for the 019 gate, etc.).
- **`-d ownership_leak`** selects the new SnapshotDelta oracle; included in `-d all`.
- **Graduation:** unchanged model — SnapshotDelta stays out of the default high-confidence set until
  validated, per `feedback-flag-graduation-model`.

## Interaction with Existing Features

| Feature | Interaction |
|---------|------------|
| 015 Reflexive Lever | `campaign.promoted` (a-priori) and PromotionCandidate (a-posteriori) both gain `kind`; secant path is the `Value` branch |
| 019 Causal Identity | **direct coupling** — 019-C sets `kind = Permission`; `LeakClass::Permission.middleware()` returns the 019 `MiddlewareType::PermissionLeak` |
| 013 Provenance | unchanged; SnapshotDelta reads state values, not taint |
| 004 Ghost Identities | Permission still reads `TrustedCallerMetadata`; Ownership is orthogonal (watches slot values, not caller sets) |
| o_func / o_arb / o_invariant / rebasing | grouped under LeakClass; detection logic unchanged |
| reentrancy / fee-on-transfer | become `ControlFlow`/`Value` middleware bindings; code unchanged |

## Performance

- **020-A refactor:** zero runtime cost — `LeakClass` methods are compile-time `match`es over
  `&'static` slices; selection happens once at startup.
- **SnapshotDelta:** post-hoc, boundary-only. Cost = one HashMap read of the bounded watch set per tx
  (no per-opcode hook). Target: within ~5% of the ~860 exec/sec yDAI baseline; watch-set size is the
  only lever and is topology-bounded.
- **`kind` field:** one enum discriminant on PromotionCandidate; negligible.

## Test Plan

- **Unit (`leak_class` module):**
  - `every_leakclass_maps_to_oracles` — `ALL.iter()` all return non-empty `.oracles()`.
  - `middleware_law_holds` — `Invariant`/`Ownership`/`Message` return `None`;
    `ControlFlow`/`Value`/`Permission` return `Some(_)`.
  - `from_str_roundtrip_and_aliases` — `as_str` ↔ `from_str`, plus legacy aliases
    (`function`→Permission, `reentrancy`→ControlFlow) resolve.
- **Golden refactor (rule 2):** `-d all` and each `-d <oracle>` select a byte-identical oracle set
  pre/post migration (assert the registered oracle-id set is unchanged).
- **Promotion:** a value-inflow promotion round-trips with `kind == Value`; a synthetic
  Permission-tagged candidate round-trips with `kind == Permission` and is **not** routed to the
  numeric secant (020-C).
- **SnapshotDelta (020-B):**
  - `owner_change_fires` — a tx that sets a watched owner slot to a new value → objective.
  - `owner_noop_no_fire` — re-setting the same owner value (pre==post) → no objective (mirrors 019
    materiality: a no-op is not a leak).
  - `upgrade_slot_change_fires` — EIP-1967 impl slot change → objective.
- **Regression:** flag/selection off → objectives + ledger output byte-identical to pre-020 `main`.
