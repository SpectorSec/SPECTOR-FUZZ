# Feature 020 — Leak Taxonomy Unification (LeakClass SSOT)

**Status:** Specified
**Owner:** TBD
**Last updated:** 2026-07-04
**Held:** LOCAL (builds on 019 Phase A permission-leak gate; restructures the shared PromotionCandidate → coordinate with 019-C)

---

## Overview

The engine carries **three unaligned taxonomies** for what is conceptually one thing — a leak
primitive. `OracleType` (`src/evm/mod.rs:525`, 16 variants, the `-d` selection strings) enumerates
*detection*. `MiddlewareType` (`src/evm/middlewares/middleware.rs:22`, 20 variants, mostly infra)
enumerates *inline hooks*. `PromotionCandidate` (`src/evm/planner/campaign_planner.rs:99`)
enumerates *what gets amplified* — but with **zero class information**: its only discriminator is
`best_inflow: u128`. Nothing binds these three; the mapping lives in developers' heads and in a
fragile documentation table, and it drifts the moment anyone renames a struct.

This feature makes a single Rust enum — `LeakClass` — the **Single Source of Truth**. Every one of
the three surfaces *derives* from it via trait methods the compiler validates:
`.oracles() -> &[OracleType]`, `.middleware() -> Option<MiddlewareType>`, `.as_str()`. A new
`OracleType` or `MiddlewareType` that isn't accounted for in the `LeakClass` impls becomes a visible
compile-time hole, not silent drift. It then makes `PromotionCandidate` **reason-aware** (adds
`kind: LeakClass`), which is the prerequisite for `mutator.rs` to specialize amplification per
primitive instead of treating every promotion as a value-inflow secant target.

It also resolves the one primitive with no detection home — **Ownership (Class 06)** — by defining a
new post-hoc `SnapshotDelta` oracle (a governance-state objective gate on owner/admin slots),
keeping it cleanly distinct from Permission (the *act of calling*) without building a dead
middleware.

**Weapons this builds on** (`spector-weapons.md`): 015 Promote→Locate→Amplify (LedgerSecant), 019
Permission-Leak materiality gate (`MiddlewareType::PermissionLeak`), the reentrancy/fee/permission
inline templates, the `-d`/`OracleType::from_strs` selection surface (`mod.rs:772`, `:1121`). It adds
**one** new detection surface (SnapshotDelta/Ownership); everything else is *rationalization*, not
new capability.

## Why This Matters

The Middleware Audit established the **Information Availability Law** (memory:
`project_middleware_audit`): an oracle needs an inline middleware iff its verdict depends on
during-execution state. The proposed `LeakClass` encodes that law *in the type system* —
`.middleware()` returns `None` for post-hoc primitives, proving no middleware should exist for them.
Three concrete failures the current split-brain creates:

1. **Promotion is reason-blind.** `PromotionCandidate` erases *why* a step was promoted — it keeps
   only `best_inflow`, so every promotion is implicitly a Value leak. `record_aposteriori_candidate`
   (`feedbacks.rs:395`) is value-inflow-only by construction. When 019-C routes a **Permission** leak
   (which moves *no* value, `best_inflow = 0`) into promotion, there is no field to carry the reason,
   and `mutator.rs:666-752` cannot tell a value skew from an authority breach. The result is that a
   permission leak would either be dropped by the inflow high-water gate or amplified with the wrong
   strategy (numeric secant on a call that has no numeric belly).
2. **Vocabulary drift is unenforced.** With three independent enums plus a paper table, "Price Skew"
   can be filed as Value one day and Invariant the next; a JSON preset tag and the Rust struct it
   configures can silently diverge. There is no compiler check binding a primitive name to its
   detection logic and its config string.
3. **Ownership has no home.** The taxonomy claims six primitives but only five have any detection
   substrate. Ownership (authority *relocation* — `transferOwnership`/`renounceOwnership`/
   `upgradeTo`) is neither a value move nor an unauthorized *call*; it is a governance-state delta
   with no oracle today. Left unmapped, Class 06 is a permanent asterisk that invites folding it into
   Permission and blurring two distinct belly gaps.

## Success Criteria

Worth building iff:

1. **One source of truth.** `LeakClass` exists with `.oracles()`, `.middleware()`, `.as_str()`,
   `.from_str()` (canonical + back-compat aliases), and `ALL`. The `evm_fuzzer` oracle/middleware
   registration and the `-d` parse route *through* `LeakClass`; no second selection path remains.
2. **Reason-aware promotion.** `PromotionCandidate` carries `kind: LeakClass`. A promoted permission
   leak reads back as `LeakClass::Permission`; a value-inflow promotion as `LeakClass::Value`.
3. **Ownership has a home.** A `SnapshotDelta` oracle fires an objective when a watched owner/admin
   slot changes across the tx boundary; `LeakClass::Ownership.oracles()` returns it. On a regression
   contract calling `transferOwnership`, the objective fires; a no-op re-set of the same owner does
   not.
4. **Differentiated amplification.** `mutator.rs` branches on `cand.kind`: `Value` → the existing
   numeric LedgerSecant; `Permission` → administrative call-tree permutation (not numeric tuning).
   Verified: a promoted permission lever does **not** enter the secant numeric path.
5. **Zero behavioral change on the refactor path.** Every existing `-d <oracle>` invocation selects
   the byte-identical oracle set post-migration; `PromotionCandidate.kind` defaults to `Value`, so
   pre-020 value-inflow promotions are unchanged (Constitution rule 2). SnapshotDelta and the
   kind-branch are additive, behind their own selection/flag.
6. **Throughput held.** SnapshotDelta reads a bounded owner/admin slot set at the tx boundary only
   (post-hoc, no per-opcode cost); exec/sec stays within ~5% of the ~860 yDAI baseline.

## Out of Scope

- **Deleting `OracleType` / `MiddlewareType`.** They remain the concrete registries `LeakClass`
  *delegates to*. This feature binds them under one master enum; it does not collapse them. Removing
  the `-d <oracle-name>` back-compat aliases is explicitly deferred.
- **A `--mw-*` flag namespace.** Rejected in design: it would create a second way to configure the
  same primitive alongside `-d` and the capability flags — the exact split-brain this feature
  removes. Selection stays `-d <class|oracle>`; inline behavior stays on capability flags
  (`--causal-identity`, etc.).
- **Phase B Message-leak middleware.** Still gated on cross-contract provenance (019 Checkpoint
  19.4, `mutator.rs:757`). `LeakClass::Message.middleware()` returns `None` until then, with a
  documented Phase-B upgrade to `Some(MiddlewareType::MessageLeak)`.
- **New value/invariant detection surface.** Those primitives keep their existing oracle sets; 020
  only *groups* them under `LeakClass`.

## Investigation Checkpoints

### Checkpoint 20.1 — three unaligned taxonomies  ✓ RESOLVED
**Files:** `src/evm/mod.rs:525` (OracleType), `src/evm/middlewares/middleware.rs:22`
(MiddlewareType), `src/evm/planner/campaign_planner.rs:99` (PromotionCandidate).
**Question:** Is there any single structure binding primitive → oracle → middleware → config string?
**Evidence:** None. `OracleType` (16) drives `-d` via `from_strs` (`mod.rs:772`, `:1121`);
`MiddlewareType` (20, mostly infra: OnChain/Coverage/Sha3/CallPrinter…) drives inline attach;
`PromotionCandidate` has `{contract, selector, best_inflow, set}` and no class link. The mapping is
implicit. **Confirmed: no SSOT; drift is unprevented.**

### Checkpoint 20.2 — PromotionCandidate reason-erasure  ✓ RESOLVED
**Files:** `src/evm/planner/campaign_planner.rs:99`, `src/evm/feedbacks.rs:344-401`,
`src/evm/mutator.rs:666-752`.
**Question:** Can the engine tell *why* a candidate was promoted?
**Evidence:** Two promotion sources — a-priori (`campaign_planner.rs:261`, reflexive-lever →
`campaign.promoted`) and a-posteriori (`feedbacks.rs:395`, highest `best_inflow` → PromotionCandidate
→ pinned by `mutator.rs:684`). Both are value/inflow driven; a distinct confirmation channel
(`INJECTION_CONFIRMED_*`, `cmp_linearity.rs:110-113`) is process-global booleans, unrelated to the
candidate struct. **Confirmed: promotion carries no leak class; 019-C has nowhere to record
"Permission". This is the field 020 adds.**

### Checkpoint 20.3 — only 3/6 primitives have (should have) a middleware  ✓ RESOLVED
**Files:** `middlewares/reentrancy.rs`, `middlewares/fee_on_transfer_detector.rs`,
`middlewares/permission_leak.rs`.
**Question:** Does every primitive need an inline hook?
**Evidence:** Built inline mws map to exactly ControlFlow (Reentrancy), Value (FeeOnTransferDetector),
Permission (PermissionLeak, 019). Message is post-hoc until Phase B; Invariant + Ownership are
post-hoc by nature (their verdict is a final-state comparison — Information Availability Law says no
during-exec witness is required). **Confirmed: `.middleware()` must be `Option`; forcing a struct for
Invariant/Ownership would be dead code.**

### Checkpoint 20.4 — Ownership has no detection home  ✓ RESOLVED (design decision)
**Files:** `src/evm/oracles/` (no ownership oracle), `oracles/function.rs` (Permission), 
`oracles/selfdestruct.rs` / `oracles/approval.rs` (nearest neighbors).
**Question:** What detects authority *relocation* (distinct from an unauthorized call)?
**Evidence:** Nothing. Permission (o_func) fires on *who called*; it does not watch the owner slot
*value*. `selfdestruct`/`approval` are adjacent but not governance-state. **Resolution:** define a
new post-hoc `SnapshotDelta` oracle (objective gate) that snapshots watched owner/admin storage slots
and fires when one changes across the tx boundary. New `OracleType::Ownership`; no middleware.
**This gives Class 06 a crisp, distinct home.**

### Checkpoint 20.5 — `-d` back-compat surface  ✓ RESOLVED
**Files:** `src/evm/mod.rs:772`, `:1121` (`OracleType::from_strs(args.detectors)`).
**Question:** Will routing selection through `LeakClass` break existing `-d function`/`-d all`
invocations?
**Evidence:** `-d` strings are parsed by `OracleType::from_strs` into the oracle registry. `LeakClass`
sits *above* this: `from_str` accepts class names *and* the legacy oracle aliases, expanding a class
to `.oracles()`. `-d all` continues to select the full registry. **Confirmed: back-compat is a
superset — no existing invocation changes meaning.**

## Risks

- **Refactor regression (byte-identical path).** Routing oracle selection through `LeakClass` must
  reproduce the exact same oracle set for every existing `-d` string. Mitigation: `LeakClass` is a
  *grouping* over the unchanged `OracleType` registry; a golden test asserts `-d all` and each
  `-d <oracle>` yield an identical oracle set pre/post migration.
- **`kind` default polarity.** `PromotionCandidate.kind` must default to `LeakClass::Value` — the
  existing a-posteriori path is value-inflow, so a legacy/untagged candidate must read as Value or
  serialized corpora regress. Fail-safe default, not `Ownership`/`Permission`.
- **SnapshotDelta slot selection.** Watching *all* storage is prohibitive and noisy. v1 watches a
  bounded set: slots the ABI/topology scan flags as owner/admin (EIP-1967 impl/admin slots,
  `owner()`-backing slots, known governance selectors' targets). Over-broad → false objectives;
  over-narrow → misses. Start narrow (topology-flagged only), widen behind evidence.
- **mutator kind-branch coupling with 019-C.** The `Permission` amplification path only has an input
  once 019-C routes permission hits into promotion with `kind = Permission`. Sequence 020-A (enum +
  field, Value default) can land independently; 020-C (kind-branch) should land with or after 019-C
  so the branch has a live producer. Call out the ordering in the plan.

## Open Questions

- **SnapshotDelta granularity:** objective on *any* owner/admin slot change, or only when the new
  value is attacker-controlled/attacker-favorable (owner → attacker address)? (Lean: any change is an
  objective for v1 — an unexpected authority move is the signal; provenance refinement is a follow-on.)
- **Ownership vs Permission overlap on `upgradeTo`:** a proxy upgrade is both an unauthorized call
  (Permission, if caller ∉ admins) and an authority relocation (Ownership, impl slot changes). Do we
  emit both, or dedupe to Ownership? (Lean: both may fire; distinct bug-idx, distinct belly — dedupe
  only if double-emit proves noisy, mirroring the 019 legacy-suppression pattern.)
- **`LeakClass` home module:** co-locate with `OracleType` in `src/evm/mod.rs`, or a dedicated
  `src/evm/leak_class.rs` re-exported? (Lean: dedicated module — this enum is the taxonomy root and
  will accrete trait impls; keep it out of the already-large `mod.rs`.)
- **JSON preset tags:** migrate existing `ExploitTemplate` metadata tags to `LeakClass::as_str()`
  now, or dual-read (accept old + new) for one release? (Lean: dual-read during migration, hard-cut
  after presets are regenerated.)
