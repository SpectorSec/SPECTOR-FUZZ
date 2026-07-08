# Plan — Feature 019 — Causal Identity Engine

**Status:** Phase A **BUILT + LIVE-VALIDATED** (LOCAL, unpushed) — lib compiles, unit-green, zero regressions, and the live A/B on the yDAI fork confirms the burn(0)/zero-delta permission-leak FP class is dead under `--causal-identity` (control fires at 52s, treatment 0 objectives over 288s / 121k exec). Phase B still gated (Checkpoint 19.4). 019-C routing wire deferred within Phase A (see Implementation Evidence).
**Checkpoints resolved:** 19.1 ✓, 19.2 ✓, 19.3 ✓, 19.4 ⚠ (blocks Phase B), 19.5 ✓
**Last updated:** 2026-07-04
**Held:** LOCAL

> **Rename note (2026-07-07):** the middleware authored here as `permission_leak.rs` / `PermissionLeakTracer` / `MiddlewareType::PermissionLeak` was renamed to **`function_auth.rs` / `FunctionAuthTracer` / `MiddlewareType::FunctionAuth`** — identity is oracle-rooted (it hardens `OracleType::Function`), per the naming law formalized in Feature 020. The `permission_leak_metadata` state field and `-d permission_leak` CLI string are unchanged (detection-domain, not identity). Original names below preserved as authored.

---

## Implementation Evidence (Phase A, 2026-07-04)

**Build:** `cargo test --lib` → 157 passed / 0 failed / 14 ignored. New module tests (6):
`burn_zero_is_not_material`, `tainted_privileged_sstore_is_material`,
`material_delta_without_taint_still_material`, `materiality_absent_fails_closed`,
`value_call_is_material`, `zero_value_call_not_material`. No regression to the 31
`dim_propagation_tests` or any existing suite.

**Files:** new `src/evm/middlewares/permission_leak.rs`; edits to `middlewares/mod.rs`,
`middlewares/middleware.rs` (MiddlewareType::PermissionLeak), `vm.rs`
(EVMState::permission_leak_metadata), `oracles/function.rs` (materiality gate + causal_identity
field/setter), `config.rs` + `mod.rs` (`--causal-identity` flag, both Config literals),
`fuzzers/evm_fuzzer.rs` (register PermissionLeakTracer + `fn_oracle.set_causal_identity`).

**Design refinement vs the plan above (deliberate, cleaner partition):**
- The plan had the *middleware* hold the privileged-selector set and emit `found: (contract,
  selector)`. **Built instead:** the middleware (`PermissionLeakTracer`) is a pure **materiality
  recorder** — it records `material_writes: HashSet<(contract, slot)>` (SSTORE pre≠post) and
  `value_moves: HashSet<contract>` (CALL value>0) into `PermissionLeakData`, knowing nothing about
  privilege or authorization. The **oracle** (`FunctionOracle`) keeps the single source of truth for
  rules + `TrustedCallerMetadata` (Ghost Identities) and adds ONE gate: an unauthorized privileged
  call fires only if `permission_leak_metadata.contract_material(&contract)`. This avoids duplicating
  the rule set into the middleware and keeps authorization in one place.
- **Materiality gate = the delta (`pre≠post`), not taint.** Rationale discovered during build:
  `cmp_linearity` populates the taint bus on a *separate* reexecution pass (feedbacks.rs:138), so
  requiring `arg_slot_provenance` in the main pass would false-negative inputs that pass hasn't
  visited. The delta is same-pass and ordering-robust, and adding it can only *suppress* fires (a
  real mint always changes state → no false-negative risk). Taint is retained as **best-effort
  confirmation** in `tainted_material` (evidence enrichment, not a gate input). This satisfies the
  fail-CLOSED intent (absent delta → not material → no fire) without the reexecution-timing fragility
  the original "provenance_absent_fails_closed" framing would have introduced.
- **019-C routing wire (`found`→PromotionCandidate) deferred within Phase A.** The burn(0) success
  gate is achieved by the oracle materiality gate alone; the oracle still `push_to_output`s (now
  gated). The promotion wire in `feedbacks.rs` is a distinct, higher-surface enhancement — build it
  after the live burn(0)-dead validation confirms the gate, so promotion rides a verified signal.

**Phase A success gate — MET (live A/B, 2026-07-04).** Fresh-corpus fork run, anvil block 11792183,
release binary rebuilt with `--causal-identity` exposed. Both arms: `-d all --bounty --reflexive-lever
--dimension-warp` on the yDAI preset-only target, empty corpus (no injected seed).

| Arm | flag | permission-leak FP | fuzz run-time | executions | objectives |
|-----|------|--------------------|---------------|-----------|-----------|
| control | (none) | **FIRED** `DAI.burn() reached by unauthorized caller … without reverting` | 52s (then `--bounty` early-exit) | 2,087 | **1** |
| treatment | `--causal-identity` | **none** | full 288s (timeout, no early-exit; exit 124) | **121,703** | **0** |

Treatment ran 5.5× longer and executed **58× more inputs** than the control needed to hit the FP,
with the permission-leak oracle active (16 privileged functions monitored, identical to control) and
**65.2% DAI instruction / 56.6% branch coverage** — i.e. it repeatedly exercised the burn/mint/
transferFrom no-op surface and the materiality gate suppressed every fire. This is suppression, not
absence of exploration. The `DAI.burn(0x0,0)` phantom (and its `mint()`/`transferFrom(0,0,0)`
siblings — the whole zero-delta permission-leak *class*) is dead under the gate. Confirms the unit
fixture `burn_zero_is_not_material` on the live target.

**Note (incidental, pre-existing):** the `-r/--replay-file` path can't round-trip saved
`*_replayable` dumps — the dumper serializes via `ConciseEVMInputReadable` (no `nested_actions`)
while the loader deserializes `ConciseEVMInput` (requires `nested_actions: Vec<NestedAction>`, not
`#[serde(default)]`). Also the `Some(_)` replay branch (evm_fuzzer.rs:1016) only re-runs for
trace+coverage and never evaluates objectives. Deterministic reproduction therefore goes through
`--load-corpus` (the `None`/`evaluate_input_events` path), not `-r`. Orthogonal to 019; noting for
a future replay-path fix.

---

## Architecture Decision

Two new inline middlewares + one routing wire, modeled on the two shipped inline-mw→oracle pairs.
No `revm` fork, no parallel system (Constitution rules 3–4). The build **partitions cleanly by the
one blocked prerequisite** (Checkpoint 19.4):

```
PHASE A — UNBLOCKED (build now)
  permission_leak.rs (on_step: JUMPI/SSTORE/CALL)
        │  materiality guard on EXISTING calldata provenance (same-contract sink)
        ▼
  host.evmstate.permission_leak_metadata.found        ── replaces o_func
        │
        └──► 019-C Routing Wire ──► PromotionCandidate ──► Signed Secant Solver
                                                              (campaign.promoted)

PHASE B — GATED on cross-contract provenance (Checkpoint 19.4, mutator.rs:757)
  message_leak.rs (on_step: CALL/STATICCALL/DELEGATECALL)
        │  read target stack word; validate arg_slot_provenance (cross-contract)
        ▼
  host.evmstate.message_leak_metadata.found           ── replaces o_arb
        └──► same 019-C wire
```

**Why the partition matters:** Permission Leak's material sink lives in the *same* privileged
contract as the tainted calldata, so it needs only the same-contract provenance that already ships.
Message Leak must trace calldata to a CALL target that may be *another* contract (proxy routing), so
it is blocked on lifting `mutator.rs:757` from `*addr == step.contract` to a cross-contract map.
**Phase A fixes the live burn(0) phantom without touching the blocked substrate.**

## New Types

| Type / field | Purpose | impl_serdeany? |
|--------------|---------|----------------|
| `PermissionLeakMetadata { found: HashSet<(EVMAddress,[u8;4])> }` on `EVMState` | inline-recorded material permission breaches (contract, selector) | matches `reentrancy_metadata` carrier pattern |
| `MessageLeakMetadata { found: HashSet<(EVMAddress,usize)> }` on `EVMState` (Phase B) | inline-recorded attacker-authored CALL targets (caller, pc) | same |
| `PermissionLeakDetector` (middleware) | `on_step` JUMPI/SSTORE/CALL; materiality guard | n/a (middleware) |
| `MessageLeakDetector` (middleware, Phase B) | `on_step` CALL/STATICCALL/DELEGATECALL; target-word provenance | n/a |

Carriers live on `EVMState` next to `reentrancy_metadata` (Checkpoint 19.3), reset per-tx like the
existing `found` sets. No new process-global statics — unlike 017's flow flags, these are per-tx
verdicts, so they belong in tx-scoped metadata, not `static mut`.

## The Routing Wire (019-C)

The single novel edge (Checkpoint 19.5 confirmed none exists). At the end of execution, before the
aposteriori candidate pass, read the two `found` sets; if non-empty, emit a `PromotionCandidate`
tagged `INJECTION_CONFIRMED` for the step whose input produced the hit. Integration point =
`feedbacks.rs` alongside `record_aposteriori_candidate` (:344), reusing its `PromotionCandidate`
construction but **sourced from the inline `found` set instead of the ledger-delta gate**. The
promoted step then flows into `campaign.promoted` → the Locate+Amplify secant locks its offset
(015 machinery, unchanged).

This is the wire fuzzland never built: `found` → promotion, not `found` → `push_to_output`.

## Registration

- **`middlewares/mod.rs`** — register `PermissionLeakDetector` (Phase A), `MessageLeakDetector`
  (Phase B) in the middleware chain, gated on the new flag.
- **`vm.rs` / `EVMState`** — add `permission_leak_metadata`, `message_leak_metadata` fields;
  `Default` empty; per-tx reset alongside `reentrancy_metadata`.
- **`evm_fuzzer.rs`** — when the flag is off, middlewares are not inserted and the legacy
  o_func/o_arb run unchanged (byte-identical path, Success Criterion 4).
- **`feedbacks.rs`** — 019-C wire reads the two `found` sets and emits `PromotionCandidate`.
- **corpus_initializer.rs** — reuse the existing privileged-selector scan that populates
  `FunctionOracle.rules`; the middleware reads the same rule set (single source of truth for
  "which selectors are privileged").

## CLI

- **Flag:** `--causal-identity` (moves Permission + Message leak inline; suppresses legacy
  o_func/o_arb for covered (contract, selector) pairs to avoid double-emit).
- **Config field:** `causal_identity: bool`
- **Graduation (per `feedback-flag-graduation-model`):** own flag during validation; do **not**
  add `|| args.bounty` yet. Phase A may graduate into `--bounty` independently once burn(0) is
  confirmed dead on the yDAI run and a regression contract passes (Open Question in specify.md).
- **Conflicts:** none. Additive to `--reflexive-lever`/`--dimension-warp`; distinct from `--bounty`
  bundle (checked `spector-cli.md`).

## Interaction with Existing Features

| Feature | Interaction |
|---------|------------|
| 004 Ghost Identities | **reads** `TrustedCallerMetadata` — Permission Leak honors dynamic trusted callers exactly as o_func does today (same allow-set semantics, moved inline) |
| 013 Provenance | **direct dependency** — materiality guard reads `arg_slot_provenance`; Phase A same-contract (ships), Phase B cross-contract (blocked, Checkpoint 19.4) |
| 014 Oracle Middlewares | sibling inline layer; `OracleTracker` proximity unaffected |
| 015 Reflexive Lever | **synergistic** — 019-C feeds `PromotionCandidate` into the same Promote→Locate→Amplify secant 015 owns; a confirmed leak becomes a Lever |
| o_func / o_arb (legacy) | **superseded when flag on** (suppressed for covered pairs), retained as default when off until graduation |
| reentrancy / fee-on-transfer | **templates** — same `on_step`→`found`→(now)promotion shape |

## Performance

- **When disabled:** zero code path — middlewares not inserted, `found` sets stay empty and unread,
  legacy oracles run the unchanged path. Byte-identical (rule 2).
- **When enabled — mandatory spatial fast-fail (Risk §1):** each `on_step` does an O(1) opcode
  discriminant check *first*. The heavier `arg_slot_provenance` bitset lookup runs **only** when
  (a) the opcode is a strict sink (SSTORE, or CALL with `value > 0`, or the CALL-family for Message
  Leak) AND (b) the executing selector is flagged privileged/under-analysis. Pure reads, non-sink
  opcodes, and non-privileged contexts short-circuit before any map touch. Target: within ~5% of
  the ~860 exec/sec yDAI fork baseline.

## Test Plan

- **Unit (isolated), `permission_leak` module:**
  - `burn_zero_is_not_material` — privileged selector, non-allowlisted caller, SSTORE with pre==post
    (or value-0 CALL) → `found` empty. **The burn(0) regression fixture.**
  - `tainted_privileged_sstore_is_material` — same caller, but attacker-tainted calldata drives an
    SSTORE where pre≠post → `found` contains (contract, selector).
  - `provenance_absent_fails_closed` — sink reached but no provenance bit set → not material (Risk
    §4 polarity: opposite of the fail-open LOCATE filter).
- **Unit (Phase B), `message_leak` module:**
  - `attacker_authored_target_flagged` — CALL whose target word carries a calldata provenance bit →
    `found` records it; a hardcoded-target CALL does not.
- **Integration (`tests/`):**
  - yDAI preset-only fork: with `--causal-identity`, the `DAI.burn(0x0,0)` objective no longer fires
    (Success Criterion 1).
  - Routing: a real material breach yields a non-empty `campaign.promoted` sourced from the inline
    `found` set (Success Criterion 3).
- **Regression (rule 2):** flag off → objectives + ledger output byte-identical to pre-019 `main`.
