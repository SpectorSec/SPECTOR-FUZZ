# System Inventory & Thesis-to-Code Alignment Matrix

**Method:** static, code-verified only (grep/read against HEAD `30efe6f`, no test execution). Every
row below is backed by a file:line citation, not a spec claim taken on faith. This document exists
to answer one question across the whole codebase, not per-feature: **for a given oracle/leak class,
does the closed loop (Oracle → Objective → Intent → Primitive → Campaign → Scheduler → New
Observation) actually complete, or does it silently dead-end?**

Consolidates three prior review passes (self + two independent Codex passes) into one artifact so
future feature work has a single source of ground truth instead of re-deriving it per-PR.

Last verified: `30efe6f` (2026-07-10). Prior baseline: `c53eb7c`. Re-inventory by diffing the
tables below against current oracle files + `leak_class.rs` + `campaign_planner.rs`.

---

## 1. Oracle capability map

20 oracle files exist in `src/evm/oracles/`. `OracleType` (`src/evm/mod.rs:526-545`) has 18
variants. `LeakClass::oracles()` (`src/evm/leak_class.rs:61-71`) is the SSOT binding every
oracle to a primitive.

| Oracle file | OracleType variant | LeakClass home | Emits `PromotionCandidate`? | Loop status |
|---|---|---|---|---|
| `erc20.rs` | ERC20 | Value | No | Detect-only; feeds ledger indirectly |
| `fee_on_transfer.rs` | FeeOnTransfer | Value | No | Detect-only |
| `rebasing.rs` | Rebasing | Value | No | Detect-only |
| `erc4626.rs` | ERC4626 | Value | No | Detect-only; in `-d all` (`mod.rs`), ABI auto-activation now consistent (`3b95709`) |
| `function.rs` | Function | Permission | **Yes** (`function.rs:265`) | Fully-wired producer |
| `snapshot_delta.rs` | Ownership | Ownership | **Yes** (`snapshot_delta.rs`, `c99cbb2`) | Producer added; `structural_pin` Ownership branch now live |
| `invariant.rs` | Invariant | Invariant | **Yes** (`invariant.rs`, `c99cbb2`) | Producer added; routes to `value_lever_pin` (`matches!(kind, Value\|Invariant)`) |
| `state_comp.rs` | StateComparison | Invariant | **Yes** (`state_comp.rs`, `c99cbb2`) | Producer added |
| `echidna.rs` | Echidna | Invariant | **Yes** (`echidna.rs`, `c99cbb2`) | Producer added; uses `PromotionCandidates` (plural, PR #1) |
| `reentrancy.rs` (oracle) | Reentrancy | ControlFlow | No | Producer gap — no feature currently scoped to fix it |
| `arb_call.rs` | ArbitraryCall | Message | No | Deferred by design (019-B gate) |
| `v2_pair.rs` | Pair | Value (`c542a38`) | No | Detect-only; orphan resolved — bound to Value (k-constant imbalance drain) |
| `arb_transfer.rs` | MathCalculate | Value (`c542a38`) | No | Detect-only; orphan resolved — bound to Value (arbitrary ERC20 transfer to attacker) |
| `typed_bug.rs` | TypedBug | Invariant (`c542a38`) | No | Detect-only; orphan resolved — bound to Invariant (typed invariant assertion) |
| `selfdestruct.rs` | SelfDestruct | Ownership (`c542a38`) | No | Detect-only; orphan resolved — bound to Ownership; naming collision in `from_str` now consistent with `oracles()` |
| `approval.rs` | Approval | Permission (`c542a38`) | No | Detect-only; orphan resolved — bound to Permission (unauthorized allowance grant) |
| `crosschain.rs` | CrossChain | Message (`c542a38`) | No | Detect-only; orphan resolved — bound to Message (bridge message origin forgery) |
| `nft.rs` | NFT | Ownership (`c542a38`) | No | Detect-only; NFTOwnershipOracle bound into Ownership (028-orphan bind) |
| `freshness.rs` | **not in `OracleType`** | **none** | No | **Fully outside the taxonomy** — auto-activated by ABI fingerprint (`evm_fuzzer.rs:622-628`), invisible to `-d`, invisible to `LeakClass`. Known gap; intentional (§5.4). |
| `temporal_skim.rs` | **not in `OracleType`** | **none** | No | **Fully outside the taxonomy** — gated only by `--temporal-skimming` (`evm_fuzzer.rs:592-597`). Known gap; intentional (§5.4). |

**Headline number:** of 20 oracle files, **15 never touch `PromotionCandidate`** — they detect,
call `EVMBugResult::push_to_output()`, and stop. Five oracle files now emit: `function.rs`
(Permission), `snapshot_delta.rs` (Ownership), `invariant.rs`/`state_comp.rs`/`echidna.rs`
(Invariant). Value production is in `feedbacks.rs` (ledger, not an oracle file). ControlFlow and
Message gaps remain open.

**Orphan count:** 0 — all 6 formerly-orphaned `OracleType` variants now have `LeakClass` mappings
(`c542a38`). The SSOT covers all 18 registered `OracleType` variants. The two out-of-band oracles
(`freshness`, `temporal_skim`) remain intentionally outside the taxonomy (§5.4).

---

## 2. LeakClass lifecycle map

For each of the 6 declared primitives, tracing producer → objective encoding → planner routing →
secant amplification → scheduler feedback:

| LeakClass | Producer exists? | Objective encoding | Planner routing | Secant amplification | Scheduler feedback |
|---|---|---|---|---|---|
| **Value** | Yes — `record_aposteriori_candidate` (`feedbacks.rs:465-485`), gated by `--reflexive-lever`. Independent of whether ERC20/FeeOnTransfer/Rebasing/ERC4626 oracles are enabled. | `best_inflow: u128` (unsigned magnitude) | `value_lever_pin`, unconditional (`mutator.rs`, `campaign_planner.rs`) | `secant_promotable(Value, _) = true` always | Generic `promote_boost` on `(contract,selector)` match, kind-agnostic (`scheduler.rs:515-533`) |
| **Permission** | Yes — `function.rs:265` | `best_inflow: u128` (presence flag; 0 for a call that moves no value — magnitude semantically undefined here, field is repurposed as "objective to maximize") | `structural_pin`, gated on `matches!(kind, Permission\|Ownership)` | `secant_promotable(Permission, n_args) = n_args >= 1` | Generic `promote_boost`, kind-agnostic — fires today (confirmed `scheduler.rs:515-533`); not objective-magnitude-aware |
| **Ownership** | **Yes** — `snapshot_delta.rs` emits `PromotionCandidate{kind: Ownership}` on slot relocations (`c99cbb2`). | `best_inflow: u128` = relocation count | `structural_pin` filter `matches!(kind, Permission\|Ownership)` — now live (was dead code before producer) | `secant_promotable(Ownership, _) = false` (explicit, tested) — correctly excluded; structural-prime role only | Generic `promote_boost` fires on `cand.set` match |
| **Invariant** | **Yes** — `invariant.rs`/`state_comp.rs`/`echidna.rs` emit `PromotionCandidate{kind: Invariant}` on violation (`c99cbb2`). `oracle_should_skip!` gate surrounds only `push_to_output()`, not the emit. | `best_inflow: u128` = `|violation_delta|` (unsigned deviation magnitude) | `value_lever_pin` filter extended: `matches!(c.kind, Value\|Invariant)` — routing correct (`c99cbb2`) | `secant_promotable(Invariant, _) = true` (updated `c99cbb2`, tested) | Generic `promote_boost` fires on `cand.set` match |
| **ControlFlow** | **No.** `reentrancy.rs` (oracle) reports and stops. Not scoped by any existing feature. | N/A | Would land in `structural_pin` IF filter extended to include `ControlFlow` | Not in `secant_promotable` match — falls to `_ => false` | N/A |
| **Message** | **No** — by design, gated on 019-B (cross-contract provenance, not built). `LeakClass::Message.middleware()` correctly returns `None`. | N/A | N/A | N/A | N/A |

**The one line that matters:** Value is fully closed (producer + routing + amplification + scheduler
feedback). Permission has all four (presence-based). Ownership has producer + routing + presence
scheduler; secant correctly excluded (structural-prime only). Invariant now has producer + routing +
amplification + presence scheduler — near-complete loop; objective-magnitude weighting not yet
built. ControlFlow and Message remain open (ControlFlow: no feature scoped; Message: 019-B deferred).

---

## 3. Action-space inventory (the primitives, decoupled from who chooses them)

Cheat-code surface actually implemented in `src/evm/middlewares/cheatcode/mod.rs` (grepped
`VmCalls::` match arms): `prank_0/1`, `startPrank_0/1`, `stopPrank`, `warp`, `roll`, `deal`, `store`,
`load`, `etch`, `computeCreateAddress`, `computeCreate2Address_0/1`, `getNonce_0`, `chainId`,
`coinbase`, `difficulty`, `prevrandao_0/1`, `fee`, `txGasPrice`, `label`, `getLabel`,
`readCallers`, `record`, `recordLogs`, `getRecordedLogs`, `accesses`, `createSelectFork_0/1/2`,
`expectRevert_0/1/2`, `expectEmit_0/1/2/3`, `expectCall_*`, `expectCallMinGas_*`, plus the full
`assertEq`/`assertGt`/`assertApprox*` family (Foundry-test-compat, not exploit primitives). This
confirms the README's "full cheat-code suite" claim — the action space genuinely is that broad.

Campaign-level primitives (`campaign_planner.rs`): `Borrow` step (flashloan), `Prime`/`Exploit` ABI
steps (`build_abi_step`), `Structural` step (`build_structural_step`), `warps: Vec<(usize, u64)>`
(block advance before a step), `promoted: Vec<usize>` (secant-tunable step indices),
`divergence_value` pin (pre-seeded `txn_value`).

**None of this is in dispute** — the action space is real and matches 032's characterization. The
gap is entirely on the controller side (§2), not the primitive side.

---

## 4. Planner / campaign-shape inventory — assembly order (as-built)

`plan_campaign_sampled` (`campaign_planner.rs:408-545`) assembles steps in this order:

1. Borrow (`:439-442`)
2. Prime ABI step (`pick_prime_and_exploit`, `:446-449`) — Exploit held for step 7
3. **Structural pin** (`structural_pin`, `:456-465`) — Permission/Ownership Prime; skipped if already present or selector not in cache; NOT added to `promoted`
4. Dynamic Value/Invariant lever, if `value_lever_pin` set (`:472-482`) — added to `promoted`
5. Static reflexive cold-start fallback, if no dynamic fire AND `effective_reflexive` (`:489-494`) — added to `promoted`
6. `aposteriori` arm flag set (`:501`, no step pushed)
7. Divergence-value pin applied to first non-Borrow step (`:507-510`)
8. Exploit step pushed (`:513-515`)
9. Temporal warp computed and inserted before the Exploit index (`:526-538`)

**Assembly-order defect FIXED** (`3b95709`): the structural_pin block (step 3) was previously
inserted after the lever blocks — violating BPLE (Borrow → Prime → Lever → Exploit) when
`--reflexive-lever` was set and a live Permission/Ownership candidate existed. Confirmed fixed:
structural_pin at `:456-465` precedes dynamic lever at `:472-482` and cold-start fallback at
`:489-494`.

Temporal warp activation (step 9) has two independent triggers: `temporal_skimming` (human flag)
**or** `ts_located` (`dimension_warp` flag AND `TIMESTAMP_DIM_LOCATED` static, set by taint
analysis in Feature 017 Wire B, `feedbacks.rs:441-445`). The second path is oracle/taint-driven.
THESIS.md updated to reflect "partially oracle-driven, same tier as the Value dynamic/static split."

---

## 5. Silent-failure audit

### 5.1 Naming collision in `LeakClass::from_str` — RESOLVED
`leak_class.rs:110`: `"selfdestruct" => LeakClass::Ownership`. `OracleType::SelfDestruct` is now
bound to `LeakClass::Ownership.oracles()` (`c542a38`) — `[Ownership, NFT, SelfDestruct]`. The two
methods are now consistent: `from_str` and `oracles()` agree that SelfDestruct belongs to Ownership.

### 5.2 `best_inflow: u128` semantics — RESOLVED
Decision (`c99cbb2`): keep `u128` unsigned magnitude across all kinds. Invariant stores
`|violation_delta|` (absolute deviation from invariant boundary — unsigned suffices for secant
maximization). Permission stores `0` (presence flag; semantically distinct from value magnitude but
no type widening needed — the field's role is "objective to maximize" not "inflow specifically").
`PromotionCandidates` (plural, PR #1) provides per-kind slots so kinds don't overwrite each other;
`best_inflow` retains its per-slot meaning. No serialization churn.

### 5.3 ERC4626 bypasses the `-d` flag system — RESOLVED
`3b95709`: `OracleType::ERC4626` added to the hardcoded `"all"` list in `from_strs`
(`src/evm/mod.rs`). ABI auto-activation (topology-fingerprint gate) remains but is now consistent
with what `-d all` selects. Test assertion added:
`assert!(OracleType::from_strs("all").contains(&OracleType::ERC4626))`.

### 5.4 Two oracles live entirely outside `OracleType`/`LeakClass` — KNOWN, INTENTIONAL
`freshness.rs` and `temporal_skim.rs` are real detectors with no `OracleType` variant and no
`LeakClass`. They predate and sit beside 020 by design. Documented in `leak_class.rs` module
comment (`c542a38`) so they are discoverable. Not a regression; not a fix target unless the
taxonomy is explicitly extended to cover out-of-band detectors.

### 5.5 Scheduler feedback is less absent than the specs claimed — CORRECTED
`scheduler.rs:515-533`'s `promote_boost` is gated only on `cand.set` + `(contract, selector)` match
— no `kind` filter. Permission (and now Ownership/Invariant) promotions get the identical
corpus-power boost Value gets. The real gap is narrower: "kind-agnostic but not
objective-magnitude-aware" — no weighting by how much privilege depth or violation distance
improved. THESIS.md updated to reflect this accurately (`c542a38`).

---

## 6. Thesis-to-code alignment matrix

| Thesis claim | Code reality | Status |
|---|---|---|
| "Value objective is the only fully-realized loop end-to-end" | True at original audit. Permission was always near-complete. Invariant now has full routing + amplification + presence feedback. | **Updated — see §2** |
| "Ownership: structural_pin expanded in 031, no scheduler feedback" | Producer added (`c99cbb2`); `structural_pin` Ownership branch is live. Generic scheduler feedback fires. Secant amplification correctly excluded. | **Fixed — `c99cbb2`** |
| "Temporal: warp injected, no oracle-driven activation" | `ts_located` path (`TIMESTAMP_DIM_LOCATED` from Feature 017 Wire B) is oracle/taint-driven. THESIS.md updated. | **Corrected — `c542a38`** |
| "031's routing handles Invariant automatically via `value_lever_pin`" (033 original claim) | Was false — filter was `== Value` strict equality. Fixed: `matches!(c.kind, Value\|Invariant)` in `mutator.rs`. `secant_promotable` updated to `true` for Invariant. | **Fixed — `c99cbb2`** |
| "The secant optimizes whatever objective the oracle defines" (033) | `best_inflow: u128` resolved as unsigned magnitude across all kinds; per-kind slots via `PromotionCandidates`; Invariant stores `\|violation_delta\|`. Type-level blocker cleared. | **Fixed — `c99cbb2` + PR #1** |
| "`-d all` continues to select the full registry" (020 risk mitigation) | Fixed: `ERC4626` added to `all` literal list (`3b95709`). | **Fixed — `3b95709`** |
| "One source of truth... no second selection path remains" (020 success criterion) | All 6 formerly-orphaned `OracleType` variants now have `LeakClass` mappings (`c542a38`). SSOT covers all 18 registered types. Two out-of-band oracles intentionally documented outside. | **Fixed for 18 registered; 2 intentional gaps documented** |
| "Cheat-code suite is the action space, fully implemented" (032) | Confirmed — full `VmCalls` inventory matches the README claim. | **True** |
| "BPLE: Permission/Ownership → Prime, must precede the Lever" (031) | Assembly-order defect fixed (`3b95709`): structural_pin now precedes lever blocks in `plan_campaign_sampled`. | **Fixed — `3b95709`** |

---

## 7. Remediation — COMPLETE (2026-07-10)

All 7 items from the original remediation order are closed as of HEAD `30efe6f`.

| # | Item | Commit | Status |
|---|---|---|---|
| 1 | Assembly-order bug (BPLE structural_pin before lever) | `3b95709` | ✅ |
| 2 | `-d all` / ERC4626 activation split | `3b95709` | ✅ |
| 3 | Ownership + Invariant producers | `c99cbb2` | ✅ |
| 4 | Extend routing + `secant_promotable` for Invariant | `c99cbb2` | ✅ |
| 5 | `best_inflow` type/semantics decision | `c99cbb2` + PR #1 (`1d9e8dd`) | ✅ |
| 6 | Register 6 orphaned `OracleType` variants into `LeakClass` | `c542a38` | ✅ |
| 7 | Doc pass (THESIS.md + alignment matrix) | `c542a38` + `30efe6f` | ✅ |

---

## 8. Feature 029 (Divergence Optimization) — a second, parallel channel, independently audited

Not part of the original LeakClass/`PromotionCandidate` remediation — this is a separate objective
channel (`publish_divergence`/`read_divergence`, `feedbacks.rs:80-87`) that predates 033/034/035
and was never inventoried against them. Flagged for audit because `045b32f` ("docs(v5.3): draw 029
divergence optimizer BUILT") is exactly the same shape of overclaim the rest of this document
exists to catch, and it sits in the same files (`feedbacks.rs`, `mutator.rs`, `campaign_planner.rs`)
our recent commits touched.

**Verified split: the secant half is live, the sequence-discovery half is dead.**

| Component | Built? | Wired into the running loop? |
|---|---|---|
| `publish_divergence`/`read_divergence` thread-local channel | Yes | Yes — `erc4626.rs:154` publishes |
| `apply_divergence_secant` (Phase 1 magnitude peak-finder) | Yes | Yes — called at `mutator.rs:1427`, gated by `DivergenceSecantState.pin_gate` |
| `divergence_value` planner pre-load | Yes | Yes — read at `campaign_planner.rs:507`, composes cleanly alongside `structural_pin`/`value_lever_pin` as an independent `Option` param |
| `DivergenceFeedback` (infant-scheduler vote on divergence-maximizing **sequences**) | Yes (`feedbacks.rs:859-950`) | **No.** Confirmed by grep — referenced nowhere outside its own definition. `evm_fuzzer.rs:472-497` builds the infant-scheduler feedback as `EagerOrFeedback::new(cmp_feedback, balance_feedback)` — a fixed two-slot combinator with no path to include a third feedback. `DivergenceFeedback::is_interesting` (and its `scheduler.vote(...)`) has never executed. |
| `CompoundSequenceCanary` (compound divergence+inflow telemetry) | Yes (`feedbacks.rs:538-571`) | **No.** `029/plan.md:24` states it "feeds into 026 energy boosts" — grepped `scheduler.rs` and the whole tree: nothing ever reads `CompoundSequenceCanary`. It's write-only metadata, same pattern as every dead producer this document already tracks. |

**Relationship to 033/034/035 (checked, not conflicting):** none of the five recent producers
(`function.rs`, `snapshot_delta.rs`, `invariant.rs`, `state_comp.rs`, `echidna.rs`, `reentrancy.rs`)
call `publish_divergence` — grepped, zero hits. This is correct, not a gap in that work: 029's own
spec calls generic (non-ERC4626) divergence publishing "Tier 2" and explicitly scopes it as not yet
built. The two channels are independent and compose without collision.

**Completion gap — specced, then found BLOCKED on a deeper order-of-operations defect
(2026-07-10, second pass):** `.speckit/features/037-wire-divergence-feedback/specify.md`. The
first draft of 037 proposed nesting `DivergenceFeedback` into `infant_feedback`'s existing
`EagerOrFeedback` combinator. Tracing the actual per-iteration call order in
`fuzzer.rs::evaluate_input_events` shows this is wrong, not just incomplete:

- `self.infant_feedback.is_interesting(...)` runs at `fuzzer.rs:423-425`.
- `self.objective.is_interesting(...)` — bound to `OracleFeedback`, confirmed the ONLY place any
  oracle (including `ERC4626Oracle`, the only current `publish_divergence` caller) actually
  executes (`feedback.rs:219-220`'s own doc comment) — runs at `fuzzer.rs:427-429`, i.e. AFTER
  `infant_feedback`.
- `DIVERGENCE_OBJECTIVE` (`feedbacks.rs:58`) is a thread-local `Cell` never reset between
  iterations. So `DivergenceFeedback`, if placed in `infant_feedback`, would read the PREVIOUS
  iteration's published value every time — a silent one-iteration lag, not a crash, not a test
  failure, just permanently wrong data feeding the infant-scheduler vote.
- Moving it to `infant_result_feedback` (which does run after the oracle pass) doesn't fix the
  underlying problem either — whether an infant state is added at all is decided at
  `fuzzer.rs:446` using ONLY `infant_feedback`'s verdict; a later-running feedback can add extra
  votes to a state something else already added, but can never be the thing that triggers adding
  it — which is exactly what `DivergenceFeedback`'s own doc comment says it must do.
- Confirmed `CmpFeedback`/`TokenBalanceFeedback` (today's `infant_feedback` contents) don't have
  this problem: `TokenBalanceFeedback::is_interesting` (`feedbacks.rs:689`) reads
  `state.get_execution_result()` directly, populated synchronously by `run_target()` — no
  dependency on the later oracle pass. `DivergenceFeedback` is architecturally different (an
  oracle-produced side-channel, not an execution-result-direct read), and the original spec
  didn't check that distinction before proposing the same combinator slot.

037 was corrected in place to document this, then **built and independently verified**
(`f338652`): `fuzzer.rs` reordered so `objective`/`OracleFeedback` runs before the infant gate,
`clear_divergence()` added as a stale-value guard at the top of every `run_target` call,
`DivergenceFeedback` wired into the infant `EagerOrFeedback` chain, and `CompoundSequenceCanary`
given a scheduler consumer via a testcase-local snapshot at `on_add` (avoiding the same
cross-iteration-bleed pattern, not just avoiding it for `DivergenceFeedback`). Compiled clean,
199/199 tests passing, both new regression tests (`clear_divergence_drops_previous_execution_value`,
`compound_boost_decays_from_full_to_neutral`) confirmed by name. The reorder also retroactively
fixed a second, previously undiscovered instance of the same bug:
`TokenBalanceFeedback::record_aposteriori_candidate` (`feedbacks.rs:538`, which writes
`CompoundSequenceCanary`) also reads `read_divergence()` and was subject to the identical stale-read
problem since Feature 029 was written — fixed for free by the same reorder. This is exactly the
class of finding this document's method (trace actual data flow, not just reachability) is supposed
to catch — reachability alone ("is it called") is necessary but not sufficient; timing relative to
the data it depends on is a separate, equally load-bearing question.

---

## 9. Execution-Ordering Audit (PR #2) — a second audit *dimension*, not just more findings

Prompted directly by the §8 finding above: reachability checks (does X get called) are necessary
but not sufficient — a component can be perfectly reachable and still read the wrong iteration's
data. PR #2 (`.speckit/research/execution-ordering-audit-2026-07-10.md`, merged `17ea4e7`)
independently audited the campaign-execution path (`executor.rs::run_target`, not
`campaign_executor.rs`, which is a stub) for exactly this class of bug. All four findings were
independently re-verified against source before speccing — one (EO-03) was found to be narrower
than originally claimed once traced further.

| Finding | Verified? | Spec |
|---|---|---|
| EO-01 — stale `CampaignIntermediateStates`/`CampaignWarpStates`/`CampaignInflowBoundaries` bleed into non-campaign executions (non-campaign path never clears them; `OracleFeedback` reads them unconditionally, `feedback.rs:250-258`) | **Confirmed**, exact lines | `.speckit/features/038-clear-campaign-scoped-metadata/specify.md` |
| EO-02 — `intermediate_states.push(current_state)` (`executor.rs:186`) runs before `current_state` is reassigned to the post-step result (`:190-194`) — records each step's *input* state, not its *output* | **Confirmed**, exact lines | `.speckit/features/039-post-step-intermediate-states/specify.md` |
| EO-03 — controlled temporal probes (`executor.rs:218-262`) run through the same VM/host as the real exploit step before it executes | **Narrowed, not confirmed at the claimed scope.** Traced whether `execute()` mutates a persistent host or reloads an explicit staged state per call (`vm.rs:1463` — reloads per call), whether `reentrancy_metadata` is part of that reloaded state (confirmed via `reentrancy.rs`), whether coverage is cleared per-call (`vm.rs:1357-1358`'s `clear_branch_status()`), and whether `DIVERGENCE_OBJECTIVE`/`TIMESTAMP_DIM_LOCATED` are reachable from probes at all (they're only written in the post-`run_target` feedback pass — probes execute *inside* `run_target`, before it returns, and structurally cannot reach that code). All four specific channels the original finding worried about check out safe. | `.speckit/features/040-isolate-temporal-probes/specify.md` — scoped to a targeted middleware audit task + regression canary, not the broader "isolate probes into a cloned VM" rewrite originally proposed |
| EO-04 — `CampaignSequence.linkages`/`StepLinkage` (`input.rs:39-54`) declared, zero consumers anywhere in the executor | **Confirmed** — grepped the whole tree; also confirmed `campaign_planner.rs:542` always emits `linkages: Vec::new()` today, so the fix is purely additive with zero current behavioral impact | `.speckit/features/041-apply-step-linkages/specify.md` |

**The methodological point worth keeping**: EO-03 is the clearest illustration in this whole
document of why every finding needs independent re-verification rather than trusting a well-written
audit at face value — even one that's otherwise batting 3-for-4 on the same page. A plausible-sounding
mechanism ("probes run through the same stack, so state could leak") doesn't automatically survive
contact with how the specific execution model actually works (per-call state reload +
post-return-only side-channel writes). Confirm, don't extrapolate from plausibility.

---

**Remaining open items — now specced (2026-07-10 re-inventory pass):**
- ControlFlow producer — **specced, ready to build**: `.speckit/features/034-controlflow-promotion-producer/specify.md`. `reentrancy.rs`'s `reentrancy_metadata.found` already has exactly the (contract, magnitude) shape the existing producers use; routes to `structural_pin` per 031's own suggestion.
- Objective-magnitude-aware scheduler feedback — **specced, ready to build**: `.speckit/features/035-objective-magnitude-scheduler/specify.md`. Log-scaled, bounded, zero-at-magnitude-0 multiplier on top of the existing `promote_boost`; strict enhancement, never a regression.
- `freshness.rs` / `temporal_skim.rs` formal taxonomy enrollment — **specced, low priority**: `.speckit/features/036-out-of-band-oracle-enrollment/specify.md`. Taxonomy-only (OracleType + LeakClass binding), no activation-logic change — mirrors the ERC4626 precedent.
- Message producer — **still genuinely blocked, not specced.** Verified directly: the commit-message hint that Feature 028 ("cross-contract provenance") unblocked `ArbitraryCall` was checked and is not accurate — 028 is the LOCATE/secant's storage-provenance consumption (a different layer), not the Message-detection gate. The actual prerequisite is **Feature 019 Phase B** (lifting `arg_slot_provenance`'s same-contract filter for the CALL-target word specifically, `019-causal-identity-engine/specify.md:67-69,124,155-158`), which 019's own spec still describes as not built. Do not spec Message closure until 019-B lands.
