# Feature 019 — Causal Identity Engine (Inline Permission + Message Leak)

**Status:** Specified
**Owner:** TBD
**Last updated:** 2026-07-03
**Held:** LOCAL (builds on 013 provenance + 014 oracle middlewares; inherits the taint-stack no-push policy)

---

## Overview

Two Phase-2b oracles make a **causal claim from non-causal evidence**. `FunctionOracle`
(o_func, Permission Leak) and `ArbitraryCallOracle` (o_arb, Message Leak) run *after* the tx
boundary and pattern-match the final `EVMState` — but the property they assert ("an unauthorized
principal did something dangerous" / "the attacker controlled an external call target") depends on
information that only exists *during* execution and is destroyed by the time the oracle runs.

The result is phantoms. `FunctionOracle` fires on exactly `(caller ∉ allowed) ∧ (¬reverted)`
(`oracles/function.rs`, `oracle()` body) with **no materiality guard**. The live consequence is on
record: the yDAI preset-only fork run reports 4/4 objectives as the same vacuous
**`DAI.burn(0x0, 0)`** — a zero-value burn from a non-allowlisted caller that doesn't revert. There
is no post-hoc guard that fixes this (an `amount>0` band-aid just relocates the phantom to the next
zero-effect administrative call); the verdict genuinely needs an *in-loop* witness that
attacker-tainted calldata reached a **material sink**.

This feature moves both detectors into the `revm` `on_step` loop, following the **two inline
middleware→oracle pairs already shipped**: `middlewares/reentrancy.rs` (interleaving) and
`middlewares/fee_on_transfer_detector.rs` (per-frame delta). It then closes the routing gap those
two templates *left open* — neither ever wires its `found` set back into the economic loop; they
stop at surfacing. 019 routes an inline causality hit (`INJECTION_CONFIRMED`) into
`PromotionCandidate`, turning a passive log into an active Lever for the Signed Secant Solver.

**Weapons this builds on** (`spector-weapons.md`): 013 Injection/Provenance
(`arg_slot_provenance`), 014 Oracle Middlewares (`OracleTracker` proximity), 015 Promote→Locate→
Amplify (LedgerSecant), reentrancy + fee-on-transfer middleware templates. This **replaces** two
post-hoc oracles with inline primitives; it adds no new detection *surface* (same two primitives),
only correct *placement*.

## Why This Matters

The Middleware Audit (memory: `project_middleware_audit`) established the **Information
Availability Law**: an oracle needs an inline middleware iff its verdict depends on state that
exists solely during execution (interleaving, per-frame delta, taint provenance). o_func and o_arb
are the two structural oracles on the wrong side of that line — the only two that assert causality
from a final snapshot plus a `¬reverted` flag.

1. **Permission Leak phantoms are live, not hypothetical.** burn(0) is 4/4 of the yDAI run's
   objectives. Every zero-effect privileged call (pause-when-already-paused, burn(0), approve(0))
   is an identical false positive. Post-hoc cannot distinguish a material breach from a vacuous one
   because the material fact — *did attacker calldata flow to a state-mutating sink* — is gone.
2. **Message Leak is undetectable post-hoc by construction.** Whether the attacker *controlled* a
   CALL's target address is a provenance question about the stack word at CALL time; the final
   state shows the call happened, never who authored the destination. o_arb today infers it from
   `OracleTargetMetadata`/`TrustedCallerMetadata` heuristics — brittle, and blind to proxy routing.
3. **The promotion wire is the fuzzland gap.** ityfuzz's original reentrancy got inline-detect
   right but `push_to_output`-only — the `found` set never reached the campaign economics. Our
   reentrancy/fee pairs inherited that stop-at-the-bark shape. A confirmed inline causality hit
   should *promote a lever*, not just log — that's how a detected primitive becomes an extraction.

## Success Criteria

Worth building iff:

1. **burn(0) dies.** On the yDAI preset-only fork run, the `DAI.burn(0x0,0)` objective no longer
   fires; a Permission Leak is reported only when attacker-tainted calldata reaches a non-zero
   material sink (SSTORE state change or CALL moving > 0 value) inside a privileged selector.
2. **Message Leak fires on real routing.** On a regression contract with an
   attacker-controlled-target external call, the inline Message Leak middleware records the hit via
   `arg_slot_provenance` on the CALL target word — including one behind a proxy hop (Phase B).
3. **The wire exists.** An inline `INJECTION_CONFIRMED` for either primitive produces a
   `PromotionCandidate` tagged as an active Lever (verified: the promoted step appears in
   `campaign.promoted` and the secant locks its offset), not merely a `push_to_output` log.
4. **Zero behavioral change when off.** Both flags off → runs reproduce byte-for-byte vs pre-019
   `main` (Constitution rule 2). The legacy o_func/o_arb remain the default until graduation.
5. **Throughput held.** With the inline hooks on, exec/sec stays within ~5% of the ~860 baseline on
   the yDAI deep-call-tree fork (spatial fast-fail guard, §Perf).

## Out of Scope

- **Identity → Provenance coupling.** 017 graded this *correct within the calldata-mutation threat
  model*: `CALLER`/`ORIGIN`/`CALLVALUE` are intentionally `clean!()` (`cmp_linearity.rs:745`). The
  original 019 draft listed it as a prerequisite — **it is not.** Permission authorization is a
  *set-membership* test (`caller ∈ allowed?`), already answerable from the call frame; it does not
  require the caller identity to be *tainted*. The materiality guard rides on the **existing
  calldata provenance bus**, not a new identity-taint bus. Keeping this out of scope is what
  **unblocks Phase A**. Deferred, deliberately — not a defect.
- **Deleting legacy o_func / o_arb.** They stay as the default detectors behind their existing
  wiring until the inline replacements graduate (flag-graduation model, memory:
  `feedback-flag-graduation-model`). 019 ships them additively behind a new flag first.
- **New oracle families.** This relocates two existing primitives; it adds no detection surface.

## Investigation Checkpoints

### Checkpoint 19.1 — o_func fires without materiality  ✓ RESOLVED
**Files:** `src/evm/oracles/function.rs`
**Question:** On what exact condition does FunctionOracle emit?
**Evidence:** `oracle()` returns a bug when `!result.reverted`, `data.len() ≥ 4`, and
`caller ∉ allowed_static ∪ allowed_dynamic` — **no check that the call changed any state or moved
value.** A `burn(0x0, 0)` from a non-allowlisted caller that does not revert satisfies all three.
**Confirmed: post-hoc, non-material. This is the burn(0) phantom's root.**

### Checkpoint 19.2 — o_arb infers target control from final-state metadata  ✓ RESOLVED
**Files:** `src/evm/oracles/arb_call.rs`
**Question:** How does ArbitraryCallOracle decide the attacker controlled the CALL target?
**Evidence:** `oracle()` reads `OracleTargetMetadata` + `TrustedCallerMetadata` and an
`ArbitraryCallMetadata.known_calls` map — a final-state heuristic, no read of `arg_slot_provenance`
on the destination stack word. **Confirmed: no in-loop provenance witness of target control.**

### Checkpoint 19.3 — inline templates + the `found` carrier  ✓ RESOLVED
**Files:** `src/evm/middlewares/reentrancy.rs`, `src/evm/middlewares/fee_on_transfer_detector.rs`,
`src/evm/host.rs`
**Question:** What is the shipped inline-mw shape, and where does a hit get parked?
**Evidence:** `reentrancy.rs` `on_step` hooks SLOAD/SSTORE, `depth = post_execution.len()`, writes
`host.evmstate.reentrancy_metadata.found`. `fee_on_transfer_detector.rs` brackets CALL frames and
pushes `(token, recipient, claimed, actual)` to a per-tx metadata vec. `host.arg_slot_provenance:
HashMap<(EVMAddress, EVMU256), u64>` (`host.rs:456`) is the provenance carrier. **Two working
templates; the `found`-style metadata carrier is the model for `permission_leak`/`message_leak`.**

### Checkpoint 19.4 — cross-contract provenance is same-contract only  ⚠ BLOCKS PHASE B
**Files:** `src/evm/mutator.rs`, `src/evm/feedbacks.rs`
**Question:** Can provenance trace calldata through a proxy hop today?
**Evidence:** `mutator.rs:757` filters `per_slot` by `*addr == step.contract` — **same-contract
only.** `ArgStorageProvenance` (`feedbacks.rs:85`) keys `(EVMAddress, slot)` but the consuming
filter drops cross-address bits. **Message Leak through a proxy (Phase B) requires lifting this to
cross-contract mapping. Permission Leak (Phase A) does NOT — its sink is in the same privileged
contract as the tainted calldata.**

### Checkpoint 19.5 — the promotion wire terminus  ✓ RESOLVED
**Files:** `src/evm/feedbacks.rs`, `src/evm/planner/campaign_planner.rs`
**Question:** Is there any path from an inline `found` set to `PromotionCandidate`?
**Evidence:** `record_aposteriori_candidate` (`feedbacks.rs:344`) builds candidates from **ledger
delta**, gated on `campaign.aposteriori && promoted.is_empty()` + inflow thresholds — it reads no
middleware `found` set. reentrancy/fee oracles only `push_to_output`. **No edge connects inline
causality → promotion. This is the wire 019-C builds.**

## Risks

- **Throughput on deep call trees.** New `on_step` hooks run on every opcode of a ~860 exec/sec
  deep fork. Mitigation (mandatory): an O(1) spatial fast-fail — cheap opcode/register check first;
  only touch `arg_slot_provenance` when the opcode is a *strict sink* (CALL-with-value, or SSTORE
  in a privileged-selector context). See Plan §Performance.
- **Materiality definition drift.** "Material sink" must be precise or it re-introduces phantoms.
  v1 definition: SSTORE that changes a slot value (pre ≠ post) OR a CALL with `value > 0`, reached
  while the active selector is in the privileged set AND at least one contributing stack input
  carries a non-zero provenance bit. Pure reads / zero-value / no-op writes are not material.
- **Double-reporting during additive phase.** While legacy o_func/o_arb still run, a real breach
  could fire both. Mitigation: the new flag, when on, suppresses the legacy oracle for the same
  (contract, selector) so the two never co-emit (bug-idx collision avoided).
- **Provenance fail-open.** Existing LOCATE filter fails *open* (None → don't skip). The materiality
  guard must fail *closed* on absent provenance (None → not material) or burn(0) survives. Opposite
  polarity from the mutator filter — call it out in review.

## Open Questions

- Message Leak scope for v1: gate strictly on `arg_slot_provenance` proving the target word is
  attacker-authored, or also flag targets constructed via same-tx SSTORE→SLOAD round-trips? (Lean:
  direct calldata→target for v1; round-trip is a Phase B follow-on with cross-contract provenance.)
- Should Phase A graduate (fold into `--bounty`, retire legacy o_func) before Phase B lands, or hold
  both behind one flag until the pair is complete? (Lean: graduate Phase A independently — it fixes
  a live phantom on the current run; don't couple its release to the blocked half.)
- Materiality on `DELEGATECALL`: a delegatecall mutates the *caller's* storage — does the SSTORE
  materiality check attribute correctly across the delegate frame? Needs one targeted test.
