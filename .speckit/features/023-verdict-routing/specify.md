# Feature 023 — Verdict Routing (Phase-Tagged Post-Hoc → Kind-Aware Carry)

**Status:** Investigating (4/5 checkpoints resolved 2026-07-07 by live source-trace)
**Owner:** TBD
**Last updated:** 2026-07-07
**Held:** LOCAL
**Origin:** capstone finding — see memory `post-hoc-routing-capstone`.

## Overview
A post-hoc verdict should be **routed by its KIND to a position in the Borrow → Prime → Lever → Exploit chain**, using the shared address `(product, vuln, phase)` that already binds the archetype (shape) and divergence (kind-per-slot) priors:

- **Value verdict** (ledger delta) → its step becomes a **Lever** — amplify the magnitude. *(exists: reflexive lever, but kind-blind.)*
- **Structural verdict** (authority/permission reached a privileged fn — FunctionAuth) → its step becomes a locked **Prime** — no magnitude; the move is *required and preserved* so the sequence keeps reaching it. *(does not exist.)*

The keystone: the verdict must carry the **phase/step** where it fired. Today it carries `bug_idx` + contract only, so nothing can place it. Without the phase tag the merge is random; with it, kind decides Lever-vs-Prime and the coordinate decides where.

## Weapons this builds on (`spector-weapons.md`)
015 Promote→Locate→Amplify (LedgerSecant) · 019 Causal Identity (FunctionAuth inline producer) · 020 LeakClass SSOT (the `kind`) · 022 JIT causal-path gate (taint marries post-hoc: causal-real + material) · `CampaignInflowBoundaries` step-offset attribution (feedbacks.rs). Subsumes/completes pending **019-C** ("Permission producer + kind-aware mutator amplification").

## Why This Matters
Structural-bound exploits — staking-reward (order/identity/re-entry), ERC4626/yDAI `earn()` — can only be **reported** today, never **planned**. The value path half-works (candidate→mutator, kind-blind); the structural path is fully dead-ended at `bug_idx → report`. This is the missing spine under the whole 2026-07-07 session (naming, worker-filing, reflexive-loop all converge here). The taint→post-hoc reality makes a routed verdict trustworthy (causal-real via taint, material via the outcome); this feature gives that trustworthy verdict somewhere to go.

## Success Criteria
1. Every registered verdict carries a **phase/step** coordinate (derived from `CampaignInflowBoundaries`).
2. Routing is **kind-aware**: value→Lever (amplify, existing), structural→Prime (lock, new) — read from `PromotionCandidate.kind`, which is currently write-only.
3. A structural verdict produces a **structural candidate** that the mutator **locks** its Prime step by phase (mirrors the value candidate's amplify-pin at `mutator.rs:667`).
4. The merge is **deterministic**: a verdict lands at the step matching its `(contract, selector, phase)` — not random.
5. **Regression:** with no structural verdict, the value/reflexive-lever path is byte-identical.

## Out of Scope
- Wiring `archetype_catalog.json` + `divergence_diagnostic.json` INTO the planner — the a-priori "sockets" (separate PROPOSED edges; integration-1/2 diagrams). 023 builds the **plug** (a phase-tagged, kind-routed verdict); full archetype-slot placement is enhanced later by those. The mutator-carry lock-Prime behavior does NOT require them.
- The value-forward `Promote → Scheduler` energy edge (separate: memory `reflexive-loop-scheduler-gap`).
- Any change to oracle detection logic or taint.

## Investigation Checkpoints
### 23.1 — Planner is a-priori only ✓ RESOLVED
**Files:** `campaign_planner.rs:284`. **Q:** can any post-hoc signal enter the planner? **Evidence:** `plan_campaign_sampled(cache, topology_report, temporal_skimming, reflexive_lever, dimension_warp, rand)` — body reads NO state/metadata/kind. No intake. → forward-carry must ride the **mutator** (like value), not the planner.

### 23.2 — `kind` is write-only ✓ RESOLVED
**Files:** `leak_class.rs:10` (only ref, a doc comment), `feedbacks.rs` (writer, always `Value` on a-posteriori path). **Q:** is `PromotionCandidate.kind` ever read to route? **Evidence:** never read. The classifier is dead data. → routing must start by *reading kind*.

### 23.3 — the sole forward-carry is kind-blind ✓ RESOLVED
**Files:** `mutator.rs:667`. **Q:** does candidate→mutator respect kind? **Evidence:** matches `(contract, selector)`, ignores `.kind`; action is always amplify. → add a kind branch: `Value`⇒amplify, structural⇒lock.

### 23.4 — verdict lacks a phase tag; the infra to compute it EXISTS ✓ RESOLVED (keystone)
**Files:** `feedbacks.rs:340,367-383` (`CampaignInflowBoundaries`, per-step offsets, `offsets.len()==steps.len()+1`), `oracle.rs:157` (`BugMetadata` = `known_bugs`/`current_bugs`/`corpus_idx_to_bug` — NO phase). **Q:** is the step index available at bug-registration, or is it plumbing? **Evidence:** the value/inflow path already derives `(step_index, inflow)` from boundary offsets (`feedbacks.rs:482`). The *bug* path drops it. → keystone = attribute the verdict to a step via the SAME boundary offsets + add a phase field to the verdict record. Not new infra; an extension.

### 23.5 — the shared coordinate ✓ PARTIAL (confirm in plan)
Archetype keyed `(product, vuln, phase_sig)`; divergence keyed `(product, vuln)`; verdict → `(contract, selector, phase, kind)`. Shared = `(product, vuln, phase)`. **Open:** confirm the verdict's `phase` (step index) maps to the archetype's `phase_sig` slot when the archetype socket lands (out of scope here, but the tag must be phase_sig-compatible).

## Open question for sign-off (→ plan.md)
For a **structural** verdict, which step do we attribute it to? The value path uses "largest ledger-moving belly call." The structural analogue: the step whose frame produced the authority move recorded in `permission_leak_metadata`. Confirm that boundary offsets can map that frame back to a step index (23.4 says the offsets exist; the mapping for the structural signal is the one thing to verify in plan.md before Phase 1 codes).
