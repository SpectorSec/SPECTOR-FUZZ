# Feature 007 — Call Sequence Topology

**Status:** Investigating
**Owner:** TBD
**Last updated:** 2026-06-27

---

## Overview

ABI fingerprinting and topology tell the campaign manager WHAT exploit class is live — the macro shape of the target protocol. What they don't provide is HOW exploits in that class actually sequence at the call level across the known universe of real incidents.

This feature introduces **Call Sequence Topology**: a statistical reference model built from real DeFi POC call sequences that captures two things for each vulnerability category:

1. **The canonical shape** — the ordering that 80% (or whatever the actual split is) of real exploits follow
2. **The variation diff** — which specific steps change position in the remaining exploits that still achieve the exact same result

The variation is not a different exploit. It is the same exploit reached via a different path. Mapping the diff across 100 real incidents reveals which steps have **hard order dependencies** (never move — order-critical) and which steps are **order-flexible** (appear in different positions across incidents, exploit still fires). That diff is a partial order map of the exploit: not a strict sequence but a dependency graph.

The campaign manager consumes this as a reference model — locking order-critical steps and freely mutating within the order-flexible steps — rather than treating the entire sequence as either fixed or random.

Builds on but does not replace:
- **Campaign Orchestrator (Feature 003)** — this extends its playbook generation with shape-aware seeding
- **Engagement Seeder (Feature 002)** — currently seeds data-flow linkage; this adds sequence archetype seeds
- **Topology Intelligence** — ABI topology gives exploit class; call sequence topology gives exploit shape within that class

---

## Why This Matters

### The gap in current coverage

SPECTOR-FUZZ found 109/200 vulnerabilities in baseline testing. The 91 misses are not random — they cluster around exploits that require unusual call ordering not discoverable from ABI shape alone. The canonical path gets found. The variation space doesn't.

### What the data would prove

If 80% of reentrancy exploits share a canonical call sequence shape and 20% are variations — that 20% variation space is a master class in sequencing that no topology system can derive. It requires studying the actual sequences across hundreds of real incidents.

### Three real classes this targets

**Reentrancy variation** — canonical shape is enter → callback → reenter → drain. But flash loan-assisted reentrancy, cross-function reentrancy, and cross-contract reentrancy all produce different sequence shapes that share the same root category. Without knowing the variation space, the fuzzer converges on canonical and misses the variants.

**Access control sequencing** — privileged function calls depend on prior state setup. The order of setup calls varies across incidents. Knowing that 70% of access control exploits require 3+ setup steps before the privileged call, and what those steps look like statistically, changes how the campaign manager generates sequences.

**Price manipulation multi-step** — flash loan → swap → oracle read → borrow. The variation is in which step the oracle is read relative to the manipulation. Knowing the distribution of that ordering across real incidents is not derivable from ABI topology alone.

---

## Success Criteria

This feature is worth building if and only if:

1. A normalized call sequence dataset can be extracted from real DeFi POC transactions and aligned by vulnerability category
2. A meaningful similarity metric can be defined for EVM call sequences that captures structural shape independent of specific addresses and values
3. The canonical shape (80%) and variation space (20%) are quantifiably distinct for at least 3 vulnerability categories
4. The shape + variation data can be represented as campaign seeds or mutation bias metadata that the campaign manager can consume without architectural changes to Feature 003
5. A benchmark shows that shape-seeded campaigns find exploits faster or find exploits in the variation space that topology-only campaigns miss

---

## Out of Scope

- Machine learning or neural network approaches — this is statistical and deterministic
- Real-time learning during fuzzing runs — the reference model is static, built offline from the incident dataset
- Replacing ABI topology (which identifies WHAT) — this adds HOW within a known class
- Automated POC extraction — manual or agent-assisted extraction of the 800-incident dataset is a prerequisite, not part of this feature
- Cross-category analysis — v1 treats each vulnerability category independently

---

## Investigation Checkpoints

### Checkpoint 7.1 — Data Availability
**Prerequisite:** External agent mining DeFi Hack Labs 800-incident dataset
**Question:** What format does the extracted call sequence data arrive in? Selector sequences? Full calldata? State transition traces? What normalization is needed to make sequences comparable across incidents?
**Evidence required:** Sample of extracted sequences from at least 3 incidents per category (reentrancy, access control, price manipulation). Confirm addresses and values can be abstracted away leaving structural shape.

### Checkpoint 7.2 — Similarity Metric
**Files:** None yet — research question
**Question:** What similarity metric captures call sequence shape for EVM transactions? Options: edit distance on selector sequences, state transition vector similarity, call graph isomorphism. Which produces meaningful clustering on real data?
**Evidence required:** Apply at least one metric to a sample dataset and show that known-similar exploits cluster together while known-different ones separate. Must work without addresses or values — structural shape only.

### Checkpoint 7.3 — Distribution Shape of Call Sequences
**Files:** TBD — depends on dataset
**Question:** For a given category (start with reentrancy): what is the statistical distribution of call sequences across 100 real incidents? Specifically: what is the canonical center (mean/mode of step ordering), what is the variation range (standard deviation — sequences that differ in ordering but still achieve the exploit), and what are the tails (sequences at the extreme edges of the distribution)?
**Evidence required:** Distribution analysis across at least 50 incidents in one category. Output:
- The canonical shape (the center — what most exploits look like)
- The variation band (1 sigma — ordering changes that still fire the exploit)
- The edge cases (2 sigma — rare but real)
- The tail boundary (beyond which no known incident exists)
- A partial order map: which steps are order-critical (never move) vs. order-flexible (appear at different positions across the distribution)

This is the core artifact. The distribution shape — not just the split percentage — determines how the campaign manager explores: center first, then within sigma, then edge. The tail is zero-day territory: not random, but the natural extension of a known distribution bounded by the current target's topology.

### Checkpoint 7.4 — Campaign Manager Consumption
**Files:** `src/evm/planner/campaign_planner.rs`, `src/evm/input.rs` (CampaignSequence, StepLinkage), `src/evm/corpus_initializer.rs`
**Question:** How would shape + variation data be injected into the campaign manager? As corpus seeds with pre-ordered CampaignSequence steps? As mutation bias weights in the scheduler? As a new metadata type that plan_campaign() reads to constrain step ordering?
**Evidence required:** Read campaign_planner.rs and confirm the injection point. Determine if this requires a new metadata type or extends existing StepLinkage/TopologyReport structures.

### Checkpoint 7.5 — Benchmark Design
**Files:** `tests/bench/`
**Question:** What benchmark proves this works? Need a target where topology-only campaign fails and shape-seeded campaign succeeds. Does any existing test fixture qualify, or does a new mock contract need to be built that requires non-canonical ordering?
**Evidence required:** Identified benchmark target. Baseline result (topology only, no shape seeding). Prediction of what shape-seeded result should look like.

---

## Risks

- **Data quality** — DeFi Hack Labs POCs may not all have clean, extractable call sequences. Some incidents may be multi-transaction, cross-chain, or involve off-chain components that can't be normalized.
- **Similarity metric validity** — EVM call sequences are high-dimensional. A metric that works on a sample may not scale to 800 incidents cleanly.
- **Campaign manager coupling** — injecting shape data into plan_campaign() without breaking Feature 003's existing logic requires careful wiring. Risk of overriding topology-derived orderings with shape-derived ones incorrectly.
- **Static reference model staleness** — new vulnerability patterns emerge constantly. A static model built on historical data may not capture novel exploit shapes.
- **Variation space sparsity** — if the variation space has too many sub-shapes with too few examples each, the statistical model is too noisy to be useful.

---

## Open Questions

- Is the right abstraction SELECTOR sequences (which function was called in what order) or STATE TRANSITION sequences (what storage changed in what order)? These are different levels of abstraction and may produce different similarity results.
- Should the reference model be per-category (reentrancy, access control, etc.) or per-primitive (Control Leak, Value Leak, etc.)? The six primitives may provide a more stable grouping than traditional vulnerability labels.
- Once the data agent delivers the dataset, what is the minimum viable analysis that would confirm or kill the 80/20 hypothesis without requiring full implementation?
- Does the variation space (the 20%) actually require new campaign manager machinery, or can existing mutation operators explore it naturally once given the canonical shape as a starting point?
