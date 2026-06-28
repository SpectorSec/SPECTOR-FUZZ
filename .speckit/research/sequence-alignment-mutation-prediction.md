# Research Note: Sequence Alignment, Conservation Maps, and Bayesian Mutation Prediction

**Date:** 2026-06-28
**Status:** Research — informs Feature 007 (Call Sequence Topology) and Feature 008 (Position-Aware Mutation Prediction)
**Origin:** Derived from conversation analyzing 700+ DeFi exploit call traces

---

## 1. The Core Problem with Aggregate Similarity

Raw sequence similarity (LCS, edit distance) asks: *how similar are two sequences overall?*

That's the wrong question for exploit analysis. Two exploits can have low overall similarity but share the exact same conserved steps at the same positions. The meaningful signal is not the overall score — it is **where in the sequence the variation happens**.

---

## 2. The Bioinformatics Parallel: Multiple Sequence Alignment

DNA researchers solved an identical problem decades ago. When studying a gene across hundreds of organisms, they found sequences that are related but not identical. Their solution: **Multiple Sequence Alignment (MSA)**.

MSA aligns N sequences against each other and produces a **conservation profile**:

```
Sequence A:  flashLoan  ·transfer·  deposit  withdraw  swap
Sequence B:  flashLoan  ·approve·   deposit  withdraw  swap
Sequence C:  flashLoan  ·transfer·  borrow   withdraw  swap
Sequence D:  approve    ·flashLoan· deposit  liquidate swap

Conservation: ████████   ░░░░░░░░   ▒▒▒▒▒▒  ████████  ████████
              CONSERVED  VARIABLE   MIXED   CONSERVED CONSERVED
```

**Conserved positions** — the same function appears across nearly all exploits in the category. These are the structural necessities. The linchpins that must be present.

**Variable positions** — different functions appear at this position across exploits, but all still achieve the same exploit outcome. This is the mutation site — where attackers made different choices to reach the same result.

**Conservation score** — a percentage (0–100%) for each position expressing how often the most common function appears there across all sequences in the category.

The **conservation profile** across all positions is the MODEL for that vulnerability class. It is not a single sequence — it is a map of structural necessity vs flexibility.

---

## 3. What This Means for DeFi Exploit Analysis

For a category like **reentrancy**, MSA across 100 real exploits would produce:

- Position 1: flashLoan appears in 78% → HIGH conservation (near-canonical)
- Position 2: transfer(38%), approve(31%), swap(21%), other(10%) → LOW conservation (mutation site)
- Position 3: deposit/borrow appears in 85% → HIGH conservation
- Position 4: withdraw(60%), liquidate(25%), claim(15%) → MEDIUM conservation (partial mutation site)
- Position 5: swap/exit appears in 90% → HIGH conservation (exit step always present)

The conservation profile tells you:
- The **linchpin steps** (high conservation) — the steps that cannot be skipped
- The **mutation sites** (low conservation) — where different exploit strategies diverge while still achieving the same outcome
- The **variation space** — which functions are valid at each mutation site and in what proportion

---

## 4. The Variation Space Is Not Noise

The 20-40% of exploits that deviate from canonical at mutation sites are not failed or anomalous exploits. They are **valid alternative exploit paths**. They achieved the same outcome via different ordering or function choice.

This is what makes the variation space so valuable:
- The canonical shape is what every fuzzer eventually discovers
- The variation space is where novel exploits live
- An attacker writing a zero-day intuitively finds a point in or near the known variation space
- The tails (beyond known variation) are the true unknowns — but they are bounded extensions of known patterns, not random

The distribution is a bell curve. Center = canonical. 1 sigma = variation. 2 sigma = edge cases. Tail = zero-day territory.

---

## 5. Harvey's Input Prediction (Microsoft Research)

Harvey (Wustholz & Christakis, Microsoft Research 2018–2020) introduced **input prediction** for smart contract fuzzing.

**Harvey's approach:**
- Given a partial execution trace, predict what INPUT VALUE would push execution down an unexplored branch
- Lightweight symbolic reasoning: if a comparison `x > 100` is about to fail, predict an input where `x = 101`
- Not full symbolic execution — a fast approximation that guides mutation toward new coverage

**What Harvey predicted:** VALUES (arguments to calls)
**What we are describing:** POSITIONS (which function to call at which position in the sequence)

Position prediction is a higher-level abstraction than value prediction. Harvey answers "what value completes this call?" We are asking "what function should come next in this sequence to complete this exploit?"

---

## 6. Bayesian Mutation Prediction

Combining the conservation map (Feature 007) with snapshot-based execution creates a Bayesian mutation framework:

### The Three Components

**Prior — Historical Distribution**
From the MSA conservation map: at variable position N in category C, what is the distribution of functions that appeared historically?

```
Position 4, reentrancy category:
  P(withdraw)  = 0.60
  P(liquidate) = 0.25
  P(claim)     = 0.15
```

This is the prior — what worked historically at this position.

**Likelihood — Current EVM State**
The snapshot at position 3 captures the actual current state of the EVM: balances, storage slots, active positions, flags. The likelihood asks: given this specific state, which function at variable position 4 is most compatible?

```
Current state: contract has active lending position open
Likelihood update:
  P(withdraw  | active loan) = 0.30  ↓  (wrong path for active loan)
  P(liquidate | active loan) = 0.60  ↑  (compatible with loan state)
  P(claim     | active loan) = 0.10  ↓
```

**Posterior — Predicted Next Move**
Bayes: posterior ∝ prior × likelihood

```
P(withdraw  | state) ∝ 0.60 × 0.30 = 0.18
P(liquidate | state) ∝ 0.25 × 0.60 = 0.15
P(claim     | state) ∝ 0.15 × 0.10 = 0.015
(normalize) → liquidate wins despite lower prior
```

The posterior is the **predicted next move** — the function the fuzzer should try first at this variable position given BOTH historical evidence AND current runtime state.

### Why This Is Powerful

Without prediction: random mutation explores all possible functions at all positions equally.

With Bayesian position prediction:
- Conserved positions are not mutated (conservation score > threshold)
- Variable positions are mutated, but in priority order from the posterior distribution
- The fuzzer tries most-likely first, not random first
- The snapshot makes testing cost near-zero — try liquidate, observe oracle signal, jump back, try withdraw if liquidate failed

This is **hypothesis-driven exploration**: form a ranked hypothesis about what comes next, test it with near-zero cost via snapshot, update based on oracle feedback, try next hypothesis.

---

## 7. Position-Aware Mutation vs Existing SPECTOR-FUZZ Mutation

Current SPECTOR-FUZZ mutation is already sophisticated:
- **Oracle-biased resampling** — biases function selection toward oracle-flagged targets
- **Ghost Identities** — biases caller identity toward trusted protocol addresses
- **Topology mutation boost (Gamma Ray)** — biases energy toward topology-predicted paths
- **Engagement Seeder** — data-flow linkage between steps

What position-aware Bayesian prediction adds:
- **Sequence position awareness** — knows WHERE in the exploit sequence the fuzzer currently is
- **Historical prior** — knows what worked at this position across 700 real exploits
- **State compatibility** — knows which historical option fits the current EVM state
- **Conservation-gated mutation** — skips mutation entirely at conserved positions

These are orthogonal to existing capabilities. They do not replace oracle bias or ghost identities — they add a sequence-level layer on top of the existing function-level bias.

---

## 8. The Snapshot Cost Advantage

Without snapshots: testing N candidate functions at position 4 requires replaying the entire sequence from position 0 → N times. Cost: O(N × sequence_length).

With snapshots (ItyFuzz / SPECTOR-FUZZ): jump to the state at position 3 (already snapshotted), test candidate function, observe oracle signal, jump back. Cost: O(N × 1) — one step per candidate.

The snapshot makes Bayesian prediction economically feasible. The cost of testing each hypothesis is near-zero. The fuzzer can exhaust the entire posterior distribution at a variable position cheaply before moving forward.

This is why snapshot + position prediction is a force multiplier: prediction tells you the order to try, snapshot makes the trying almost free.

---

## 9. Feature Implications

### Feature 007 — Call Sequence Topology (Investigating)
Produces the conservation map. The primary artifact is:
- Per-category conservation profiles (position → conservation score)
- Variable position inventories (position → function distribution)
- The partial order map (which steps are order-critical vs order-flexible)

Feature 007 is the prerequisite for Feature 008.

### Feature 008 — Position-Aware Bayesian Mutation (Not Yet Specced)
Consumes the conservation map from Feature 007 and wires it into the campaign manager's mutation engine:
- Conservation-gated mutation (skip mutation at high-conservation positions)
- Prior-weighted function selection at variable positions
- State-compatibility likelihood update from current EVM state
- Posterior-ranked hypothesis testing via snapshot loop

**Prerequisite:** Feature 007 must be complete and produce a valid conservation map.
**Data prerequisite:** The 700-exploit call sequence dataset (currently being built).
**Investigation gate:** Feature 007's checkpoints 7.3 and 7.4 must confirm that the conservation profile is quantifiably distinct and statistically meaningful before Feature 008 can be planned.

---

## 10. Key Terms Reference

| Term | Definition |
|------|-----------|
| **Multiple Sequence Alignment (MSA)** | Bioinformatics technique for aligning N sequences to find conserved vs variable positions |
| **Conservation score** | Percentage of sequences in a category where the most common function appears at a given position |
| **Conserved position** | Sequence position with high conservation score — structurally necessary, should not be mutated |
| **Variable position / Mutation site** | Sequence position with low conservation score — where different exploit strategies diverge |
| **Conservation profile** | The full map of conservation scores across all positions — the MODEL for a vulnerability class |
| **Variation space** | The set of valid alternative functions at each variable position |
| **Prior** | Historical distribution of functions at a variable position from the dataset |
| **Likelihood** | Compatibility of each candidate function with the current EVM state |
| **Posterior** | Bayes: prior × likelihood — the predicted next move |
| **Position-aware mutation** | Mutation that targets variable positions first and prioritizes by posterior distribution |
| **Hypothesis-driven exploration** | Form ranked prediction, test via snapshot (near-zero cost), update, try next |
| **Harvey** | Microsoft Research smart contract fuzzer (2018–2020) — introduced value-level input prediction |
| **Conservation-gated mutation** | Do not mutate positions with conservation score above threshold |
