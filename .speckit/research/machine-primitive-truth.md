# Research Note: Machine Primitive Truth — What Actually Breaks DeFi Protocols

**Date:** 2026-06-28
**Status:** Research — informs Feature 007, Feature 008, and oracle design philosophy
**Evidence:** Mechanical cluster analysis of 910,444 call nodes across 700+ real DeFi exploits
**Origin:** Conversation deriving machine truth from call sequence data, not human taxonomy

---

## 1. The Human Taxonomy Is Lossy

The DeFi vulnerability type index (23 categories) describes the semantic story of each exploit —
what went wrong and why, told in human language after the fact.

The mechanical cluster analysis proved this directly:

**Step 3 of the analysis returned zero results.**

Not a single function in the top 40 mechanical vocabulary is specific to one human category.
Every function that appears in "reentrancy" also appears in "oracle-price-manipulation",
"business-logic", "flash-loan", and others. The human taxonomy does not correspond to
distinct mechanical signatures at any measurable level.

```
flashLoan   → appears across 22 of 23 human categories
transfer    → appears across all 23 human categories
getReserves → appears across 23 human categories
withdraw    → appears across 22 human categories
```

The categories are post-hoc explanations. The EVM doesn't know what category it is executing.

---

## 2. One Root Cause at the Opcode Level

All 23 human categories reduce to one opcode-level pattern:

> **The protocol reads state (SLOAD), an external call changes that state (SSTORE via CALL),
> and the protocol applies an effect based on now-stale state.**

Proven across every category:

| Human label | Which SLOAD went stale | What changed it |
|---|---|---|
| Reentrancy | balance slot | re-entered frame reads the slot before the outer frame writes it back |
| Oracle/Price Manipulation | reserve0/reserve1 slots | attacker swapped in same tx, reserves already changed |
| Tax/Deflationary Token | transfer amount accounting | token's internal SSTORE moved less than expected |
| Donation/Vault Inflation | reserve slots | attacker direct-transferred before sync, inflated reserves |
| Access Control | owner/authorized slot | check missing — sensitive SSTORE executes without CALLER validation |
| Approval Abuse | allowance slot | transferFrom drains an allowance the victim set legitimately |
| Unprotected Callback | authentication missing | callback function has no CALLER == expected_pool check |

Different human names. Same opcode story: **stale SLOAD, wrong arithmetic, incorrect SSTORE.**

The 7 primitives listed here are still function-call-level abstractions —
they name WHICH slot went stale, not the opcode pattern itself.
The opcode pattern is one thing.

**Mechanism vs detection — do not conflate them (correction).**
The table above describes the *mechanism* of each bug (what makes it a bug).
It does NOT describe how the fuzzer *detects* it. These are separate layers and
an earlier version of this note blurred them. See Section 4a for the actual
detection architecture. In particular: reentrancy is NOT detected by the
`READ_MAP/WRITE_MAP` dataflow coverage map, and NOT by `CONTROL_LEAK_DETECTED`
(that is the arbitrary-call hook, bug idx 8). Reentrancy has a dedicated
depth-aware middleware detector (bug idx 9). Likewise, structural reentrancy
detection is INDEPENDENT of the `earned > owed` value oracle (bug idx 0) — a
reentrancy can be flagged with zero value extracted, and value extraction can
happen with no reentrancy.

---

## 3. Flash Loan Is Infrastructure, Not a Vulnerability

**ItyFuzz source confirms this directly** (`src/evm/onchain/flashloan.rs`):

```rust
pub struct FlashloanData {
    pub owed: EVMU512,   // tokens borrowed
    pub earned: EVMU512, // tokens received back
}
// when transfer/transferFrom and src is ours → return success, add owed
// when transfer/transferFrom and src is not ours → return success, reduce owed
```

FuzzLand built a flash loan PROVIDER, not a flash loan detector.
The middleware intercepts token transfers, fakes unlimited capital,
tracks earned vs owed. They wired it at the infrastructure layer because
they understood: flash loan is not a vulnerability. It is the key to the
state space where vulnerabilities exist.

**The mechanical cluster analysis confirms this:**

```
Exploits using flash-loan mechanics but NOT labeled 'flash-loan':
  oracle-price-manipulation   n=99   (57% of that category)
  business-logic              n=69
  reentrancy                  n=43
  defl-tax-token              n=39
  access-control              n=39
  staking-reward              n=30
```

99 of 174 oracle-manipulation exploits ARE mechanically flash-loan exploits.
The human labeled them "oracle" because that is the vulnerability exploited.
The machine sees "flash-loan" because that is the delivery mechanism used.
Both are true. They describe different layers of the same execution.

**Flash loan's role:**
- Provides capital that makes the staleness-delta large enough to be profitable
- Compresses the entire attack into ONE atomic transaction
- The protocol assumes state transitions happen in relative isolation between blocks
- Flash loan destroys that assumption: the attacker's entire multi-step manipulation
  settles atomically before the protocol can respond

**Flash loan is not in the vulnerability primitive list.**
It is the universal capital delivery mechanism that amplifies all the others.

---

## 4. ItyFuzz's Oracle — The Laziest Correct Answer

```
earned > owed?
```

This is the machine-level vulnerability type index reduced to its irreducible form.
Not 23 categories. One question: did the attacker end up with more value than they started with?

The 23 human categories are 23 different stories about HOW `earned > owed` became true.
ItyFuzz's oracle doesn't care about the story. It measures the outcome directly.

This is not lazy engineering — it is the most mechanically honest oracle possible.
It detects the universal consequence of every exploit regardless of which SLOAD went stale
and which SSTORE applied the wrong effect.

SPECTOR-FUZZ inherits this oracle and extends it. The extensions (temporal skimming,
value capture, oracle price manipulation detection) detect specific PRECURSORS to
`earned > owed` — earlier in the execution before the net gain is finalized.

`earned > owed` is the right oracle for the VALUE-EXTRACTION bug class (bug idx 0).
It is NOT the universal detector for all bugs. Structural bugs like reentrancy have
their own dedicated detectors that fire on shape, not on profit. See Section 4a.

---

## 4a. The Detection Architecture — Three Distinct Layers

Source-verified. Do not conflate these. They are separate mechanisms with separate jobs.

**Layer 1 — Coverage / dataflow maps (guidance, NOT detection).**
`JMP_MAP` (path-sensitive edge coverage via the `jumpi_trace` rolling hash),
`READ_MAP`/`WRITE_MAP` (SLOAD/SSTORE dataflow), `CMP_MAP` (comparison distance
minimization). These guide the fuzzer toward interesting states. They never
report a bug. They are the senses, not the verdict.

**Layer 2 — Mid-flight middlewares (real-time structural detection).**
Run as `on_step` per-opcode DURING execution. They detect structural patterns
as they happen, regardless of profit. The reentrancy tracer is the canonical example.

**Layer 3 — Post-hoc oracles (the scribes).**
Run after execution. They read what the middlewares recorded and emit the bug
report. `oracles/reentrancy.rs` is purely a reporter — it reads
`reentrancy_metadata.found` and writes the finding. The detection already happened
in Layer 2.

### Reentrancy: the depth-tagged Read-Read-Write detector

`src/evm/middlewares/reentrancy.rs`. Comment in source: `// Reentrancy: Read, Read, Write`.

Algorithm (per-opcode, depth-aware where depth = `post_execution.len()`):
1. On a READ (`0x54 | 0x5c` = SLOAD | TLOAD) of a slot, record the call depth.
2. If the same slot was already read at a SHALLOWER depth and not yet written,
   mark that shallow depth in `need_writes`.
3. On a WRITE (`0x55 | 0x5d` = SSTORE | TSTORE) at a depth pending in `need_writes`
   → **reentrancy found**, insert `(address, slot)` into `found`.

The signature: read at depth d1 (outer frame) → read again at depth d2 > d1
(the re-entered frame sees stale state because the write hasn't happened) →
write back at d1. This is a depth-tagged storage-staleness detector. It is what
the original ItyFuzz used — NOT `CONTROL_LEAK_DETECTED`, NOT the dataflow map,
NOT `earned > owed`.

This also corrects the earlier "stale SLOAD/SSTORE" shorthand: reentrancy is
specifically a Read-Read-Write pattern ACROSS CALL DEPTHS, not a generic
single-frame stale read.

### TLOAD/TSTORE lineage — SPECTOR-FUZZ's clean extension

| | Read arm | Write arm |
|---|---|---|
| Original ItyFuzz (`original-ityfuzz`) | `0x54` only | `0x55` only |
| SPECTOR-FUZZ (`ityfuzz-src`) | `0x54 \| 0x5c` | `0x55 \| 0x5d` |

SPECTOR-FUZZ added the transient-storage opcodes to the SAME depth-aware
algorithm. Consequence: transient-storage reentrancy — a Cancun-era TSTORE
reentrancy guard (Uniswap V4, ERC-7399-style) being re-entered — is detected
identically to persistent-storage reentrancy. This is enabled by the revm 41
upgrade (original ran a dead revm fork `1dead51` with no EIP-1153, so it could
never have written this). Detection-layer coverage of transient reentrancy is
NOT a gap — it already exists.

### What this implies for `CONTROL_LEAK_DETECTED`

`CONTROL_LEAK_DETECTED` (and `ARB_CALL_BUG_IDX = 8`) is a SEPARATE detector for
arbitrary-call / control-leak: the victim hands control to a fuzzer-controlled
address mid-execution. It is the *injection hook* that lets the fuzzer place a
`NestedAction` re-entrant call — it is not itself the reentrancy verdict. The
reentrancy verdict is the depth-tagged middleware above.

### Bug-class independence

| Bug | Idx | Detector | Fires on |
|---|---|---|---|
| Value extraction | 0 | flashloan middleware | `earned > owed` (profit) |
| Arbitrary call / control leak | 8 | host hook | victim CALLs fuzzer-controlled addr |
| Reentrancy | 9 | depth-aware middleware | Read-Read-Write across depths (shape) |

These are orthogonal. A reentrancy can be flagged with zero profit. Value can be
extracted with no reentrancy. Control can leak without either. Oracle design must
respect this independence — do not assume every bug reduces to `earned > owed`.

---

## 5. Temporal Skimming — A Mechanically Distinct Primitive

Temporal skimming is NOT the same opcode pattern as the storage staleness exploits above.

**The key distinction:**

| Dimension | Storage staleness exploits | Temporal skimming |
|---|---|---|
| State domain | Storage — `SLOAD` / `SSTORE` | Block context — `TIMESTAMP` / `NUMBER` |
| Staleness cause | Attacker SSTORE in same tx | Real-world time advancing between txs |
| Attack scope | Intra-transaction | Inter-transaction, across time |
| Flash loan needed | Usually yes | Usually no |
| Detection method | earned > owed in one tx | Balance delta before vs after warp |
| EVM opcode abused | SLOAD reads stale storage | TIMESTAMP reads block context that protocol didn't reconcile |

**How temporal staleness works:**

The protocol stores `lastUpdateTime` in storage (normal SSTORE).
Value accrues as a function of `block.timestamp - lastUpdateTime`:
staking rewards, Chainlink heartbeat freshness, governance timelocks, vested amounts.

Time passes in the real world. The contract state doesn't reconcile.
The gap between `block.timestamp` and the stored `lastUpdateTime` IS the exploitable value.
The attacker does not manufacture the staleness — time manufactures it.
The attacker harvests the drift.

**Why the call tree dataset cannot see this:**

1. `vm.warp` and `vm.roll` were filtered as noise in the call tree analysis
2. The call tree is intra-transaction — one snapshot of one execution
3. Temporal exploits live in the DELTA between snapshots, not within one call tree
4. Temporal skimming exploits appear as ordinary staking or oracle exploits in the call tree
   because the warp calls are stripped out and the time dimension is invisible

The call tree analysis captures the spatial domain (SLOAD/SSTORE).
Temporal skimming lives in the temporal domain (TIMESTAMP/NUMBER delta across snapshots).

**This is why SPECTOR-FUZZ required a dedicated oracle for temporal skimming.**
The `earned > owed` oracle catches the SLOAD/SSTORE domain.
The Temporal Skimming Oracle catches the TIMESTAMP/NUMBER domain via warp-aware
balance snapshots in `OracleCtx.temporal_warps`.
They measure two mechanically different kinds of protocol failure.

---

## 6. The Complete Machine-Level Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    DeFi Protocol Failure                        │
├────────────────────────────┬────────────────────────────────────┤
│   SPATIAL DOMAIN           │   TEMPORAL DOMAIN                  │
│   (SLOAD / SSTORE)         │   (TIMESTAMP / NUMBER)             │
│                            │                                    │
│   Intra-transaction        │   Inter-transaction                │
│   Flash loan amplified     │   Time amplified                   │
│                            │                                    │
│   Root: stale SLOAD →      │   Root: TIMESTAMP - lastUpdate     │
│   wrong arithmetic →       │   grows unbounded → accumulated    │
│   incorrect SSTORE         │   value extractable                │
│                            │                                    │
│   Oracle: earned > owed    │   Oracle: balance delta            │
│   (ItyFuzz core)           │   before vs after warp             │
│                            │   (Temporal Skimming)              │
├────────────────────────────┴────────────────────────────────────┤
│                    DELIVERY LAYER                               │
│   Flash loan = universal capital key (not a vulnerability)      │
│   Compresses multi-step attack into one atomic transaction      │
│   Amplifies delta large enough to be profitable                 │
└─────────────────────────────────────────────────────────────────┘
```

**Human taxonomy**: 23 categories naming the story
**Function-level**: 7 primitives naming which slot went stale
**Opcode-level spatial**: one pattern — stale SLOAD, wrong SSTORE
**Opcode-level temporal**: one pattern — TIMESTAMP drift, accumulated delta
**Detection-level**: NOT one equation — at least three independent detectors
  (value `earned > owed` idx 0, control leak idx 8, structural reentrancy idx 9),
  plus the temporal-domain detectors. See Section 4a.

Every layer is correct. Each is a different resolution of the same truth.
The human reads at the taxonomy level. SPECTOR-FUZZ bridges layers by detecting
patterns at the function/opcode level using machine-speed execution.

Caveat (corrected): `earned > owed` is the irreducible form of the VALUE-EXTRACTION
bug class, not a universal reduction for all bugs. Structural bugs (reentrancy,
control leak) are detected on shape, independent of profit. Treating
`earned > owed` as the single ground truth all bugs collapse to was an
over-simplification — accurate for value bugs, wrong as a general law.

---

## 7. Implications for SPECTOR-FUZZ Oracle Design

1. **Oracle primitives should map to state domains, not human categories.**
   Spatial domain oracles detect SLOAD/SSTORE staleness patterns.
   Temporal domain oracles detect TIMESTAMP/NUMBER drift patterns.
   Human categories are irrelevant to oracle architecture.

2. **Flash loan middleware is infrastructure, not detection.**
   FuzzLand already knew this. SPECTOR-FUZZ inherits it.
   Flash loan is the capital key — wired at middleware, not oracle level.

3. **The conservation map (Feature 007) lives in the spatial domain.**
   The call sequence topology analysis captures intra-transaction mechanics.
   It cannot see temporal patterns because warp calls are noise-filtered.
   Feature 007's conservation map is a spatial domain artifact.

4. **Temporal skimming is orthogonal to Feature 007.**
   The two oracle systems are detecting different state domains.
   They are not overlapping — they are complementary.
   A protocol can be vulnerable in both domains simultaneously.

5. **`earned > owed` is the ground truth for VALUE bugs only — not all bugs.**
   (Corrected.) It is the irreducible form of the value-extraction class (idx 0),
   and most spatial/temporal precursor oracles are early warning for it. But
   structural detectors (reentrancy idx 9, control leak idx 8) fire on shape with
   no profit requirement and are valid bugs in their own right. Do not scrutinize a
   new oracle merely because it does not trace to `earned > owed` — ask instead
   which of the three detection classes it belongs to (value, structural, temporal)
   and whether it fires on a real machine-observable pattern. See Section 4a.

6. **Respect the three-layer detection architecture (Section 4a).**
   Coverage maps guide; mid-flight middlewares detect structure in real time;
   post-hoc oracles report. A new structural bug detector belongs in a middleware
   (`on_step`), not in a post-hoc oracle. Putting structural detection in a
   post-hoc oracle loses the per-opcode, depth-aware signal that makes it work.

---

## 8. Data Evidence Summary

From mechanical cluster analysis of 910,444 call rows, 1,357 exploit entries:

- **Zero** category-specific functions found at any meaningful scale
- **Top 3 co-occurring function pairs** (transfer+transferFrom: 443, approve+transferFrom: 413, approve+transfer: 409) — all ERC-20 substrate, present in all categories
- **flashLoan** appears in 22/23 human categories, with 99 oracle-manipulation exploits using flash loan mechanics
- **Depth distribution peaks at depth 4** (128,832 calls) — real exploit logic lives at depth 3-5, not at the entry point (depth 1)
- **605 of 1,357 entries** improved by parser fix — inner callback sequences were previously invisible
- **Temporal domain is unobservable** in current dataset — warp/roll filtered as noise, call tree is intra-transaction only
