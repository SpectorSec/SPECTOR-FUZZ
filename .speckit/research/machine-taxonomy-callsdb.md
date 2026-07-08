# The Machine-Level Taxonomy of `calls.db`

**Date:** 2026-07-04
**Status:** GROUND FLOOR. This is the machine's-eye view — the axes the fuzzer/DB can sort a
call along, before any human category is applied. Everything (the frame, the priors, the taint
config) keys off this.
**Grounded on:** live `calls.db` (DuckDB) — 910,444 calls · 660 exploit files · 1,357 exploit
rows. All numbers below are queried, not recited.

---

## 0. What the machine HAS (and what it does not)

The machine sees a call as **exactly 10 fields**:

`file_name · call_id · parent_id · depth · raw_contract · function_name · call_type · gas · result · is_noise`
(+ per-file in `exploits`: `chain · year · month · fork_block · category · vuln_type · label_source · success · has_real_calls`)

From those, the machine can classify a call along **6 orthogonal axes**. It has **NO column** for:
- **calldata / arguments** → cannot see *mutated parameters*
- **value / amount moved** → `result` holds return *data* (67% has-data, 33% empty), never *how much* → cannot see *materiality*
- **opcodes / arithmetic** → cannot see *rounding / overflow* (Class-2 blindness)
- **storage slots written** → cannot see *SSTORE deltas* directly

**These three absences are the machine/human boundary, measured — not a TODO.**

---

## AXIS 1 — Identity & position (`file_name`, `call_id`, `parent_id`, `depth`)

The tree coordinate. `parent_id` + `depth` reconstruct the full call tree per incident.
Classes: **entry node** (depth 0–1), **interior node**, **leaf**. This axis is what lets the
machine say "*nested inside a trusted call*" — the only structural evidence it has for Prime.

---

## AXIS 2 — Architecture (`call_type`) — *how* a call is invoked

| Class | Count | % | Reads as |
|---|---|---|---|
| STATICCALL | 482,769 | **53.0%** | reads — oracle/price/reserve queries (no state change) |
| CALL | 325,081 | **35.7%** | value-moving / state-changing invocations |
| DELEGATECALL | 102,594 | **11.3%** | proxy / borrowed-context execution (trusted-context signal) |

Per-category the mix shifts (v3 §7c, verified): staking 18/48/34 (proxy-heavy), oracle 44/43/13
(read-heavy), flash-loan 73/19/8 (direct). **DELEGATECALL fraction is the proxy/trusted-context
fingerprint.**

---

## AXIS 3 — Structure (`depth`) — *where in the tree* logic lives

Non-noise call population by depth (peak at depth 4):
```
d1  43,789   ENTRY band     — capital acquisition (borrow/approve)
d2  99,330      "
d3  82,129   ┐
d4 128,832   │ GATE / LOGIC band — the exploit logic + gates (secant's home)
d5  78,373   │
d6  39,909   ┘
d7  41,665   deep gates / repeated oracle reads
d8  28,458
d9+ tail     extraction bottoms out at the deepest node
```
Three structural classes: **ENTRY (d1–2)** = borrow · **GATE (d4–8)** = lever/mechanical point ·
**FLOOR (deepest node)** = extraction. This is why the secant aims d4–8, not the shallow entry.

---

## AXIS 4 — Signal (`is_noise`) — real vs test scaffolding

| Class | Count | % |
|---|---|---|
| real (`is_noise=false`) | 629,846 | 69.2% |
| harness scaffolding (`is_noise=true`) | 280,598 | 30.8% |

Scaffolding = `setUp`/`testExploit`/`testPoC`/`run`/`assertEq`/`startPrank`. **Every taxonomy
query filters `is_noise=false`** or it measures the test harness, not the exploit (v3 §12 rule).

---

## AXIS 5 — Vocabulary (`function_name`) — the richest axis, 3 sub-classifications

The raw top-30 non-noise names (transfer 108k, referredBy 88k, getReserves 47k, swap 37k, mint
31k, transferFrom 30k, sync 18k, approve 17k, skim 12k, latestRoundData 9.5k, latestAnswer 6.4k,
getPrice 3.9k, getReserveNormalizedIncome 3.2k, scaledTotalSupply 3.0k, withdraw 2.9k …) cluster
three independent ways:

### 5a — SEMANTIC ROLE (the machine grammar) — non-noise call counts
| Role | Count | Filler functions |
|---|---|---|
| CAPITAL / borrow | 21,135 | flashLoan, flash, approve, borrow, deposit |
| READ / oracle | 78,571 | getReserves, latestAnswer, latestRoundData, getPrice, getAmountsOut |
| TRADE / move | 78,455 | swap, sync, skim, feeOnTransfer-swap |
| EXTRACT / payout | 172,851 | transfer, transferFrom, mint, withdraw, redeem, claim |

The universal grammar: **CAPITAL → READ → TRADE → EXTRACT.** Role conservation (~55–86%, v3 §9) is
the real skeleton; the *function* filling a role shuffles by protocol.

### 5b — MECHANICAL CLASS (from ablation, v3 §2/Q2) — what a fn IS
| Class | Functions | Meaning |
|---|---|---|
| NECESSITY | transferFrom (100% drop), transfer (98), mint (82), withdraw (80) | remove it → exploit dies. THE exploit. |
| INFRASTRUCTURE | flash (0% drop), flashLoan (0%) | present everywhere (delivery) but load-bearing nowhere |
| NOISE (mechanical) | approve (1% drop) | ~zero mechanical weight (but cheap → mutation leader, Q3) |

**High presence ≠ causal necessity.** flash is everywhere yet removable; transferFrom is the actual bug.

### 5c — EXTRACTION PRIMITIVE TIER (the 6 leak primitives) — file coverage
| Primitive | Files | Tier |
|---|---|---|
| transfer | 525/660 (80%) | universal substrate |
| transferFrom | 473/660 (72%) | universal substrate |
| mint | 211/660 (32%) | common |
| withdraw | 213/660 (32%) | common |
| redeem | 38/660 (6%) | rare, category-specific (lending/staking) |
| claim | 14/660 (2%) | rare, category-specific (staking) |

Detection prioritizes transfer/transferFrom (universal); claim/redeem are category-gated.

### 5d — ENTRY archetype (first depth-1 non-noise call per file)
approve 135 · flashLoan 81 · swap 43 · attack 33 · flash 30 · transfer 26 · mint 10 · transferFrom 8.
→ 90% of exploits enter as **Approval-First** or **Flash-Loan-Capitalist** (v3 §7c). This is the
machine's read on the **Borrow** phase entry.

---

## AXIS 6 — Outcome (`exploits.success`, `gas`, `result`)
`success` (bool) = did the PoC land. `gas` = per-call cost (reentrancy 192k avg → mutation cost
model). `result` = **return data only, NOT value moved** → the machine can see a call *returned
something* but never *how much value moved*. **Materiality is off-axis for the DB.**

---

## AXIS 7 (META) — RESOLUTION CLASS — the machine's taxonomy of its OWN visibility

The most important machine-level classification: **which mechanisms are even representable at
function-call granularity** (v3 §17). This is what tells you, per mechanism, how much the machine
can pre-fill vs how much is human/engine.

| Class | What it is | Machine visibility | Mechanisms | Routes to |
|---|---|---|---|---|
| **1 VISIBLE MECHANISM** | real on-chain function signature | machine CAN characterize | oracle-price-manip, flash-loan, staking(stake), defl-tax/reflective(skim/deliver), slippage-amm, reentrancy(partial), mint-subfamily | topology + priors + secant |
| **1 IMPROVISATIONAL** | protocol-distributed callbacks | fn unknown until topology IDs protocol | unprotected-callback | topology → callback map → callback-arg secant |
| **2 ARITHMETIC (invisible)** | bug is rounding/overflow — no fn signature, only protocol family shows | machine sees WHERE not WHAT | integer-precision, donation-inflation, signature-replay(crypto) | CMP_MAP / opcode + balance-delta |
| **3 STRUCTURE-LESS** | defined by ABSENCE or OFF-CHAIN | machine sees NOTHING | access-control (missing check), private-key (off-chain), arbitrary-call (attacker calldata), business-logic/accounting, bridge, governance | earned>owed + control-leak + arbitrary-call oracle |

**~40% of exploits live in Class 2/3 — the DB is structurally blind to them.** For those, the
machine's honest output is a NULL with a route hint, not a fabricated signature.

---

## Summary — the machine's coordinate for one call

```
call = {
  identity:      (file, call_id, parent_id, depth-band ∈ {ENTRY, GATE, FLOOR}),
  architecture:  call_type ∈ {STATIC(read), CALL(move), DELEGATE(proxy)},
  signal:        is_noise ∈ {real, harness},
  vocabulary:    { role ∈ {CAPITAL,READ,TRADE,EXTRACT},
                   mech_class ∈ {NECESSITY,INFRASTRUCTURE,NOISE},
                   extract_tier ∈ {substrate,common,rare} | none },
  outcome:       success, gas   (value moved = OFF-AXIS, no column),
}
per-mechanism: resolution_class ∈ {1, 1-improv, 2, 3}   ← governs how much machine can fill
```

**Blind axes (no column → human/engine only):** mutated parameters · materiality/value ·
arithmetic/opcodes · storage-slot deltas.

This is the machine level. The delivery frame (Borrow/Prime/Lever/Exploit) is built ON TOP of
these axes; the human supplies only the blind axes + intent. See
`framed-taint-comining-protocol.md` for that next layer.
