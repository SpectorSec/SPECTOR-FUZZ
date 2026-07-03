# Reflexive-Lever Corpus Mining — data-driven lever catalogue for Feature 015

**Date:** 2026-07-03  **Source:** `/workspace/_global/calls.db` (DuckDB; 660 files with
real traces, ~910k non-noise call rows).  **Scripts:** `scratchpad/lever_extractor.py`,
`reflexive_fast.py` (this artifact ships copies under `research/scripts/`).

## Thesis validated
`Borrow → Prime → LEVER → Exploit`. Borrow/Prime are *systematic* (generic scaffolding
present in nearly every trace). The **LEVER** is the one *learned* element — and it is
directly minable from the corpus. Topology is only the *identifier*; the DB is the *teacher*.

## Lever predicate (name-agnostic)
A call `L` is a lever iff a **value-gating read** (generic DeFi valuation: `get_virtual_price`,
`getPricePerFullShare`, `pricePerShare`, `latestRoundData`, `getReserves`, `exchangeRate`,
`convertToAssets`, `get_dy`, `getAmountsOut`, `getUnderlyingPrice`, …) is consumed shortly
after `L`. `L` must be a mutating `CALL` (not a read, not plumbing). We never look for
`add_liquidity` by name — whatever mutation precedes such a read *nominates itself*.

## Headline results
- **355 / 660 incidents (54%)** exhibit a lever→value-read pattern. Levers are not a yDAI
  quirk; half the corpus is lever-driven.
- **Bimodal by GAP DISTANCE** (calls between lever and its consuming read):
  - **Adjacent (gap ≤ 2): 318 incidents** — spot-price manip (`swap → getReserves`, ~38k
    occurrences). Single-frame; a classic fuzzer already reaches it.
  - **Cross-step reflexive (gap ≥ 5 into a vault/share read): 57 incidents** — the *belly gap*.
    Manipulate in one step, poisoned valuation consumed in a *later* step. yDAI ∈ this set.
    **This is Feature 015's addressable market (~9% of traced corpus, ~16% of lever-bearing).**
- **The reflexive family is dominated by LENDING forks, not Curve.** Hardcoding the two Curve
  selectors covered ~10 incidents; the lending family (`mint`/`borrow`/`redeem`/…) is ~40+.

## Deployable target matrix (57 reflexive incidents; 52 resolve a known primitive)
Selectors = `keccak256(canonical signature)[:4]` (pycryptodome keccak; verified:
`add_liquidity(uint256[3],uint256)=0x4515cef3`, `remove_liquidity_imbalance(uint256[3],uint256)=0x9fdaea0c`
— byte-identical to the current hardcoded consts).

Roles: **KNOB** = attacker-callable lever (target candidate); **MECH** = internal state-mutator
(the reflexive mechanism); **HOOK** = comptroller policy check (not a target).

| role | #inc | fn | selector(s) |
|------|-----:|----|-------------|
| KNOB | 41 | mint (cToken) | `0xa0712d68` |
| KNOB | 26 | borrow | `0xc5ebeaec` `0xeac5b6e1` |
| KNOB | 25 | enterMarkets¹ | `0xc2998238` |
| KNOB | 18 | redeemUnderlying | `0x852a12e3` |
| KNOB | 17 | redeem | `0xdb006a75` |
| KNOB | 10 | add_liquidity | `0x0b4c7e4d` `0x4515cef3` `0x029b2f34` |
| KNOB |  7 | repayBorrow | `0x0e752702` |
| KNOB |  7 | liquidateBorrow | `0xf5e3c462` |
| KNOB |  6 | exchange | `0x3df02124` |
| KNOB |  4 | repay | `0x371fd8e6` `0x573ade81` |
| KNOB |  3 | remove_liquidity_one_coin | `0x1a4d01d2` |
| KNOB |  2 | remove_liquidity_imbalance | `0xe3103273` `0x9fdaea0c` `0x18a7bd76` |
| KNOB |  1 | exchange_underlying | `0xa6417ed6` |
| MECH |  8 | accrueInterest | `0xa6afed95` |
| MECH |  6 | seize | `0xb2a02ff1` |
| HOOK | 26 | mintAllowed | `0x4ef4c3e1` |
| HOOK | 18 | redeemAllowed | `0xeabe7d91` |
| HOOK | 15 | repayBorrowAllowed | `0x24008a62` |
| HOOK | 13 | redeemVerify | `0x51dff989` |
| HOOK |  4 | borrowAllowed | `0xda3d454c` |

¹ `mint`/`enterMarkets` are arguably **Prime** (positioning), not the manipulation knob — they
open the position the later `borrow`/`redeem` exploits. Keep as candidates but rank below the
true state-warpers. `accrueInterest`/`seize` are the *mechanism* the KNOBs trigger.

## Deployable Rust const
```rust
// Data-mined from calls.db across 57 cross-step reflexive incidents.
// Replaces the 2 hardcoded Curve selectors in campaign_planner.rs::find_targets_by_selector.
pub const REFLEXIVE_LEVER_SELECTORS: &[[u8; 4]] = &[
    [0xa0,0x71,0x2d,0x68], // mint(uint256)                       cToken
    [0xc5,0xeb,0xea,0xec], // borrow(uint256)                     Compound
    [0xea,0xc5,0xb6,0xe1], // borrow(uint256,...,address)         Aave
    [0xc2,0x99,0x82,0x38], // enterMarkets(address[])
    [0x85,0x2a,0x12,0xe3], // redeemUnderlying(uint256)
    [0xdb,0x00,0x6a,0x75], // redeem(uint256)
    [0x0b,0x4c,0x7e,0x4d], // add_liquidity(uint256[2],uint256)   Curve
    [0x45,0x15,0xce,0xf3], // add_liquidity(uint256[3],uint256)   Curve (was hardcoded)
    [0x02,0x9b,0x2f,0x34], // add_liquidity(uint256[4],uint256)   Curve
    [0x0e,0x75,0x27,0x02], // repayBorrow(uint256)
    [0xf5,0xe3,0xc4,0x62], // liquidateBorrow(address,uint256,address)
    [0x3d,0xf0,0x21,0x24], // exchange(int128,int128,uint256,uint256)  Curve
    [0x37,0x1f,0xd8,0xe6], // repay(uint256)
    [0x57,0x3a,0xde,0x81], // repay(address,uint256,uint256,address)   Aave
    [0x1a,0x4d,0x01,0xd2], // remove_liquidity_one_coin(uint256,int128,uint256)  Curve
    [0xe3,0x10,0x32,0x73], // remove_liquidity_imbalance(uint256[2],uint256)     Curve
    [0x9f,0xda,0xea,0x0c], // remove_liquidity_imbalance(uint256[3],uint256)  Curve (was hardcoded)
    [0x18,0xa7,0xbd,0x76], // remove_liquidity_imbalance(uint256[4],uint256)     Curve
    [0xa6,0x41,0x7e,0xd6], // exchange_underlying(int128,int128,uint256,uint256) Curve
];
```

## Honest scope limits
- **Class-1 VISIBLE only.** This predicate sees value-movement + protocol vocabulary in the
  function-level tree. It is blind to *Class-2 arithmetic* levers (donation-inflation,
  integer-precision) which have no valuation-read fingerprint and need balance-delta / CMP-map.
- **Depth is NOT a valid attacker/internal split on a PoC corpus** — the harness
  (`testExploit → flashLoan → receiveFlashLoan`) occupies shallow depths and buries the true
  lever deeper. Classification here is by **protocol vocabulary**, not depth.
- Selector resolution requires the canonical arg signature (the DB stores decoded names only);
  multi-variant names emit all standard forms.

## Next build
Wire `REFLEXIVE_LEVER_SELECTORS` into `campaign_planner.rs::find_targets_by_selector` (replacing
the 2 Curve consts) and extend `ExploitClass::ReflexiveSkew` scoring to fire on lending-family
co-occurrence in `topology.rs`. This is the a-priori arm; the a-posteriori arm (T10) already
covers whatever this catalogue misses at runtime.
