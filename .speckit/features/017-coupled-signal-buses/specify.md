# Feature 017 — Coupled Signal Buses (Dimension → Warp Lever)

**Status:** Specified (Phase 1 built; **Phase 2 specified below**)
**Owner:** TBD
**Last updated:** 2026-07-03
**Held:** LOCAL (builds on 016 TaintDim engine; inherits the taint-stack no-push policy)

---

## Overview

SPECTOR-FUZZ computes rich per-value metadata — economic **dimension** (016), **provenance**
(013), and caller **identity** (004) — but three of these signals are computed and then *never
routed to the decision that would consume them*. This feature closes the highest-value routing
gap: the **dimension bus does not reach the warp lever**.

Concretely, the `TaintDim` engine tags timestamp-derived values `Timestamp` and publishes a
located dimension to the mutator's secant (`read_located_dim()` → `probe_delta`). But the **warp
lever** — the mechanism that advances blocks between a prime step and an exploit step to let
off-screen accrual happen — is engaged purely by the `--temporal-skimming` flag and structural
position (last step), with a **fixed** base warp of 10 blocks. The `Timestamp` dimension the
engine already discovered has zero influence on whether or how far to warp.

This surfaced during the outside-in "chalkboard" exercise (see `project_system_design_capstone`
in memory / `SYSTEM_DESIGN.dot`): an external abstraction repeatedly drew a `dimension → warp`
edge that the code does not have. The abstraction assumed the clean, fully-coupled design; the
as-built ships the decoupled version.

**Weapons this builds on** (`spector-weapons.md`): TaintDim dimension tagging (016), Temporal
Pre-condition Skimming warp lever (005), Ledger Secant LOCATE/AMPLIFY (015).
This is an **extension** wiring two existing weapons together, not a new primitive.

## Why This Matters

Compound exploits that manipulate **a price AND rely on time progression** are the miss:

1. **yDAI / ERC4626 reflexive accrual** — `pricePerShare` (Price dim) inflates *and* the exploit
   needs a block advance for `earn()`/interest to compound. The `.max()` merge publishes `Price`
   (rank 4 > `Timestamp` rank 1), so the Timestamp signal is dropped before the planner ever
   decides to warp; warp then fires only if `--temporal-skimming` was set by hand.
2. **Reward-accrual drains (e.g., Yearn-style / staking)** — value accrues per-block; the located
   lever is an `Accumulator`-dim slot, but the probe delta for `Accumulator` falls through to the
   coarse generic bucket (`_ => x1/64`), under-resolving the tiny per-step drift.
3. **Oracle-staleness + timelock combos** — a `Timestamp`-dim comparison gates the exploit, but
   the warp magnitude is a fixed 10 blocks regardless of the discovered time-sensitivity.

In each case the engine *found the right dimension* and then failed to act on it.

## Success Criteria

This feature is worth building if and only if:

1. A campaign whose located lever carries a `Timestamp` dimension engages the warp lever **even
   without** the explicit `--temporal-skimming` flag (dimension-driven, not flag-only).
2. A compound value carrying **both** `Price` and `Timestamp` provenance preserves the `Timestamp`
   signal through the merge (the scalar `.max()` collapse no longer silently drops it).
3. Zero behavioral change when the new coupling flag is off — existing runs reproduce byte-for-byte
   (Constitution rule 2).
4. Measurable: on a reward-accrual regression contract, dimension-driven warp finds the divergence
   in ≥1 fewer manual-tuning iteration than flag-only warp (benchmark documented at Complete).

## Out of Scope

- **Caller-identity → provenance coupling.** Graded during the exercise as *correct within the
  calldata-mutation threat model*: `CALLER`/`ORIGIN`/`CALLVALUE` are intentionally `clean!()`
  (`cmp_linearity.rs:745`) because a write governed by `msg.sender` identity is not a
  fuzzer-mutable calldata lever. Not a defect; deliberately excluded.
- **Full bitset re-representation of `TaintDim`.** A complete set-valued dimension is a larger
  refactor; this feature takes the *minimal* signal-preserving change (a Timestamp-present bit
  riding alongside the scalar), not a rewrite of the lattice. See Risks.
- **New oracle.** This wires existing detectors; it adds no detection surface.

## Investigation Checkpoints

### Checkpoint 17.1 — Dimension bus terminus  ✓ RESOLVED
**Files:** `src/evm/mutator.rs`, `src/evm/planner/campaign_planner.rs`
**Question:** Does the located dimension reach the warp decision anywhere?
**Evidence:** `located_dim` is consumed *only* at `mutator.rs:727` (`probe_delta` scaling). The
planner's warp push is `campaign_planner.rs:304` `if temporal_skimming { warps.push((exploit_idx,
10)) }` — gated on the flag alone, fixed magnitude 10, no dimension read. **Confirmed decoupled.**

### Checkpoint 17.2 — Scalar collapse drops Timestamp  ✓ RESOLVED
**Files:** `src/evm/middlewares/cmp_linearity.rs`, `src/evm/feedbacks.rs`
**Question:** When a value is both Price- and Timestamp-derived, what dimension publishes?
**Evidence:** `TaintDim` merges via `.max()` (most-specific-wins) with `Price(4) > Timestamp(1)`;
`publish_located_dim()` emits a single scalar. A Price+Time value publishes `Price`; Timestamp is
lost before the mutator or planner sees it. **Confirmed lossy for compounds.**

### Checkpoint 17.3 — Warp engagement + refinement points  ✓ RESOLVED
**Files:** `src/evm/planner/campaign_planner.rs`, `src/executor.rs`
**Question:** Where is the base warp set, and where is it refined? Where does a dimension gate attach?
**Evidence:** Base warp set at `campaign_planner.rs:310` (fixed 10, gated on `temporal_skimming`).
Refined at `executor.rs:207-260` (controlled-probe secant, `temporal_argmin`/`temporal_read`),
but **only if `warp_delta > 0`** (`executor.rs:213`). So the refinement is dead unless the planner
seeded a base. **Wiring point = the planner's base-warp gate** (open it to the Timestamp
dimension); refinement then follows for free.

### Checkpoint 17.4 — Accumulator probe granularity  ✓ RESOLVED
**Files:** `src/evm/mutator.rs`
**Question:** Does the probe delta honor the `Accumulator` dimension?
**Evidence:** `mutator.rs:727-731` handles `Price => /256`, `Balance => /16`, and **everything
else — including `Accumulator` and `Timestamp` — falls to `_ => /64`.** Accumulator is a first-class
lattice member (rank 3) but has no dedicated probe granularity. **Confirmed under-routed.**

## Risks

- **Merge representation.** Adding a Timestamp-present bit alongside the scalar `dim` touches the
  hottest path in the taint engine (`pushtb!` on every opcode). Must stay a single `u8`/bool field
  in `TB`, `.max()`-free, OR-merged, to avoid regressing throughput. A full bitset is explicitly
  deferred.
- **False warp engagement.** Dimension-driven warp could fire on incidental `Timestamp` taint
  (any `TIMESTAMP` opcode read). Mitigation: gate on the *located* lever's dimension (post-LOCATE,
  the arg the secant actually selected), not on mere presence of Timestamp taint anywhere.
- **Interaction with `--temporal-skimming`.** New coupling must be additive (`flag OR
  dimension`), never suppress the existing flag-driven path (rule 2).

## Open Questions

- Should dimension-driven warp reuse the fixed base=10, or scale the base by the discovered
  time-sensitivity? (Lean: keep base=10 for v1; let the executor secant refine — smaller change,
  refinement already exists.)
- Accumulator probe granularity: `/512` (finer than Price, per the exercise's proposal) or `/256`
  (parity with Price)? Needs one benchmark on a reward-accrual contract to decide. (Plan assumes
  `/256` as the conservative default, revisit at Complete.)

---

# Phase 2 — Cross-CALL Provenance Routing

**Status:** Built (LOCAL, unpushed) — code complete + unit-tested; 31/31 in `dim_propagation_tests`
**Last updated:** 2026-07-03
**Held:** LOCAL

## Overview

Phase 1 fixed the *dimension* bus (Timestamp → warp). Phase 2 fixes the **provenance** bus across
the one place it is severed: the CALL boundary. Today `TB.provenance: u64` (`cmp_linearity.rs:299`)
— the bitset recording *which top-level calldata word* authored a value — is a **stack-only,
within-frame** quantity. It does not survive a CALL into another contract, so a single logical
attacker execution is really N disconnected provenance islands, one per frame. Anything that needs
to ask "did attacker calldata word *i* reach *this* sink, possibly several contracts deep?" — the
secant's arg-filtered LOCATE, and (downstream) 019's materiality/message-leak guards — is blind past
the first hop.

There are **two compounding reasons** it doesn't cross (both confirmed in code):

1. **Provenance is memory-lossy by design.** The memory shadow `self.mem: Vec<TaintDim>` carries
   only dimension, not provenance; MLOAD "provenance reset (simplification)" (`:839`). But calldata
   args **always round-trip through memory** — they are MSTORE'd into `argOffset` before the CALL.
   So the provenance u64 is already gone before `push_ctx` could forward it. There is no
   memory-provenance shadow to snapshot.
2. **The callee re-mints local bits.** Even the dim that *does* cross (via `input_data`) only sets
   `tainted`; `CALLDATALOAD` (`:780-785`) then mints `1u64 << arg_idx` indexed by the **callee's
   own** calldata layout. That bit is a fresh coordinate system per frame — bit 3 in the callee has
   zero linkage to attacker calldata word 3 at the top level.

Phase 2 mirrors, for the provenance channel, the machinery 016 already built for the **dimension**
channel (`self.mem` → `Ctx.input_data` → `read_input`), in the **forward (calldata) direction**.
The return-data seam (016 Phase 4: `ret_dims` + `tag_oracle_return`, `:488-527`) is the analogue for
returns; Phase 2 is the harder forward half because provenance has no memory shadow at all yet.

**Weapons this builds on:** 013 Injection/Provenance (`TB.provenance`, `arg_slot_provenance`), 016
memory-shadow carry (`input_data`/`write_input`/`read_input`). This is a **channel-mirroring
extension**, not a new primitive.

## Why This Matters

- **Enables 019 Phase B (Message Leak) and deepens 019 Phase A (Permission Leak).** Both ask a
  cross-frame provenance question. Message Leak through a proxy is *undetectable* without this;
  Permission Leak materiality is under-powered when the material sink sits one delegatecall away.
- **Unblocks the DOT's `prov_map → locate` dashed-red edge** ("cross-contract provenance;
  same-contract only today", `mutator.rs:757` `*addr == step.contract`). The mutator's arg-skip
  filter can only trust cross-contract bits once the engine actually threads them.
- **Stays inside the calldata threat model.** `ORIGIN/CALLER/CALLVALUE` remain `clean!()` (`:769`).
  Phase 2 threads **calldata** provenance across frames only; it does *not* touch the deliberately
  descoped Identity→Provenance coupling.

## Success Criteria

1. A value read via `CALLDATALOAD` inside a callee (call_depth > 0), whose bytes were forwarded from
   an attacker-tainted argument in the caller, carries the **caller's origin-anchored** provenance
   bit — not a freshly minted callee-local `1 << arg_idx`.
2. Provenance survives an MSTORE→CALL round-trip: the bits written to the `argOffset` memory region
   in the caller are the bits the callee inherits.
3. Depth-0 behavior is unchanged: the top frame still mints `1 << arg_idx` (it is the origin
   anchor), so all existing single-contract provenance tests pass byte-for-byte.
4. Zero behavioral change for single-contract executions (depth-0 mint unchanged — the byte-identical
   guarantee that replaces the flag-off path); throughput within ~5% of the ~860 exec/sec yDAI-fork
   baseline.

## Out of Scope

- **Return-direction provenance.** Carrying provenance *out* of a callee via RETURNDATA is a
  separate seam (the dim side is 016 Phase 4). Phase 2 is forward-only (caller args → callee).
- **Identity/`msg.sender` provenance.** Unchanged from Phase 1 Out of Scope — deliberately `clean!`.
- **Cross-contract `arg_slot_provenance` map re-key.** Phase 2 threads provenance through the *taint
  stack* across CALLs; lifting the *storage* provenance map (`mutator.rs:757` same-contract filter)
  to consume the now-available cross-frame bits is the immediate follow-on but is tracked as its own
  wiring step (it reads Phase 2's output).

## Investigation Checkpoints

### Checkpoint 17.5 — Provenance severed at the CALL seam  ✓ RESOLVED
**Files:** `src/evm/middlewares/cmp_linearity.rs`
**Question:** Does `TB.provenance` cross a CALL into a callee?
**Evidence:** `push_ctx` (`:455-466`) forwards `input_data = write_input(arg_offset, arg_len)` — a
snapshot of `self.mem`, which is `Vec<TaintDim>` (**dim only**, no provenance). The callee's
`CALLDATALOAD` (`:780-785`) mints `1u64 << arg_idx` from its *own* offset. **Confirmed: provenance
does not cross; it is re-minted per frame in a frame-local coordinate system.**

### Checkpoint 17.6 — Provenance is memory-lossy  ✓ RESOLVED
**Files:** `src/evm/middlewares/cmp_linearity.rs`
**Question:** Can provenance even reach `push_ctx`, given calldata is built in memory?
**Evidence:** `self.mem` carries only `TaintDim`; MLOAD resets provenance to 0 ("simplification",
`:839`); MSTORE writes no provenance shadow. Calldata args are MSTORE'd to `argOffset` pre-CALL.
**Confirmed: the provenance u64 is destroyed at the MSTORE before the CALL — a memory-provenance
shadow is a prerequisite, not optional.**

### Checkpoint 17.7 — Dim-channel machinery to mirror  ✓ RESOLVED
**Files:** `src/evm/middlewares/cmp_linearity.rs`
**Question:** What existing structure does the provenance carry copy?
**Evidence:** dim crosses via `self.mem` → `Ctx.input_data` (`write_input`, `:456`) → `read_input`
(`:335`, consumed at CALLDATALOAD `:780`). `MAX_CALL_DEPTH = 3` (`:78`) bounds the recursion.
**Confirmed: Phase 2 = a provenance-typed twin of this exact path.**

## Risks

- **Throughput.** A `mem_prov: Vec<u64>` twin doubles memory-shadow writes on every MSTORE. Bounded
  by `MAX_CALL_DEPTH = 3` but it is the primary risk against the ~860 exec/sec ceiling. Mitigation:
  the shadow is only maintained when the coupling flag is on; consider only populating provenance for
  words already `tainted` in the dim shadow (skip clean regions).
- **Bit-space exhaustion across hops.** `provenance` is a 64-bit arg bitset. Origin-preserving carry
  keeps the top-level index, so depth does not consume new bits (good). A *presence-only* collapse
  would, but is rejected (see Open Questions).
- **Fail-closed vs fail-open.** Downstream consumers (019 materiality) must treat "no inherited bit"
  as *not attacker-authored*. The carry itself must never invent a bit it cannot source.

## Open Questions

- **Origin-preserving vs presence-only (design fork — needs a decision before build).**
  *Origin-preserving* keeps attacker arg #3 as bit 3 through every hop (answers "did top-level word
  *i* reach this deep sink?" — exactly what LOCATE arg-filtering and 019 materiality need).
  *Presence-only* collapses to a single "attacker-authored" bit past frame 0 — cheaper, loses
  which-arg resolution. **Lean: origin-preserving**, since the arg resolution is the entire point.
- **`mem_prov` granularity.** Dim shadow is per-byte; provenance is per-32-byte word. Store
  per-byte-u64 (mirror `mem` indexing, fill 32 bytes/word) for uniformity, or a word-indexed
  `Vec<u64>`? (Lean: per-byte for code symmetry with `mem`, revisit if the write cost bites.)
- **Flag? — RESOLVED: no flag.** Cross-CALL provenance is a *correctness fix* to existing
  provenance plumbing, not a reach/detect lever, so it takes no new flag and does **not** ride
  `--dimension-warp` (different bus; overloading it is flag rot). It ships unconditional, gated on
  **call depth**: depth 0 keeps the exact `1 << arg_idx` mint (byte-identical for single-contract);
  the carry activates only at depth > 0, where the old severed-taint behavior was simply wrong.
  Throughput validated via git-toggle A/B build, not a runtime toggle. (See `plan.md` §CLI.)
