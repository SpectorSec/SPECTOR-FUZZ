# Plan — Feature 017 — Coupled Signal Buses (Dimension → Warp Lever)

**Status:** Planned (Phase 1); **Phase 2 planned below**
**Checkpoints resolved:** 17.1 ✓, 17.2 ✓, 17.3 ✓, 17.4 ✓, 17.5 ✓, 17.6 ✓, 17.7 ✓
**Last updated:** 2026-07-03
**Held:** LOCAL

---

## Architecture Decision

This is a **wiring extension**, not a new trait. It connects three existing subsystems along the
path a signal *should* already travel:

```
TB.dim (016, cmp_linearity)  ──emit──►  publish_located_dim / located flag
        │                                        │
        │ (Wire A: preserve Timestamp             │ (existing: scalar → probe_delta)
        │  through the .max() merge)              ▼
        ▼                                 mutator secant probe (017: Accumulator granularity)
 timestamp_seen bit ──────────────► planner base-warp gate (Wire B)
                                           campaign_planner.rs:304
                                           `if temporal_skimming || ts_located`
                                                     │
                                                     ▼
                                     executor secant warp refinement (existing, fires if base>0)
```

No `revm` fork, no parallel system (Constitution rules 3-4). Reuses `on_step` taint hook and the
existing executor refinement.

## New Types

Minimal. No new metadata struct — piggyback on existing carriers.

| Type / field | Purpose | impl_serdeany? |
|--------------|---------|----------------|
| `TB.ts_seen: bool` (new field on existing `TB`) | Timestamp-present bit that survives `.max()` merge via OR (Wire A) | n/a (TB is not serde) |
| `TIMESTAMP_DIM_LOCATED: static mut bool` (cmp_linearity) | published alongside `located_dim`; true when the located lever carried Timestamp taint | n/a (static flag, matches existing `PRICE_DIM_CMP_SEEN` pattern) |

Rationale: the codebase already uses process-global `static mut` flags for cross-layer dimension
signals (`PRICE_DIM_CMP_SEEN`, `PRICE_MANIPULATION_FLOW`, `ACCUMULATOR_INFLATION_FLOW`). Wire B's
signal follows that established pattern rather than inventing a new metadata channel.

## Registration

- **corpus_initializer.rs** — no new metadata insert required (flags are statics; `ts_seen`
  defaults false in `TB::default()`).
- **evm_fuzzer.rs** — gate the whole coupling behind the new flag; when off, `TIMESTAMP_DIM_LOCATED`
  is never read and the planner condition degrades to the existing `if temporal_skimming`.
- **campaign_planner.rs** — read `TIMESTAMP_DIM_LOCATED` in the warp gate (Wire B).

## CLI

- **Flag:** `--dimension-warp` (couples located `Timestamp` dimension → warp engagement)
- **Config field:** `dimension_warp: bool`
- **Conflicts with:** none. Checked `spector-cli.md`: `--temporal-skimming`, `--reflexive-lever`,
  `--topology-bias` are distinct. `--dimension-warp` is additive to `--temporal-skimming`
  (OR-combined at the planner gate).

## Interaction with Existing Features

| Feature | Interaction |
|---------|------------|
| 001 Value Capture | none (reads no `observed_values`) |
| 002 Engagement Seeder | none |
| 003 Campaign Orchestrator | reads `CampaignSequence.warps` — Wire B changes when a warp is *added*, not the struct |
| 004 Ghost Identities | none (identity→provenance explicitly out of scope) |
| 005 Temporal Skimming | **additive** — same `warps` vector and executor refinement; new path engages warp when Timestamp dim is located even absent `--temporal-skimming` |
| 015 Reflexive Lever | **synergistic** — 015 locates the reflexive Price lever; 017 ensures a Price+Time compound still warps. Shared LOCATE machinery |
| 016 TaintDim | **direct extension** — adds `ts_seen` OR-bit + Accumulator probe granularity |

## Performance

- **When disabled:** zero code path. `ts_seen` is written but never read; `TIMESTAMP_DIM_LOCATED`
  never published; planner gate is the unchanged `if temporal_skimming`.
- **When enabled:** one extra `bool` field OR-merged per `pushtb!` (negligible; already merging
  `t`, `nl`, `provenance`, `dim`). One extra static read per campaign plan. Warp refinement cost is
  unchanged (reuses existing executor secant).

## Test Plan

- **Unit test (isolated from EVM), `cmp_linearity` test module:**
  - `ts_seen_survives_price_merge` — merge a `{dim:Timestamp, ts_seen:true}` TB with a
    `{dim:Price}` TB; assert result `dim==Price` (scalar unchanged) **and** `ts_seen==true`
    (Wire A preserves the signal the scalar drops).
  - `accumulator_gets_own_probe_delta` — assert `probe_delta(Accumulator, x1)` differs from the
    generic `/64` bucket (Checkpoint 17.4 fix).
- **Integration test (`tests/` reward-accrual contract):**
  - With `--dimension-warp` and **without** `--temporal-skimming`, a campaign whose located lever
    is Timestamp-dim produces a non-empty `campaign.warps` (Wire B engages warp dimension-driven).
- **Regression test (Constitution rule 2):**
  - Same contract, both flags off → `campaign.warps` and all ledger output byte-identical to
    pre-017 `main`. Confirms zero code path when disabled.

---

# Phase 2 Plan — Cross-CALL Provenance Routing

**Status:** Built (LOCAL, unpushed) — unit tests green; integration proxy test + A/B perf pending
**Checkpoints resolved:** 17.5 ✓, 17.6 ✓, 17.7 ✓
**Last updated:** 2026-07-03
**Held:** LOCAL
**Build evidence:** `cargo test --lib dim_propagation_tests` → 31 passed / 0 failed. New: `provenance_crosses_call_boundary`, `depth_zero_still_mints`, `clean_calldata_no_inherit`. No Phase-1 regression (depth-0 mint byte-identical).

## Architecture Decision

A **provenance-typed twin** of the existing dimension-carry machinery, forward direction only. No
new trait, no `revm` fork (Constitution rules 3–4). The dim channel already travels
`self.mem → Ctx.input_data → read_input`; Phase 2 adds the parallel provenance path and flips the
callee mint to an inherit:

```
CALLER frame                              CALLEE frame (call_depth > 0)
  MSTORE args ──► mem_prov[argOff..]       CALLDATALOAD(off):
        │           (NEW: prov shadow)        depth==0 ? mint 1<<arg_idx        (unchanged, origin anchor)
        ▼                                     depth >0 ? read Ctx.input_prov    (NEW: inherit caller bits)
  push_ctx: Ctx.input_prov =                      │
     write_input_prov(argOff,argLen) ─────────────┘
```

Origin-preserving semantics (Open Question resolved to origin-preserving in specify.md): the carried
bit keeps its **top-level** arg index, so depth consumes no new bits.

## New Types / Fields

| Type / field | Purpose | notes |
|--------------|---------|-------|
| `CmpLinearityTaint.mem_prov: Vec<u64>` | memory-provenance shadow, twin of `self.mem` | written on MSTORE/MSTORE8/CALLDATACOPY; per-byte-u64 to mirror `mem` indexing |
| `Ctx.input_prov: Vec<u64>` | callee's inherited calldata provenance, twin of `input_data` | snapshot at `push_ctx` |
| `fn write_input_prov(start,len) -> Vec<u64>` | reads `mem_prov[start..end]`, twin of `write_input` | `push_ctx` uses it |
| `fn read_input_prov(&self,start,len) -> u64` | OR of inherited bits over a word, twin of `read_input` | `CALLDATALOAD` uses it at depth>0 |

No new metadata struct, no `impl_serdeany` — this is internal taint-engine state, reset in
`full_reset` alongside `mem`/`ctxs` (`:379-394`).

## Touch Points (exact)

- `cmp_linearity.rs` **MSTORE/MSTORE8 handlers** — write the source `TB.provenance` into
  `mem_prov[dest..dest+32]` (currently they only touch `self.mem` dim).
- `cmp_linearity.rs:456` **push_ctx** — add `input_prov: self.write_input_prov(arg_offset, arg_len)`
  to the `Ctx { .. }` literal; clear `mem_prov` alongside `self.mem.clear()` (`:467`).
- `cmp_linearity.rs:780-785` **CALLDATALOAD** — branch on `self.ctxs.len()` / `host.call_depth`:
  depth 0 keeps `1u64 << arg_idx`; depth > 0 uses `ctx.read_input_prov(off, 32)`.
- `cmp_linearity.rs:379` **full_reset** — `self.mem_prov.clear();`.
- `Default`/`new` (`:362-377`) — initialize `mem_prov: Vec::new()`.

## CLI — none (decision: unconditional correctness fix, no flag)

Cross-CALL provenance is a **correctness fix to existing plumbing**, not a reach/detect lever, so it
takes **no new flag** and does **not** ride `--dimension-warp` (a different bus — dimension→warp;
overloading it is the flag rot `feedback-flag-graduation-model` guards against). It ships
unconditional, gated on **call depth**, not a config bool:

- **Depth 0 (top frame):** unchanged — `CALLDATALOAD` mints `1 << arg_idx`. Byte-identical to
  pre-Phase-2 for all single-contract exploits and existing tests (the origin anchor).
- **Depth > 0:** the carry activates — the callee inherits the caller's origin-anchored bits. The
  old behavior here was not a baseline worth preserving; it was severed (wrong) taint.

Throughput is validated by a **git-toggle A/B build** (with vs. without the `mem_prov` writes),
not a runtime flag. If the hot-path cost proves unacceptable, gating/optimization is a later,
evidence-driven step — not a flag forced up front.

## Interaction with Existing Features

| Feature | Interaction |
|---------|------------|
| 013 Provenance | **direct extension** — makes `TB.provenance` cross-frame; depth-0 mint unchanged |
| 016 TaintDim (Phase 4 return seam) | **parallel** — same push_ctx/pop_ctx machinery, provenance is the forward twin of the dim return carry |
| 015 LOCATE arg-filter | **consumer** — arg-skip can now trust bits sourced from a deeper frame |
| 019 Causal Identity (Phase B Message Leak) | **unblocks** — Message Leak's target-provenance read becomes valid through a proxy hop |
| `mutator.rs:757` same-contract filter | **follow-on** — lifting the storage-provenance map to cross-contract consumes Phase 2's output; tracked separately (specify.md Out of Scope) |

## Performance

- **When disabled:** zero code path (no `mem_prov` writes; CALLDATALOAD unchanged mint).
- **When enabled:** one extra `Vec<u64>` write per MSTORE, bounded by `MAX_CALL_DEPTH = 3` (`:78`).
  Mitigation: only write `mem_prov` for regions whose dim shadow is already non-Generic (skip clean
  memory), keeping the twin sparse. Target within ~5% of the ~860 exec/sec yDAI-fork baseline;
  benchmark documented at Complete.

## Test Plan

- **Unit (`cmp_linearity` test module):**
  - `provenance_crosses_call_boundary` — MSTORE an attacker arg (bit 3) into memory, CALL a callee,
    assert the callee's `CALLDATALOAD` of that word carries **bit 3** (origin-preserved), not a
    re-minted local bit.
  - `depth_zero_still_mints` — top-frame CALLDATALOAD unchanged (`1 << arg_idx`); all Phase 1
    provenance tests pass.
  - `clean_calldata_no_inherit` — forwarding untainted bytes yields provenance 0 in the callee
    (fail-closed, no invented bit).
- **Integration (`tests/` proxy contract):**
  - Attacker calldata routed through a proxy `delegatecall` reaches a sink; assert the sink's value
    carries the original top-level arg bit (drives 019 Phase B).
- **Regression (rule 2):** flag off → all taint verdicts + ledger output byte-identical to pre-Phase-2
  `main`.
