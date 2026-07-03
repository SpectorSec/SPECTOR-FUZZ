# Plan — Feature 017 — Coupled Signal Buses (Dimension → Warp Lever)

**Status:** Planned
**Checkpoints resolved:** 17.1 ✓, 17.2 ✓, 17.3 ✓, 17.4 ✓
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
