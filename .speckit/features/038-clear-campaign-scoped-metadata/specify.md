# Feature 038 — Clear Campaign-Scoped Metadata on the Non-Campaign Path (EO-01)

## Status
Ready to build. Source: PR #2's execution-ordering audit (EO-01, High severity), independently
verified against `executor.rs`/`feedback.rs` before speccing — not taken from the PR's description.

## The gap (code-verified)

`FuzzExecutor::run_target`'s campaign path (`executor.rs:151-296`) writes three metadata entries
into the long-lived `state.metadata_map()` after the final campaign step:

```rust
state.add_metadata(CampaignIntermediateStates { states: intermediate_states });   // executor.rs:273-275
state.add_metadata(CampaignWarpStates { warps: campaign.warps.clone() });          // executor.rs:276-278
state.add_metadata(crate::evm::planner::CampaignInflowBoundaries { offsets: inflow_offsets }); // executor.rs:289-291, aposteriori-gated
```

The non-campaign path (`executor.rs:298-305`) never clears or replaces any of these:

```rust
crate::evm::middlewares::function_auth::set_campaign_step(None);
let res = self.vm.deref().borrow_mut().execute(input, state);
state.set_execution_result(res);
Ok(ExitKind::Ok)
```

`OracleFeedback::is_interesting` (`feedback.rs:250-258`) reads both `CampaignIntermediateStates`
and `CampaignWarpStates` **unconditionally**, for every execution, campaign or not:

```rust
let campaign_intermediate_states = state.metadata_map().get::<CampaignIntermediateStates<Loc, Addr, VS, CI>>().map(|m| m.states.clone());
let temporal_warps = state.metadata_map().get::<CampaignWarpStates>().map(|m| m.warps.clone());
let mut oracle_ctx = OracleCtx::new(state, input.get_state(), self.executor.clone(), input, campaign_intermediate_states, temporal_warps);
```

Since `state` (the `FuzzState`) persists across every `run_target` call for the life of the fuzzing
process, once ANY campaign has executed, its `CampaignIntermediateStates`/`CampaignWarpStates`
remain in `metadata_map()` forever afterward — fed into the `OracleCtx` of every subsequent
non-campaign (or unrelated later campaign's) execution until another campaign overwrites them.

## Why this matters

Producers/oracles that read `ctx.campaign_intermediate_states`/`ctx.temporal_warps` from
`OracleCtx` can attribute a single, unrelated transaction's effects to a stale, unrelated campaign
frame from a prior execution — false phase attribution, stale warp attribution, and (per 034's new
`reentrancy.rs` producer and 033's Invariant producers, both of which read execution-scoped state)
a plausible source of misattributed `PromotionCandidate` phase/context data if any of them come to
depend on campaign context in the future.

## What changes

### 1. `src/executor.rs` — clear campaign-scoped metadata on the non-campaign path

At the non-campaign branch (`executor.rs:298`, right after `set_campaign_step(None)`):

```rust
#[cfg(feature = "evm")]
{
    crate::evm::middlewares::function_auth::set_campaign_step(None);
    // Feature 038 (EO-01): this is not a campaign execution — clear any campaign-scoped
    // metadata left over from a prior campaign run so OracleFeedback's context construction
    // (feedback.rs:250-258) doesn't attribute this execution to a stale campaign frame.
    state.metadata_map_mut().remove::<CampaignIntermediateStates<Loc, Addr, VS, CI>>();
    state.metadata_map_mut().remove::<CampaignWarpStates>();
    state.metadata_map_mut().remove::<crate::evm::planner::CampaignInflowBoundaries>();
}
```

Also clear them at the *start* of the campaign path (before line 151's branch, or immediately
inside it before the loop) for the case of campaign N's execution reverting partway through
(`executor.rs:187-189`'s early `return Ok(ExitKind::Ok)` on a reverted prefix step) — in that case
NEITHER the campaign nor non-campaign metadata-write blocks run, so a revert mid-campaign leaves
whatever the PREVIOUS execution (campaign or not) wrote fully intact. Concretely: clear all three
at the top of `run_target`, unconditionally, before either branch — this is simpler than clearing
in two separate places and covers the early-revert-return case for free.

### 2. Verify `libafl`'s metadata removal API

Check whichever of `metadata_map_mut().remove::<T>()` or a `HasMetadata`-provided equivalent this
codebase's `libafl`/`libafl_bolts` fork actually exposes — other code in this repo already calls
`.remove::<T>()` (e.g. `temporal_skim.rs:133`, `mutator.rs:2006` both do
`metadata_map_mut().remove::<TemporalBalanceSnapshot>()`), so the API exists and this is a
mechanical addition, not new plumbing.

### 3. Tests

- Regression test matching the audit's suggestion: construct a `FuzzState`, run a campaign input
  that sets `CampaignWarpStates`/`CampaignIntermediateStates`, then run a plain (non-campaign)
  `EVMInput` immediately after, and assert `state.metadata_map().get::<CampaignWarpStates>()` and
  `get::<CampaignIntermediateStates<...>>()` are both `None` after the second execution.
- A second case: campaign A executes and sets metadata, campaign B (also multi-step) executes
  next — assert campaign B's `OracleCtx` only ever sees campaign B's own
  `CampaignIntermediateStates`/warps, never a mix with campaign A's.

## What stays byte-identical

- A campaign execution immediately followed by another campaign execution — the second campaign's
  own metadata-write block (`executor.rs:273-291`) still runs and overwrites whatever's there,
  same as today; the only change is that the non-campaign path (and the top-of-function clear) now
  also actively removes rather than leaving stale data.
- Any oracle/producer that doesn't read `ctx.campaign_intermediate_states`/`ctx.temporal_warps` —
  unaffected either way.

## Out of scope

- `CampaignExecutionFrame` (the audit's cross-cutting recommendation, bundling all campaign-scoped
  fields plus an `execution_id`/`is_campaign` flag into one struct) — a larger refactor that would
  also subsume this fix and EO-02's fix below. Worth doing eventually; this feature is the minimal,
  immediately-safe fix (clear stale data) rather than the full frame redesign.
- Gating feedback on `EVMInput.campaign.is_some()` as an additional belt-and-suspenders check (the
  audit's alternate suggestion) — not needed if the metadata is reliably cleared; revisit only if
  clearing proves insufficient in practice.
