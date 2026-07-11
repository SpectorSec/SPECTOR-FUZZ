# Feature 041 — Apply `CampaignSequence.linkages` During Execution (EO-04)

## Status
Ready to build. Source: PR #2 (EO-04, Medium). Independently verified: `StepLinkage`/
`CampaignSequence.linkages` (`input.rs:39-46,52-54`) are declared, planner code can presumably
populate them, but grepped the whole tree for `.linkages`/`StepLinkage` usage — zero consumers,
including the full `executor.rs:151-296` campaign-stepping loop read end-to-end. Confirmed dead
data model, exactly as the PR describes.

## The gap (code-verified)

```rust
// input.rs:35-46
pub struct StepLinkage {
    pub from_step: usize,
    /// The observed_values registry key in `{target:?}_{selector_hex}_return` format,
    /// matching how value_capture.rs stores return values.
    pub from_registry_key: String,
    pub to_step: usize,
    pub to_param_index: usize,
}

pub struct CampaignSequence {
    pub steps: Vec<ConciseEVMInput>,
    pub linkages: Vec<StepLinkage>,
    ...
}
```

The registry `StepLinkage.from_registry_key` refers to already exists and is already populated
during normal execution: `EVMState.observed_values: HashMap<String, Vec<EVMU256>>` (`vm.rs:238`),
written by `value_capture.rs`'s middleware (`{:?}_{}_return` key format, confirmed at
`value_capture.rs:105,195`) every time a call returns. So the DATA linkages need is already
captured for free — the only missing piece is the executor reading it and applying it to a later
step's ABI arguments before that step executes.

The executor loop (`executor.rs:172-198` for prefix steps, `executor.rs:264` for the exploit step)
builds each step's input via `step_ci.to_input(current_state.clone())` and executes it directly —
no code anywhere reads `campaign.linkages`.

## Why this matters

A campaign that's *structurally* ordered (`A` before `B`) can still be *semantically* unlinked —
`B`'s argument that's supposed to be `A`'s returned nonce/ID/share-count is whatever the ABI
mutator last put there, not `A`'s actual output. For contracts requiring round IDs, deposit share
counts, or nonces captured from an earlier call, this is a reachability bug, not just an ordering
nicety — the campaign can never reach the intended state without the real captured value.

## What changes

### `src/executor.rs` — apply linkages before executing each step

At the top of the prefix-steps loop body (`executor.rs:172`, before `step_ci.to_input(...)` at
line 176) and again before the exploit step's input is built (`executor.rs:264`):

```rust
// Feature 041 (EO-04): apply any linkage targeting this step BEFORE building its input,
// using the source step's captured return value from EVMState.observed_values (populated
// by value_capture.rs — the same registry StepLinkage.from_registry_key already names).
for linkage in campaign.linkages.iter().filter(|l| l.to_step == i) {
    if linkage.from_step >= i {
        // Enforce from_step < to_step — a linkage that isn't backward-referencing is
        // malformed (the planner should never emit this, but don't trust silently).
        continue;
    }
    if let Some(values) = current_state.state.observed_values.get(&linkage.from_registry_key) {
        if let Some(captured) = values.last() {
            // Reuse the existing calldata-word-write pattern (mutator.rs's
            // write_calldata_arg_u128: offset = 4 + arg_idx*32, big-endian word write)
            // rather than inventing a second mechanism for the same operation.
            apply_linkage_arg(&mut step_input, linkage.to_param_index, *captured);
        }
    }
    // Missing source key: per the audit's suggested invariant, this should either skip
    // campaign execution or mark it invalid — see "Missing-linkage policy" below.
}
```

This needs `step_input` to exist before the loop runs, so the exact ordering is: build
`step_input` via `to_input`, THEN apply linkages onto it, THEN (for prefix steps) apply the
existing warp-delta adjustment, THEN execute. Reorder `executor.rs:172-183`'s existing lines
accordingly rather than trying to apply linkages before `to_input` runs.

### `apply_linkage_arg` helper

Mirror `mutator.rs`'s existing `write_calldata_arg_u128` (offset = `4 + arg_idx * 32`, writes the
lower 16 bytes of a big-endian 32-byte word) — same calldata layout assumption, just applied to
`EVMU256` (the full 32-byte word) rather than truncating to `u128`, since `observed_values` stores
`EVMU256`. Either extract a shared helper both call sites use, or duplicate the ~10-line pattern —
implementer's call given how small it is.

### Missing-linkage policy (flag for decision, don't guess)

The audit suggests: *"missing linkage should either skip campaign execution or mark the campaign
invalid, not silently execute random arguments."* Two options:
1. **Skip the campaign entirely** (return early from `plan_campaign_sampled` or have the executor
   bail before executing anything) if any linkage's source key isn't found by the time its target
   step is reached — safest, but could silently drop otherwise-fine campaigns if the source call
   reverted or the key format doesn't match exactly.
2. **Execute the step with its un-linked (mutator-chosen) argument as a fallback**, same as today
   — cheapest, matches current behavior when linkages are absent, but doesn't fully close the gap
   for the specific case the audit flagged (a step whose call REQUIRES the linked value to
   succeed will just revert, same as today).

Recommend option 2 as the default (fail open, matches "byte-identical when no linkage" principle
this whole audit series has used elsewhere) with option 1 available behind a stricter mode if the
team wants campaigns with unsatisfied linkages to be discarded rather than attempted. Not deciding
this unilaterally — it's a real behavioral choice.

## Tests to add

- The audit's own suggested test: two-step contract where step 1 returns a nonce and step 2
  requires that exact nonce. A campaign WITH the linkage should reach step 2 successfully; the
  same campaign WITHOUT the linkage should revert at step 2 (proving the fix actually changes
  outcome, not just plumbing).
- `from_step >= to_step` rejected (the ordering invariant) — construct a malformed linkage and
  assert it's skipped, not applied.
- Missing registry key (source step's call reverted, or `value_capture.rs` didn't capture that
  selector) — assert the step still executes with its original (unlinked) argument, per whichever
  missing-linkage policy is chosen above.

## What stays byte-identical

- `campaign.linkages.is_empty()` (the case for every campaign the planner produces today, since
  nothing populates `linkages` yet either — confirmed by the same grep that found zero consumers)
  → the new loop iterates zero times → no behavior change for any existing campaign.

## Out of scope

- Making the PLANNER populate `linkages` in the first place — this feature only makes the executor
  *honor* linkages if they exist. Whether/how `campaign_planner.rs` should start emitting
  `StepLinkage` entries (e.g., detecting a nonce/ID dependency between two ABI-matched steps) is a
  separate, larger feature.
- The `CampaignExecutionFrame` cross-cutting refactor — same note as 038/039.
