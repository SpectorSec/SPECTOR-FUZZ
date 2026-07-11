# Execution Ordering Audit — SPECTOR-FUZZ Overlay Mechanisms

Date: 2026-07-10
Scope: `.speckit`, `.speckit/research`, and SPECTOR-FUZZ mechanisms layered above revm/LibAFL (campaign planning/execution, topology hints, producers/oracles, promotion metadata). This audit intentionally does not assess revm or LibAFL internals.

## Executive Summary

SPECTOR-FUZZ's overlay is explicitly built around ordering: campaign steps are planned as `Borrow → Prime → Lever → Exploit`, then executed atomically while producers/oracles interpret the resulting trace and metadata. The highest-risk bugs are therefore not plain reachability bugs; they are places where metadata, probes, or planned edges are observed in a different order than the campaign actually executed.

I found four execution-ordering issues worth prioritizing:

1. **Stale campaign metadata can be consumed by later non-campaign executions.** Campaign execution writes `CampaignIntermediateStates`, `CampaignWarpStates`, and sometimes `CampaignInflowBoundaries` into global fuzzer state metadata, but the non-campaign path does not clear them. Feedback then unconditionally reads those metadata entries for every successful execution.
2. **Campaign intermediate-state snapshots are captured before each prefix step, not after it.** Consumers asking for “state drift across the entire chained sequence” receive prefix/pre-step snapshots and never receive the final post-step chain as an ordered vector.
3. **Controlled temporal probes execute inside the real campaign event before the exploit step.** If `execute` or middleware has side effects outside the returned staged state, the probe order can contaminate the real exploit execution and the trace/producers that follow it.
4. **`CampaignSequence.linkages` defines ordered output-to-input dependencies but the executor never applies them.** This makes some planned sequences look structurally ordered while the dynamic execution still uses unlinked ABI-mutated arguments.

## Finding EO-01 — Stale Campaign Metadata Bleeds Into Later Executions

**Severity:** High

**Type:** execution-ordering / attribution contamination

**Affected mechanisms:** campaign executor metadata publication, oracle feedback context construction, a-posteriori promotion, temporal skimming metadata.

### Evidence

Campaign execution publishes campaign context into the long-lived fuzzer state metadata after the final campaign step:

```rust
state.add_metadata(CampaignIntermediateStates { states: intermediate_states });
state.add_metadata(CampaignWarpStates { warps: campaign.warps.clone() });
...
state.add_metadata(crate::evm::planner::CampaignInflowBoundaries { offsets: inflow_offsets });
```

The single-input path only sets the current campaign step to `None` and executes the input; it does not remove or replace any campaign metadata:

```rust
crate::evm::middlewares::function_auth::set_campaign_step(None);
let res = self.vm.deref().borrow_mut().execute(input, state);
state.set_execution_result(res);
```

Feedback then reads `CampaignIntermediateStates` and `CampaignWarpStates` from state metadata for every non-reverted execution, regardless of whether the current input is a campaign:

```rust
let campaign_intermediate_states = state.metadata_map().get::<CampaignIntermediateStates<...>>().map(|m| m.states.clone());
let temporal_warps = state.metadata_map().get::<CampaignWarpStates>().map(|m| m.warps.clone());
```

### Why This Is an Execution-Ordering Bug

The oracle context for execution `N+1` can contain campaign metadata from execution `N`. That means producers/oracles may attribute a single transaction's effects to an older ordered campaign frame. The execution order observed by the analysis layer becomes:

```text
old campaign metadata → new single execution → oracle analysis
```

instead of:

```text
new single execution → oracle analysis with no campaign frame
```

This can create false phase attribution, stale warp attribution, and stale a-posteriori step-boundary interpretation.

### Suggested Fix

At the beginning of `run_target`, or at least on the non-campaign path and before campaign execution starts, clear campaign-scoped metadata:

- `CampaignIntermediateStates`
- `CampaignWarpStates`
- `CampaignInflowBoundaries`

If LibAFL metadata removal is awkward, write explicit empty metadata for non-campaign executions and make feedback additionally gate on `EVMInput.campaign.is_some()` before reading campaign-specific metadata.

### Regression Test

Add a unit/integration test that:

1. Executes a campaign with a warp and/or aposteriori boundaries.
2. Executes a plain `EVMInput` immediately afterward.
3. Asserts feedback receives `None`/empty campaign metadata for the plain input.

## Finding EO-02 — Intermediate States Are Recorded Before Steps, Not After Steps

**Severity:** Medium-High

**Type:** phase ordering / state-drift misobservation

**Affected mechanisms:** campaign execution, oracles that inspect `campaign_intermediate_states`, temporal/drift oracles.

### Evidence

The executor initializes `current_state` from the campaign input state, executes all prefix steps, and pushes `current_state` into `intermediate_states` immediately after the VM call but before replacing `current_state` with `res.new_state`:

```rust
let mut current_state: EVMStagedVMState = evm_input.sstate.clone();
...
let res = self.vm.deref().borrow_mut().execute(step_ref, state);
state.set_execution_result(res);
// Capture intermediate state for oracle consumption
intermediate_states.push(current_state);
if state.get_execution_result().reverted { ... }
current_state = state.get_execution_result().new_state.clone();
```

The oracle context describes these states as “Intermediate states from multi-step campaign execution” that allow inspection of drift across the chained sequence.

### Why This Is an Execution-Ordering Bug

For a campaign `[S0, S1, S2]`, the vector currently contains the state *before* step 0, then before step 1, etc. It does not contain the post-step state at the matching index. For a 3-step campaign, an oracle expecting `intermediate_states[i]` to represent the result after step `i` will read the wrong phase.

This is especially risky for drift-oriented checks: a temporal skim oracle that compares “after prime” vs “after exploit” can accidentally compare “before prime” vs “before lever/exploit.”

### Suggested Fix

Make the ordering contract explicit and enforce it in code. Recommended representation:

- `pre_states[0]` if the initial state is needed.
- `post_states[i]` for the state after step `i` completes.
- Include the final exploit post-state or document why it is only available via `state.get_execution_result().new_state`.

At minimum, move `intermediate_states.push(...)` after `current_state = new_state.clone()` and rename the metadata to `CampaignPostStepStates` if compatibility permits.

### Regression Test

Create a three-step mock where each step increments a distinct storage slot. Assert that the state snapshot at index `i` includes the mutation made by step `i` and not just mutations from prior phases.

## Finding EO-03 — Controlled Temporal Probes Run Inline Before the Real Exploit Step

**Severity:** Medium

**Type:** probe/execution ordering contamination

**Affected mechanisms:** temporal skimming, controlled-probe warp refinement, middleware/producers that observe execution-local globals.

### Evidence

When a temporal warp exists, the executor refines it by executing the last campaign step twice at controlled warps before executing the real exploit step:

```rust
let _ = self.vm.deref().borrow_mut().execute(pr, state); // probe 1
...
let _ = self.vm.deref().borrow_mut().execute(pr, state); // probe 2
...
let res = self.vm.deref().borrow_mut().execute(last_ref, state); // real step
state.set_execution_result(res);
```

The probes intentionally use the same prefix state, which is good for measuring temporal slope, but they still run through the same VM/executor/middleware stack as normal executions.

### Why This Is an Execution-Ordering Bug

The logical campaign order is:

```text
prefix steps → exploit step
```

The actual VM call order under temporal skimming is:

```text
prefix steps → exploit probe at warp A → exploit probe at warp B → exploit step at warp C
```

If any middleware/global telemetry is not fully reset between probe runs and the real exploit run, producers/oracles can observe probe artifacts as if they happened before the exploit in the same campaign. The code resets temporal comparison globals, but the risk is broader than temporal globals: function-auth attribution, transfer logs, trace-local side channels, objective globals, and execution counters can all become probe-observable unless they are explicitly isolated.

### Suggested Fix

Treat controlled probes as isolated dry-runs:

- Execute probes against a cloned fuzzer/VM state or a dedicated “probe mode” that suppresses producer/oracle-visible side effects.
- Reset all execution-local middleware/global maps after probes, not only temporal comparison state.
- Do not leave `state.get_execution_result()` pointing at a probe result if an early return or panic path is introduced later.

### Regression Test

Add a mock middleware counter/trace marker and assert that after temporal probe refinement, only the real exploit step is visible to feedback/oracle context.

## Finding EO-04 — Declared Step Linkages Are Not Applied During Execution

**Severity:** Medium

**Type:** planned-order dependency lost at execution time

**Affected mechanisms:** `CampaignSequence.linkages`, value-capture sequencing, reachability through dynamic dataflow.

### Evidence

`CampaignSequence` defines ordered data dependencies from one step's output registry to a later step's parameter:

```rust
pub struct StepLinkage {
    pub from_step: usize,
    pub from_registry_key: String,
    pub to_step: usize,
    pub to_param_index: usize,
}
...
pub struct CampaignSequence {
    pub steps: Vec<ConciseEVMInput>,
    pub linkages: Vec<StepLinkage>,
    ...
}
```

But the executor iterates over `campaign.steps`, calls `to_input(current_state.clone())`, and executes the result. No code in the campaign execution path reads `campaign.linkages` or mutates a target step's ABI arguments from prior step output.

### Why This Is an Execution-Ordering Bug

The data model says “step B depends on a value captured from step A,” but the dynamic execution never enforces that ordered dependency. The campaign can therefore be structurally ordered while semantically unlinked:

```text
plan:    A returns x → B(arg=x)
execute: A returns x → B(arg=random/mutated)
```

That is both an execution-ordering bug and a reachability bug when contracts require IDs, shares, nonces, round IDs, or quote outputs from earlier calls.

### Suggested Fix

Before executing each step, apply all linkages where `to_step == i` using values captured from completed prior steps. Enforce ordering invariants:

- `from_step < to_step`
- source key exists before target step executes
- ABI type/width conversion succeeds
- missing linkage should either skip campaign execution or mark the campaign invalid, not silently execute random arguments

### Regression Test

Construct a two-step contract where step 1 returns a nonce and step 2 requires that nonce. A campaign with a linkage should reach step 2; the same campaign without linkage should revert.

## Cross-Cutting Recommendation — Add an Explicit Campaign Execution Frame

Most issues above come from campaign-scoped data living in global fuzzer metadata without a per-execution frame boundary. Introduce a single `CampaignExecutionFrame` metadata value created fresh at the start of campaign execution and cleared/replaced for every `run_target` call:

```rust
struct CampaignExecutionFrame {
    execution_id: u64,
    is_campaign: bool,
    pre_states: Vec<EVMStagedVMState>,
    post_states: Vec<EVMStagedVMState>,
    warps_applied: Vec<(usize, u64)>,
    inflow_boundaries: Vec<usize>,
    probe_count: usize,
}
```

Feedback should only consume campaign fields when `is_campaign == true` and `execution_id` matches the current execution. That frame turns the implicit ordering contract into a concrete API and prevents stale metadata, probe bleed, and index ambiguity from recurring.
