# Feature 039 — Record Post-Step, Not Pre-Step, Intermediate States (EO-02)

## Status
Ready to build. Source: PR #2 (EO-02, Medium-High). Independently verified against `executor.rs`
directly — exact line numbers below, not paraphrased from the PR.

## The gap (code-verified)

`executor.rs:172-198`, the prefix-steps loop:

```rust
for (i, step_ci) in steps.iter().enumerate().take(steps.len() - 1) {
    ...
    let (mut step_input, _) = step_ci.to_input(current_state.clone());   // :176 — INPUT uses current_state (pre-step)
    ...
    let res = self.vm.deref().borrow_mut().execute(step_ref, state);      // :183
    state.set_execution_result(res);                                     // :184
    // Capture intermediate state for oracle consumption
    intermediate_states.push(current_state);                             // :186 — pushes PRE-step state
    if state.get_execution_result().reverted {
        return Ok(ExitKind::Ok);
    }
    current_state = /* ...res.new_state... */;                           // :190-194 — NOW becomes post-step
    ...
}
```

`intermediate_states.push(current_state)` at line 186 runs **before** `current_state` is
reassigned to the post-execution result at lines 190-194. For a campaign `[S0, S1, S2]`, the
resulting vector holds: `[state before S0, state before S1]` (the loop only covers
`steps.len() - 1` = the prefix, not the final exploit step) — i.e., each step's *input* state, not
its *output* state. A consumer expecting `intermediate_states[i]` to mean "the state after step `i`
completed" (which is the natural reading of "intermediate states from multi-step campaign
execution" for any drift/divergence-style analysis) gets the wrong phase — off by one step in the
direction of "too early."

## Why this matters

Any oracle or future producer that inspects `ctx.campaign_intermediate_states[i]` to compare
"state after prime" vs. "state after lever" vs. "state after exploit" is comparing the wrong
snapshots — it would see "state before prime" vs. "state before lever," silently shifted one phase
earlier than intended. No current oracle in this codebase consumes
`ctx.campaign_intermediate_states` yet (checked: `OracleCtx::new`'s `campaign_intermediate_states`
parameter is threaded through but not read by any of the oracle files audited in the
producer-inventory pass) — so this is not YET causing an observed wrong answer, but it is a latent
correctness trap for whichever oracle/producer is the first to consume it, and the semantics should
be fixed before anything starts relying on them.

## What changes

### `src/executor.rs:172-198` — push after reassignment, not before

```rust
for (i, step_ci) in steps.iter().enumerate().take(steps.len() - 1) {
    crate::evm::middlewares::function_auth::set_campaign_step(Some(i));
    let (mut step_input, _) = step_ci.to_input(current_state.clone());
    if let Some(delta) = campaign.warps.iter().find(|(idx, _)| *idx == i).map(|(_, d)| d) {
        step_input.env.block.number += EVMU256::from(*delta);
        step_input.env.block.timestamp += EVMU256::from(*delta * 12);
    }
    let step_ref: &I = unsafe { &*(&step_input as *const EVMInput as *const I) };
    let res = self.vm.deref().borrow_mut().execute(step_ref, state);
    state.set_execution_result(res);
    if state.get_execution_result().reverted {
        return Ok(ExitKind::Ok);
    }
    current_state = unsafe {
        let generic_ref: &StagedVMState<Loc, Addr, VS, CI> = &state.get_execution_result().new_state;
        let concrete_ref: &EVMStagedVMState = &*(generic_ref as *const StagedVMState<Loc, Addr, VS, CI> as *const EVMStagedVMState);
        concrete_ref.clone()
    };
    // Feature 039 (EO-02): capture the POST-step state, matching the natural reading of
    // "intermediate state from multi-step campaign execution" — the state AFTER step i,
    // not before it. Moved to after the reassignment above and after the revert check, so a
    // reverted step contributes no post-state (consistent with the early-return already skipping
    // metadata publication for a reverted prefix step).
    intermediate_states.push(current_state.clone());
    if aposteriori {
        inflow_offsets.push(current_state.state.erc20_transfers.len());
    }
}
```

Note this reorders relative to today's code in one more way: the revert check now happens BEFORE
the push (today it's push-then-check-revert). This is intentional — a reverted step produced no
valid "post-step" state, so it shouldn't be recorded as one. Confirm this doesn't change
`inflow_offsets`' existing semantics (`aposteriori` push at line 196 today happens after the revert
check already, so this aligns the two pushes to the same ordering rather than leaving them
inconsistent with each other, which they currently are).

### Naming (optional, flag for decision)

The audit suggests renaming to `CampaignPostStepStates` if backward compatibility allows. Since
nothing currently consumes `CampaignIntermediateStates` (confirmed above), there is no serialized
corpus compatibility concern — this rename is safe and free. Recommend taking it, since
"intermediate" is exactly the ambiguous word that let the pre/post confusion happen in the first
place; "post-step" is unambiguous. If the team prefers minimal diff, keep the struct name and only
fix the ordering — functionally equivalent, just a documentation improvement forgone.

## Tests to add

- Three-step mock campaign where each step increments a distinct storage slot (matches the audit's
  own suggested test exactly). Assert `intermediate_states[i]`'s snapshot includes step `i`'s
  storage mutation, not just mutations from steps `0..i`.
- A revert case: step 1 of 3 reverts — assert `intermediate_states` has at most 1 entry (step 0's
  post-state only), not 2 (which today's pre-push ordering would have produced: pre-step-0 AND
  pre-step-1, even though step 1 never successfully completed).

## What stays byte-identical

- The final exploit step's handling (`executor.rs:200-293`) is untouched — this feature only
  touches the prefix-steps loop.
- Nothing currently reads `CampaignIntermediateStates`, so there is no existing consumer whose
  behavior could regress from this semantic fix.

## Out of scope

- Adding the initial pre-campaign state as `pre_states[0]` (the audit's fuller proposed shape,
  `pre_states`/`post_states` as two separate vectors) — not needed unless a future oracle
  specifically wants the very first state; can be added later without breaking this fix.
- The `CampaignExecutionFrame` cross-cutting refactor — same note as 038.
