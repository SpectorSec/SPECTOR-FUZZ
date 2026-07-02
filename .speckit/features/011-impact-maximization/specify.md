# Feature 011 — Impact Maximization

**Status:** Specified — **Part A + Part B SUPERSEDED BY Feature 015 (2026-07-02)**
**Owner:** Skyler
**Last updated:** 2026-07-02
**Sign-off:** Skyler 2026-06-29 — checkpoints 11.1–11.4, 11.6 ✓; 11.5 ◑ (TVL normalizer scoped as optional follow-on). Part A core = realized-ETH gradient; %-of-TVL metric deferred.

> **Superseded note (2026-07-02):** Parts A and B were specified here but never wired into
> the run loop (verified: empty grep `blood|amplif|ladder|scale_up`). They are realized as
> **Part 3 of Feature 015 (Reflexive Lever Pipeline)** — the realized-ETH ledger becomes the
> ledger-secant's *objective*, and the amplifier is built there so it can act on a *promoted*
> reflexive lever (011 alone could only tune amounts already in the frame, which for reflexive
> exploits like yDAI never contain the lever). Build/track the amplifier in 015, not here. The
> %-of-TVL severity metric (11.5) remains an independent optional follow-on.

---

## Overview

SPECTOR-FUZZ today *detects* fund loss but does not *maximize* it. Value is handled by
three disconnected layers, and the financial-impact pursuit that distinguishes us from
Fuzzland's open-source baseline is incomplete:

- **Layer 1 — `TokenBalanceFeedback`** (weapons dictionary; `src/evm/feedbacks.rs:180`).
  The named "fund-extraction gradient." It climbs `best_inflow` — the max attacker inflow
  **per token, in raw token UNITS** — and votes 5× for the infant state on a new ceiling.
  It is (a) **value-blind** (ranks token quantity, never ETH/USD; a mountain of a thin-
  liquidity token out-votes a smaller blue-chip position) and (b) **passive** (it only
  re-prioritizes scheduling; it never actively pushes amounts upward).
- **Layer 2 — liquidation fraction** (`src/evm/oracles/erc20.rs:219`, mutator
  `src/evm/mutator.rs:937`). `LIQ_PERCENT = 10` → dumps **100% or 0%**, binary,
  **slippage-blind**: a single full-balance dump can realize *less* ETH than a staged exit.
- **Layer 3 — the bug gate** (`src/evm/oracles/erc20.rs:276`). A **flat** `earned − owed >
  0.01 ETH` threshold — Fuzzland original. No magnitude gradient; the reported `net_eth` is
  whatever the triggering execution happened to realize. This is *correct as a detector* and
  deliberately left as-is; it is weak only as a *maximizer*, which is what this feature adds
  above it.

**Why existing weapons are insufficient.** `TokenBalanceFeedback` exists but optimizes the
wrong unit and never amplifies. The "value-capture middleware" some notes refer to
(`ValueCaptureMiddleware`, Feature 001) is **return-value harvesting for campaign input
linkage** (`observed_values`, `{target}_{selector}_return`) — a name collision; it has
nothing to do with financial-impact magnitude. No "blood in the water" amplifier exists
anywhere in the codebase (verified: no `blood`/`amplif`/`doubling`/`scale_up` and no
amount-scaling `U256::MAX` in the mutators — the only `U256::MAX` there is the Feature 008
secant/concolic CMP solver).

**This feature has two parts:**

- **Part A — Value-denominated extraction gradient** (EXTENSION of `TokenBalanceFeedback`).
  Rank by **realized ETH value** via the validated `liquidate_via_engine` / `resolveToEth`
  multi-route engine (the same path the loot oracle uses), summed across tokens — not raw
  per-token units. Optionally normalize by pool TVL to emit "% of TVL drained" as a severity
  metric (the TVL idea).
- **Part B — Blood-in-the-water amplifier** (NEW capability; LibAFL `Mutator`/stage). When a
  sequence registers a new ETH-value ceiling, **actively** scale the profitable
  transaction's amount operands upward (geometric ladder and/or secant-found optimum) and
  re-run; keep the variant that realizes more ETH; back off on revert (the liquidity/
  slippage ceiling). Conceptually `liquidate_via_engine` in a doubling-down loop, but ranked
  by Part A so it chases ETH, not token-unit mirages.

## Why This Matters

- **Yearn (our 69× baseline)** — the validated PoC realizes **15,562 USDC**. Against the
  pool's TVL that is a sliver. If the true extractable ceiling is higher, today nothing
  pushes the borrow/deposit amounts toward it; the run stops at the first threshold cross.
- **bZx (2020, ~$8M across two attacks)** — impact scaled directly with borrow size; a
  fixed-amount fuzzer finds *an* exploit, not the *maximal* one. Amplifying the borrow on a
  found path is exactly the bZx escalation.
- **Cream Finance ($130M, 2021)** — oracle manipulation profit was a function of position
  size; the difference between "a finding" and "the bounty number" is the amount ladder.

## Success Criteria

This feature is worth building if and only if:

1. On the Yearn fork, the reported **realized-ETH ceiling with the amplifier ON is strictly
   greater** than with it OFF (a measured delta, same seed/time budget) — or provably already
   at the liquidity ceiling.
2. The gradient ranks by **ETH value, not token units**: a unit test with two synthetic
   tokens (more units of a cheap token vs fewer units of an expensive one) shows the
   higher-ETH path wins the vote.
3. **Zero code path when the flag is off** (constitution rule 1): an existing run with no new
   flag produces byte-equivalent results (regression test).
4. The amplifier **terminates and is overflow-safe**: it backs off cleanly on revert /
   liquidity ceiling, never loops unbounded, and amplified amounts (up to `type(uint256).max`)
   never overflow the `EVMU512` earned/owed accounting or trip the depth cap pathologically.

## Out of Scope

- **Cross-protocol contagion** — Feature 006.
- **Changing the oracle bug-fire boolean** — the `0.01 ETH` gate (erc20.rs:276) stays; this
  feature improves the *gradient and amount search above* it, not the detection threshold.
- **Full staged/partial-liquidation search** — Part B may scale amounts, but a general
  partial-liquidation-percentage optimizer is a possible follow-on, noted not built.
- **Return-value linkage** — already handled by Feature 001 `ValueCaptureMiddleware`; this
  feature does not touch `observed_values`.

## Investigation Checkpoints

### Checkpoint 11.1 — How `TokenBalanceFeedback` currently ranks  ✓ RESOLVED
**Files:** `src/evm/feedbacks.rs:233-289`, `src/fuzzers/evm_fuzzer.rs:381-388`
**Question:** What unit does the gradient climb, and how is it wired?
**Evidence:** `is_interesting` sums `*value` from `result.new_state.state.erc20_transfers`
for `to ∈ attackers` into `inflow_by_token` (**raw token units, per token**); a new per-token
max sets `new_ceiling`, which votes `INFANT_STATE_INITIAL_VOTES * 5`. Wired via
`balance_feedback = TokenBalanceFeedback::new(attackers, infant_scheduler.clone())` →
`EagerOrFeedback::new(cmp_feedback, balance_feedback)` as `infant_feedback`. **Confirmed
value-blind and passive.**

### Checkpoint 11.2 — Can a Feedback call `resolveToEth` / `liquidate_via_engine`?  ✓ RESOLVED
**Files:** `src/evm/feedbacks.rs:45,90,106`, `src/fuzzers/evm_fuzzer.rs:379-384`, `src/evm/vm.rs`
**Question:** Can `TokenBalanceFeedback` hold an executor ref and call the engine inside
`is_interesting` without a `RefCell` double-borrow?
**Evidence:** `CmpFeedback` holds `evm_executor: Rc<RefCell<EVMExecutor<...>>>` (feedbacks.rs:45)
and already calls `self.evm_executor.deref().borrow_mut().reexecute_with_middleware(...)` *inside*
its own `is_interesting` (lines 90, 106). The pattern is proven. `TokenBalanceFeedback` is
constructed at evm_fuzzer.rs:384 where `evm_executor_ref` is in scope, so it can take the same
`Rc<RefCell<EVMExecutor>>` and call `liquidate_via_engine`. **Borrow safety:** the only live
borrow during `TokenBalanceFeedback::is_interesting` is `state.get_execution_result()` — a
borrow of `state`, a *different object* from the executor `RefCell` — so the engine's
`borrow_mut()` cannot conflict. Valuation runs on the completed post-execution result, not the
oracle's mutation window. **No conflict.**

### Checkpoint 11.3 — Where are the amplifiable amount operands in `EVMInput`?  ✓ RESOLVED
**Files:** `src/evm/input.rs:170-205`, `src/evm/abi.rs:394,414,637-728`
**Question:** Which fields encode the call amounts, and how are uint256 args mutated?
**Evidence:** Two operand sites. (1) **`txn_value: Option<EVMU256>`** on `EVMInput` — native
msg.value. (2) **uint256 ABI args** = the `A256` type (abi.rs:637) with
`inner_type: A256InnerType::Uint` (abi.rs:661); the value lives in `A256.data` and is read as
`U256::try_from_be_slice(&self.data)` (abi.rs:728), written via `set_bytes` (abi.rs:714). The
existing mutation entry point is `BoxedABI::mutate_with_vm_slots` (abi.rs:394), which downcasts
to `A256` (abi.rs:414). **The amplifier extends this path** (constitution rule 3): walk
`input.data` (BoxedABI), select `A256` args where `inner_type == Uint`, read the current U256,
scale it (saturating ×factor, or `U256::MAX`), write back via `set_bytes`. No parallel system.

### Checkpoint 11.4 — How does the amplifier learn *which* input was profitable?  ✓ RESOLVED
**Files:** `src/scheduler.rs:28,143,237-241`, `src/evm/mutator.rs:623,649`,
`src/evm/concolic/concolic_stage.rs:29,74`
**Question:** What is the feedback→amplifier hand-off?
**Evidence:** Two complementary, already-existing mechanisms.
- **Scheduling (passive):** `vote(state, idx, amount)` (scheduler.rs:28) increments
  `votes_and_visits` (scheduler.rs:143); selection scores by `votes/visits` (scheduler.rs:240).
  So Part A's heavier (ETH-weighted) vote already biases re-selection of the profitable state —
  no new plumbing needed for prioritization.
- **Metadata (active):** the mutator already reads typed metadata from `state.metadata_map()` —
  e.g. `TopologyHints` at mutator.rs:649, and the Feature 008 secant inserts/reads its own
  metadata throughout (`state.metadata_map_mut().insert(secant)`). **Pattern for Part B:** Part A
  writes an `AmplifyHint` (profitable input handle + `A256` operand offsets + current ETH ceiling)
  into `state.metadata_map_mut()`; Part B reads it in `mutate` (mutator.rs:623), mirroring the
  `TopologyHints`/secant flow.
- **Stage option:** `ConcolicStage` (concolic_stage.rs:29, `impl Stage` / `fn perform` at :74,
  Feature 009) is the in-tree template for a dedicated **re-run loop** — a better fit for Part B's
  "amplify → execute → keep-best → back-off" loop than a single `mutate()` call.
**Decision deferred to plan.md** (mutator branch vs dedicated Stage); both mechanisms confirmed
available.

### Checkpoint 11.5 — TVL / reserve data availability for the normalizer  ◑ PARTIALLY RESOLVED
**Files:** `src/evm/oracles/erc20.rs:152-163`, `src/evm/tokens/v2_transformer.rs`
(`UniswapPairContext.initial_reserves`), `src/evm/onchain/flashloan.rs:444` (`prev_reserves`)
**Question:** Can pool reserves feed a "% of TVL" metric without a per-exec fork call?
**Evidence:** `UniswapPairContext` already carries `initial_reserves: (EVMU256, EVMU256)` (set
once at registration, erc20.rs:163-175), and `FlashloanData.prev_reserves:
HashMap<EVMAddress,(EVMU256,EVMU256)>` already caches reserves. So a TVL baseline **is** obtainable
from cached data without a fresh call. **Still open:** whether to denominate TVL at the route's
WETH leg (clean, single number) or sum multi-hop legs, and whether stale `initial_reserves` is
accurate enough post-manipulation. **This is the TVL-normalizer (Part A optional sub-feature);
it does not block the core ETH-gradient or Part B** — resolve fully in plan.md or defer the TVL
metric to a follow-on.

### Checkpoint 11.6 — Overflow / revert safety of amplified amounts  ✓ RESOLVED
**Files:** `src/evm/onchain/flashloan.rs:49-53` (`scale!()`), `:354,:411` (earned/owed),
`:438-439` (EVMU512 types), `src/evm/oracles/erc20.rs:232,255` (backup/restore)
**Question:** Does scaling amounts to `type(uint256).max` overflow `earned/owed`, and does an
amplified revert unwind cleanly?
**Evidence:** `scale!() = EVMU512::from(1_000_000)` = **1e6** (correcting an earlier note that
assumed 1e24). `earned`/`owed` are `EVMU512`. Worst-case bound: `U256::MAX` (≈1.16e77) `× 1e6`
≈ **1.16e83**, against `EVMU512::MAX` ≈ **1.34e154** — headroom ~1e71; summing would need ~1e71
max-value transfers to overflow. **Cannot overflow in practice.** Moreover, ERC20-amount
amplification does not even touch `earned` directly (earned counts *native* value_transfer to a
`has_caller`, flashloan.rs:411); amplified token amounts flow through liq→sell→ETH-forward,
**bounded by real pool liquidity (slippage)**, so realized `earned` stays far below the ceiling
regardless. **Back-off:** the loot path already snapshots `backup` and restores on failure
(erc20.rs:232,255); an amplified re-run that reverts is discarded, keeping the prior best.
**Overflow-safe; back-off path exists.**

## Risks

- **Corpus thrash** — the amplifier could spend all energy re-running one seed. Mitigate:
  bounded ladder, fire only on a *new* ceiling, cap re-runs per seed.
- **Valuation overhead** — calling the engine to ETH-value every execution is expensive.
  Mitigate: value only when raw inflow changed (cheap pre-filter), cache per token.
- **`RefCell` borrow conflicts** — engine call from feedback during the oracle's state-mutation
  window (Checkpoint 11.2).
- **Amplified amounts interacting with this session's depth-cap / overflow fixes** — must
  respect, not bypass them (Checkpoint 11.6).
- **Constitution rule 2** — extending `TokenBalanceFeedback` must not change behavior when the
  new flag is off (the existing token-unit gradient must remain the default path).

## Open Questions

- Value **every** token inflow or only the dominant one each execution? (accuracy vs perf)
- Amplifier amount search: fixed geometric ladder `{2×, 10×, 100×, MAX}` **or** adaptive —
  reuse the **Feature 008 snapshot-secant** method to find the slippage-bound optimum
  (where dETH/damount → 0) instead of blind doubling? The secant is already in-tree.
- Does Part B belong in `mutator.rs` (a new mutation branch) or as a dedicated **stage**
  (mirroring Feature 009's `concolic_stage`)? A stage isolates the re-run loop cleanly.
- One CLI flag for both parts, or separate (`--impact-gradient-eth` vs `--amplify`)? Part A
  is a low-risk default-candidate; Part B is more aggressive — separability may be worth it.
