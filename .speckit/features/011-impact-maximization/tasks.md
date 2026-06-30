# Feature 011 — Impact Maximization · Tasks (Phase 1: Part A — ETH-value gradient)

**Status:** In Progress — T1 ✅ (df1c3f9) · T2–T5 ✅ (af07921) · T6–T7 ✅ (tests green via `aggregate_eth_inflow` seam) · T8 (Lane-A Yearn measure) remaining — Skyler's deploy step
**Owner:** Skyler
**Last updated:** 2026-06-30
**Plan:** [`plan.md`](./plan.md) §2, §5, §7 · **Spec:** [`specify.md`](./specify.md) (SC-2, SC-3)

> Scope: **Phase 1 only** — the realized-ETH extraction gradient (Part A). The amplifier
> (Part B), `AmplifyHint`, and `ImpactAmplifierStage` are **not** in this phase; Part A's
> hint-write (plan §2.3) is deferred to Phase 2 so Phase 1 is a clean, independently
> measurable change. No code begins until this file is signed off (constitution rule 7).

---

## Task list

### T1 — Add reusable ETH-valuation helper *(additive; no behavior change)*
**File:** `src/evm/vm.rs` (right after `liquidate_via_engine`, :658)
- Add `pub fn value_token_inflow_eth(&mut self, caller, token, amount, state) -> Option<EVMU512>`
  on `EVMExecutor`: snapshot `host.evmstate` (mirror erc20.rs:232 `backup`), record
  `flashloan_data.earned` **before**, call `liquidate_via_engine`, record `earned` **after**,
  **always restore** the snapshot (measurement-only), return `Some(after - before)` if the
  liquidation succeeded else `None`.
- **CORRECTION (a):** the helper does **not** rewire the loot oracle. The oracle's
  commit-and-aggregate semantics (multiple liquidations accumulating into shared `earned`,
  successes kept, only failures restored — erc20.rs:227–262) differ from the feedback's
  measure-then-restore; rewiring would risk the validated 69× loot path. The shared "one
  valuation path" (constitution rule 3) is `liquidate_via_engine` itself, which both already use.
- **CORRECTION (b):** return the **raw `EVMU512` earned-delta**, not de-scaled wei. `earned`
  is `EVMU512` (flashloan.rs:439) scaled by `scale!()`; the oracle's display de-scale is
  internally inconsistent. Part A only needs to *rank* inflows ⇒ a consistent scale suffices.
- Reads the same observable field (`host.evmstate.flashloan_data.earned`) the oracle trusts
  post-liquidation, so the measurement matches the oracle's notion of realized value.
- **Acceptance:** builds green; oracle code byte-unchanged ⇒ loot path cannot regress; helper
  is `pub`, ready for T4 to call. (Helper is uncalled until T4 — `pub fn` so no dead-code warn.)

### T2 — Config + CLI flag `--impact-eth-gradient` (default false)
**File:** `src/evm/config.rs` (Config struct) + CLI layer
- Add `pub impact_eth_gradient: bool`, default `false`, plumbed from the CLI arg.
- **Acceptance:** flag parses; absent ⇒ `false`; no other behavior reachable yet.

### T3 — Extend `TokenBalanceFeedback` struct + constructor
**File:** `src/evm/feedbacks.rs:191–208`
- Add fields: `eth_gradient: bool`, `evm_executor: Option<Rc<RefCell<EVMExecutor<...>>>>`,
  `best_eth_inflow: HashMap<EVMAddress, EVMU256>` (or a single summed `best_eth: EVMU256` — see T4).
- Change `new(...)` signature to `new(attackers, scheduler, eth_gradient, evm_executor)`.
- **Acceptance:** compiles; `eth_gradient=false, evm_executor=None` reproduces today's struct state.

### T4 — `is_interesting` ETH-valuation branch
**File:** `src/evm/feedbacks.rs:233–289`
- Keep the existing raw-unit `inflow_by_token` + `new_ceiling` block **as the pre-filter** (OQ1).
- **When `self.eth_gradient` AND a token's raw ceiling rose:** call
  `self.evm_executor.as_ref().unwrap().deref().borrow_mut().value_token_inflow_eth(attacker, token, inflow, state)`
  (T1 helper); sum ETH across attacker-held tokens; compare against `best_eth`; the
  **vote uses the ETH ceiling** rather than the token-unit ceiling.
- **When `self.eth_gradient` is false:** behavior is byte-identical to today (early structural
  branch; the executor ref is `None` and never touched).
- **Borrow safety:** only `state.get_execution_result()` borrows `state`; engine `borrow_mut()`
  is on the executor `RefCell` (distinct object). Mirror `CmpFeedback` (feedbacks.rs:90,106).
- **Acceptance:** SC-2 unit test (T7) passes; flag-off path unchanged.

### T5 — Wire the feedback at the construction site
**File:** `src/fuzzers/evm_fuzzer.rs:384`
- `let eth_engine_ref = config.impact_eth_gradient.then(|| evm_executor_ref.clone());`
- `TokenBalanceFeedback::new(attackers, infant_scheduler.clone(), config.impact_eth_gradient, eth_engine_ref)`
- **Acceptance:** compiles; `EagerOrFeedback` wiring (line 388) unchanged.

### T6 — Regression guard (SC-3: zero code path when off)
- Run a known seed with `--impact-eth-gradient` absent; diff corpus/oracle output against
  pre-feature `main`. Must be **byte-equivalent**.
- **Acceptance:** no diff. (This is the constitution-rule-1/2 gate.)

### T7 — Unit test (SC-2: ranks ETH, not units)
**File:** `src/evm/feedbacks.rs` (test module)
- Two synthetic tokens: many units of a cheap token vs few units of an expensive one (stub/mock
  the `value_token_inflow_eth` rate). Assert the higher-**ETH** path produces the higher vote /
  `is_interesting == true` on the expensive path even when its token-unit count is lower.
- **Acceptance:** test passes; documents the value-blind→value-aware behavior change.

### T8 — Measure on Yearn fork (SC-1 precursor; informational for Phase 1)
- **Lane A** (Skyler deploys): same seed + budget, `--impact-eth-gradient` ON vs OFF; record the
  realized-ETH ceiling each way. Phase 1 does not *require* a strict increase (that's the
  amplifier's job, Phase 2) — but the ETH-ranked run should not regress the loot, and the number
  is the baseline Phase 2 must beat.
- **Acceptance:** measurement recorded in this file; no loot regression vs OFF.

---

## Out of this phase (→ Phase 2)
- `AmplifyHint` struct + `impl_serdeany!` (plan §4)
- Part A's `AmplifyHint` write on new ETH ceiling (plan §2.3)
- `ImpactAmplifierStage` + ladder + back-off (plan §3)
- `--amplify` flag (plan §5)

## Sequencing
T1 → T2 → T3 → T4 → T5 (build order), then T6 (regression) + T7 (unit) gate the phase,
T8 is the on-fork measurement. T1 is independently mergeable (pure refactor) if we want an
early commit point.
