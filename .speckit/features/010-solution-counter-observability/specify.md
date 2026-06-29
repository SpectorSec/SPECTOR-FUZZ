# Feature 010 — Solution-Counter Observability (wire bugs into the board)

**Status:** Spec (not implemented)
**Owner:** TBD
**Last updated:** 2026-06-29
**Why:** You cannot tell from the live board whether the fuzzer found anything — "objectives"
sits at 0 even when bugs are found. This wires ItyFuzz's bug path into LibAFL's objective
counter so the board reflects reality.

---

## 1. Root cause (verified from source)

Bugs are reported entirely through ItyFuzz's own path; the LibAFL objective counter is never
fed. In `fuzzer.rs`, `ExecuteInputResult::Solution` branch (~548-627):
- registers `BugMetadata.register_corpus_idx` (:553)
- minimizes, prints `😊😊 Found vulnerabilities!` (:568), writes `vuln_info.jsonl` + `vulnerabilities/`
- `if !RUN_FOREVER { exit(0); }` (:623), then returns.

It **never calls `state.add_solution`/`solutions_mut().add`** and **never fires
`Event::Objective`**. The board's "objectives" = LibAFL solution count / objective events →
**always 0 by construction.** Compounding: normal mode `exit(0)`s on the first bug (dies before
the next ~1s stats print); `RUN_FOREVER` keeps going but still never increments.

**Consequence:** "objectives: 0" is cosmetic, not a signal. Real ledger = stdout `😊😊`,
`vuln_info.jsonl`, `vulnerabilities/`, `BugMetadata`/`ORACLE_OUTPUT`.

## 2. Goal

Make the live board's objective counter reflect actual bugs found — so a glance answers "did it
find anything," especially in `RUN_FOREVER`/campaign runs. Strictly additive; keep the existing
oracle/jsonl/BugMetadata path untouched.

## 3. Design

In the `ExecuteInputResult::Solution` branch, **before** the `if !RUN_FOREVER { exit(0) }`
(`fuzzer.rs:~623`), add:

1. **Record the solution in LibAFL state** so `state.solutions().count()` ticks:
   ```rust
   // state already satisfies HasSolutions (see fuzz_one where-clause, fuzzer.rs:377)
   let sol_tc = Testcase::new(input.clone());
   state.solutions_mut().add(sol_tc)?;   // increments objective corpus count
   ```
2. **Fire an objective event** so the monitor/board updates immediately (not just on next tick):
   ```rust
   manager.fire(state, Event::Objective {
       objective_size: state.solutions().count(),
       // + time/executions fields per LibAFL Event::Objective signature in this version
   })?;
   ```
3. Leave everything else (BugMetadata, ORACLE_OUTPUT, println, jsonl, minimizer, exit/return)
   exactly as-is.

Result: normal mode shows `objectives: 1` on the board the instant before it exits;
`RUN_FOREVER`/campaign mode accumulates a live count across finds.

## 4. Integration points
- `src/fuzzer.rs` — Solution branch (~548-623); add the two calls above before exit.
- Verify the solutions corpus is configured on the state (ItyFuzz state implements `HasSolutions`;
  confirm `solutions_mut().add` is backed by a real corpus, e.g. `OnDiskCorpus`/`InMemoryCorpus`,
  in `evm_fuzzer.rs` state construction. If the solutions corpus is a no-op/None, add an
  `InMemoryCorpus` for solutions — minimal).
- Confirm `Event::Objective` field signature against the pinned LibAFL version (objective_size +
  the version's required fields).

## 5. Acceptance / validation
- Run a known-vuln target (e.g. an existing DeFiHackLabs fixture that ItyFuzz finds):
  board shows `objectives: 1` (or N for `RUN_FOREVER`) at/just before the `😊😊` print.
- `RUN_FOREVER` multi-bug run: objective count increments per distinct find; matches
  `wc -l vuln_info.jsonl` (or BugMetadata count).
- No behavior change to single-bug mode beyond the counter showing 1 before exit; no perf impact
  (fires only on a solution, which is rare).

## 6. Notes / scope
- Low risk, additive, high observability payoff. Reasonable to ship default-ON (not feature-gated)
  since it only runs on a found solution.
- De-dup consideration: if the same bug can fire multiple times in `RUN_FOREVER`, optionally key
  the solution add on `BugMetadata` bug_idx to avoid double-counting the same vuln (cosmetic; the
  jsonl already appends per fire). Decide based on whether the board should show "distinct vulns"
  or "solution events."
- Out of scope: changing oracle detection, the exit-on-first-bug default, or the jsonl format.

## 7. Interim (until implemented)
To know if a run found anything *right now*, watch the real ledger, not the board:
`tail -f <work_dir>/vuln_info.jsonl`  or grep stdout for `Found vulnerabilities`.
