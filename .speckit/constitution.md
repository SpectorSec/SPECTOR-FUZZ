# ItyFuzz Enhancement Project — Constitution
**Version:** 1.0  
**Date:** 2026-06-12  
**Scope:** Extensions to github.com/fuzzland/ityfuzz (master branch)

---

## What This Document Is

This constitution defines the non-negotiable constraints for every enhancement built in this project. No implementation plan is valid if it violates a constraint here. If a proposed design conflicts with this document, the constitution wins — or the constitution is formally amended with a written rationale before the design proceeds.

---

## 1. Language and Toolchain

- **Language:** Rust, stable toolchain only (version pinned in `rust-toolchain.toml` in the ItyFuzz repo)
- **Build:** Cargo. All code must compile with `cargo build --locked` — no dependency additions without explicit justification and lock file update
- **Style:** Follow existing codebase conventions (no reformatting existing code as a side effect of an enhancement PR)

---

## 2. Core Dependencies — Do Not Fight These

These libraries define the architecture. Enhancements must work with them, not around them.

| Dependency | Role | Constraint |
|---|---|---|
| **LibAFL** | Fuzzing backbone (corpus, scheduler, mutator, stage system) | All new fuzzing primitives must implement LibAFL traits — no parallel systems |
| **revm** | EVM executor with interpreter hooks | Instrumentation must use revm's existing hook system (`on_step`) — no forking revm |
| **Z3** | Constraint solving (concolic module) | Already in use — new constraint-based features should extend `concolic_host.rs`, not add a second solver |
| **LibAFL corpus** | Infant state corpus and transaction corpus | State storage must go through `IndexedCorpus` — no separate in-memory structures outside LibAFL's lifecycle |

---

## 3. Performance Constraints — Hard Limits

The paper's core value proposition is **second-level response time** for on-chain auditing. No enhancement may regress this.

- **Baseline:** ItyFuzz covers ~all instructions in the B1 benchmark (57 ERC20 contracts) within 10 seconds
- **Requirement:** Any new feature, when disabled via its flag, must produce identical benchmark results to the unmodified baseline
- **Requirement:** Any new feature, when enabled, must show a measurable improvement in the target metric (coverage, vulnerability detection time, or memory usage) that justifies its overhead
- **Measurement:** Every feature ships with a reproducible benchmark script targeting at minimum the B1 dataset

---

## 4. Opt-In Architecture — No Silent Behavior Changes

Smart contract fuzzers are used in production auditing pipelines. Unexpected behavior changes can cause missed vulnerabilities or false negatives in CI.

- Every enhancement must be **disabled by default**
- Every enhancement must be **activatable via a CLI flag** (following existing ItyFuzz CLI patterns in `src/evm/config.rs`)
- When disabled, the code path must be entirely bypassed — not just a no-op that still runs

---

## 5. No Breaking Changes to Existing Behavior

- Existing fuzzing runs that do not use new flags must produce statistically equivalent results (same coverage distribution, same vulnerability detection rate within measurement noise)
- The on-chain mode must continue to work after any offline-mode enhancement
- The Move VM module must not be broken by EVM-specific changes

---

## 6. Testing Requirements

Every feature must ship with:
1. **Unit tests** covering the new algorithm's core logic (isolated from EVM execution)
2. **Integration test** using at least one contract from the existing `tests/` directory that validates the enhancement's claimed benefit
3. **Regression test** confirming the feature produces no change when disabled

No PR moves to implementation without a written testing plan in the feature's `plan.md`.

---

## 7. Documentation Requirements

- Every new CLI flag must be documented in the flag's help string
- Every new algorithm must have a single-paragraph explanation in its source file's module docstring explaining *why* it exists (the problem it solves), not *what* it does (the code already shows that)
- The feature's `specify.md` is the permanent decision log — it must be updated if the implementation deviates from the original specification

---

## 8. Investigation Gate — Specific to This Project

This project has an unusual constraint: **three of the four enhancement ideas have open research questions that could invalidate the proposed approach entirely.** The following rule is absolute:

> No `plan.md` is written until all checkpoints in the feature's `specify.md` Investigation Checkpoints section are resolved with concrete evidence.

> No `tasks.md` is written until `plan.md` is approved.

> No code is written until `tasks.md` is approved.

This is the most important constraint in this document. The cost of violating it is building something that doesn't work or that ItyFuzz already does.

---

## 9. Collaboration Protocol (Senior/Junior Dev)

- **Research and checkpoint resolution:** Either developer can do this
- **Architecture decisions (plan.md):** Senior reviews before proceeding to tasks
- **Implementation:** Junior implements task by task; senior reviews each task before the next begins
- **Blocked tasks:** Surface immediately — do not attempt workarounds without discussion
- **Assumption vs. evidence:** If something isn't confirmed by reading source code or running a benchmark, it is an assumption. Label it as such.

---

## 10. Feature Status Definitions

| Status | Meaning | Gate to next |
|---|---|---|
| **Investigating** | Checkpoints in specify.md are open | All checkpoints resolved with evidence |
| **Specified** | specify.md complete and approved | Senior dev sign-off |
| **Planned** | plan.md written | Senior dev sign-off, all specify.md questions answered |
| **Tasked** | tasks.md written and ordered | Senior dev sign-off |
| **In Progress** | Coding has begun | N/A |
| **Complete** | Code merged, benchmark validates improvement | Benchmark result documented |
| **Closed** | Investigation revealed problem doesn't exist or isn't worth solving | Written rationale in specify.md |
