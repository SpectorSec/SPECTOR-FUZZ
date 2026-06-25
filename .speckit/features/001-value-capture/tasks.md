# Task List — Value Capture Middleware

**Status:** Completed  
**Owner:** TBD  
**Last updated:** 2026-06-25  

This document lists the sequential, atomic tasks required to implement the Value Capture Middleware.

---

## Task Checklist

- [x] **Task 1 — Extend `EVMState` struct**  
  *Description:* Add `observed_values: HashMap<String, Vec<EVMU256>>` to the `EVMState` struct definition. Ensure it is serialized and initialized automatically via default constructors.  
  *Touches:* [src/evm/vm.rs](file:///workspace/_global/ityfuzz-src/src/evm/vm.rs)  
  *Done when:* Project compiles and `EVMState` includes the new field.

- [x] **Task 2 — Register `MiddlewareType`**  
  *Description:* Add `ValueCapture` to the `MiddlewareType` enum in `middleware.rs`.  
  *Touches:* [src/evm/middlewares/middleware.rs](file:///workspace/_global/ityfuzz-src/src/evm/middlewares/middleware.rs)  
  *Done when:* Enum includes `ValueCapture` and compiles.

- [x] **Task 3 — Add `--value-capture` CLI flag**  
  *Description:* Add `value_capture: bool` to the `FuzzConfig` struct and expose it as a CLI argument (`--value-capture`) in the argument parser.  
  *Touches:* [src/evm/config.rs](file:///workspace/_global/ityfuzz-src/src/evm/config.rs)  
  *Done when:* Running `cargo run -- --help` prints the new `--value-capture` option.

- [x] **Task 4 — Implement `ValueCaptureMiddleware`**  
  *Description:* Create `value_capture.rs` containing the middleware struct, call stack tracking, and raw U256 return value parsing logic (with a history limit of 10 values per selector).  
  *Touches:* [src/evm/middlewares/value_capture.rs](file:///workspace/_global/ityfuzz-src/src/evm/middlewares/value_capture.rs) (New File)  
  *Done when:* Middleware compiles and correctly implements `Middleware<SC>`.

- [x] **Task 5 — Hook top-level call returns**  
  *Description:* Add return interception logic at the end of `execute_from_pc` in `vm.rs` to capture values returned by the top-level transaction execution.  
  *Touches:* [src/evm/vm.rs](file:///workspace/_global/ityfuzz-src/src/evm/vm.rs)  
  *Done when:* Top-level return value parsing compiles and populates `result.new_state.observed_values`.

- [x] **Task 6 — Register middleware in the fuzzer setup**  
  *Description:* Instantiate `ValueCaptureMiddleware` and add it to `fuzz_host` if `config.value_capture` is enabled.  
  *Touches:* [src/fuzzers/evm_fuzzer.rs](file:///workspace/_global/ityfuzz-src/src/fuzzers/evm_fuzzer.rs)  
  *Done when:* Project compiles and registers the middleware under the opt-in flag.

- [x] **Task 7 — Write middleware unit tests**  
  *Description:* Write unit tests verifying the parsing of return data bytes into U256 values and the enforcement of the 10-value history limit.  
  *Touches:* [src/evm/middlewares/value_capture.rs](file:///workspace/_global/ityfuzz-src/src/evm/middlewares/value_capture.rs)  
  *Done when:* `cargo test` executes and passes the new unit tests.

- [x] **Task 8 — Write integration and regression tests**  
  *Description:* Deploy a mock Solidity contract that returns dynamic values. Verify that running the fuzzer with `--value-capture` captures the values in the output corpus, and running without the flag leaves the observed values empty.  
  *Touches:* [src/evm/middlewares/value_capture.rs](file:///workspace/_global/ityfuzz-src/src/evm/middlewares/value_capture.rs)  
  *Done when:* Integration tests execute successfully and verify the correct capture/non-capture behavior.
