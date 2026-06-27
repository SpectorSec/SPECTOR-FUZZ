# Task Breakdown — Ghost Identities

**Status:** Tasked  
**Owner:** TBD  
**Last updated:** 2026-06-26  

---

## Tasks (in order, must complete sequentially)

### Task 1 — Add TrustedCallerMetadata Type
- [ ] **File:** `src/evm/oracles/mod.rs`
- [ ] Add `TrustedCallerMetadata` struct with `trusted_callers: HashMap<(EVMAddress, [u8; 4]), HashSet<EVMAddress>>`
- [ ] Add `impl_serdeany!(TrustedCallerMetadata)`
- [ ] Export in module
- [ ] **Verify:** `cargo check --features evm` compiles

### Task 2 — Insert Metadata at Corpus Init
- [ ] **File:** `src/evm/corpus_initializer.rs`
- [ ] In setup block, insert `TrustedCallerMetadata::default()` into state metadata map
- [ ] (Optional) Seed from `CrossChainOracle.trusted_bridges` if already populated
- [ ] **Verify:** Metadata exists in state after init (add debug log or unit test)

### Task 3 — Extend Mutator Prank Injection
- [ ] **File:** `src/evm/mutator.rs`
- [ ] Import `TrustedCallerMetadata`
- [ ] In NestedAction generation block (~line 372-419):
  - Detect if current (target_addr, selector) is privileged (`ProtocolFamily::Privileged`)
  - Look up `TrustedCallerMetadata[(target_addr, selector)]`
  - If non-empty, prefer trusted address for `vm.prank()` (30% chance)
  - Fallback to existing `WhaleAddressMetadata` logic
- [ ] **Verify:** Unit test mocks state with both metadatas; assert correct address chosen

### Task 4 — Wire FunctionOracle from Metadata
- [ ] **File:** `src/evm/oracles/function.rs`
- [ ] In oracle `transition()` or during corpus init, iterate `TrustedCallerMetadata` and call `add_rule()` for each entry
- [ ] Ensure `FunctionOracle` allowlist prevents flagging trusted callers
- [ ] **Verify:** Integration test — oracle doesn't fire for trusted caller, does fire for untrusted

### Task 5 — Add ArbCallOracle Allowlist Filter
- [ ] **File:** `src/evm/oracles/arb_call.rs`
- [ ] Add check: if caller in `TrustedCallerMetadata` for target+selector, return `OracleResult::None`
- [ ] **Verify:** Unit test

### Task 6 — CLI Flag Gate
- [ ] **File:** `src/evm/config.rs`
- [ ] Add `pub ghost_identities: bool` to `EVMConfig`
- [ ] Add CLI flag `--ghost-identities` in `args.rs` (or wherever flags are defined)
- [ ] In `mutator.rs`, gate the trusted-caller logic behind `config.ghost_identities`
- [ ] **Verify:** Run with and without flag; behavior differs

### Task 7 — Unit Tests
- [ ] **File:** `src/evm/mutator.rs` test module (or new test file)
- [ ] Test `TrustedCallerMetadata` serialization round-trip
- [ ] Test mutator draws trusted address for privileged selector
- [ ] Test mutator falls back to whale for non-privileged selector
- [ ] Test FunctionOracle allowlist integration

### Task 8 — Integration Test
- [ ] Add test contract with `onlyRouter` guard (or use existing)
- [ ] Run fuzzer with `--ghost-identities` on contract
- [ ] Assert fuzzer reaches guarded function
- [ ] Run WITHOUT flag; assert guarded function NOT reached

### Task 9 — Regression Test
- [ ] Add test to CI that runs B1 benchmark with flag disabled → same results as baseline
- [ ] Run B1 with flag enabled → no regression (or improvement documented)

### Task 10 — Documentation
- [ ] Update flag help string in `config.rs` / `args.rs`
- [ ] Add module docstring to `TrustedCallerMetadata` explaining purpose
- [ ] Update README features list if needed