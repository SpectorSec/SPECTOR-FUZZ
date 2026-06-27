# Implementation Plan — Ghost Identities (Confused Deputy / Identity Spoofing)

**Status:** Planned  
**Owner:** TBD  
**Last updated:** 2026-06-26  

---

## 1. Algorithm Design & Pseudocode

Ghost Identities adds a new metadata type `TrustedCallerMetadata` and extends the mutator to draw from it when generating prank NestedActions for privileged selectors.

### New Metadata Type
```rust
// src/evm/oracles/mod.rs
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrustedCallerMetadata {
    // (contract_address, selector) -> set of addresses that successfully called it
    pub trusted_callers: HashMap<(EVMAddress, [u8; 4]), HashSet<EVMAddress>>,
}
impl_serdeany!(TrustedCallerMetadata);
```

### Population Hook (Dynamic Discovery)
During execution, when a call to a privileged selector succeeds:
```
1. In the oracle transition phase (or host post-call), detect:
   - Call target contract + selector matches ProtocolFamily::Privileged
   - Execution result is non-reverted
   - Caller address is a contract (has code, not EOA)
2. If all true:
   - Insert caller into TrustedCallerMetadata[(contract, selector)]
```

### Mutator Prank Injection Extension
Current logic (`mutator.rs:372-419`): 30% chance to inject `vm.prank(whale)` from `WhaleAddressMetadata`.

Extended logic:
```
When generating NestedActions for a target (contract, selector):
1. Check if (contract, selector) is in TrustedCallerMetadata
2. If yes, and state.rand() < 30:
   - Pick address from TrustedCallerMetadata[(contract, selector)]
   - Inject vm.prank(trusted_address) + target call
3. Else if WhaleAddressMetadata exists and state.rand() < 30:
   - Fallback to existing whale prank logic
```

### FunctionOracle Integration
`FunctionOracle.add_rule()` already has the schema. During corpus init or dynamically:
```
For each (contract, selector) in TrustedCallerMetadata:
    FunctionOracle.add_rule(contract, selector, fn_name, trusted_callers_set)
```
This makes the FunctionOracle *not flag* calls from trusted addresses as bugs.

---

## 2. Modified Existing Files

### A. `src/evm/oracles/mod.rs`
- Add `TrustedCallerMetadata` struct with `impl_serdeany!`
- Export in module

### B. `src/evm/corpus_initializer.rs`
- Insert empty `TrustedCallerMetadata::default()` into state metadata map during init
- (Optional) Seed from CrossChainOracle's `trusted_bridges` if already populated

### C. `src/evm/mutator.rs` (lines 372-419)
- Import `TrustedCallerMetadata`
- Extend prank injection logic:
  ```rust
  // Inside the 15% oracle-biased NestedAction block, after oracle_target selection
  let is_privileged = /* check if selector matches ProtocolFamily::Privileged */;
  let trusted_caller = if is_privileged {
      state.metadata_map().get::<TrustedCallerMetadata>()
          .and_then(|m| m.trusted_callers.get(&(target_addr, selector)))
          .and_then(|set| set.iter().next().cloned())
  } else { None };
  
  let prank_addr = trusted_caller.or_else(|| {
      // existing whale fallback
      state.metadata_map().get::<WhaleAddressMetadata>()
          .and_then(|w| w.addresses.iter().next().cloned())
  });
  ```

### D. `src/evm/oracles/function.rs`
- At corpus init (or dynamically), call `FunctionOracle.add_rule()` for each entry in `TrustedCallerMetadata`
- This prevents the FunctionOracle from flagging legitimate trusted-caller invocations as bugs

### E. `src/evm/oracles/arb_call.rs` (if needed)
- Add similar allowlist check for trusted caller addresses so ArbCallOracle doesn't flag them

---

## 3. New Files

None required — all changes extend existing types and logic.

---

## 4. CLI Flag

Add `--ghost-identities` flag to `src/evm/config.rs`:
```rust
pub ghost_identities: bool,
```
- When disabled: `TrustedCallerMetadata` is not consulted; mutator uses only `WhaleAddressMetadata`
- When enabled: mutator draws from both metadata sources

---

## 5. Testing Plan

### Unit Tests
1. **TrustedCallerMetadata serialization** — insert, serialize, deserialize, verify integrity
2. **Mutator draws from trusted callers** — mock state with both metadata types; verify prank NestedAction uses trusted address for privileged selector, whale for non-privileged
3. **FunctionOracle integration** — add rule from metadata; verify call from trusted address doesn't fire oracle; call from untrusted address fires oracle

### Integration Test
Use existing test contract with `onlyRouter` guard (or add one to test fixtures):
1. Deploy contract with `withdraw()` that requires `msg.sender == trusted_router`
2. Run fuzzer with `--ghost-identities`
3. Verify fuzzer reaches the guarded function (requires `TrustedCallerMetadata` populated + mutator prank injection)

### Regression Test
Run same test with `--ghost-identities` **disabled** — verify the guarded function is NOT reached (prank uses whale EOA, which fails the `onlyRouter` check).

---

## 6. Performance Impact

- **Memory:** `TrustedCallerMetadata` grows with unique (contract, selector) pairs. Expected < 1000 entries per campaign. Negligible.
- **CPU:** Mutator check adds one `HashMap` lookup per NestedAction generation. Occurs at ~15% of mutations. Negligible.
- **Benchmark:** Must pass B1 benchmark within same time as baseline when flag is disabled.

---

## 6. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| False positives from prank spoofing | FunctionOracle/ArbCallOracle allowlist prevents flagging; add `TrustedCallerMetadata` to their allowlist check |
| Metadata staleness (proxy upgrades) | Dynamic population from live traces; trust set evolves with execution |
| Oracle noise | Callback-style selector allowlist pattern already exists in ArbCallOracle — apply same pattern to trusted caller addresses |

---

## 7. Dependencies

- Requires `ProtocolFamily::Privileged` classification from topology (already implemented)
- Requires `FunctionOracle` to be active (already default)
- No new crates or external dependencies

---

## 8. Implementation Order

1. Add `TrustedCallerMetadata` to `oracles/mod.rs`
2. Insert empty metadata in `corpus_initializer.rs`
3. Extend mutator prank injection in `mutator.rs` (core logic)
4. Wire `FunctionOracle.add_rule()` population from metadata
5. Add `--ghost-identities` flag to `config.rs` and gate mutator logic
6. Add allowlist filter to `FunctionOracle` and `ArbCallOracle`
7. Write unit + integration + regression tests