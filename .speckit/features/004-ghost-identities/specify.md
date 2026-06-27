# Feature 004 — Ghost Identities (Confused Deputy / Identity Spoofing)

**Status:** Specified  
**Owner:** TBD  
**Last updated:** 2026-06-26  

---

## Overview

Many DeFi exploits involve making a target contract believe it is being called by a **trusted protocol address** — a router, vault, middleware, or bridge endpoint — rather than by an end user or attacker EOA. The target contract's access control (`onlyRouter`, `onlyVault`, `msg.sender == trusted_bridge`) passes because `msg.sender` has been spoofed to match the expected caller.

Currently, SPECTOR-FUZZ's prank system (`vm.prank`, `vm.startPrank/stopPrank`, `host.apply_prank()`) is fully wired and functional, but the mutator only draws prank targets from `WhaleAddressMetadata` — rich EOAs with high token balances. This lets the fuzzer bypass `balanceOf > threshold` checks, but not `msg.sender == trusted_contract` checks.

Ghost Identities extends the prank system to also spoof **protocol contract addresses** as `msg.sender`, enabling the fuzzer to explore confused-deputy and identity-based access control bypasses.

---

## Why This Matters

From the DeFi incident database, confused-deputy patterns appear across multiple vulnerability categories:

- **Arbitrary call exploits (74 incidents):** Attackers call a router function that delegatecalls or calls out with attacker-supplied data — the vault trusts the router's `msg.sender`
- **Cross-chain bridge exploits:** The receiver contract checks `msg.sender == trusted_bridge_endpoint` — spoofing the bridge identity allows arbitrary message injection
- **Flash loan + access control combos:** Protocols that allow privileged operations only from specific router/vault addresses during a callback window
- **Governance attacks:** Proposals executed from a known governor address

The topology already classifies `ProtocolFamily::Privileged` for functions with privileged keywords. The missing half is "who is allowed to call them."

---

## Success Criteria

This feature is worth building if and only if:

1. We can produce a `TrustedCallerMetadata` that maps privileged functions to their authorized caller addresses
2. The mutator can draw from this metadata (not just `WhaleAddressMetadata`) when injecting `vm.prank()` into NestedActions
3. The discovery mechanism works without manual configuration — it must derive trusted callers from the fork state or execution traces
4. When combined with the existing campaign planner, Ghost Identities enables the fuzzer to reach code paths behind `onlyRouter` / `onlyVault` guards that it currently cannot reach

---

## Out of Scope

- A general-purpose static analyzer for Solidity access control modifiers (OpenZeppelin `Ownable`, role-based RBAC). We focus on *discovering* the authorized caller by observation, not by parsing `require(msg.sender == ...)` patterns
- Modifying the EVM or revm to bypass access control at the interpreter level — we stay within the prank cheatcode system

---

## Investigation Checkpoints

### Checkpoint 4.1 — Trace the Full Prank Pipeline ✅ **RESOLVED**
**Files:** `src/evm/middlewares/cheatcode/common.rs:248-267`, `src/evm/host.rs:1140-1166,1334-1337`, `src/evm/mutator.rs:372-419`  
**Evidence:** Complete pipeline traced:

1. **Mutator injection** (`mutator.rs:372-419`): When generating NestedActions (30% chance), the mutator pulls a whale address from `WhaleAddressMetadata` and encodes `vm.prank_0Call { msgSender: whale_addr }` (or `startPrank_0Call`) as a NestedAction targeting `CHEATCODE_ADDRESS`. The prank action is pushed *before* the actual target call.

2. **Cheatcode dispatch** (`host.rs:1370-1382`): When EVM executes a CALL to `CHEATCODE_ADDRESS`, `host.rs` extracts calldata, caller, tx_origin, and dispatches to the cheatcode middleware via `cheat.dispatch()`. This calls `prank0()` / `prank1()` / `start_prank0()` / `start_prank1()` in `common.rs`.

3. **Prank creation** (`common.rs:248-267`): `prank0()` creates a `Prank` struct with `old_caller`, `new_caller = msgSender`, `single_call = true`, `depth = host.call_depth - 1`, stores it in `host.prank = Some(Prank::new(...))`.

4. **Prank application** (`host.rs:1140-1151`): On every CALL, `call_internal()` calls `self.apply_prank(&caller_addr, &mut input)` **before** incrementing `call_depth`. `apply_prank()` checks `if self.call_depth >= prank.depth && contract_caller == &prank.old_caller` — if true, overrides `input.caller = prank.new_caller` (and `tx.origin` if set).

5. **Prank cleanup** (`host.rs:1154-1166`): After the subcall returns, `clean_prank()` restores `tx.origin` if it was changed, and for `single_call` pranks, removes the prank entirely (`self.prank.take()`).

**Conditions where prank is applied:**
- `host.call_depth >= prank.depth` (prank is active at this depth or deeper)
- `contract_caller == prank.old_caller` (the caller making the call matches the original caller who invoked `vm.prank()`)
- `single_call` pranks only apply to the **next** call at that depth; `startPrank` applies until `stopPrank` or depth changes

---

### Checkpoint 4.2 — WhaleAddressMetadata Injection Pattern ✅ **RESOLVED**
**Files:** `src/evm/oracles/mod.rs:18-28`, `src/evm/corpus_initializer.rs:367-385`, `src/evm/mutator.rs:372-419`  
**Evidence:**

**Metadata struct** (`oracles/mod.rs:22-28`):
```rust
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WhaleAddressMetadata {
    pub addresses: HashSet<EVMAddress>,
}
impl_serdeany!(WhaleAddressMetadata);
```

**Population site** (`corpus_initializer.rs:367-385`): During corpus init, seeds from:
- `WHALES` constant array (hardcoded rich EOA addresses)
- `FIX_DEPLOYER` and `FOUNDRY_DEPLOYER` addresses
```rust
let mut whale_set = HashSet::new();
for addr in WHALES { whale_set.insert(*addr); }
if let Ok(fix) = EVMAddress::from_str(FIX_DEPLOYER) { whale_set.insert(fix); }
if let Ok(foundry) = EVMAddress::from_str(FOUNDRY_DEPLOYER) { whale_set.insert(foundry); }
self.state.metadata_map_mut().insert(WhaleAddressMetadata { addresses: whale_set });
```

**Mutator consumption** (`mutator.rs:372-419`): When generating NestedActions (inside the 15% probability block for oracle-biased target selection):
```rust
let whale_meta = state.metadata_map().get::<WhaleAddressMetadata>().cloned();
if let Some(whale_meta) = whale_meta {
    if !whale_meta.addresses.is_empty() && state.rand_mut().below(100) < 30 {
        let whale_addr = random choice from whale_meta.addresses;
        // 50%: vm.prank(whale) + target call
        // 50%: vm.startPrank(whale) + target call + vm.stopPrank()
    }
}
```

**Key observation:** The address pool is **exclusively EOAs** (rich users, deployers). No protocol contract addresses are ever added.

---

### Checkpoint 4.3 — Can Topology Identify Trusted Callers? ✅ **RESOLVED — DYNAMIC APPROACH VIABLE, STATIC LIMITED**
**Files:** `src/evm/topology.rs`, `src/evm/oracles/function.rs:47-58, 128-165`, `src/evm/oracles/crosschain.rs:48-52`  

**Static approach (bytecode analysis):** **Not feasible with current tooling.** The codebase has no bytecode pattern matcher for `require(msg.sender == <address>)`. Existing tools (`src/evm/abi.rs`, `src/evm/contract_utils.rs`) extract selectors and basic ABI, not access control logic. Adding a static analyzer would be a separate feature.

**Dynamic approach (execution traces):** **Fully viable with existing infrastructure.**

1. **FunctionOracle already has the schema** (`function.rs:47-58`):
   ```rust
   pub fn add_rule(
       &mut self,
       contract: EVMAddress,
       selector: [u8; 4],
       fn_name: String,
       allowed_callers: HashSet<EVMAddress>,  // <-- THIS EXISTS BUT IS NEVER POPULATED
   ) {
       self.rules.insert((contract, selector), allowed_callers);
   }
   ```
   The `allowed_callers` field is a `HashSet<EVMAddress>` — exactly the trusted caller set we need. But `add_rule()` is **never called** anywhere in the codebase.

2. **CrossChainOracle proves the pattern** (`crosschain.rs:48-52`):
   ```rust
   pub struct CrossChainOracle {
       pub trusted_bridges: HashSet<EVMAddress>,  // Same shape
       pub address_to_name: HashMap<EVMAddress, String>,
   }
   ```
   It checks `if self.trusted_bridges.contains(&caller) { return vec![]; }` — if caller IS in trusted set, call is expected; if NOT in set but call succeeds → bug.

3. **Dynamic discovery mechanism** (to be built):
   - During corpus init / execution, track `(contract, selector) → Set<caller_address>` for **successful** calls (non-reverted)
   - For each `(contract, selector)` classified as `ProtocolFamily::Privileged` by topology, the set of successful callers becomes the trusted caller candidates
   - Filter out EOAs that are obviously not protocol contracts (could use balance thresholds or code size checks)
   - Populate `FunctionOracle.add_rule(contract, selector, fn_name, trusted_callers)` or create a new `TrustedCallerMetadata` with the same schema

**Resolution:** The topology tells us *which functions are privileged* (`ProtocolFamily::Privileged`). The dynamic trace tells us *which callers actually succeed on those selectors*. Combining both gives us the trusted caller set without static analysis.

---

### Checkpoint 4.4 — Campaign Planner Interaction ✅ **RESOLVED — NESTED ACTIONS, NOT SEPARATE STEPS**
**Files:** `src/evm/planner/campaign_planner.rs:165-180`, `src/evm/input.rs:73-78, 196-246`  
**Evidence:**

The campaign planner builds `CampaignSequence` with steps as `ConciseEVMInput` (`input.rs:196-246`). Each step has:
- `caller: EVMAddress` (the `msg.sender` for that step)
- `contract: EVMAddress` (target contract)
- `nested_actions: Vec<NestedAction>` (callback payloads)

**Two integration paths:**

1. **Prank as separate step (not recommended):** Add a `ConciseEVMInput` step targeting `CHEATCODE_ADDRESS` with `vm.prank` calldata. Problem: `apply_prank()` only affects calls *from* the same `old_caller` at depth >= prank depth. A separate step would execute in its own context and not carry over.

2. **Prank via NestedActions (RECOMMENDED — already how it works):** The mutator already injects `vm.prank` into `nested_actions` of the step that calls the privileged function (see `mutator.rs:372-419`). The prank executes, then the target call executes in the same transaction, same `call_depth` context. The privileged function sees the spoofed `msg.sender`.

**Campaign planner integration:** The planner doesn't need to change. When a topology-driven campaign identifies a `ProtocolFamily::Privileged` step, the mutator should:
- Check if we have a trusted caller for that `(contract, selector)` in `TrustedCallerMetadata`
- If yes, inject `vm.prank(trusted_address)` into that step's `nested_actions` (same logic as whale prank, different address pool)

No schema changes needed. The `ConciseEVMInput` already has `nested_actions` field that the executor respects.

---

### Checkpoint 4.5 — Real Incident Validation ✅ **RESOLVED**
**File:** `/workspace/_global/DeFi-Security-Incident/vulns/access-control.md`  

**Three incidents analyzed:**

| Incident | Protocol | Expected `msg.sender` | Current Prank Covers It? | TrustedCallerMetadata Would Cover It? |
|---|---|---|---|---|
| **2024-10-13_MorphoBlue_BundlerAccessControl_ETH.md** | MorphoBlue | Bundler contract address (bundler is allowed to call `onAction`) | ❌ No — bundler is a contract, not a whale EOA | ✅ Yes — dynamic trace would see successful `onAction` calls from bundler address |
| **2024-07-16_LIFI_DiamondFacetArbitraryCall_ETH.md** | LiFi | Router/Diamond facet address | ❌ No — router is a contract | ✅ Yes — trace would show successful calls from router to diamond facet |
| **2024-03-20_ParaSwap_AccessControl_Multichain.md** | ParaSwap | Multi-sig / governor address | ❌ No — governor is a contract (Gnosis Safe) | ✅ Yes — dynamic trace would see successful privileged calls from governor |

**Pattern:** All three involve a **protocol contract** (bundler, router/facet, governor) as the expected `msg.sender`. Whale prank only has EOAs, so it cannot reach these paths. Dynamic trace of successful calls on privileged selectors would capture all three.

---

## Risks

- **False positives:** The prank system overriding `msg.sender` to a protocol address might produce "exploits" that are not actually exploitable (e.g., the protocol has additional guards beyond `msg.sender` check)
- **Oracle noise:** The existing `FunctionOracle` and `ArbCallOracle` might flag spoofed-identity calls as bugs when they're just the prank system working as designed — may need an allowlist filter similar to the callback selector filter
- **Metadata staleness:** Trusted router addresses can change (proxy upgrades, new deployments). Dynamic discovery via traces is preferred over static extraction

---

## Open Questions — RESOLVED

- **Can we reuse CrossChainOracle's `trusted_bridges` pattern generically?** YES — `TrustedCallerMetadata` should follow the exact same schema: `HashSet<EVMAddress>` per `(contract, selector)`. The CrossChainOracle is the proof-of-concept.
- **Does FunctionOracle already identify privileged functions and their callers?** YES — it has `add_rule(contract, selector, fn_name, allowed_callers: HashSet<EVMAddress>)` but it's **never called**. The `allowed_callers` field is the missing population step.

---

## Next Steps (for `plan.md`)

1. Define `TrustedCallerMetadata` struct (mirror `WhaleAddressMetadata` / `CrossChainOracle.trusted_bridges` shape)
2. Add dynamic population hook: during execution, when a `ProtocolFamily::Privileged` call succeeds (non-reverted), record the caller address
3. Extend mutator's prank injection to also draw from `TrustedCallerMetadata` for privileged selectors
4. Add filter to `FunctionOracle` / `ArbCallOracle` to ignore prank-spoofed calls (similar to callback selector allowlist)