# Feature 004 — Ghost Identities (Confused Deputy / Identity Spoofing)

**Status:** Investigating  
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

The topology already classifies `ProtocolFamily::Privileged` functions. The missing half is "who is allowed to call them."

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

### Checkpoint 4.1 — Trace the Full Prank Pipeline
**Files:** `src/evm/middlewares/cheatcode/common.rs`, `src/evm/host.rs`, `src/evm/mutator.rs`  
**Question:** Trace the complete path from `vm.prank(address)` being encoded in a NestedAction, through cheatcode dispatch, through `host.apply_prank()`, to the sub-interpreter seeing the modified `msg.sender`. What are the exact conditions where prank is applied vs. ignored?  
**Evidence required:** Paste the code path with line numbers.

### Checkpoint 4.2 — WhaleAddressMetadata Injection Pattern
**Files:** `src/evm/oracles/mod.rs`, `src/evm/mutator.rs`, `src/evm/corpus_initializer.rs`  
**Question:** How is `WhaleAddressMetadata` populated and consumed? Trace from corpus initialization through oracle feedback to mutator consumption. What schema does it use?  
**Evidence required:** The metadata struct definition, the population site, and the mutator's prank injection logic with exact conditions/branching.

### Checkpoint 4.3 — Can Topology Identify Trusted Callers?
**Files:** `src/evm/topology.rs`, `src/evm/oracles/function.rs`  
**Question:** The topology classifies `ProtocolFamily::Privileged` for functions with privileged keywords. But can we determine *which address is allowed* to call them? Investigate two approaches:
- **Static:** Does the bytecode contain a `PUSH20` followed by an address near a `require( caller == )` or `require(msg.sender == )` pattern? What tools exist in the codebase for bytecode analysis?
- **Dynamic:** During execution traces, can we observe which callers *succeed* when calling a privileged selector vs. which revert? Does the execution result (`reverted` flag) give us this signal reliably?

### Checkpoint 4.4 — Campaign Planner Interaction
**Files:** `src/evm/planner/campaign_planner.rs`, `src/evm/topology.rs`  
**Question:** If we discover a trusted caller address, how should the campaign planner use it? A privileged function might require `msg.sender == TrustedRouter`. The planner would need to:
1. Insert a "prank step" before the privileged call step
2. Set the caller to the trusted router address for that step only

Does the current `CampaignStep` / `CampaignSequence` schema support adding a cheatcode action as a step? Or would we need to extend the schema?

### Checkpoint 4.5 — Real Incident Validation
**File:** `/workspace/_global/DeFi-Security-Incident/vulns/access-control.md`  
**Question:** Pick 3 access-control incidents from the database. For each:
1. What specific address was `msg.sender` expected to be?
2. Could the attacker have produced that `msg.sender` through the existing whale-based prank? (Likely no — whales are EOAs, not contracts.)
3. Would a `TrustedCallerMetadata` populated from bytecode/traces have covered this identity?

---

## Risks

- **False positives:** The prank system overriding `msg.sender` to a protocol address might produce "exploits" that are not actually exploitable (e.g., the protocol has additional guards beyond `msg.sender` check)
- **Oracle noise:** The existing `FunctionOracle` and `ArbCallOracle` might flag spoofed-identity calls as bugs when they're just the prank system working as designed — may need an allowlist filter similar to the callback selector filter
- **Metadata staleness:** Trusted router addresses can change (proxy upgrades, new deployments). Dynamic discovery via traces is preferred over static extraction

---

## Open Questions

- Can we reuse the `CrossChainOracle`'s `trusted_bridges` pattern generically? That oracle already has a `HashSet<EVMAddress>` for trusted callers — could a generalized `TrustedCallerMetadata` follow the same shape?
- Does the `FunctionOracle` already identify privileged functions and their callers? The `allowed_callers` field exists in `PrivilegedFunctionOracle` (line 47 of `function.rs`) — is it populated anywhere?
