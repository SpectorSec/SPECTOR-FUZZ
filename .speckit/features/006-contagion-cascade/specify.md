# Feature 006 — Cross-Protocol Contagion Cascade

**Status:** Investigating  
**Owner:** TBD  
**Last updated:** 2026-06-27  

---

## Overview

The most damaging DeFi exploits don't end in the contract where they start. A bridge is compromised → poisoned assets land on the destination chain → they're deposited into a lending pool → the attacker borrows against inflated collateral → the cascade propagates.

Currently, SPECTOR-FUZZ has:

- **CrossChainOracle** (`oracles/crosschain.rs`): Detects an untrusted address calling `lzReceive`/`ccipReceive`/`xReceive`. Flags the bridge miss itself.
- **TemporalSkimOracle** (Feature 005): Detects balance divergence across a block-advance warp.
- **Value Capture Middleware** (Feature 001): Captures return values from each transaction step.
- **Engagement Seeder** (Feature 002): Links output values from one step as input parameters to the next.

What's missing: a way to **follow the poisoned asset** across protocol boundaries and detect the downstream value mismatch — the contamination event itself.

Cross-Protocol Contagion Cascade adds a new oracle that tracks an asset from its initial manipulation (bridge miss, mint, price spike) through deposits into downstream protocols (lending pools, vaults, DEXs) and flags when a protocol's internal accounting diverges from fundamental reality.

---

## Why This Matters

Three real incidents that follow the contamination chain:

### Kelp DAO + Aave ($292M)
1. LayerZero bridge adapter accepts forged payload (from trusted endpoint, so CrossChainOracle doesn't flag it)
2. 116,500 unbacked rsETH minted on Ethereum
3. Attacker deposits rsETH into Aave as collateral
4. Aave's oracle values rsETH at full market price
5. Attacker borrows $190M in clean WETH against inflated collateral

The `CrossChainOracle` only detects case 1 if the caller is untrusted. In Kelp, the caller **was** the trusted LayerZero endpoint — the message was just forged. No existing oracle catches the downstream contamination (cases 3-5).

### Mango Markets ($117M)
1. Attacker manipulates MNGO oracle price via a single large swap
2. Uses inflated MNGO as collateral on Mango's own lending market
3. Borrows all available liquidity against it
4. Oracle price crashes back, but liquidity is gone

The `TemporalSkimOracle` (Feature 005) can detect the price divergence across a warp, but nothing tracks that the inflated asset was specifically *used as collateral to borrow another asset* — the contamination vector.

### Radiant Capital ($50M)
1. Attacker compromises multi-sig signing infrastructure
2. Forged messages set malicious reward parameters
3. Attacker claims inflated rewards across multiple markets
4. Drains USDC and ETH from lending pools

---

## Success Criteria

This feature is worth building if and only if:

1. The fuzzer can track an asset's flow from a source transaction (bridge receive, mint, swap) across protocol boundaries into a destination contract (lending pool, vault)
2. A new `ContagionOracle` detects when the tracked asset's apparent value (oracle price, ABI-reported balance) exceeds its fundamental backing (supply-side balance, mint event)
3. The oracle fires specifically on **downstream contamination** — not on the initial manipulation itself (which existing oracles handle)
4. The feature reproduces at least one validated incident from the database that no single oracle currently catches

---

## Out of Scope

- Simulating actual cross-chain message relay (we stay single-chain, fork-based)
- LayerZero/CCIP endpoint impersonation (Feature 004 Ghost Identities covers this)
- Detecting the bridge miss itself (CrossChainOracle covers this)
- Automated discovery of asset flow paths (manual annotation via topology or CLI config for v1)

---

## Investigation Checkpoints

### Checkpoint 6.1 — Existing Asset Flow Infrastructure
**Files:** `src/evm/middlewares/value_capture.rs`, `src/evm/input.rs` (StepLinkage), `src/evm/vm.rs` (observed_values)  
**Question:** What infrastructure already exists for tracking an asset from one step's output to another step's input? Can we trace a specific token address through the `observed_values` HashMap or `StepLinkage` table?  
**Evidence required:** How `value_capture` stores return values; how `StepLinkage.from_registry_key` maps outputs to inputs; how `observed_values` is populated and queried.

### Checkpoint 6.2 — Collateral Detection in Lending Pools
**Files:** `src/evm/onchain/flashloan.rs`, `src/evm/liquidation_router.rs`, `src/evm/liquidation.rs`  
**Question:** How does the fuzzer currently detect that an asset was deposited as collateral? Are there existing queries for `balanceOf(protocol)` or `getUserCollateral()` patterns?  
**Evidence required:** Existing liquidation-aware code paths; any calls to Aave/Compound-style collateral queries; how the fuzzer identifies lending pools.

### Checkpoint 6.3 — Oracle Price Awareness
**Files:** `src/evm/topology/mod.rs` (`ProtocolFamily`), `src/evm/oracles/freshness.rs`, `src/evm/host.rs`  
**Question:** Does the fuzzer already know which contracts are oracles? Can it detect that a protocol is querying a specific price feed, and can it identify when that price diverges from a fundamental value?  
**Evidence required:** How `ProtocolFamily::Chainlink` / oracle contracts are detected; how `FreshnessOracle` monitors oracle answers; how to compare an oracle-reported price against a computed fundamental value (e.g., pool reserves).

### Checkpoint 6.4 — Existing Contamination-Adjacent Oracles
**Files:** `src/evm/oracles/` (all)  
**Question:** Which oracles already detect partial contamination patterns? Does `RebasingOracle`, `ERC4626Oracle`, `FeeOnTransferOracle`, or `ArbitraryCallOracle` already catch any cross-protocol state?  
**Evidence required:** For each oracle, whether it would flag anything in the Kelp→Aave chain: (a) rsETH mint, (b) deposit into Aave, (c) borrow against rsETH collateral.

### Checkpoint 6.5 — Real Incident Validation
**File:** `solutions/` or incident database  
**Question:** Pick 3 incidents where a manipulated asset crosses a protocol boundary. For each:
1. What asset is manipulated in Phase 1?
2. What downstream protocol accepts it?
3. What oracle/mechanism values it incorrectly?
4. Could any existing SPECTOR-FUZZ oracle detect this? (Likely no — the contamination vector requires tracking asset identity across protocols.)

---

## Risks

- **Asset tracking complexity:** Following a specific token through arbitrary contract interactions requires symbolic tracking or explicit path annotation. For v1, constrain to known paths (bridge → lending pool).
- **False positives:** A value divergence between two protocols is not automatically an exploit. Need a clear "this asset was used as collateral" signal before flagging.
- **Performance:** If every oracle call queries `balanceOf` for every known token on every known protocol, overhead adds up. Cache and scope queries to active contamination paths.
- **Path explosion:** If the fuzzer can deposit any asset into any protocol, the combinatorial search space explodes. Use topology hints (ProtocolFamily) to constrain.

---

## Open Questions

- Can the `observed_values` registry key format `{target:?}_{selector_hex}_return` be used to trace a minted token address from a bridge call to a deposit call? Or do we need a dedicated asset flow metadata type?
- Should the `ContagionOracle` be a single oracle or a new oracle family (one per protocol type — lending, vault, DEX)?
- For v1, should contamination paths be manually specified via CLI (e.g., `--contagion-path bridge_addr:aave_addr`), or can the topology engine auto-detect them?
