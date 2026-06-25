# SPECTOR-FUZZ
**EVM-only DeFi flow extractor. Fork of ItyFuzz stripped to EVM and extended with an autonomous oracle pipeline.**

*The thesis: Every DeFi exploit is one of six data-flow primitives. We don't audit code — we extract flows, confirm exploitability directly on a live fork, and produce actionable outcomes.*

---

## The Philosophy: The Six DeFi Primitives
Rather than checking for simple code correctness or reverts, SPECTOR-FUZZ is designed around the concept that all DeFi exploits reduce to one of six fundamental data-flow leaks:

1.  **Control Leak**: A caller gains execution flow (e.g., through arbitrary callbacks) they should not have.
2.  **Value Leak**: More assets come out of a system than went in (direct economic drain).
3.  **Message Leak**: Cross-contract calls are executed using unvalidated input.
4.  **Permission Leak**: Privileged or administrative functions are successfully called by unprivileged actors.
5.  **Invariant Leak**: Protocol accounting equations break (e.g., $k=xy$, or shares-to-assets inflation).
6.  **Ownership Leak**: Asset ownership (ERC-721/1155/20) is transferred without explicit authorization.

By treating the fork state as the absolute ground truth, SPECTOR-FUZZ executes transactions in real time, observing state mutations. If an oracle detects a leak, the exploit is confirmed.

---

## The Progressive Intelligence Pipeline
SPECTOR-FUZZ does not execute blindly. It uses a dual-phase pipeline that transitions seamlessly from static analysis to dynamic runtime adaptation as the fuzzing campaign progresses:

### Phase 1: Static Blueprinting (Reconnaissance)
*   **ABI Fingerprinting**: At startup, it scans target bytecodes to build an initial intelligence map of selectors.
*   **Auto-Oracle Activation**: Automatically maps signatures to corresponding bug detectors (e.g., detecting an ERC-4626 vault signature activates `ERC4626Oracle`; detecting a Chainlink feed activates `FreshnessOracle`).

### Phase 2: Dynamic Runtime Discovery (Adaptation)
As the chain state evolves, parameters (like pool tokens or initialized states) change. The fuzzer adapts dynamically:
*   **Consensus Slot Detection**: Uses `eth_createAccessList`-based tracing to dynamically map token balance storage layouts (supporting both Vyper and Solidity custom formats) to pre-fund caller balances via whale consensus.
*   **Attacker Bytecode Injection & Callback Surface**: Injecting an attacker contract on-the-fly, the fuzzer registers hook entry points (like `executeOperation` for flashloans or receiver hooks) as active mutation paths.
*   **Warp Delta Sync**: Dynamically accelerates block warp and time simulation to bypass time-lock deadlocks and trigger freshness oracle checks.
*   **Oracle-Biased Function Re-sampling**: Dynamically re-biases inputs to avoid getting stuck in loops, focusing instead on branches that trigger oracle events.

---

## Features & Extensions

### 1. Autonomous Liquidation Router
Replaces the Node.js pairs server entirely. The fork IS the pairs server.
Queries Curve registry, Uniswap V2/V3 factories, and ERC-4626 vaults directly via `eth_call` against the live fork state. No external processes, no hardcoded pool addresses, no hints.
*   **Recursive Route Discovery**: Dynamically resolves and traces exit routes for vault and lending tokens (Compound, Aave, ERC-4626) recursively back to WETH.
*   **Dynamic Uniswap V3 Fee Resolution**: Queries active pool fees directly on-chain via `fee()` calls to format accurate swap paths.
*   **Priority**: ERC-4626 redeem → Curve registry → UniV2 getPair → UniV3 getPool → Illiquid
*   **Overrides**: Per-chain factory overrides for BSC, Polygon, Arbitrum, Optimism.

### 2. ABI Fingerprinting Pipeline
Oracles activate automatically from selector detection — no manual configuration:

| Selector | Detected as | Oracle activated |
|----------|-------------|------------------|
| `0x07a2d13a` | ERC-4626 vault | `ERC4626Oracle` |
| `0xfeaf968c` | Chainlink oracle | `FreshnessOracle` |
| `0x3644e515` | EIP-712 domain | permit seed corpus |
| *17 keywords* | Permission boundary | `FunctionOracle` |

### 3. Oracle Suite (`-d all`)
All 14 DeFi Ghost properties are covered:

| Oracle | Detects | Ghost |
|--------|---------|-------|
| `ERC20Oracle` | Fund extraction | #1 |
| `FreshnessOracle` | Stale Chainlink data accepted without revert | #3 |
| `ERC4626Oracle` | Share price manipulation / vault inflation | #5 |
| `FunctionOracle` | Unauthorized privileged function call | #4 |
| `ReentrancyOracle` | Control flow hijack mid-state | #2 |
| `InvariantOracle` | Echidna `invariant_*` / failed slot tripped | #7 |
| `ArbitraryCallOracle` | Unvalidated external call target | #6 |
| `NFTOracle` | ERC-721/1155 ownership leak | #6 |
| `ApprovalOracle` | Unlimited approval granted to attacker | #4 |
| `FeeOnTransferOracle` | Fee-on-transfer token accounting error | #1 |
| `RebasingOracle` | Rebasing token balance desync | #5 |
| `CrossChainOracle` | Cross-chain message trust boundary | #6 |

### 4. Cheatcode Extensions & Nested Pranking
Supports `vm.computeCreateAddress`, `vm.computeCreate2Address` (both variants), and `vm.getNonce` for predicting CREATE2 exploit addresses.
*   **Nested Multi-call Pranks**: Seamlessly supports `startPrank` and `stopPrank` pairs for complex multi-call nested impersonations.
*   **Full suite**: `vm.prank`, `vm.deal`, `vm.warp`, `vm.roll`, `vm.load`, `vm.store`, `vm.etch`, `vm.label`, `vm.createSelectFork`, `vm.expectRevert`, `vm.expectEmit`, `vm.recordLogs`, and all assert variants.

### 5. Callback Surface Seeds
Corpus entries for hook entry points:
*   `onERC721Received` — NFT safeTransferFrom callback
*   `onERC1155Received` / `onERC1155BatchReceived` — ERC-1155 callbacks
*   `executeOperation` — Aave/Balancer flashloan callback
*   `tokensReceived` — ERC-777 send callback

These represent free execution windows mid-protocol-state that the fuzzer explores automatically.

### 6. Topology Intelligence & Anti-Topology Pre-flight
Every DeFi protocol exposes its shape through its ABI selector set. When two or more protocol families appear in the same target set, their intersection is almost always where the vulnerability lives. 

SPECTOR-FUZZ implements static topology mapping at startup to analyze these shapes and guide both the oracle and mutation engines:
*   **Protocol Family Mapping (ABI Fingerprinting)**: Classifies contract selectors into `ProtocolFamily` categories (e.g., ERC-20, ERC-721, ERC-4626, Chainlink, Lending, FlashLoan).
*   **Co-occurrence & Exploit Classification**: Matches co-occurring families to rank exploit classes and auto-activate corresponding oracles (e.g., `ERC-4626` + `Chainlink` triggers `ERC4626Oracle` with 95% confidence for price-gated vault inflation).
*   **Anti-Topology Pre-flight Warnings**: Scans for the **absence** of critical safety mechanisms (e.g., a Chainlink oracle without a freshness/staleness check, or callbacks without reentrancy guards) and logs pre-flight warnings at startup.
*   **Topology Mutation Boost ("Gamma Ray")**: Generates `TopologyHints` that boost mutation energy in the scheduler for input sequences matching predicted exploit paths, focusing pressure where bugs are most likely to exist.

---

## Quick Start

### Build
```bash
cargo build --release
```

### Onchain fork — point at any RPC
```bash
ityfuzz evm \
  -t 0xPOOL,0xLIQUIDATOR,0xUSDC \
  -c base \
  -b 26400000 \
  -u http://localhost:8545 \
  -k $ETHERSCAN_KEY \
  -d all \
  -f \
  --fetch-tx-data \
  --onchain-storage-fetching dump \
  --run-forever \
  -w ./findings
```

### Offchain — compile first with forge build
```bash
ityfuzz evm -t "build/*" -d all --run-forever -w ./findings
```

### Key Flags
| Flag | What it does |
|------|--------------|
| `-t` | Target: glob pattern, address, or comma-separated addresses |
| `-c` | Chain: eth bsc base arbitrum optimism polygon etc. |
| `-b` | Fork at block number |
| `-u` | RPC endpoint (works with localhost anvil) |
| `-d all` | All oracles active. Default is high_confidence |
| `-f` | Enable fund-loss detection layer (economic oracle) |
| `--fetch-tx-data` | Pull constructor state from fork — required for non-trivial contracts |
| `--run-forever` | Keep finding after first bug |
| `--concolic` | Symbolic execution for deeper path coverage |
| `--onchain-storage-fetching dump` | Faster storage fetch for large contracts |

---

## Architecture

```
ABI fingerprint
    ↓
corpus_initializer.rs — detects token standards, oracle interfaces, privileged fns
    ↓
evm_fuzzer.rs — auto-activates matching oracles
    ↓
LibAFL mutation engine → revm fork execution
    ↓
Oracle layer — post-execution state observation
    ↓
LiquidationRouter — confirms economic extractability via fork-native DEX routing
    ↓
findings/
```

---

## Based on
*   **ItyFuzz** (Fuzzland) — hybrid fuzzing framework
*   **revm** — EVM execution backend
*   **LibAFL** — core fuzzing engine
*   **foundry-cheatcodes** — cheatcode interfaces
