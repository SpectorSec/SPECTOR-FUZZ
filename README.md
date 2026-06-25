# SPECTOR-FUZZ
EVM-only DeFi flow extractor. Fork of ItyFuzz stripped to EVM and extended with an autonomous oracle pipeline.

The thesis: every DeFi exploit is one of six data-flow primitives. We don't audit — we extract flows, confirm exploitability on a live fork, and produce output.

## What's different from upstream ItyFuzz

### Autonomous Liquidation Router
Replaces the Node.js pairs server entirely. The fork IS the pairs server.

Queries Curve registry, Uniswap V2/V3 factories, and ERC-4626 vaults directly via `eth_call` against the live fork state. No external processes, no hardcoded pool addresses, no hints.

*   **Recursive Route Discovery**: Dynamically resolves and traces exit routes for vault and lending tokens (Compound, Aave, ERC-4626) recursively back to WETH.
*   **Dynamic Uniswap V3 Fee Resolution**: Queries active pool fees directly on-chain via `fee()` calls to format accurate swap paths.
*   **Priority**: ERC-4626 redeem → Curve registry → UniV2 getPair → UniV3 getPool → Illiquid
*   Per-chain factory overrides for BSC, Polygon, Arbitrum, Optimism.

### ABI Fingerprinting Pipeline
Oracles activate automatically from selector detection — no manual configuration.

| Selector | Detected as | Oracle activated |
|----------|-------------|------------------|
| `0x07a2d13a` | ERC-4626 vault | `ERC4626Oracle` |
| `0xfeaf968c` | Chainlink oracle | `FreshnessOracle` |
| `0x3644e515` | EIP-712 domain | permit seed corpus |
| 17 privileged keywords | Permission boundary | `FunctionOracle` |

### Oracle Suite (`-d all`)

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

All 14 DeFi Ghost properties covered.

### Cheatcode Extensions
`vm.computeCreateAddress`, `vm.computeCreate2Address` (both variants), `vm.getNonce` — CREATE2 exploit address prediction pattern.

Full existing suite: `vm.prank`, `vm.startPrank`, `vm.deal`, `vm.warp`, `vm.roll`, `vm.load`, `vm.store`, `vm.etch`, `vm.label`, `vm.createSelectFork`, `vm.expectRevert`, `vm.expectEmit`, `vm.recordLogs`, and all assert variants.

### Callback Surface Seeds
Corpus entries for every hook entry point:
- `onERC721Received` — NFT `safeTransferFrom` callback
- `onERC1155Received` / `onERC1155BatchReceived` — ERC-1155 callbacks
- `executeOperation` — Aave/Balancer flashloan callback
- `tokensReceived` — ERC-777 send callback

These are free execution windows mid-protocol-state. The fuzzer explores them automatically.

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

## Key Flags

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

Full flag reference in `src/evm/config.rs`.

## Six Primitives
Every DeFi exploit reduces to one:
1. **Control leak** — caller gains execution it shouldn't have
2. **Value leak** — more comes out than went in
3. **Message leak** — cross-contract call with unvalidated input
4. **Permission leak** — privileged function called by unprivileged caller
5. **Invariant leak** — protocol accounting breaks (k=xy, shares/assets ratio)
6. **Ownership leak** — asset ownership transferred without authorization

The oracle suite maps directly to these. `-d all` covers all six.

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

The fork is ground truth. No static analysis, no inference, no probability. The oracle fires because it observed the state change.

## Based on
- ItyFuzz — fuzzland
- revm — EVM execution
- LibAFL — fuzzing engine
- foundry-cheatcodes — cheatcode interface
