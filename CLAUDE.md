# CLAUDE.md

## Core Project Goal & Constraints
*   **Primary Objective**: Economic exploit detection (specifically **theft or direct loss of funds** rather than simple code correctness/reverts). We want to find high-value vulnerabilities that pay bounties.
*   **Workflow**: Pin a local Anvil fork from a public/free remote RPC node -> Run setup scripts on Anvil to deploy target contracts/state -> Point fuzzer at local Anvil (`http://127.0.0.1:8545`) using local compilation artifacts (`-t "out/*"`) to load ABIs.
*   **RPC Quota Constraint**: Strict low-volume RPC usage. No redundant queries. The fuzzer must load ABIs locally and rely on its **persistent local disk cache** (`cache/`) to intercept storage slot/bytecode queries so restarting Anvil doesn't hit the remote RPC.
*   **Profit Validation**: Use the **Whale-Consensus Slot Detector** (`slot_detector.rs`) to pre-fund caller balances and the **Autonomous Liquidation Router** to verify if drained assets can be swapped to WETH/USDC locally.
*   **Configured API Keys & Fallbacks**:
    *   Etherscan: `F2Y8KBJ66MHHPJ2IGT94IIUW4SD7KJKXBQ` (for ABIs)
    *   Primary Alchemy RPC: `https://eth-mainnet.g.alchemy.com/v2/ZudLM8AAn0OCfiE5JvhAL`
    *   Fallback Ankr RPC: `https://rpc.ankr.com/eth/4dc6bca2aff8bcb62f9989a3e104be5cd6ac025c004b3f7ef51696e7a678a54c`


## Guidance for Claude Code when working in this repository.

## What this is

SpectorSec fork of ItyFuzz — EVM hybrid fuzzer (concolic + coverage + reentrancy engine) built on LibAFL + revm 41.

Move/Sui support has been removed. This is EVM-only.

## Build

```bash
cargo build --release
cargo check   # fast type check
```

Requires Rust nightly (see `rust-toolchain.toml`).

## Running tests

```bash
cargo test
./target/release/ityfuzz evm -t 'build/*' --fetch-tx-data
```

## Architecture

### Core loop
- `src/evm/mod.rs` — CLI args, wires everything together
- `src/fuzzers/evm_fuzzer.rs` — LibAFL fuzzer setup
- `src/evm/host.rs` — EVM host (call dispatch, prank, middlewares)
- `src/evm/vm.rs` — EVMState, storage

### Weapons (do not strip)
- `src/evm/middlewares/reentrancy.rs` — PostExecutionCtx reentrancy engine
- `src/evm/middlewares/sha3_bypass.rs` — symbolic SHA3 taint
- `src/evm/concolic/` — concolic execution (Z3)
- `src/evm/middlewares/cheatcode/` — Foundry cheatcode support

### Oracles
- `src/evm/oracles/` — bug detectors (ERC20, reentrancy, arb-call, invariant, etc.)

### Onchain
- `src/evm/onchain/endpoints.rs` — RPC, etherscan, chain configs
- `src/evm/onchain/mod.rs` — OnChain middleware
- `src/evm/onchain/flashloan.rs` — flashloan simulation

### Artifacts
- `src/evm/blaz/` — BuildJobResult (artifact format), OffChainArtifact, linking
- `src/evm/contract_utils.rs` — ContractLoader

### Fixtures (load-bearing)
- `tests/presets/cheatcode/` — Cheatcode.t.sol (active work)
- `tests/presets/v2_pair/` — UniswapV2 bytecodes included via include_str! at compile time

## Key CLI flags

```
-t 'build/*'                    glob of .abi/.bin files
--fetch-tx-data                 fetch onchain tx data for setup
-c eth                          chain (eth, bsc, polygon, arb, etc.)
-b <block>                      fork block number
--flashloan                     enable flashloan simulation
--concolic                      enable concolic execution
--sha3-bypass                   enable SHA3 taint tracking
--onchain-etherscan-api-key KEY
```

## Do not remove
- `vendor/libafl_bolts-0.11.2` — patched, load-bearing
- `tests/presets/v2_pair/*.bytecode` — included via include_str! in contract_utils.rs
- `rust-toolchain.toml` — pins nightly version

## Git Synchronization & SSH Push Setup
*   **Target GitHub Repo**: `git@github.com:SpectorSec/SPECTOR-FUZZ.git` mapped under remote name `spectorfuzz`.
*   **SSH Credentials**: Authenticates automatically using the user's SSH keys configured at `~/.ssh/id_ed25519` (linked to `SpectorSec` GitHub account).
*   **Shallow/Divergent History Sync**: The remote repository was initialized with a different/shallow history. In order to sync local work, agents must:
    1.  Ensure the repository is unshallowed by running `git fetch --unshallow upstream` if it is shallow.
    2.  Force-push the local `main` branch to update the remote: `git push --force spectorfuzz main`.
