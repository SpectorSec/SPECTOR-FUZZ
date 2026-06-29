#!/usr/bin/env python3
"""Extract benchmark targets from DeFiHackLabs _exp.sol files."""
import json, os, re, sys

DEFIHACKLABS = "/workspace/_global/DeFiHackLabs/src/test"
OUTPUT = "/workspace/_global/spectorfuzz/scripts/benchmark_manifest.json"

CHAIN_MAP = {
    "mainnet":   {"chain": "eth",       "id": 1,     "explorer": "https://api.etherscan.io/v2/api?chainid=1"},
    "bsc":       {"chain": "bsc",       "id": 56,    "explorer": "https://api.bscscan.com/api"},
    "arbitrum":  {"chain": "arbitrum",  "id": 42161, "explorer": "https://api.arbiscan.io/api"},
    "polygon":   {"chain": "polygon",   "id": 137,   "explorer": "https://api.polygonscan.com/api"},
    "avalanche": {"chain": "avalanche", "id": 43114, "explorer": "https://api.snowtrace.io/api"},
    "fantom":    {"chain": "fantom",    "id": 250,   "explorer": "https://api.ftmscan.com/api"},
    "optimism":  {"chain": "optimism",  "id": 10,    "explorer": "https://api-optimistic.etherscan.io/api"},
    "base":      {"chain": "base",      "id": 8453,  "explorer": "https://api.basescan.org/api"},
    "celo":      {"chain": "celo",      "id": 42220, "explorer": "https://api.celoscan.io/api"},
    "gnosis":    {"chain": "gnosis",    "id": 100,   "explorer": "https://api.gnosisscan.io/api"},
    "linea":     {"chain": "linea",     "id": 59144, "explorer": "https://api.lineascan.build/api"},
    "mantle":    {"chain": "mantle",    "id": 5000,  "explorer": "https://api.mantlescan.xyz/api"},
    "blast":     {"chain": "blast",     "id": 81457, "explorer": "https://api.blastscan.io/api"},
    "moonriver": {"chain": "moonriver", "id": 1285,  "explorer": "https://api.moonriver.moonscan.io/api"},
    "sei":       {"chain": "sei",       "id": 1329,  "explorer": "https://api.seiscan.app/api"},
}

# Regex: createSelectFork("chain", block_num) or createSelectFork("chain", block_num - 1)
FORK_RE = re.compile(
    r'(?:cheats|vm)\.createSelectFork\("(\w+)",\s*([^)]+)\s*\)'
)
ADDR_RE = re.compile(r'0x([a-fA-F0-9]{40})')

def strip_us(n: str) -> int | None:
    n = n.strip().replace("_", "")
    # Check for arithmetic like "20729672-1" or "20729672 - 1"
    m = re.match(r"(\d+)\s*([+-])\s*(\d+)$", n)
    if m:
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        return a - b if op == "-" else a + b
    try:
        return int(n)
    except ValueError:
        return None  # variable-based block (blocknumToForkFrom, blockNumber, etc.)

def parse_exp_file(path: str) -> dict | None:
    with open(path) as f:
        text = f.read()

    m = FORK_RE.search(text)
    if not m:
        return None
    chain_name = m.group(1)
    block = strip_us(m.group(2))

    if block is None:
        print(f"  [skip] variable block number in {path}", file=sys.stderr)
        return None

    chain_info = CHAIN_MAP.get(chain_name)
    if not chain_info:
        print(f"  [skip] unknown chain '{chain_name}' in {path}", file=sys.stderr)
        return None

    # Collect all addresses; skip zero-address and known-non-contract noise
    all_addrs = set()
    for m2 in ADDR_RE.finditer(text):
        all_addrs.add("0x" + m2.group(1).lower())

    # Exclude zero address, deployer/test addresses often in comments/headers
    noise = {
        "0x0000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000001",
        "0x000000000000000000000000000000000000dead",
        "0x0000000000000000000000000000000000000002",
    }
    addrs = sorted(a for a in all_addrs if a not in noise)

    name = os.path.splitext(os.path.basename(path))[0]
    rel = os.path.relpath(path, DEFIHACKLABS)

    return {
        "name": name,
        "file": rel,
        "path": path,
        "chain_name": chain_name,
        "chain": chain_info["chain"],
        "chain_id": chain_info["id"],
        "block": block,
        "explorer": chain_info["explorer"],
        "addresses": sorted(addrs),
    }

def main():
    results = []
    for root, _dirs, files in os.walk(DEFIHACKLABS):
        for f in sorted(files):
            if not f.endswith("_exp.sol"):
                continue
            path = os.path.join(root, f)
            entry = parse_exp_file(path)
            if entry:
                results.append(entry)
                print(f"  {entry['name']}: chain={entry['chain']} block={entry['block']} addrs={len(entry['addresses'])}")
            else:
                print(f"  [skip] {f}: no fork/block info", file=sys.stderr)

    print(f"\nTotal targets extracted: {len(results)}")
    with open(OUTPUT, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Manifest written to {OUTPUT}")

if __name__ == "__main__":
    main()
