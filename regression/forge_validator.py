#!/usr/bin/env python3
"""Forge-based exploit reproducibility validator.

For each exploit, runs `forge test` against an anvil fork at the exploit's
block and reports success/failure. Groups exploits by (chain, fork_block)
to reuse anvil instances.

Usage:
  python3 forge_validator.py
  python3 forge_validator.py --categories Reentrancy --limit 5
  python3 forge_validator.py --batch 4  # parallel anvils
"""

import json
import subprocess
import sys
import time
import argparse
import signal
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

EXPLOITS_JSON = Path(__file__).parent / "exploits.json"

def start_anvil(chain: str, fork_block: int, rpc_port: int) -> subprocess.Popen:
    """Start an anvil fork at the given chain/block."""
    # Map chain names to RPC URLs
    RPC_URLS = {
        "mainnet": "https://eth.llamarpc.com",
        "ethereum": "https://eth.llamarpc.com",
        "eth": "https://eth.llamarpc.com",
        "bsc": "https://bsc-dataseed.binance.org",
        "bnb": "https://bsc-dataseed.binance.org",
        "polygon": "https://polygon-rpc.com",
        "matic": "https://polygon-rpc.com",
        "arbitrum": "https://arb1.arbitrum.io/rpc",
        "arb": "https://arb1.arbitrum.io/rpc",
        "optimism": "https://mainnet.optimism.io",
        "op": "https://mainnet.optimism.io",
        "gnosis": "https://rpc.gnosischain.com",
        "avalanche": "https://api.avax.network/ext/bc/C/rpc",
        "avax": "https://api.avax.network/ext/bc/C/rpc",
        "fantom": "https://rpc.ftm.tools",
        "base": "https://mainnet.base.org",
    }
    
    rpc = RPC_URLS.get(chain.lower(), f"https://{chain}.llamarpc.com")
    
    proc = subprocess.Popen(
        ["anvil",
         "--fork-url", rpc,
         "--fork-block-number", str(fork_block),
         "--port", str(rpc_port),
         "--silent",  # Reduce output noise
         "--block-time", "0",  # No auto-mining
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    
    # Wait for anvil to be ready
    time.sleep(2)
    return proc


def run_forge_test(sol_path: str, rpc_url: str) -> dict:
    """Run forge test for a single exploit file."""
    test_dir = Path(sol_path).parent
    file_name = Path(sol_path).name
    
    try:
        result = subprocess.run(
            ["forge", "test",
             "--match-path", file_name,
             "--fork-url", rpc_url,
             "-vvv",  # Verbose output for debugging
             "--no-match-coverage",
            ],
            cwd=test_dir,
            capture_output=True,
            text=True,
            timeout=120,  # 2 min per test
        )
        
        return {
            "returncode": result.returncode,
            "stdout": result.stdout[-2000:],  # Last 2000 chars
            "stderr": result.stderr[-2000:],
        }
    except subprocess.TimeoutExpired:
        return {
            "returncode": -1,
            "stdout": "TIMEOUT",
            "stderr": "",
        }
    except FileNotFoundError:
        return {
            "returncode": -2,
            "stdout": "forge not found",
            "stderr": "",
        }
    except Exception as e:
        return {
            "returncode": -3,
            "stdout": str(e),
            "stderr": "",
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str, default=str(EXPLOITS_JSON))
    parser.add_argument("--categories", type=str, default="",
                        help="Comma-separated vuln_type patterns")
    parser.add_argument("--limit", type=int, default=0,
                        help="Max exploits to test")
    parser.add_argument("--batch", type=int, default=1,
                        help="Number of parallel anvil instances")
    parser.add_argument("--port-start", type=int, default=8545,
                        help="Starting port for anvil instances")
    parser.add_argument("--dry-run", action="store_true",
                        help="Just print what would be tested")
    args = parser.parse_args()
    
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} not found. Run export_exploits.py first.")
        sys.exit(1)
    
    with open(input_path) as f:
        data = json.load(f)
    
    # Filter exploits
    exploits = data["exploits"]
    if args.categories:
        patterns = [p.strip().lower() for p in args.categories.split(",")]
        exploits = [e for e in exploits 
                   if any(p in e["vuln_type"].lower() for p in patterns)]
    
    if args.limit > 0:
        exploits = exploits[:args.limit]
    
    # Filter to those with sol_path
    exploits = [e for e in exploits if e.get("sol_path")]
    
    # Group by fork_block + chain
    groups = defaultdict(list)
    for e in exploits:
        key = (e["chain"], e["fork_block"])
        groups[key].append(e)
    
    print(f"Groups: {len(groups)}, Exploits: {len(exploits)}")
    
    if args.dry_run:
        for (chain, block), exps in sorted(groups.items())[:5]:
            print(f"  {chain} @ {block}: {len(exps)} exploits")
        return
    
    results = {"pass": 0, "fail": 0, "skip": 0, "timeout": 0}
    details = []
    
    port = args.port_start
    running_anvils = {}
    
    def handle_sigint(sig, frame):
        print("\nShutting down...")
        for proc in running_anvils.values():
            proc.terminate()
        sys.exit(1)
    
    signal.signal(signal.SIGINT, handle_sigint)
    
    for (chain, block), exps in sorted(groups.items()):
        print(f"\n{'='*60}")
        print(f"Fork: {chain} @ block {block} ({len(exps)} exploits)")
        print(f"{'='*60}")
        
        # Start anvil
        proc = start_anvil(chain, block, port)
        running_anvils[(chain, block)] = proc
        rpc_url = f"http://localhost:{port}"
        port += 1
        if port > args.port_start + 20:
            port = args.port_start  # Wrap around
        time.sleep(1)
        
        for exploit in exps:
            file_name = exploit["file_name"]
            sol_path = exploit["sol_path"]
            vt = exploit["vuln_type"]
            
            print(f"  Testing: {file_name} ({vt})...", end=" ", flush=True)
            
            if not Path(sol_path).exists():
                print("SKIP (file not found)")
                results["skip"] += 1
                continue
            
            res = run_forge_test(sol_path, rpc_url)
            
            if res["returncode"] == 0:
                print("PASS")
                results["pass"] += 1
            elif res["returncode"] == -1:
                print("TIMEOUT")
                results["timeout"] += 1
            elif res["returncode"] == -2:
                print("SKIP (forge not found)")
                results["skip"] += 1
            else:
                print("FAIL")
                results["fail"] += 1
                # Show last few lines of output
                out = res["stdout"][-500:]
                # Find the relevant failure message
                for line in out.split("\n"):
                    if "FAIL" in line or "Error" in line or "revert" in line.lower():
                        print(f"    {line.strip()[:120]}")
            
            details.append({
                "file_name": file_name,
                "vuln_type": vt,
                "chain": chain,
                "fork_block": block,
                "result": "PASS" if res["returncode"] == 0 else "FAIL" if res["returncode"] > 0 else "TIMEOUT",
            })
        
        # Stop anvil
        proc.terminate()
        proc.wait()
        del running_anvils[(chain, block)]
    
    # Summary
    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")
    total = sum(results.values())
    print(f"  PASS:    {results['pass']}")
    print(f"  FAIL:    {results['fail']}")
    print(f"  TIMEOUT: {results['timeout']}")
    print(f"  SKIP:    {results['skip']}")
    print(f"  TOTAL:   {total}")
    
    return 0 if results["fail"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
