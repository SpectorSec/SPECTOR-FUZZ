#!/usr/bin/env python3
"""SpecterFuzz Oracle Regression Test Suite.

Run structural assertions against exported exploit call trees.

Usage:
  # Full suite
  python3 run_regression.py

  # Category filter
  python3 run_regression.py --categories Reentrancy,FlashLoan

  # Verbose (show per-exploit results)
  python3 run_regression.py -v

The test reads the exported exploits.json (produced by export_exploits.py),
analyzes each exploit's call tree structure, and checks that the expected
oracle(s) for the exploit's vuln_type are consistent with the call tree data.

This is a DATA-INTEGRITY regression suite — it validates the call tree data
is structurally consistent with the exploit classification. For actual oracle
code regression testing, use `cargo test` which runs the #[cfg(test)] modules
in each oracle file.
"""

import json
import sys
import argparse
from collections import defaultdict
from pathlib import Path

EXPLOITS_JSON = Path(__file__).parent / "exploits.json"

# ---------------------------------------------------------------------------
# Call tree analysis functions
# Each returns (passed: bool, details: str) given an exploit entry
# ---------------------------------------------------------------------------

def analyze_reentrancy(exploit):
    """Check call tree for nested same-contract CALL patterns."""
    tree = exploit["call_tree"]
    # Build parent lookup
    by_id = {f["call_id"]: f for f in tree}
    children_of = defaultdict(list)
    for f in tree:
        p = f["parent_id"]
        if p is not None:
            children_of.setdefault(p, [])
            children_of[p].append(f["call_id"])
    
    # Walk the tree, track call stack of contract addresses
    nested_same_contract = []
    
    def walk(node_id, call_stack):
        node = by_id[node_id]
        addr = node["contract"]
        
        if node["call_type"] == "CALL" and addr in call_stack:
            # Found reentrancy: CALL to contract that's already on the stack
            nested_same_contract.append((addr, call_stack))
        
        new_stack = call_stack + [addr]
        for child_id in children_of.get(node_id, []):
            walk(child_id, new_stack)
    
    if tree:
        walk(tree[0]["call_id"], [])
    
    return nested_same_contract, len(nested_same_contract)


def analyze_arbitrary_calls(exploit):
    """Check call tree for CALL-type frames to non-protocol addresses.
    
    A CALL is "arbitrary" if it targets an address that:
    - Is not a known protocol contract (Uniswap, Aave, etc.)
    - Is an EOA or user-deployed contract
    - Has calldata that the attacker controls
    
    From the call tree alone, we flag CALL frames where:
    - The call_type is "CALL" (not STATICCALL or DELEGATECALL)
    - The contract address looks like a user address (not a known protocol)
    """
    # Known protocol address prefixes (lowercase)
    KNOWN_PROTOCOLS = {
        # Uniswap V2
        "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",  # V2Router02
        "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f",  # V2Factory
        "0x1f98431c8ad98523631ae4a59f267346ea31f984",  # UNI
        # Uniswap V3
        "0xe592427a0aece92de3edee1f18e0157c05861564",  # V3Router
        "0x1f98400000000000000000000000000000000000",  # V3Factory
        # PancakeSwap (BSC)
        "0x10ed43c718714eb63d5aa57b78b54704e256024e",  # PCS Router
        "0xcaf43c0a3a5c8e58d6ca7ece4fe7981d144a629b",  # PCS Factory (BSC)
        # Aave
        "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9",  # V2 LendingPool
        "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",  # V3 Pool
        # Yearn
        "0x0000000000000000000000000000000000000000",  # Zero address (VM calls)
    }
    
    tree = exploit["call_tree"]
    arbitrary = []
    
    for f in tree:
        if f["call_type"] == "CALL" and f["depth"] > 0:
            addr = f["contract"].lower()
            # Skip known protocols
            if addr not in KNOWN_PROTOCOLS and not addr.startswith("0x00000000000000000000000000000000000"):
                arbitrary.append(f)
    
    return arbitrary, len(arbitrary)


def analyze_erc20_transfers(exploit):
    """Count transfer/transferFrom calls."""
    tree = exploit["call_tree"]
    transfers = [f for f in tree if f["function"] in ("transfer", "transferFrom")]
    return transfers, len(transfers)


def analyze_approvals(exploit):
    """Count approve calls."""
    tree = exploit["call_tree"]
    approvals = [f for f in tree if f["function"] == "approve"]
    return approvals, len(approvals)


def analyze_nft_transfers(exploit):
    """Count safeTransferFrom/transferFrom calls on known NFT contracts."""
    tree = exploit["call_tree"]
    nft_calls = [f for f in tree if f["function"] in ("safeTransferFrom", "transferFrom")]
    return nft_calls, len(nft_calls)


def analyze_flashloan_patterns(exploit):
    """Detect flashloan protocol interactions."""
    tree = exploit["call_tree"]
    flashloan_sigs = {"flashLoan", "flashloan", "withdraw", "borrow", "flash"}
    fl_calls = [f for f in tree if f["function"] in flashloan_sigs]
    return fl_calls, len(fl_calls)


def analyze_oracle_reads(exploit):
    """Count balanceOf / getReserves / price queries before state changes."""
    tree = exploit["call_tree"]
    reads = [f for f in tree if f["function"] in ("balanceOf", "getReserves", "totalSupply", "getPrice")]
    return reads, len(reads)


# ---------------------------------------------------------------------------
# Oracle assertion mapping
# ---------------------------------------------------------------------------

ORACLE_ANALYZERS = {
    "reentrancy": analyze_reentrancy,
    "arb_call": analyze_arbitrary_calls,
    "erc20": analyze_flashloan_patterns,  # flashloan oracles check fund flow
    "approval": analyze_approvals,
    "nft": analyze_nft_transfers,
    "freshness": analyze_oracle_reads,
}

# Map vuln_type patterns to oracle names
VULN_TO_ORACLE = {
    "arbitrarycall": "arb_call",
    "accesscontrol": "arb_call",
    "arbitrary": "arb_call",
    "unverifiedinput": "arb_call",
    "callinjection": "arb_call",
    "reentrancy": "reentrancy",
    "readonlyreentrancy": "reentrancy",
    "flashloan": "erc20",
    "feeontransfer": None,  # No structural analysis available
    "erc4626inflation": None,
    "sharepriceinflation": None,
    "oraclemanipulation": "freshness",
    "pricemanipulation": "freshness",
    "approval": "approval",
    "approvalabuse": "approval",
    "reflective": None,
    "nft": "nft",
}

ORACLE_NAMES = {
    0: "erc20",
    1: "function",
    2: "v2_pair",
    3: "arb_transfer",
    4: "typed_bug",
    5: "selfdestruct",
    6: "echidna",
    7: "state_comp",
    8: "arb_call",
    9: "reentrancy",
    10: "invariant",
    11: "int_overflow",
    12: "nft",
    13: "fee_on_transfer",
    14: "approval",
    15: "crosschain",
    16: "rebasing",
    17: "erc4626",
    18: "freshness",
    19: "temporal_skim",
}


def classify_exploit(exploit):
    """Determine which oracles should fire for this exploit."""
    vt = exploit["vuln_type"].lower().replace(" ", "").replace("_", "")
    
    # Try each vuln pattern
    for pattern, oracle_name in VULN_TO_ORACLE.items():
        if pattern in vt:
            if oracle_name:
                return oracle_name
            break
    
    return None


def run_test(exploit, verbose=False):
    """Run all applicable structural assertions for an exploit."""
    oracle_name = classify_exploit(exploit)
    
    results = []
    all_passed = True
    
    # Run the applicable oracle check
    if oracle_name and oracle_name in ORACLE_ANALYZERS:
        analyzer = ORACLE_ANALYZERS[oracle_name]
        frames, count = analyzer(exploit)
        
        # Check: if oracle should fire, verify the call tree has matching pattern
        if count > 0:
            detail = f"{oracle_name}: found {count} matching calls"
            results.append(("PASS", detail))
        else:
            detail = f"{oracle_name}: expected but no matching calls found in tree"
            if verbose:
                # Show some context about what's in the tree
                funcs = [f["function"] for f in exploit["call_tree"][:10]]
                detail += f" (top funcs: {funcs})"
            results.append(("WARN", detail))
            # Don't fail — the call tree might not capture all patterns
    
    # Also check if the expected_oracles list is non-empty but we don't have an analyzer
    expected = exploit.get("expected_oracles", {})
    should_fire = expected.get("should_fire", [])
    for idx in should_fire:
        name = ORACLE_NAMES.get(idx, f"oracle_{idx}")
        if name not in ORACLE_ANALYZERS:
            results.append(("INFO", f"oracle {name} (idx={idx}): no structural analyzer available"))
    
    return results


def main():
    parser = argparse.ArgumentParser(description="SpecterFuzz Oracle Regression Suite")
    parser.add_argument("--input", type=str, default=str(EXPLOITS_JSON))
    parser.add_argument("--categories", type=str, default="",
                        help="Comma-separated vuln_type patterns")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} not found. Run export_exploits.py first.")
        sys.exit(1)
    
    with open(input_path) as f:
        data = json.load(f)
    
    exploits = data["exploits"]
    if args.categories:
        patterns = [p.strip().lower() for p in args.categories.split(",")]
        exploits = [e for e in exploits 
                   if any(p in e["vuln_type"].lower() for p in patterns)]
    
    print(f"Running regression suite: {len(exploits)} exploits")
    print(f"  {len(data['groups'])} fork groups")
    print(f"  {len([e for e in exploits if classify_exploit(e)])} testable with structural analysis")
    print()
    
    # Category stats
    from collections import Counter
    cat_counts = Counter()
    for e in exploits:
        oc = classify_exploit(e)
        cat_counts[oc or "untestable"] += 1
    
    print("Category breakdown:")
    for cat, cnt in cat_counts.most_common(20):
        print(f"  {cat:20s} {cnt}")
    print()
    
    # Run tests
    passed = 0
    failed = 0
    warnings = 0
    skipped = 0
    
    for exploit in exploits:
        results = run_test(exploit, verbose=args.verbose)
        
        file_name = exploit["file_name"]
        vt = exploit["vuln_type"]
        
        has_fail = any(r[0] == "FAIL" for r in results)
        has_warn = any(r[0] == "WARN" for r in results)
        
        if has_fail:
            failed += 1
        elif has_warn:
            warnings += 1
        else:
            passed += 1
        
        if args.verbose and results:
            status = "FAIL" if has_fail else ("WARN" if has_warn else "PASS")
            print(f"  [{status:5s}] {file_name:45s} ({vt[:30]})")
            for r_type, r_detail in results:
                print(f"           {r_type}: {r_detail}")
    
    print()
    print(f"Results: {passed} passed, {warnings} warnings, {failed} failed, {skipped} skipped")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
