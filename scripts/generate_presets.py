#!/usr/bin/env python3
"""
Generate DefiHacksPresets.json from DuckDB call database + DeFiHackLabs PoCs.

Maps function names from call trees to 4-byte selectors using:
1. Known standard function signatures (ERC20, Uniswap, Chainlink, etc.)
2. For custom functions, skips gracefully (won't match target ABI anyway)

Output: ExploitTemplate JSON appended to existing presets.
"""
import json
import os
import sys
import duckdb
from collections import OrderedDict

DB_PATH = "/workspace/_global/calls.db"
PRESETS_PATH = "/workspace/_global/spectorfuzz/tests/presets/DefiHacksPresets.json"

# ── Known standard function signatures ──────────────────────────────────────
# Format: function_name -> [(signature, selector_hex), ...]
# Multiple signatures per name because some functions have overloads (e.g., swap),
# and different protocols use different parameterizations.
STANDARD_SIGS = OrderedDict([
    # ── ERC20 / ERC721 / ERC4626 ──
    ("transfer", [
        ("transfer(address,uint256)", "0xa9059cbb"),
        ("transfer(address,uint256,bytes)", "0xbe45fd62"),
    ]),
    ("transferFrom", [
        ("transferFrom(address,address,uint256)", "0x23b872dd"),
        ("transferFrom(address,address,uint256,bytes)", "0x23b872dd"),
    ]),
    ("approve", [
        ("approve(address,uint256)", "0x095ea7b3"),
        ("approve(address,uint256,address,uint256)", "0x095ea7b3"),
    ]),
    ("allowance", [("allowance(address,address)", "0xdd62ed3e")]),
    ("balanceOf", [("balanceOf(address)", "0x70a08231")]),
    ("totalSupply", [("totalSupply()", "0x18160ddd")]),
    ("decimals", [("decimals()", "0x313ce567")]),
    ("name", [("name()", "0x06fdde03")]),
    ("symbol", [("symbol()", "0x95d89b41")]),
    ("burn", [("burn(uint256)", "0x42966c68"), ("burn(address,uint256)", "0x9dc29fac")]),
    ("mint", [("mint(address,uint256)", "0x40c10f19")]),
    ("deposit", [("deposit(uint256)", "0xb6b55f25"), ("deposit()", "0xd0e30db0")]),
    ("withdraw", [("withdraw(uint256)", "0x2e1a7d4d"), ("withdraw(address,uint256)", "0xf3fef3a3")]),
    ("redeem", [("redeem(uint256)", "0xbe040fb0"), ("redeem(uint256,address,address)", "0xba087652")]),

    # ── Uniswap V2 ──
    ("swap", [("swap(uint256,uint256,address,bytes)", "0x022c0d9f")]),
    ("sync", [("sync()", "0xfff6cae9")]),
    ("skim", [("skim(address)", "0xbc25cf77")]),
    ("getReserves", [("getReserves()", "0x0902f1ac")]),
    ("pairFor", [("pairFor(address,address,address)", "0xd5b4a4a3")]),
    ("getAmountsOut", [("getAmountsOut(uint256,address[])", "0xd06ca61f")]),
    ("getAmountsIn", [("getAmountsIn(uint256,address[])", "0xa88e1a5d")]),
    ("getAmountOut", [("getAmountOut(uint256,uint256,uint256)", "0x054d50d4")]),
    ("getPair", [("getPair(address,address)", "0xe6a43905")]),
    ("factory", [("factory()", "0xc45a0155")]),
    ("token0", [("token0()", "0x0dfe1681")]),
    ("token1", [("token1()", "0xd21220a7")]),
    ("swapExactTokensForTokens", [
        ("swapExactTokensForTokens(uint256,uint256,address[],address)", "0x38ed1739"),
    ]),
    ("swapExactTokensForETH", [
        ("swapExactTokensForETH(uint256,uint256,address[],address)", "0x18cbafe5"),
    ]),
    ("swapExactTokensForTokensSupportingFeeOnTransferTokens", [
        ("swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address)", "0xb6f9de95"),
    ]),
    ("swapExactETHForTokensSupportingFeeOnTransferTokens", [
        ("swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)", "0xb6f9de95"),
    ]),

    # ── Uniswap V3 ──
    ("slot0", [("slot0()", "0x3850c7bd")]),
    ("observe", [("observe(uint32[])", "0x883bdbfd")]),
    ("mint", [("mint(address,address,int24,int24,uint128,bytes)", "0x3c8a7d8d")]),
    ("exactInputSingle", [("exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))", "0x414bf389")]),
    ("exactInput", [("exactInput((bytes,address,uint256,uint256,uint256))", "0xc04b8d59")]),
    ("exactOutputSingle", [("exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))", "0xdb3e2198")]),
    ("exactOutput", [("exactOutput((bytes,address,uint256,uint256,uint256))", "0xf28c0498")]),
    ("uniswapV3SwapCallback", [("uniswapV3SwapCallback(int256,int256,bytes)", "0x23a69e75")]),
    ("uniswapV3MintCallback", [("uniswapV3MintCallback(uint256,uint256,bytes)", "0x7b7c2f28")]),
    ("uniswapV3FlashCallback", [("uniswapV3FlashCallback(uint256,uint256,bytes)", "0xefa80830")]),

    # ── PancakeSwap (same selectors as Uniswap V2 for most) ──
    ("pancakeCall", [("pancakeCall(address,uint256,uint256,bytes)", "0x10d1e85c")]),

    # ── Chainlink / Oracles ──
    ("latestRoundData", [("latestRoundData()", "0xfeaf968c")]),
    ("latestAnswer", [("latestAnswer()", "0x50d25bcd")]),
    ("getRoundData", [("getRoundData(uint80)", "0x9a6fc8f5")]),
    ("latestTimestamp", [("latestTimestamp()", "0xb633620c")]),
    ("getPrice", [("getPrice(address)", "0x41976e09")]),
    ("getAssetPrice", [("getAssetPrice(address)", "0xb3596f07")]),
    ("getPriceFromCacheOrOracle", [("getPriceFromCacheOrOracle(address)", "0x9faa3c91")]),
    ("peek", [("peek()", "0x59e02dd7")]),

    # ── Aave ──
    ("flashLoan", [
        ("flashLoan(address,address,uint256,bytes)", "0xab9c4b5d"),
    ]),
    ("flashLoanSimple", [("flashLoanSimple(address,address,uint256,bytes,uint16)", "0xab9c4b5d")]),
    ("deposit", [("deposit(address,uint256,address,uint16)", "0xe8eda9df")]),
    ("borrow", [("borrow(address,uint256,uint256,uint16,address)", "0xa415bcad")]),
    ("repay", [("repay(address,uint256,uint256,address)", "0x573ade81")]),
    ("liquidationCall", [("liquidationCall(address,address,address,uint256,bool)", "0x41c728b9")]),
    ("getReserveData", [("getReserveData(address)", "0x35ea6a75")]),
    ("getReserveNormalizedIncome", [("getReserveNormalizedIncome(address)", "0xd15e0053")]),
    ("getUserAccountData", [("getUserAccountData(address)", "0xbf92857c")]),
    ("executeOperation", [("executeOperation(address[],uint256[],address[],address)", "0x0b3a95b2")]),

    # ── Compound / Forks ──
    ("mint", [("mint(uint256)", "0xa0712d68"), ("mint()", "0x1249c58b")]),
    ("redeem", [("redeem(uint256)", "0xdb006a75")]),
    ("redeemUnderlying", [("redeemUnderlying(uint256)", "0x852a12e3")]),
    ("borrow", [("borrow(uint256)", "0xc5ebeaec")]),
    ("repayBorrow", [("repayBorrow(uint256)", "0x0e752702")]),
    ("liquidateBorrow", [("liquidateBorrow(address,uint256,address)", "0xf5e3c462")]),
    ("exchangeRateCurrent", [("exchangeRateCurrent()", "0xbd6d894d")]),
    ("exchangeRateStored", [("exchangeRateStored()", "0x182df0f5")]),
    ("getCash", [("getCash()", "0x3b1d21a2")]),
    ("totalBorrows", [("totalBorrows()", "0x08f87766")]),
    ("totalReserves", [("totalReserves()", "0x8f840ddd")]),
    ("seize", [("seize(address,address,address,uint256,uint256)", "0x0a1b9d4c")]),
    ("enterMarkets", [("enterMarkets(address[])", "0xc2998238")]),
    ("exitMarket", [("exitMarket(address)", "0xede4edd0")]),
    ("comptroller", [("comptroller()", "0x5fe3b567")]),
    ("getAccountLiquidity", [("getAccountLiquidity(address)", "0x2b1879b9")]),

    # ── Curve ──
    ("exchange", [("exchange(int128,int128,uint256,uint256)", "0x3df02124")]),
    ("exchange_underlying", [("exchange_underlying(int128,int128,uint256,uint256)", "0xa6417ed6")]),
    ("get_dy", [("get_dy(int128,int128,uint256)", "0x0e5566df")]),
    ("add_liquidity", [("add_liquidity(uint256[2],uint256)", "0x0b4c7e4d")]),
    ("remove_liquidity_one_coin", [("remove_liquidity_one_coin(uint256,int128,uint256)", "0x1a4d01d2")]),
    ("remove_liquidity", [("remove_liquidity(uint256,uint256[2])", "0x5b36389c")]),
    ("remove_liquidity_imbalance", [("remove_liquidity_imbalance(uint256[2],uint256)", "0x2b6e993a")]),

    # ── Convex / Yearn ──
    ("deposit", [("deposit(uint256,address)", "0x6e553f65")]),
    ("withdraw", [("withdraw(uint256,address,address)", "0xba087652")]),
    ("getPricePerFullShare", [("getPricePerFullShare()", "0x77c7b8fc")]),
    ("convertToAssets", [("convertToAssets(uint256)", "0x07a2d13a")]),
    ("convertToShares", [("convertToShares(uint256)", "0xef8b30f7")]),
    ("previewDeposit", [("previewDeposit(uint256)", "0xef8b30f7")]),
    ("previewRedeem", [("previewRedeem(uint256)", "0x4cdad506")]),
    ("totalAssets", [("totalAssets()", "0x01e1d114")]),
    ("maxWithdraw", [("maxWithdraw(address)", "0xd905777e")]),
    ("maxDeposit", [("maxDeposit(address)", "0x402d267d")]),
    ("maxRedeem", [("maxRedeem(address)", "0xd905777e")]),
    ("scaledTotalSupply", [("scaledTotalSupply()", "0x8f840ddd")]),
    ("scaledBalanceOf", [("scaledBalanceOf(address)", "0xb8e0e9b6")]),

    # ── Yield / Lido / stETH ──
    ("submit", [("submit(address)", "0xa1903eab")]),
    ("getPooledEthByShares", [("getPooledEthByShares(uint256)", "0x44f8c981")]),
    ("getSharesByPooledEth", [("getSharesByPooledEth(uint256)", "0x2820a2ca")]),
    ("wrap", [("wrap(uint256)", "0xea598cb0")]),
    ("unwrap", [("unwrap(uint256)", "0xde0e9a3e")]),

    # ── WETH ──
    ("deposit", [("deposit()", "0xd0e30db0")]),
    ("withdraw", [("withdraw(uint256)", "0x2e1a7d4d")]),

    # ── GMX / Perps ──
    ("increasePosition", [("increasePosition(address,address,address,uint256,uint256,uint256,uint256,bytes32,address)", "0x45fce190")]),
    ("decreasePosition", [("decreasePosition(address,address,address,uint256,uint256,uint256,bool,address)", "0x524e6e06")]),
    ("swap", [("swap(address,address,address,uint256,uint256,address,bytes)", "0x20d39c2f")]),

    # ── Balancer ──
    ("swap", [("swap((address,address,uint256,bytes,bytes,address),address,bytes)", "0x52bbbe29")]),
    ("joinPool", [("joinPool(bytes32,address,address,((address[],uint256[],bytes,bytes[])))", "0xb95cac28")]),
    ("exitPool", [("exitPool(bytes32,address,address,((address[],uint256[],bytes,bytes[])))", "0x8bdb3913")]),
    ("batchSwap", [("batchSwap((address,address,uint256,uint256,uint256,bytes),address[],int256[],uint256)", "0x945bcec9")]),
    ("getPoolTokens", [("getPoolTokens(bytes32)", "0xf94d4668")]),
    ("getSwapFeePercentage", [("getSwapFeePercentage()", "0x5c84df1b")]),
    ("queryBatchSwap", [("queryBatchSwap(uint8,(address,address,uint256,uint256,uint256,bytes)[],address[],int256[])", "0xd5c096c4")]),

    # ── Lido / Curve stETH ──
    ("get_virtual_price", [("get_virtual_price()", "0xbb7b27b7")]),
    ("get_dy", [("get_dy(int128,int128,uint256)", "0x0e5566df")]),
    ("calc_withdraw_one_coin", [("calc_withdraw_one_coin(uint256,int128)", "0xcc2b27d7")]),

    # ── Reentrancy / Callbacks ──
    ("onERC721Received", [("onERC721Received(address,address,uint256,bytes)", "0x150b7a02")]),
    ("onERC1155Received", [("onERC1155Received(address,address,uint256,uint256,bytes)", "0xf23a6e61")]),
    ("tokensReceived", [("tokensReceived(address,address,address,uint256,bytes,bytes)", "0x0023de29")]),
    ("receiveFlashLoan", [("receiveFlashLoan(IERC20[],uint256[],uint256[],bytes)", "0x0b3a95b2")]),

    # ── Multisig / Governance ──
    ("submitTransaction", [("submitTransaction(address,uint256,bytes)", "0xc6427474")]),
    ("confirmTransaction", [("confirmTransaction(uint256)", "0xc6427474")]),
    ("executeTransaction", [("executeTransaction(uint256)", "0x0db5dbdc")]),
    ("propose", [("propose(address[],uint256[],bytes[],string)", "0xda95691a")]),
    ("execute", [("execute(address[],uint256[],bytes[],bytes32,bytes32)", "0x6103a680")]),
    ("queue", [("queue(bytes32)", "0x83275c84")]),
    ("cancel", [("cancel(bytes32)", "0xfe4b84df")]),
    ("executeProposalWithIndex", [("executeProposalWithIndex(uint256,uint256)", "0x57cef759")]),
    ("grantRole", [("grantRole(bytes32,address)", "0x2f2ff15d")]),
    ("revokeRole", [("revokeRole(bytes32,address)", "0xd547741f")]),
    ("renounceRole", [("renounceRole(bytes32,address)", "0x36568abe")]),
    ("hasRole", [("hasRole(bytes32,address)", "0x91d14854")]),

    # ── Upgrade / Proxy ──
    ("upgradeTo", [("upgradeTo(address)", "0x3659cfe6")]),
    ("upgradeToAndCall", [("upgradeToAndCall(address,bytes)", "0x4f1ef286")]),
    ("implementation", [("implementation()", "0x5c60da1b")]),
    ("proxyOwner", [("proxyOwner()", "0x025313a2")]),
    ("transferOwnership", [("transferOwnership(address)", "0xf2fde38b")]),
    ("owner", [("owner()", "0x8da5cb5b")]),
    ("initialize", [("initialize()", "0x8129fc1c"), ("initialize(address,uint256,bytes)", "0xf364c3ec")]),

    # ── Other Common ──
    ("multicall", [("multicall(bytes[])", "0xac9650d8")]),
    ("delegateCallReserves", [("delegateCallReserves(address,bytes)", "0xd6742324")]),
    ("delegateToImplementation", [("delegateToImplementation(bytes)", "0x8b3a8ef7")]),
    ("performOperations", [("performOperations((address,uint256,bytes)[])", "0x6697872b")]),
    ("cook", [("cook((uint8,uint256,uint256)[])", "0x41dc2b0e")]),
    ("sweepToken", [("sweepToken(address,uint256)", "0xdfbc53db")]),
    ("skim", [("skim(address)", "0xbc25cf77")]),
    ("stake", [("stake(uint256)", "0xa694fc3a")]),
    ("unstake", [("unstake(uint256)", "0x2e17de78")]),
    ("claimRewards", [("claimRewards()", "0x3720040c")]),
    ("harvest", [("harvest()", "0x4641257d")]),

    # ── ERC-1967 Proxy ──
    ("getImplementation", [("getImplementation()", "0x5c60da1b")]),
    ("getAdmin", [("getAdmin()", "0xf851a440")]),

    # ── ERC-1155 ──
    ("safeTransferFrom", [("safeTransferFrom(address,address,uint256,uint256,bytes)", "0xf242432a")]),
    ("balanceOf", [("balanceOf(address,uint256)", "0x00fdd58e")]),
    ("setApprovalForAll", [("setApprovalForAll(address,bool)", "0xa22cb465")]),
    ("isApprovedForAll", [("isApprovedForAll(address,address)", "0xe985e9c5")]),

    # ── Lending / Borrowing ──
    ("deposit", [("deposit(uint256,uint256,address,address)", "0xaa7902ab")]),
    ("withdraw", [("withdraw(address,uint256,address,address)", "0x69328dec")]),
    ("borrow", [("borrow(address,uint256,uint256,address,address)", "0xef4234b1")]),
    ("repay", [("repay(address,uint256,uint256,address,address)", "0x4b8a3529")]),
    ("flashLoan", [("flashLoan(address,uint256,address,bytes)", "0x0b3a95b2")]),

    # ── Silo ──
    ("deposit", [("deposit(address,uint256,address,uint256)", "0xde3281b4")]),
    ("withdraw", [("withdraw(address,uint256,address,uint256)", "0x4e239145")]),
    ("borrow", [("borrow(address,uint256,address,uint256)", "0xc5e2d761")]),
    ("repay", [("repay(address,address,uint256,address)", "0x345983a8")]),

    # ── Morpho ──
    ("supply", [("supply(address,address,uint256,bytes)", "0x4b8a3529")]),
    ("borrow", [("borrow(address,address,uint256,address,address,uint256)", "0x50d64d0e")]),
    ("repay", [("repay(address,address,uint256,address,bytes)", "0x573ade81")]),
    ("withdraw", [("withdraw(address,address,uint256,address,address)", "0x69328dec")]),

    # ── Sudoswap ──
    ("swapETHForSpecificNFTs", [("swapETHForSpecificNFTs(uint256[],address[],uint256[],address,uint256)", "0xb1d3f1c1")]),
    ("swapNFTsForToken", [("swapNFTsForToken(uint256[],uint256[],address,address,uint256)", "0xd7d3b5f1")]),

    # ── Pendle ──
    ("swapExactPtForSy", [("swapExactPtForSy(address,uint256,bytes)", "0xc6bd2a2b")]),
    ("mintPY", [("mintPY(address,address,uint256)", "0xb8f18262")]),
    ("redeemPy", [("redeemPy(address,address,uint256)", "0x5cd1f88a")]),

    # ── Zapper / Aggregators ──
    ("zapIn", [("zapIn(address,uint256,address)", "0x6251ed3c")]),
    ("zapInToken", [("zapInToken(address,uint256,address,address)", "0xff8aae0f")]),

    # ── OneInch ──
    ("unoswapTo", [("unoswapTo(address,uint256,uint256,uint256[])", "0xa28b4e86")]),
    ("swap", [("swap(address,address,uint256,uint256,bytes)", "0x7c025200")]),

    # ── ERC-20 Permits ──
    ("permit", [("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", "0xd505accf")]),

    # ── Misc ──
    ("referredBy", []),  # custom — skip, won't match most ABIs
    ("identity", [("identity(uint256)", "0x4b85f48b")]),
    ("autoBurnLiquidityPairTokens", []),  # custom
    ("hourBurn", []),  # custom
    ("buyFor", []),  # custom
    ("claimToken", []),  # custom
    ("sellRewardToken", []),  # custom
])

def fn_name_to_selectors(name):
    """Convert a function name to list of possible 4-byte selectors."""
    if name in STANDARD_SIGS:
        sigs = STANDARD_SIGS[name]
        return [s[1] for s in sigs if s[1]]
    # Check if it's already a hex selector
    if name.startswith("0x") and len(name) == 10:
        return [name]
    # Unmapped custom function
    return []


def main():
    print(f"Connecting to {DB_PATH}...")
    con = duckdb.connect(DB_PATH)

    # Read existing presets
    existing = []
    if os.path.exists(PRESETS_PATH):
        with open(PRESETS_PATH) as f:
            existing = json.load(f)
        print(f"Existing templates: {len(existing)}")

    # Get all unique exploit file_names from the DB
    exploits = con.execute("""
        SELECT DISTINCT e.file_name, e.vuln_type, e.category
        FROM exploits e
        WHERE e.success = true
        ORDER BY e.file_name
    """).fetchall()
    print(f"Successful exploits in DB: {len(exploits)}")

    # Track existing exploit names to avoid dupes
    existing_names = set(t["exploit_name"] for t in existing)

    new_templates = []
    skipped = 0
    total_call_calls = 0
    mapped_call_calls = 0

    for (file_name, vuln_type, category) in exploits:
        # Skip if we already have it
        if file_name.replace("_exp", "") in existing_names:
            continue
        if file_name in existing_names:
            continue

        # Get all calls for this exploit, ordered by call_id (which preserves call tree order)
        calls = con.execute("""
            SELECT function_name, call_type, depth
            FROM calls
            WHERE file_name = ?
            AND function_name IS NOT NULL
            AND function_name != ''
            AND is_noise = false
            ORDER BY call_id
        """, [file_name]).fetchall()

        if not calls:
            continue

        # Build ordered call list and unique function sigs
        call_selectors = []  # ordered sequence
        fn_sig_set = {}      # deduped function_sigs

        for (fn_name, call_type, depth) in calls:
            selectors = fn_name_to_selectors(fn_name)
            total_call_calls += 1
            if selectors:
                mapped_call_calls += 1
                # Use the first matching selector
                sel = selectors[0]
                call_selectors.append(sel)
                fn_sig_set[sel] = True

        if not fn_sig_set:
            skipped += 1
            continue

        # Build exploit name from file_name
        exploit_name = file_name.replace("_exp.sol", "").replace("_exp", "").replace(".sol", "")
        if category:
            exploit_name = f"{category} {exploit_name}"
        if vuln_type:
            exploit_name = f"{vuln_type} {exploit_name}"

        template = {
            "exploit_name": exploit_name,
            "function_sigs": sorted(fn_sig_set.keys()),
            "calls": call_selectors,
        }
        new_templates.append(template)

    con.close()

    print(f"\nNew templates generated: {len(new_templates)}")
    print(f"Skipped (no mappable selectors): {skipped}")
    print(f"Call coverage: {mapped_call_calls}/{total_call_calls} ({mapped_call_calls*100//max(total_call_calls,1)}%)")

    # Merge with existing
    all_templates = existing + new_templates
    print(f"Total templates (existing + new): {len(all_templates)}")

    # Write back
    with open(PRESETS_PATH, "w") as f:
        json.dump(all_templates, f, indent=2)
    print(f"Written to {PRESETS_PATH}")

    # Stats
    total_sigs = sum(len(t["function_sigs"]) for t in all_templates)
    total_calls = sum(len(t["calls"]) for t in all_templates)
    print(f"Total function_sigs: {total_sigs}")
    print(f"Total calls: {total_calls}")


if __name__ == "__main__":
    main()
