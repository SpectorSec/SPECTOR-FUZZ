// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Source: src/evm/tokens/UltimateForkLiquidationEngine.sol

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IWETH {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}

interface IERC4626 {
    function asset() external view returns (address);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256);
}

interface ICToken {
    function underlying() external view returns (address);
    function redeem(uint256 redeemTokens) external returns (uint256);
}

interface IAToken {
    function UNDERLYING_ASSET_ADDRESS() external view returns (address);
}

interface IAavePool {
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);
}

interface IWstETH {
    function stETH() external view returns (address);
    function unwrap(uint256 amount) external returns (uint256);
}

interface ICurveAddressProvider {
    function get_address(uint256 id) external view returns (address);
}

interface ICurveRegistry {
    function find_pool_for_coins(address from, address to, uint256 i) external view returns (address);
}

interface ICurvePool {
    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy) external payable returns (uint256);
    function coins(uint256 index) external view returns (address);
}

interface IUniV2Factory {
    function getPair(address a, address b) external view returns (address);
}

interface IUniV2Router {
    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline
    ) external;
}

interface IUniV3Factory {
    function getPool(address a, address b, uint24 fee) external view returns (address);
}

interface IUniV3Router {
    struct ExactInputSingleParams {
        address tokenIn; address tokenOut; uint24 fee; address recipient;
        uint256 deadline; uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata params) external returns (uint256);
}

interface ISudoPair {
    function swapNFTsForToken(uint256[] calldata nftIds, uint256 minOut, address payable to) external returns (uint256);
}

contract UltimateForkLiquidationEngine {
    address public immutable WETH;
    address public immutable UNI_V2_FACTORY;
    address public immutable UNI_V2_ROUTER;
    address public immutable UNI_V3_FACTORY;
    address public immutable UNI_V3_ROUTER;
    address public immutable AAVE_V3_POOL;

    address constant CURVE_PROVIDER    = 0x0000000022D53366457F9d5E68Ec105046FC4383;
    address constant ETH_SENTINEL      = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    uint24[4] private V3_FEES;

    receive() external payable {}

    constructor(
        address _weth,
        address _v2Factory,
        address _v2Router,
        address _v3Factory,
        address _v3Router,
        address _aavePool
    ) {
        WETH        = _weth;
        UNI_V2_FACTORY = _v2Factory;
        UNI_V2_ROUTER  = _v2Router;
        UNI_V3_FACTORY = _v3Factory;
        UNI_V3_ROUTER  = _v3Router;
        AAVE_V3_POOL   = _aavePool;
        V3_FEES = [uint24(100), 500, 3000, 10000];
    }

    // ── Main entrypoint ───────────────────────────────────────────────────────

    function resolveToEth(address asset, uint256 amount) external returns (uint256) {
        if (amount == 0 || asset == address(0)) return 0;
        if (asset == WETH) {
            IWETH(WETH).withdraw(amount);
            return amount;
        }

        uint256 before = address(this).balance;

        // 1. ERC-4626 vault shares → redeem → recurse
        try IERC4626(asset).asset() returns (address underlying) {
            if (underlying != address(0)) {
                IERC20(asset).approve(asset, amount);
                try IERC4626(asset).redeem(amount, address(this), address(this)) returns (uint256 got) {
                    return this.resolveToEth(underlying, got);
                } catch {}
            }
        } catch {}

        // 2. Compound cTokens → redeem → recurse
        try ICToken(asset).underlying() returns (address underlying) {
            if (underlying != address(0)) {
                IERC20(asset).approve(asset, amount);
                try ICToken(asset).redeem(amount) returns (uint256 err) {
                    if (err == 0) {
                        uint256 bal = IERC20(underlying).balanceOf(address(this));
                        return this.resolveToEth(underlying, bal);
                    }
                } catch {}
            }
        } catch {}

        // 3. Aave aTokens → pool withdraw → recurse
        try IAToken(asset).UNDERLYING_ASSET_ADDRESS() returns (address underlying) {
            if (underlying != address(0)) {
                IERC20(asset).approve(AAVE_V3_POOL, amount);
                try IAavePool(AAVE_V3_POOL).withdraw(underlying, amount, address(this)) returns (uint256 got) {
                    return this.resolveToEth(underlying, got);
                } catch {}
            }
        } catch {}

        // 4. wstETH → unwrap → recurse on stETH
        try IWstETH(asset).stETH() returns (address stEth) {
            if (stEth != address(0)) {
                IERC20(asset).approve(asset, amount);
                try IWstETH(asset).unwrap(amount) returns (uint256 got) {
                    return this.resolveToEth(stEth, got);
                } catch {}
            }
        } catch {}

        // 5. Curve registry discovery
        {
            address pool = _findCurvePool(asset);
            if (pool != address(0)) {
                (int128 i, int128 j, bool ok) = _curveIndices(pool, asset);
                if (ok) {
                    IERC20(asset).approve(pool, amount);
                    try ICurvePool(pool).exchange(i, j, amount, 0) {
                        return address(this).balance - before;
                    } catch {}
                }
            }
        }

        // 6. Uniswap V3 — try all fee tiers
        IERC20(asset).approve(UNI_V3_ROUTER, amount);
        for (uint256 k = 0; k < 4; k++) {
            try IUniV3Router(UNI_V3_ROUTER).exactInputSingle(
                IUniV3Router.ExactInputSingleParams({
                    tokenIn: asset, tokenOut: WETH, fee: V3_FEES[k],
                    recipient: address(this), deadline: block.timestamp + 60,
                    amountIn: amount, amountOutMinimum: 0, sqrtPriceLimitX96: 0
                })
            ) returns (uint256 wethOut) {
                IWETH(WETH).withdraw(wethOut);
                return address(this).balance - before;
            } catch {}
        }

        // 7. Uniswap V2 — fee-on-transfer safe
        {
            address pair = IUniV2Factory(UNI_V2_FACTORY).getPair(asset, WETH);
            if (pair != address(0)) {
                address[] memory path = new address[](2);
                path[0] = asset; path[1] = WETH;
                IERC20(asset).approve(UNI_V2_ROUTER, amount);
                try IUniV2Router(UNI_V2_ROUTER)
                    .swapExactTokensForETHSupportingFeeOnTransferTokens(
                        amount, 0, path, address(this), block.timestamp + 60
                    ) {
                    return address(this).balance - before;
                } catch {}
            }
        }

        return 0;
    }

    function resolveNftToEth(
        address nftContract,
        uint256[] calldata nftIds,
        address sudoPair
    ) external returns (uint256) {
        if (nftIds.length == 0 || nftContract == address(0)) return 0;
        uint256 before = address(this).balance;
        nftContract.call(abi.encodeWithSignature("setApprovalForAll(address,bool)", sudoPair, true));
        try ISudoPair(sudoPair).swapNFTsForToken(nftIds, 0, payable(address(this))) {
            return address(this).balance - before;
        } catch {}
        return 0;
    }

    // ── Discovery (for Rust router compatibility) ─────────────────────────────

    function discoverRoute(address token)
        external view
        returns (uint8 routeType, address routeAddr)
    {
        try IERC4626(token).asset() returns (address u) {
            if (u != address(0)) return (1, u);
        } catch {}
        try ICToken(token).underlying() returns (address u) {
            if (u != address(0)) return (2, u);
        } catch {}
        try IAToken(token).UNDERLYING_ASSET_ADDRESS() returns (address u) {
            if (u != address(0)) return (3, u);
        } catch {}
        address pool = _findCurvePool(token);
        if (pool != address(0)) return (4, pool);
        address pair = IUniV2Factory(UNI_V2_FACTORY).getPair(token, WETH);
        if (pair != address(0)) return (5, pair);
        for (uint256 k = 0; k < 4; k++) {
            address v3pool = IUniV3Factory(UNI_V3_FACTORY).getPool(token, WETH, V3_FEES[k]);
            if (v3pool != address(0)) return (6, v3pool);
        }
        return (0, address(0));
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    function _findCurvePool(address token) internal view returns (address) {
        try ICurveAddressProvider(CURVE_PROVIDER).get_address(0) returns (address reg) {
            if (reg == address(0)) return address(0);
            try ICurveRegistry(reg).find_pool_for_coins(token, WETH, 0) returns (address p) {
                if (p != address(0)) return p;
            } catch {}
            try ICurveRegistry(reg).find_pool_for_coins(token, ETH_SENTINEL, 0) returns (address p) {
                return p;
            } catch {}
        } catch {}
        return address(0);
    }

    function _curveIndices(address pool, address token)
        internal view returns (int128 i, int128 j, bool found)
    {
        bool gi; bool gj;
        for (uint256 k = 0; k < 4; k++) {
            try ICurvePool(pool).coins(k) returns (address coin) {
                if (coin == token) { i = int128(uint128(k)); gi = true; }
                if (coin == WETH || coin == ETH_SENTINEL) { j = int128(uint128(k)); gj = true; }
            } catch { break; }
        }
        found = gi && gj;
    }
}
