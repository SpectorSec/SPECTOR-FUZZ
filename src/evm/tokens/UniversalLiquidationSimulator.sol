// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IERC4626 {
    function asset() external view returns (address);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256);
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
    function getPair(address tokenA, address tokenB) external view returns (address pair);
}

interface IUniV2Pair {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112 r0, uint112 r1, uint32);
}

interface IUniV3Factory {
    function getPool(address tokenA, address tokenB, uint24 fee) external view returns (address pool);
}

interface IUniV3Pool {
    function swap(
        address recipient,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96,
        bytes calldata data
    ) external returns (int256 amount0, int256 amount1);
}

interface IUniV2Router {
    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external;
}

/// @title UniversalLiquidationSimulator
/// @notice Deployed onto the fork at a fixed address by the fuzzer.
///         Given any token, discovers the best liquidation route autonomously
///         via on-chain registries and executes the swap — no external pairs
///         server needed. Returns real ETH received (captures fee-on-transfer).
contract UniversalLiquidationSimulator {
    address public immutable WETH;
    address public immutable uniV2Factory;
    address public immutable uniV2Router;
    address public immutable uniV3Factory;

    ICurveAddressProvider constant CURVE_PROVIDER =
        ICurveAddressProvider(0x0000000022D53366457F9d5E68Ec105046FC4383);

    // ETH sentinel used by Curve for native ETH slots
    address constant ETH_SENTINEL = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    uint24[4] private V3_FEES = [uint24(500), 3000, 10000, 100];

    receive() external payable {}

    constructor(
        address _weth,
        address _uniV2Factory,
        address _uniV2Router,
        address _uniV3Factory
    ) {
        WETH = _weth;
        uniV2Factory = _uniV2Factory;
        uniV2Router = _uniV2Router;
        uniV3Factory = _uniV3Factory;
    }

    /// @notice Liquidate `amount` of `token` to ETH.
    ///         Tries: ERC-4626 unwrap → Curve → UniV2 → UniV3
    ///         Returns actual ETH received (0 if no route found).
    function liquidateToEth(address token, uint256 amount) external returns (uint256) {
        if (amount == 0 || token == address(0)) return 0;

        // ── 1. ERC-4626: unwrap shares → recurse on underlying ───────────────
        try IERC4626(token).asset() returns (address underlying) {
            if (underlying != address(0)) {
                IERC20(token).approve(token, amount);
                try IERC4626(token).redeem(amount, address(this), address(this))
                    returns (uint256 received)
                {
                    return this.liquidateToEth(underlying, received);
                } catch {}
            }
        } catch {}

        // ── 2. Curve: autonomous pool + index discovery ───────────────────────
        {
            address pool = _findCurvePool(token);
            if (pool != address(0)) {
                (int128 i, int128 j, bool ok) = _curveIndices(pool, token);
                if (ok) {
                    IERC20(token).approve(pool, amount);
                    uint256 before = address(this).balance;
                    try ICurvePool(pool).exchange(i, j, amount, 0) {
                        return address(this).balance - before;
                    } catch {}
                }
            }
        }

        // ── 3. Uniswap V2: fee-on-transfer safe swap ──────────────────────────
        {
            address pair = IUniV2Factory(uniV2Factory).getPair(token, WETH);
            if (pair != address(0)) {
                address[] memory path = new address[](2);
                path[0] = token;
                path[1] = WETH;
                IERC20(token).approve(uniV2Router, amount);
                uint256 before = address(this).balance;
                try IUniV2Router(uniV2Router)
                    .swapExactTokensForETHSupportingFeeOnTransferTokens(
                        amount, 0, path, address(this), block.timestamp + 3600
                    )
                {
                    return address(this).balance - before;
                } catch {}
            }
        }

        // ── 4. Uniswap V3: try common fee tiers ──────────────────────────────
        for (uint256 k = 0; k < 4; k++) {
            address pool = IUniV3Factory(uniV3Factory).getPool(token, WETH, V3_FEES[k]);
            if (pool != address(0)) {
                // V3 swap is complex; return 0 here — route exists, value TBD
                // A full V3 swap requires callback handling; stub for now.
                return 1; // non-zero signals "route found"
            }
        }

        return 0; // illiquid
    }

    /// @notice View-only route discovery — returns (routeType, pool/pair address).
    ///         routeType: 0=none, 1=erc4626, 2=curve, 3=univ2, 4=univ3
    function discoverRoute(address token)
        external
        view
        returns (uint8 routeType, address routeAddr)
    {
        // ERC-4626
        try IERC4626(token).asset() returns (address u) {
            if (u != address(0)) return (1, u);
        } catch {}

        // Curve
        address pool = _findCurvePool(token);
        if (pool != address(0)) return (2, pool);

        // UniV2
        address pair = IUniV2Factory(uniV2Factory).getPair(token, WETH);
        if (pair != address(0)) return (3, pair);

        // UniV3
        for (uint256 k = 0; k < 4; k++) {
            address v3pool = IUniV3Factory(uniV3Factory).getPool(token, WETH, V3_FEES[k]);
            if (v3pool != address(0)) return (4, v3pool);
        }

        return (0, address(0));
    }

    function _findCurvePool(address token) internal view returns (address) {
        try CURVE_PROVIDER.get_address(0) returns (address registry) {
            if (registry == address(0)) return address(0);
            try ICurveRegistry(registry).find_pool_for_coins(token, WETH, 0)
                returns (address pool)
            {
                if (pool != address(0)) return pool;
            } catch {}
            // Try with ETH sentinel
            try ICurveRegistry(registry).find_pool_for_coins(token, ETH_SENTINEL, 0)
                returns (address pool)
            {
                return pool;
            } catch {}
        } catch {}
        return address(0);
    }

    function _curveIndices(address pool, address token)
        internal
        view
        returns (int128 i, int128 j, bool found)
    {
        bool gotI;
        bool gotJ;
        for (uint256 k = 0; k < 4; k++) {
            try ICurvePool(pool).coins(k) returns (address coin) {
                if (coin == token) { i = int128(uint128(k)); gotI = true; }
                if (coin == WETH || coin == ETH_SENTINEL) { j = int128(uint128(k)); gotJ = true; }
            } catch { break; }
        }
        found = gotI && gotJ;
    }
}
