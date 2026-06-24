// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Source: src/evm/tokens/UniversalAcquisitionEngine.sol
// The "do business" counterpart to UltimateForkLiquidationEngine.
// Given ETH, acquires any token the fuzzer needs as an exploit precondition.

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IWETH {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IERC4626 {
    function asset() external view returns (address);
    function deposit(uint256 assets, address receiver) external returns (uint256);
}

interface ICToken {
    function underlying() external view returns (address);
    function mint(uint256 mintAmount) external returns (uint256);
}

interface IAavePool {
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
}

interface IAToken {
    function UNDERLYING_ASSET_ADDRESS() external view returns (address);
}

interface IWstETH {
    function wrap(uint256 stETHAmount) external returns (uint256);
}

interface ILido {
    function submit(address referral) external payable returns (uint256);
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
    function swapExactETHForTokens(
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable returns (uint256[] memory amounts);

    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable;
}

interface IUniV3Factory {
    function getPool(address a, address b, uint24 fee) external view returns (address);
}

interface IUniV3Router {
    struct ExactInputSingleParams {
        address tokenIn; address tokenOut; uint24 fee; address recipient;
        uint256 deadline; uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256);
}

contract UniversalAcquisitionEngine {
    address public immutable WETH;
    address public immutable UNI_V2_FACTORY;
    address public immutable UNI_V2_ROUTER;
    address public immutable UNI_V3_FACTORY;
    address public immutable UNI_V3_ROUTER;
    address public immutable AAVE_V3_POOL;
    address public immutable LIDO;         // stETH
    address public immutable WSTETH;

    address constant CURVE_PROVIDER = 0x0000000022D53366457F9d5E68Ec105046FC4383;
    address constant ETH_SENTINEL   = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    uint24[4] private V3_FEES;

    receive() external payable {}

    constructor(
        address _weth,
        address _v2Factory,
        address _v2Router,
        address _v3Factory,
        address _v3Router,
        address _aavePool,
        address _lido,
        address _wsteth
    ) {
        WETH           = _weth;
        UNI_V2_FACTORY = _v2Factory;
        UNI_V2_ROUTER  = _v2Router;
        UNI_V3_FACTORY = _v3Factory;
        UNI_V3_ROUTER  = _v3Router;
        AAVE_V3_POOL   = _aavePool;
        LIDO           = _lido;
        WSTETH         = _wsteth;
        V3_FEES = [uint24(100), 500, 3000, 10000];
    }

    /// @notice Buy `token` using `msg.value` ETH. Transfer result to `recipient`.
    /// @return acquired Amount of token acquired and sent to recipient.
    function acquire(address token, address recipient) external payable returns (uint256 acquired) {
        if (msg.value == 0 || token == address(0)) return 0;

        // WETH: just wrap
        if (token == WETH) {
            IWETH(WETH).deposit{value: msg.value}();
            IWETH(WETH).transfer(recipient, msg.value);
            return msg.value;
        }

        // wstETH: ETH → stETH via Lido → wrap
        if (token == WSTETH && WSTETH != address(0)) {
            try ILido(LIDO).submit{value: msg.value}(address(0)) returns (uint256 stEthGot) {
                IERC20(LIDO).approve(WSTETH, stEthGot);
                try IWstETH(WSTETH).wrap(stEthGot) returns (uint256 wstGot) {
                    IERC20(WSTETH).transfer(recipient, wstGot);
                    return wstGot;
                } catch {}
            } catch {}
        }

        // ERC-4626: buy underlying, deposit
        try IERC4626(token).asset() returns (address underlying) {
            if (underlying != address(0)) {
                uint256 underlyingGot = _buyWithEth(underlying, msg.value, address(this));
                if (underlyingGot > 0) {
                    IERC20(underlying).approve(token, underlyingGot);
                    try IERC4626(token).deposit(underlyingGot, recipient) returns (uint256 shares) {
                        return shares;
                    } catch {}
                    // deposit failed — just give recipient the underlying
                    IERC20(underlying).transfer(recipient, underlyingGot);
                    return 0;
                }
            }
        } catch {}

        // Compound cToken: buy underlying, mint
        try ICToken(token).underlying() returns (address underlying) {
            if (underlying != address(0)) {
                uint256 underlyingGot = _buyWithEth(underlying, msg.value, address(this));
                if (underlyingGot > 0) {
                    IERC20(underlying).approve(token, underlyingGot);
                    try ICToken(token).mint(underlyingGot) returns (uint256 err) {
                        if (err == 0) {
                            uint256 bal = IERC20(token).balanceOf(address(this));
                            IERC20(token).transfer(recipient, bal);
                            return bal;
                        }
                    } catch {}
                    IERC20(underlying).transfer(recipient, underlyingGot);
                    return 0;
                }
            }
        } catch {}

        // Aave aToken: buy underlying, supply to Aave
        try IAToken(token).UNDERLYING_ASSET_ADDRESS() returns (address underlying) {
            if (underlying != address(0)) {
                uint256 underlyingGot = _buyWithEth(underlying, msg.value, address(this));
                if (underlyingGot > 0) {
                    IERC20(underlying).approve(AAVE_V3_POOL, underlyingGot);
                    try IAavePool(AAVE_V3_POOL).supply(underlying, underlyingGot, address(this), 0) {
                        uint256 bal = IERC20(token).balanceOf(address(this));
                        IERC20(token).transfer(recipient, bal);
                        return bal;
                    } catch {}
                    IERC20(underlying).transfer(recipient, underlyingGot);
                    return 0;
                }
            }
        } catch {}

        // Direct buy: try UniV3, then UniV2, then Curve
        uint256 got = _buyWithEth(token, msg.value, recipient);
        return got;
    }

    // ── Internal: buy token directly with ETH ────────────────────────────────

    function _buyWithEth(address token, uint256 ethAmt, address to) internal returns (uint256) {
        // UniV3 — try all fee tiers
        IWETH(WETH).deposit{value: ethAmt}();
        IERC20(WETH).approve(UNI_V3_ROUTER, ethAmt);
        for (uint256 k = 0; k < 4; k++) {
            try IUniV3Router(UNI_V3_ROUTER).exactInputSingle(
                IUniV3Router.ExactInputSingleParams({
                    tokenIn: WETH, tokenOut: token, fee: V3_FEES[k],
                    recipient: to, deadline: block.timestamp + 60,
                    amountIn: ethAmt, amountOutMinimum: 0, sqrtPriceLimitX96: 0
                })
            ) returns (uint256 got) {
                if (got > 0) return got;
            } catch {}
        }

        // UniV2 — fee-on-transfer safe
        address pair = IUniV2Factory(UNI_V2_FACTORY).getPair(token, WETH);
        if (pair != address(0)) {
            IERC20(WETH).approve(UNI_V2_ROUTER, ethAmt);
            // unwrap back to ETH for V2 which takes ETH directly
            IWETH(WETH).withdraw(ethAmt);
            address[] memory path = new address[](2);
            path[0] = WETH; path[1] = token;
            uint256 balBefore = IERC20(token).balanceOf(to);
            try IUniV2Router(UNI_V2_ROUTER).swapExactETHForTokensSupportingFeeOnTransferTokens{value: ethAmt}(
                0, path, to, block.timestamp + 60
            ) {
                return IERC20(token).balanceOf(to) - balBefore;
            } catch {}
            // re-wrap for curve attempt
            IWETH(WETH).deposit{value: ethAmt}();
        }

        // Curve — find pool and swap WETH → token
        {
            address pool = _findCurvePool(token);
            if (pool != address(0)) {
                (int128 j, int128 i, bool ok) = _curveIndices(pool, token);
                if (ok) {
                    IERC20(WETH).approve(pool, ethAmt);
                    try ICurvePool(pool).exchange(i, j, ethAmt, 0) returns (uint256 got) {
                        if (to != address(this)) IERC20(token).transfer(to, got);
                        return got;
                    } catch {}
                }
            }
        }

        // Nothing worked — return ETH to caller
        IWETH(WETH).withdraw(ethAmt);
        (bool ok, ) = msg.sender.call{value: ethAmt}("");
        require(ok);
        return 0;
    }

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
        internal view returns (int128 tokenIdx, int128 wethIdx, bool found)
    {
        bool gt; bool gw;
        for (uint256 k = 0; k < 4; k++) {
            try ICurvePool(pool).coins(k) returns (address coin) {
                if (coin == token) { tokenIdx = int128(uint128(k)); gt = true; }
                if (coin == WETH || coin == ETH_SENTINEL) { wethIdx = int128(uint128(k)); gw = true; }
            } catch { break; }
        }
        found = gt && gw;
    }
}
