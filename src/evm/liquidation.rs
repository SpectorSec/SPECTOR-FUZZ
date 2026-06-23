/// AutonomousLiquidationRouter
///
/// Replaces the Node.js pairs server entirely. Instead of making HTTP calls
/// to an external process that queries the chain via RPC, we query the chain
/// directly through the executor — the fork IS the pairs server.
///
/// Routing priority:
///   1. ERC-4626 vault shares → redeem() → recurse on underlying
///   2. Curve pool (via on-chain registry at 0x0000...022D53) → exchange()
///   3. Uniswap V2 factory → getPair() → swapExactTokensForETH (fee-on-transfer safe)
///   4. Uniswap V3 factory → getPool() → exactInputSingle()
///   5. Return ZERO (illiquid: NFT, unlisted token)
///
/// All discovery is done via fast_static_call on the live fork state.
/// No external processes, no hardcoded pool addresses, no hints needed.

use std::str::FromStr;

use bytes::Bytes;

use crate::evm::types::{EVMAddress, EVMU256};

// ── Well-known on-chain addresses (mainnet, same on most forks) ──────────────

/// Curve Finance AddressProvider — same address on every EVM chain Curve supports.
pub const CURVE_ADDRESS_PROVIDER: &str = "0x0000000022D53366457F9d5E68Ec105046FC4383";

/// Uniswap V2 factory (mainnet). Each chain has its own; we fall back to this.
pub const UNISWAP_V2_FACTORY_ETH: &str    = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f";
pub const UNISWAP_V2_ROUTER_ETH: &str     = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";

/// Uniswap V3 factory (mainnet / same on Arbitrum, Optimism, Polygon, Base).
pub const UNISWAP_V3_FACTORY_ETH: &str    = "0x1F98431c8aD98523631AE4a59f267346ea31F984";

// ── ABI selectors ─────────────────────────────────────────────────────────────

/// ERC-4626: asset() → address
const ERC4626_ASSET_SEL: [u8; 4] = [0x38, 0xd5, 0x2e, 0x0f];

/// Curve AddressProvider: get_address(uint256) → address
const CURVE_GET_ADDRESS_SEL: [u8; 4] = [0x49, 0x35, 0x00, 0xb1];

/// Curve Registry: find_pool_for_coins(address,address,uint256) → address
const CURVE_FIND_POOL_SEL: [u8; 4] = [0xa8, 0x7d, 0xf0, 0x6c];

/// Curve Pool: coins(uint256) → address
const CURVE_COINS_SEL: [u8; 4] = [0xc6, 0x61, 0x06, 0x57];

/// Uniswap V2 Factory: getPair(address,address) → address
const V2_GET_PAIR_SEL: [u8; 4] = [0xe6, 0xa4, 0x30, 0x48];

/// Uniswap V3 Factory: getPool(address,address,uint24) → address
const V3_GET_POOL_SEL: [u8; 4] = [0x17, 0x69, 0x83, 0x56];

const ZERO_ADDR: [u8; 20] = [0u8; 20];

// ── Helper: ABI encode / decode ───────────────────────────────────────────────

fn encode_address(addr: &EVMAddress) -> [u8; 32] {
    let mut slot = [0u8; 32];
    slot[12..].copy_from_slice(addr.as_slice());
    slot
}

fn encode_u256(v: u64) -> [u8; 32] {
    let mut slot = [0u8; 32];
    slot[24..].copy_from_slice(&v.to_be_bytes());
    slot
}

fn decode_address(data: &[u8]) -> Option<EVMAddress> {
    if data.len() < 32 { return None; }
    let addr = EVMAddress::from_slice(&data[12..32]);
    if addr.as_slice() == ZERO_ADDR { None } else { Some(addr) }
}

// ── Route result ──────────────────────────────────────────────────────────────

/// Result of autonomous route discovery.
/// The caller uses this to know HOW to liquidate, not just the dollar value.
#[derive(Debug, Clone)]
pub enum LiquidationRoute {
    /// ERC-4626: redeem shares → underlying token → recurse
    Vault {
        vault:      EVMAddress,
        underlying: EVMAddress,
    },
    /// Curve exchange: swap token → WETH via pool at given indices
    Curve {
        pool: EVMAddress,
        i:    i128,
        j:    i128,
    },
    /// Uniswap V2 pair: swapExactTokensForETHSupportingFeeOnTransferTokens
    UniV2 {
        pair:   EVMAddress,
        router: EVMAddress,
    },
    /// Uniswap V3 pool: exactInputSingle
    UniV3 {
        pool: EVMAddress,
        fee:  u32,
    },
    /// No liquid exit found (NFT, unlisted token)
    Illiquid,
}

// ── Main router ───────────────────────────────────────────────────────────────

pub struct LiquidationRouter {
    pub weth: EVMAddress,
    pub v2_factory: EVMAddress,
    pub v2_router:  EVMAddress,
    pub v3_factory: EVMAddress,
    pub curve_provider: EVMAddress,
    /// V3 fee tiers to probe in order
    pub v3_fees: Vec<u32>,
}

impl Default for LiquidationRouter {
    fn default() -> Self {
        Self {
            weth: EVMAddress::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
            v2_factory: EVMAddress::from_str(UNISWAP_V2_FACTORY_ETH).unwrap(),
            v2_router:  EVMAddress::from_str(UNISWAP_V2_ROUTER_ETH).unwrap(),
            v3_factory: EVMAddress::from_str(UNISWAP_V3_FACTORY_ETH).unwrap(),
            curve_provider: EVMAddress::from_str(CURVE_ADDRESS_PROVIDER).unwrap(),
            v3_fees: vec![500, 3000, 10000, 100],
        }
    }
}

impl LiquidationRouter {
    /// Override WETH and factory for non-mainnet chains (BSC, Polygon, etc.)
    pub fn with_chain(mut self, weth: EVMAddress, v2_factory: EVMAddress, v2_router: EVMAddress) -> Self {
        self.weth = weth;
        self.v2_factory = v2_factory;
        self.v2_router  = v2_router;
        self
    }

    /// Core entry point: given a token, discover the best liquidation route
    /// by making static calls directly against the fork state.
    ///
    /// `call` is a closure that wraps fast_static_call for a single (addr, data) pair.
    /// Signature: `|(addr, calldata)| → Vec<u8>` (empty = call failed/reverted).
    pub fn discover_route<F>(&self, token: EVMAddress, call: &mut F) -> LiquidationRoute
    where
        F: FnMut(EVMAddress, Bytes) -> Vec<u8>,
    {
        // ── 1. ERC-4626 ──────────────────────────────────────────────────────
        let asset_result = call(token, Bytes::from(ERC4626_ASSET_SEL.to_vec()));
        if let Some(underlying) = decode_address(&asset_result) {
            return LiquidationRoute::Vault { vault: token, underlying };
        }

        // ── 2. Curve (via on-chain registry) ─────────────────────────────────
        if let Some(route) = self.try_curve(token, call) {
            return route;
        }

        // ── 3. Uniswap V2 ────────────────────────────────────────────────────
        if let Some(pair) = self.try_v2_pair(token, call) {
            return LiquidationRoute::UniV2 { pair, router: self.v2_router };
        }

        // ── 4. Uniswap V3 ────────────────────────────────────────────────────
        for &fee in &self.v3_fees {
            if let Some(pool) = self.try_v3_pool(token, fee, call) {
                return LiquidationRoute::UniV3 { pool, fee };
            }
        }

        LiquidationRoute::Illiquid
    }

    // ── Curve discovery ───────────────────────────────────────────────────────

    fn try_curve<F>(&self, token: EVMAddress, call: &mut F) -> Option<LiquidationRoute>
    where
        F: FnMut(EVMAddress, Bytes) -> Vec<u8>,
    {
        // Get the main Curve registry address (id=0) from the AddressProvider.
        let mut cd = vec![CURVE_GET_ADDRESS_SEL[0], CURVE_GET_ADDRESS_SEL[1],
                          CURVE_GET_ADDRESS_SEL[2], CURVE_GET_ADDRESS_SEL[3]];
        cd.extend_from_slice(&encode_u256(0)); // id = 0 (main registry)
        let registry_raw = call(self.curve_provider, Bytes::from(cd));
        let registry = decode_address(&registry_raw)?;

        // Ask the registry: find_pool_for_coins(token, weth, 0)
        let mut cd = vec![CURVE_FIND_POOL_SEL[0], CURVE_FIND_POOL_SEL[1],
                          CURVE_FIND_POOL_SEL[2], CURVE_FIND_POOL_SEL[3]];
        cd.extend_from_slice(&encode_address(&token));
        cd.extend_from_slice(&encode_address(&self.weth));
        cd.extend_from_slice(&encode_u256(0)); // index 0 = first matching pool
        let pool_raw = call(registry, Bytes::from(cd));
        let pool = decode_address(&pool_raw)?;

        // Discover coin indices by iterating coins(0..4)
        let mut token_i: Option<i128> = None;
        let mut weth_j:  Option<i128> = None;
        // Curve uses address(0xEeee...EEeE) for native ETH
        let eth_sentinel = EVMAddress::from_str(
            "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"
        ).unwrap();

        for k in 0i128..4 {
            let mut cd = vec![CURVE_COINS_SEL[0], CURVE_COINS_SEL[1],
                              CURVE_COINS_SEL[2], CURVE_COINS_SEL[3]];
            cd.extend_from_slice(&encode_u256(k as u64));
            let coin_raw = call(pool, Bytes::from(cd));
            if coin_raw.is_empty() { break; }
            if let Some(coin) = decode_address(&coin_raw) {
                if coin == token                    { token_i = Some(k); }
                if coin == self.weth || coin == eth_sentinel { weth_j  = Some(k); }
            }
        }

        if let (Some(i), Some(j)) = (token_i, weth_j) {
            Some(LiquidationRoute::Curve { pool, i, j })
        } else {
            None
        }
    }

    // ── Uniswap V2 discovery ──────────────────────────────────────────────────

    fn try_v2_pair<F>(&self, token: EVMAddress, call: &mut F) -> Option<EVMAddress>
    where
        F: FnMut(EVMAddress, Bytes) -> Vec<u8>,
    {
        let mut cd = vec![V2_GET_PAIR_SEL[0], V2_GET_PAIR_SEL[1],
                          V2_GET_PAIR_SEL[2], V2_GET_PAIR_SEL[3]];
        cd.extend_from_slice(&encode_address(&token));
        cd.extend_from_slice(&encode_address(&self.weth));
        let result = call(self.v2_factory, Bytes::from(cd));
        decode_address(&result)
    }

    // ── Uniswap V3 discovery ──────────────────────────────────────────────────

    fn try_v3_pool<F>(&self, token: EVMAddress, fee: u32, call: &mut F) -> Option<EVMAddress>
    where
        F: FnMut(EVMAddress, Bytes) -> Vec<u8>,
    {
        let mut cd = vec![V3_GET_POOL_SEL[0], V3_GET_POOL_SEL[1],
                          V3_GET_POOL_SEL[2], V3_GET_POOL_SEL[3]];
        cd.extend_from_slice(&encode_address(&token));
        cd.extend_from_slice(&encode_address(&self.weth));
        // fee as uint24 — right-align in 32-byte slot
        let mut fee_slot = [0u8; 32];
        fee_slot[29..32].copy_from_slice(&fee.to_be_bytes()[1..4]);
        cd.extend_from_slice(&fee_slot);
        let result = call(self.v3_factory, Bytes::from(cd));
        decode_address(&result)
    }
}
