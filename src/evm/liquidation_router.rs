use bytes::Bytes;

use crate::evm::liquidation::LiquidationRoute;
use crate::evm::types::EVMAddress;

/// Discover how to route a token to its base asset (WETH/ETH) using
/// on-chain probes — no pairs server needed.
pub trait LiquidationRouter {
    /// Probe the fork state to find the best path from `token` to the
    /// base asset. Returns a [`LiquidationRoute`] describing the route.
    fn route_to_base<F>(&self, token: EVMAddress, call: &mut F) -> LiquidationRoute
    where
        F: FnMut(EVMAddress, Bytes) -> Vec<u8>;
}
