use std::collections::HashMap;
use std::sync::Mutex;

use crypto::{digest::Digest, sha3::Sha3};
use lazy_static::lazy_static;

use super::onchain::ChainConfig;
use super::types::{EVMAddress, EVMU256};
use tracing::info;

/// Cache: token address → detected balance mapping slot number.
/// Populated once on first access, reused across all callers.
lazy_static! {
    static ref BALANCE_SLOT_CACHE: Mutex<HashMap<EVMAddress, u64>> = Mutex::new(HashMap::new());
}

/// Hardcoded overrides for well-known tokens whose balance mapping is NOT at
/// slot 0.  These are verified against the actual on-chain contract layout and
/// bypass the heuristic whale-detection algorithm entirely, which can produce
/// false positives when the fork RPC has inconsistent archive access.
const KNOWN_SLOTS: &[(EVMAddress, u64)] = &[
    // DAI (DS-Token, MakerDAO) — _balances mapping at slot 8
    (evm_addr("0x6B175474E89094C44Da98b954EedeAC495271d0F"), 8),
    // WETH (Vyper/Canonical WETH9) — balanceOf at slot 3
    (evm_addr("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"), 3),
    // USDC (FiatTokenV2_2, Circle) — _balances at slot 9
    (evm_addr("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"), 9),
    // USDC on Base
    (evm_addr("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"), 9),
    // USDT (Tether, OpenZeppelin-ish) — _balances at slot 0 (standard)
    (evm_addr("0xdAC17F958D2ee523a2206206994597C13D831ec7"), 0),
];

/// Well-known addresses that hold diverse tokens and have non-zero balances.
/// Using a variety of protocols ensures coverage for most tokens.
pub const WHALES: &[EVMAddress] = &[
    // MakerDAO Pause Proxy (holds DAI, MKR, USDC, etc.)
    evm_addr("0xBE8E3e3618f7474F8cB1d074A26afFef007E46FB"),
    // Aave Collector (AAVE, stkAAVE)
    evm_addr("0x464C71f6c2F760DdA6093dCB91C24c39e5d6e18c"),
    // Binance 14 (majority of BEP-20/ERC-20)
    evm_addr("0x28C6c06298d514Db089934071355E5743bf21d60"),
    // Bitfinex multisig
    evm_addr("0x742d35Cc6634C0532925a3b844Bc454e4438f44e"),
    // Ethereum Foundation (holds diverse tokens)
    evm_addr("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"),
    // Uniswap V3: Universal Router
    evm_addr("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"),
    // Compound Timelock (COMP, cTokens)
    evm_addr("0x6d903f6003cca6255D85CcA4D3B5E5146dC33925"),
    // Curve Treasury
    evm_addr("0x99aE10F7D7f41e5aE8cE3ebacC7e5A51bE2B8e1B"),
    // Arbitrum Bridge (holds various ETH L2 tokens)
    evm_addr("0xCEe284F754E854890e311e3280b767F80797180d"),
    // Gnosis Safe (accumulates fee tokens)
    evm_addr("0x0D0707963952f2fBA59dD06f2b425ace40b492Fe"),
];

/// Helper to parse a hex address at compile time.
const fn evm_addr(s: &str) -> EVMAddress {
    let bytes = s.as_bytes();
    assert!(bytes.len() == 42 && bytes[0] == b'0' && bytes[1] == b'x');
    let mut addr = [0u8; 20];
    let mut i = 0;
    while i < 20 {
        let hi = hex_val(bytes[2 + i * 2]);
        let lo = hex_val(bytes[2 + i * 2 + 1]);
        addr[i] = (hi << 4) | lo;
        i += 1;
    }
    EVMAddress::new(addr)
}

const fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Compute the storage slot for a Solidity mapping at `base_slot`:
/// `slot = keccak256(abi.encode(key, base_slot))`
/// which is `keccak256(leftPad(key, 32) ++ leftPad(base_slot, 32))`.
pub fn compute_mapping_storage_slot(key: EVMAddress, base_slot: EVMU256) -> EVMU256 {
    let mut input = [0u8; 64];
    // key occupies the last 20 bytes of the first 32-byte word
    input[12..32].copy_from_slice(key.as_slice());
    // base_slot occupies the second 32-byte word
    let slot_bytes = base_slot.to_be_bytes::<32>();
    input[32..64].copy_from_slice(&slot_bytes);

    let mut hasher = Sha3::keccak256();
    hasher.input(&input);
    let mut out = [0u8; 32];
    hasher.result(&mut out);
    EVMU256::from_be_bytes(out)
}

pub fn compute_vyper_mapping_storage_slot(key: EVMAddress, base_slot: EVMU256) -> EVMU256 {
    let mut input = [0u8; 64];
    // base_slot occupies the first 32-byte word
    let slot_bytes = base_slot.to_be_bytes::<32>();
    input[0..32].copy_from_slice(&slot_bytes);
    // key occupies the last 20 bytes of the second 32-byte word
    input[44..64].copy_from_slice(key.as_slice());

    let mut hasher = Sha3::keccak256();
    hasher.input(&input);
    let mut out = [0u8; 32];
    hasher.result(&mut out);
    EVMU256::from_be_bytes(out)
}

/// Read the cached balance slot for a token (returns None if not yet detected).
pub fn get_cached_balance_slot(token: &EVMAddress) -> Option<u64> {
    BALANCE_SLOT_CACHE.lock().unwrap().get(token).copied()
}

/// Detect which storage slot a token uses for its balance mapping.
///
/// Resolution order:
/// 1. Hardcoded KNOWN_SLOTS table (for well-known tokens like DAI, WETH, USDC)
/// 2. Whale cross-reference: find whales with non-zero balance, scan slots 0..20,
///    require consensus (≥2 whales) to avoid false positives.
/// 3. Fallback to slot 0.
///
/// Results are cached globally so each token is detected once per session.
pub fn detect_balance_slot(token: EVMAddress, chain: &mut dyn ChainConfig) -> u64 {
    // Check cache first
    if let Some(slot) = BALANCE_SLOT_CACHE.lock().unwrap().get(&token) {
        return *slot;
    }

    // Check hardcoded overrides for known tokens
    for &(known_addr, known_slot) in KNOWN_SLOTS {
        if known_addr == token {
            info!(
                "slot_detector: token {:?} balance slot = {known_slot} (known token override)",
                token,
            );
            BALANCE_SLOT_CACHE.lock().unwrap().insert(token, known_slot);
            return known_slot;
        }
    }

    // Whale-based detection with multi-whale consensus
    let mut candidates: Vec<(EVMAddress, EVMU256)> = Vec::new();
    for &whale in WHALES {
        let balance = chain.get_token_balance(token, whale);
        if balance > EVMU256::ZERO {
            candidates.push((whale, balance));
            if candidates.len() >= 3 {
                break; // enough whales to verify
            }
        }
    }

    if candidates.is_empty() {
        info!(
            "slot_detector: no whale found for token {:?}, defaulting to slot 0",
            token
        );
        return 0;
    }

    // Try Access List Slot Detection first
    for &(whale, _) in &candidates {
        let mut call_data = vec![0x70, 0xa0, 0x82, 0x31]; // balanceOf(address) selector
        let mut pad_address = [0u8; 32];
        pad_address[12..32].copy_from_slice(whale.as_slice());
        call_data.extend_from_slice(&pad_address);

        let accessed_slots = chain.get_access_list(whale, token, call_data);
        if !accessed_slots.is_empty() {
            for slot_num in 0..=50 {
                let slot_key = EVMU256::from(slot_num);
                
                // Solidity mapping check
                let solidity_slot = compute_mapping_storage_slot(whale, slot_key);
                if accessed_slots.contains(&solidity_slot) {
                    info!(
                        "slot_detector: token {:?} balance slot = {slot_num} (detected via Solidity access list)",
                        token
                    );
                    BALANCE_SLOT_CACHE.lock().unwrap().insert(token, slot_num);
                    return slot_num;
                }

                // Vyper mapping check
                let vyper_slot = compute_vyper_mapping_storage_slot(whale, slot_key);
                if accessed_slots.contains(&vyper_slot) {
                    info!(
                        "slot_detector: token {:?} balance slot = {slot_num} (detected via Vyper access list)",
                        token
                    );
                    BALANCE_SLOT_CACHE.lock().unwrap().insert(token, slot_num);
                    return slot_num;
                }
            }
        }
    }

    // Fallback: For each candidate slot, check if ≥2 whales agree.
    // This avoids false positives from coincidental single-whale matches.
    for slot_num in 0..=20 {
        let slot_key = EVMU256::from(slot_num);
        let mut matches = 0;
        for &(whale, expected) in &candidates {
            let raw = compute_mapping_storage_slot(whale, slot_key);
            let stored = chain.get_contract_slot(token, raw);
            if stored == expected {
                matches += 1;
            }
        }
        if matches >= 2 {
            info!(
                "slot_detector: token {:?} balance slot = {slot_num} (matched {}/{} whales via brute-force fallback)",
                token, matches, candidates.len()
            );
            BALANCE_SLOT_CACHE.lock().unwrap().insert(token, slot_num);
            return slot_num;
        }
    }

    // Fallback to slot 0
    info!(
        "slot_detector: balance slot not found for token {:?}, defaulting to slot 0",
        token
    );
    BALANCE_SLOT_CACHE.lock().unwrap().insert(token, 0);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::onchain::endpoints::OnChainConfig;
    use crate::evm::onchain::ChainConfig;
    use crate::evm::types::EVMAddress;
    use std::str::FromStr;

    #[cfg_attr(not(feature = "integration_test"), ignore)]
    #[test]
    fn test_access_list_slot_detection() {
        // Initialize OnChainConfig with a public RPC to verify.
        let rpc_url = "https://eth-mainnet.g.alchemy.com/v2/ZudLM8AAn0OCfiE5JvhAL".to_string();
        let mut config = OnChainConfig::new_raw(
            rpc_url,
            1,
            17000000, // fork at block 17,000,000
            "".to_string(),
            "eth".to_string(),
        );

        // LINK token address (Not in KNOWN_SLOTS, expected slot = 1)
        let link = EVMAddress::from_str("0x514910771AF9Ca656af840dff83E8264ECF986CA").unwrap();
        
        let detected = detect_balance_slot(link, &mut config as &mut dyn ChainConfig);
        assert_eq!(detected, 1);
    }
}

