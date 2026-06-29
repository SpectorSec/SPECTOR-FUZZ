use std::collections::HashMap;

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref TIMESTAMP_SIG: HashMap<&'static str, usize> = HashMap::from_iter(vec![
        ("addLiquidity", 7),
        ("addLiquidityETH", 5),
        ("removeLiquidity", 6),
        ("removeLiquidityETH", 5),
        ("removeLiquidityWithPermit", 6),
        ("removeLiquidityETHWithPermit", 5),
        ("swapExactTokensForTokens", 4),
        ("swapTokensForExactTokens", 4),
        ("swapExactETHForTokens", 3),
        ("swapTokensForExactETH", 4),
        ("swapExactTokensForETH", 4),
        ("swapETHForExactTokens", 3),
        ("removeLiquidityETHSupportingFeeOnTransferTokens", 5),
        ("removeLiquidityETHWithPermitSupportingFeeOnTransferTokens", 5),
        ("swapExactTokensForTokensSupportingFeeOnTransferTokens", 4),
        ("swapExactETHForTokensSupportingFeeOnTransferTokens", 3),
        ("swapExactTokensForETHSupportingFeeOnTransferTokens", 4),
        ("selfPermit", 2),
        ("selfPermitIfNecessary", 2),
    ]);
}

/// Fallback: try to look up a selector from 4byte.directory.
/// Only called when selector_override has no match.
pub fn get_fn_signature(input: &str, output: &str, target: &str) -> Result<(String, Option<String>)> {
    let ret_sig = guess_ret_signature(output);
    // Try the HTTP lookup
    match lookup_selector(&input[..10]) {
        Ok(fn_sig) => Ok((fn_sig, ret_sig)),
        Err(e) => Err(e),
    }
}

fn lookup_selector(selector: &str) -> Result<String> {
    let url = format!("https://api.openchain.xyz/signature-database/v1/lookup?function={}&filter=true", selector);
    let resp = reqwest::blocking::get(&url)
        .and_then(|r| r.json::<serde_json::Value>())
        .map_err(|e| anyhow!("HTTP lookup failed: {}", e))?;
    if !resp["ok"].as_bool().unwrap_or_default() {
        return Err(anyhow!("Signature not found"));
    }
    let found = resp["result"]["function"][selector].as_array();
    match found.and_then(|a| a.first()).and_then(|v| v["name"].as_str()) {
        Some(sig) if !sig.is_empty() => Ok(sig.to_string()),
        _ => Err(anyhow!("Signature not found")),
    }
}

fn guess_ret_signature(output: &str) -> Option<String> {
    match super::guesser::abi_guess(output) {
        Ok(super::guesser::GuessedAbi::ParamSig(sig)) => Some(sig),
        _ => None,
    }
}
