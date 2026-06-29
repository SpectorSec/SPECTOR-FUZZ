pub mod abi;
pub mod call;
pub mod contract;
pub mod girl;
pub mod utils;

/// Generate a Foundry PoC (.t.sol) from a pre-recorded call tree and ABI data.
/// This is the entry point for the SpecterFuzz bridge.
///
/// * `calls` — the call tree, one `Call` per testcase step (last = root).
/// * `sender` — the fuzzer deployer/caller address (hex).
/// * `selector_override` — maps selector hex (e.g. `"0xa9059cbb"`) to
///   full function signature (e.g. `"transfer(address,uint256)"`).
/// * `output_dir` — directory to write the `.t.sol` file into.
///
/// Returns `(output_path, contract_name)` on success.
pub fn gen_from_call_tree(
    calls: Vec<call::Call>,
    sender: &str,
    selector_override: std::collections::HashMap<String, String>,
    output_dir: &str,
    chain: String,
    block: String,
) -> Result<(String, String), anyhow::Error> {
    let mut gf = girl::Girlfriend::new(output_dir.to_string())
        .with_selector_override(selector_override)
        .with_fork(chain, block);
    gf.gen_from_calls(calls, sender)
}
