use std::collections::HashMap;

use libafl::prelude::HasMetadata;

use super::girlfriend::{self, call::Call, gen_from_call_tree};
use crate::evm::{
    corpus_initializer::ABIMap,
    host::CallTreeMetadata,
};

/// Generate a Girlfriend-grade Foundry PoC from the minimizer's call tree
/// stored in EVMFuzzState metadata.
///
/// Called from the generic fuzzer bug-found path. Silently no-ops if no
/// call tree metadata exists (e.g. non-EVM backends).
pub fn generate_girlfriend_poc(state: &impl HasMetadata, work_dir: &str) {
    let Some(call_tree_meta) = state.metadata_map().get::<CallTreeMetadata>() else {
        tracing::debug!("[girlfriend] no CallTreeMetadata in state — skipping PoC");
        return;
    };
    let frames = &call_tree_meta.frames;
    tracing::debug!("[girlfriend] CallTreeMetadata has {} top-level frames", frames.len());
    if frames.is_empty() {
        return;
    }

    let mut selector_override: HashMap<String, String> = HashMap::new();
    if let Some(abi_map) = state.metadata_map().get::<ABIMap>() {
        for (sig, config) in &abi_map.signature_to_abi {
            // girl.rs looks up by `&call.input[..10]` = "0x"+8 hex (WITH prefix) and expects a
            // FULL signature like "transfer(address,uint256)". ABIConfig stores the name and
            // the "(types)" tuple separately, so combine them. (Previously: no "0x" prefix +
            // only the type tuple → every lookup missed → fell back to flaky 4byte → fuzz_N stubs.)
            let sig_hex = format!("0x{}", alloy_primitives::hex::encode(sig));
            let full_sig = format!("{}{}", config.function_name, config.abi);
            selector_override.insert(sig_hex, full_sig);
        }
    }

    let calls: Vec<Call> = frames.iter().map(|f| frame_to_call(f)).collect();

    // Sender = the attacker EOA. frames[0] can be a "step" input whose caller is 0x0
    // (the direct-data exec path uses EVMAddress::default()), so pick the first non-zero
    // top-level caller; fall back to frames[0] only if every frame is zero.
    let sender_addr = frames
        .iter()
        .map(|f| f.caller)
        .find(|c| !c.is_zero())
        .unwrap_or(frames[0].caller);
    let sender = alloy_primitives::hex::encode_prefixed(sender_addr.as_ref() as &[u8]);

    let output_dir = format!("{}/vulnerabilities", work_dir);
    // Active fork chain + block so the PoC emits a valid vm.createSelectFork(chain, block).
    let (chain, block) = crate::evm::solution::cli_chain_and_block();
    // GAP 1 — temporal warp wire: feed campaign warps into the PoC so vm.warp/vm.roll
    // are emitted at the correct step boundaries for temporal-skimming exploits.
    let warps = state
        .metadata_map()
        .get::<crate::evm::oracles::CampaignWarpStates>()
        .map(|w| w.warps.clone())
        .unwrap_or_default();
    match gen_from_call_tree(calls, &sender, selector_override, &output_dir, chain, block, warps) {
        Ok(_) => tracing::debug!("[girlfriend] PoC written under {}/ (sender {})", output_dir, sender),
        Err(e) => tracing::warn!("Girlfriend PoC generation failed: {e}"),
    }
}

fn frame_to_call(frame: &crate::evm::host::CallTreeFrame) -> Call {
    let caller = alloy_primitives::hex::encode_prefixed(frame.caller.as_ref() as &[u8]);
    let target = alloy_primitives::hex::encode_prefixed(frame.target.as_ref() as &[u8]);
    let input = alloy_primitives::hex::encode_prefixed(&frame.input);
    let output = alloy_primitives::hex::encode_prefixed(&frame.output);
    let sub_calls: Vec<Call> = frame.sub_frames.iter().map(|f| frame_to_call(f)).collect();
    Call::from_raw(
        &frame.ty,
        &caller,
        &target,
        frame.value,
        &input,
        &output,
        sub_calls,
    )
}
