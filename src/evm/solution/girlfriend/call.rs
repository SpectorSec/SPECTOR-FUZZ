use alloy_primitives::U256;
use serde_json::Value;

use super::utils::{checksum, hash_to_name};

#[derive(Debug, Default, Clone)]
pub struct Call {
    pub ty: String,
    pub caller: String,
    pub target: String,
    pub target_var: String,
    pub value: U256,
    pub input: String,
    pub output: String,
    pub sub_calls: Vec<Call>,
}

impl From<&Value> for Call {
    fn from(v: &Value) -> Self {
        Self::from_json(v, "", "")
    }
}

impl Call {
    pub fn from_json(v: &Value, parent_ty: &str, parent_addr: &str) -> Self {
        let ty = v["type"].as_str().unwrap_or_default().to_lowercase();
        let caller = if parent_ty == "delegatecall" {
            parent_addr.to_string()
        } else {
            checksum(v["from"].as_str().unwrap_or_default())
        };
        let target = checksum(v["to"].as_str().unwrap_or_default());
        let target_var = hash_to_name(&target);
        let value = U256::from_str_radix(
            v["value"].as_str().unwrap_or("0x0").trim_start_matches("0x"),
            16,
        ).unwrap_or_default();
        let input = v["input"].as_str().unwrap_or_default().to_string();
        let output = v["output"].as_str().unwrap_or_default().to_string();
        let sub_calls = v["calls"].as_array()
            .map(|a| a.iter().map(|v| Call::from_json(v, &ty, &target)).collect())
            .unwrap_or_default();
        Self { ty, caller, target, target_var, value, input, output, sub_calls }
    }

    /// Build a Call from raw fuzzer data (SpecterFuzz bridge path).
    /// `input` and `output` are hex-encoded with 0x prefix.
    pub fn from_raw(
        ty: &str,
        caller: &str,
        target: &str,
        value: U256,
        input: &str,
        output: &str,
        sub_calls: Vec<Call>,
    ) -> Self {
        Self {
            ty: ty.to_string(),
            caller: checksum(caller),
            target: checksum(target),
            target_var: hash_to_name(target),
            value,
            input: input.to_string(),
            output: output.to_string(),
            sub_calls,
        }
    }

    pub fn mock_parent(caller: &str, target: &str, call: &Call) -> Self {
        let mut c = call.clone();
        c.caller = target.to_string();
        Self {
            ty: "call".to_string(),
            caller: caller.to_string(),
            target: target.to_string(),
            target_var: hash_to_name(target),
            sub_calls: vec![c],
            ..Default::default()
        }
    }
}
