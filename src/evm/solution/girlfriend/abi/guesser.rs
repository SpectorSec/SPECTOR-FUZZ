use anyhow::{anyhow, Result};
use serde_json::Value;

#[derive(Debug, Clone)]
pub enum GuessedAbi {
    FnSig(String),
    ParamSig(String),
}

pub fn abi_guess(input: &str) -> Result<GuessedAbi> {
    let output = std::process::Command::new("abi-guesser")
        .arg(input)
        .output()
        .map_err(|e| anyhow!("abi-guesser failed: {}", e))?;
    if !output.status.success() {
        return Err(anyhow!("abi-guesser failed: {:?}", output));
    }
    let output = String::from_utf8(output.stdout)?;
    let mut output: Value = serde_json::from_str(&output)?;
    let fragment = output["fragment"].take();
    let param_types = output["paramTypes"].take();
    if !fragment.is_null() {
        return abi_guess_fn_signature(fragment);
    }
    if !param_types.is_null() {
        return abi_guess_param_signature(param_types);
    }
    Err(anyhow!("Not a function or param"))
}

fn abi_guess_fn_signature(fragment: Value) -> Result<GuessedAbi> {
    let fragment = fragment.as_object().ok_or(anyhow!("Not a function"))?;
    if fragment["type"].as_str().unwrap_or_default() != "function" {
        return Err(anyhow!("Not a function"));
    }
    let name = fragment["name"].as_str().unwrap_or_default();
    if name.is_empty() { return Err(anyhow!("Function name not found")); }
    let default_inputs = vec![];
    let inputs = fragment["inputs"].as_array().unwrap_or(&default_inputs);
    let mut input_types = Vec::new();
    for input in inputs {
        let input_type = input["type"].as_str().unwrap_or_default();
        if input_type.is_empty() { return Err(anyhow!("Function param type not found")); }
        input_types.push(input_type.replace("tuple", ""));
    }
    Ok(GuessedAbi::FnSig(format!("{}({})", name, input_types.join(","))))
}

fn abi_guess_param_signature(param_types: Value) -> Result<GuessedAbi> {
    let param_types = param_types.as_array().ok_or(anyhow!("Not a param"))?;
    let param_types: Vec<_> = param_types.iter()
        .map(|v| v["type"].as_str().unwrap_or_default().to_string().replace("tuple", ""))
        .collect();
    if param_types.iter().any(|v| v.is_empty()) { return Err(anyhow!("Param type not found")); }
    Ok(GuessedAbi::ParamSig(param_types.join(",")))
}
