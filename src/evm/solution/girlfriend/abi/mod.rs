pub mod guesser;
pub mod signature;
pub mod types;

use std::{collections::HashMap, mem, str::FromStr};

use alloy_dyn_abi::{DynSolType, DynSolValue, FunctionExt, JsonAbiExt, Specifier};
use alloy_json_abi::Function;
use alloy_primitives::{hex, Address, U256};
use anyhow::{anyhow, Result};
use types::*;

use self::signature::TIMESTAMP_SIG;
use super::utils::hash_to_name;

const MAX_DECODE_BYTES_LEN: usize = 2048;

#[derive(Debug, Default)]
pub struct Abi {
    pub addresses: HashMap<String, String>,
    pub struct_defs: HashMap<String, StructDef>,
    pub memory_vars: Vec<MemoryVar>,
    bytes_nonce: usize,
    array_nonce: usize,
    struct_nonces: HashMap<String, usize>,
    tuple_struct_names: HashMap<String, String>,
}

impl Abi {
    pub fn new() -> Self { Self::default() }

    pub fn decode_input(&mut self, sig: &str, input: &str) -> Result<Vec<DecodedArg>> {
        let func = Function::parse(sig)?;
        let calldata = hex::decode(input)?;
        let tokens = func.abi_decode_input(&calldata[4..])?;
        let mut args = vec![];
        for (i, t) in tokens.iter().enumerate() {
            let token_type = func.inputs[i].resolve()?;
            args.push(self.format_token(t, token_type));
        }
        update_block_timestamp(sig, &mut args);
        Ok(args)
    }

    pub fn decode_output(&mut self, ret_sig: &str, output: &str) -> Result<Vec<DecodedArg>> {
        let sig = format!("anonymous()({})", ret_sig.trim_start_matches('(').trim_end_matches(')'));
        let func = Function::parse(&sig)?;
        let output = hex::decode(output)?;
        let tokens = func.abi_decode_output(&output)?;
        let mut args = vec![];
        for (i, t) in tokens.iter().enumerate() {
            let token_type = func.outputs[i].resolve()?;
            args.push(self.format_token(t, token_type));
        }
        Ok(args)
    }

    pub fn take_addresses(&mut self) -> HashMap<String, String> { mem::take(&mut self.addresses) }
    pub fn take_struct_defs(&mut self) -> HashMap<String, StructDef> { mem::take(&mut self.struct_defs) }
    pub fn take_memory_vars(&mut self) -> Vec<MemoryVar> { mem::take(&mut self.memory_vars) }

    pub fn take_memory_vars_map(&mut self) -> HashMap<String, MemoryVar> {
        mem::take(&mut self.memory_vars)
            .into_iter()
            .filter_map(|v| v.var_name().map(|n| (n, v)))
            .collect()
    }

    pub fn take_bytes(&mut self) -> Vec<Bytes> {
        mem::take(&mut self.memory_vars)
            .into_iter()
            .filter_map(|v| v.into_bytes())
            .collect()
    }

    pub fn get_fn_def_signature(&self, fn_sig: &str, struct_defs: &HashMap<String, StructDef>) -> Result<String> {
        let func = Function::parse(fn_sig)?;
        let fn_name = func.name;
        let mut params = vec![];
        for p in func.inputs.iter() {
            let ty = p.resolve()?;
            params.push(self.format_type(&ty, struct_defs)?);
        }
        Ok(format!("{}({})", fn_name, params.join(", ")))
    }

    pub fn get_ret_def_signature(&self, ret_sig: &str, struct_defs: &HashMap<String, StructDef>) -> Result<String> {
        let fn_sig = format!("anonymous()({})", ret_sig.trim_start_matches('(').trim_end_matches(')'));
        let func = Function::parse(&fn_sig)?;
        let mut rets = vec![];
        for r in func.outputs.iter() {
            let ty = r.resolve()?;
            rets.push(self.format_type(&ty, struct_defs)?);
        }
        Ok(rets.join(", "))
    }

    fn format_type(&self, ty: &DynSolType, struct_defs: &HashMap<String, StructDef>) -> Result<String> {
        match ty {
            DynSolType::Tuple(_) => {
                let sig = ty.sol_type_name().to_string();
                let sd = struct_defs.get(&sig).ok_or(anyhow!("missing struct: {}", sig))?;
                Ok(format!("{} memory", sd.name))
            }
            DynSolType::CustomStruct { name, .. } => Ok(format!("{} memory", name)),
            DynSolType::FixedArray(inner, len) => {
                Ok(format!("{}[{}] memory", self.format_inner_type(inner, struct_defs), len))
            }
            DynSolType::Array(inner) => {
                Ok(format!("{}[] memory", self.format_inner_type(inner, struct_defs)))
            }
            DynSolType::Bytes => Ok("bytes memory".to_string()),
            DynSolType::String => Ok("string memory".to_string()),
            _ => Ok(ty.sol_type_name().to_string()),
        }
    }

    fn format_inner_type(&self, ty: &DynSolType, struct_defs: &HashMap<String, StructDef>) -> String {
        match ty {
            DynSolType::Tuple(_) => {
                let sig = ty.sol_type_name();
                struct_defs.get(&sig.to_string())
                    .map(|sd| sd.name.clone())
                    .unwrap_or_else(|| sig.to_string())
            }
            DynSolType::CustomStruct { name, .. } => name.clone(),
            _ => ty.sol_type_name().to_string(),
        }
    }

    fn format_token(&mut self, token: &DynSolValue, token_type: DynSolType) -> DecodedArg {
        match token {
            DynSolValue::Address(addr) => self.named_address(addr),
            DynSolValue::Bytes(bytes) => self.build_bytes(bytes),
            DynSolValue::Tuple(tuple) => self.build_struct(tuple, token_type),
            DynSolValue::CustomStruct { tuple, .. } => self.build_struct(tuple, token_type),
            DynSolValue::FixedArray(tokens) => self.build_array(token_type, tokens),
            DynSolValue::Array(tokens) => self.build_array(token_type, tokens),
            _ => {
                let ty = token_type.sol_type_name();
                let value = format_token_raw(token);
                DecodedArg::new(&ty, &value, token.is_dynamic())
            }
        }
    }

    fn format_token_type(&mut self, ty: &DynSolType) -> String {
        match ty {
            DynSolType::Tuple(_) => self.build_struct_type(ty),
            DynSolType::CustomStruct { .. } => self.build_struct_type(ty),
            DynSolType::FixedArray(..) => self.build_array_type(ty),
            DynSolType::Array(_) => self.build_array_type(ty),
            _ => ty.sol_type_name().to_string(),
        }
    }

    fn build_struct_type(&mut self, ty: &DynSolType) -> String {
        if let Some(DynSolType::CustomStruct { name, prop_names, tuple: prop_types }) = self.get_struct_type(ty) {
            self.build_struct_def(ty, &name, &prop_types, &prop_names);
            return name;
        }
        ty.sol_type_name().to_string()
    }

    fn build_array_type(&mut self, ty: &DynSolType) -> String {
        let (inner_type, len) = match ty {
            DynSolType::FixedArray(t, l) => (t.as_ref(), Some(*l)),
            DynSolType::Array(t) => (t.as_ref(), None),
            _ => return ty.sol_type_name().to_string(),
        };
        let inner_name = self.format_token_type(inner_type);
        if let Some(l) = len { format!("{}[{}]", inner_name, l) }
        else { format!("{}[]", inner_name) }
    }

    fn named_address(&mut self, addr: &Address) -> DecodedArg {
        let addr = addr.to_checksum(None);
        let name = hash_to_name(&addr);
        self.addresses.entry(name.clone()).or_insert(addr);
        DecodedArg::new("address", &name, false)
    }

    fn build_bytes(&mut self, bytes: &[u8]) -> DecodedArg {
        if bytes.is_empty() { return DecodedArg::new("bytes", "\"\"", true); }
        if !bytes_need_decode(bytes) { return DecodedArg::new("bytes", format!("hex\"{}\"", hex::encode(bytes)).as_str(), true); }
        if let Ok(guessed) = guesser::abi_guess(hex::encode(bytes).as_str()) {
            if let Ok(res) = self.decode_bytes_with_sig(&guessed, bytes) { return res; }
        }
        self.try_decode_bytes(bytes)
    }

    fn decode_bytes_with_sig(&mut self, sig: &guesser::GuessedAbi, bytes: &[u8]) -> Result<DecodedArg> {
        let (sig, selector, input) = match sig {
            guesser::GuessedAbi::FnSig(fn_sig) => (
                fn_sig.to_string(),
                Some(hex::encode_prefixed(&bytes[..4])),
                hex::encode(bytes),
            ),
            guesser::GuessedAbi::ParamSig(param_sig) => {
                let fn_sig = format!("anonymous({})", param_sig);
                let input = format!("00000000{}", hex::encode(bytes));
                (fn_sig, None, input)
            }
        };
        let decoded = self.decode_input(&sig, &input)?;
        Ok(self.insert_decoded_bytes(selector, decoded))
    }

    pub fn try_decode_bytes(&mut self, bytes: &[u8]) -> DecodedArg {
        let need_decode_uint = bytes.len() <= MAX_DECODE_BYTES_LEN;
        let parts = bytes.chunks(32).map(hex::encode).map(|b| self.decode_bytes32(&b, need_decode_uint));
        let mut decoded = vec![];
        let mut undecoded = String::new();
        for arg in parts {
            if arg.ty == "bytes32" { undecoded.push_str(&arg.to_string()); }
            else {
                if !undecoded.is_empty() {
                    decoded.push(DecodedArg::new("bytes", format!("hex\"{}\"", undecoded).as_str(), true));
                    undecoded.clear();
                }
                decoded.push(arg);
            }
        }
        if !undecoded.is_empty() {
            decoded.push(DecodedArg::new("bytes", format!("hex\"{}\"", undecoded).as_str(), true));
        }
        self.insert_decoded_bytes(None, decoded)
    }

    fn insert_decoded_bytes(&mut self, selector: Option<String>, decoded: Vec<DecodedArg>) -> DecodedArg {
        let var_name = format!("b{:02}", self.get_bytes_nonce());
        let bytes = Bytes::new(&var_name, selector, &decoded);
        self.memory_vars.push(MemoryVar::Bytes(bytes));
        DecodedArg::new("bytes", &var_name, true)
    }

    fn decode_bytes32(&mut self, bytes32: &str, need_decode_uint: bool) -> DecodedArg {
        if let Some(addr) = bytes32_to_address(bytes32) {
            let name = hash_to_name(&addr);
            self.addresses.entry(name.clone()).or_insert(addr);
            return DecodedArg::new("address", &name, false);
        }
        if need_decode_uint {
            if let Some(num) = bytes32_to_u256(bytes32) {
                return DecodedArg::new("uint256", &num, false);
            }
        }
        DecodedArg::new("bytes32", bytes32, false)
    }

    fn build_struct(&mut self, prop_values: &[DynSolValue], token_type: DynSolType) -> DecodedArg {
        if let Some(DynSolType::CustomStruct { name, prop_names, tuple: prop_types }) = self.get_struct_type(&token_type) {
            let struct_sig = self.build_struct_def(&token_type, &name, &prop_types, &prop_names);
            let var_name = format!("{}{:02}", name.to_lowercase(), self.get_struct_nonce(&struct_sig));
            let values = self.build_struct_args(&prop_types, prop_values);
            self.memory_vars.push(MemoryVar::StructIns(StructIns::new(&name, &var_name, &values)));
            return DecodedArg::new(&name, &var_name, true);
        }
        unreachable!("invalid struct type: {:?}", token_type);
    }

    fn get_struct_type(&mut self, token_type: &DynSolType) -> Option<DynSolType> {
        match token_type {
            DynSolType::Tuple(tuple) => {
                let struct_name = self.build_tuple_struct_name(token_type.clone());
                let prop_names = (0..tuple.len()).map(|i| format!("p{}", i + 1)).collect();
                Some(DynSolType::CustomStruct { name: struct_name, prop_names, tuple: tuple.clone() })
            }
            DynSolType::CustomStruct { .. } => Some(token_type.clone()),
            _ => None,
        }
    }

    fn build_struct_def(&mut self, ty: &DynSolType, name: &str, prop_types: &[DynSolType], prop_names: &[String]) -> String {
        let sig = ty.sol_type_name().to_string();
        let props: Vec<String> = prop_types.iter().enumerate().map(|(i, t)| {
            format!("{} {}", self.format_token_type(t), prop_names[i])
        }).collect();
        self.struct_defs.insert(sig.clone(), StructDef::new(name, &props));
        sig
    }

    fn build_struct_args(&mut self, prop_types: &[DynSolType], prop_values: &[DynSolValue]) -> Vec<DecodedArg> {
        prop_types.iter().zip(prop_values.iter()).map(|(t, v)| self.format_token(v, t.clone())).collect()
    }

    fn build_tuple_struct_name(&mut self, token_type: DynSolType) -> String {
        let sig = token_type.sol_type_name().to_string();
        let tuple_nonce = self.tuple_struct_names.len() + 1;
        self.tuple_struct_names.entry(sig).or_insert(format!("S{}", tuple_nonce)).clone()
    }

    fn build_array(&mut self, array_type: DynSolType, tokens: &[DynSolValue]) -> DecodedArg {
        let (inner_type, len) = match &array_type {
            DynSolType::FixedArray(t, l) => (t.as_ref(), Some(*l)),
            DynSolType::Array(t) => (t.as_ref(), None),
            _ => unreachable!(),
        };
        let inner_type_name = self.format_token_type(inner_type);
        let array_type_name = if let Some(l) = len { format!("{}[{}]", inner_type_name, l) } else { format!("{}[]", inner_type_name) };
        let var_name = format!("arr{:02}", self.get_array_nonce());
        let values: Vec<String> = tokens.iter().map(|t| self.format_token(t, inner_type.clone()).value).collect();
        self.memory_vars.push(MemoryVar::Array(Array::new(&inner_type_name, len, &var_name, &values)));
        DecodedArg::new(&array_type_name, &var_name, true)
    }

    fn get_bytes_nonce(&mut self) -> usize { self.bytes_nonce += 1; self.bytes_nonce }
    fn get_struct_nonce(&mut self, struct_sig: &str) -> usize {
        let n = self.struct_nonces.entry(struct_sig.to_string()).or_insert(0);
        *n += 1; *n
    }
    fn get_array_nonce(&mut self) -> usize { self.array_nonce += 1; self.array_nonce }
}

pub fn format_token_raw(token: &DynSolValue) -> String {
    match token {
        DynSolValue::Address(addr) => addr.to_checksum(None),
        DynSolValue::FixedBytes(bytes, _) => {
            if bytes.is_empty() { "\"\"".to_string() } else { hex::encode_prefixed(bytes) }
        }
        DynSolValue::Bytes(bytes) => {
            if bytes.is_empty() { "\"\"".to_string() } else { format!("hex\"{}\"", hex::encode(bytes)) }
        }
        DynSolValue::Int(num, _) => num.to_string(),
        DynSolValue::Uint(num, _) => {
            if num == &U256::MAX { "type(uint256).max".to_string() } else { num.to_string() }
        }
        DynSolValue::Bool(b) => b.to_string(),
        DynSolValue::String(s) => format!("\"{}\"", s.replace('"', "\\\"")),
        DynSolValue::FixedArray(tokens) => format!("[{}]", format_array(tokens)),
        DynSolValue::Array(tokens) => format!("[{}]", format_array(tokens)),
        DynSolValue::Tuple(tokens) => format!("({})", format_array(tokens)),
        DynSolValue::CustomStruct { tuple, .. } => format!("({})", format_array(tuple)),
        DynSolValue::Function(f) => f.to_address_and_selector().1.to_string(),
    }
}

fn format_array(tokens: &[DynSolValue]) -> String {
    tokens.iter().map(format_token_raw).collect::<Vec<_>>().join(", ")
}

pub fn bytes32_to_address(bytes32: &str) -> Option<String> {
    if (bytes32.len() != 40 && bytes32.len() != 64) ||
        (bytes32.len() == 64 && !bytes32.starts_with("0".repeat(24).as_str())) { return None; }
    let addr = if bytes32.len() == 40 { Address::from_str(bytes32).ok()? }
    else { Address::from_str(&bytes32[24..]).ok()? };
    if addr[..4] == [0; 4] { return None; }
    Some(addr.to_checksum(None))
}

pub fn bytes32_to_u256(bytes32: &str) -> Option<String> {
    if bytes32.len() != 64 || !bytes32.starts_with("0".repeat(30).as_str()) { return None; }
    U256::from_str_radix(bytes32, 16).map(|n| {
        if n == U256::MAX { "type(uint256).max".to_string() } else { n.to_string() }
    }).ok()
}

fn bytes_need_decode(bytes: &[u8]) -> bool {
    let len = bytes.len();
    len > 4 && (len % 32 == 0 || (len - 4) % 32 == 0)
}

fn update_block_timestamp(sig: &str, args: &mut Vec<DecodedArg>) {
    let fn_name = sig.split('(').next().unwrap_or("");
    if let Some(idx) = TIMESTAMP_SIG.get(fn_name) {
        if args.len() > *idx && args[*idx].ty == "uint256" {
            args[*idx].value = "block.timestamp + 1".to_string();
        }
    }
}
