use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, File},
    mem,
    path::Path,
};

use alloy_primitives::{hex, U256};
use anyhow::{anyhow, Result};
use handlebars::{handlebars_helper, Handlebars};
use serde::Serialize;
use tracing::debug;

use super::{
    abi::{
        self,
        signature::get_fn_signature,
        types::{DecodedArg, MemoryVar, StructDef},
        Abi,
    },
    call::Call,
    contract::{
        build_sub_contracts, Contract, ParsedCall, ParsedCallType, ReturnData, SubContract, UnresolvedFn, VmState,
    },
    utils::{hash_to_name, checksum},
};

const TEMPLATE: &str = include_str!("assets/template.hbs");
const HARDHAT_CHEAT_ADDR: &str = "0x000000000000000000636F6e736F6c652e6c6f67";
const PHALCON_URL: &str = "https://explorer.phalcon.xyz/tx";
const CALL_STACK_MAX_DEPTH: usize = 30;

handlebars_helper!(add: |x: usize, y: usize| x + y);

#[derive(Debug)]
pub struct Girlfriend {
    pub output_dir: String,
    pub abi: Abi,
    pub nonce: usize,
    /// selector_hex → full_fn_signature (e.g. "0xa9059cbb" → "transfer(address,uint256)")
    pub selector_override: HashMap<String, String>,
    /// Fork chain alias + block for `vm.createSelectFork(chain, block)`.
    pub chain: String,
    pub block: String,
}

#[derive(Debug, Serialize, Default)]
pub struct TemplateArgs {
    pub file_name: String,
    pub receiver_name: String,
    pub last_txhash: String,
    pub chain_name: String,
    pub sender: String,
    pub sender_scan_url: String,
    pub struct_defs: HashMap<String, StructDef>,
    pub interface: HashSet<String>,
    pub contracts: Vec<Contract>,
}

#[derive(Debug)]
struct ParsedInput {
    fn_signature: String,
    ret_signature: String,
    fn_name: String,
    args: Vec<DecodedArg>,
}

impl Girlfriend {
    pub fn new(output_dir: String) -> Self {
        Self {
            output_dir,
            abi: Abi::new(),
            nonce: 0,
            selector_override: HashMap::new(),
            chain: String::new(),
            block: String::new(),
        }
    }

    pub fn with_selector_override(mut self, map: HashMap<String, String>) -> Self {
        self.selector_override = map;
        self
    }

    pub fn with_fork(mut self, chain: String, block: String) -> Self {
        self.chain = chain;
        self.block = block;
        self
    }

    /// Generate Foundry PoC from pre-recorded call tree.
    pub fn gen_from_calls(&mut self, calls: Vec<Call>, sender: &str) -> Result<(String, String)> {
        if calls.is_empty() { return Err(anyhow!("No calls provided")); }
        if !Path::new(&self.output_dir).exists() {
            fs::create_dir_all(&self.output_dir)?;
        }
        let args = self.make_template_args_from_calls(calls, sender)?;
        self.render_test_file(&args)
    }

    fn make_template_args_from_calls(&mut self, mut calls: Vec<Call>, sender: &str) -> Result<TemplateArgs> {
        let last_tx_hash = format!("fuzz_{}", calls.len().saturating_sub(1));
        let root_call = calls.pop().unwrap();
        let receiver = root_call.target.clone();
        let file_name = format!("{}.t.sol", hash_to_name(&last_tx_hash));

        let mut contract_map = self.initialize_contracts(&receiver);
        let mut struct_defs = HashMap::new();
        let mut parsed_root_calls = vec![];

        // Parse pre-calls (all but the last)
        for c in &calls {
            let mut pc = self.parse_pre_call(sender, &receiver, &last_tx_hash);
            struct_defs.extend(pc.struct_defs.clone());
            parsed_root_calls.push(pc.clone());
            let parent = Call::mock_parent(sender, &receiver, c);
            let parsed = self.parse_calls(&parent, sender, &mut pc, &mut contract_map, &mut vec![]);
            self.organize_parsed_calls(parsed, sender, &mut contract_map, &mut struct_defs);
        }

        // Parse root call
        let mut pc = self.parse_root_call(sender, &root_call, &last_tx_hash);
        struct_defs.extend(pc.struct_defs.clone());
        parsed_root_calls.push(pc.clone());
        let rc = if ["create", "create2"].contains(&root_call.ty.as_str()) {
            Call::mock_parent(sender, &receiver, &root_call)
        } else {
            root_call
        };
        let parsed = self.parse_calls(&rc, sender, &mut pc, &mut contract_map, &mut vec![]);
        self.organize_parsed_calls(parsed, sender, &mut contract_map, &mut struct_defs);

        build_sub_contracts(&mut contract_map);
        let sub_map = contract_map.values().map(|c| (c.name.to_lowercase(), c.sub_contracts.clone())).collect();
        for c in contract_map.values_mut() {
            c.build_sub_contracts_constructor_args(&sub_map);
        }

        let root_fn_sigs: Vec<&str> = parsed_root_calls.iter().map(|prc| prc.fn_signature.as_str()).collect();
        let mut interface = HashSet::new();
        for c in contract_map.values_mut() {
            c.generate(&sub_map, &last_tx_hash, &root_fn_sigs, &mut interface, &struct_defs);
        }

        let mut recv = contract_map.remove(&receiver).unwrap();
        let first_state = parsed_root_calls.first().and_then(|pc| pc.vm_state.clone()).unwrap_or_default();
        let last_state = parsed_root_calls.last().and_then(|pc| pc.vm_state.clone()).unwrap_or_default();
        recv.setup_test1_vm_state(first_state, last_state);
        for (i, prc) in parsed_root_calls.iter().enumerate() {
            recv.push_test1_call(prc.clone(), i == parsed_root_calls.len() - 1);
        }
        recv.tidy_named_addresses();

        let receiver_name = recv.name.clone();
        let mut contracts = vec![recv];
        contracts.extend(contract_map.into_values());

        Ok(TemplateArgs {
            file_name,
            receiver_name,
            last_txhash: last_tx_hash,
            chain_name: self.chain.clone(),
            sender: sender.to_string(),
            sender_scan_url: String::new(),
            struct_defs,
            interface,
            contracts,
        })
    }

    fn render_test_file(&self, args: &TemplateArgs) -> Result<(String, String)> {
        let mut handlebars = Handlebars::new();
        handlebars.register_template_string("foundry_test", TEMPLATE)?;
        handlebars.register_helper("add", Box::new(add));
        let path = format!("{}/{}", self.output_dir, args.file_name);
        let mut output = File::create(&path)?;
        handlebars.render_to_write("foundry_test", args, &mut output)?;
        Ok((path, args.receiver_name.clone()))
    }

    fn parse_calls(
        &mut self,
        call: &Call,
        sender: &str,
        parent_call: &mut ParsedCall,
        contracts: &mut HashMap<String, Contract>,
        parsed_calls: &mut Vec<ParsedCall>,
    ) -> Vec<ParsedCall> {
        let contract_addrs: Vec<String> = contracts.keys().cloned().collect();
        let mut return_vars = HashMap::new();
        let mut return_vars_clear_idx = CALL_STACK_MAX_DEPTH;
        let mut has_parentheses = false;
        let mut var_nonce = 1;
        let mut all_parsed = VecDeque::new();

        for (idx, c) in call.sub_calls.iter().enumerate() {
            if idx == return_vars_clear_idx {
                return_vars.clear();
                return_vars_clear_idx += CALL_STACK_MAX_DEPTH;
                if !has_parentheses { has_parentheses = true; parsed_calls.push(ParsedCall::left_parenthesis()); }
                else {
                    parsed_calls.push(ParsedCall::right_parenthesis());
                    parsed_calls.push(ParsedCall::left_parenthesis());
                }
            }

            let target = c.target.clone();
            let target_is_contract = contract_addrs.contains(&target);
            let receiver = contracts.get(&c.caller).map(|c| c.addr.clone()).unwrap_or_default();
            let mut parsed_call = self.parse_call(c, sender, &receiver, target_is_contract, &return_vars);

            if parsed_call.sol_ty == "staticcall" && !parsed_call.ret_signature.is_empty() {
                if let Ok(()) = parsed_call.add_returns(&c.output, var_nonce) {
                    var_nonce += parsed_call.return_data.len();
                    return_vars.extend(parsed_call.return_vars.clone());
                }
            } else if [ParsedCallType::Create, ParsedCallType::Create2].contains(&parsed_call.ty) {
                if !contracts.contains_key(&target) {
                    contracts.insert(target.clone(), Contract::new(target.clone(), false, true, parsed_call.salt.clone()));
                }
            }

            parsed_calls.push(parsed_call.clone());
            let mut sub_parsed = vec![];
            let all_subs = self.parse_calls(c, sender, &mut parsed_call, contracts, &mut sub_parsed);
            all_parsed.extend(all_subs);
        }
        if has_parentheses { parsed_calls.push(ParsedCall::right_parenthesis()); }

        parent_call.sub_calls = mem::take(parsed_calls);
        all_parsed.push_front(parent_call.clone());
        all_parsed.into()
    }

    fn organize_parsed_calls(
        &self,
        parsed_calls: Vec<ParsedCall>,
        sender: &str,
        contracts: &mut HashMap<String, Contract>,
        struct_defs: &mut HashMap<String, StructDef>,
    ) {
        for parsed_call in parsed_calls {
            let mut named_addresses = HashMap::new();
            for sub in &parsed_call.sub_calls {
                if sub.ty == ParsedCallType::Parentheses { continue; }
                if [ParsedCallType::Raw, ParsedCallType::WithSelector].contains(&sub.ty) {
                    self.push_fallback(sub.clone(), contracts);
                }
                struct_defs.extend(sub.struct_defs.clone());
                named_addresses.insert(hash_to_name(&sub.target), sub.target.clone());
                named_addresses.extend(sub.named_addresses.clone());
            }
            if let Some(c) = contracts.get_mut(&parsed_call.target) {
                c.build_function(parsed_call, struct_defs);
                c.named_addresses.extend(named_addresses);
                c.named_addresses.remove(&hash_to_name(sender));
            }
        }
    }

    fn push_fallback(&self, parsed_call: ParsedCall, contracts: &mut HashMap<String, Contract>) {
        if let Some(c) = contracts.get_mut(&parsed_call.target) {
            let sel = parsed_call.raw_input[..10].to_string();
            c.fallback.entry(parsed_call.fn_signature.clone()).or_insert(UnresolvedFn::new(sel, parsed_call.fn_signature));
        }
    }

    fn parse_call(
        &mut self,
        call: &Call,
        sender: &str,
        receiver: &str,
        target_is_contract: bool,
        return_vars: &HashMap<String, ReturnData>,
    ) -> ParsedCall {
        let parsed_input = self.parse_input(call);
        let pct = get_parsed_call_type(call, &parsed_input, target_is_contract);

        let mut contract_var = call.target_var.clone();
        if receiver == call.target { contract_var = "r".to_string(); }
        else if sender == call.target { contract_var = "address(tx.origin)".to_string(); }

        let sender_var = hash_to_name(sender);
        let receiver_var = if receiver.is_empty() { String::new() } else { hash_to_name(receiver) };

        let ret_sig = parsed_input.as_ref().map(|i| i.ret_signature.clone()).unwrap_or_default();
        let mut named_addresses = HashMap::new();

        let (fn_sig, fn_call) = match pct {
            ParsedCallType::Create | ParsedCallType::Create2 => call_inner_create(call, &contract_var),
            ParsedCallType::SelfDestruct => call_selfdestruct(&contract_var),
            ParsedCallType::WithSelector => call_with_selector(call, &contract_var, &sender_var, &receiver_var, return_vars, &mut named_addresses),
            _ => {
                if let Ok(ref input) = parsed_input {
                    let fn_s = format_fn_sig(&input.fn_signature, &pct);
                    let fn_a = format_fn_args(&input.args, &sender_var, &receiver_var, return_vars, &pct);
                    let fn_c = format_fn_call(call, input, &pct, target_is_contract, &contract_var, &fn_a);
                    (fn_s, fn_c)
                } else if pct == ParsedCallType::HardhatCheat {
                    generate_hardhat_comment(call, &sender_var, &receiver_var, return_vars)
                } else {
                    call_with_rawdata(call, &contract_var)
                }
            }
        };
        named_addresses.extend(self.abi.take_addresses());

        let salt = if pct == ParsedCallType::Create2 { Some(self.generate_salt()) } else { None };

        ParsedCall {
            ty: pct,
            sol_ty: call.ty.clone(),
            caller: call.caller.clone(),
            target: call.target.clone(),
            fn_signature: fn_sig,
            ret_signature: ret_sig,
            fn_call,
            raw_input: call.input.to_string(),
            raw_output: call.output.to_string(),
            value: call.value,
            target_is_contract,
            memory_vars: self.take_memory_vars(&sender_var, &receiver_var),
            named_addresses,
            struct_defs: self.abi.take_struct_defs(),
            salt,
            ..Default::default()
        }
    }

    /// Build the fork VmState from the active chain/block so createSelectFork renders
    /// `vm.createSelectFork("eth", 25420000)` instead of the broken `("", )`.
    fn fork_vm_state(&self) -> Option<VmState> {
        if self.chain.is_empty() && self.block.is_empty() {
            return None;
        }
        Some(VmState {
            forked_rpc: self.chain.clone(),
            block_number: self.block.clone(),
            ..Default::default()
        })
    }

    fn parse_pre_call(&mut self, sender: &str, receiver: &str, tx_hash: &str) -> ParsedCall {
        let fn_sig = format!("{}()", &tx_hash[..8.min(tx_hash.len())]);
        ParsedCall {
            ty: ParsedCallType::Interface,
            sol_ty: "call".to_string(),
            caller: sender.to_string(),
            target: receiver.to_string(),
            fn_call: format!("{};", fn_sig),
            fn_signature: fn_sig,
            target_is_contract: true,
            vm_state: self.fork_vm_state(),
            ..Default::default()
        }
    }

    fn parse_root_call(&mut self, sender: &str, call: &Call, tx_hash: &str) -> ParsedCall {
        if ["create", "create2"].contains(&call.ty.as_str()) {
            return self.parse_pre_call(sender, &call.target, tx_hash);
        }
        let parsed_input = self.parse_input(call);
        let sender_var = hash_to_name(sender);
        let ty = ParsedCallType::Interface;
        // When the selector resolves (the common case) render the typed interface call.
        // When it doesn't, fall back to a raw low-level call that replays the EXACT
        // calldata — mirrors the sub-call path's call_with_rawdata. Previously the Err
        // branch dropped the args and emitted an empty `0x..()` no-op (the call silently
        // did nothing), so an unresolved root selector meant the PoC didn't reproduce.
        let (fn_signature, fn_call) = match parsed_input {
            Ok(ref input) => {
                let rv = HashMap::new();
                let args = format_fn_args(&input.args, &sender_var, &call.target_var, &rv, &ty);
                let fn_call = if call.value != U256::ZERO {
                    format!("this.{}{{value: {}}}({});", input.fn_name, call.value, args)
                } else {
                    format!("{}({});", input.fn_name, args)
                };
                (input.fn_signature.clone(), fn_call)
            }
            Err(_) => {
                let calldata = if call.input.len() <= 2 {
                    "\"\"".to_string()
                } else {
                    format!("hex\"{}\"", &call.input[2..])
                };
                let value = if call.value != U256::ZERO {
                    format!("{{value: {}}}", call.value)
                } else {
                    String::new()
                };
                // Raw call against the real target address; preserves the full calldata.
                let fn_call = format!("address({}).call{}({});", call.target, value, calldata);
                let sig = if call.input.len() >= 10 {
                    format!("rawcall_{}()", &call.input[2..10])
                } else {
                    "rawcall()".to_string()
                };
                (sig, fn_call)
            }
        };
        ParsedCall {
            ty,
            sol_ty: call.ty.clone(),
            caller: call.caller.clone(),
            target: call.target.clone(),
            fn_signature,
            fn_call,
            target_is_contract: true,
            raw_input: call.input.clone(),
            raw_output: call.output.clone(),
            value: call.value,
            vm_state: self.fork_vm_state(),
            memory_vars: self.take_memory_vars(&sender_var, &call.target_var),
            named_addresses: self.abi.take_addresses(),
            struct_defs: self.abi.take_struct_defs(),
            ..Default::default()
        }
    }

    fn parse_input(&mut self, call: &Call) -> Result<ParsedInput> {
        if call.input.len() < 10 { return Err(anyhow!("Ignore: {}", call.input)); }
        let selector = &call.input[..10];

        // Check the SpecterFuzz-provided override map first.
        let (fn_sig, ret_sig) = if let Some(sig) = self.selector_override.get(selector) {
            (sig.clone(), None)
        } else {
            // Fallback to HTTP lookup
            match get_fn_signature(&call.input, &call.output, &call.target) {
                Ok((fs, rs)) => (fs, rs),
                Err(e) => return Err(e),
            }
        };

        let fn_name = fn_sig.split('(').next().unwrap_or(selector).to_string();
        let args = self.abi.decode_input(&fn_sig, &call.input)?;
        Ok(ParsedInput { fn_signature: fn_sig, ret_signature: ret_sig.unwrap_or_default(), fn_name, args })
    }

    fn initialize_contracts(&mut self, receiver: &str) -> HashMap<String, Contract> {
        let mut m = HashMap::new();
        m.insert(receiver.to_string(), Contract::new(receiver.to_string(), true, false, None));
        m
    }

    fn generate_salt(&mut self) -> String { self.nonce += 1; self.nonce.to_string() }

    fn take_memory_vars(&mut self, sender_var: &str, receiver_var: &str) -> Vec<MemoryVar> {
        let mut mv = self.abi.take_memory_vars();
        for v in &mut mv {
            v.replace_sender(sender_var);
            if !receiver_var.is_empty() { v.replace_receiver(receiver_var); }
        }
        mv
    }
}

// Free functions
fn get_parsed_call_type(call: &Call, parsed_input: &Result<ParsedInput>, target_is_contract: bool) -> ParsedCallType {
    let input_is_parsed = parsed_input.is_ok();
    let fn_name = parsed_input.as_ref().map(|i| i.fn_name.clone()).unwrap_or_default();
    let input_len = call.input.len();
    if call.target == HARDHAT_CHEAT_ADDR { ParsedCallType::HardhatCheat }
    else if call.ty == "create" { ParsedCallType::Create }
    else if call.ty == "create2" { ParsedCallType::Create2 }
    else if call.ty == "selfdestruct" { ParsedCallType::SelfDestruct }
    else if call.ty == "delegatecall" { ParsedCallType::DelegateCall }
    else if input_is_parsed {
        if !target_is_contract && fn_name.starts_with("guessed_") { ParsedCallType::WithSelector }
        else { ParsedCallType::Interface }
    }
    else if input_len < 10 { ParsedCallType::SendValue }
    else if input_len >= 74 && (input_len - 10) % 64 == 0 { ParsedCallType::WithSelector }
    else { ParsedCallType::Raw }
}

fn call_inner_create(call: &Call, contract_var: &str) -> (String, String) {
    let cn = call.target_var[..1].to_uppercase() + &call.target_var[1..];
    ("constructor()".to_string(), format!("{} = address(new {}());", contract_var, cn))
}

fn call_selfdestruct(contract_var: &str) -> (String, String) {
    (String::new(), format!("selfdestruct(payable({}));", contract_var))
}

fn call_with_rawdata(call: &Call, contract_var: &str) -> (String, String) {
    let fs = if call.input.len() < 10 { format!("{}()", call.ty) } else { format!("{}()", &call.input[1..10]) };
    let args = if call.input.len() <= 2 { "\"\"".to_string() } else { format!("hex\"{}\"", &call.input[2..]) };
    let mut fc = format!("{}.{}", contract_var, call.ty);
    if call.value != U256::ZERO { fc.push_str(format!("{{value: {}}}", call.value).as_str()); }
    fc.push_str(format!("({});", args).as_str());
    (fs, fc)
}

fn generate_hardhat_comment(call: &Call, sender_var: &str, receiver_var: &str, rv: &HashMap<String, ReturnData>) -> (String, String) {
    let mut na = HashMap::new();
    let args = decode_bytes_arg(&call.input[10..], sender_var, receiver_var, rv, &mut na);
    (String::new(), format!("// hardhat.console.log({});", args.join(", ")))
}

fn call_with_selector(call: &Call, cv: &str, sv: &str, rv: &str, return_vars: &HashMap<String, ReturnData>, na: &mut HashMap<String, String>) -> (String, String) {
    let sel = &call.input[0..10];
    let fs = format!("{}()", &call.input[1..10]);
    let args = decode_bytes_arg(&call.input[10..], sv, rv, return_vars, na);
    let mut fc = format!("{}.{}", cv, call.ty);
    if call.value != U256::ZERO { fc.push_str(format!("{{value: {}}}", call.value).as_str()); }
    if args.is_empty() { fc.push_str(format!("(abi.encodeWithSelector({}));", sel).as_str()); }
    else { fc.push_str(format!("(abi.encodeWithSelector({}, {}));", sel, args.join(", ")).as_str()); }
    (fs, fc)
}

fn format_fn_sig(fn_signature: &str, pct: &ParsedCallType) -> String {
    match pct {
        ParsedCallType::Create | ParsedCallType::Create2 => "constructor()".to_string(),
        ParsedCallType::SelfDestruct => String::new(),
        _ => fn_signature.to_string(),
    }
}

fn format_fn_args(args: &[DecodedArg], sv: &str, rv: &str, return_vars: &HashMap<String, ReturnData>, pct: &ParsedCallType) -> String {
    args.iter().map(|a| {
        if a.ty == "address" && a.value == sv { "tx.origin".to_string() }
        else if a.ty == "address" && a.value == rv { "r".to_string() }
        else if a.value != "0" && return_vars.contains_key(&a.value) {
            return_vars.get(&a.value).unwrap().try_replace(&a.ty, &a.value)
        }
        else if pct == &ParsedCallType::HardhatCheat && a.ty != "string" { format!("{}({})", a.ty, a.value) }
        else { a.to_string() }
    }).collect::<Vec<_>>().join(", ")
}

fn format_fn_call(call: &Call, pi: &ParsedInput, pct: &ParsedCallType, tic: bool, cv: &str, args: &str) -> String {
    let cn = call.target_var[..1].to_uppercase() + &call.target_var[1..];
    let target = if tic && pct == &ParsedCallType::Interface { format!("{}(payable({}))", cn, cv) }
    else if pct == &ParsedCallType::Interface { format!("I({})", cv) }
    else { cv.to_string() };
    match pct {
        ParsedCallType::DelegateCall => call_delegatecall(target, call, pi, args),
        ParsedCallType::HardhatCheat => call_hardhat(pi, args),
        _ => call_with_interface(target, call, pi, args),
    }
}

fn call_delegatecall(target: String, call: &Call, pi: &ParsedInput, args: &str) -> String {
    let mut fa = format!("abi.encodeWithSignature(\"{}\"", pi.fn_signature);
    if args.is_empty() { fa.push(')'); } else { fa.push_str(format!(", {})", args).as_str()); }
    let mut fc = format!("{}.{}", target, call.ty);
    if call.value != U256::ZERO { fc.push_str(format!("{{value: {}}}", call.value).as_str()); }
    fc.push_str(format!("({});", fa).as_str());
    fc
}

fn call_hardhat(pi: &ParsedInput, args: &str) -> String {
    format!("{}.{}({});", "console2", pi.fn_name, args)
}

fn call_with_interface(target: String, call: &Call, pi: &ParsedInput, args: &str) -> String {
    let mut fc = format!("{}.{}", target, pi.fn_name);
    if call.value != U256::ZERO { fc.push_str(format!("{{value: {}}}", call.value).as_str()); }
    fc.push_str(format!("({});", args).as_str());
    fc
}

fn decode_bytes_arg(arg: &str, sv: &str, rv: &str, return_vars: &HashMap<String, ReturnData>, na: &mut HashMap<String, String>) -> Vec<String> {
    let bytes = hex::decode(arg).unwrap_or_default();
    let mut abi = Abi::new();
    abi.try_decode_bytes(&bytes);
    let decoded = abi.take_bytes();
    if decoded.len() != 1 { return vec![arg.to_string()]; }
    let d = decoded.into_iter().next().unwrap();
    na.extend(abi.take_addresses());
    d.parts.into_iter().map(|DecodedArg { ty, value, .. }| {
        if ty == "address" && value == sv { "tx.origin".to_string() }
        else if ty == "address" && value == rv { "r".to_string() }
        else if value != "0" && return_vars.contains_key(&value) {
            return_vars.get(&value).unwrap().try_replace(&ty, &value)
        } else { value }
    }).collect()
}

impl ReturnData {
    pub fn try_replace(&self, ty: &str, value: &str) -> String {
        if self.is_dynamic {
            format!("{}({})", self.var, value)
        } else {
            self.var.clone()
        }
    }
}
