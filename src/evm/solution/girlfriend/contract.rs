use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Display,
    mem,
    str::FromStr,
};

use alloy_primitives::U256;
use anyhow::Result;
use serde::Serialize;
use tracing::error;

use super::{
    abi::{
        self,
        types::{DecodedArg, MemoryVar, StructDef},
        Abi,
    },
    utils::hash_to_name,
};

const HARDHAT_CHEAT_ADDR: &str = "0x000000000000000000636F6e736F6c652e6c6f67";
const CALL_STACK_MAX_DEPTH: usize = 30;
const PHALCON_URL: &str = "https://explorer.phalcon.xyz/tx";

#[derive(Debug, Serialize, Default)]
pub struct Contract {
    pub name: String,
    pub addr: String,
    pub setup_constructor: Option<SetupConstructor>,
    pub sub_contracts: HashMap<String, SubContract>,
    pub ordered_sub_contracts: Vec<SubContract>,
    pub named_addresses: BTreeMap<String, String>,
    pub test1_calls: Vec<String>,
    pub test2_calls: Vec<String>,
    pub functions: HashMap<String, Function>,
    pub ordered_functions: Vec<ConciseFn>,
    pub counters: Vec<String>,
    pub fallback: HashMap<String, UnresolvedFn>,
    pub salt: Option<String>,
    pub is_receiver: bool,
    pub is_inner: bool,
}

#[derive(Debug, Serialize, Default)]
pub struct SetupConstructor {
    pub fn_def: String,
    pub fn_calls: Vec<String>,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct SubContract {
    pub name: String,
    pub var_name: String,
    pub addr: String,
    pub is_receiver: bool,
    pub is_inner: bool,
    pub salt: Option<String>,
    pub initcode_hash: Option<InitCodeHash>,
    pub str_constructor_args: String,
    pub constructor_args: HashMap<String, String>,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct InitCodeHash {
    pub var: String,
    pub value: String,
}

#[derive(Debug, Default, Serialize)]
pub struct Function {
    pub is_view: bool,
    pub fn_def_signature: String,
    pub ret_signature: String,
    pub call_groups: Vec<CallGroup>,
    pub payable: bool,
}

impl Function {
    /// Collapse consecutive identical call groups into one, recording how many times it
    /// repeats (repeats.0) and the running index (repeats.1). Without this, every group
    /// kept repeats=(1,0) and the generated dispatch guards were `<= 0` (dead code), so the
    /// PoC body did nothing. Ported from the standalone girlfriend generator.
    pub fn merge_duplicate_calls(&mut self) {
        if self.call_groups.is_empty() {
            return;
        }
        let mut merged: Vec<CallGroup> = vec![];
        let mut prev = self.call_groups.first().unwrap().clone();
        for (idx, call) in self.call_groups.iter().enumerate().skip(1) {
            if &prev == call {
                prev.repeats.0 += 1;
            } else {
                merged.push(prev);
                prev = call.clone();
            }
            prev.repeats.1 = idx;
        }
        merged.push(prev);
        self.call_groups = merged;
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct CallGroup {
    pub calls: Vec<ParsedCall>,
    pub raw_output: String,
    pub decoded_output: Vec<String>,
    /// (repeats, last_idx). Two consecutive identical groups merge, incrementing
    /// repeats.0 and recording the running index in repeats.1.
    pub repeats: (usize, usize),
}

// Custom equality: a group repeats if its calls + output match — `repeats` itself
// (which mutates during merge) must be excluded from the comparison.
impl PartialEq for CallGroup {
    fn eq(&self, other: &Self) -> bool {
        self.calls == other.calls && self.raw_output == other.raw_output
    }
}

#[derive(Debug, Serialize, Default)]
pub struct ConciseFn {
    pub is_view: bool,
    pub fn_def_signature: String,
    pub ret_def_signature: String,
    pub counter: String,
    pub call_groups: Vec<ConciseCallGroup>,
    pub payable: bool,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct ConciseCallGroup {
    pub calls: Vec<String>,
    pub outputs: Vec<String>,
    pub cond: String,
}

#[derive(Debug, Serialize, Default)]
pub struct UnresolvedFn {
    pub fn_selector: String,
    pub fn_signature: String,
}

#[derive(Debug, Eq, PartialEq, Default, Clone, Serialize)]
pub enum ParsedCallType {
    #[default]
    Interface,
    Raw,
    SendValue,
    Create,
    Create2,
    SelfDestruct,
    DelegateCall,
    HardhatCheat,
    WithSelector,
    Parentheses,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ParsedCall {
    pub ty: ParsedCallType,
    pub sol_ty: String,
    pub caller: String,
    pub target: String,
    pub fn_signature: String,
    pub ret_signature: String,
    pub fn_call: String,
    pub raw_input: String,
    pub raw_output: String,
    pub value: U256,
    pub sub_calls: Vec<ParsedCall>,
    pub memory_vars: Vec<MemoryVar>,
    pub named_addresses: HashMap<String, String>,
    pub struct_defs: HashMap<String, StructDef>,
    pub return_vars: HashMap<String, ReturnData>,
    pub return_data: Vec<ReturnData>,
    pub ret_decode_call: Option<String>,
    pub salt: Option<String>,
    pub comment: Option<String>,
    pub target_is_contract: bool,
    pub vm_state: Option<VmState>,
    pub inner_create_vars: HashSet<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct VmState {
    pub forked_rpc: String,
    pub tx_hash: String,
    pub block_number: String,
    pub block_timestamp: String,
}

impl VmState {
    pub fn generate(&self, is_first_call: bool) -> Vec<String> {
        if is_first_call {
            vec![format!("vm.createSelectFork(\"{}\", {}); // tx.blockNumber - 1", self.forked_rpc, self.block_number)]
        } else {
            vec![
                format!("vm.warp({});", self.block_timestamp),
                format!("vm.roll({});", self.block_number),
            ]
        }
    }
}

#[derive(Debug, Serialize, Default, Clone, PartialEq, Eq)]
pub struct ReturnData {
    pub ty: String,
    pub var: String,
    pub value: String,
    pub is_dynamic: bool,
}

impl Display for ReturnData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_dynamic {
            write!(f, "// {} memory {} = {};", self.ty, self.var, self.value)
        } else {
            write!(f, "// {} {} = {};", self.ty, self.var, self.value)
        }
    }
}

impl Contract {
    pub fn new(addr: String, is_receiver: bool, is_inner: bool, salt: Option<String>) -> Self {
        let mut name = hash_to_name(&addr);
        name = name[..1].to_uppercase() + &name[1..];
        Self { name, addr, is_receiver, is_inner, salt, ..Default::default() }
    }

    pub fn generate(
        &mut self,
        all_contracts: &HashMap<String, HashMap<String, SubContract>>,
        last_txhash: &str,
        root_fn_sigs: &[&str],
        interface: &mut HashSet<String>,
        struct_defs: &HashMap<String, StructDef>,
    ) {
        if self.is_receiver {
            self.build_setup(last_txhash);
            self.build_receiver_constructor();
        } else {
            self.build_constructor(interface, all_contracts, struct_defs);
        }
        self.tidy_functions(root_fn_sigs, interface, all_contracts, struct_defs);
        self.named_addresses.remove(&self.name.to_lowercase());
        self.order_sub_contracts();
    }

    pub fn build_function(&mut self, call: ParsedCall, struct_defs: &HashMap<String, StructDef>) {
        let mut func = if let Some(f) = self.functions.remove(&call.fn_signature) {
            f
        } else {
            match call.generate_function(struct_defs) {
                Ok(f) => f,
                Err(_) => return,
            }
        };
        let decoded_output = self.parse_output(&func.ret_signature, &call.raw_output);
        func.call_groups.push(CallGroup::new(call.sub_calls, call.raw_output, decoded_output));
        self.functions.insert(call.fn_signature, func);
    }

    pub fn setup_test1_vm_state(&mut self, first_state: VmState, last_state: VmState, sender: &str) {
        self.test1_calls.extend(vec![
            format!("vm.createSelectFork(\"{}\", {}); // tx.blockNumber - 1", last_state.forked_rpc, last_state.block_number),
            format!("// vm.createSelectFork(\"{}\", bytes32({}));", first_state.forked_rpc, first_state.tx_hash),
            format!("vm.deal({sender}, 100 ether); // match INITIAL_BALANCE set during fuzzing"),
            String::new(),
        ]);
    }

    pub fn push_test1_call(&mut self, root_call: ParsedCall, is_last_call: bool) {
        self.named_addresses.extend(root_call.named_addresses.clone());
        let calls = root_call.generate_test1_call(is_last_call, self);
        self.test1_calls.extend(calls);
    }

    pub fn push_test2_call(&mut self, root_call: ParsedCall, is_first_call: bool, is_last_call: bool) {
        self.named_addresses.extend(root_call.named_addresses.clone());
        let calls = root_call.generate_test2_call(is_first_call, is_last_call, self);
        self.test2_calls.extend(calls);
    }

    pub fn init_address_vars(&self) -> Vec<String> {
        let mut calls = vec![];
        for sub in &self.ordered_sub_contracts {
            if let Some(ref salt) = sub.salt {
                if let Some(ref initcode_hash) = sub.initcode_hash {
                    calls.push(format!("bytes32 {} = {};", initcode_hash.var, initcode_hash.value));
                    calls.push(format!("{} = address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), r, bytes32({:?}), {})))));", sub.var_name, salt, initcode_hash.var));
                }
            } else if !sub.is_inner {
                calls.push(format!("{} = {};", sub.var_name, sub.addr));
            }
        }
        calls
    }

    fn build_setup(&mut self, last_txhash: &str) {
        let tx_hash_link = format!("{}/{}/{}", PHALCON_URL, "", last_txhash);
        self.setup_constructor = Some(SetupConstructor {
            fn_def: "function setUp() public".to_string(),
            fn_calls: vec![format!("// {tx_hash_link}")],
        });
    }

    fn build_receiver_constructor(&mut self) {
        let sub_contracts = self.ordered_sub_contracts.clone();
        if sub_contracts.is_empty() { return; }
        let mut calls = vec![];
        for sub in &sub_contracts {
            if let Some(ref salt) = sub.salt {
                calls.push(format!("{} = address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), r, bytes32({:?}), {})))));", sub.var_name, salt, "initcodeHash"));
            } else if sub.is_inner {
                calls.push(format!("{} = address(new {}());", sub.var_name, sub.name));
            } else {
                calls.push(format!("{} = {};", sub.var_name, sub.addr));
            }
        }
    }

    fn build_constructor(
        &mut self,
        interface: &mut HashSet<String>,
        all_contracts: &HashMap<String, HashMap<String, SubContract>>,
        struct_defs: &HashMap<String, StructDef>,
    ) {
        let mut calls = vec![];
        for sub in &self.ordered_sub_contracts {
            if let Some(ref salt) = sub.salt {
                let initcode_hash_key = sub.name.to_lowercase();
                let initcode_hash = all_contracts.get(&initcode_hash_key)
                    .and_then(|subs| subs.values().find(|s| s.initcode_hash.is_some()))
                    .and_then(|s| s.initcode_hash.clone());
                if let Some(ref initcode_hash) = initcode_hash {
                    calls.push(format!("bytes32 {} = {};", initcode_hash.var, initcode_hash.value));
                    calls.push(format!("{} = address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), r, bytes32({:?}), {})))));", sub.var_name, salt, initcode_hash.var));
                }
            } else if sub.is_inner {
                if sub.str_constructor_args.is_empty() {
                    calls.push(format!("{} = address(new {}());", sub.var_name, sub.name));
                } else {
                    calls.push(format!("{} = address(new {}({}));", sub.var_name, sub.name, sub.str_constructor_args));
                }
            } else {
                calls.push(format!("{} = {};", sub.var_name, sub.addr));
                if !sub.is_receiver && !sub.is_inner {
                    self.named_addresses.insert(sub.var_name.clone(), sub.addr.clone());
                }
            }
        }
        self.setup_constructor = Some(SetupConstructor {
            fn_def: "constructor() public".to_string(),
            fn_calls: calls,
        });
    }

    fn tidy_functions(
        &mut self,
        root_fn_sigs: &[&str],
        interface: &mut HashSet<String>,
        all_contracts: &HashMap<String, HashMap<String, SubContract>>,
        struct_defs: &HashMap<String, StructDef>,
    ) {
        let functions = mem::take(&mut self.functions);
        let mut ordered: Vec<(String, Function)> = functions.into_iter().collect();
        ordered.sort_by(|a, b| {
            let a_is_root = root_fn_sigs.contains(&a.0.as_str());
            let b_is_root = root_fn_sigs.contains(&b.0.as_str());
            if a_is_root && !b_is_root { std::cmp::Ordering::Less }
            else if !a_is_root && b_is_root { std::cmp::Ordering::Greater }
            else { a.0.cmp(&b.0) }
        });
        // Collapse consecutive duplicate call groups and populate `repeats` so the dispatch
        // guards below are real (`== n` / `<= n`) instead of dead `<= 0`.
        for (_, func) in ordered.iter_mut() {
            func.merge_duplicate_calls();
        }
        let mut counters = vec![];
        for (fn_sig, func) in &ordered {
            let counter = if func.call_groups.len() > 1 {
                let c = format!("{}_counter", fn_sig.split('(').next().unwrap_or("fn").to_lowercase());
                counters.push(c.clone());
                Some(c)
            } else { None };
            let mut abi = Abi::new();
            let fn_def_signature = abi.get_fn_def_signature(fn_sig, struct_defs).unwrap_or_else(|_| fn_sig.clone());

            let mut call_groups: Vec<ConciseCallGroup> = vec![];
            for cg in &func.call_groups {
                let mut calls = vec![];
                for c in &cg.calls {
                    let _ = c.generate_calls(&mut calls, self, interface, all_contracts, struct_defs, fn_sig);
                }
                calls.extend(cg.decoded_output.iter().cloned());
                // counter++ is emitted before the if-block, so the counter starts at 1.
                // A group seen once → `== idx+1` (fires on exactly that call); a group that
                // repeats → `<= idx+1` (fires for the whole run of duplicates).
                let cond = if counter.is_some() {
                    if cg.repeats.0 == 1 { format!("== {}", cg.repeats.1 + 1) }
                    else { format!("<= {}", cg.repeats.1 + 1) }
                } else { String::new() };
                call_groups.push(ConciseCallGroup { calls, outputs: vec![], cond });
            }

            let ret_def_signature = if func.ret_signature.is_empty() {
                String::new()
            } else {
                abi.get_ret_def_signature(&func.ret_signature, struct_defs).unwrap_or_default()
            };

            self.ordered_functions.push(ConciseFn {
                is_view: func.is_view,
                fn_def_signature,
                ret_def_signature,
                counter: counter.unwrap_or_default(),
                call_groups,
                payable: func.payable,
            });
        }
        self.counters = counters;
    }

    fn order_sub_contracts(&mut self) {
        let subs = mem::take(&mut self.sub_contracts);
        let mut ordered: Vec<_> = subs.into_values().collect();
        ordered.sort_by(|a, b| a.name.cmp(&b.name));
        self.ordered_sub_contracts = ordered;
    }

    pub fn build_sub_contracts(&mut self, all_contracts: &[SubContract]) {
        for c in all_contracts {
            if c.addr == self.addr { continue; }
            let var_name = c.var_name.clone();
            self.sub_contracts.entry(var_name.clone()).or_insert_with(|| {
                let mut sc = c.clone();
                sc.is_receiver = false;
                sc
            });
        }
    }

    pub fn build_sub_contracts_constructor_args(&mut self, all_contracts: &HashMap<String, HashMap<String, SubContract>>) {
        for sub in self.sub_contracts.values_mut() {
            if sub.constructor_args.is_empty() { continue; }
            let args = all_contracts.get(&sub.name.to_lowercase())
                .map(|subs| {
                    sub.constructor_args.iter().map(|(k, v)| {
                        subs.values().find(|s| s.var_name == *k)
                            .map(|s| s.var_name.clone())
                            .unwrap_or_else(|| v.clone())
                    }).collect::<Vec<_>>().join(", ")
                })
                .unwrap_or_default();
            sub.str_constructor_args = args;
        }
    }

    pub fn flat_nested_sub_contracts(&mut self, all_contracts: &HashMap<String, HashMap<String, SubContract>>) {
        let keys: Vec<String> = self.sub_contracts.keys().cloned().collect();
        for key in keys {
            if let Some(sub) = self.sub_contracts.get(&key).cloned() {
                // Check this sub's own subs
                let lower = sub.name.to_lowercase();
                if let Some(subs) = all_contracts.get(&lower) {
                    for (vk, vs) in subs {
                        if !self.sub_contracts.contains_key(vk) {
                            self.sub_contracts.entry(vk.clone()).or_insert_with(|| {
                                let mut sc = vs.clone();
                                sc.is_inner = true;
                                sc
                            });
                        }
                    }
                }
            }
        }
    }

    pub fn tidy_named_addresses(&mut self) {
        // Remove our own address from named_addresses
        let key = self.name.to_lowercase();
        self.named_addresses.remove(&key);
    }

    pub fn parse_output(&self, ret_sig: &str, output: &str) -> Vec<String> {
        if ret_sig.is_empty() || output.is_empty() || output == "0x" { return vec![]; }
        let mut abi = Abi::new();
        match abi.decode_output(ret_sig, output) {
            Ok(args) => args.into_iter().map(|a| a.value).collect(),
            Err(_) => vec![],
        }
    }
}

impl SubContract {
    pub fn new(name: &str, addr: &str, is_receiver: bool, is_inner: bool, salt: Option<String>) -> Self {
        Self {
            name: name.to_string(),
            var_name: name.to_lowercase(),
            addr: addr.to_string(),
            is_receiver,
            is_inner,
            salt,
            ..Default::default()
        }
    }
}

impl From<&Contract> for SubContract {
    fn from(c: &Contract) -> Self {
        Self::new(&c.name, &c.addr, c.is_receiver, c.is_inner, c.salt.clone())
    }
}

impl UnresolvedFn {
    pub fn new(fn_selector: String, fn_signature: String) -> Self {
        Self { fn_selector, fn_signature }
    }
}

impl CallGroup {
    pub fn new(calls: Vec<ParsedCall>, raw_output: String, decoded_output: Vec<String>) -> Self {
        // repeats starts at (1, 0): a fresh group has occurred once. merge_duplicate_calls
        // bumps .0 for each consecutive duplicate and tracks the running index in .1.
        Self { calls, raw_output, decoded_output, repeats: (1, 0) }
    }
}

impl ParsedCall {
    pub fn left_parenthesis() -> Self {
        Self { ty: ParsedCallType::Parentheses, fn_call: "{".to_string(), ..Default::default() }
    }

    pub fn right_parenthesis() -> Self {
        Self { ty: ParsedCallType::Parentheses, fn_call: "}".to_string(), ..Default::default() }
    }

    pub fn add_returns(&mut self, raw_output: &str, var_nonce: usize) -> Result<()> {
        let mut abi = Abi::new();
        let args = abi.decode_output(&self.ret_signature, raw_output)?;
        for (i, arg) in args.iter().enumerate() {
            let is_dynamic = arg.is_dynamic;
            let var = format!("ret{}{}", var_nonce, i);
            let rd = ReturnData {
                ty: arg.ty.clone(),
                var,
                value: arg.value.clone(),
                is_dynamic,
            };
            self.return_vars.insert(arg.value.clone(), rd.clone());
            self.return_data.push(rd);
        }
        Ok(())
    }

    pub fn generate_function(&self, struct_defs: &HashMap<String, StructDef>) -> Result<Function> {
        let mut abi = Abi::new();
        let fn_def_signature = abi.get_fn_def_signature(&self.fn_signature, struct_defs)?;
        let ret_def_signature = if self.ret_signature.is_empty() {
            String::new()
        } else {
            abi.get_ret_def_signature(&self.ret_signature, struct_defs)?
        };
        Ok(Function {
            fn_def_signature,
            ret_signature: ret_def_signature,
            is_view: self.sol_ty == "staticcall",
            payable: self.value > U256::ZERO && self.sol_ty != "staticcall",
            ..Default::default()
        })
    }

    pub fn generate_calls(
        &self,
        calls: &mut Vec<String>,
        contract: &Contract,
        interface: &mut HashSet<String>,
        all_contracts: &HashMap<String, HashMap<String, SubContract>>,
        struct_defs: &HashMap<String, StructDef>,
        fn_sig: &str,
    ) -> Result<()> {
        let mut abi = Abi::new();
        let fn_def_signature = abi.get_fn_def_signature(fn_sig, struct_defs)?;
        interface.insert(format!("function {fn_def_signature} external payable;"));

        let mv = self.memory_vars.clone();
        for v in mv {
            calls.extend(v.generate_sol_code());
        }
        calls.push(self.fn_call.clone());

        for sub in &self.sub_calls {
            for mv in &sub.memory_vars {
                calls.extend(mv.generate_sol_code());
            }
            calls.push(sub.fn_call.clone());
        }
        Ok(())
    }

    pub fn generate_test1_call(&self, is_last_call: bool, contract: &Contract) -> Vec<String> {
        let mut calls = vec![];
        for mv in &self.memory_vars {
            calls.extend(mv.generate_sol_code());
        }
        calls.push(self.fn_call.clone());
        calls.extend(contract.init_address_vars());
        calls
    }

    pub fn generate_test2_call(&self, is_first_call: bool, is_last_call: bool, contract: &Contract) -> Vec<String> {
        let mut calls = vec![];
        if is_first_call {
            if let Some(ref vs) = self.vm_state {
                calls.extend(vs.generate(true));
            }
        } else {
            if let Some(ref vs) = self.vm_state {
                calls.extend(vs.generate(false));
            }
        }
        calls.push(self.fn_call.clone());
        calls.extend(contract.init_address_vars());
        calls
    }

    pub fn new_log(&self) -> Option<ParsedCall> {
        let outputs = self.return_data.iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>();
        if outputs.is_empty() { return None; }
        let fn_call = format!("console2.log(\"{}\", {});", self.fn_signature, outputs.join(", "));
        Some(ParsedCall { ty: ParsedCallType::Interface, fn_call, ..Default::default() })
    }
}

pub fn build_sub_contracts(contracts: &mut HashMap<String, Contract>) {
    let concise = contracts.values().map(SubContract::from).collect::<Vec<_>>();
    for c in contracts.values_mut() { c.build_sub_contracts(&concise); }
    let sub_map = contracts.values().map(|c| (c.name.to_lowercase(), c.sub_contracts.clone())).collect();
    for c in contracts.values_mut() { c.flat_nested_sub_contracts(&sub_map); }
}
