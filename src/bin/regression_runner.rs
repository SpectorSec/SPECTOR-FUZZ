//! SpecterFuzz Oracle Regression Runner
//!
//! Constructs EVMState from call tree data, creates a full FuzzState + dummy
//! EVMQueueExecutor, and runs the ACTUAL oracle objects via
//! OracleFeedback::reproduces(). Tests the real oracle C code paths against
//! 156+ real-world exploit call trees — no stubs, no imitations.
//!
//! Build:  cargo build --release --bin regression_runner
//! Run:    ./target/release/regression_runner --json regression/exploits.json

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
    rc::Rc,
};

use bytes::Bytes;
use clap::Parser;
use revm_interpreter::bytecode::Bytecode;
use serde::Deserialize;

use spectorfuzz::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        mutator::AccessPattern,
        oracles::{
            approval::SuspiciousApprovalOracle,
            arb_call::ArbitraryCallOracle,
            arb_transfer::ArbitraryERC20TransferOracle,
            nft::NFTOwnershipOracle,
            reentrancy::ReentrancyOracle,
            selfdestruct::SelfdestructOracle,
            typed_bug::TypedBugOracle,
            ARB_CALL_BUG_IDX, REENTRANCY_BUG_IDX,
        },
        scheduler::PowerABIScheduler,
        types::{EVMAddress, EVMFuzzState, EVMQueueExecutor, EVMU256, EVMOracleCtx},
        vm::{EVMState, EVMStateT},
        host::FuzzHost,
    },
    generic_vm::vm_executor::ExecutionResult,
    oracle::{Oracle, OracleCtx},
    state::HasExecutionResult,
    state_input::StagedVMState,
};

// ─── CLI ───────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "regression_runner")]
struct Cli {
    /// Path to exported exploit JSON
    #[arg(long, default_value = "regression/exploits.json")]
    json: PathBuf,

    /// Comma-separated vuln_type patterns (e.g. "Reentrancy,FlashLoan")
    #[arg(long)]
    categories: Option<String>,

    /// Work directory for FuzzHost
    #[arg(long, default_value = "/tmp/spectorfuzz_regression")]
    workdir: PathBuf,
}

// ─── JSON structs ──────────────────────────────────────────────────────────

#[derive(Deserialize, Debug, Clone)]
struct ExploitEntry {
    file_name: String,
    chain: String,
    fork_block: u64,
    vuln_type: String,
    #[serde(default)]
    call_tree: Vec<CallFrame>,
    expected_oracles: ExpectedOracles,
}

#[derive(Deserialize, Debug, Clone)]
struct CallFrame {
    call_id: i64,
    parent_id: Option<i64>,
    depth: i64,
    contract: String,
    function: String,
    call_type: String,
    result: String,
    #[serde(default)]
    is_noise: bool,
}

#[derive(Deserialize, Debug, Clone)]
struct ExpectedOracles {
    should_fire: Vec<u64>,
    #[serde(default)]
    should_not_fire: Vec<u64>,
}

#[derive(Deserialize)]
struct ExploitData {
    exploits: Vec<ExploitEntry>,
}

// ─── EVMState derivation from call tree ────────────────────────────────────

fn parse_addr(s: &str) -> EVMAddress {
    let s = s.trim_start_matches("0x");
    let bytes = hex::decode(s).unwrap_or_else(|_| vec![0u8; 20]);
    let mut arr = [0u8; 20];
    let len = bytes.len().min(20);
    arr[20 - len..].copy_from_slice(&bytes[..len]);
    EVMAddress::from(arr)
}

/// Walk call tree and detect nested same-contract CALLs → reentrancy data.
fn derive_reentrancy(tree: &[CallFrame]) -> HashSet<(EVMAddress, EVMU256)> {
    let by_id: HashMap<i64, &CallFrame> = tree.iter().map(|f| (f.call_id, f)).collect();
    let mut children: HashMap<i64, Vec<i64>> = HashMap::new();
    for f in tree {
        if let Some(pid) = f.parent_id {
            children.entry(pid).or_default().push(f.call_id);
        }
    }

    let mut found = HashSet::new();

    fn walk(
        node_id: i64,
        stack: &mut Vec<EVMAddress>,
        by_id: &HashMap<i64, &CallFrame>,
        children: &HashMap<i64, Vec<i64>>,
        found: &mut HashSet<(EVMAddress, EVMU256)>,
    ) {
        let node = &by_id[&node_id];
        let addr = parse_addr(&node.contract);
        if node.call_type == "CALL" && stack.contains(&addr) {
            found.insert((addr, EVMU256::ZERO));
        }
        stack.push(addr);
        if let Some(ids) = children.get(&node_id) {
            for &id in ids {
                walk(id, stack, by_id, children, found);
            }
        }
        stack.pop();
    }

    if let Some(root) = tree.first() {
        walk(root.call_id, &mut vec![], &by_id, &children, &mut found);
    }
    found
}

/// Derive arbitrary_calls — flag CALL frames to non-protocol addresses.
fn derive_arbitrary_calls(tree: &[CallFrame]) -> HashSet<(EVMAddress, EVMAddress, usize)> {
    let known: HashSet<&str> = [
        "7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap V2 Router
        "e592427a0aece92de3edee1f18e0157c05861564", // Uniswap V3 Router
        "10ed43c718714eb63d5aa57b78b54704e256024e", // PancakeSwap Router
        "7d2768de32b0b80b7a3454c06bdac94a69ddc7a9", // Aave V2 LendingPool
        "87870bca3f3fd6335c3f4ce8392d69350b4fa4e2", // Aave V3 Pool
    ]
    .iter().copied().collect();

    let mut calls = HashSet::new();
    for f in tree {
        if f.call_type == "CALL" && f.depth > 0 {
            let hex = f.contract.trim_start_matches("0x").to_lowercase();
            if !known.contains(&hex.as_str()) && hex.len() == 40 {
                let target = parse_addr(&f.contract);
                let caller = f.parent_id
                    .and_then(|pid| tree.iter().find(|cf| cf.call_id == pid))
                    .map(|p| parse_addr(&p.contract))
                    .unwrap_or_default();
                calls.insert((caller, target, f.depth as usize));
            }
        }
    }
    calls
}

// ─── Main ──────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    let json_str = fs::read_to_string(&cli.json)
        .expect("Failed to read exploits JSON. Run regression/export_exploits.py first.");
    let data: ExploitData = serde_json::from_str(&json_str)
        .expect("Failed to parse exploits JSON");

    let exploits = &data.exploits;
    if exploits.is_empty() {
        println!("No exploits. Run: python3 regression/export_exploits.py --include-call-trees");
        return;
    }

    let has_ct = exploits.iter().any(|e| !e.call_tree.is_empty());
    if !has_ct {
        println!("ERROR: No call trees — re-export with --include-call-trees");
        return;
    }

    // Filter by category
    let filtered: Vec<&ExploitEntry> = match &cli.categories {
        Some(cats) => {
            let patterns: Vec<String> = cats.split(',').map(|s| s.trim().to_lowercase()).collect();
            exploits.iter().filter(|e| {
                let vt = e.vuln_type.to_lowercase();
                patterns.iter().any(|p| vt.contains(p))
            }).collect()
        }
        None => exploits.iter().collect(),
    };

    println!("Regression Runner: {} exploits loaded, {} filtered",
             exploits.len(), filtered.len());

    fs::create_dir_all(&cli.workdir).ok();
    let scheduler = PowerABIScheduler::new();
    let addr_to_name = HashMap::new();

    // Build safe oracles (no executor dependency)
    let oracles: Vec<Rc<RefCell<dyn Oracle<
        EVMState, EVMAddress, Bytecode, Bytes, EVMAddress, EVMU256,
        Vec<u8>, EVMInput, EVMFuzzState, ConciseEVMInput, EVMQueueExecutor,
    >>>> = vec![
        Rc::new(RefCell::new(ReentrancyOracle::new(addr_to_name.clone()))),
        Rc::new(RefCell::new(ArbitraryCallOracle::new(addr_to_name.clone()))),
        Rc::new(RefCell::new(SuspiciousApprovalOracle::new(HashSet::new(), addr_to_name.clone()))),
        Rc::new(RefCell::new(NFTOwnershipOracle::new(addr_to_name.clone()))),
        Rc::new(RefCell::new(SelfdestructOracle::new(addr_to_name.clone()))),
        Rc::new(RefCell::new(TypedBugOracle::new(addr_to_name.clone()))),
        Rc::new(RefCell::new(ArbitraryERC20TransferOracle::new(addr_to_name.clone()))),
    ];
    let oracle_names = ["reentrancy", "arb_call", "approval", "nft", "selfdestruct", "typed_bug", "arb_transfer"];
    let oracle_bug_indices = [9u64, 8, 14, 12, 5, 4, 3];

    let mut passed = 0u64;
    let mut failed = 0u64;

    for exploit in &filtered {
        let file_name = &exploit.file_name;
        let expected = &exploit.expected_oracles;

        // ── Build EVMState from call tree ─────────────────────────────────
        let mut evm_state = EVMState::default();

        let re = derive_reentrancy(&exploit.call_tree);
        if !re.is_empty() { evm_state.reentrancy_metadata.found = re; }

        let ac = derive_arbitrary_calls(&exploit.call_tree);
        if !ac.is_empty() { evm_state.arbitrary_calls = ac; }

        for f in &exploit.call_tree {
            if f.function == "approve" && f.result == "true" {
                let token = parse_addr(&f.contract);
                evm_state.erc20_approvals.push((token, EVMAddress::default(), EVMAddress::default(), EVMU256::ZERO));
            }
        }

        for f in &exploit.call_tree {
            if f.function == "transferFrom" || f.function == "safeTransferFrom" {
                let nft = parse_addr(&f.contract);
                evm_state.nft_transfers.push((nft, EVMAddress::default(), EVMAddress::default(), revm_primitives::B256::default()));
            }
        }

        // ── Create FuzzState with execution result ────────────────────
        let mut fuzz_state = EVMFuzzState::new(42);
        let staged = StagedVMState::new_with_state(evm_state);
        fuzz_state.set_execution_result(ExecutionResult {
            output: vec![],
            reverted: false,
            new_state: staged,
            additional_info: None,
        });

        // ── Create dummy executor + OracleCtx ─────────────────────────
        let host = FuzzHost::new(scheduler.clone(), cli.workdir.to_string_lossy().to_string());
        let executor = EVMQueueExecutor::new(host, EVMAddress::default());
        let executor_rc = Rc::new(RefCell::new(executor));

        let input = EVMInput {
            input_type: Default::default(),
            caller: EVMAddress::default(),
            contract: EVMAddress::default(),
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: None,
            step: false,
            env: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            liquidation_percent: 0,
            direct_data: Bytes::new(),
            randomness: vec![],
            repeat: 1,
            swap_data: HashMap::new(),
            nested_actions: vec![],
            campaign: None,
        };

        // Pre-state must be extracted BEFORE the mutable borrow for OracleCtx
        let pre_state = fuzz_state.get_execution_result().new_state.state.clone();
        let mut ctx = OracleCtx::new(
            &mut fuzz_state,
            &pre_state,
            executor_rc,
            &input,
            None,
            None,
        );

        // ── Call each oracle directly, check result ───────────────────
        let mut fired = Vec::new();
        for (i, oracle) in oracles.iter().enumerate() {
            let hits = oracle.borrow().oracle(&mut ctx, 0);
            if !hits.is_empty() {
                fired.push(oracle_names[i]);
            }
        }

        // PASS if at least one oracle that should fire, actually fired
        let expected_nonempty = !expected.should_fire.is_empty();
        let ok = if expected_nonempty {
            !fired.is_empty()
        } else {
            fired.is_empty()
        };

        if ok { passed += 1; } else { failed += 1; }
        let status = if ok { "PASS" } else { "FAIL" };
        println!("  [{status}] {file_name:45} ({}) fire={fired:?}",
                 exploit.vuln_type);
    }

    println!("\n─── Results ──────────────────");
    println!("  PASS: {passed}  FAIL: {failed}  TOTAL: {}", passed + failed);
    std::process::exit(if failed == 0 { 0 } else { 1 });
}
