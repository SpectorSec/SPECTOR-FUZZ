use std::{cell::RefCell, collections::HashMap, fs::File, io::Read, ops::Deref, path::Path, process::exit, rc::Rc};

use bytes::Bytes;
use glob::glob;
use itertools::Itertools;
use libafl::{
    feedbacks::Feedback,
    prelude::{HasMetadata, MaxMapFeedback, SimpleEventManager, SimpleMonitor, StdMapObserver},
    Evaluator,
    Fuzzer,
};
use libafl_bolts::tuples::tuple_list;
use revm_interpreter::bytecode::Bytecode;
use tracing::{debug, error, info};

use crate::{
    evm::{
        abi::{ABIAddressToInstanceMap, BoxedABI},
        blaz::builder::ArtifactInfoMetadata,
        concolic::{
            concolic_host::CONCOLIC_TIMEOUT,
            concolic_stage::{ConcolicFeedbackWrapper, ConcolicStage},
        },
        config::Config,
        contract_utils::FIX_DEPLOYER,
        corpus_initializer::EVMCorpusInitializer,
        cov_stage::CoverageStage,
        feedbacks::{Sha3WrappedFeedback, TokenBalanceFeedback},
        host::{
            FuzzHost,
            ACTIVE_MATCH_EXT_CALL,
            CALL_UNTIL,
            CMP_MAP,
            JMP_MAP,
            PANIC_ON_BUG,
            READ_MAP,
            WRITE_MAP,
            WRITE_RELATIONSHIPS,
        },
        input::{ConciseEVMInput, EVMInput},
        middlewares::{
            call_printer::CallPrinter,
            cheatcode::Cheatcode,
            coverage::{Coverage, EVAL_COVERAGE},
            middleware::Middleware,
            reentrancy::ReentrancyTracer,
            sha3_bypass::{Sha3Bypass, Sha3TaintAnalysis},
            value_capture::ValueCaptureMiddleware,
        },
        minimizer::EVMMinimizer,
        mutator::FuzzMutator,
        planner::CampaignTargetCache,
        onchain::{flashloan::Flashloan, offchain::OffChainConfig, ChainConfig, OnChain, WHITELIST_ADDR},
        oracles::{
            approval::SuspiciousApprovalOracle,
            arb_call::ArbitraryCallOracle,
            arb_transfer::ArbitraryERC20TransferOracle,
            echidna::EchidnaOracle,
            fee_on_transfer::FeeOnTransferOracle,
            invariant::InvariantOracle,
            nft::NFTOwnershipOracle,
            reentrancy::ReentrancyOracle,
            selfdestruct::SelfdestructOracle,
            typed_bug::TypedBugOracle,
        },
        presets::ExploitTemplate,
        scheduler::{PowerABIMutationalStage, PowerABIScheduler, UncoveredBranchesMetadata},
        types::{fixed_address, EVMAddress, EVMFuzzMutator, EVMFuzzState, EVMQueueExecutor, EVMU256},
        vm::{EVMExecutor, EVMState},
    },
    executor::FuzzExecutor,
    feedback::{CmpFeedback, DataflowFeedback, OracleFeedback},
    fuzzer::{ItyFuzzer, REPLAY, RUN_FOREVER},
    oracle::BugMetadata,
    scheduler::SortedDroppingScheduler,
    state::{FuzzState, HasCaller, HasExecutionResult, HasPresets},
};

#[allow(clippy::type_complexity)]
pub fn evm_fuzzer(
    config: Config<
        EVMState,
        EVMAddress,
        Bytecode,
        Bytes,
        EVMAddress,
        EVMU256,
        Vec<u8>,
        EVMInput,
        EVMFuzzState,
        ConciseEVMInput,
        EVMQueueExecutor,
    >,
    state: &mut EVMFuzzState,
) {
    info!("\n\n ================ EVM Fuzzer Start ===================\n\n");

    // create work dir if not exists
    let _path = Path::new(config.work_dir.as_str());

    let monitor = SimpleMonitor::new(|s| info!("{}", s));
    let mut mgr = SimpleEventManager::new(monitor);
    let infant_scheduler = SortedDroppingScheduler::new();
    let scheduler = PowerABIScheduler::new();

    let jmps = unsafe { &mut JMP_MAP };
    let cmps = unsafe { &mut CMP_MAP };
    let reads = unsafe { &mut READ_MAP };
    let writes = unsafe { &mut WRITE_MAP };
    let jmp_observer = unsafe { StdMapObserver::new("jmp", jmps) };

    let deployer = fixed_address(FIX_DEPLOYER);
    let mut fuzz_host = FuzzHost::new(scheduler.clone(), config.work_dir.clone());
    fuzz_host.set_spec_id(config.spec_id);

    // **Note**: cheatcode should be the first middleware because it consumes the
    // step if it is a call to cheatcode_address, and this step should not be
    // visible to other middlewares.
    fuzz_host.add_middlewares(Rc::new(RefCell::new(Cheatcode::new(&config.etherscan_api_key))));

    macro_rules! create_onchain {
        ($onchain: expr) => {{
            let mid = Rc::new(RefCell::new(OnChain::new(
                // scheduler can be cloned because it never uses &mut self
                $onchain,
                config.onchain_storage_fetching.unwrap(),
            )));

            debug!("onchain middleware enabled");
            fuzz_host.add_middlewares(mid.clone());
            mid
        }};
    }

    let onchain_middleware = match config.onchain.clone() {
        Some(onchain) => Some(create_onchain!(onchain)),
        None => {
            // enable active match for offchain fuzzing (todo: handle this more elegantly)
            match &config.contract_loader.setup_data.clone().map(|s| s.onchain_middleware) {
                Some(Some(mid)) => {
                    let mid = Rc::new(RefCell::new(mid.clone()));
                    fuzz_host.add_middlewares(mid.clone());
                    Some(mid)
                }
                _ => {
                    unsafe {
                        ACTIVE_MATCH_EXT_CALL = false;
                    }
                    None
                }
            }
        }
    };

    if config.write_relationship {
        unsafe {
            WRITE_RELATIONSHIPS = true;
        }
    }

    if config.run_forever {
        unsafe {
            RUN_FOREVER = true;
        }
    }

    unsafe {
        PANIC_ON_BUG = config.panic_on_bug;
    }

    if !config.only_fuzz.is_empty() {
        unsafe {
            WHITELIST_ADDR = Some(config.only_fuzz.clone());
        }
    }

    if config.flashloan {
        // we should use real balance of tokens in the contract instead of providing
        // flashloan to contract as well for on chain env
        {
            let chain_cfg: Option<Box<dyn ChainConfig>> = if let Some(onchain) = config.onchain.clone() {
                Some(Box::new(onchain) as Box<dyn ChainConfig>)
            } else if let Some(ref setup_data) = config.contract_loader.setup_data {
                if setup_data.v2_pairs.is_empty() {
                    None
                } else {
                    Some(Box::new(OffChainConfig::new(setup_data).unwrap()) as Box<dyn ChainConfig>)
                }
            } else {
                None
            };

            fuzz_host.add_flashloan_middleware(Flashloan::new(true, chain_cfg, config.flashloan_oracle));
        }
    }
    let sha3_taint = Rc::new(RefCell::new(Sha3TaintAnalysis::new()));

    debug!("sha3 bypass enabled (unconditional)");
    fuzz_host.add_middlewares(Rc::new(RefCell::new(Sha3Bypass::new(sha3_taint.clone()))));

    if config.reentrancy_oracle {
        debug!("reentrancy oracle enabled");
        fuzz_host.add_middlewares(Rc::new(RefCell::new(ReentrancyTracer::new())));
    }

    if config.value_capture {
        debug!("value capture middleware enabled");
        fuzz_host.add_middlewares(Rc::new(RefCell::new(ValueCaptureMiddleware::new())));
    }

    let mut evm_executor: EVMQueueExecutor = EVMExecutor::new(fuzz_host, deployer);

    if config.replay_file.is_some() {
        // add coverage middleware for replay
        unsafe {
            REPLAY = true;
        }
    }

    // moved here to ensure state has ArtifactInfoMetadata during corpus
    // initialization
    if !state.has_metadata::<ArtifactInfoMetadata>() {
        state.add_metadata(ArtifactInfoMetadata::new());
    }
    let mut corpus_initializer = EVMCorpusInitializer::new(
        &mut evm_executor,
        scheduler.clone(),
        infant_scheduler.clone(),
        state,
        config.work_dir.clone(),
    );

    let mut artifacts = corpus_initializer.initialize(&mut config.contract_loader.clone());

    // Store topology hints in state metadata so CorpusPowerABITestcaseScore
    // can boost mutation energy toward topology-predicted exploit sequences.
    if let Some(ref report) = artifacts.topology {
        use crate::evm::topology::TopologyHints;
        state.add_metadata(TopologyHints::from_report_and_abi(report, &artifacts.address_to_abi));
    }

    let mut instance_map = ABIAddressToInstanceMap::new();
    artifacts.address_to_abi_object.iter().for_each(|(addr, abi)| {
        instance_map.map.insert(*addr, abi.clone());
    });

    #[cfg(feature = "use_presets")]
    {
        // Start with the baked-in DefiHacksPresets corpus — always loaded,
        // no flag required. This is the third capability gate flipped to
        // default-on in this fork (after Sha3Bypass and flashloan accounting).
        // The README's "80% of previous hacks" claim depends on these
        // templates being matched against the target's deployed contracts.
        let mut exploit_templates = ExploitTemplate::baked_in();
        debug!("loaded {} baked-in exploit templates", exploit_templates.len());

        // If the user passed --preset-file-path, layer those templates ON TOP
        // of the baked-in set (additive, never replacing). Keeps power-user
        // workflows working — they can ship their own curated corpus and
        // still benefit from the baked-in historical set.
        if !config.preset_file_path.is_empty() {
            let extra = ExploitTemplate::from_filename(config.preset_file_path.clone());
            debug!("loaded {} additional templates from {}", extra.len(), config.preset_file_path);
            exploit_templates.extend(extra);
        }

        let mut sig_to_addr_abi_map = HashMap::new();
        let mut matched_templates = vec![];
        for template in exploit_templates {
            // to match, all function_sigs in the template
            // must exists in all abi.function
            let mut function_sigs = template.function_sigs.clone();
            for (addr, abis) in &artifacts.address_to_abi_object {
                for abi in abis {
                    for (idx, function_sig) in function_sigs.iter().enumerate() {
                        if abi.function == function_sig.value {
                            debug!("matched: {:?} @ {:?}", abi.function, addr);
                            sig_to_addr_abi_map.insert(function_sig.value, (*addr, abi.clone()));
                            function_sigs.remove(idx);
                            break;
                        }
                    }
                }
                if function_sigs.is_empty() {
                    matched_templates.push(template);
                    break;
                }
            }
        }
        let has_preset_match = !matched_templates.is_empty();
        debug!("has_preset_match: {} {}", has_preset_match, matched_templates.len());

        state.init_presets(has_preset_match, matched_templates.clone(), sig_to_addr_abi_map);
    }
    let cov_middleware = Rc::new(RefCell::new(Coverage::new(
        artifacts.address_to_name.clone(),
        config.work_dir.clone(),
    )));

    evm_executor.host.add_middlewares(cov_middleware.clone());

    state.add_metadata(instance_map);

    evm_executor.host.initialize(state);
    evm_executor.host.initial_block_timestamp = Some(artifacts.initial_env.block.timestamp);

    // now evm executor is ready, we can clone it

    let evm_executor_ref = Rc::new(RefCell::new(evm_executor));

    let meta = state.metadata_map_mut().get_mut::<ArtifactInfoMetadata>().unwrap();
    for (addr, build_artifact) in &artifacts.build_artifacts {
        meta.add(*addr, build_artifact.clone());
    }

    for (addr, bytecode) in &mut artifacts.address_to_bytecode {
        unsafe {
            cov_middleware.deref().borrow_mut().on_insert(
                None,
                &mut evm_executor_ref.deref().borrow_mut().host,
                state,
                bytecode,
                *addr,
            );
        }
    }

    let mut feedback = MaxMapFeedback::new(&jmp_observer);
    feedback.init_state(state).expect("Failed to init state");
    // let calibration = CalibrationStage::new(&feedback);
    if config.concolic {
        unsafe { CONCOLIC_TIMEOUT = config.concolic_timeout };
        // Feature 009: the linearity reexecution / dispatch triage only matters when
        // concolic is on (it manages the concolic budget). Gate it on this flag.
        crate::evm::middlewares::cmp_linearity::lin_set_concolic_enabled(true);
    }

    let concolic_stage = ConcolicStage::new(
        config.concolic,
        config.concolic_caller,
        evm_executor_ref.clone(),
        config.concolic_num_threads,
    );
    if config.campaign_orchestrator {
        // The executor stores CampaignIntermediateStates as metadata after a campaign
        // run; its SerdeAny impl needs explicit registration (the others use
        // impl_serdeany!). Without this, the first insert panics "inserted without
        // registration". Safe here: single-threaded setup, before fuzzing starts.
        unsafe {
            crate::evm::types::CampaignIntermediateStatesEVM::register();
        }
        let instance_map = state.metadata_map().get::<ABIAddressToInstanceMap>().cloned();
        let cache = instance_map
            .map(|m| CampaignTargetCache::new(&m, Vec::new()))
            .unwrap_or_else(|| CampaignTargetCache::new(&ABIAddressToInstanceMap::default(), Vec::new()));
        state.add_metadata(cache);
    }

    let mutator: EVMFuzzMutator = FuzzMutator::new(infant_scheduler.clone(), config.campaign_orchestrator, config.ghost_identities, config.temporal_skimming);

    state.metadata_map_mut().insert(UncoveredBranchesMetadata::new());
    let std_stage = PowerABIMutationalStage::new(mutator);

    let call_printer_mid = Rc::new(RefCell::new(CallPrinter::new(artifacts.address_to_name.clone())));

    let coverage_obs_stage = CoverageStage::new(
        evm_executor_ref.clone(),
        cov_middleware.clone(),
        call_printer_mid.clone(),
        config.work_dir.clone(),
    );

    let mut stages = tuple_list!(std_stage, concolic_stage, coverage_obs_stage);

    let mut executor = FuzzExecutor::new(evm_executor_ref.clone(), tuple_list!(jmp_observer));

    #[cfg(feature = "deployer_is_attacker")]
    state.add_caller(&deployer);
    let cmp_feedback = CmpFeedback::new(cmps, infant_scheduler.clone(), evm_executor_ref.clone());

    // Build attacker set for TokenBalanceFeedback from callers_pool.
    let attackers: std::collections::HashSet<EVMAddress> =
        state.callers_pool.iter().cloned().collect();
    let balance_feedback = TokenBalanceFeedback::new(attackers, infant_scheduler.clone());

    // Combine: any new coverage ceiling OR any new fund-extraction ceiling
    // makes the state interesting and gets added to infant corpus.
    let infant_feedback = libafl::feedbacks::EagerOrFeedback::new(cmp_feedback, balance_feedback);
    let infant_result_feedback = DataflowFeedback::new(reads, writes);

    let mut oracles = config.oracle;

    if config.echidna_oracle {
        let echidna_oracle = EchidnaOracle::new(
            artifacts
                .address_to_abi
                .iter()
                .flat_map(|(address, abis)| {
                    abis.iter()
                        .filter(|abi| abi.function_name.starts_with("echidna_") && abi.abi == "()")
                        .map(|abi| (*address, abi.function.to_vec()))
                        .collect_vec()
                })
                .collect_vec(),
            artifacts
                .address_to_abi
                .iter()
                .flat_map(|(_address, abis)| {
                    abis.iter()
                        .filter(|abi| abi.function_name.starts_with("echidna_") && abi.abi == "()")
                        .map(|abi| (abi.function.to_vec(), abi.function_name.clone()))
                        .collect_vec()
                })
                .collect::<HashMap<Vec<u8>, String>>(),
        );
        oracles.push(Rc::new(RefCell::new(echidna_oracle)));
    }

    if config.invariant_oracle {
        let invariant_oracle = InvariantOracle::new(
            artifacts
                .address_to_abi
                .iter()
                .flat_map(|(address, abis)| {
                    abis.iter()
                        .filter(|abi| abi.function_name.starts_with("invariant_") && abi.abi == "()")
                        .map(|abi| (*address, abi.function.to_vec()))
                        .collect_vec()
                })
                .collect_vec(),
            artifacts
                .address_to_abi
                .iter()
                .flat_map(|(_address, abis)| {
                    abis.iter()
                        .filter(|abi| abi.function_name.starts_with("invariant_") && abi.abi == "()")
                        .map(|abi| (abi.function.to_vec(), abi.function_name.clone()))
                        .collect_vec()
                })
                .collect::<HashMap<Vec<u8>, String>>(),
        );
        oracles.push(Rc::new(RefCell::new(invariant_oracle)));
    }

    if config.nft_oracle {
        let nft_oracle = NFTOwnershipOracle::new(artifacts.address_to_name.clone());
        oracles.push(Rc::new(RefCell::new(nft_oracle)));
    }

    if config.fee_on_transfer_oracle {
        let fee_oracle = FeeOnTransferOracle::new(artifacts.address_to_name.clone());
        oracles.push(Rc::new(RefCell::new(fee_oracle)));
    }

    if config.approval_oracle {
        use std::collections::HashSet as StdHashSet;
        let known_contracts: StdHashSet<EVMAddress> = artifacts.address_to_name.keys().cloned().collect();
        let approval_oracle = SuspiciousApprovalOracle::new(
            known_contracts,
            artifacts.address_to_name.clone(),
        );
        oracles.push(Rc::new(RefCell::new(approval_oracle)));
    }

    if config.crosschain_oracle {
        use crate::evm::oracles::crosschain::CrossChainOracle;
        use std::collections::HashSet as StdHashSet;
        // Start with an empty trusted_bridges set. In practice, users can add
        // known bridge endpoints via the onchain config; the fuzzer will flag
        // any non-trusted caller that successfully invokes a receiver.
        let trusted_bridges: StdHashSet<EVMAddress> = StdHashSet::new();
        let cc_oracle = CrossChainOracle::new(trusted_bridges, artifacts.address_to_name.clone());
        oracles.push(Rc::new(RefCell::new(cc_oracle)));
    }

    if config.rebasing_oracle {
        use crate::evm::oracles::rebasing::RebasingOracle;
        use std::collections::HashSet as StdHashSet;
        let known_contracts: StdHashSet<EVMAddress> = artifacts.address_to_name.keys().cloned().collect();
        let rebasing_oracle = RebasingOracle::new(known_contracts, artifacts.address_to_name.clone());
        oracles.push(Rc::new(RefCell::new(rebasing_oracle)));
    }

    if config.temporal_skimming {
        use crate::evm::oracles::temporal_skim::TemporalSkimOracle;
        let temporal_oracle = TemporalSkimOracle::new(artifacts.address_to_name.clone());
        oracles.push(Rc::new(RefCell::new(temporal_oracle)));
        info!("Temporal Skim oracle activated (--temporal-skimming)");
    }

    // Auto-detected from ABI fingerprinting — no config flag needed.
    // ERC-4626: activated whenever convertToAssets(uint256) is found in any contract ABI.
    if !artifacts.erc4626_vaults.is_empty() {
        use crate::evm::oracles::erc4626::ERC4626Oracle;
        let erc4626_oracle = ERC4626Oracle::new(
            artifacts.erc4626_vaults.clone(),
            artifacts.address_to_name.clone(),
        );
        oracles.push(Rc::new(RefCell::new(erc4626_oracle)));
        info!("ERC-4626 share-price oracle auto-activated for {} vault(s)", artifacts.erc4626_vaults.len());
    }

    // EIP-712: corpus seeds already injected in corpus_initializer.
    // Log detection for visibility.
    if !artifacts.eip712_contracts.is_empty() {
        info!("EIP-712 domain separator detected in {} contract(s) — zero-sig seeds injected", artifacts.eip712_contracts.len());
    }

    // Freshness oracle: auto-activated when Chainlink-style oracle contracts
    // are detected in the ABI (latestRoundData / latestAnswer / getRoundData).
    // Monitors updatedAt field post-execution; flags stale data accepted without
    // a freshness check — Ghost #3 from the DeFi ghost taxonomy.
    if !artifacts.oracle_contracts.is_empty() {
        use crate::evm::oracles::freshness::FreshnessOracle;
        let freshness_oracle = FreshnessOracle::new(
            artifacts.oracle_contracts.clone(),
            artifacts.address_to_name.clone(),
            3600, // 1-hour default staleness threshold (Chainlink heartbeat)
        );
        oracles.push(Rc::new(RefCell::new(freshness_oracle)));
        info!(
            "Freshness oracle auto-activated: {} oracle contract(s) monitored (max staleness: 3600s)",
            artifacts.oracle_contracts.len()
        );
    }

    // Permission-leak oracle: auto-activated when privileged functions are
    // detected in the ABI. All attacker callers are treated as unauthorized;
    // the deployer (address_to_name key that is not in callers_pool) is implicitly
    // allowed by populating the allowed set with only non-attacker addresses.
    if !artifacts.privileged_functions.is_empty() {
        use crate::evm::oracles::function::FunctionOracle;
        let attackers: std::collections::HashSet<EVMAddress> =
            state.callers_pool.iter().cloned().collect();
        let mut fn_oracle = FunctionOracle::new(artifacts.address_to_name.clone());
        for (contract, selector, fn_name) in &artifacts.privileged_functions {
            // Allow only non-attacker callers (i.e., the deployer).
            // Any address in callers_pool is a fuzzer-controlled attacker.
            let deployers: std::collections::HashSet<EVMAddress> = artifacts
                .address_to_name
                .keys()
                .filter(|a| !attackers.contains(*a))
                .cloned()
                .collect();
            fn_oracle.add_rule(*contract, *selector, fn_name.clone(), deployers);
        }
        info!(
            "Permission-leak oracle auto-activated: {} privileged function(s) monitored",
            artifacts.privileged_functions.len()
        );
        oracles.push(Rc::new(RefCell::new(fn_oracle)));
    }

    // if let Some(path) = config.state_comp_oracle {
    //     let mut file = File::open(path.clone()).expect("Failed to open state comp
    // oracle file");     let mut buf = String::new();
    //     file.read_to_string(&mut buf)
    //         .expect("Failed to read state comp oracle file");

    //     let evm_state =
    // serde_json::from_str::<EVMState>(buf.as_str()).expect("Failed to parse state
    // comp oracle file");

    //     let oracle = Rc::new(RefCell::new(StateCompOracle::new(
    //         evm_state,
    //         config.state_comp_matching.unwrap(),
    //     )));
    //     oracles.push(oracle);
    // }

    if config.arbitrary_external_call {
        oracles.push(Rc::new(RefCell::new(ArbitraryCallOracle::new(
            artifacts.address_to_name.clone(),
        ))));
        oracles.push(Rc::new(RefCell::new(
            ArbitraryERC20TransferOracle::new(artifacts.address_to_name.clone()),
        )));
    }

    if config.typed_bug {
        oracles.push(Rc::new(RefCell::new(TypedBugOracle::new(
            artifacts.address_to_name.clone(),
        ))));
    }

    state.add_metadata(BugMetadata::new());

    if config.selfdestruct_oracle {
        oracles.push(Rc::new(RefCell::new(SelfdestructOracle::new(
            artifacts.address_to_name.clone(),
        ))));
    }

    if config.reentrancy_oracle {
        oracles.push(Rc::new(RefCell::new(ReentrancyOracle::new(
            artifacts.address_to_name.clone(),
        ))));
    }

    // Topology dispatch: translate ranked exploit classes into oracle activation.
    // Only fires for oracles not already activated by CLI flags.
    // Confidence threshold: 70% — below that the signal is too weak to act on.
    //
    // Note: InvariantOracle is Echidna-specific (needs invariant_* named functions).
    // For invariant-leak exploit classes we use ReentrancyOracle + ArbitraryCallOracle
    // which observe the execution trace and catch the state violation at runtime.
    if let Some(ref topo) = artifacts.topology {
        use crate::evm::topology::ExploitClass;
        use crate::evm::oracles::rebasing::RebasingOracle;

        // Track which oracle types topology has already auto-activated
        // so we don't push duplicates.
        let mut topo_reentrancy = config.reentrancy_oracle;
        let mut topo_nft = config.nft_oracle;
        let mut topo_rebasing = config.rebasing_oracle;
        let mut topo_approval = config.approval_oracle;
        let mut topo_arbitrary = config.arbitrary_external_call;
        let mut topo_fee = config.fee_on_transfer_oracle;

        for (class, confidence) in &topo.ranked {
            if *confidence < 70 {
                break; // sorted descending — everything below is also low confidence
            }
            match class {
                ExploitClass::PriceGatedVault => {
                    // FreshnessOracle + ERC4626Oracle already auto-activated from
                    // artifacts.oracle_contracts / artifacts.erc4626_vaults.
                    // Reentrancy catches flash-loan re-entry during vault operations.
                    if !topo_reentrancy {
                        oracles.push(Rc::new(RefCell::new(ReentrancyOracle::new(
                            artifacts.address_to_name.clone(),
                        ))));
                        topo_reentrancy = true;
                        info!("[topology {confidence}%] PriceGatedVault → ReentrancyOracle auto-activated");
                    }
                }
                ExploitClass::FlashDepositDrain => {
                    if !topo_reentrancy {
                        oracles.push(Rc::new(RefCell::new(ReentrancyOracle::new(
                            artifacts.address_to_name.clone(),
                        ))));
                        topo_reentrancy = true;
                        info!("[topology {confidence}%] FlashDepositDrain → ReentrancyOracle auto-activated");
                    }
                }
                ExploitClass::FlashBorrowLeverage => {
                    if !topo_reentrancy {
                        oracles.push(Rc::new(RefCell::new(ReentrancyOracle::new(
                            artifacts.address_to_name.clone(),
                        ))));
                        topo_reentrancy = true;
                        info!("[topology {confidence}%] FlashBorrowLeverage → ReentrancyOracle auto-activated");
                    }
                    if !topo_arbitrary {
                        oracles.push(Rc::new(RefCell::new(ArbitraryCallOracle::new(
                            artifacts.address_to_name.clone(),
                        ))));
                        oracles.push(Rc::new(RefCell::new(ArbitraryERC20TransferOracle::new(
                            artifacts.address_to_name.clone(),
                        ))));
                        topo_arbitrary = true;
                        info!("[topology {confidence}%] FlashBorrowLeverage → ArbitraryCallOracle auto-activated");
                    }
                }
                ExploitClass::FlashGovernance => {
                    // FunctionOracle auto-activated from artifacts.privileged_functions.
                    // Arbitrary call catches the unvalidated execute() target.
                    if !topo_arbitrary {
                        oracles.push(Rc::new(RefCell::new(ArbitraryCallOracle::new(
                            artifacts.address_to_name.clone(),
                        ))));
                        oracles.push(Rc::new(RefCell::new(ArbitraryERC20TransferOracle::new(
                            artifacts.address_to_name.clone(),
                        ))));
                        topo_arbitrary = true;
                        info!("[topology {confidence}%] FlashGovernance → ArbitraryCallOracle auto-activated");
                    }
                }
                ExploitClass::OraclePriceManip => {
                    // FreshnessOracle auto-activated from artifacts.oracle_contracts.
                    // Reentrancy catches price-update callbacks used to skew oracle reads.
                    if !topo_reentrancy {
                        oracles.push(Rc::new(RefCell::new(ReentrancyOracle::new(
                            artifacts.address_to_name.clone(),
                        ))));
                        topo_reentrancy = true;
                        info!("[topology {confidence}%] OraclePriceManip → ReentrancyOracle auto-activated");
                    }
                }
                ExploitClass::NFTReentrancy => {
                    if !topo_nft {
                        oracles.push(Rc::new(RefCell::new(NFTOwnershipOracle::new(
                            artifacts.address_to_name.clone(),
                        ))));
                        topo_nft = true;
                        info!("[topology {confidence}%] NFTReentrancy → NFTOracle auto-activated");
                    }
                    if !topo_reentrancy {
                        oracles.push(Rc::new(RefCell::new(ReentrancyOracle::new(
                            artifacts.address_to_name.clone(),
                        ))));
                        topo_reentrancy = true;
                        info!("[topology {confidence}%] NFTReentrancy → ReentrancyOracle auto-activated");
                    }
                }
                ExploitClass::RewardAccumulator => {
                    // Rebasing oracle catches reward token balance desync.
                    if !topo_rebasing {
                        let known: std::collections::HashSet<EVMAddress> =
                            artifacts.address_to_name.keys().cloned().collect();
                        oracles.push(Rc::new(RefCell::new(RebasingOracle::new(
                            known,
                            artifacts.address_to_name.clone(),
                        ))));
                        topo_rebasing = true;
                        info!("[topology {confidence}%] RewardAccumulator → RebasingOracle auto-activated");
                    }
                }
                ExploitClass::SignatureReplay => {
                    if !topo_approval {
                        let known: std::collections::HashSet<EVMAddress> =
                            artifacts.address_to_name.keys().cloned().collect();
                        oracles.push(Rc::new(RefCell::new(SuspiciousApprovalOracle::new(
                            known,
                            artifacts.address_to_name.clone(),
                        ))));
                        topo_approval = true;
                        info!("[topology {confidence}%] SignatureReplay → ApprovalOracle auto-activated");
                    }
                }
                ExploitClass::ArbitraryCallDrain | ExploitClass::UnprotectedCallback => {
                    if !topo_arbitrary {
                        oracles.push(Rc::new(RefCell::new(ArbitraryCallOracle::new(
                            artifacts.address_to_name.clone(),
                        ))));
                        oracles.push(Rc::new(RefCell::new(ArbitraryERC20TransferOracle::new(
                            artifacts.address_to_name.clone(),
                        ))));
                        topo_arbitrary = true;
                        info!("[topology {confidence}%] {:?} → ArbitraryCallOracle auto-activated", class);
                    }
                    if !topo_reentrancy {
                        oracles.push(Rc::new(RefCell::new(ReentrancyOracle::new(
                            artifacts.address_to_name.clone(),
                        ))));
                        topo_reentrancy = true;
                        info!("[topology {confidence}%] {:?} → ReentrancyOracle auto-activated", class);
                    }
                }
                ExploitClass::AMMInvariant => {
                    // K-invariant bypasses often use swap callbacks — reentrancy covers it.
                    if !topo_reentrancy {
                        oracles.push(Rc::new(RefCell::new(ReentrancyOracle::new(
                            artifacts.address_to_name.clone(),
                        ))));
                        topo_reentrancy = true;
                        info!("[topology {confidence}%] AMMInvariant → ReentrancyOracle auto-activated");
                    }
                }
                ExploitClass::DeflationaryToken => {
                    if !topo_fee {
                        oracles.push(Rc::new(RefCell::new(FeeOnTransferOracle::new(
                            artifacts.address_to_name.clone(),
                        ))));
                        topo_fee = true;
                        info!("[topology {confidence}%] DeflationaryToken → FeeOnTransferOracle auto-activated");
                    }
                    if !topo_rebasing {
                        let known: std::collections::HashSet<EVMAddress> =
                            artifacts.address_to_name.keys().cloned().collect();
                        oracles.push(Rc::new(RefCell::new(RebasingOracle::new(
                            known,
                            artifacts.address_to_name.clone(),
                        ))));
                        topo_rebasing = true;
                        info!("[topology {confidence}%] DeflationaryToken → RebasingOracle auto-activated");
                    }
                }
                ExploitClass::PermissionEscalation => {
                    // FunctionOracle already auto-activated from artifacts.privileged_functions.
                }
            }
        }
    }

    if let Some(m) = onchain_middleware.clone() {
        m.borrow_mut().add_abi(artifacts.address_to_abi.clone());
    }

    let mut producers = config.producers;

    let objective: OracleFeedback<
        '_,
        EVMState,
        EVMAddress,
        Bytecode,
        Bytes,
        EVMAddress,
        revm_primitives::ruint::Uint<256, 4>,
        Vec<u8>,
        EVMInput,
        FuzzState<EVMInput, EVMState, EVMAddress, EVMAddress, Vec<u8>, ConciseEVMInput>,
        ConciseEVMInput,
        EVMQueueExecutor,
    > = OracleFeedback::new(&mut oracles, &mut producers, evm_executor_ref.clone());
    let wrapped_feedback = ConcolicFeedbackWrapper::new(Sha3WrappedFeedback::new(
        feedback,
        sha3_taint,
        evm_executor_ref.clone(),
        config.sha3_bypass,
    ));

    let mut fuzzer: ItyFuzzer<_, _, _, _, _, _, _, _, _, _, _, _, _, _, EVMMinimizer> = ItyFuzzer::new(
        scheduler,
        infant_scheduler,
        wrapped_feedback,
        infant_feedback,
        infant_result_feedback,
        objective,
        EVMMinimizer::new(evm_executor_ref.clone()),
        config.work_dir,
    );

    let initial_vm_state = artifacts.initial_state.clone();
    let mut testcases = vec![];
    let to_load_glob: String;

    if let Some(files) = config.replay_file.clone() {
        to_load_glob = files;
    } else {
        to_load_glob = config.load_corpus;
    }

    if !to_load_glob.is_empty() {
        'process_file: for file in glob(to_load_glob.as_str()).expect("Failed to read glob pattern") {
            let mut f = File::open(file.as_ref().expect("glob issue")).expect("Failed to open file");
            let mut transactions = String::new();
            let mut deserialized_transactions = vec![];
            f.read_to_string(&mut transactions).expect("Failed to read file");
            for txn in transactions.split('\n') {
                if txn.len() < 4 {
                    continue;
                }
                let deserialized_tx = serde_json::from_slice::<ConciseEVMInput>(txn.as_bytes());
                if deserialized_tx.is_err() {
                    error!("Failed to deserialize file: {:?}", file);
                    continue 'process_file;
                }
                deserialized_transactions.push(deserialized_tx.unwrap());
            }
            testcases.push(deserialized_transactions);
        }
    }

    macro_rules! load_code {
        ($txn: expr) => {
            if let Some(onchain_mid) = onchain_middleware.clone() {
                onchain_mid.borrow_mut().load_code(
                    $txn.contract,
                    &mut evm_executor_ref.clone().deref().borrow_mut().host,
                    false,
                    true,
                    false,
                    $txn.caller,
                    state,
                );
            }
        };
    }

    match config.replay_file {
        None => {
            // load initial corpus
            for testcase in testcases {
                let mut vm_state = initial_vm_state.clone();
                for txn in testcase {
                    load_code!(txn);
                    let (inp, call_until) = txn.to_input(vm_state.clone());
                    unsafe {
                        CALL_UNTIL = call_until;
                    }
                    fuzzer
                        .evaluate_input_events(state, &mut executor, &mut mgr, inp, false)
                        .unwrap();
                    vm_state = state.get_execution_result().new_state.clone();
                }
            }
            let res = fuzzer.fuzz_loop(&mut stages, &mut executor, state, &mut mgr);

            // it is not possible to reach here unless an exception is thrown
            let rv = res.err().unwrap().to_string();
            if rv == "No items in No entries in corpus" {
                error!("There is nothing to fuzz. Please check the target you provided.");
                return;
            } else {
                error!("{}", rv);
            }
            exit(1);
        }
        Some(_) => {
            unsafe {
                EVAL_COVERAGE = true;
            }

            let printer = Rc::new(RefCell::new(CallPrinter::new(artifacts.address_to_name.clone())));
            evm_executor_ref.borrow_mut().host.add_middlewares(printer.clone());

            for testcase in testcases {
                let mut vm_state = initial_vm_state.clone();
                let mut idx = 0;
                for txn in testcase {
                    load_code!(txn);
                    idx += 1;
                    // let splitter = txn.split(" ").collect::<Vec<&str>>();
                    info!("============ Execution {} ===============", idx);
                    let (inp, call_until) = txn.to_input(vm_state.clone());
                    printer.borrow_mut().cleanup();

                    unsafe {
                        CALL_UNTIL = call_until;
                    }

                    fuzzer
                        .evaluate_input_events(state, &mut executor, &mut mgr, inp, false)
                        .unwrap();

                    info!("============ Execution result {} =============", idx);
                    info!("reverted: {:?}", state.get_execution_result().clone().reverted);
                    info!("call trace:\n{}", printer.deref().borrow().get_trace());
                    info!("output: {:?}", hex::encode(state.get_execution_result().clone().output));

                    // debug!(
                    //     "new_state: {:?}",
                    //     state.get_execution_result().clone().new_state.state
                    // );

                    vm_state = state.get_execution_result().new_state.clone();
                    if config.value_capture {
                        info!("Observed values: {:?}", vm_state.state.observed_values);
                    }
                    info!("================================================");
                }
            }

            // dump coverage:
            cov_middleware.borrow_mut().record_instruction_coverage();
            // unsafe {
            //     EVAL_COVERAGE = false;
            //     CALL_UNTIL = u32::MAX;
            // }

            // fuzzer
            //     .fuzz_loop(&mut stages, &mut executor, state, &mut mgr)
            //     .expect("Fuzzing failed");
        }
    }
}
