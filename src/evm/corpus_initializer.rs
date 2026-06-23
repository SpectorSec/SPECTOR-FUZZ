use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fs::File,
    io::{Read, Write},
    ops::Deref,
    path::Path,
    rc::Rc,
    time::Duration,
};

use bytes::Bytes;
use revm_primitives::Bytes as PrimBytes;
use hex;
use itertools::Itertools;
use libafl::{
    corpus::{Corpus, Testcase},
    prelude::HasMetadata,
    schedulers::Scheduler,
    state::HasCorpus,
};
use libafl_bolts::impl_serdeany;
use revm_interpreter::bytecode::Bytecode;
use crate::evm::types::Env;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use super::{scheduler::ABIScheduler, srcmap::SOURCE_MAP_PROVIDER};
/// Utilities to initialize the corpus
/// Add all potential calls with default args to the corpus
use crate::evm::abi::{get_abi_type_boxed, BoxedABI};
#[cfg(feature = "print_txn_corpus")]
use crate::fuzzer::DUMP_FILE_COUNT;
use crate::{
    dump_txn,
    evm::{
        blaz::builder::BuildJobResult,
        bytecode_analyzer,
        contract_utils::{extract_sig_from_contract, to_hex_string, ABIConfig, ContractLoader},
        input::{ConciseEVMInput, EVMInput, EVMInputTy},
        // middlewares::cheatcode::CHEATCODE_ADDRESS,
        mutator::AccessPattern,
        onchain::{abi_decompiler::fetch_abi_evmole, flashloan::register_borrow_txn, BLACKLIST_ADDR},
        presets::Preset,
        types::{
            fixed_address,
            EVMAddress,
            EVMExecutionResult,
            EVMFuzzState,
            EVMInfantStateState,
            EVMStagedVMState,
            EVMU256,
        },
        vm::{EVMExecutor, EVMState},
    },
    fuzzer::REPLAY,
    generic_vm::vm_executor::GenericVM,
    input::ConciseSerde,
    r#const::UNKNOWN_SIGS_DIVISOR,
    state::HasCaller,
    state_input::StagedVMState,
};

pub const INITIAL_BALANCE: u128 = 100_000_000_000_000_000_000; // 100 ether

pub struct EVMCorpusInitializer<'a, SC, ISC>
where
    SC: ABIScheduler<State = EVMFuzzState> + Clone,
    ISC: Scheduler<State = EVMInfantStateState>,
{
    executor: &'a mut EVMExecutor<EVMState, ConciseEVMInput, SC>,
    scheduler: SC,
    infant_scheduler: ISC,
    state: &'a mut EVMFuzzState,
    #[cfg(feature = "use_presets")]
    presets: Vec<&'a dyn Preset<EVMInput, EVMState, SC>>,
    work_dir: String,
}

#[derive(Default)]
pub struct EVMInitializationArtifacts {
    pub address_to_bytecode: HashMap<EVMAddress, Bytecode>,
    pub address_to_abi: HashMap<EVMAddress, Vec<ABIConfig>>,
    pub address_to_abi_object: HashMap<EVMAddress, Vec<BoxedABI>>,
    pub address_to_name: HashMap<EVMAddress, String>,
    pub initial_state: EVMStagedVMState,
    pub initial_env: Env,
    pub build_artifacts: HashMap<EVMAddress, BuildJobResult>,
    /// ERC-4626 vaults detected from ABI fingerprinting (convertToAssets selector).
    pub erc4626_vaults: Vec<EVMAddress>,
    /// Contracts with EIP-712 domain separator detected from ABI.
    pub eip712_contracts: Vec<EVMAddress>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct EnvMetadata {
    pub env: Env,
}

impl_serdeany!(EnvMetadata);

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ABIMap {
    pub signature_to_abi: HashMap<[u8; 4], ABIConfig>,
}

impl_serdeany!(ABIMap);

impl ABIMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, abi: ABIConfig) {
        self.signature_to_abi.insert(abi.function, abi);
    }

    pub fn get(&self, signature: &[u8; 4]) -> Option<&ABIConfig> {
        self.signature_to_abi.get(signature)
    }
}

#[macro_export]
macro_rules! handle_contract_insertion {
    ($state: expr, $host: expr, $deployed_address: expr, $impl_address: expr, $abi: expr) => {
        let (is_erc20, is_pair) = match $host.flashloan_middleware {
            Some(ref middleware) => {
                let mut mid = middleware.deref().borrow_mut();
                mid.on_contract_insertion(&$deployed_address, &$impl_address, &$abi, $state)
            }
            None => (false, false),
        };
        if is_erc20 {
            // scheduler should be mutable but host cannot be borrowed as mutable
            let scheduler = $host.scheduler.clone();
            register_borrow_txn(scheduler, $state, $deployed_address);
        }
        if is_pair {
            let mut mid = $host.flashloan_middleware.as_ref().unwrap().deref().borrow_mut();
            mid.on_pair_insertion(&$host, $state, $deployed_address);
        }
    };
}

macro_rules! wrap_input {
    ($input: expr) => {{
        let mut tc = Testcase::new($input);
        tc.set_exec_time(Duration::from_secs(0));
        tc
    }};
}

macro_rules! add_input_to_corpus {
    ($state: expr, $scheduler: expr, $input: expr) => {
        let idx = $state.add_tx_to_corpus(wrap_input!($input)).expect("failed to add");
        $scheduler.on_add($state, idx).expect("failed to call scheduler on_add");
    };
    ($state:expr, $scheduler:expr, $input:expr, $artifacts:expr) => {
        let idx = $state.add_tx_to_corpus(wrap_input!($input)).expect("failed to add");
        $scheduler
            .on_add_artifacts($state, idx, $artifacts)
            .expect("failed to call scheduler on_add_artifact");
    };
}

impl<'a, SC, ISC> EVMCorpusInitializer<'a, SC, ISC>
where
    SC: ABIScheduler<State = EVMFuzzState> + Clone + 'static,
    ISC: Scheduler<State = EVMInfantStateState>,
{
    pub fn new(
        executor: &'a mut EVMExecutor<EVMState, ConciseEVMInput, SC>,
        scheduler: SC,
        infant_scheduler: ISC,
        state: &'a mut EVMFuzzState,
        work_dir: String,
    ) -> Self {
        Self {
            executor,
            scheduler,
            infant_scheduler,
            state,
            #[cfg(feature = "use_presets")]
            presets: vec![],
            work_dir,
        }
    }

    #[cfg(feature = "use_presets")]
    pub fn register_preset(&mut self, preset: &'a dyn Preset<EVMInput, EVMState, SC>) {
        self.presets.push(preset);
    }

    pub fn initialize(&mut self, loader: &mut ContractLoader) -> EVMInitializationArtifacts {
        self.state.metadata_map_mut().insert(ABIMap::new());
        self.setup_default_callers(loader);
        self.setup_contract_callers(loader);
        self.init_cheatcode_contract();
        self.initialize_contract(loader);
        self.initialize_source_map(loader);
        self.initialize_corpus(loader)
    }

    pub fn initialize_contract(&mut self, loader: &mut ContractLoader) {
        self.executor
            .host
            .evmstate
            .set_balance(self.executor.deployer, EVMU256::from(INITIAL_BALANCE));

        // deploy
        for contract in &mut loader.contracts {
            info!("Deploying contract: {}", contract.name);
            let deployed_address = if !contract.is_code_deployed {
                match self.executor.deploy(
                    Bytecode::new_raw(PrimBytes::from(contract.code.clone())),
                    Some(Bytes::from(contract.constructor_args.clone())),
                    contract.deployed_address,
                    self.state,
                ) {
                    Some(addr) => addr,
                    None => {
                        error!("Failed to deploy contract: {}", contract.name);
                        // we could also panic here
                        continue;
                    }
                }
            } else {
                debug!("Contract {} is already deployed", contract.name);
                // directly set bytecode
                let contract_code = Bytecode::new_raw(PrimBytes::from(contract.code.clone()));
                bytecode_analyzer::add_analysis_result_to_state(&contract_code, self.state);
                self.executor
                    .host
                    .set_code(contract.deployed_address, contract_code, self.state);
                contract.deployed_address
            };
            contract.deployed_address = deployed_address;

            // set all contracts real balance
            self.executor
                .host
                .evmstate
                .set_balance(deployed_address, contract.balance);

            info!(
                "Contract {} deployed to: {deployed_address:?} -> balacne is {:?}",
                contract.name, contract.balance
            );

            // TODO: enable cheatcode when https://github.com/matter-labs/zksync-era/issues/4581 is resolved
            // if deployed_address != CHEATCODE_ADDRESS {
            //     self.state.add_address(&deployed_address);
            // }
            self.state.add_address(&deployed_address);
        }
        info!("Deployed all contracts\n");
    }

    fn initialize_source_map(&self, loader: &ContractLoader) {
        for contract in &loader.contracts {
            if SOURCE_MAP_PROVIDER
                .lock()
                .unwrap()
                .has_source_map(&contract.deployed_address)
            {
                continue;
            }

            if let Some(build_job_result) = &contract.build_artifact {
                build_job_result.save_source_map(&contract.deployed_address);

                // let runtime_bytecode = self
                //     .executor
                //     .host
                //     .code
                //     .get(&contract.deployed_address)
                //     .expect("get runtime bytecode failed")
                //     .bytecode().to_vec();
                //
                // let build_job_bytecode = build_job_result.bytecodes.clone().to_vec();
                // println!("contract.name is: {:?}", contract.name);
                // println!("runtime_bytecode_str {:?}",
                // to_hex_string(runtime_bytecode.as_slice()));
                // println!("build_job_bytecode_str {:?}",
                // to_hex_string(build_job_bytecode.as_slice()));
                // assert_eq!(runtime_bytecode, build_job_bytecode, "Bytecode mismatch");
                continue;
            }

            if let Some(srcmap) = &contract.raw_source_map {
                let runtime_bytecode = self
                    .executor
                    .host
                    .code
                    .get(&contract.deployed_address)
                    .expect("get runtime bytecode failed")
                    .bytecode()
                    .to_vec();

                SOURCE_MAP_PROVIDER.lock().unwrap().decode_instructions_for_address(
                    &contract.deployed_address,
                    runtime_bytecode,
                    srcmap.clone(),
                    &contract.files,
                    contract.source_map_replacements.as_ref(),
                );
            }
        }
    }

    pub fn initialize_corpus(&mut self, loader: &mut ContractLoader) -> EVMInitializationArtifacts {
        let mut artifacts = EVMInitializationArtifacts {
            address_to_bytecode: HashMap::new(),
            address_to_abi: HashMap::new(),
            address_to_abi_object: Default::default(),
            address_to_name: Default::default(),
            initial_state: StagedVMState::new_with_state(match loader.setup_data {
                Some(ref setup_data) => setup_data.evmstate.clone(),
                None => self.executor.host.evmstate.clone(),
            }),
            build_artifacts: Default::default(),
            initial_env: match loader.setup_data {
                Some(ref setup_data) => setup_data.env.clone(),
                None => Default::default(),
            },
            erc4626_vaults: Vec::new(),
            eip712_contracts: Vec::new(),
        };

        self.state.metadata_map_mut().insert(EnvMetadata {
            env: artifacts.initial_env.clone(),
        });

        for contract in &mut loader.contracts {
            if contract.abi.is_empty() {
                // this contract's abi is not available, we will use 3 layers to handle this
                // 1. Extract abi from bytecode, and see do we have any function sig available
                //    in state
                // 2. Use EVMole to extract abi
                // 3. Reconfirm on failures of EVMole
                info!("Contract {} has no abi", contract.name);
                let contract_code = hex::encode(&contract.code);
                let sigs = extract_sig_from_contract(&contract_code);
                let mut unknown_sigs: usize = 0;
                for sig in &sigs {
                    if let Some(abi) = self.state.metadata_map().get::<ABIMap>().unwrap().get(sig) {
                        contract.abi.push(abi.clone());
                    } else {
                        unknown_sigs += 1;
                    }
                }

                if unknown_sigs >= sigs.len() / UNKNOWN_SIGS_DIVISOR {
                    info!("Too many unknown function signature for {:?}, we are going to decompile this contract using EVMole", contract.name);
                    let abis = fetch_abi_evmole(&contract.code)
                        .iter()
                        .map(|abi| {
                            if let Some(known_abi) =
                                self.state.metadata_map().get::<ABIMap>().unwrap().get(&abi.function)
                            {
                                known_abi
                            } else {
                                abi
                            }
                        })
                        .cloned()
                        .collect_vec();
                    contract.abi = abis;
                }
            }

            artifacts
                .address_to_abi
                .insert(contract.deployed_address, contract.abi.clone());
            let mut code = vec![];
            if let Some(c) = self.executor.host.code.clone().get(&contract.deployed_address) {
                code.extend_from_slice(c.bytecode());
            }
            artifacts
                .address_to_bytecode
                .insert(contract.deployed_address, Bytecode::new_raw(PrimBytes::from(code)));

            let mut name = contract.name.clone().trim_end_matches('*').to_string();
            if name != format!("{:?}", contract.deployed_address) {
                name = format!("{}({:?})", name, contract.deployed_address.clone());
            }
            artifacts.address_to_name.insert(contract.deployed_address, name);

            if let Some(build_artifact) = &contract.build_artifact {
                artifacts
                    .build_artifacts
                    .insert(contract.deployed_address, build_artifact.clone());
            }

            {
                handle_contract_insertion!(
                    self.state,
                    self.executor.host,
                    contract.deployed_address,
                    contract.deployed_address,
                    contract.abi.clone()
                );
            }

            if unsafe {
                BLACKLIST_ADDR.is_some() && BLACKLIST_ADDR.as_ref().unwrap().contains(&contract.deployed_address)
            } {
                continue;
            }

            let mut target_sig = None; // none means all selectors are targeted

            if let Some(setup_data) = &loader.setup_data {
                // Check if this contract is included by Foundry targetContracts
                if !setup_data.target_contracts.is_empty() &&
                    !setup_data.target_contracts.contains(&contract.deployed_address)
                {
                    continue;
                }
                // Check if this contract is excluded by Foundry excludeContracts
                if !setup_data.excluded_contracts.is_empty() &&
                    setup_data.excluded_contracts.contains(&contract.deployed_address)
                {
                    continue;
                }

                // Check if this contract and sig is included by Foundry targetSelectors
                if !setup_data.target_selectors.is_empty() {
                    target_sig = Some(
                        setup_data
                            .target_selectors
                            .get(&contract.deployed_address)
                            .cloned()
                            .unwrap_or(
                                vec![], // empty vec means none of the selectors are targeted
                            ),
                    );
                }
            }

            for abi in contract.abi.clone() {
                let name = &abi.function_name;

                if name.starts_with("invariant_") || name.starts_with("echidna_") || name == "setUp" || name == "failed"
                {
                    debug!("Skipping function: {}", name);
                    continue;
                }

                if let Some(target_sig) = target_sig.clone() {
                    if !target_sig.contains(&Vec::from_iter(abi.function.iter().cloned())) {
                        debug!("Skipping function because of targetSelectors: {}", name);
                        continue;
                    }
                }

                self.add_abi(&abi, contract.deployed_address, &mut artifacts);
            }

            // ABI fingerprinting: auto-detect token standards and register
            // the appropriate oracles without any user configuration.
            let selectors: Vec<[u8; 4]> = contract.abi.iter().map(|a| a.function).collect();

            // ERC-4626: convertToAssets(uint256) = 0x07a2d13a
            if selectors.iter().any(|s| s == &[0x07, 0xa2, 0xd1, 0x3a]) {
                artifacts.erc4626_vaults.push(contract.deployed_address);
            }

            // EIP-712: DOMAIN_SEPARATOR() = 0x3644e515
            if selectors.iter().any(|s| s == &[0x36, 0x44, 0xe5, 0x15]) {
                artifacts.eip712_contracts.push(contract.deployed_address);
                // Inject zero-sig seeds for any function in this contract that
                // accepts (v, r, s) — identified by having >=3 params where
                // the ABI string contains "bytes32" twice and "uint8" once.
                for abi in &contract.abi {
                    let sig = &abi.abi;
                    let has_vrs = sig.matches("bytes32").count() >= 2 && sig.contains("uint8");
                    // skip permit — already handled by its own seed block
                    if abi.function == [0xd5, 0x05, 0xac, 0xcf] { continue; }
                    if !has_vrs { continue; }

                    let callers: Vec<EVMAddress> = self.state.callers_pool.clone();
                    for caller in &callers {
                        for v_byte in [0u8, 27u8, 28u8] {
                            // Build a 4 + N*32 calldata with selector + all-zero params
                            // except v which gets the boundary value.
                            // We don't know the exact ABI layout so we send a
                            // 7-slot payload (224 bytes) — covers most sig functions.
                            let mut calldata = vec![
                                abi.function[0], abi.function[1],
                                abi.function[2], abi.function[3],
                            ];
                            // 6 slots of zeros
                            calldata.extend_from_slice(&[0u8; 192]);
                            // Overwrite slot 4 last byte with v_byte (covers common v positions)
                            let v_pos = 4 + 3 * 32 + 31; // 4th slot, last byte
                            if v_pos < calldata.len() {
                                calldata[v_pos] = v_byte;
                            }

                            let eip712_seed = EVMInput {
                                caller: *caller,
                                contract: contract.deployed_address,
                                data: None,
                                sstate: StagedVMState::new_uninitialized(),
                                sstate_idx: 0,
                                txn_value: None,
                                step: false,
                                env: artifacts.initial_env.clone(),
                                access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                                liquidation_percent: 0,
                                input_type: EVMInputTy::ABI,
                                direct_data: Bytes::from(calldata),
                                randomness: vec![0],
                                repeat: 1,
                                swap_data: HashMap::new(),
                            };
                            add_input_to_corpus!(
                                self.state, &mut self.scheduler, eip712_seed, &artifacts
                            );
                        }
                    }
                }
            }
        }

        let mut tc = Testcase::new(artifacts.initial_state.clone());
        tc.set_exec_time(Duration::from_secs(0));
        let idx = self
            .state
            .infant_states_state
            .corpus_mut()
            .add(tc)
            .expect("failed to add");
        self.infant_scheduler
            .on_add(&mut self.state.infant_states_state, idx)
            .expect("failed to call infant scheduler on_add");
        artifacts
    }

    pub fn setup_default_callers(&mut self, loader: &mut ContractLoader) {
        // We override default callers when target senders are specified
        if let Some(setup_data) = &loader.setup_data {
            if !setup_data.target_senders.is_empty() {
                for caller in setup_data.target_senders.iter() {
                    self.state.add_caller(caller);
                    self.executor
                        .host
                        .evmstate
                        .set_balance(*caller, EVMU256::from(INITIAL_BALANCE));
                }
                return;
            }
        }

        let default_callers = HashSet::from([
            fixed_address("8EF508Aca04B32Ff3ba5003177cb18BfA6Cd79dd"),
            fixed_address("35c9dfd76bf02107ff4f7128Bd69716612d31dDb"),
            // fixed_address("5E6B78f0748ACd4Fb4868dF6eCcfE41398aE09cb"),
        ]);

        for caller in default_callers {
            self.state.add_caller(&caller);
            self.executor
                .host
                .evmstate
                .set_balance(caller, EVMU256::from(INITIAL_BALANCE));
        }
    }

    pub fn setup_contract_callers(&mut self, loader: &mut ContractLoader) {
        // We no longer need to setup contract callers when target senders are specified
        // The target senders are already setup in setup_default_callers. Existence
        // of the code in those addresses depends on setUp function of the contract.
        if let Some(setup_data) = &loader.setup_data {
            if !setup_data.target_senders.is_empty() {
                return;
            }
        }

        let contract_callers = HashSet::from([
            fixed_address("e1A425f1AC34A8a441566f93c82dD730639c8510"),
            fixed_address("68Dd4F5AC792eAaa5e36f4f4e0474E0625dc9024"),
            // fixed_address("aF97EE5eef1B02E12B650B8127D8E8a6cD722bD2"),
        ]);
        for caller in contract_callers {
            self.state.add_caller(&caller);
            self.executor
                .host
                .set_code(caller, Bytecode::new_raw(PrimBytes::from(vec![0xfd, 0x00])), self.state);
            self.executor
                .host
                .evmstate
                .set_balance(caller, EVMU256::from(INITIAL_BALANCE));
        }
    }

    pub fn init_cheatcode_contract(&mut self) {
        // TODO: enable cheatcode when https://github.com/matter-labs/zksync-era/issues/4581 is resolved
        // self.executor.host.set_code(
        //     CHEATCODE_ADDRESS,
        //     Bytecode::new_raw(PrimBytes::from(vec![0xfd, 0x00])),
        //     self.state,
        // );
    }

    fn add_abi(&mut self, abi: &ABIConfig, deployed_address: EVMAddress, artifacts: &mut EVMInitializationArtifacts) {
        if abi.is_constructor {
            return;
        }

        match self.state.hash_to_address.get_mut(abi.function.clone().as_slice()) {
            Some(addrs) => {
                addrs.insert(deployed_address);
            }
            None => {
                self.state
                    .hash_to_address
                    .insert(abi.function, HashSet::from([deployed_address]));
            }
        }
        #[cfg(not(feature = "fuzz_static"))]
        if abi.is_static {
            return;
        }
        let mut abi_instance = get_abi_type_boxed(&abi.abi);
        abi_instance.set_func_with_signature(abi.function, &abi.function_name, &abi.abi);

        artifacts
            .address_to_abi_object
            .entry(deployed_address)
            .or_default()
            .push(abi_instance.clone());
        let input = EVMInput {
            caller: self.state.get_rand_caller(),
            contract: deployed_address,
            data: if abi.function_name != "!receive!" {
                Some(abi_instance)
            } else {
                None
            },
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: if abi.is_payable { Some(EVMU256::ZERO) } else { None },
            step: false,
            env: artifacts.initial_env.clone(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            liquidation_percent: 0,
            input_type: EVMInputTy::ABI,
            direct_data: Default::default(),
            randomness: vec![0],
            repeat: 1,
            swap_data: HashMap::new(),
        };
        add_input_to_corpus!(self.state, &mut self.scheduler, input.clone(), artifacts);

        // permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        // Selector: 0xd505accf. Inject seeds with zero-signature + protocol-as-owner to fuzz
        // signature validation bypasses (e.g. permit() accepting v=0 or v=27, r=0, s=0).
        if abi.function == [0xd5, 0x05, 0xac, 0xcf] {
            let callers: Vec<EVMAddress> = self.state.callers_pool.clone();
            let protocol_addrs: Vec<EVMAddress> = artifacts.address_to_name.keys().cloned().collect();
            // For each (protocol_owner, attacker_spender) pair, add zero-sig and max-deadline seeds
            for owner in &protocol_addrs {
                for spender in &callers {
                    for v_byte in [0u8, 27u8, 28u8] {
                        let mut calldata = vec![0xd5u8, 0x05, 0xac, 0xcf];
                        // owner: left-padded to 32 bytes
                        calldata.extend_from_slice(&[0u8; 12]);
                        calldata.extend_from_slice(owner.as_slice());
                        // spender
                        calldata.extend_from_slice(&[0u8; 12]);
                        calldata.extend_from_slice(spender.as_slice());
                        // value: type(uint256).max
                        calldata.extend_from_slice(&[0xff; 32]);
                        // deadline: type(uint256).max
                        calldata.extend_from_slice(&[0xff; 32]);
                        // v
                        calldata.extend_from_slice(&[0u8; 31]);
                        calldata.push(v_byte);
                        // r: zero
                        calldata.extend_from_slice(&[0u8; 32]);
                        // s: zero
                        calldata.extend_from_slice(&[0u8; 32]);

                        let permit_seed = EVMInput {
                            caller: *spender,
                            contract: deployed_address,
                            data: None,
                            sstate: StagedVMState::new_uninitialized(),
                            sstate_idx: 0,
                            txn_value: None,
                            step: false,
                            env: artifacts.initial_env.clone(),
                            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                            liquidation_percent: 0,
                            input_type: EVMInputTy::ABI,
                            direct_data: Bytes::from(calldata),
                            randomness: vec![0],
                            repeat: 1,
                            swap_data: HashMap::new(),
                        };
                        add_input_to_corpus!(self.state, &mut self.scheduler, permit_seed, artifacts);
                    }
                }
            }
        }

        // Cross-chain receiver seeds: lzReceive / ccipReceive / xReceive.
        // Selectors: 0x001d3567, 0x85572ffb, 0x2901504d.
        // Inject seeds where msg.sender = each attacker address (not the trusted
        // bridge endpoint) to fuzz access-control bypass in the receiver.
        const CROSSCHAIN_SELECTORS: [[u8; 4]; 3] = [
            [0x00, 0x1d, 0x35, 0x67], // lzReceive(uint16,bytes,uint64,bytes)
            [0x85, 0x57, 0x2f, 0xfb], // ccipReceive((bytes32,uint64,bytes,bytes,...))
            [0x29, 0x01, 0x50, 0x4d], // xReceive(bytes32,uint256,address,bytes32,string,bytes)
        ];
        if CROSSCHAIN_SELECTORS.iter().any(|s| abi.function == *s) {
            let sel = abi.function;
            let callers: Vec<EVMAddress> = self.state.callers_pool.clone();
            // Representative (srcChainId, srcSender) combinations to probe:
            // chain IDs 0, 1, 0xffff (boundary), and a few arbitrary values.
            let chain_ids: &[u16] = &[0, 1, 0x65, 0x89, 0xffff]; // 0=invalid,1=mainnet,101=LZ ETH,137=polygon,65535=max
            for caller in &callers {
                for &chain_id in chain_ids {
                    // Build minimal valid-looking ABI for the receiver:
                    // lzReceive: (uint16 srcChainId, bytes srcAddress, uint64 nonce, bytes payload)
                    // All other receivers share a "bytes payload" field — we send a zero payload.
                    let mut calldata = vec![sel[0], sel[1], sel[2], sel[3]];
                    // srcChainId (uint16 → uint256 slot): chain_id left-padded
                    calldata.extend_from_slice(&[0u8; 30]);
                    calldata.extend_from_slice(&chain_id.to_be_bytes());
                    // srcAddress (bytes): offset=0x80, length=20, value=caller
                    // For simplicity use a fixed layout with caller address as src:
                    // offset to srcAddress bytes (4th slot = 0x80)
                    calldata.extend_from_slice(&[0u8; 31]);
                    calldata.push(0x80);
                    // nonce (uint64): 0
                    calldata.extend_from_slice(&[0u8; 32]);
                    // offset to payload bytes (6th slot = 0xc0)
                    calldata.extend_from_slice(&[0u8; 31]);
                    calldata.push(0xc0);
                    // srcAddress bytes: length=20, data=caller
                    calldata.extend_from_slice(&[0u8; 31]);
                    calldata.push(20u8);
                    calldata.extend_from_slice(&[0u8; 12]);
                    calldata.extend_from_slice(caller.as_slice());
                    // pad to 32 bytes
                    calldata.extend_from_slice(&[0u8; 12]);
                    // payload bytes: length=0
                    calldata.extend_from_slice(&[0u8; 32]);

                    let cc_seed = EVMInput {
                        caller: *caller,
                        contract: deployed_address,
                        data: None,
                        sstate: StagedVMState::new_uninitialized(),
                        sstate_idx: 0,
                        txn_value: None,
                        step: false,
                        env: artifacts.initial_env.clone(),
                        access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                        liquidation_percent: 0,
                        input_type: EVMInputTy::ABI,
                        direct_data: Bytes::from(calldata),
                        randomness: vec![0],
                        repeat: 1,
                        swap_data: HashMap::new(),
                    };
                    add_input_to_corpus!(self.state, &mut self.scheduler, cc_seed, artifacts);
                }
            }
        }

        #[cfg(feature = "print_txn_corpus")]
        {
            let corpus_dir = format!("{}/corpus", self.work_dir.as_str());
            dump_txn!(corpus_dir, &input)
        }
        #[cfg(feature = "use_presets")]
        {
            let presets = self.presets.clone();
            for p in presets {
                let presets = p.presets(abi.function, &input, self.executor);
                presets.iter().for_each(|preset| {
                    add_input_to_corpus!(self.state, &mut self.scheduler, preset.clone());
                });
            }
        }
    }
}
