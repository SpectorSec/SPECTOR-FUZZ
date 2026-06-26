// on_call
// when approval, balanceof, give 2000e18 token
// when transfer, transferFrom, and src is our, return success, add owed
// when transfer, transferFrom, and src is not our, return success, reduce owed
use std::{
    any,
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt::Debug,
    ops::Deref,
    rc::Rc,
    str::FromStr,
    time::Duration,
};

use bytes::Bytes;
use libafl::{
    corpus::{Corpus, Testcase},
    inputs::Input,
    prelude::{HasCorpus, State, UsesInput},
    schedulers::Scheduler,
    state::HasMetadata,
};
use revm_interpreter::{interpreter_types::{InputsTr, Jumps}, Interpreter};
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::ChainConfig;
use crate::{
    evm::{
        contract_utils::ABIConfig,
        corpus_initializer::EnvMetadata,
        host::FuzzHost,
        input::{ConciseEVMInput, EVMInput, EVMInputT, EVMInputTy},
        middlewares::middleware::{Middleware, MiddlewareType},
        mutator::AccessPattern,
        oracles::erc20::IERC20OracleFlashloan,
        tokens::{uniswap::fetch_uniswap_path, TokenContext},
        types::{convert_u256_to_h160, EVMAddress, EVMFuzzState, EVMU256, EVMU512},
    },
    generic_vm::vm_state::VMStateT,
    input::VMInputT,
    state::{HasCaller, HasItyState},
};

pub static mut CAN_LIQUIDATE: bool = false;

#[macro_export]
macro_rules! scale {
    () => {
        EVMU512::from(1_000_000)
    };
}
pub struct Flashloan {
    pub use_contract_value: bool,
    pub known_addresses: HashSet<EVMAddress>,
    pub chain_cfg: Option<Box<dyn ChainConfig>>,
    pub erc20_address: HashSet<EVMAddress>,
    pub pair_address: HashSet<EVMAddress>,
    pub unbound_tracker: HashMap<usize, HashSet<EVMAddress>>, // pc -> [address called]
    pub flashloan_oracle: Rc<RefCell<IERC20OracleFlashloan>>,
    pub token_context_cache: HashMap<EVMAddress, TokenContext>,
}

impl Debug for Flashloan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flashloan")
            .field("use_contract_value", &self.use_contract_value)
            .finish()
    }
}

pub fn register_borrow_txn<VS, I, S, SC>(mut scheduler: SC, state: &mut S, token: EVMAddress)
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    S: State
        + HasCorpus
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCaller<EVMAddress>
        + Clone
        + Debug
        + UsesInput<Input = I>
        + 'static,
    VS: VMStateT + Default,
    SC: Scheduler<State = S> + Clone,
{
    let mut tc = Testcase::new(
        {
            EVMInput {
                input_type: EVMInputTy::Borrow,
                caller: state.get_rand_caller(),
                contract: token,
                data: None,
                sstate: Default::default(),
                sstate_idx: 0,
                txn_value: Some(EVMU256::from_str("10000000000000000000").unwrap()),
                step: false,
                env: state.metadata_map().get::<EnvMetadata>().unwrap().env.clone(),
                access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                liquidation_percent: 0,
                direct_data: Default::default(),
                randomness: vec![0],
                repeat: 1,
                swap_data: HashMap::new(),
                nested_actions: Vec::new(),
            campaign: None,
            }
        }
        .as_any()
        .downcast_ref::<I>()
        .unwrap()
        .clone(),
    ) as Testcase<I>;
    tc.set_exec_time(Duration::from_secs(0));
    let idx = state.corpus_mut().add(tc).expect("failed to add");
    scheduler.on_add(state, idx).expect("failed to call scheduler on_add");
}

impl Flashloan {
    pub fn new(
        use_contract_value: bool,
        chain_cfg: Option<Box<dyn ChainConfig>>,
        flashloan_oracle: Rc<RefCell<IERC20OracleFlashloan>>,
    ) -> Self {
        Self {
            use_contract_value,
            known_addresses: Default::default(),
            chain_cfg,
            erc20_address: Default::default(),
            pair_address: Default::default(),
            unbound_tracker: Default::default(),
            token_context_cache: Default::default(),
            flashloan_oracle,
        }
    }

    pub fn get_token_context(&mut self, addr: EVMAddress) -> Option<TokenContext> {
        self.chain_cfg.as_mut().map(|config| fetch_uniswap_path(config, addr))
    }

    pub fn on_contract_insertion(
        &mut self,
        addr: &EVMAddress,
        impl_addr: &EVMAddress,
        abi: &[ABIConfig],
        _state: &mut EVMFuzzState,
    ) -> (bool, bool) {
        // should not happen, just sanity check
        if self.known_addresses.contains(impl_addr) {
            return (false, false);
        }
        self.known_addresses.insert(*impl_addr);

        // balanceOf(address) - 70a08231
        // allowance(address,address) - dd62ed3e
        // transfer(address,uint256) - a9059cbb
        // approve(address,uint256) - 095ea7b3
        // transferFrom(address,address,uint256) - 23b872dd
        let abi_signatures_token = vec![
            [0x70, 0xa0, 0x82, 0x31],
            [0xdd, 0x62, 0xed, 0x3e],
            [0xa9, 0x05, 0x9c, 0xbb],
            [0x09, 0x5e, 0xa7, 0xb3],
            [0x23, 0xb8, 0x72, 0xdd],
        ];

        let abi_signatures_pair = vec![
            [0x02, 0x2c, 0x0d, 0x9f],
            [0xff, 0xf6, 0xca, 0xe9],
            [0xbc, 0x25, 0xcf, 0x77],
        ];
        let abi_names = abi.iter().map(|x| x.function.clone()).collect::<HashSet<[u8; 4]>>();

        let mut is_erc20 = false;
        let mut is_pair = false;
        // check abi_signatures_token is subset of abi.name
        {
            if abi_signatures_token.iter().all(|x| abi_names.contains(x)) {
                let token_ctx = self.get_token_context(*addr).unwrap_or_else(|| {
                    let weth_addr = self.chain_cfg.as_ref()
                        .map(|c| c.get_weth())
                        .and_then(|w| EVMAddress::from_str(&w).ok())
                        .unwrap_or_else(|| EVMAddress::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap());
                    TokenContext {
                        swaps: vec![],
                        is_weth: *addr == weth_addr,
                        weth_address: weth_addr,
                    }
                });

                let oracle = self.flashloan_oracle.deref().try_borrow_mut();
                if oracle.is_ok() {
                    let can_liquidate = !token_ctx.swaps.is_empty();
                    oracle.unwrap().register_token(*addr, token_ctx, can_liquidate);
                    self.erc20_address.insert(*addr);
                    is_erc20 = true;
                } else {
                    println!("Unable to liquidate token {:?}", addr);
                }
            }
        }

        // if the contract is pair
        if abi_signatures_pair.iter().all(|x| abi_names.contains(x)) {
            self.pair_address.insert(*addr);
            debug!("pair detected @ address {:?}", addr);
            is_pair = true;
        }

        (is_erc20, is_pair)
    }

    pub fn register_local_pair_route<SC>(
        &self,
        token_in: EVMAddress,
        token_out: EVMAddress,
        pair: EVMAddress,
        reserve_slot: EVMU256,
        host: &FuzzHost<SC>,
    ) where
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        let weth_addr = self.chain_cfg.as_ref()
            .map(|c| c.get_weth())
            .and_then(|w| EVMAddress::from_str(&w).ok())
            .unwrap_or_else(|| EVMAddress::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap());
            
        let has_route_out = token_out == weth_addr || self.flashloan_oracle.borrow().known_tokens.borrow().contains_key(&token_out);
        
        if has_route_out {
            let side = if token_in < token_out { 0 } else { 1 };
            
            let mut initial_reserves = (EVMU256::ZERO, EVMU256::ZERO);
            if let Some(storage) = host.evmstate.get(&pair) {
                if let Some(val) = storage.get(&reserve_slot) {
                    initial_reserves = crate::evm::tokens::v2_transformer::reserve_parser(val);
                }
            }
            
            let pair_ctx = crate::evm::tokens::v2_transformer::UniswapPairContext {
                pair_address: pair,
                in_token_address: token_in,
                next_hop: token_out,
                side,
                uniswap_info: std::sync::Arc::new(crate::evm::tokens::UniswapInfo {
                    pool_fee: 30,
                    router: None,
                }),
                initial_reserves,
            };
            
            let route_step = crate::evm::tokens::PairContextTy::Uniswap(Rc::new(RefCell::new(pair_ctx)));
            let mut route = vec![route_step];
            
            if token_out != weth_addr {
                if let Some(out_ctx) = self.flashloan_oracle.borrow().known_tokens.borrow().get(&token_out).cloned() {
                    if !out_ctx.swaps.is_empty() {
                        route.extend(out_ctx.swaps[0].route.clone());
                    }
                }
            }
            
            let path_ctx = crate::evm::tokens::PathContext { route };
            
            let mut oracle = self.flashloan_oracle.borrow_mut();
            let mut known = oracle.known_tokens.borrow_mut();
            let token_ctx = known.entry(token_in).or_insert_with(|| TokenContext {
                swaps: vec![],
                is_weth: token_in == weth_addr,
                weth_address: weth_addr,
            });
            
            if !token_ctx.swaps.iter().any(|p| p.route.iter().any(|r| {
                match r {
                    crate::evm::tokens::PairContextTy::Uniswap(c) => c.borrow().pair_address == pair,
                    _ => false,
                }
            })) {
                token_ctx.swaps.push(path_ctx);
                unsafe {
                    CAN_LIQUIDATE = true;
                }
                println!("[FlashloanMiddleware] Registered dynamic local route for {:?} -> {:?} via pair {:?}", token_in, token_out, pair);
            }
        }
    }

    pub fn on_pair_insertion<SC>(&mut self, host: &FuzzHost<SC>, state: &mut EVMFuzzState, pair: EVMAddress)
    where
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        let slots = host.find_static_call_read_slot(
            pair,
            Bytes::from(vec![0x09, 0x02, 0xf1, 0xac]), // getReserves
            state,
        );
        let mut reserve_slot = EVMU256::from(8); // standard Uniswap V2 reserve slot
        if slots.len() == 3 {
            reserve_slot = slots[0];
            self.flashloan_oracle
                .deref()
                .borrow_mut()
                .register_pair_reserve_slot(pair, reserve_slot);
        } else {
            self.flashloan_oracle
                .deref()
                .borrow_mut()
                .register_pair_reserve_slot(pair, reserve_slot);
        }

        // Scan pair storage slots (e.g. 5, 6, 7) to discover token0 and token1
        let mut candidates = Vec::new();
        if let Some(storage) = host.evmstate.get(&pair) {
            for slot_num in 5..=8 {
                if let Some(val) = storage.get(&EVMU256::from(slot_num)) {
                    let val_bytes = val.to_be_bytes::<32>();
                    if val_bytes[0..12].iter().all(|&b| b == 0) {
                        let addr = EVMAddress::from_slice(&val_bytes[12..32]);
                        if !addr.is_zero() && addr != pair {
                            candidates.push(addr);
                        }
                    }
                }
            }
        }

        candidates.sort();
        candidates.dedup();
        
        let weth_addr = self.chain_cfg.as_ref()
            .map(|c| c.get_weth())
            .and_then(|w| EVMAddress::from_str(&w).ok())
            .unwrap_or_else(|| EVMAddress::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap());

        let token_candidates: Vec<_> = candidates.into_iter()
            .filter(|addr| self.erc20_address.contains(addr) || *addr == weth_addr)
            .collect();

        if token_candidates.len() >= 2 {
            let t0 = token_candidates[0];
            let t1 = token_candidates[1];
            
            self.register_local_pair_route(t0, t1, pair, reserve_slot, host);
            self.register_local_pair_route(t1, t0, pair, reserve_slot, host);
        }
    }
}

impl Flashloan {
    pub fn analyze_call(&self, input: &EVMInput, flashloan_data: &mut FlashloanData) {
        // if the txn is a transfer op, record it
        if input.get_txn_value().is_some() {
            flashloan_data.owed += EVMU512::from(input.get_txn_value().unwrap()) * scale!();
        }
        let addr = input.get_contract();
        // dont care if the call target is not erc20
        if self.erc20_address.contains(&addr) {
            // if the target is erc20 contract, then check the balance of the caller in the
            // oracle
            flashloan_data.oracle_recheck_balance.insert(addr);
        }

        if self.pair_address.contains(&addr) {
            // if the target is pair contract, then check the balance of the caller in the
            // oracle
            flashloan_data.oracle_recheck_reserve.insert(addr);
        }
    }
}

impl<SC> Middleware<SC> for Flashloan
where
    SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, s: &mut EVMFuzzState) {
        // if simply static call, we dont care
        // if unsafe { IS_FAST_CALL_STATIC } {
        //     return;
        // }

        let opcode = interp.bytecode.opcode();
        match opcode {
            // detect whether it mutates token balance
            0xf1 | 0xfa => {}
            0x55 | 0x5d => {
                if self.pair_address.contains(&interp.input.target_address) {
                    let key = interp.stack.peek(0).unwrap();
                    if key == EVMU256::from(8) {
                        host.evmstate
                            .flashloan_data
                            .oracle_recheck_reserve
                            .insert(interp.input.target_address);
                    }
                }
                return;
            }
            _ => {
                return;
            }
        };

        let value_transfer = match opcode {
            0xf1 | 0xf2 => interp.stack.peek(2).unwrap(),
            _ => EVMU256::ZERO,
        };

        // todo: fix for delegatecall
        let call_target: EVMAddress = convert_u256_to_h160(interp.stack.peek(1).unwrap());

        if value_transfer > EVMU256::ZERO && s.has_caller(&call_target) {
            host.evmstate.flashloan_data.earned += EVMU512::from(value_transfer) * scale!();
        }

        let call_target: EVMAddress = convert_u256_to_h160(interp.stack.peek(1).unwrap());
        if self.erc20_address.contains(&call_target) {
            host.evmstate.flashloan_data.oracle_recheck_balance.insert(call_target);
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::Flashloan
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn any::Any {
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FlashloanData {
    pub oracle_recheck_reserve: HashSet<EVMAddress>,
    pub oracle_recheck_balance: HashSet<EVMAddress>,
    pub owed: EVMU512,
    pub earned: EVMU512,
    pub prev_reserves: HashMap<EVMAddress, (EVMU256, EVMU256)>,
    pub unliquidated_tokens: HashMap<EVMAddress, EVMU256>,
    pub extra_info: String,
}

impl FlashloanData {
    pub fn new() -> Self {
        Self {
            oracle_recheck_reserve: HashSet::new(),
            oracle_recheck_balance: HashSet::new(),
            owed: Default::default(),
            earned: Default::default(),
            prev_reserves: Default::default(),
            unliquidated_tokens: Default::default(),
            extra_info: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::host::FuzzHost;
    use crate::evm::oracles::erc20::IERC20OracleFlashloan;
    use crate::evm::producers::erc20::ERC20Producer;
    use crate::evm::types::{EVMAddress, EVMFuzzState, EVMU256};
    use crate::state::FuzzState;
    use std::{cell::RefCell, collections::HashMap, rc::Rc, str::FromStr};
    use libafl::schedulers::StdScheduler;

    #[test]
    fn test_dynamic_pair_route_discovery() {
        let mut state: EVMFuzzState = FuzzState::new(0);
        
        let token_a = EVMAddress::from_str("0x000000000000000000000000000000000000000a").unwrap();
        let _token_b = EVMAddress::from_str("0x000000000000000000000000000000000000000b").unwrap();
        let pair = EVMAddress::from_str("0x00000000000000000000000000000000000000ff").unwrap();
        let weth = EVMAddress::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

        let erc20_producer = Rc::new(RefCell::new(ERC20Producer::new()));
        let flashloan_oracle = Rc::new(RefCell::new(IERC20OracleFlashloan::new(erc20_producer)));
        
        let mut flashloan = Flashloan::new(
            true,
            None,
            flashloan_oracle.clone(),
        );

        // Register token_a and weth as known tokens
        flashloan.erc20_address.insert(token_a);
        flashloan.erc20_address.insert(weth);

        // Setup host and state
        let mut host = FuzzHost::new(StdScheduler::new(), "work_dir".to_string());
        
        // Manually write storage for pair into host
        // Slot 6: token_a, Slot 7: weth (representing pair(Token A, WETH))
        let mut storage = HashMap::new();
        storage.insert(EVMU256::from(6), EVMU256::from_be_slice(token_a.as_slice()));
        storage.insert(EVMU256::from(7), EVMU256::from_be_slice(weth.as_slice()));
        
        // Reserves slot 8 (standard Uniswap V2 reserve slot)
        let mut reserve_bytes = [0u8; 32];
        let r0_bytes = EVMU256::from(1000).to_be_bytes::<32>();
        reserve_bytes[18..32].copy_from_slice(&r0_bytes[18..32]);
        let r1_bytes = EVMU256::from(2000).to_be_bytes::<32>();
        reserve_bytes[4..18].copy_from_slice(&r1_bytes[18..32]);
        
        storage.insert(EVMU256::from(8), EVMU256::from_be_bytes(reserve_bytes));

        host.evmstate.state.insert(pair, storage);

        // Call on_pair_insertion
        flashloan.on_pair_insertion(&host, &mut state, pair);

        // Verify that route for token_a -> weth is registered inside known_tokens
        let binding = flashloan_oracle.borrow();
        let known = binding.known_tokens.borrow();
        assert!(known.contains_key(&token_a), "Token A should be registered in known_tokens");
        let token_ctx = known.get(&token_a).unwrap();
        assert!(!token_ctx.swaps.is_empty(), "Token A swaps route should not be empty");
        
        let path = &token_ctx.swaps[0];
        assert_eq!(path.route.len(), 1, "Route should have exactly 1 step");
        match &path.route[0] {
            crate::evm::tokens::PairContextTy::Uniswap(p_ctx) => {
                let borrowed = p_ctx.borrow();
                assert_eq!(borrowed.pair_address, pair);
                assert_eq!(borrowed.in_token_address, token_a);
                assert_eq!(borrowed.next_hop, weth);
            }
            _ => panic!("Expected Uniswap pair context"),
        }
    }
}

