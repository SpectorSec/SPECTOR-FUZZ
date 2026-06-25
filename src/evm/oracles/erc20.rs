use std::{cell::RefCell, collections::HashMap, ops::Deref, rc::Rc, str::FromStr};

use bytes::Bytes;
use revm_interpreter::bytecode::Bytecode;

use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput},
        onchain::flashloan::CAN_LIQUIDATE,
        oracle::EVMBugResult,
        oracles::{u512_div_float, ERC20_BUG_IDX},
        producers::erc20::ERC20Producer,
        tokens::TokenContext,
        types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMQueueExecutor, EVMU256, EVMU512},
        vm::EVMState,
    },
    generic_vm::{vm_executor::GenericVM, vm_state::VMStateT},
    oracle::Oracle,
    state::HasExecutionResult,
};

pub struct IERC20OracleFlashloan {
    pub balance_of: Vec<u8>,
    pub known_tokens: RefCell<HashMap<EVMAddress, TokenContext>>,
    pub known_pair_reserve_slot: HashMap<EVMAddress, EVMU256>,
    pub erc20_producer: Rc<RefCell<ERC20Producer>>,
}

impl IERC20OracleFlashloan {
    pub fn new(erc20_producer: Rc<RefCell<ERC20Producer>>) -> Self {
        Self {
            balance_of: hex::decode("70a08231").unwrap(),
            known_tokens: RefCell::new(HashMap::new()),
            known_pair_reserve_slot: HashMap::new(),
            erc20_producer,
        }
    }

    pub fn register_token(&mut self, token: EVMAddress, token_ctx: TokenContext, can_liquidate: bool) {
        // setting can_liquidate to true to turn on liquidation
        unsafe {
            CAN_LIQUIDATE |= can_liquidate;
        }
        self.known_tokens.borrow_mut().insert(token, token_ctx);
    }

    pub fn register_pair_reserve_slot(&mut self, pair: EVMAddress, slot: EVMU256) {
        self.known_pair_reserve_slot.insert(pair, slot);
    }
}

impl
    Oracle<
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
    > for IERC20OracleFlashloan
{
    fn transition(&self, _ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> u64 {
        0
    }

    fn oracle(&self, ctx: &mut EVMOracleCtx<'_>, _stage: u64) -> Vec<u64> {
        use crate::evm::input::EVMInputT;
        ctx.fuzz_state
            .get_execution_result_mut()
            .new_state
            .state
            .flashloan_data
            .oracle_recheck_balance
            .clear();
        ctx.fuzz_state
            .get_execution_result_mut()
            .new_state
            .state
            .flashloan_data
            .oracle_recheck_reserve
            .clear();
        let liquidation_percent = ctx.input.get_liquidation_percent();
        if liquidation_percent > 0 {
            // println!("Liquidation percent: {}", liquidation_percent);
            let liquidation_percent = EVMU256::from(liquidation_percent);
            let mut liquidations_earned = Vec::new();

            for ((caller, token), new_balance) in self.erc20_producer.deref().borrow().balances.iter() {
                if *new_balance > EVMU256::ZERO {
                    let mut has_token = self.known_tokens.borrow().contains_key(token);
                    if !has_token {
                        let flashloan_mid_opt = ctx.executor.deref().borrow().host.flashloan_middleware.clone();
                        if let Some(flashloan_mid) = flashloan_mid_opt {
                            let mut mid = flashloan_mid.borrow_mut();
                            if let Some(token_ctx) = mid.get_token_context(*token) {
                                let can_liquidate = !token_ctx.swaps.is_empty();
                                unsafe {
                                    CAN_LIQUIDATE |= can_liquidate;
                                }
                                self.known_tokens.borrow_mut().insert(*token, token_ctx);
                                has_token = true;
                            } else {
                                // Try to find a local pair that swaps *token
                                let mut found_pair = None;
                                let mut other_token = EVMAddress::default();
                                
                                for pair in mid.pair_address.iter() {
                                    let calls = vec![
                                        (*pair, Bytes::from(vec![0x0d, 0xfe, 0xa0, 0x05])), // token0()
                                        (*pair, Bytes::from(vec![0xd2, 0x12, 0x20, 0xa7])), // token1()
                                    ];
                                    
                                    let results = ctx.executor.borrow_mut().fast_static_call(
                                        &calls,
                                        &ctx.post_state,
                                        ctx.fuzz_state
                                    );
                                    
                                    if results.len() == 2 && results[0].len() >= 32 && results[1].len() >= 32 {
                                        let t0 = EVMAddress::from_slice(&results[0][12..32]);
                                        let t1 = EVMAddress::from_slice(&results[1][12..32]);
                                        
                                        if t0 == *token {
                                            found_pair = Some(*pair);
                                            other_token = t1;
                                            break;
                                        } else if t1 == *token {
                                            found_pair = Some(*pair);
                                            other_token = t0;
                                            break;
                                        }
                                    }
                                }
                                
                                if let Some(pair_addr) = found_pair {
                                    let weth_addr = mid.chain_cfg.as_ref()
                                        .map(|c| c.get_weth())
                                        .and_then(|w| EVMAddress::from_str(w.as_str()).ok())
                                        .unwrap_or_else(|| EVMAddress::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap());
                                        
                                    let has_route_out = other_token == weth_addr || self.known_tokens.borrow().contains_key(&other_token);
                                    
                                    if has_route_out {
                                        let side = if *token < other_token { 0 } else { 1 };
                                        
                                        let mut initial_reserves = (EVMU256::ZERO, EVMU256::ZERO);
                                        let reserves_call = vec![
                                            (pair_addr, Bytes::from(vec![0x09, 0x02, 0xf1, 0xac])), // getReserves()
                                        ];
                                        let reserves_res = ctx.executor.borrow_mut().fast_static_call(
                                            &reserves_call,
                                            &ctx.post_state,
                                            ctx.fuzz_state
                                        );
                                        if !reserves_res.is_empty() && reserves_res[0].len() >= 64 {
                                            let r0 = EVMU256::try_from_be_slice(&reserves_res[0][0..32]).unwrap_or_default();
                                            let r1 = EVMU256::try_from_be_slice(&reserves_res[0][32..64]).unwrap_or_default();
                                            initial_reserves = (r0, r1);
                                        }
                                        
                                        let pair_ctx = crate::evm::tokens::v2_transformer::UniswapPairContext {
                                            pair_address: pair_addr,
                                            in_token_address: *token,
                                            next_hop: other_token,
                                            side,
                                            uniswap_info: std::sync::Arc::new(crate::evm::tokens::UniswapInfo {
                                                pool_fee: 30,
                                                router: None,
                                            }),
                                            initial_reserves,
                                        };
                                        
                                        let route_step = crate::evm::tokens::PairContextTy::Uniswap(Rc::new(RefCell::new(pair_ctx)));
                                        let mut route = vec![route_step];
                                        
                                        if other_token != weth_addr {
                                            if let Some(out_ctx) = self.known_tokens.borrow().get(&other_token).cloned() {
                                                if !out_ctx.swaps.is_empty() {
                                                    route.extend(out_ctx.swaps[0].route.clone());
                                                }
                                            }
                                        }
                                        
                                        let path_ctx = crate::evm::tokens::PathContext { route };
                                        
                                        let mut known = self.known_tokens.borrow_mut();
                                        let token_ctx = known.entry(*token).or_insert_with(|| TokenContext {
                                            swaps: vec![],
                                            is_weth: *token == weth_addr,
                                            weth_address: weth_addr,
                                        });
                                        
                                        if !token_ctx.swaps.iter().any(|p| p.route.iter().any(|r| {
                                            match r {
                                                crate::evm::tokens::PairContextTy::Uniswap(c) => c.borrow().pair_address == pair_addr,
                                                _ => false,
                                            }
                                        })) {
                                            token_ctx.swaps.push(path_ctx);
                                            unsafe {
                                                CAN_LIQUIDATE = true;
                                            }
                                            println!("[DynamicRouter] Registered dynamic local route for {:?} -> {:?} via pair {:?}", token, other_token, pair_addr);
                                        }
                                        has_token = true;
                                    }
                                }
                            }
                        }
                    }
                    if has_token {
                        let known_tokens = self.known_tokens.borrow();
                        let token_info = known_tokens.get(token).unwrap();
                        let liq_amount = *new_balance * liquidation_percent / EVMU256::from(10);
                        liquidations_earned.push((*caller, token_info.clone(), liq_amount));
                    }
                }
            }

            let _path_idx = ctx.input.get_randomness()[0] as usize;

            {
                ctx.executor.deref().borrow_mut().host.evmstate = ctx.post_state.clone();
            }
            let mut failed = false;
            for (caller, _token_info, _amount) in liquidations_earned {
                let backup = ctx.executor.deref().borrow_mut().host.evmstate.clone();
                if _token_info
                    .sell(
                        _amount,
                        caller,
                        ctx.fuzz_state,
                        &mut *ctx.executor.deref().borrow_mut(),
                        ctx.input.get_randomness().as_slice(),
                    )
                    .is_none()
                {
                    ctx.executor.deref().borrow_mut().host.evmstate = backup;
                    continue;
                }
            }
            if !failed {
                ctx.fuzz_state.get_execution_result_mut().new_state.state =
                    ctx.executor.deref().borrow_mut().host.evmstate.clone();
            }
        }

        let exec_res = ctx.fuzz_state.get_execution_result_mut();

        if exec_res.new_state.state.has_post_execution() {
            return vec![];
        }

        // println!(
        //     "balance: {:?} - {:?}",
        //     exec_res.new_state.state.flashloan_data.earned,
        // exec_res.new_state.state.flashloan_data.owed );

        if exec_res.new_state.state.flashloan_data.earned > exec_res.new_state.state.flashloan_data.owed &&
            exec_res.new_state.state.flashloan_data.earned - exec_res.new_state.state.flashloan_data.owed >
                EVMU512::from(10_000_000_000_000_000_000_000_u128)
        // > 0.01ETH
        {
            let net = exec_res.new_state.state.flashloan_data.earned - exec_res.new_state.state.flashloan_data.owed;
            // we scaled by 1e24, so divide by 1e24 to get ETH
            let net_eth = u512_div_float(net, EVMU512::from(1_000_000_000_000_000_000_000_u128), 3);

            EVMBugResult::new_simple(
                "Fund Loss".to_string(),
                ERC20_BUG_IDX,
                format!(
                    "Anyone can earn {} ETH by interacting with the provided contracts\n",
                    net_eth,
                ),
                ConciseEVMInput::from_input(ctx.input, ctx.fuzz_state.get_execution_result()),
            )
            .push_to_output();
            vec![ERC20_BUG_IDX]
        } else {
            vec![]
        }
    }
}
