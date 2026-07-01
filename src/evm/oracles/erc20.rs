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

            // Whole-campaign baseline (FlashloanData::initial_token_holdings): the
            // attacker's token balances before the sequence began. Only the NET gain
            // (post - initial) is real loot; liquidating the full balance would count
            // pre-existing/seeded holdings as phantom profit.
            let initial_holdings = ctx
                .fuzz_state
                .get_execution_result()
                .new_state
                .state
                .flashloan_data
                .initial_token_holdings
                .clone();

            for ((caller, token), new_balance) in self.erc20_producer.deref().borrow().balances.iter() {
                if *new_balance > EVMU256::ZERO {
                    // Engine-only liquidation: the deployed fork engine discovers the
                    // route on-chain (ERC-4626/Aave/Compound/Lido/Curve/Uniswap V2/V3),
                    // so no TokenContext / known_tokens gate is needed. Only the NET
                    // gain over the whole-campaign baseline is real loot.
                    let initial = initial_holdings
                        .get(caller)
                        .and_then(|m| m.get(token))
                        .copied()
                        .unwrap_or(EVMU256::ZERO);
                    let gained = (*new_balance).saturating_sub(initial);
                    if gained == EVMU256::ZERO {
                        continue;
                    }
                    let liq_amount = gained * liquidation_percent / EVMU256::from(10);
                    liquidations_earned.push((*caller, *token, liq_amount));
                }
            }

            let _path_idx = ctx.input.get_randomness()[0] as usize;

            {
                ctx.executor.deref().borrow_mut().host.evmstate = ctx.post_state.clone();
            }
            let mut failed = false;
            for (caller, token_addr, amount) in liquidations_earned {
                let backup = ctx.executor.deref().borrow_mut().host.evmstate.clone();
                // One loop: liquidate through the SAME deployed fork engine that
                // acquisition uses. It discovers the route on-chain (ERC-4626/Compound/
                // Aave/Lido/Curve/Uniswap V2/V3) and forwards realized ETH to the attacker
                // so earned/owed counts it. None = illiquid → revert this leg. No
                // in-process Uniswap-sim (System 1) fallback — both legs price through
                // the same on-chain source, so the round-trip is a closed loop.
                let via_engine = ctx
                    .executor
                    .deref()
                    .borrow_mut()
                    .liquidate_via_engine(caller, token_addr, amount, ctx.fuzz_state)
                    .is_some();
                if !via_engine {
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
