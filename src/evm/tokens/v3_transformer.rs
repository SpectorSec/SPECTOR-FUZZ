use std::{collections::HashMap, fmt::Debug, sync::Arc};

use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::{
    interpreter::{ExtBytecode, InputsImpl, SharedMemory},
    interpreter_types::ReturnData as ReturnDataTr,
    CallInput, Interpreter,
};
use revm_primitives::{hardfork::SpecId, Bytes as PrimBytes};
use serde::{de::DeserializeOwned, Serialize};

use super::{uniswap::CODE_REGISTRY, PairContext, UniswapInfo};
use crate::{
    evm::{
        tokens::v2_transformer::{balance_of_bytes, UniswapPairContext},
        types::{EVMAddress, EVMFuzzState, EVMU256},
        vm::{EVMExecutor, MEM_LIMIT},
    },
    generic_vm::vm_state::VMStateT,
    get_code_tokens,
    input::ConciseSerde,
    is_call_success,
};

#[derive(Debug)]
pub struct UniswapV3PairContext {
    pub fee: u32,
    pub inner: UniswapPairContext,
}

impl UniswapV3PairContext {
    pub fn initial_transfer<VS, CI, SC>(
        &self,
        src: &EVMAddress,
        next: &EVMAddress,
        amount: EVMU256,
        state: &mut EVMFuzzState,
        vm: &mut EVMExecutor<VS, CI, SC>,
    ) -> Option<()>
    where
        VS: VMStateT + Default + 'static,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        self.inner.initial_transfer(src, next, amount, state, vm)
    }
}

#[derive(Debug)]
pub struct Slot0 {
    pub price: EVMU256,
    pub fee: u8,
    pub unlocked: bool,
}

impl Slot0 {
    pub fn get_fee(&self) -> u32 {
        self.fee as u32
    }
}

pub fn slot0_parser(data: EVMU256) -> Slot0 {
    // struct Slot0 {
    //     // the current price
    //     uint160 sqrtPriceX96; 20
    //     // the current tick
    //     int24 tick; 3
    //     // the most-recently updated index of the observations array
    //     uint16 observationIndex; 2
    //     // the current maximum number of observations that are being stored
    //     uint16 observationCardinality; 2
    //     // the next maximum number of observations to store, triggered in
    // observations.write     uint16 observationCardinalityNext; 2
    //     // the current protocol fee as a percentage of the swap fee taken on
    // withdrawal     // represented as an integer denominator (1/x)%
    //     uint8 feeProtocol; 1
    //     // whether the pool is locked
    //     bool unlocked; 1
    // }
    let data: [u8; 32] = data.to_le_bytes();
    let price = EVMU256::from_le_slice(&data[0..20]);
    let fee = data[29];
    let unlocked = data[30] == 1;

    Slot0 { price, fee, unlocked }
}

pub fn approve_bytes(dst: &EVMAddress) -> Bytes {
    let mut ret = Vec::new();
    ret.extend_from_slice(&[0x09, 0x5e, 0xa7, 0xb3]); // approve
    ret.extend_from_slice(&[0x00; 12]); // padding
    ret.extend_from_slice(dst.as_slice()); // dst
    ret.extend_from_slice([0xff; 32].as_ref()); // amount
    Bytes::from(ret)
}

pub fn exact_in_single_swap(
    token_in: EVMAddress,
    token_out: EVMAddress,
    fee: u32,
    next_hop: EVMAddress,
    amount_in: EVMU256,
) -> Bytes {
    // struct ExactInputSingleParams {
    //         address tokenIn;
    //         address tokenOut;
    //         uint24 fee;
    //         address recipient;
    //         uint256 deadline;
    //         uint256 amountIn;
    //         uint256 amountOutMinimum;
    //         uint160 sqrtPriceLimitX96;
    //     }

    let mut ret = Vec::new();
    ret.extend_from_slice(&[0x41, 0x4b, 0xf3, 0x89]); // exactInputSingle
    ret.extend_from_slice(&[0x00; 12]); // padding
    ret.extend_from_slice(token_in.as_slice()); // tokenIn
    ret.extend_from_slice(&[0x00; 12]); // padding
    ret.extend_from_slice(token_out.as_slice()); // tokenOut
    ret.extend_from_slice(&[0x00; 28]); // padding
    ret.extend_from_slice(&fee.to_be_bytes()); // fee (4 bytes)
    ret.extend_from_slice(&[0x00; 12]); // padding
    ret.extend_from_slice(next_hop.as_slice()); // recipient
    ret.extend_from_slice(&[0xff; 32]); // deadline
    ret.extend_from_slice(&amount_in.to_be_bytes::<32>()); // amountIn
    ret.extend_from_slice(&[0x00; 32]); // amountOutMinimum
    ret.extend_from_slice(&[0x00; 32]); // sqrtPriceLimitX96
    Bytes::from(ret)
}

pub const V3_TOKEN_HOLDER: [u8; 20] = [0xa1; 20];
impl PairContext for UniswapV3PairContext {
    fn transform<VS, CI, SC>(
        &self,
        _src: &EVMAddress,
        next: &EVMAddress,
        _amount: EVMU256,
        state: &mut EVMFuzzState,
        vm: &mut EVMExecutor<VS, CI, SC>,
        reverse: bool,
    ) -> Option<(EVMAddress, EVMU256)>
    where
        VS: VMStateT + Default + 'static,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        let src = EVMAddress::from_slice(&V3_TOKEN_HOLDER);
        // assert_eq!(src, *_src);
        let (in_token_address, out_token_address, side) = if reverse {
            (self.inner.next_hop, self.inner.in_token_address, 1 - self.inner.side)
        } else {
            (self.inner.in_token_address, self.inner.next_hop, self.inner.side)
        };

        let in_token_code = get_code_tokens!(in_token_address, vm, state);
        let out_token_code = get_code_tokens!(out_token_address, vm, state);
        macro_rules! balanceof_token {
            ($dir: expr, $who: expr) => {{
                let addr = if $dir { in_token_address } else { out_token_address };
                let code = if $dir { in_token_code.clone() } else { out_token_code.clone() };
                let calldata = balance_of_bytes($who);
                let interp_input = InputsImpl {
                    target_address: addr,
                    bytecode_address: Some(addr),
                    caller_address: EVMAddress::default(),
                    input: CallInput::Bytes(PrimBytes::copy_from_slice(calldata.as_ref())),
                    call_value: EVMU256::ZERO,
                };
                let mut interp = Interpreter::new(
                    SharedMemory::new_with_memory_limit(MEM_LIMIT),
                    ExtBytecode::new((*code).clone()),
                    interp_input,
                    false,
                    SpecId::PRAGUE,
                    1e10 as u64,
                );
                let ir = vm.host.run_inspect(&mut interp, state);
                if !is_call_success!(ir) {
                    return None;
                }
                let in_balance =
                    if let Some(num) = EVMU256::try_from_be_slice(interp.return_data.buffer().as_ref()) {
                        num
                    } else {
                        return None;
                    };

                in_balance
            }};
        }
        macro_rules! approve_token {
            ($dir: expr, $who: expr, $dst: expr) => {{
                let addr = if $dir { in_token_address } else { out_token_address };
                let code = if $dir { in_token_code.clone() } else { out_token_code.clone() };
                let calldata = approve_bytes($dst);
                let interp_input = InputsImpl {
                    target_address: addr,
                    bytecode_address: Some(addr),
                    caller_address: $who,
                    input: CallInput::Bytes(PrimBytes::copy_from_slice(calldata.as_ref())),
                    call_value: EVMU256::ZERO,
                };
                let mut interp = Interpreter::new(
                    SharedMemory::new_with_memory_limit(MEM_LIMIT),
                    ExtBytecode::new((*code).clone()),
                    interp_input,
                    false,
                    SpecId::PRAGUE,
                    1e10 as u64,
                );
                let ir = vm.host.run_inspect(&mut interp, state);
                if !is_call_success!(ir) {
                    return None;
                }
            }};
        }

        // 0. ensure not locked, check unlock slot at 0xc
        if let Some(slots) = vm.host.evmstate.state.get(&self.inner.pair_address) {
            if let Some(slot) = slots.get(&EVMU256::from(0x0)) {
                let slot0 = slot0_parser(slot.clone());
                if !slot0.unlocked {
                    return None;
                }
            }
        }

        // 1. approve the router
        let router = self.inner.uniswap_info.router.expect("router not found");
        approve_token!(true, src, &router);
        let orig_balance = balanceof_token!(false, next);

        // 2. use router to do the swap
        // println!("looking for router code: {:?}", router);
        let router_code = get_code_tokens!(router, vm, state);
        let by = exact_in_single_swap(in_token_address, out_token_address, self.fee, *next, _amount);
        // println!("bytes: {:?}", hex::encode(by.clone()));

        let interp_input = InputsImpl {
            target_address: router,
            bytecode_address: Some(router),
            caller_address: src,
            input: CallInput::Bytes(PrimBytes::copy_from_slice(by.as_ref())),
            call_value: EVMU256::ZERO,
        };
        let mut interp = Interpreter::new(
            SharedMemory::new_with_memory_limit(MEM_LIMIT),
            ExtBytecode::new((*router_code).clone()),
            interp_input,
            false,
            SpecId::PRAGUE,
            1e10 as u64,
        );
        let ir = vm.host.run_inspect(&mut interp, state);
        if !is_call_success!(ir) {
            // println!("transfer failed2");
            // println!(
            //     "{:?}", hex::encode(
            //         get_code_tokens!(router, vm, state).bytecode()
            //     )
            // );
            // println!("return value: {:?} {:?} {:x} {:?} {:?} {:?}",
            //          interp.return_value(),
            //          ir,
            //          interp.program_counter(),
            //          interp.current_opcode(),
            //          hex::encode(interp.return_data_buffer),
            //          interp.contract.code_address
            // );
            return None;
        }

        // 3. now we have raped the pair, setup flashloan data and transfer out
        vm.host
            .evmstate
            .flashloan_data
            .oracle_recheck_balance
            .insert(in_token_address);
        vm.host
            .evmstate
            .flashloan_data
            .oracle_recheck_balance
            .insert(out_token_address);
        vm.host
            .evmstate
            .flashloan_data
            .oracle_recheck_reserve
            .insert(self.inner.pair_address);
        Some((*next, balanceof_token!(false, next) - orig_balance))
    }

    fn name(&self) -> String {
        "uniswap_v3".to_string()
    }
}

mod test {
    use std::str::FromStr;

    use crate::evm::types::{EVMAddress, EVMU256};

    #[test]
    fn test_slot0_parser() {
        let data = hex::decode("0001000001000100000d89e7fffd8963efd1fc6a506488495d951d5263988d25").unwrap();
        let slot0 = super::slot0_parser(EVMU256::from_be_slice(&data));
        assert_eq!(
            slot0.price,
            EVMU256::from_str("0xfffd8963efd1fc6a506488495d951d5263988d25").unwrap()
        );
        assert_eq!(slot0.fee, 0x00);
        assert_eq!(slot0.unlocked, true);
    }

    #[test]
    fn test_exact_in_single_swap() {
        let calldata = super::exact_in_single_swap(
            EVMAddress::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
            EVMAddress::from_str("0xfAbA6f8e4a5E8Ab82F62fe7C39859FA577269BE3").unwrap(),
            3000,
            EVMAddress::from_str("0xf5213a6a2f0890321712520b8048D9886c1A9900").unwrap(),
            EVMU256::from_str("3619200000000000000").unwrap(),
        );
        println!("calldata: {:?}", hex::encode(calldata.as_ref()));
    }
}
