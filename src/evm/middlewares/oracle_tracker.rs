use std::any::Any;
use std::fmt::Debug;

use std::collections::HashMap;
use std::collections::HashSet;

use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::{
    interpreter_types::{InputsTr, Jumps},
    Interpreter,
};

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    types::{as_u64, convert_u256_to_h160, EVMAddress, EVMFuzzState, EVMU256},
    vm::EVMState,
};

pub static mut ORACLE_GATED_TRANSFER_DETECTED: bool = false;

fn is_value_moving_sink(addr: &EVMAddress, hash_to_address: &HashMap<[u8; 4], HashSet<EVMAddress>>) -> bool {
    let transfer_sel = [0xa9, 0x05, 0x9c, 0xbb];       // transfer(address,uint256)
    let transfer_from_sel = [0x23, 0xb8, 0x72, 0xdd];   // transferFrom(address,address,uint256)
    let deposit_sel = [0xd0, 0xe3, 0x0d, 0xb0];         // deposit()
    let mint_sel = [0x94, 0xbf, 0x80, 0x4d];             // mint(address,uint256)
    hash_to_address
        .get(&transfer_sel)
        .map_or(false, |addrs| addrs.contains(addr))
        || hash_to_address
            .get(&transfer_from_sel)
            .map_or(false, |addrs| addrs.contains(addr))
        || hash_to_address
            .get(&deposit_sel)
            .map_or(false, |addrs| addrs.contains(addr))
        || hash_to_address
            .get(&mint_sel)
            .map_or(false, |addrs| addrs.contains(addr))
}

const PROXIMITY_WINDOW: usize = 60;

#[derive(Debug, Clone)]
pub struct OracleTracker {
    oracle_call_pc: Option<usize>,
    oracle_gated_cmp_pc: Option<usize>,
}

impl OracleTracker {
    pub fn new() -> Self {
        Self {
            oracle_call_pc: None,
            oracle_gated_cmp_pc: None,
        }
    }

    pub fn reset_static() {
        unsafe {
            ORACLE_GATED_TRANSFER_DETECTED = false;
        }
    }
}

impl<SC> Middleware<SC> for OracleTracker
where
    SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) {
        let opcode = interp.bytecode.opcode();
        let pc = interp.bytecode.pc();

        match opcode {
            0xf1 | 0xf2 | 0xf4 | 0xfa => {
                let to = convert_u256_to_h160(interp.stack.peek(1).unwrap_or(EVMU256::ZERO));
                if let Some(selectors) = host.oracle_selectors.get(&to) {
                    let args_offset = as_u64(interp.stack.peek(3).unwrap_or(EVMU256::ZERO)) as usize;
                    if interp.memory.len() >= args_offset + 4 {
                        let mut sel = [0u8; 4];
                        sel.copy_from_slice(&interp.memory.slice_len(args_offset, 4));
                        if selectors.contains(&sel) {
                            self.oracle_call_pc = Some(pc);
                            return;
                        }
                    }
                }
            }
            0x10..=0x14 => {
                if let Some(oracle_pc) = self.oracle_call_pc {
                    if pc <= oracle_pc + PROXIMITY_WINDOW {
                        self.oracle_gated_cmp_pc = Some(pc);
                    }
                }
            }
            0xf1 => {
                if let Some(_cmp_pc) = self.oracle_gated_cmp_pc {
                    let to = convert_u256_to_h160(interp.stack.peek(1).unwrap_or(EVMU256::ZERO));
                    if is_value_moving_sink(&to, &host.hash_to_address) {
                        ORACLE_GATED_TRANSFER_DETECTED = true;
                        host.current_typed_bug
                            .push(("oracle_gated_transfer".to_string(), (to, pc)));
                    }
                }
            }
            _ => {}
        }
    }

    unsafe fn on_return(
        &mut self,
        _interp: &mut Interpreter,
        _host: &mut FuzzHost<SC>,
        _state: &mut EVMFuzzState,
        _ret: &Bytes,
    ) {
        self.oracle_call_pc = None;
        self.oracle_gated_cmp_pc = None;
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::OracleTracker
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
