use std::any::Any;
use std::fmt::Debug;

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

pub static mut FLASH_LOAN_MANIPULATION: bool = false;

#[derive(Debug, Clone)]
struct OracleRead {
    call_index: usize,
    address: EVMAddress,
    selector: [u8; 4],
}

#[derive(Debug, Clone)]
struct ValueMovement {
    call_index: usize,
    sink_address: EVMAddress,
    amount: EVMU256,
}

const SEL_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const SEL_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];

#[derive(Debug, Clone)]
pub struct FlashloanOracle {
    oracle_reads: Vec<OracleRead>,
    value_movements: Vec<ValueMovement>,
    call_index: usize,
    borrow_seen: bool,
}

impl FlashloanOracle {
    pub fn new() -> Self {
        Self {
            oracle_reads: Vec::new(),
            value_movements: Vec::new(),
            call_index: 0,
            borrow_seen: false,
        }
    }

    pub fn reset_static() {
        unsafe {
            FLASH_LOAN_MANIPULATION = false;
        }
    }
}

impl<SC> Middleware<SC> for FlashloanOracle
where
    SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) {
        let opcode = interp.bytecode.opcode();

        match opcode {
            0xf1 => {
                let to = convert_u256_to_h160(interp.stack.peek(1).unwrap_or(EVMU256::ZERO));
                let value = interp.stack.peek(2).unwrap_or(EVMU256::ZERO);
                let args_offset = as_u64(interp.stack.peek(3).unwrap_or(EVMU256::ZERO)) as usize;

                let mut sel = [0u8; 4];
                let has_sel = interp.memory.len() >= args_offset + 4;
                if has_sel {
                    sel.copy_from_slice(&interp.memory.slice_len(args_offset, 4));
                }

                self.call_index += 1;

                // Detect oracle read
                if has_sel {
                    if let Some(selectors) = host.oracle_selectors.get(&to) {
                        if selectors.contains(&sel) {
                            self.oracle_reads.push(OracleRead {
                                call_index: self.call_index,
                                address: to,
                                selector: sel,
                            });
                            return;
                        }
                    }
                }

                // Detect borrow (value-bearing call to non-oracle, non-sink)
                if !value.is_zero() && !has_sel {
                    self.borrow_seen = true;
                    return;
                }

                // Detect value movement to sink
                if has_sel && (sel == SEL_TRANSFER || sel == SEL_TRANSFER_FROM) {
                    let is_sink = host
                        .hash_to_address
                        .get(&SEL_TRANSFER)
                        .map_or(false, |addrs| addrs.contains(&to))
                        || host
                            .hash_to_address
                            .get(&SEL_TRANSFER_FROM)
                            .map_or(false, |addrs| addrs.contains(&to));
                    if is_sink {
                        self.value_movements.push(ValueMovement {
                            call_index: self.call_index,
                            sink_address: to,
                            amount: value,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    unsafe fn on_return(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<SC>,
        _state: &mut EVMFuzzState,
        _ret: &Bytes,
    ) {
        if self.oracle_reads.len() >= 2 && self.value_movements.len() >= 1 && self.borrow_seen {
            let first_read_ci = self.oracle_reads[0].call_index;
            let last_read_ci = self.oracle_reads.last().unwrap().call_index;
            if last_read_ci > first_read_ci {
                let has_movement_between = self.value_movements.iter().any(|vm| {
                    vm.call_index > first_read_ci && vm.call_index < last_read_ci
                });
                if !has_movement_between {
                    let has_movement_after = self
                        .value_movements
                        .iter()
                        .any(|vm| vm.call_index > last_read_ci);
                    if has_movement_after {
                        FLASH_LOAN_MANIPULATION = true;
                        host.current_typed_bug
                            .push(("flash_loan_manipulation".to_string(), (interp.input.target_address, 0)));
                    }
                }
            }
        }
        self.oracle_reads.clear();
        self.value_movements.clear();
        self.call_index = 0;
        self.borrow_seen = false;
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::FlashloanOracle
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
