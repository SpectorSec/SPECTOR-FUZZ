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
    oracles::freshness::is_oracle_interface,
    types::{as_u64, convert_u256_to_h160, EVMFuzzState, EVMU256},
    vm::EVMState,
};

pub static mut STALE_ORACLE_DETECTED: bool = false;

const STALE_WINDOW: usize = 50;

#[derive(Debug, Clone)]
pub struct OracleStaleness {
    oracle_read_pc: Option<usize>,
    timestamp_seen_pc: Option<usize>,
    stale_check_observed: bool,
}

impl OracleStaleness {
    pub fn new() -> Self {
        Self {
            oracle_read_pc: None,
            timestamp_seen_pc: None,
            stale_check_observed: false,
        }
    }

    pub fn reset_static() {
        unsafe {
            STALE_ORACLE_DETECTED = false;
        }
    }
}

impl<SC> Middleware<SC> for OracleStaleness
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
                            self.oracle_read_pc = Some(pc);
                            self.stale_check_observed = false;
                            self.timestamp_seen_pc = None;
                        }
                    }
                }
            }
            0x42 => {
                if self.oracle_read_pc.is_some() {
                    if let Some(oracle_pc) = self.oracle_read_pc {
                        if pc > oracle_pc && pc <= oracle_pc + STALE_WINDOW {
                            self.timestamp_seen_pc = Some(pc);
                        }
                    }
                }
            }
            0x10..=0x14 => {
                if self.timestamp_seen_pc.is_some() {
                    self.stale_check_observed = true;
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
        if self.oracle_read_pc.is_some() && !self.stale_check_observed {
            STALE_ORACLE_DETECTED = true;
            host.current_typed_bug
                .push(("stale_oracle".to_string(), (interp.input.target_address, 0)));
        }
        self.oracle_read_pc = None;
        self.timestamp_seen_pc = None;
        self.stale_check_observed = false;
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::OracleStaleness
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
