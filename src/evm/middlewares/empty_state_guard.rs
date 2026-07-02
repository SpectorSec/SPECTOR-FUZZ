use std::any::Any;
use std::fmt::Debug;

use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::{interpreter_types::Jumps, Interpreter};

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    types::{as_u64, convert_u256_to_h160, EVMFuzzState, EVMU256},
    vm::EVMState,
};

pub static mut EMPTY_STATE_GUARD_MISSING: bool = false;

const SEL_DEPOSIT: [u8; 4] = [0xd0, 0xe3, 0x0d, 0xb0];
const SEL_MINT: [u8; 4] = [0x94, 0xbf, 0x80, 0x4d];
const SEL_WITHDRAW: [u8; 4] = [0x2e, 0x1a, 0x7d, 0x4d];
const SEL_REDEEM: [u8; 4] = [0xba, 0x08, 0x76, 0x52];
const SEL_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const SEL_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];

const MAX_OPS_FOR_GUARD: usize = 40;

#[derive(Debug, Clone)]
pub struct EmptyStateGuard {
    /// Opcodes remaining in monitoring window
    watch_ops: usize,
    /// Saw an SLOAD during monitoring
    sload_seen: bool,
    /// Saw a JUMPI after SLOAD (guard present)
    jumpi_seen: bool,
    /// Saw a value-moving CALL (transfer/transferFrom)
    value_moved: bool,
    /// Current call depth at entry, to reset on return
    entry_depth: u64,
}

impl EmptyStateGuard {
    pub fn new() -> Self {
        Self {
            watch_ops: 0,
            sload_seen: false,
            jumpi_seen: false,
            value_moved: false,
            entry_depth: 0,
        }
    }

    pub fn reset_static() {
        unsafe {
            EMPTY_STATE_GUARD_MISSING = false;
        }
    }
}

fn is_deposit_selector(sel: &[u8; 4]) -> bool {
    *sel == SEL_DEPOSIT || *sel == SEL_MINT || *sel == SEL_WITHDRAW || *sel == SEL_REDEEM
}

impl<SC> Middleware<SC> for EmptyStateGuard
where
    SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) {
        let opcode = interp.bytecode.opcode();

        match opcode {
            0xf1 => {
                let args_offset = as_u64(interp.stack.peek(3).unwrap_or(EVMU256::ZERO)) as usize;
                if interp.memory.len() >= args_offset + 4 {
                    let mut sel = [0u8; 4];
                    sel.copy_from_slice(&interp.memory.slice_len(args_offset, 4));
                    if is_deposit_selector(&sel) {
                        self.watch_ops = MAX_OPS_FOR_GUARD;
                        self.sload_seen = false;
                        self.jumpi_seen = false;
                        self.value_moved = false;
                        self.entry_depth = host.call_depth;
                    }
                }
            }
            _ => {}
        }

        if self.watch_ops > 0 {
            self.watch_ops -= 1;
            match opcode {
                0x54 => {
                    self.sload_seen = true;
                }
                0x57 => {
                    if self.sload_seen {
                        self.jumpi_seen = true;
                    }
                }
                0xf1 => {
                    let to = convert_u256_to_h160(interp.stack.peek(1).unwrap_or(EVMU256::ZERO));
                    let args_offset = as_u64(interp.stack.peek(3).unwrap_or(EVMU256::ZERO)) as usize;
                    if interp.memory.len() >= args_offset + 4 {
                        let mut sel = [0u8; 4];
                        sel.copy_from_slice(&interp.memory.slice_len(args_offset, 4));
                        if sel == SEL_TRANSFER || sel == SEL_TRANSFER_FROM {
                            self.value_moved = true;
                            if !self.jumpi_seen {
                                EMPTY_STATE_GUARD_MISSING = true;
                                host.current_typed_bug.push((
                                    "empty_state_guard_missing".to_string(),
                                    (to, interp.bytecode.pc()),
                                ));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    unsafe fn on_return(
        &mut self,
        interp: &mut Interpreter,
        _host: &mut FuzzHost<SC>,
        _state: &mut EVMFuzzState,
        _ret: &Bytes,
    ) {
        if self.watch_ops > 0 && interp.bytecode.pc() == 0 {
            self.watch_ops = 0;
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::EmptyStateGuard
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
