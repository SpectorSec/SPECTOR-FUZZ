use std::any::Any;
use std::fmt::Debug;

use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::{interpreter_types::Jumps, Interpreter};

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    types::{EVMAddress, EVMFuzzState, EVMU256},
    vm::EVMState,
};

pub static mut DOS_VIA_STATE_DEPENDENT_REVERT: bool = false;

#[derive(Debug, Clone)]
struct LastCmp {
    address: EVMAddress,
    storage_key: Option<EVMU256>,
}

#[derive(Debug, Clone)]
pub struct DoSDetector {
    last_cmp: Option<LastCmp>,
}

impl DoSDetector {
    pub fn new() -> Self {
        Self { last_cmp: None }
    }

    pub fn reset_static() {
        unsafe {
            DOS_VIA_STATE_DEPENDENT_REVERT = false;
        }
    }
}

impl<SC> Middleware<SC> for DoSDetector
where
    SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) {
        let opcode = interp.bytecode.opcode();
        let pc = interp.bytecode.pc();

        match opcode {
            0x10..=0x14 => {
                // Track if comparison operands come from storage
                let a = interp.stack.peek(0).unwrap_or(EVMU256::ZERO);
                let b = interp.stack.peek(1).unwrap_or(EVMU256::ZERO);
                // Check if either value directly follows an SLOAD by tracking the
                // common pattern: SLOAD → comparison
                // We can't verify this perfectly without instruction tracing, so we
                // use the address + last SLOAD result cache approach.
                // For MVP, check if comparison involves a value that COULD be from
                // storage: both operands non-trivial
                if !a.is_zero() || !b.is_zero() {
                    // Storage key detection is deferred to on_return when we check
                    // against tainted_storage. For now just mark that a comparison
                    // happened with non-trivial values.
                }
            }
            0x54 => {
                let key = interp.stack.peek(0).unwrap_or(EVMU256::ZERO);
                self.last_cmp = Some(LastCmp {
                    address: interp.input.target_address,
                    storage_key: Some(key),
                });
            }
            0xfd | 0xfe => {
                if let Some(ref cmp) = self.last_cmp {
                    if let Some(key) = cmp.storage_key {
                        if let Some(provenance) = host.tainted_storage.get(&(cmp.address, key)) {
                            if provenance.tainted {
                                DOS_VIA_STATE_DEPENDENT_REVERT = true;
                                host.current_typed_bug
                                    .push(("dos_via_state_dependent_revert".to_string(), (cmp.address, pc)));
                            }
                        }
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
        self.last_cmp = None;
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::DoSDetector
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
