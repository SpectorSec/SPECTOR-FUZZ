use std::{
    any,
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt::Debug,
    rc::Rc,
};

use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::{bytecode::opcode::JUMPI, interpreter_types::{InputsTr, Jumps}, Interpreter};
use tracing::debug;

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    types::{as_u64, EVMAddress, EVMFuzzState, EVMU256},
};

const MAX_CALL_DEPTH: u64 = 3;

/// Hard cap on dirty_memory growth and on input_data lengths returned by
/// {read,write}_input. The taint analysis tracks one bool per byte of EVM
/// memory. The real EVM's memory expansion is quadratic in gas, so reaching
/// even 1 MB costs ~2M gas; 16 MB is unreachable under any block gas limit.
/// Stack inputs that resolve to offsets or lengths beyond this cap therefore
/// imply the executing frame will run out of gas before any tainted byte
/// could be observed by a subsequent opcode — making the taint update moot.
///
/// Bounding here turns adversarial fuzzer-generated u256 values into safe
/// no-ops instead of capacity-overflow panics from Vec::resize.
const MEMORY_LIMIT_BYTES: usize = 1 << 24; // 16 MB

/// Returns `Some(offset + len)` if the range fits within MEMORY_LIMIT_BYTES
/// without integer overflow; `None` otherwise. Callers must skip the memory
/// access when this returns None.
#[inline]
fn safe_mem_end(offset: usize, len: usize) -> Option<usize> {
    offset
        .checked_add(len)
        .filter(|&end| end <= MEMORY_LIMIT_BYTES)
}

#[derive(Clone, Debug)]
pub struct Sha3TaintAnalysisCtx {
    pub dirty_memory: Vec<bool>,
    pub dirty_storage: HashMap<EVMU256, bool>,
    pub dirty_stack: Vec<bool>,
    pub input_data: Vec<bool>,
}

impl Sha3TaintAnalysisCtx {
    pub fn read_input(&self, start: usize, length: usize) -> Vec<bool> {
        // Cap length to keep adversarial fuzzer inputs from triggering an
        // exabyte-scale allocation. The returned vec may be shorter than
        // requested; downstream lookups go through this function so they
        // see the clamped slice, not the original length.
        let length = length.min(MEMORY_LIMIT_BYTES);
        let mut res = vec![false; length];
        let available = self.input_data.len();
        if start < available && length > 0 {
            let end = start.saturating_add(length).min(available);
            if end > start {
                res[..end - start].copy_from_slice(&self.input_data[start..end]);
            }
        }
        res
    }
}

#[derive(Clone, Debug)]
pub struct Sha3TaintAnalysis {
    pub dirty_memory: Vec<bool>,
    pub dirty_storage: HashMap<EVMU256, bool>,
    pub dirty_stack: Vec<bool>,
    pub tainted_jumpi: HashSet<(EVMAddress, usize)>,
    // Diagnostics: prev_opcode/prev_dirty_len are set at the END of on_step,
    // so on the NEXT on_step call they reflect what truly ran before the
    // current opcode. Without this, prev_opcode == current opcode at the
    // mismatch point and the field is useless.
    pub prev_opcode: u8,
    pub prev_dirty_len: usize,

    pub ctxs: Vec<Sha3TaintAnalysisCtx>,
}

impl Default for Sha3TaintAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3TaintAnalysis {
    pub fn new() -> Self {
        Self {
            dirty_memory: vec![],
            dirty_storage: HashMap::new(),
            dirty_stack: vec![],
            tainted_jumpi: HashSet::new(),
            prev_opcode: 0x00,
            prev_dirty_len: 0,
            ctxs: vec![],
        }
    }

    /// Per-frame cleanup. Used INSIDE push_ctx after the current ctx has
    /// been saved — must NOT clear `ctxs` or it would discard the save.
    pub fn cleanup(&mut self) {
        self.dirty_memory.clear();
        self.dirty_storage.clear();
        self.dirty_stack.clear();
    }

    /// Full per-execution reset. Call this BETWEEN test cases (not inside
    /// push_ctx). Without this, dirty state from one re-execution leaks
    /// into the next — the first opcode of the new run sees a real_stack
    /// of 0 but a dirty_stack carrying the previous run's leftover, and
    /// the assertion in on_step trips immediately.
    pub fn full_reset(&mut self) {
        self.cleanup();
        self.ctxs.clear();
        self.prev_opcode = 0;
        self.prev_dirty_len = 0;
    }

    pub fn write_input(&self, start: usize, length: usize) -> Vec<bool> {
        // See read_input — same adversarial-length protection.
        let length = length.min(MEMORY_LIMIT_BYTES);
        let mut res = vec![false; length];
        let available = self.dirty_memory.len();
        if start < available && length > 0 {
            let end = start.saturating_add(length).min(available);
            if end > start {
                res[..end - start].copy_from_slice(&self.dirty_memory[start..end]);
            }
        }
        res
    }

    pub fn push_ctx(&mut self, interp: &mut Interpreter) {
        // EVM stack layout for CALL-family opcodes:
        //   CALL/CALLCODE (0xf1/0xf2): gas, recipient, value, arg_offset, arg_size, ret_offset, ret_size
        //   DELEGATECALL/STATICCALL (0xf4/0xfa): gas, recipient, arg_offset, arg_size, ret_offset, ret_size
        // In both cases arg_offset is at peek(3) and arg_size is at peek(2).
        let (arg_offset, arg_len) = match interp.bytecode.opcode() {
            0xf1 | 0xf2 | 0xf4 | 0xfa => {
                (interp.stack.peek(3).unwrap(), interp.stack.peek(2).unwrap())
            }
            _ => {
                panic!("not supported opcode");
            }
        };

        let arg_offset = as_u64(arg_offset) as usize;
        let arg_len = as_u64(arg_len) as usize;

        let saved_dirty_len = self.dirty_stack.len();
        self.ctxs.push(Sha3TaintAnalysisCtx {
            input_data: self.write_input(arg_offset, arg_len),
            dirty_memory: self.dirty_memory.clone(),
            dirty_storage: self.dirty_storage.clone(),
            dirty_stack: self.dirty_stack.clone(),
        });
        eprintln!(
            "push_ctx op={:#x} saved_dirty_len={} ctxs_after={}",
            interp.bytecode.opcode(),
            saved_dirty_len,
            self.ctxs.len(),
        );

        self.cleanup();
    }

    pub fn pop_ctx(&mut self) {
        let before_ctxs = self.ctxs.len();
        let before_dirty = self.dirty_stack.len();
        let ctx = self.ctxs.pop().expect("ctxs is empty");
        self.dirty_memory = ctx.dirty_memory;
        self.dirty_storage = ctx.dirty_storage;
        self.dirty_stack = ctx.dirty_stack;
        eprintln!(
            "pop_ctx ctxs_before={} dirty_before={} restored_dirty_len={}",
            before_ctxs,
            before_dirty,
            self.dirty_stack.len(),
        );
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn any::Any {
        self
    }
}

impl<SC> Middleware<SC> for Sha3TaintAnalysis
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) {
        // skip taint analysis if call depth is too deep
        if host.call_depth > MAX_CALL_DEPTH {
            return;
        }

        // Self-correcting reset on fresh top-level call entry.
        //
        // Within one reexecute_with_middleware invocation, execute_call_single!
        // (vm.rs:468) creates a NEW Interpreter for EACH top-level call in the
        // input sequence. The real stack is fresh (empty) on each, but our
        // shadow state persists across them — feedbacks.rs only calls
        // full_reset() ONCE at the start of the re-execution, not per call.
        //
        // When we observe depth=0 + real_stack=0 + dirty_stack non-empty,
        // we KNOW there's stale shadow state from a previous top-level
        // call's RETURN that didn't get cleared. Reset what should reset
        // at a new top-level boundary: per-frame state (stack, memory, ctxs)
        // and telemetry. KEEP dirty_storage — storage state legitimately
        // persists across calls within a single re-execution session.
        if host.call_depth == 0 && interp.stack.is_empty() && !self.dirty_stack.is_empty() {
            self.dirty_stack.clear();
            self.dirty_memory.clear();
            self.ctxs.clear();
            self.prev_opcode = 0;
            self.prev_dirty_len = 0;
        }

        //
        // debug!("on_step: {:?} with {:x}", interp.program_counter(),
        // *interp.instruction_pointer); debug!("stack: {:?}",
        // self.dirty_stack); debug!("origin: {:?}", interp.stack);

        macro_rules! pop_push {
            ($pop_cnt: expr,$push_cnt: expr) => {{
                let mut res = false;
                for _ in 0..$pop_cnt {
                    res |= self.dirty_stack.pop().expect("stack is empty");
                }
                for _ in 0..$push_cnt {
                    self.dirty_stack.push(res);
                }
            }};
        }

        macro_rules! stack_pop_n {
            ($pop_cnt: expr) => {
                for _ in 0..$pop_cnt {
                    self.dirty_stack.pop().expect("stack is empty");
                }
            };
        }

        macro_rules! push_false {
            () => {
                self.dirty_stack.push(false)
            };
        }

        macro_rules! ensure_size {
            ($t: expr, $size: expr) => {
                if $t.len() < $size {
                    $t.resize($size, false);
                }
            };
        }

        macro_rules! setup_mem {
            () => {{
                stack_pop_n!(3);
                let len = as_u64(interp.stack.peek(0).expect("stack is empty")) as usize;
                let mem_offset = as_u64(interp.stack.peek(2).expect("stack is empty")) as usize;
                if let Some(end) = safe_mem_end(mem_offset, len) {
                    ensure_size!(self.dirty_memory, end);
                    self.dirty_memory[mem_offset..end]
                        .copy_from_slice(vec![false; len].as_slice());
                }
                // else: adversarial offset/len, EVM will OOG. Stack pop above
                // matches real EVM behavior; skip memory tracking only.
            }};
        }

        let opcode = interp.bytecode.opcode();

        if interp.stack.len() != self.dirty_stack.len() {
            // Shadow (taint) stack desynced from the real EVM stack. This used to be an
            // `assert_eq!` that crashed the entire fuzzer (~half of runs hit it). Resync to
            // the real stack length so the run continues — taint precision degrades only for
            // this trace; new slots are padded untainted (conservative).
            debug!(
                "sha3 shadow-stack desync: real={} dirty={} pc={:#x} addr={:#x} depth={} \
                 prev_opcode={:#x} prev_dirty_len={} current_op={:#x} ctxs_len={} — resyncing",
                interp.stack.len(),
                self.dirty_stack.len(),
                interp.bytecode.pc(),
                interp.input.target_address,
                host.call_depth,
                self.prev_opcode,
                self.prev_dirty_len,
                opcode,
                self.ctxs.len(),
            );
            self.dirty_stack.resize(interp.stack.len(), false);
        }

        match opcode {
            0x00 => {}
            0x01..=0x7 => {
                pop_push!(2, 1)
            }
            0x08..=0x09 => {
                pop_push!(3, 1)
            }
            0xa | 0x0b | 0x10..=0x14 => {
                pop_push!(2, 1);
            }
            0x15 => {
                pop_push!(1, 1);
            }
            0x16..=0x18 => {
                pop_push!(2, 1);
            }
            0x19 => {
                pop_push!(1, 1);
            }
            0x1a..=0x1d => {
                pop_push!(2, 1);
            }
            0x20 => {
                // sha3
                stack_pop_n!(2);
                self.dirty_stack.push(true);
            }
            0x30 => push_false!(),
            // BALANCE
            0x31 => pop_push!(1, 1),
            // ORIGIN
            0x32 => push_false!(),
            // CALLER
            0x33 => push_false!(),
            // CALLVALUE
            0x34 => push_false!(),
            // CALLDATALOAD
            0x35 => {
                self.dirty_stack.pop();
                if !self.ctxs.is_empty() {
                    let ctx = self.ctxs.last().unwrap();
                    let offset = as_u64(interp.stack.peek(0).expect("stack is empty")) as usize;
                    if offset == 0 {
                        push_false!();
                    } else {
                        let input = ctx.read_input(offset, 32).contains(&true);
                        // debug!("CALLDATALOAD: {:x} -> {}", offset, input);
                        self.dirty_stack.push(input);
                    }
                } else {
                    push_false!();
                }
            }
            // CALLDATASIZE
            0x36 => push_false!(),
            // CALLDATACOPY
            0x37 => setup_mem!(),
            // CODESIZE
            0x38 => push_false!(),
            // CODECOPY
            0x39 => setup_mem!(),
            // GASPRICE
            0x3a => push_false!(),
            // EXTCODESIZE
            0x3b | 0x3f => {
                stack_pop_n!(1);
                self.dirty_stack.push(false);
            }
            // EXTCODECOPY (pops 4: address, mem_offset, code_offset, size)
            0x3c => {
                stack_pop_n!(4);
                let len = as_u64(interp.stack.peek(0).expect("stack is empty")) as usize;
                let mem_offset = as_u64(interp.stack.peek(2).expect("stack is empty")) as usize;
                if let Some(end) = safe_mem_end(mem_offset, len) {
                    ensure_size!(self.dirty_memory, end);
                    self.dirty_memory[mem_offset..end]
                        .copy_from_slice(vec![false; len].as_slice());
                }
            }
            // RETURNDATASIZE
            0x3d => push_false!(),
            // RETURNDATACOPY
            0x3e => setup_mem!(),
            // COINBASE
            0x41..=0x48 => push_false!(),
            // POP
            0x50 => {
                self.dirty_stack.pop();
            }
            // MLOAD
            0x51 => {
                self.dirty_stack.pop();
                let mem_offset = as_u64(interp.stack.peek(0).expect("stack is empty")) as usize;
                let is_dirty = if let Some(end) = safe_mem_end(mem_offset, 32) {
                    ensure_size!(self.dirty_memory, end);
                    self.dirty_memory[mem_offset..end].iter().any(|x| *x)
                } else {
                    // Adversarial offset — EVM will OOG. Push clean.
                    false
                };
                self.dirty_stack.push(is_dirty);
            }
            // MSTORE
            0x52 => {
                stack_pop_n!(1);
                let mem_offset = as_u64(interp.stack.peek(0).expect("stack is empty")) as usize;
                let is_dirty = self.dirty_stack.pop().expect("stack is empty");
                if let Some(end) = safe_mem_end(mem_offset, 32) {
                    ensure_size!(self.dirty_memory, end);
                    self.dirty_memory[mem_offset..end]
                        .copy_from_slice(vec![is_dirty; 32].as_slice());
                }
            }
            // MSTORE8
            0x53 => {
                stack_pop_n!(1);
                let mem_offset = as_u64(interp.stack.peek(0).expect("stack is empty")) as usize;
                let is_dirty = self.dirty_stack.pop().expect("stack is empty");
                if let Some(end) = safe_mem_end(mem_offset, 1) {
                    ensure_size!(self.dirty_memory, end);
                    self.dirty_memory[mem_offset] = is_dirty;
                }
            }
            // SLOAD
            0x54 | 0x5c => {
                self.dirty_stack.pop();
                let key = interp.stack.peek(0).expect("stack is empty");
                let is_dirty = self.dirty_storage.get(&key).unwrap_or(&false);
                self.dirty_stack.push(*is_dirty);
            }
            // SSTORE
            0x55 | 0x5d => {
                self.dirty_stack.pop();
                let is_dirty = self.dirty_stack.pop().expect("stack is empty");
                let key = interp.stack.peek(0).expect("stack is empty");
                self.dirty_storage.insert(key, is_dirty);
            }
            // JUMP
            0x56 => {
                self.dirty_stack.pop();
            }
            // JUMPI
            0x57 => {
                self.dirty_stack.pop();
                let v = self.dirty_stack.pop().expect("stack is empty");
                if v {
                    debug!(
                        "new tainted jumpi: {:x} {:x}",
                        interp.input.target_address,
                        interp.bytecode.pc()
                    );
                    self.tainted_jumpi
                        .insert((interp.input.target_address, interp.bytecode.pc()));
                }
            }
            // PC
            0x58..=0x5a => {
                push_false!();
            }
            // JUMPDEST
            0x5b => {}
            // MCOPY (EIP-5656, Cancun)
            0x5e => {
                stack_pop_n!(3);
                let size = as_u64(interp.stack.peek(0).expect("stack is empty")) as usize;
                let src = as_u64(interp.stack.peek(1).expect("stack is empty")) as usize;
                let dest = as_u64(interp.stack.peek(2).expect("stack is empty")) as usize;
                if let Some(size) = size.checked_sub(1) {
                    if let (Some(src_end), Some(dest_end)) = (safe_mem_end(src, size), safe_mem_end(dest, size)) {
                        let max_end = src_end.max(dest_end);
                        ensure_size!(self.dirty_memory, max_end);
                        if src < self.dirty_memory.len() && dest < self.dirty_memory.len() {
                            let src_slice: Vec<bool> = {
                                let end = src + size;
                                if end > self.dirty_memory.len() {
                                    let mut v = self.dirty_memory[src..].to_vec();
                                    v.resize(size, false);
                                    v
                                } else {
                                    self.dirty_memory[src..end].to_vec()
                                }
                            };
                            let dest_end = dest + size;
                            if dest_end > self.dirty_memory.len() {
                                self.dirty_memory.resize(dest_end, false);
                            }
                            self.dirty_memory[dest..dest_end].copy_from_slice(&src_slice);
                        }
                    }
                }
            }
            // PUSH
            0x5f..=0x7f => {
                push_false!();
            }
            // DUP
            0x80..=0x8f => {
                let _n = opcode - 0x80 + 1;
                self.dirty_stack
                    .push(self.dirty_stack[self.dirty_stack.len() - _n as usize]);
            }
            // SWAP
            0x90..=0x9f => {
                let _n = opcode - 0x90 + 2;
                let _l = self.dirty_stack.len();
                self.dirty_stack.swap(_l - _n as usize, _l - 1);
            }
            // LOG
            0xa0..=0xa4 => {
                let _n = opcode - 0xa0 + 2;
                stack_pop_n!(_n);
            }
            0xf0 => {
                stack_pop_n!(3);
                self.dirty_stack.push(false);
            }
            0xf1 => {
                stack_pop_n!(7);
                self.dirty_stack.push(false);
                self.push_ctx(interp);
            }
            0xf2 => {
                stack_pop_n!(7);
                self.dirty_stack.push(false);
                self.push_ctx(interp);
            }
            0xf3 => {
                stack_pop_n!(2);
            }
            0xf4 => {
                stack_pop_n!(6);
                self.dirty_stack.push(false);
                self.push_ctx(interp);
            }
            0xf5 => {
                stack_pop_n!(4);
                self.dirty_stack.push(false);
            }
            0xfa => {
                stack_pop_n!(6);
                self.dirty_stack.push(false);
                self.push_ctx(interp);
            }
            0xfd => {
                // stack_pop_n!(2);
            }
            0xfe => {
                // stack_pop_n!(1);
            }
            0xff => {
                // stack_pop_n!(1);
            }
            _ => panic!("unknown opcode: {:x}", opcode),
        }

        // Record AFTER handler runs so the next on_step sees the actual
        // previous opcode and the dirty_stack length it produced.
        self.prev_opcode = opcode;
        self.prev_dirty_len = self.dirty_stack.len();
    }

    unsafe fn on_return(
        &mut self,
        _interp: &mut Interpreter,
        host: &mut FuzzHost<SC>,
        _state: &mut EVMFuzzState,
        _by: &Bytes,
    ) {
        // Mirror the depth gate in on_step: push_ctx only ran when the calling
        // instruction fired at depth <= MAX_CALL_DEPTH. The callee that triggered
        // this on_return is at depth = (caller_depth + 1), so we must only pop
        // when the callee's depth is <= MAX_CALL_DEPTH + 1. Without this gate,
        // sub-calls made by frames that on_step skipped pop ctxs that were
        // saved by outer frames, corrupting dirty_stack.
        eprintln!(
            "on_return entry call_depth={} ctxs_len={} dirty_len={}",
            host.call_depth,
            self.ctxs.len(),
            self.dirty_stack.len(),
        );
        // host.call_depth at this point is the PARENT's depth (call_depth -= 1
        // already ran in FuzzHost::call before on_return is invoked). So if
        // call_depth > MAX_CALL_DEPTH, the parent's on_step was skipped and
        // never called push_ctx — we must skip the pop too.
        if host.call_depth > MAX_CALL_DEPTH {
            eprintln!("on_return SKIP (depth > MAX_CALL_DEPTH)");
            return;
        }
        self.pop_ctx();
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::Sha3TaintAnalysis
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn any::Any {
        self
    }
}

#[derive(Debug)]
pub struct Sha3Bypass {
    pub sha3_taints: Rc<RefCell<Sha3TaintAnalysis>>,
}

impl Sha3Bypass {
    pub fn new(sha3_taints: Rc<RefCell<Sha3TaintAnalysis>>) -> Self {
        Self { sha3_taints }
    }
}

impl<SC> Middleware<SC> for Sha3Bypass
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) {
        if interp.bytecode.opcode() == JUMPI {
            let jumpi = interp.bytecode.pc();
            if self
                .sha3_taints
                .borrow()
                .tainted_jumpi
                .contains(&(interp.input.target_address, jumpi))
            {
                let stack_len = interp.stack.len();
                interp.stack.data_mut()[stack_len - 2] = EVMU256::from((jumpi + host.randomness[0] as usize) % 2);
            }
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::Sha3Bypass
    }

    fn as_any(&self) -> &dyn any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, path::Path, rc::Rc, sync::Arc};

    use bytes::Bytes;
    use itertools::Itertools;
    use libafl::schedulers::StdScheduler;
    use revm_interpreter::bytecode::{
        opcode::{ADD, EQ, JUMPDEST, JUMPI, MSTORE, PUSH0, PUSH1, KECCAK256, STOP},
        Bytecode,
    };

    use super::*;
    use crate::{
        evm::{
            input::{ConciseEVMInput, EVMInput, EVMInputTy},
            mutator::AccessPattern,
            types::{generate_random_address, EVMFuzzState},
            vm::{EVMExecutor, EVMState},
        },
        generic_vm::vm_executor::GenericVM,
        state::FuzzState,
        state_input::StagedVMState,
    };

    fn execute(bys: Bytes, code: Bytes) -> Vec<usize> {
        let mut state: EVMFuzzState = FuzzState::new(0);
        let path = Path::new("work_dir");
        if !path.exists() {
            let _ = std::fs::create_dir(path);
        }
        let mut evm_executor: EVMExecutor<EVMState, ConciseEVMInput, StdScheduler<EVMFuzzState>> = EVMExecutor::new(
            FuzzHost::new(StdScheduler::new(), "work_dir".to_string()),
            generate_random_address(&mut state),
        );

        let target_addr = generate_random_address(&mut state);
        evm_executor.host.code.insert(
            target_addr,
            Arc::new(Bytecode::new_legacy(revm_primitives::Bytes::from(code))),
        );

        let sha3 = Rc::new(RefCell::new(Sha3TaintAnalysis::new()));
        evm_executor.host.add_middlewares(sha3.clone());

        let input = EVMInput {
            caller: generate_random_address(&mut state),
            contract: target_addr,
            data: None,
            sstate: StagedVMState::new_uninitialized(),
            sstate_idx: 0,
            txn_value: Some(EVMU256::ZERO),
            step: false,
            env: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            liquidation_percent: 0,
            direct_data: bys,
            input_type: EVMInputTy::ABI,
            randomness: vec![],
            repeat: 1,
            swap_data: HashMap::new(),
            nested_actions: Vec::new(),
            campaign: None,
        };

        let res = evm_executor.execute(&input, &mut state);
        assert!(!res.reverted);
        return sha3
            .borrow()
            .tainted_jumpi
            .iter()
            .map(|(_addr, pc)| pc)
            .cloned()
            .collect_vec();
    }

    #[test]
    fn test_hash_none() {
        let bys = vec![
            PUSH1, 0x2, PUSH0, ADD, // stack = [2]
            PUSH1, 0x7, // stack = [2, 7]
            JUMPI, JUMPDEST, STOP,
        ];
        let taints = execute(Bytes::new(), Bytes::from(bys));
        assert_eq!(taints.len(), 0);
    }

    #[test]
    fn test_hash_simple() {
        let bys = vec![
            PUSH0, PUSH1, 0x42, MSTORE, PUSH0, PUSH1, 0x1, KECCAK256, PUSH1, 0x2, EQ, PUSH1, 0xe, JUMPI, JUMPDEST, STOP,
        ];
        let taints = execute(Bytes::new(), Bytes::from(bys));
        assert_eq!(taints.len(), 1);
        assert_eq!(taints[0], 0xd);
    }

    #[test]
    fn test_hash_simple_none() {
        let bys = vec![
            PUSH0, PUSH1, 0x42, MSTORE, PUSH0, PUSH1, 0x1, KECCAK256, PUSH1, 0x2, EQ, PUSH0, PUSH1, 0xf, JUMPI, JUMPDEST,
            STOP,
        ];
        let taints = execute(Bytes::new(), Bytes::from(bys));
        assert_eq!(taints.len(), 0);
    }

    #[test]
    fn test_hash_complex_1() {
        // contract Test {
        //     mapping (uint256=>bytes32) a;
        //
        //     fallback(bytes calldata x) external payable returns (bytes memory) {
        //         a[1] = keccak256(x);
        //
        //         if (a[1] == hex"cccc") {
        //             return "cccc";
        //         } else {
        //             return "dddd";
        //         }
        //     }
        // }
        let taints = execute(
            Bytes::new(),
            Bytes::from(hex::decode("608060405260003660608282604051610019929190610132565b604051809103902060008060018152602001908152602001600020819055507fcccc0000000000000000000000000000000000000000000000000000000000006000806001815260200190815260200160002054036100af576040518060400160405280600481526020017f636363630000000000000000000000000000000000000000000000000000000081525090506100e8565b6040518060400160405280600481526020017f646464640000000000000000000000000000000000000000000000000000000081525090505b915050805190602001f35b600081905092915050565b82818337600083830152505050565b600061011983856100f3565b93506101268385846100fe565b82840190509392505050565b600061013f82848661010d565b9150819050939250505056fea26469706673582212200b9b2e1716d1b88774664613e1e244bbf62489a4aded40c5a9118d1f302068e364736f6c63430008130033").unwrap())
        );
        assert_eq!(taints.len(), 1);
        debug!("{:?}", taints);
    }

    #[test]
    fn test_hash_complex_2() {
        // contract Test {
        //     mapping (uint256=>bytes32) a;
        //
        //     fallback(bytes calldata x) external payable returns (bytes memory) {
        //         a[1] = keccak256(x);
        //         a[1] = hex"cccc";
        //
        //         if (a[1] == hex"cccc") {
        //             return "cccc";
        //         } else {
        //             return "dddd";
        //         }
        //     }
        // }
        let taints = execute(
            Bytes::new(),
            Bytes::from(hex::decode("60806040526000366060828260405161001992919061016a565b604051809103902060008060018152602001908152602001600020819055507fcccc00000000000000000000000000000000000000000000000000000000000060008060018152602001908152602001600020819055507fcccc0000000000000000000000000000000000000000000000000000000000006000806001815260200190815260200160002054036100e7576040518060400160405280600481526020017f63636363000000000000000000000000000000000000000000000000000000008152509050610120565b6040518060400160405280600481526020017f646464640000000000000000000000000000000000000000000000000000000081525090505b915050805190602001f35b600081905092915050565b82818337600083830152505050565b6000610151838561012b565b935061015e838584610136565b82840190509392505050565b6000610177828486610145565b9150819050939250505056fea2646970667358221220be5565ccdf8b6a6e6c8b6d9113d6643155245741374ccd9bac3a434cff27515f64736f6c63430008130033").unwrap())
        );
        assert_eq!(taints.len(), 0);
    }

    #[test]
    fn test_hash_complex_3() {
        // contract Test {
        //     mapping (uint256=>bytes32) a;
        //
        //     fallback(bytes calldata x) external payable returns (bytes memory) {
        //         a[1] = keccak256(x);
        //         a[2] = a[1] ^ hex"aaaa";
        //
        //         if (uint(a[2]) + 123 > 1) {
        //             return "cccc";
        //         } else {
        //             return "dddd";
        //         }
        //     }
        // }
        let taints = execute(
            Bytes::new(),
            Bytes::from(hex::decode("608060405260003660608282604051610019929190610170565b604051809103902060008060018152602001908152602001600020819055507faaaa00000000000000000000000000000000000000000000000000000000000060008060018152602001908152602001600020541860008060028152602001908152602001600020819055506001607b600080600281526020019081526020016000205460001c6100aa91906101c2565b11156100ed576040518060400160405280600481526020017f63636363000000000000000000000000000000000000000000000000000000008152509050610126565b6040518060400160405280600481526020017f646464640000000000000000000000000000000000000000000000000000000081525090505b915050805190602001f35b600081905092915050565b82818337600083830152505050565b60006101578385610131565b935061016483858461013c565b82840190509392505050565b600061017d82848661014b565b91508190509392505050565b6000819050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006101cd82610189565b91506101d883610189565b92508282019050808211156101f0576101ef610193565b5b9291505056fea26469706673582212204d99e1e8876b38e211054a692fb1e98d19a40c8ef970e16a43602abed56a693164736f6c63430008130033").unwrap())
        );
        debug!("{:?}", taints);
        assert_eq!(taints.len(), 2);
    }

    // --- Memory-bound regression tests ------------------------------------
    // These exercise the adversarial-input guards added to defend against
    // fuzzer-generated u256 values that would otherwise resize dirty_memory
    // beyond `isize::MAX`, triggering `capacity overflow` in raw_vec.

    #[test]
    fn safe_mem_end_accepts_within_limit() {
        assert_eq!(safe_mem_end(0, 32), Some(32));
        assert_eq!(safe_mem_end(1024, 4096), Some(5120));
        assert_eq!(safe_mem_end(0, MEMORY_LIMIT_BYTES), Some(MEMORY_LIMIT_BYTES));
    }

    #[test]
    fn safe_mem_end_rejects_overflow() {
        assert_eq!(safe_mem_end(usize::MAX, 1), None);
        assert_eq!(safe_mem_end(usize::MAX - 100, 200), None);
    }

    #[test]
    fn safe_mem_end_rejects_over_limit() {
        assert_eq!(safe_mem_end(0, MEMORY_LIMIT_BYTES + 1), None);
        assert_eq!(safe_mem_end(MEMORY_LIMIT_BYTES, 1), None);
        // Large but non-overflowing values should still be rejected.
        assert_eq!(safe_mem_end(1 << 40, 32), None);
    }

    #[test]
    fn write_input_clamps_adversarial_length() {
        // write_input is on Sha3TaintAnalysis (reads from dirty_memory).
        // Build one with a small dirty_memory but ask for a u64::MAX-scale
        // write. Must not panic and must cap allocation at MEMORY_LIMIT_BYTES.
        let mut analysis = Sha3TaintAnalysis::new();
        analysis.dirty_memory = vec![true; 64];
        let out = analysis.write_input(0, usize::MAX);
        assert_eq!(out.len(), MEMORY_LIMIT_BYTES);
        assert!(out[..64].iter().all(|&b| b));
        assert!(out[64..].iter().all(|&b| !b));
    }

    #[test]
    fn read_input_clamps_adversarial_length() {
        let ctx = Sha3TaintAnalysisCtx {
            input_data: vec![true; 16],
            dirty_memory: vec![],
            dirty_storage: HashMap::new(),
            dirty_stack: vec![],
        };
        let out = ctx.read_input(0, usize::MAX);
        assert_eq!(out.len(), MEMORY_LIMIT_BYTES);
        assert!(out[..16].iter().all(|&b| b));
        assert!(out[16..].iter().all(|&b| !b));
    }

    #[test]
    fn read_input_handles_offset_past_input() {
        let ctx = Sha3TaintAnalysisCtx {
            input_data: vec![true; 10],
            dirty_memory: vec![],
            dirty_storage: HashMap::new(),
            dirty_stack: vec![],
        };
        // start beyond input_data => all-false result, no panic
        let out = ctx.read_input(100, 32);
        assert_eq!(out.len(), 32);
        assert!(out.iter().all(|&b| !b));
    }
}
