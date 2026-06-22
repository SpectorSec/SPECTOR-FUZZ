use core::panic;
use std::{
    cell::RefCell,
    cmp::min,
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    fmt::{Debug, Formatter},
    hash::{Hash, Hasher},
    io::Write,
    ops::Deref,
    rc::Rc,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use alloy_sol_types::SolValue;
use bytes::Bytes;
use itertools::Itertools;
use libafl::prelude::{HasMetadata, Scheduler};
use revm::precompile::Precompiles;
use revm_interpreter::{
    context_interface::{
        cfg::GasParams,
        host::LoadError,
        journaled_state::AccountInfoLoad,
    },
    gas_table, instruction_table,
    interpreter::{EthInterpreter, ExtBytecode, InputsImpl, SharedMemory},
    interpreter_types::{Jumps, ReturnData as ReturnDataTr},
    state::AccountInfo,
    CallInput, CallInputs, CallScheme, CallValue, CreateInputs, FrameInput,
    Host, InstructionResult, Interpreter, InterpreterAction,
    SStoreResult, SelfDestructResult, StateLoad,
};
use revm_interpreter::bytecode::Bytecode;
use revm_primitives::{hardfork::SpecId, Address, Bytes as PrimBytes, Log, B256, KECCAK_EMPTY, U256};
use tracing::debug;

use super::types::EVMFuzzState;
use crate::evm::vm::{IS_FAST_CALL, MEM_LIMIT, SETCODE_ONLY};
use crate::{
    evm::{
        abi::{get_abi_type_boxed, register_abi_instance},
        contract_utils::extract_sig_from_contract,
        corpus_initializer::ABIMap,
        input::{EVMInput, EVMInputTy},
        middlewares::middleware::{add_corpus, CallMiddlewareReturn, Middleware, MiddlewareType},
        mutator::AccessPattern,
        onchain::{
            abi_decompiler::fetch_abi_evmole,
            flashloan::{register_borrow_txn, Flashloan},
        },
        types::{as_u64, generate_random_address, is_zero, EVMAddress, EVMU256},
        vm::{is_reverted_or_control_leak, EVMState, SinglePostExecution, IN_DEPLOY, IS_FAST_CALL_STATIC},
    },
    generic_vm::vm_executor::MAP_SIZE,
    handle_contract_insertion,
    invoke_middlewares,
    state::{HasCaller, HasHashToAddress},
    state_input::StagedVMState,
};

use crate::evm::types::Env;

pub static mut JMP_MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];

// dataflow
pub static mut READ_MAP: [bool; MAP_SIZE] = [false; MAP_SIZE];
pub static mut WRITE_MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];

// cmp
pub static mut CMP_MAP: [EVMU256; MAP_SIZE] = [EVMU256::MAX; MAP_SIZE];

pub static mut ABI_MAX_SIZE: [usize; MAP_SIZE] = [0; MAP_SIZE];
pub static mut STATE_CHANGE: bool = false;

pub const RW_SKIPPER_PERCT_IDX: usize = 100;
pub const RW_SKIPPER_AMT: usize = MAP_SIZE - RW_SKIPPER_PERCT_IDX;

// How many iterations the coverage is the same
pub static mut COVERAGE_NOT_CHANGED: u32 = 0;
pub static mut RET_SIZE: usize = 0;
pub static mut RET_OFFSET: usize = 0;

pub static mut PANIC_ON_BUG: bool = false;
// for debugging purpose, return ControlLeak when the calls amount exceeds this value
pub static mut CALL_UNTIL: u32 = u32::MAX;

/// Shall we dump the contract calls
pub static mut WRITE_RELATIONSHIPS: bool = false;

/// Branch status of the current execution
pub static mut BRANCH_STATUS: [Option<(EVMAddress, usize, bool)>; MAP_SIZE] = [None; MAP_SIZE];
pub static mut BRANCH_STATUS_IDX: usize = 0;

// Control-leak signal flags (replaces custom InstructionResult variants from old revm fork)
pub static mut CONTROL_LEAK_DETECTED: bool = false;
pub static mut ARBITRARY_CALL_DETECTED: bool = false;
pub static mut ARBITRARY_CALL_CALLER: [u8; 20] = [0u8; 20];
pub static mut ARBITRARY_CALL_TARGET: [u8; 20] = [0u8; 20];
pub static mut ARBITRARY_CALL_VALUE: EVMU256 = EVMU256::ZERO;
pub static mut UNBOUNDED_STATIC_CALL_DETECTED: bool = false;

pub fn clear_branch_status() {
    unsafe {
        for i in BRANCH_STATUS.iter_mut().take(BRANCH_STATUS_IDX + 1) {
            *i = None;
        }

        BRANCH_STATUS_IDX = 0;

        // Control-leak signal flags are per-execution. Without this reset, a
        // flag set during one fuzzer input stays set forever, corrupting
        // subsequent runs (is_call_success! returns true on Revert, and
        // execute_abi keeps pushing PostExecutionCtx on every input).
        CONTROL_LEAK_DETECTED = false;
        ARBITRARY_CALL_DETECTED = false;
        ARBITRARY_CALL_CALLER = [0u8; 20];
        ARBITRARY_CALL_TARGET = [0u8; 20];
        ARBITRARY_CALL_VALUE = EVMU256::ZERO;
        UNBOUNDED_STATIC_CALL_DETECTED = false;
    }
}

pub fn add_branch(branch: (EVMAddress, usize, bool)) {
    unsafe {
        if BRANCH_STATUS_IDX >= MAP_SIZE {
            return;
        }
        BRANCH_STATUS[BRANCH_STATUS_IDX] = Some(branch);
        BRANCH_STATUS_IDX += 1;
    }
}

const SCRIBBLE_EVENT_HEX: [u8; 32] = [
    0xb4, 0x26, 0x04, 0xcb, 0x10, 0x5a, 0x16, 0xc8, 0xf6, 0xdb, 0x8a, 0x41, 0xe6, 0xb0, 0x0c, 0x0c, 0x1b, 0x48, 0x26,
    0x46, 0x5e, 0x8b, 0xc5, 0x04, 0xb3, 0xeb, 0x3e, 0x88, 0xb3, 0xe6, 0xa4, 0xa0,
];

/// Check if address is precompile by having assumption
/// that precompiles are in range of 1 to N.
#[inline(always)]
pub fn is_precompile(address: EVMAddress, num_of_precompiles: usize) -> bool {
    if !address[..18].iter().all(|i| *i == 0) {
        return false;
    }
    let num = u16::from_be_bytes([address[18], address[19]]);
    num.wrapping_sub(1) < num_of_precompiles as u16
}

#[allow(clippy::type_complexity)]
pub struct FuzzHost<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    pub evmstate: EVMState,
    /// [EIP-1153](https://eips.ethereum.org/EIPS/eip-1153) transient storage that is discarded after every transaction
    pub transient_storage: HashMap<(EVMAddress, EVMU256), EVMU256>,
    // these are internal to the host
    pub env: Env,
    pub code: HashMap<EVMAddress, Arc<Bytecode>>,
    pub hash_to_address: HashMap<[u8; 4], HashSet<EVMAddress>>,
    pub address_to_hash: HashMap<EVMAddress, Vec<[u8; 4]>>,
    pub _pc: usize,
    pub pc_to_addresses: HashMap<(EVMAddress, usize), HashSet<EVMAddress>>,
    pub pc_to_create: HashMap<(EVMAddress, usize), usize>,
    pub pc_to_call_hash: HashMap<(EVMAddress, usize, usize), HashSet<Vec<u8>>>,
    pub middlewares_enabled: bool,
    // If you use RefCell, modifying middlewares during execution will cause a panic
    // because the executor borrows middlewares over its entire lifetime.
    pub middlewares: RwLock<Vec<Rc<RefCell<dyn Middleware<SC>>>>>,

    pub coverage_changed: bool,

    pub flashloan_middleware: Option<Rc<RefCell<Flashloan>>>,

    pub middlewares_latent_call_actions: Vec<CallMiddlewareReturn>,

    pub scheduler: SC,

    // controlled by onchain module, if sload cant find the slot, use this value
    pub next_slot: EVMU256,

    pub access_pattern: Rc<RefCell<AccessPattern>>,

    pub bug_hit: bool,
    pub current_typed_bug: Vec<(String, (EVMAddress, usize))>,
    pub call_count: u32,

    #[cfg(feature = "print_logs")]
    pub logs: HashSet<u64>,
    // set_code data
    pub setcode_data: HashMap<EVMAddress, Bytecode>,
    // selfdestruct
    pub current_self_destructs: Vec<(EVMAddress, usize)>,
    // arbitrary calls
    pub current_arbitrary_calls: Vec<(EVMAddress, EVMAddress, usize)>,
    // arbitrary ERC20 transfers
    pub current_arbitrary_transfers: Vec<(EVMAddress, usize)>,
    // integer_overflow
    pub current_integer_overflow: HashSet<(EVMAddress, usize, &'static str)>,
    // relations file handle
    relations_file: std::fs::File,
    // Filter duplicate relations
    relations_hash: HashSet<u64>,
    /// Randomness from inputs
    pub randomness: Vec<u8>,
    /// workdir
    pub work_dir: String,
    /// custom SpecId
    pub spec_id: SpecId,
    /// Precompiles
    pub precompiles: Precompiles,

    /// Gas parameters for the current spec
    pub gas_params: GasParams,

    /// All SSTORE PCs that are for mapping (i.e., writing to multiple storage slots)
    pub mapping_sstore_pcs: HashSet<(EVMAddress, usize)>,
    pub mapping_sstore_pcs_to_slot: HashMap<(EVMAddress, usize), HashSet<EVMU256>>,

    /// For future continue executing when control leak happens
    pub leak_ctx: Vec<SinglePostExecution>,

    pub jumpi_trace: usize,

    /// Depth of call stack
    pub call_depth: u64,

    /// Assert failed message for the cheatcode
    pub assert_msg: Option<String>,
}

impl<SC> Debug for FuzzHost<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuzzHost")
            .field("data", &self.evmstate)
            .field("env", &self.env)
            .field("hash_to_address", &self.hash_to_address)
            .field("address_to_hash", &self.address_to_hash)
            .field("_pc", &self._pc)
            .field("pc_to_addresses", &self.pc_to_addresses)
            .field("pc_to_call_hash", &self.pc_to_call_hash)
            .field("middlewares_enabled", &self.middlewares_enabled)
            .field("middlewares", &self.middlewares)
            .field("middlewares_latent_call_actions", &self.middlewares_latent_call_actions)
            .finish()
    }
}

// all clones would not include middlewares and states
impl<SC> Clone for FuzzHost<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            evmstate: self.evmstate.clone(),
            transient_storage: self.transient_storage.clone(),
            env: self.env.clone(),
            code: self.code.clone(),
            hash_to_address: self.hash_to_address.clone(),
            address_to_hash: self.address_to_hash.clone(),
            _pc: self._pc,
            pc_to_addresses: self.pc_to_addresses.clone(),
            pc_to_create: self.pc_to_create.clone(),
            pc_to_call_hash: self.pc_to_call_hash.clone(),
            middlewares_enabled: false,
            middlewares: RwLock::new(Default::default()),
            coverage_changed: false,
            flashloan_middleware: self.flashloan_middleware.clone(),
            middlewares_latent_call_actions: vec![],
            scheduler: self.scheduler.clone(),
            next_slot: Default::default(),
            access_pattern: self.access_pattern.clone(),
            bug_hit: false,
            call_count: 0,
            #[cfg(feature = "print_logs")]
            logs: Default::default(),
            setcode_data: self.setcode_data.clone(),
            current_self_destructs: self.current_self_destructs.clone(),
            current_arbitrary_calls: self.current_arbitrary_calls.clone(),
            current_arbitrary_transfers: self.current_arbitrary_transfers.clone(),
            current_integer_overflow: self.current_integer_overflow.clone(),
            relations_file: self.relations_file.try_clone().unwrap(),
            relations_hash: self.relations_hash.clone(),
            current_typed_bug: self.current_typed_bug.clone(),
            randomness: vec![],
            work_dir: self.work_dir.clone(),
            spec_id: self.spec_id,
            precompiles: Precompiles::default(),
            gas_params: self.gas_params.clone(),
            leak_ctx: self.leak_ctx.clone(),
            mapping_sstore_pcs: self.mapping_sstore_pcs.clone(),
            mapping_sstore_pcs_to_slot: self.mapping_sstore_pcs_to_slot.clone(),
            jumpi_trace: self.jumpi_trace,
            call_depth: self.call_depth,
            assert_msg: self.assert_msg.clone(),
        }
    }
}

// hack: I don't want to change evm internal to add a new type of return
// this return type is never used as we disabled gas
pub static mut ACTIVE_MATCH_EXT_CALL: bool = false;
const UNBOUND_CALL_THRESHOLD: usize = 50;

// if a PC transfers control to >10 addresses, we consider call at this PC to be unbounded
const CONTROL_LEAK_THRESHOLD: usize = 50;

// RW key macros — must be defined before impl blocks that use them
macro_rules! process_rw_key {
    ($key:ident) => {
        if $key > EVMU256::from(RW_SKIPPER_PERCT_IDX) {
            $key %= EVMU256::from(RW_SKIPPER_AMT);
            $key += EVMU256::from(RW_SKIPPER_PERCT_IDX);
            as_u64($key) as usize % MAP_SIZE
        } else {
            as_u64($key) as usize % MAP_SIZE
        }
    };
}

macro_rules! u256_to_u8 {
    ($key:ident) => {
        (as_u64($key >> 4) % 254) as u8
    };
}

impl<SC> FuzzHost<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    pub fn new(scheduler: SC, workdir: String) -> Self {
        Self {
            evmstate: EVMState::new(),
            transient_storage: HashMap::new(),
            env: Env::default(),
            code: HashMap::new(),
            hash_to_address: HashMap::new(),
            address_to_hash: HashMap::new(),
            _pc: 0,
            pc_to_addresses: HashMap::new(),
            pc_to_create: HashMap::new(),
            pc_to_call_hash: HashMap::new(),
            middlewares_enabled: false,
            middlewares: RwLock::new(Default::default()),
            coverage_changed: false,
            flashloan_middleware: None,
            middlewares_latent_call_actions: vec![],
            scheduler,
            next_slot: Default::default(),
            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
            bug_hit: false,
            call_count: 0,
            #[cfg(feature = "print_logs")]
            logs: Default::default(),
            setcode_data: HashMap::new(),
            current_self_destructs: Default::default(),
            current_arbitrary_calls: Default::default(),
            current_arbitrary_transfers: Default::default(),
            current_integer_overflow: Default::default(),
            relations_file: std::fs::File::create(format!("{}/relations.log", workdir)).unwrap(),
            relations_hash: HashSet::new(),
            current_typed_bug: Default::default(),
            randomness: vec![],
            work_dir: workdir,
            spec_id: SpecId::PRAGUE,
            precompiles: Default::default(),
            gas_params: GasParams::new_spec(SpecId::PRAGUE),
            leak_ctx: vec![],
            mapping_sstore_pcs: Default::default(),
            mapping_sstore_pcs_to_slot: Default::default(),
            jumpi_trace: 37,
            call_depth: 0,
            assert_msg: None,
        }
    }

    pub fn set_spec_id(&mut self, spec_id: String) {
        self.spec_id = spec_id.parse::<SpecId>().unwrap_or(SpecId::PRAGUE);
        self.gas_params = GasParams::new_spec(self.spec_id);
    }

    /// Execute bytecode with coverage tracking and sub-frame dispatch.
    /// Replaces the old `interp.run_inspect::<STATE, HOST, SPEC>(host, state)` call.
    pub fn run_inspect(&mut self, interp: &mut Interpreter, state: &mut EVMFuzzState) -> InstructionResult {
        let table = instruction_table::<EthInterpreter, FuzzHost<SC>>();
        let gas_tbl = gas_table();

        loop {
            // ---- pre-step inspection (was Host::step in old API) ----
            unsafe {
                let opcode = interp.bytecode.opcode();
                let pc = interp.bytecode.pc();

                invoke_middlewares!(self, interp, state, on_step);
                if IS_FAST_CALL_STATIC {
                    // Skip coverage tracking but still execute the instruction
                } else {
                    macro_rules! fast_peek {
                        ($idx:expr) => {
                            interp.stack.data()[interp.stack.len() - 1 - $idx]
                        };
                    }

                    match opcode {
                        0x57 => {
                            // JUMPI counter cond
                            let br = fast_peek!(1);
                            let jump_dest = if is_zero(br) { 1 } else { as_u64(fast_peek!(0)) };

                            let (shash, _) = self.jumpi_trace.overflowing_mul(54059);
                            self.jumpi_trace = (shash) ^ (pc * 76963);
                            let idx = (pc * (jump_dest as usize)) % MAP_SIZE;
                            if JMP_MAP[idx] == 0 {
                                self.coverage_changed = true;
                            }
                            JMP_MAP[idx] = JMP_MAP[idx].saturating_add(1);

                            #[cfg(feature = "cmp")]
                            {
                                let idx = pc % MAP_SIZE;
                                CMP_MAP[idx] = br;
                            }

                            add_branch((interp.input.target_address, pc, jump_dest != 1));
                        }

                        #[cfg(any(feature = "dataflow", feature = "cmp"))]
                        0x55 | 0x5d => {
                            // SSTORE | TSTORE — same [key, value] stack layout.
                            let is_sstore = opcode == 0x55;
                            if !self.mapping_sstore_pcs.contains(&(interp.input.target_address, pc)) {
                                let mut key = fast_peek!(0);
                                let slots = self
                                    .mapping_sstore_pcs_to_slot
                                    .entry((interp.input.target_address, pc))
                                    .or_default();
                                slots.insert(key);
                                if slots.len() > 10 {
                                    self.mapping_sstore_pcs.insert((interp.input.target_address, pc));
                                }

                                let value = fast_peek!(1);
                                let compressed_value = u256_to_u8!(value) + 1;
                                WRITE_MAP[process_rw_key!(key)] = compressed_value;

                                if is_sstore {
                                    let res = <FuzzHost<SC> as Host>::sload(
                                        self,
                                        interp.input.target_address,
                                        fast_peek!(0),
                                    );
                                    let value_changed = res.map(|r| r.data != value).unwrap_or(false);

                                    let idx = pc % MAP_SIZE;
                                    JMP_MAP[idx] = if value_changed { 1 } else { 0 };

                                    STATE_CHANGE |= value_changed;
                                }
                            }
                        }

                        #[cfg(feature = "dataflow")]
                        0x54 | 0x5c => {
                            // SLOAD | TLOAD
                            let mut key = fast_peek!(0);
                            READ_MAP[process_rw_key!(key)] = true;
                        }

                        // todo(shou): support signed checking
                        #[cfg(feature = "cmp")]
                        0x10 | 0x12 => {
                            // LT, SLT
                            let v1 = fast_peek!(0);
                            let v2 = fast_peek!(1);
                            let abs_diff = if v1 >= v2 {
                                if v1 - v2 != EVMU256::ZERO { v1 - v2 } else { EVMU256::from(1) }
                            } else {
                                EVMU256::ZERO
                            };
                            let idx = pc % MAP_SIZE;
                            if abs_diff < CMP_MAP[idx] {
                                CMP_MAP[idx] = abs_diff;
                            }
                        }

                        #[cfg(feature = "cmp")]
                        0x11 | 0x13 => {
                            // GT, SGT
                            let v1 = fast_peek!(0);
                            let v2 = fast_peek!(1);
                            let abs_diff = if v1 <= v2 {
                                if v2 - v1 != EVMU256::ZERO { v2 - v1 } else { EVMU256::from(1) }
                            } else {
                                EVMU256::ZERO
                            };
                            let idx = pc % MAP_SIZE;
                            if abs_diff < CMP_MAP[idx] {
                                CMP_MAP[idx] = abs_diff;
                            }
                        }

                        #[cfg(feature = "cmp")]
                        0x14 => {
                            // EQ
                            let v1 = fast_peek!(0);
                            let v2 = fast_peek!(1);
                            let abs_diff = if v1 < v2 {
                                (v2 - v1) % (EVMU256::MAX - EVMU256::from(1)) + EVMU256::from(1)
                            } else {
                                (v1 - v2) % (EVMU256::MAX - EVMU256::from(1)) + EVMU256::from(1)
                            };
                            let idx = pc % MAP_SIZE;
                            if abs_diff < CMP_MAP[idx] {
                                CMP_MAP[idx] = abs_diff;
                            }
                        }

                        0xf1 | 0xf2 | 0xf4 | 0xfa => {
                            let offset_of_ret_size: usize = match opcode {
                                0xf1 | 0xf2 => 6,
                                0xf4 | 0xfa => 5,
                                _ => unreachable!(),
                            };
                            RET_OFFSET = as_u64(fast_peek!(offset_of_ret_size - 1)) as usize;
                            RET_SIZE = as_u64(fast_peek!(offset_of_ret_size)) as usize;
                            self._pc = pc;
                        }
                        0xf0 | 0xf5 | 0xa0..=0xa4 | 0xff => {
                            self._pc = pc;
                        }
                        _ => {}
                    }

                    self.access_pattern.deref().borrow_mut().decode_instruction(interp);
                }
            }

            // ---- execute the instruction ----
            match interp.step(&table, &gas_tbl, self) {
                Ok(()) => {
                    // instruction completed normally, loop
                }
                Err(InstructionResult::Suspend) => {
                    // CALL or CREATE instruction set a NewFrame action
                    let action = interp.take_next_action();
                    match action {
                        InterpreterAction::NewFrame(FrameInput::Call(inputs)) => {
                            let (ir, mem_offset, out_bytes) = self.call_internal(inputs, interp, state);
                            // Feed result back into parent interpreter
                            interp.return_data.set_buffer(out_bytes.clone().into());
                            let target_len = min(mem_offset.len(), out_bytes.len());
                            let item = if ir.is_ok() { EVMU256::from(1) } else { EVMU256::ZERO };
                            let _ = interp.stack.push(item);
                            if ir.is_ok_or_revert() {
                                interp.memory.set(mem_offset.start, &out_bytes[..target_len]);
                            }

                            // Propagate any control-leak signal immediately
                            unsafe {
                                if CONTROL_LEAK_DETECTED || ARBITRARY_CALL_DETECTED || UNBOUNDED_STATIC_CALL_DETECTED {
                                    return InstructionResult::Revert;
                                }
                            }
                        }
                        InterpreterAction::NewFrame(FrameInput::Create(inputs)) => {
                            let (result, created_addr, output) = self.create_internal(inputs, state);
                            // Feed result back into parent interpreter
                            if result == InstructionResult::Revert {
                                interp.return_data.set_buffer(output.into());
                            } else {
                                interp.return_data.clear();
                            }
                            let stack_item = if result.is_ok() {
                                created_addr
                                    .map(|a| EVMU256::from_be_slice(&{
                                        let mut buf = [0u8; 32];
                                        buf[12..].copy_from_slice(a.as_slice());
                                        buf
                                    }))
                                    .unwrap_or(EVMU256::ZERO)
                            } else {
                                EVMU256::ZERO
                            };
                            let _ = interp.stack.push(stack_item);
                        }
                        InterpreterAction::NewFrame(FrameInput::Empty) => {
                            // Empty frame: push success
                            let _ = interp.stack.push(EVMU256::from(1));
                        }
                        InterpreterAction::Return(result) => {
                            // Make output available to caller via return_data.buffer()
                            // (revm 41 puts output in the action; callers read return_data).
                            interp.return_data.set_buffer(result.output.clone());
                            return result.result;
                        }
                    }
                }
                Err(e) => {
                    // Halt — may be a normal stop/return or an error
                    if interp.bytecode.action.is_none() {
                        interp.halt(e);
                    }
                    return match interp.take_next_action() {
                        InterpreterAction::Return(r) => {
                            interp.return_data.set_buffer(r.output.clone());
                            r.result
                        }
                        _ => InstructionResult::Stop,
                    };
                }
            }
        }
    }

    pub fn remove_all_middlewares(&mut self) {
        self.middlewares_enabled = false;
        self.middlewares = RwLock::new(Default::default());
    }

    pub fn add_middlewares(&mut self, middleware: Rc<RefCell<dyn Middleware<SC>>>) {
        self.middlewares_enabled = true;
        self.middlewares.write().unwrap().push(middleware);
    }

    pub fn remove_middlewares(&mut self, middlewares: Rc<RefCell<dyn Middleware<SC>>>) {
        let ty = middlewares.deref().borrow().get_type();

        self.middlewares
            .write()
            .unwrap()
            .retain(|x| x.deref().borrow().get_type() != ty);
    }

    pub fn remove_middlewares_by_ty(&mut self, ty: &MiddlewareType) {
        self.middlewares
            .write()
            .unwrap()
            .retain(|x| x.deref().borrow().get_type() != *ty);
    }

    pub fn add_flashloan_middleware(&mut self, middlware: Flashloan) {
        self.flashloan_middleware = Some(Rc::new(RefCell::new(middlware)));
    }

    pub fn initialize(&mut self, state: &EVMFuzzState) {
        self.hash_to_address = state.get_hash_to_address().clone();
        for key in self.hash_to_address.keys() {
            let addresses = self.hash_to_address.get(key).unwrap();
            for addr in addresses {
                match self.address_to_hash.get_mut(addr) {
                    Some(s) => {
                        s.push(*key);
                    }
                    None => {
                        self.address_to_hash.insert(*addr, vec![*key]);
                    }
                }
            }
        }
    }

    pub fn add_hashes(&mut self, address: EVMAddress, hashes: Vec<[u8; 4]>) {
        self.address_to_hash.insert(address, hashes.clone());

        for hash in hashes {
            match self.hash_to_address.get_mut(&hash) {
                Some(s) => {
                    s.insert(address);
                }
                None => {
                    self.hash_to_address.insert(hash, HashSet::from([address]));
                }
            }
        }
    }

    pub fn add_one_hashes(&mut self, address: EVMAddress, hash: [u8; 4]) {
        match self.address_to_hash.get_mut(&address) {
            Some(s) => {
                s.push(hash);
            }
            None => {
                self.address_to_hash.insert(address, vec![hash]);
            }
        }

        match self.hash_to_address.get_mut(&hash) {
            Some(s) => {
                s.insert(address);
            }
            None => {
                self.hash_to_address.insert(hash, HashSet::from([address]));
            }
        }
    }

    pub fn set_codedata(&mut self, address: EVMAddress, code: Bytecode) {
        self.setcode_data.insert(address, code);
    }

    pub fn clear_codedata(&mut self) {
        self.setcode_data.clear();
    }

    pub fn set_code(&mut self, address: EVMAddress, mut code: Bytecode, state: &mut EVMFuzzState) {
        unsafe {
            invoke_middlewares!(self, None, state, on_insert, &mut code, address);
        }
        // Ensure bytecode has jumpdest analysis
        let analyzed = Bytecode::new_legacy(code.original_bytes());
        self.code.insert(address, Arc::new(analyzed));
    }

    pub fn find_static_call_read_slot(
        &self,
        _address: EVMAddress,
        _data: Bytes,
        _state: &mut EVMFuzzState,
    ) -> Vec<EVMU256> {
        vec![]
    }

    pub fn write_relations(&mut self, caller: EVMAddress, target: EVMAddress, funtion_hash: Bytes) {
        if funtion_hash.len() < 0x4 {
            return;
        }
        let cur_write_str = format!(
            "{{caller:0x{} --> target:0x{} function(0x{})}}\n",
            hex::encode(caller),
            hex::encode(target),
            hex::encode(&funtion_hash[..4])
        );
        let mut hasher = DefaultHasher::new();
        cur_write_str.hash(&mut hasher);
        let cur_wirte_hash = hasher.finish();
        if self.relations_hash.contains(&cur_wirte_hash) {
            return;
        }
        if self.relations_hash.is_empty() {
            let write_head = "[ityfuzz relations] caller, traget, function hash\n".to_string();
            self.relations_file.write_all(write_head.as_bytes()).unwrap();
        }

        self.relations_hash.insert(cur_wirte_hash);
        self.relations_file.write_all(cur_write_str.as_bytes()).unwrap();
    }

    /// Extracts call input bytes from a CallInput (handles both Bytes and SharedBuffer variants)
    fn get_input_bytes(input: &CallInput) -> Bytes {
        match input {
            CallInput::Bytes(b) => b.clone().0,
            CallInput::SharedBuffer(_) => Bytes::new(), // SharedBuffer not usable without context
        }
    }

    fn call_allow_control_leak(
        &mut self,
        input: &mut CallInputs,
        interp: &mut Interpreter,
        (out_offset, out_len): (usize, usize),
        state: &mut EVMFuzzState,
    ) -> (InstructionResult, std::ops::Range<usize>, Bytes) {
        macro_rules! push_interp {
            () => {{
                self.leak_ctx = vec![SinglePostExecution::from_interp(interp, (out_offset, out_len))];
            }};
        }
        self.call_count += 1;
        if self.call_count >= unsafe { CALL_UNTIL } {
            push_interp!();
            unsafe { CONTROL_LEAK_DETECTED = true; }
            return (InstructionResult::Revert, input.return_memory_offset.clone(), Bytes::new());
        }

        let input_bytes = Self::get_input_bytes(&input.input);

        if unsafe { WRITE_RELATIONSHIPS } {
            self.write_relations(input.caller, input.target_address, input_bytes.clone());
        }

        let mut hash = input_bytes.to_vec();
        hash.resize(4, 0);

        macro_rules! record_func_hash {
            () => {
                unsafe {
                    let mut s = DefaultHasher::new();
                    hash.hash(&mut s);
                    let _hash = s.finish();
                    ABI_MAX_SIZE[(_hash as usize) % MAP_SIZE] = RET_SIZE;
                }
            };
        }

        // middlewares
        let mut middleware_result: Option<(InstructionResult, Bytes)> = None;
        for action in &self.middlewares_latent_call_actions {
            match action {
                CallMiddlewareReturn::Continue => {}
                CallMiddlewareReturn::ReturnRevert => {
                    middleware_result = Some((InstructionResult::Revert, Bytes::new()));
                }
                CallMiddlewareReturn::ReturnSuccess(b) => {
                    middleware_result = Some((InstructionResult::Return, b.clone()));
                }
            }
            if middleware_result.is_some() {
                break;
            }
        }
        self.middlewares_latent_call_actions.clear();

        if let Some((status, output)) = middleware_result {
            return (status, input.return_memory_offset.clone(), output);
        }

        let input_seq = input_bytes.to_vec();

        let is_target_address_unbounded = {
            assert_ne!(self._pc, 0);
            self.pc_to_addresses
                .entry((input.caller, self._pc))
                .or_default();
            let addresses_at_pc = self.pc_to_addresses.get_mut(&(input.caller, self._pc)).unwrap();
            addresses_at_pc.insert(input.target_address);
            addresses_at_pc.len() > CONTROL_LEAK_THRESHOLD
        };

        if input.scheme == CallScheme::StaticCall &&
            (state.has_caller(&input.target_address) || is_target_address_unbounded)
        {
            record_func_hash!();
            push_interp!();
            unsafe { UNBOUNDED_STATIC_CALL_DETECTED = true; }
            return (InstructionResult::Revert, input.return_memory_offset.clone(), Bytes::new());
        }

        if input.scheme == CallScheme::Call {
            // if calling sender, then definitely control leak
            if state.has_caller(&input.target_address) || is_target_address_unbounded {
                record_func_hash!();
                push_interp!();
                unsafe { CONTROL_LEAK_DETECTED = true; }
                return (InstructionResult::Revert, input.return_memory_offset.clone(), Bytes::new());
            }
            // check whether the whole CALLDATAVALUE can be arbitrary
            self.pc_to_call_hash
                .entry((input.caller, self._pc, self.jumpi_trace))
                .or_default();
            self.pc_to_call_hash
                .get_mut(&(input.caller, self._pc, self.jumpi_trace))
                .unwrap()
                .insert(hash.to_vec());
            if self
                .pc_to_call_hash
                .get(&(input.caller, self._pc, self.jumpi_trace))
                .unwrap()
                .len() >
                UNBOUND_CALL_THRESHOLD &&
                input_seq.len() >= 4
            {
                self.current_arbitrary_calls.push((
                    input.caller,
                    input.target_address,
                    self._pc,
                ));
                // ERC20 transfer detection for arbitrary_transfers oracle
                let selector = &input_bytes[..4];
                // transfer(address,uint256) = a9059cbb
                // transferFrom(address,address,uint256) = 23b872dd
                if selector == b"\xa9\x05\x9c\xbb" || selector == b"\x23\xb8\x72\xdd" {
                    self.current_arbitrary_transfers.push((
                        input.caller,
                        self._pc,
                    ));
                }
                push_interp!();
                unsafe {
                    ARBITRARY_CALL_DETECTED = true;
                    ARBITRARY_CALL_CALLER = input.caller.0.0;
                    ARBITRARY_CALL_TARGET = input.target_address.0.0;
                    ARBITRARY_CALL_VALUE = match input.value {
                        CallValue::Transfer(v) => v,
                        CallValue::Apparent(v) => v,
                        _ => EVMU256::ZERO,
                    };
                }
                return (InstructionResult::Revert, input.return_memory_offset.clone(), Bytes::new());
            }
        }

        // find contracts that have this function hash
        let contract_loc_option = self.hash_to_address.get(hash.as_slice());
        if unsafe { ACTIVE_MATCH_EXT_CALL } {
            if let Some(loc) = contract_loc_option {
                if !loc.contains(&input.target_address) {
                    if loc.len() != 1 {
                        panic!("more than one contract found for the same hash");
                    }
                    let target = *loc.iter().next().unwrap();
                    if let Some(code) = self.code.get(&target).cloned() {
                        let interp_input = InputsImpl {
                            target_address: target,
                            bytecode_address: Some(target),
                            caller_address: input.caller,
                            input: CallInput::Bytes(PrimBytes::copy_from_slice(&input_seq)),
                            call_value: match input.value {
                                CallValue::Transfer(v) => v,
                                CallValue::Apparent(v) => v,
                                _ => EVMU256::ZERO,
                            },
                        };
                        let is_static = input.scheme == CallScheme::StaticCall;
                        let mut sub_interp = Interpreter::new(
                            SharedMemory::new_with_memory_limit(MEM_LIMIT as u64),
                            ExtBytecode::new((*code).clone()),
                            interp_input,
                            is_static,
                            self.spec_id,
                            u64::MAX,
                        );
                        let ret = self.run_inspect(&mut sub_interp, state);
                        let output = sub_interp.return_data.buffer().clone().0;
                        return (ret, input.return_memory_offset.clone(), output);
                    }
                }
            }
        }

        // if there is code, then call the code
        let res = self.call_forbid_control_leak(input, state);
        match res.0 {
            r if is_control_leak_result(r) => {
                self.leak_ctx
                    .push(SinglePostExecution::from_interp(interp, (out_offset, out_len)));
            }
            _ => {}
        }
        res
    }

    fn call_forbid_control_leak(
        &mut self,
        input: &mut CallInputs,
        state: &mut EVMFuzzState,
    ) -> (InstructionResult, std::ops::Range<usize>, Bytes) {
        let input_bytes = Self::get_input_bytes(&input.input);
        let mut hash = input_bytes.to_vec();
        hash.resize(4, 0);

        let code_address = input.bytecode_address;
        if let Some(code) = self.code.get(&code_address).cloned() {
            let interp_input = InputsImpl {
                target_address: input.target_address,
                bytecode_address: Some(code_address),
                caller_address: input.caller,
                input: CallInput::Bytes(PrimBytes::copy_from_slice(input_bytes.as_ref())),
                call_value: match input.value {
                    CallValue::Transfer(v) => v,
                    CallValue::Apparent(v) => v,
                    _ => EVMU256::ZERO,
                },
            };
            let is_static = input.scheme == CallScheme::StaticCall;
            let mut sub_interp = Interpreter::new(
                SharedMemory::new_with_memory_limit(MEM_LIMIT as u64),
                ExtBytecode::new((*code).clone()),
                interp_input,
                is_static,
                self.spec_id,
                u64::MAX,
            );
            let ret = self.run_inspect(&mut sub_interp, state);
            let output = sub_interp.return_data.buffer().clone().0;
            return (ret, input.return_memory_offset.clone(), output);
        }

        // transfer txn and fallback provided
        if hash == [0x00, 0x00, 0x00, 0x00] {
            return (InstructionResult::Return, input.return_memory_offset.clone(), Bytes::new());
        }
        (InstructionResult::Revert, input.return_memory_offset.clone(), Bytes::new())
    }

    fn call_precompile(
        &mut self,
        input: &mut CallInputs,
        _state: &mut EVMFuzzState,
    ) -> (InstructionResult, std::ops::Range<usize>, Bytes) {
        let precompile = self
            .precompiles
            .get(&input.target_address)
            .expect("Check for precompile should be already done");
        let input_bytes = Self::get_input_bytes(&input.input);
        let out = precompile.execute(input_bytes.as_ref(), u64::MAX, 0);
        match out {
            Ok(output) => (InstructionResult::Return, input.return_memory_offset.clone(), output.bytes.0),
            Err(_) => (InstructionResult::PrecompileError, input.return_memory_offset.clone(), Bytes::new()),
        }
    }

    /// Apply the prank
    pub fn apply_prank(&mut self, _contract_caller: &EVMAddress, _input: &mut CallInputs) {
        // TODO: enable cheatcode when https://github.com/matter-labs/zksync-era/issues/4581 is resolved
    }

    /// Clean up the prank
    pub fn clean_prank(&mut self) {
        // TODO: enable cheatcode when https://github.com/matter-labs/zksync-era/issues/4581 is resolved
    }

    pub fn check_assert_result(&mut self) -> Option<(InstructionResult, std::ops::Range<usize>, Bytes)> {
        if let Some(ref msg) = self.assert_msg {
            return Some((InstructionResult::Revert, 0..0, msg.abi_encode().into()));
        }
        None
    }

    fn check_expected_revert(&mut self, res: (InstructionResult, std::ops::Range<usize>, Bytes)) -> (InstructionResult, std::ops::Range<usize>, Bytes) {
        res
    }

    fn check_expected_emits(&mut self, _call: &CallInputs, res: (InstructionResult, std::ops::Range<usize>, Bytes)) -> (InstructionResult, std::ops::Range<usize>, Bytes) {
        res
    }

    fn check_expected_calls(&mut self, res: (InstructionResult, std::ops::Range<usize>, Bytes)) -> (InstructionResult, std::ops::Range<usize>, Bytes) {
        res
    }

    fn check_expected(&mut self, call: &CallInputs, res: (InstructionResult, std::ops::Range<usize>, Bytes)) -> (InstructionResult, std::ops::Range<usize>, Bytes) {
        if let Some(res) = self.check_assert_result() {
            return res;
        }
        let res = self.check_expected_revert(res);
        if res.0 == InstructionResult::Revert {
            return res;
        }
        let res = self.check_expected_emits(call, res);
        if res.0 == InstructionResult::Revert {
            return res;
        }
        self.check_expected_calls(res)
    }

    /// Internal CALL handler (was `Host::call` in old API).
    /// Returns (InstructionResult, return_memory_range, output_bytes).
    fn call_internal(
        &mut self,
        input: Box<CallInputs>,
        interp: &mut Interpreter,
        state: &mut EVMFuzzState,
    ) -> (InstructionResult, std::ops::Range<usize>, Bytes) {
        let mut input = *input;
        self.apply_prank(&interp.input.caller_address, &mut input);
        self.call_depth += 1;

        let value = match input.value {
            CallValue::Transfer(v) => v,
            _ => EVMU256::ZERO,
        };
        if cfg!(feature = "real_balance") && value != EVMU256::ZERO {
            let sender = input.transfer_from();
            debug!("call sender: {:?}", sender);
            let current = if let Some(balance) = self.evmstate.get_balance(&sender) {
                *balance
            } else {
                self.evmstate.set_balance(sender, self.next_slot);
                self.next_slot
            };
            if current < value {
                self.call_depth -= 1;
                return (InstructionResult::Revert, input.return_memory_offset, Bytes::new());
            }
            self.evmstate.set_balance(sender, current - value);

            let receiver = input.transfer_to();
            if let Some(balance) = self.evmstate.get_balance(&receiver) {
                self.evmstate.set_balance(receiver, *balance + value);
            } else {
                self.evmstate.set_balance(receiver, self.next_slot + value);
            };
        }

        let output_info = (unsafe { RET_OFFSET }, unsafe { RET_SIZE });

        let mut res = if is_precompile(input.target_address, self.precompiles.len()) {
            self.call_precompile(&mut input, state)
        } else if unsafe { IS_FAST_CALL_STATIC || IS_FAST_CALL } {
            self.call_forbid_control_leak(&mut input, state)
        } else {
            self.call_allow_control_leak(&mut input, interp, output_info, state)
        };

        let ret_buffer = res.2.clone();

        self.call_depth -= 1;
        res = self.check_expected(&input, res);
        self.clean_prank();

        unsafe {
            if self.middlewares_enabled {
                let mut middlewares = self.middlewares.read().unwrap().clone();
                for middleware in middlewares.iter_mut() {
                    middleware
                        .deref()
                        .borrow_mut()
                        .on_return(interp, self, state, &ret_buffer);
                }
            }
        }
        res
    }

    /// Internal CREATE handler (was `Host::create` in old API).
    /// Returns (InstructionResult, Option<created_address>, output_bytes).
    fn create_internal(
        &mut self,
        inputs: Box<CreateInputs>,
        state: &mut EVMFuzzState,
    ) -> (InstructionResult, Option<EVMAddress>, Bytes) {
        if unsafe { IN_DEPLOY } {
            let r_addr = generate_random_address(state);

            let value = inputs.value();
            if cfg!(feature = "real_balance") && value != EVMU256::ZERO {
                let receiver = r_addr;
                if let Some(balance) = self.evmstate.get_balance(&receiver) {
                    self.evmstate.set_balance(receiver, *balance + value);
                } else {
                    self.evmstate.set_balance(receiver, self.next_slot + value);
                };
            }

            let interp_input = InputsImpl {
                target_address: r_addr,
                bytecode_address: None,
                caller_address: inputs.caller(),
                input: CallInput::Bytes(PrimBytes::new()),
                call_value: value,
            };
            let init_code = Bytecode::new_legacy(inputs.init_code().clone());
            let mut sub_interp = Interpreter::new(
                SharedMemory::new_with_memory_limit(MEM_LIMIT as u64),
                ExtBytecode::new(init_code),
                interp_input,
                false,
                self.spec_id,
                u64::MAX,
            );
            let ret = self.run_inspect(&mut sub_interp, state);
            debug!("create: {:?} -> {:?} = {:?}", inputs.caller(), r_addr, ret);
            if !is_reverted_or_control_leak(&ret) {
                let runtime_code = sub_interp.return_data.buffer().clone();
                self.set_code(r_addr, Bytecode::new_raw(runtime_code.clone()), state);
                if !unsafe { SETCODE_ONLY } {
                    // now we build & insert abi
                    let contract_code_str = hex::encode(&runtime_code);
                    let sigs = extract_sig_from_contract(&contract_code_str);
                    let mut unknown_sigs: usize = 0;
                    let mut parsed_abi = vec![];
                    for sig in &sigs {
                        if let Some(abi) = state.metadata_map().get::<ABIMap>().unwrap().get(sig) {
                            parsed_abi.push(abi.clone());
                        } else {
                            unknown_sigs += 1;
                        }
                    }

                    if unknown_sigs >= sigs.len() / 30 {
                        debug!("Too many unknown function signature for newly created contract, we are going to decompile this contract using EVMole");
                        let abis = fetch_abi_evmole(&runtime_code)
                            .iter()
                            .map(|abi| {
                                if let Some(known_abi) =
                                    state.metadata_map().get::<ABIMap>().unwrap().get(&abi.function)
                                {
                                    known_abi
                                } else {
                                    abi
                                }
                            })
                            .cloned()
                            .collect_vec();
                        parsed_abi = abis;
                    }
                    // notify flashloan and blacklisting flashloan addresses
                    handle_contract_insertion!(state, self, r_addr, r_addr, parsed_abi);

                    parsed_abi.iter().filter(|v| !v.is_constructor).for_each(|abi| {
                        #[cfg(not(feature = "fuzz_static"))]
                        if abi.is_static {
                            return;
                        }

                        let mut abi_instance = get_abi_type_boxed(&abi.abi);
                        abi_instance.set_func_with_signature(abi.function, &abi.function_name, &abi.abi);
                        register_abi_instance(r_addr, abi_instance.clone(), state);

                        let input = EVMInput {
                            caller: state.get_rand_caller(),
                            contract: r_addr,
                            data: Some(abi_instance),
                            sstate: StagedVMState::new_uninitialized(),
                            sstate_idx: 0,
                            txn_value: if abi.is_payable { Some(EVMU256::ZERO) } else { None },
                            step: false,
                            env: Default::default(),
                            access_pattern: Rc::new(RefCell::new(AccessPattern::new())),
                            liquidation_percent: 0,
                            input_type: EVMInputTy::ABI,
                            direct_data: Default::default(),
                            randomness: vec![0],
                            repeat: 1,
                            swap_data: HashMap::new(),
                        };
                        add_corpus(self, state, &input);
                    });
                }
                (InstructionResult::Return, Some(r_addr), runtime_code.0)
            } else {
                (ret, Some(r_addr), Bytes::new())
            }
        } else {
            (InstructionResult::Revert, None, Bytes::new())
        }
    }
}

/// Returns true if the result represents a control-leak (checked via static flags)
/// or is a direct Revert that followed a control-leak signal.
#[inline]
pub fn is_control_leak_result(ret: InstructionResult) -> bool {
    if ret != InstructionResult::Revert {
        return false;
    }
    unsafe { CONTROL_LEAK_DETECTED || ARBITRARY_CALL_DETECTED || UNBOUNDED_STATIC_CALL_DETECTED }
}


#[macro_export]
macro_rules! invoke_middlewares {
    ($host:expr, $interp:expr, $state:expr, $invoke:ident $(, $arg:expr)*) => {
        if $host.middlewares_enabled {
            if let Some(m) = $host.flashloan_middleware.clone() {
                let mut middleware = m.deref().borrow_mut();
                middleware.$invoke($interp, $host, $state $(, $arg)*);
            }

            if !$host.setcode_data.is_empty() {
                $host.clear_codedata();
            }

            let mut middlewares = $host.middlewares.read().unwrap().clone();
            for middleware in middlewares.iter_mut() {
                middleware.deref().borrow_mut().$invoke($interp, $host, $state $(, $arg)*);
            }

            if !$host.setcode_data.is_empty() {
                for (address, code) in &$host.setcode_data.clone() {
                    $host.set_code(address.clone(), code.clone(), $state);
                }
            }
        }
    };
}

// ---- revm 41 Host trait implementation (storage-only) ----

impl<SC> Host for FuzzHost<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    // -- Block --

    fn basefee(&self) -> U256 {
        U256::from(self.env.block.basefee)
    }

    fn blob_gasprice(&self) -> U256 {
        U256::ZERO
    }

    fn gas_limit(&self) -> U256 {
        U256::from(u64::MAX)
    }

    fn difficulty(&self) -> U256 {
        self.env.block.difficulty
    }

    fn prevrandao(&self) -> Option<U256> {
        self.env.block.prevrandao.map(|h| U256::from_be_slice(h.as_slice()))
    }

    fn block_number(&self) -> U256 {
        self.env.block.number
    }

    fn timestamp(&self) -> U256 {
        self.env.block.timestamp
    }

    fn beneficiary(&self) -> Address {
        self.env.block.beneficiary
    }

    fn slot_num(&self) -> U256 {
        U256::ZERO
    }

    fn chain_id(&self) -> U256 {
        U256::from(self.env.cfg.chain_id)
    }

    // -- Transaction --

    fn effective_gas_price(&self) -> U256 {
        U256::from(self.env.tx.gas_price)
    }

    fn caller(&self) -> Address {
        self.env.tx.caller
    }

    fn blob_hash(&self, _number: usize) -> Option<U256> {
        None
    }

    // -- Config --

    fn max_initcode_size(&self) -> usize {
        usize::MAX
    }

    fn gas_params(&self) -> &GasParams {
        &self.gas_params
    }

    fn is_amsterdam_eip8037_enabled(&self) -> bool {
        false
    }

    // -- Database --

    fn block_hash(&mut self, _number: u64) -> Option<B256> {
        Some(B256::ZERO)
    }

    // -- Journal --

    fn selfdestruct(
        &mut self,
        address: Address,
        _target: Address,
        _skip_cold_load: bool,
    ) -> Result<StateLoad<SelfDestructResult>, LoadError> {
        self.current_self_destructs.push((address, self._pc));
        Ok(StateLoad::new(SelfDestructResult::default(), false))
    }

    fn log(&mut self, log: Log) {
        let _address = log.address;
        let topics = log.data.topics();
        let _data = log.data.data.clone();

        // flag check
        if topics.len() == 1 {
            let current_flag = topics[0].0;
            if current_flag[0] == 0x66 &&
                current_flag[1] == 0x75 &&
                current_flag[2] == 0x7a &&
                current_flag[3] == 0x7a &&
                current_flag[4] == 0x6c &&
                current_flag[5] == 0x61 &&
                current_flag[6] == 0x6e &&
                current_flag[7] == 0x64 &&
                current_flag[8] == 0x00 &&
                current_flag[9] == 0x00 ||
                current_flag == SCRIBBLE_EVENT_HEX
            {
                let data_string = String::from_utf8(_data[64..].to_vec()).unwrap();
                if unsafe { PANIC_ON_BUG } {
                    panic!("target bug found: {}", data_string);
                }
                self.current_typed_bug
                    .push((data_string.trim_end_matches('\u{0}').to_string(), (_address, self._pc)));
            }
        }

        #[cfg(feature = "print_logs")]
        {
            let mut hasher = DefaultHasher::new();
            _data.to_vec().hash(&mut hasher);
            let h = hasher.finish();
            if self.logs.contains(&h) {
                return;
            }
            self.logs.insert(h);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards");
            let timestamp = now.as_nanos();
            debug!("log@{} {:?}", timestamp, hex::encode(_data));
        }
    }

    fn sstore_skip_cold_load(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        _skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, LoadError> {
        match self.evmstate.get_mut(&address) {
            Some(account) => {
                account.insert(key, value);
            }
            None => {
                let mut account = HashMap::new();
                account.insert(key, value);
                self.evmstate.insert(address, account);
            }
        };
        Ok(StateLoad::new(SStoreResult::default(), false))
    }

    fn sload_skip_cold_load(
        &mut self,
        address: Address,
        key: U256,
        _skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, LoadError> {
        if let Some(account) = self.evmstate.get_mut(&address) {
            if let Some(slot) = account.get(&key) {
                return Ok(StateLoad::new(*slot, false));
            } else {
                account.insert(key, self.next_slot);
            }
        } else {
            let mut account = HashMap::new();
            account.insert(key, self.next_slot);
            self.evmstate.insert(address, account);
        }
        Ok(StateLoad::new(self.next_slot, false))
    }

    fn tload(&mut self, address: Address, key: U256) -> U256 {
        if let Some(slot) = self.transient_storage.get(&(address, key)) {
            *slot
        } else {
            self.transient_storage.insert((address, key), self.next_slot);
            self.next_slot
        }
    }

    fn tstore(&mut self, address: Address, key: U256, value: U256) {
        self.transient_storage.insert((address, key), value);
    }

    fn load_account_info_skip_cold_load(
        &mut self,
        address: Address,
        load_code: bool,
        _skip_cold_load: bool,
    ) -> Result<AccountInfoLoad<'_>, LoadError> {
        let balance = {
            #[cfg(feature = "real_balance")]
            {
                if let Some(balance) = self.evmstate.get_balance(&address) {
                    *balance
                } else {
                    self.next_slot
                }
            }
            #[cfg(not(feature = "real_balance"))]
            {
                U256::MAX
            }
        };

        let (code_hash, code) = if load_code {
            match self.code.get(&address) {
                Some(c) => (c.hash_slow(), Some((**c).clone())),
                None => (KECCAK_EMPTY, None),
            }
        } else {
            match self.code.get(&address) {
                Some(c) => (c.hash_slow(), None),
                None => (KECCAK_EMPTY, None),
            }
        };

        let is_empty = balance == U256::ZERO && code_hash == KECCAK_EMPTY;

        // We store a local AccountInfo on the stack and return a borrowed reference.
        // Because AccountInfoLoad<'_> has lifetime tied to &mut self, we need to store
        // the AccountInfo somewhere that lives long enough. We use a thread-local for this.
        thread_local! {
            static LAST_ACCOUNT_INFO: RefCell<AccountInfo> = RefCell::new(AccountInfo::default());
        }

        LAST_ACCOUNT_INFO.with(|cell| {
            *cell.borrow_mut() = AccountInfo {
                balance,
                nonce: 0,
                code_hash,
                code,
                account_id: None,
            };
        });

        // Safety: we return a static-lifetime reference to a thread-local,
        // which is valid for as long as the thread is alive.
        // The AccountInfoLoad<'_> lifetime is tied to &mut self but we extend it here.
        // This is sound because the thread-local won't be mutated during the caller's use.
        let info_ref: &'static AccountInfo = unsafe {
            LAST_ACCOUNT_INFO.with(|cell| {
                let ptr = cell.as_ptr() as *const AccountInfo;
                &*ptr
            })
        };

        Ok(AccountInfoLoad::new(info_ref, false, is_empty))
    }
}
